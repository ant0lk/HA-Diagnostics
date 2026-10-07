"""Resource server only. Authorization code, PKCE and refresh belong to the IdP."""
import contextvars
import time
from dataclasses import dataclass
import httpx
import jwt
from .policy import LocalPolicy

@dataclass(frozen=True)
class Principal:
    sub: str
    scopes: frozenset[str]
    expires_at: float
principal_context = contextvars.ContextVar("principal",default=None)

class AccessDenied(Exception):
    pass

class TokenVerifier:
    def __init__(self, oauth, client=None, introspection_secret=None):
        self.config=oauth
        self.owns_client=client is None
        self.client=client or httpx.AsyncClient(timeout=5,follow_redirects=False,trust_env=False)
        self.introspection_secret=introspection_secret
    async def json_get(self,url):
        async with self.client.stream("GET",url) as response:
            if response.status_code!=200: raise AccessDenied()
            body=b""
            async for chunk in response.aiter_bytes():
                body+=chunk
                if len(body)>65536: raise AccessDenied()
        import json
        return json.loads(body)
    async def verify(self, token: str) -> Principal:
        try:
            if not self.config.issuer or not self.config.resource or not self.config.jwks_uri or len(token)>8192: raise AccessDenied()
            header=jwt.get_unverified_header(token)
            if header.get("alg") not in {"RS256","ES256"} or not isinstance(header.get("kid"),str): raise AccessDenied()
            jwks=await self.json_get(self.config.jwks_uri)
            keys=[k for k in jwks.get("keys",[]) if k.get("kid")==header["kid"] and k.get("use","sig")=="sig"]
            if len(keys)!=1: raise AccessDenied()
            key=jwt.PyJWK.from_dict(keys[0],algorithm=header["alg"]).key
            c=jwt.decode(token,key,algorithms=[header["alg"]],issuer=self.config.issuer,audience=self.config.resource,options={"require":["exp","iat","sub","iss","aud"]})
            if c["aud"] not in (self.config.resource,[self.config.resource]): raise AccessDenied()
            if not isinstance(c["sub"],str) or c["exp"]-c["iat"]>900 or c["iat"]>time.time()+5: raise AccessDenied()
            if c.get("resource",self.config.resource)!=self.config.resource: raise AccessDenied()
            if self.config.introspection_uri:
                # Fixed, local IdP configuration; never user-controlled URL or token forwarding to HA.
                import json
                async with self.client.stream("POST",self.config.introspection_uri,data={"token":token},auth=(self.config.client_id,self.introspection_secret or "")) as response:
                    if response.status_code!=200:raise AccessDenied()
                    raw=b""
                    async for chunk in response.aiter_bytes():
                        raw+=chunk
                        if len(raw)>65536:raise AccessDenied()
                if json.loads(raw).get("active") is not True:raise AccessDenied()
            return Principal(c["sub"],frozenset(c.get("scope","").split()),c["exp"])
        except Exception:
            raise AccessDenied("ACCESS_DENIED") from None
        finally:
            if self.owns_client:
                await self.client.aclose()

def authorize(principal: Principal | None, policy: LocalPolicy, scope: str):
    if not principal or principal.expires_at<=time.time() or not policy.remote_enabled or principal.sub != policy.owner_sub or scope not in principal.scopes:
        raise AccessDenied("ACCESS_DENIED")

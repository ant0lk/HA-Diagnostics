import json
import time
import jwt
import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from ha_diagnostics.auth import TokenVerifier,AccessDenied
from ha_diagnostics.policy import OAuthConfig

@pytest.fixture
def auth():
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    jwk=json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()));jwk['kid']='test'
    def transport(request):return httpx.Response(200,json={'keys':[jwk]})
    config=OAuthConfig(issuer='https://idp.example/realm',resource='https://mcp.example/mcp',jwks_uri='https://idp.example/realm/certs')
    verifier=TokenVerifier(config,httpx.AsyncClient(transport=httpx.MockTransport(transport)))
    claims={'iss':config.issuer,'aud':config.resource,'sub':'owner','iat':int(time.time()),'nbf':int(time.time())-1,'exp':int(time.time())+300,'scope':'diagnostics:read'}
    return key,verifier,claims

@pytest.mark.asyncio
async def test_jwt_accepts_fixed_resource(auth):
    key,v,c=auth
    token=jwt.encode(c,key,algorithm='RS256',headers={'kid':'test'})
    p=await v.verify(token);assert p.sub=='owner' and p.scopes=={'diagnostics:read'}

@pytest.mark.asyncio
@pytest.mark.parametrize('changes',[{'iss':'https://other.example'},{'aud':'home-assistant-core'},{'aud':['https://mcp.example/mcp','home-assistant-core']},{'exp':0},{'nbf':int(time.time())+3600},{'resource':'https://other.example/mcp'},{'sub':False},{'exp':int(time.time())+3600}])
async def test_jwt_invalid_claims(auth,changes):
    key,v,c=auth
    with pytest.raises(AccessDenied):await v.verify(jwt.encode(c|changes,key,algorithm='RS256',headers={'kid':'test'}))

@pytest.mark.asyncio
async def test_forged_unknown_alg_and_redirect(auth):
    key,v,c=auth
    for token in ['not-a-token',jwt.encode(c,'secret',algorithm='HS256',headers={'kid':'test'}),jwt.encode(c,key,algorithm='RS256',headers={'kid':'wrong'})]:
        with pytest.raises(AccessDenied):await v.verify(token)
    v.client=httpx.AsyncClient(transport=httpx.MockTransport(lambda r:httpx.Response(302,headers={'Location':'http://supervisor/core/api'})))
    with pytest.raises(AccessDenied):await v.verify(jwt.encode(c,key,algorithm='RS256',headers={'kid':'test'}))

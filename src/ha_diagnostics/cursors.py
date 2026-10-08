import base64
import hashlib
import hmac
import json
import time

class CursorCodec:
    def __init__(self, key: bytes, ttl=300):
        if len(key) < 32: raise ValueError("CURSOR_KEY_TOO_SHORT")
        self.key, self.ttl = key, ttl
    @staticmethod
    def digest(arguments):
        return hashlib.sha256(json.dumps(arguments, sort_keys=True, separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
    def encode(self, after, *, sub, policy, tool, arguments, generation):
        payload = {"after":after,"sub":sub,"install":policy.installation_id,"policy":policy.version,"tool":tool,"args":self.digest(arguments),"generation":generation,"exp":int(time.time())+self.ttl}
        raw=json.dumps(payload,sort_keys=True,separators=(",",":")).encode()
        sig=hmac.digest(self.key,raw,"sha256")
        return base64.urlsafe_b64encode(raw+sig).decode().rstrip("=")
    def decode(self, cursor, *, sub, policy, tool, arguments, generation):
        try:
            raw=base64.b64decode(cursor+"="*(-len(cursor)%4),altchars=b"-_",validate=True)
            body,sig=raw[:-32],raw[-32:]
            if not hmac.compare_digest(sig,hmac.digest(self.key,body,"sha256")): raise ValueError()
            p=json.loads(body)
            expected={"sub":sub,"install":policy.installation_id,"policy":policy.version,"tool":tool,"args":self.digest(arguments),"generation":generation}
            if any(p.get(k)!=v for k,v in expected.items()) or p["exp"]<time.time(): raise ValueError()
            return p["after"]
        except Exception:
            raise ValueError("CURSOR_EXPIRED") from None

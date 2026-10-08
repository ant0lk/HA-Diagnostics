"""Single-owner reference gateway. Requires operator TLS/IdP setup and live acceptance."""
import asyncio
import hashlib
import json
import os
import secrets
import stat
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4
from starlette.applications import Starlette
from starlette.responses import JSONResponse,Response
from starlette.routing import Route
from ha_diagnostics.auth import TokenVerifier,authorize,AccessDenied
from ha_diagnostics.policy import PolicyStore
from ha_diagnostics.schemas import TOOLS,SCOPES
from ha_diagnostics.relay import ROUTING_HEADERS,RESPONSE_HEADERS,validate_header_map
from mcp_types import HEADER_MISMATCH,PROTOCOL_VERSION_META_KEY
from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS
try:
    from ha_diagnostics.schemas import required_scopes
except ImportError:
    def required_scopes(name):
        return {"diagnostics:read","history:read"} if name=="get_incident_context" else {SCOPES[name]}
try:
    from gateway.local_enrollment import EnrollmentStore,EnrollmentDenied,strict_json
except ModuleNotFoundError:
    from local_enrollment import EnrollmentStore,EnrollmentDenied,strict_json

@dataclass
class Pending:
    request_id:str
    nonce:str
    expires_at:float
    body:dict
    authorization:str
    routing_headers:dict
    future:asyncio.Future
    claimed:bool=False

class Gateway:
    def __init__(self,policies,device_key=None,verifier_factory=TokenVerifier,*,key_provider=None,enrollment=None):
        if device_key is not None and len(device_key)<32:raise ValueError("DEVICE_KEY_TOO_SHORT")
        self.policies,self.device_key,self.verify=policies,device_key,verifier_factory
        self.pending={};self.queue=asyncio.Queue(maxsize=8)
        self.key_provider=key_provider;self.enrollment=enrollment
        self.channel_generation=hashlib.sha256(device_key.encode()).hexdigest() if device_key else None
        self.mcp_active=0;self.enrollment_active=0;self.tool_calls=deque(maxlen=30)
    def refresh_channel(self):
        if self.key_provider is None:return
        try:key=self.key_provider()
        except ValueError:key=None
        generation=hashlib.sha256(key.encode()).hexdigest() if key else None
        if generation!=self.channel_generation:
            self.device_key=key;self.channel_generation=generation
            for item in self.pending.values():
                if not item.future.done():
                    item.future.set_result({'status':503,'body':{'error':'CHANNEL_REVOKED'}})
            while not self.queue.empty():
                try:self.queue.get_nowait()
                except asyncio.QueueEmpty:break
    def device(self,request):
        self.refresh_channel()
        if not self.device_key:return False
        try:return secrets.compare_digest(request.headers.get('Authorization',''),'Bearer '+self.device_key)
        except TypeError:return False
    async def bounded(self,request,maximum):
        raw=bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw)>maximum:raise ValueError()
        return json.loads(raw)
    async def mcp(self,request):
        if request.method!='POST':return Response(status_code=405)
        # Admission precedes body parsing and all JWT/JWKS/IdP work.
        if self.mcp_active>=2:return JSONResponse({'error':'BACKPRESSURE'},status_code=429,headers={'Retry-After':'1'})
        self.mcp_active+=1
        try:
            return await asyncio.wait_for(self._mcp_admitted(request),30)
        except asyncio.TimeoutError:
            return JSONResponse({'error':'INSTALLATION_UNAVAILABLE'},status_code=503)
        finally:self.mcp_active-=1
    async def _mcp_admitted(self,request):
        try:
            self.refresh_channel()
            if not self.device_key:return JSONResponse({'error':'INSTALLATION_UNAVAILABLE'},status_code=503)
            body=await self.bounded(request,32768)
            if not isinstance(body,dict) or not isinstance(body.get('method'),str):return JSONResponse({'error':'INVALID_REQUEST'},status_code=400)
            # The queue cannot preserve duplicate headers: reject them rather
            # than silently converting an invalid modern request into a valid one.
            if any(len(request.headers.getlist(name))>1 for name in ROUTING_HEADERS):
                return JSONResponse({'jsonrpc':'2.0','id':body.get('id'),'error':{'code':HEADER_MISMATCH,'message':'DUPLICATE_ROUTING_HEADER'}},status_code=400)
            routing=validate_header_map({name:request.headers[name] for name in ROUTING_HEADERS if name in request.headers},ROUTING_HEADERS,maximum=256)
            params=body.get('params',{})
            meta=params.get('_meta',{}) if isinstance(params,dict) else {}
            if isinstance(meta,dict) and PROTOCOL_VERSION_META_KEY in meta:
                version=meta[PROTOCOL_VERSION_META_KEY]
                # The pinned SDK selects its HTTP era using the version header.
                # A modern envelope must not enter its legacy handler because a
                # missing/legacy header was normalized by this intermediary.
                if version not in HANDSHAKE_PROTOCOL_VERSIONS and routing.get('mcp-protocol-version')!=version:
                    return JSONResponse({'jsonrpc':'2.0','id':body.get('id'),'error':{'code':HEADER_MISMATCH,'message':'PROTOCOL_HEADER_MISMATCH'}},status_code=400)
            routing.setdefault('mcp-protocol-version','2025-11-25')
            auth=request.headers.get('Authorization','');method=body['method'];p=self.policies.read()
            if method not in {'initialize','notifications/initialized','tools/list','tools/call','ping','server/discover'}:return JSONResponse({'jsonrpc':'2.0','id':body.get('id'),'error':{'code':-32601,'message':'UNSUPPORTED_CAPABILITY'}})
            if method=='tools/call':
                name=body.get('params',{}).get('name','')
                if name not in TOOLS:raise AccessDenied()
                if not auth.startswith('Bearer '):raise AccessDenied()
                principal=await self.verify(p.oauth).verify(auth[7:])
                for scope in required_scopes(name):authorize(principal,p,scope)
                now=time.monotonic()
                while self.tool_calls and self.tool_calls[0]<=now-60:self.tool_calls.popleft()
                if len(self.tool_calls)>=30:
                    retry=max(1,int(self.tool_calls[0]+60-now)+1)
                    return JSONResponse({'error':'RATE_LIMITED'},status_code=429,headers={'Retry-After':str(retry)})
                self.tool_calls.append(now)
            self.refresh_channel()
            if not self.device_key:return JSONResponse({'error':'INSTALLATION_UNAVAILABLE'},status_code=503)
            generation=self.channel_generation
            if len(self.pending)>=8:return JSONResponse({'error':'BACKPRESSURE'},status_code=429,headers={'Retry-After':'5'})
            rid=str(uuid4());future=asyncio.get_running_loop().create_future()
            item=Pending(rid,secrets.token_urlsafe(24),time.time()+30,body,auth,routing,future)
            self.pending[rid]=item
            try:
                self.queue.put_nowait(rid)
                deadline=time.monotonic()+30
                while True:
                    self.refresh_channel()
                    remaining=deadline-time.monotonic()
                    if remaining<=0:raise asyncio.TimeoutError()
                    try:
                        result=await asyncio.wait_for(asyncio.shield(future),min(.5,remaining))
                        break
                    except asyncio.TimeoutError:
                        continue
                self.refresh_channel()
                if self.channel_generation!=generation:
                    return JSONResponse({'error':'CHANNEL_REVOKED'},status_code=503)
                current=self.policies.read()
                if method=='tools/call':
                    for scope in required_scopes(name):authorize(principal,current,scope)
                    if current.version!=p.version:raise AccessDenied()
                response_headers={'Cache-Control':'no-store',**result.get('response_headers',{})}
                if result['status']==202 and result['body'] is None:
                    return Response(status_code=202,headers=response_headers)
                return JSONResponse(result['body'],status_code=result['status'],headers=response_headers)
            except asyncio.TimeoutError:return JSONResponse({'error':'INSTALLATION_UNAVAILABLE'},status_code=503)
            finally:
                self.pending.pop(rid,None)
                # Expired/cancelled requests do not fill the bounded queue.
                waiting=[]
                while not self.queue.empty():
                    try:
                        queued=self.queue.get_nowait()
                        if queued in self.pending:waiting.append(queued)
                    except asyncio.QueueEmpty:break
                for queued in waiting:self.queue.put_nowait(queued)
        except AccessDenied:
            return JSONResponse({'error':'ACCESS_DENIED'},status_code=401,headers={'WWW-Authenticate':'Bearer resource_metadata="'+self.policies.read().oauth.resource.rsplit('/mcp',1)[0]+'/.well-known/oauth-protected-resource"'})
        except Exception:return JSONResponse({'error':'INVALID_REQUEST'},status_code=400)
    async def poll(self,request):
        if not self.device(request):return Response(status_code=401)
        deadline=time.monotonic()+25
        while time.monotonic()<deadline:
            try:rid=await asyncio.wait_for(self.queue.get(),max(.1,deadline-time.monotonic()))
            except asyncio.TimeoutError:return Response(status_code=204)
            item=self.pending.get(rid)
            if item is None or item.claimed or item.expires_at<=time.time():continue
            if not self.device(request):return Response(status_code=401)
            item.claimed=True
            return JSONResponse({k:getattr(item,k) for k in ('request_id','nonce','expires_at','body','authorization','routing_headers')},headers={'Cache-Control':'no-store'})
        return Response(status_code=204)
    async def result(self,request):
        if not self.device(request):return Response(status_code=401)
        try:
            data=await self.bounded(request,320*1024)
            if not self.device(request):return Response(status_code=401)
            if not isinstance(data,dict) or set(data)!={'request_id','nonce','status','body','content_type','response_headers'}:raise ValueError()
            validate_header_map(data['response_headers'],RESPONSE_HEADERS)
            if data['content_type']!='application/json':raise ValueError()
            item=self.pending.get(data['request_id'])
            if not item or not item.claimed or item.future.done() or item.expires_at<=time.time() or not secrets.compare_digest(item.nonce,data['nonce']):raise ValueError()
            if type(data['status']) is not int or data['status'] not in {200,202,400,401,403,404,405,413,421,429,500,503}:raise ValueError()
            item.future.set_result(data)
            return JSONResponse({'accepted':True})
        except Exception:return JSONResponse({'error':'RESULT_REJECTED'},status_code=400)
    async def enroll(self,request):
        if self.enrollment_active>=2:return JSONResponse({'error':'BACKPRESSURE'},status_code=429,headers={'Retry-After':'1'})
        self.enrollment_active+=1
        try:
            return await asyncio.wait_for(self._enroll_admitted(request),30)
        except asyncio.TimeoutError:
            return JSONResponse({'error':'ENROLLMENT_DENIED'},status_code=401)
        finally:self.enrollment_active-=1
    async def _enroll_admitted(self,request):
        if self.enrollment is None:return JSONResponse({'error':'ENROLLMENT_DENIED'},status_code=401)
        try:
            async def read_body():
                raw=bytearray()
                async for chunk in request.stream():
                    raw.extend(chunk)
                    if len(raw)>1024:raise EnrollmentDenied()
                return bytes(raw)
            raw=await asyncio.wait_for(read_body(),5)
            result=self.enrollment.consume(strict_json(raw))
            self.refresh_channel()
            return JSONResponse(result,headers={'Cache-Control':'no-store','Pragma':'no-cache'})
        except (EnrollmentDenied,ValueError,TypeError,OSError,asyncio.TimeoutError):
            return JSONResponse({'error':'ENROLLMENT_DENIED'},status_code=401,headers={'Cache-Control':'no-store'})
    async def metadata(self,request):
        p=self.policies.read()
        return JSONResponse({'resource':p.oauth.resource,'authorization_servers':[p.oauth.issuer],'scopes_supported':['diagnostics:read','history:read','artifacts:read']})
    def app(self):
        return Starlette(routes=[Route('/mcp',self.mcp,methods=['POST','GET','DELETE']),Route('/channel/poll',self.poll),Route('/channel/result',self.result,methods=['POST']),Route('/channel/enroll',self.enroll,methods=['POST']),Route('/.well-known/oauth-protected-resource',self.metadata)])

def read_fixed_secret(data, name, *, required=True):
    """Owner-local fixed files; no URLs, symlinks, unbounded reads or logging."""
    if name not in {'device-channel-key','introspection.secret'}:
        raise ValueError('GATEWAY_SECRET_NAME_FORBIDDEN')
    data=Path(data);path=data/name
    if data.is_symlink() or path.is_symlink() or bool(getattr(data,'is_junction',lambda:False)()):
        raise ValueError('GATEWAY_SECRET_PATH_FORBIDDEN')
    if not path.exists() and not required:return None
    directory_fd=None;descriptor=None
    try:
        if os.name=='posix':
            directory_fd=os.open(data,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            descriptor=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory_fd)
        else:
            # Windows is development only; production uses the dirfd path above.
            descriptor=os.open(path,os.O_RDONLY)
        info=os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size>8192:
            raise ValueError('GATEWAY_SECRET_FILE_REJECTED')
        if os.name=='posix' and (info.st_mode&0o077 or info.st_uid!=os.geteuid()):
            raise ValueError('GATEWAY_SECRET_PERMISSIONS_REJECTED')
        raw=os.read(descriptor,8193)
        if not raw or len(raw)>8192:
            raise ValueError('GATEWAY_SECRET_FILE_REJECTED')
        value=raw.decode('utf-8')
        if any(ord(c)<33 or ord(c)==127 for c in value):
            raise ValueError('GATEWAY_SECRET_VALUE_REJECTED')
        return value
    except (OSError,UnicodeError):
        raise ValueError('GATEWAY_SECRET_UNAVAILABLE') from None
    finally:
        if descriptor is not None:os.close(descriptor)
        if directory_fd is not None:os.close(directory_fd)

def create_gateway(data,verifier_factory=TokenVerifier):
    key=read_fixed_secret(data,'device-channel-key',required=False)
    introspection_secret=read_fixed_secret(data,'introspection.secret',required=False)
    policies=PolicyStore(Path(data)/'policy.json')
    if policies.read().oauth.introspection_uri and not introspection_secret:
        raise ValueError('GATEWAY_INTROSPECTION_SECRET_REQUIRED')
    enrollment=EnrollmentStore(Path(data),policies)
    return Gateway(policies,key,verifier_factory=lambda config:verifier_factory(config,introspection_secret=introspection_secret),
                   key_provider=lambda:read_fixed_secret(data,'device-channel-key',required=False),enrollment=enrollment)

def main():
    import argparse
    import uvicorn
    parser=argparse.ArgumentParser();parser.add_argument('--data',type=Path,default=Path('/data'));args=parser.parse_args()
    app=create_gateway(args.data).app()
    uvicorn.run(app,host='127.0.0.1',port=8080,proxy_headers=False,access_log=False,log_level='critical')
if __name__=='__main__':main()

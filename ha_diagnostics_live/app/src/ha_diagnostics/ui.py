"""HA Ingress admin UI. Header identity only accepted from fixed trusted peer."""
import json
import secrets
from pathlib import Path
from starlette.applications import Starlette
from starlette.responses import FileResponse, JSONResponse
from starlette.routing import Route

class AdminGate:
    def __init__(self,admin_id="",demo=False):
        self.admin_id=admin_id;self.demo=demo;self.csrf=secrets.token_urlsafe(32)
    def allow(self,request):
        peer=request.client.host if request.client else ""
        if self.demo: return peer in {"127.0.0.1","::1","testclient"}
        # Supervisor's fixed Ingress peer; never X-Forwarded-For or an arbitrary caller claim.
        return bool(self.admin_id) and peer=="172.30.32.2" and request.headers.get("X-Remote-User-Id")==self.admin_id
    def write_allowed(self,request):
        if not self.allow(request) or not secrets.compare_digest(request.headers.get("X-CSRF-Token",""),self.csrf): return False
        if self.demo:
            origin=request.headers.get("origin","")
            return origin in {"http://127.0.0.1:8099","http://localhost:8099"}
        return bool(request.headers.get("X-Ingress-Path")) and request.headers.get("Sec-Fetch-Site") in {"same-origin","same-site"}

def create_ui(admin_client, *, gate, web_dir, audit_path=None):
    web_dir=Path(web_dir)
    async def index(request):
        if not gate.allow(request): return JSONResponse({"error":"INGRESS_ADMIN_NOT_VERIFIED"},status_code=403)
        return FileResponse(web_dir/"index.html",headers={"Content-Security-Policy":"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'self'; base-uri 'self'; form-action 'self'","Cache-Control":"no-store","X-Content-Type-Options":"nosniff"})
    async def asset(request):
        if not gate.allow(request): return JSONResponse({"error":"ACCESS_DENIED"},status_code=403)
        name=request.url.path.rsplit("/",1)[-1]
        if name not in {"app.js","style.css"}: return JSONResponse({"error":"NOT_FOUND"},status_code=404)
        return FileResponse(web_dir/name)
    async def status(request):
        if not gate.allow(request): return JSONResponse({"error":"ACCESS_DENIED"},status_code=403)
        try: data=await admin_client.request("admin_status",{})
        except Exception: return JSONResponse({"error":"SOURCE_UNAVAILABLE"},status_code=503)
        audit=[]
        if audit_path:
            try:
                with Path(audit_path).open("rb") as audit_file:
                    audit_file.seek(0,2);audit_file.seek(max(0,audit_file.tell()-65536))
                    lines=audit_file.read(65536).decode("utf-8",errors="replace").splitlines()[-100:]
                    for line in lines:
                        try:audit.append(json.loads(line))
                        except ValueError:pass
            except OSError:pass
        return JSONResponse(data|{"csrf":gate.csrf,"demo":gate.demo,"audit":audit},headers={"Cache-Control":"no-store"})
    async def action(request):
        if not gate.write_allowed(request): return JSONResponse({"error":"ACCESS_DENIED"},status_code=403)
        # Stream bound before JSON parsing; do not read unbounded request.body().
        raw=bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw)>29*1024**2: return JSONResponse({"error":"IMPORT_TOO_LARGE"},status_code=413)
        try:
            data=json.loads(raw)
            if not isinstance(data,dict) or set(data)!={"op","args"}: raise ValueError()
            result=await admin_client.request(data["op"],data["args"])
            return JSONResponse(result,headers={"Cache-Control":"no-store"})
        except Exception:
            return JSONResponse({"error":"ADMIN_REQUEST_REJECTED"},status_code=400)
    return Starlette(routes=[Route("/",index),Route("/app.js",asset),Route("/style.css",asset),Route("/api/status",status),Route("/api/action",action,methods=["POST"])])

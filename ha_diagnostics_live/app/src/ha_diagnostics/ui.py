"""HA Ingress admin UI. Header identity only accepted from fixed trusted peer."""
import json
import secrets
import re
import os
import stat
from pathlib import Path
from starlette.applications import Starlette
from starlette.responses import FileResponse, JSONResponse, StreamingResponse
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

def create_ui(admin_client, *, gate, web_dir, audit_path=None, transport_client=None, export_dir=None):
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
        tunnel={"available":False,"reason":"SETUP_UNAVAILABLE"}
        if transport_client:
            try:tunnel=await transport_client.request("tunnel_status",{})
            except Exception:pass
        if data.get("workflow")=="zip_export":
            return JSONResponse(data|{"csrf":gate.csrf,"demo":gate.demo},headers={"Cache-Control":"no-store"})
        return JSONResponse(data|{"csrf":gate.csrf,"demo":gate.demo,"audit":audit,"tunnel":tunnel},headers={"Cache-Control":"no-store"})
    async def download_export(request):
        if not gate.allow(request):return JSONResponse({"error":"ACCESS_DENIED"},status_code=403)
        export_id=request.path_params["export_id"]
        if export_dir is None or not re.fullmatch(r"export_[a-f0-9]{32}",export_id):
            return JSONResponse({"error":"EXPORT_NOT_FOUND"},status_code=404)
        try:
            result=await admin_client.request("export_download",{"export_id":export_id})
            # The worker returns metadata, never a user-selected filesystem path.
            path=Path(export_dir)/(export_id+".zip")
            if path.is_symlink():raise OSError()
            fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:
                os.close(fd);raise OSError()
        except Exception:
            return JSONResponse({"error":"EXPORT_NOT_READY"},status_code=404,headers={"Cache-Control":"no-store"})
        # Pin the file for the whole download, including concurrent removal.
        # Avoid buffering a potentially large ZIP in browser JS or server memory.
        import anyio
        async def chunks():
            with os.fdopen(fd,"rb") as source:
                while chunk:=await anyio.to_thread.run_sync(source.read,256*1024):
                    yield chunk
        return StreamingResponse(chunks(),media_type="application/zip",headers={
            "Content-Disposition":f'attachment; filename="ha-diagnostics-{export_id[7:]}.zip"',
            "Content-Length":str(info.st_size),"Cache-Control":"no-store",
            "X-Content-Type-Options":"nosniff"})
    async def save_tunnel(request):
        if not gate.write_allowed(request):return JSONResponse({"error":"ACCESS_DENIED"},status_code=403)
        if not transport_client:return JSONResponse({"error":"SETUP_UNAVAILABLE"},status_code=503)
        raw=bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw)>16384:return JSONResponse({"error":"SETTINGS_TOO_LARGE"},status_code=413)
        try:
            from .ipc import _json_loads
            from .transport_setup import TunnelArgs
            data=_json_loads(bytes(raw))
            args=TunnelArgs.model_validate(data)
            from .local_setup import _validate_secret
            _validate_secret(args.runtime_key.get_secret_value())
            result=await transport_client.request("save_tunnel",data)
            return JSONResponse(result,headers={"Cache-Control":"no-store"})
        except Exception:
            return JSONResponse({"error":"TUNNEL_SETTINGS_REJECTED"},status_code=400,headers={"Cache-Control":"no-store"})
    async def yandex_events(request):
        if not gate.allow(request):
            return JSONResponse({"error":"ACCESS_DENIED"},status_code=403,headers={"Cache-Control":"no-store"})
        try:
            from .yandex_history import YandexEventsArgs
            params=request.query_params
            if set(params)-{"before_event_id","limit"} or any(len(params.getlist(key))!=1 for key in params):
                raise ValueError()
            if any(not value.isascii() or not value.isdecimal() or len(value)>19 for value in params.values()):
                raise ValueError()
            args=YandexEventsArgs.model_validate({key:int(value) for key,value in params.items()})
        except ValueError:
            return JSONResponse({"error":"YANDEX_EVENTS_REJECTED"},status_code=400,headers={"Cache-Control":"no-store"})
        try:
            result=await admin_client.request("yandex_events",args.model_dump())
            return JSONResponse(result,headers={"Cache-Control":"no-store"})
        except Exception:
            return JSONResponse({"error":"YANDEX_STORAGE_UNAVAILABLE"},status_code=503,headers={"Cache-Control":"no-store"})
    async def save_yandex(request):
        if not gate.write_allowed(request):return JSONResponse({"error":"ACCESS_DENIED"},status_code=403)
        raw=bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw)>16384:return JSONResponse({"error":"SETTINGS_TOO_LARGE"},status_code=413)
        try:
            from .ipc import _json_loads
            from .yandex_history import YandexArgs
            data=_json_loads(bytes(raw))
            YandexArgs.model_validate(data)
            result=await admin_client.request("set_yandex",data)
            return JSONResponse(result,headers={"Cache-Control":"no-store"})
        except Exception as error:
            from .broker import BrokerError
            from .ipc import IPCError
            code=error.code if isinstance(error,(BrokerError,IPCError)) and error.code in {
                "YANDEX_TOKEN_REQUIRED","YANDEX_SAVE_FAILED","YANDEX_STORAGE_UNAVAILABLE","YANDEX_DEMO_DISABLED"} else "YANDEX_SETTINGS_REJECTED"
            return JSONResponse({"error":code},status_code=503 if code in {"YANDEX_SAVE_FAILED","YANDEX_STORAGE_UNAVAILABLE"} else 400,headers={"Cache-Control":"no-store"})
    async def yandex_matching(request):
        if not gate.allow(request):
            return JSONResponse({"error":"ACCESS_DENIED"},status_code=403,headers={"Cache-Control":"no-store"})
        candidates=request.url.path.endswith("candidates")
        try:
            from .yandex_matching import CandidateArgs, MatchingArgs
            params=request.query_params
            if any(len(params.getlist(key))!=1 for key in params):raise ValueError()
            args=(CandidateArgs if candidates else MatchingArgs).model_validate(dict(params))
        except ValueError:
            return JSONResponse({"error":"YANDEX_MATCHING_REJECTED"},status_code=400,headers={"Cache-Control":"no-store"})
        try:
            result=await admin_client.request("yandex_candidates" if candidates else "yandex_links",args.model_dump())
            return JSONResponse(result,headers={"Cache-Control":"no-store"})
        except Exception:
            return JSONResponse({"error":"YANDEX_MATCHING_UNAVAILABLE"},status_code=503,headers={"Cache-Control":"no-store"})
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
        except Exception as exc:
            from .broker import BrokerError
            from .ipc import IPCError
            if isinstance(exc,(BrokerError,IPCError)) and exc.code in {
                    "EXPORT_BUSY","EXPORT_NOT_FOUND","EXPORT_NOT_READY","DISK_LOW","SOURCE_UNAVAILABLE","SCHEDULE_SAVE_FAILED",
                    "YANDEX_CONNECTION_CHANGED","YANDEX_DEVICE_NOT_FOUND","YANDEX_CANDIDATE_CHANGED","HA_ENTITY_NOT_FOUND","YANDEX_SKILL_NOT_FOUND"}:
                code=409 if exc.code in {"EXPORT_BUSY","YANDEX_CONNECTION_CHANGED","YANDEX_CANDIDATE_CHANGED"} else 507 if exc.code=="DISK_LOW" else 400 if exc.code in {"YANDEX_DEVICE_NOT_FOUND","HA_ENTITY_NOT_FOUND","YANDEX_SKILL_NOT_FOUND"} else 503
                return JSONResponse({"error":exc.code},status_code=code,headers={"Cache-Control":"no-store"})
            return JSONResponse({"error":"ADMIN_REQUEST_REJECTED"},status_code=400)
    return Starlette(routes=[Route("/",index),Route("/app.js",asset),Route("/style.css",asset),Route("/api/status",status),Route("/api/exports/{export_id}/download",download_export),Route("/api/tunnel",save_tunnel,methods=["POST"]),Route("/api/yandex",save_yandex,methods=["POST"]),Route("/api/yandex/events",yandex_events),Route("/api/yandex/links",yandex_matching),Route("/api/yandex/candidates",yandex_matching),Route("/api/action",action,methods=["POST"])])

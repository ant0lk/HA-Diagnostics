"""Minimal root bootstrap followed by separate unprivileged Linux workers.

Windows --demo is import-only development, not OS isolation evidence.
"""
import argparse
import asyncio
import ctypes
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import secrets
import stat

BROKER_UID=10001
QUERY_UID=10002
UI_UID=10003
TRANSPORT_UID=10004
READ_GROUP=11000

class BootstrapStorage:
    """Root-only, descriptor-relative preparation; no path ownership changes.

    A worker may replace entries in its own directory. Root never follows such
    entries: every opened inode is checked before fchown/fchmod, and every leaf
    must be a single-link regular file. The trusted /data directory itself must
    remain root-owned and unwritable by workers.
    """
    DIRECTORIES={"private":(BROKER_UID,BROKER_UID,0o700),
                 "public":(BROKER_UID,READ_GROUP,0o2750),
                 "ipc":(BROKER_UID,UI_UID,0o2750),
                 "query":(QUERY_UID,UI_UID,0o2750),
                 "transport":(TRANSPORT_UID,TRANSPORT_UID,0o700)}

    def __init__(self,data):
        self.data=Path(os.path.abspath(data));self.root=None;self.directories={}

    @staticmethod
    def _check_directory(fd,owners):
        info=os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in owners or info.st_mode&0o022:
            raise RuntimeError("UNSAFE_BOOTSTRAP_STORAGE")

    def __enter__(self):
        flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
        current=None
        try:
            # Do not resolve() first: doing so would erase evidence of a link.
            current=os.open(self.data.anchor,flags)
            self._check_directory(current,{0})
            for component in self.data.parts[1:]:
                child=os.open(component,flags,dir_fd=current)
                try:self._check_directory(child,{0})
                except BaseException:os.close(child);raise
                os.close(current);current=child
            self.root=current
            return self
        except (OSError,ValueError):
            if current is not None:os.close(current)
            raise RuntimeError("UNSAFE_BOOTSTRAP_STORAGE") from None
        except BaseException:
            if current is not None:os.close(current)
            raise

    def __exit__(self,*_):
        for descriptor in self.directories.values():os.close(descriptor)
        self.directories.clear()
        if self.root is not None:os.close(self.root);self.root=None

    def prepare_directories(self):
        for name,(uid,gid,mode) in self.DIRECTORIES.items():
            try:os.mkdir(name,0o700,dir_fd=self.root)
            except FileExistsError:pass
            try:fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=self.root)
            except OSError:raise RuntimeError("UNSAFE_BOOTSTRAP_STORAGE") from None
            try:
                self._check_directory(fd,{0,uid})
                os.fchown(fd,uid,gid);os.fchmod(fd,mode)
            except BaseException:os.close(fd);raise
            self.directories[name]=fd
        os.fchmod(self.root,0o755)

    def _open_file(self,directory,name,owner,*,optional=False):
        if directory not in {"root",*self.DIRECTORIES} or name not in {
            "options.json","policy.json","introspection.secret","tunnel.json",
            "control-plane-api-key","relay.json","relay-device-key"}:
            raise RuntimeError("UNSAFE_BOOTSTRAP_STORAGE")
        parent=self.root if directory=="root" else self.directories[directory]
        try:fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        except FileNotFoundError:
            if optional:return None
            raise RuntimeError("MISSING_BOOTSTRAP_SETTINGS") from None
        except OSError:raise RuntimeError("UNSAFE_BOOTSTRAP_STORAGE") from None
        try:
            info=os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or
                    info.st_uid not in {0,owner} or info.st_mode&0o022):
                raise RuntimeError("UNSAFE_BOOTSTRAP_STORAGE")
            return fd
        except BaseException:os.close(fd);raise

    def read(self,directory,name,owner,*,limit=8192,optional=False,permissions=None):
        fd=self._open_file(directory,name,owner,optional=optional)
        if fd is None:return None
        try:
            if os.fstat(fd).st_size>limit:raise RuntimeError("BOOTSTRAP_SETTINGS_LIMIT")
            body=bytearray()
            while len(body)<=limit:
                chunk=os.read(fd,min(4096,limit+1-len(body)))
                if not chunk:break
                body.extend(chunk)
            if len(body)>limit:raise RuntimeError("BOOTSTRAP_SETTINGS_LIMIT")
            if permissions is not None:
                # Recheck link count before mutation, always using the pinned FD.
                if os.fstat(fd).st_nlink!=1:raise RuntimeError("UNSAFE_BOOTSTRAP_STORAGE")
                os.fchown(fd,*permissions[:2]);os.fchmod(fd,permissions[2])
            return bytes(body)
        finally:os.close(fd)

    def initialize_policy(self,profile):
        from .policy import LocalPolicy
        body=self.read("public","policy.json",BROKER_UID,limit=256*1024,optional=True,
                       permissions=(BROKER_UID,READ_GROUP,0o640))
        if body is not None:
            try:LocalPolicy.model_validate_json(body)
            except ValueError:raise RuntimeError("INVALID_BOOTSTRAP_POLICY") from None
            return
        policy=LocalPolicy(mode=profile,installation_id=secrets.token_hex(16),version=2)
        fd=None
        try:
            fd=os.open("policy.json",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,
                       0o600,dir_fd=self.directories["public"])
            payload=memoryview(policy.model_dump_json(indent=2).encode())
            while payload:
                written=os.write(fd,payload)
                if written<=0:raise OSError("BOOTSTRAP_POLICY_WRITE_FAILED")
                payload=payload[written:]
            os.fchown(fd,BROKER_UID,READ_GROUP);os.fchmod(fd,0o640)
            os.fsync(fd)
            os.fsync(self.directories["public"])
        except OSError:raise RuntimeError("UNSAFE_BOOTSTRAP_STORAGE") from None
        finally:
            if fd is not None:os.close(fd)

def read_bootstrap_options(data):
    with BootstrapStorage(data) as storage:
        raw=storage.read("root","options.json",0,limit=16384,optional=True,
                         permissions=(0,0,0o600))
    options=json.loads(raw) if raw is not None else {}
    if not isinstance(options,dict) or set(options)-{"mode","ingress_admin_id"}:
        raise RuntimeError("INVALID_BOOTSTRAP_OPTIONS")
    if ("mode" in options and options["mode"] not in {"import_only","live"} or
            not isinstance(options.get("ingress_admin_id",""),str) or
            len(options.get("ingress_admin_id",""))>100):
        raise RuntimeError("INVALID_BOOTSTRAP_OPTIONS")
    return options

def prepare_bootstrap_storage(data,profile):
    from .relay import validate_gateway
    with BootstrapStorage(data) as storage:
        storage.prepare_directories();storage.initialize_policy(profile)
        storage.read("query","introspection.secret",QUERY_UID,optional=True,
                     permissions=(QUERY_UID,QUERY_UID,0o600))
        tunnel=storage.read("transport","tunnel.json",TRANSPORT_UID,optional=True,
                            permissions=(TRANSPORT_UID,TRANSPORT_UID,0o600))
        relay=storage.read("transport","relay.json",TRANSPORT_UID,optional=True,
                           permissions=(TRANSPORT_UID,TRANSPORT_UID,0o600))
        if tunnel is not None and relay is not None:raise RuntimeError("TRANSPORT_CONFLICT")
        if relay is not None:
            config=json.loads(relay)
            if not isinstance(config,dict) or set(config)!={"origin"} or not isinstance(config["origin"],str):
                raise RuntimeError("INVALID_TRANSPORT_SETTINGS")
            validate_gateway(config["origin"])
            raw=storage.read("transport","relay-device-key",TRANSPORT_UID,
                             permissions=(TRANSPORT_UID,TRANSPORT_UID,0o600))
            key=raw.decode("utf-8")
            if not key or any(ord(c)<33 or ord(c)==127 for c in key):raise RuntimeError("INVALID_TRANSPORT_SETTINGS")
            return {"relay":True}
        if tunnel is not None:
            import re
            config=json.loads(tunnel)
            if (not isinstance(config,dict) or set(config)!={"tunnel_id"} or
                    not isinstance(config["tunnel_id"],str) or
                    not re.fullmatch(r"tunnel_[a-zA-Z0-9]{8,100}",config["tunnel_id"])):
                raise RuntimeError("INVALID_TUNNEL_ID")
            raw=storage.read("transport","control-plane-api-key",TRANSPORT_UID,
                             permissions=(TRANSPORT_UID,TRANSPORT_UID,0o600))
            key=raw.decode("utf-8")
            if not key or any(ord(c)<33 or ord(c)==127 for c in key):raise RuntimeError("INVALID_TRANSPORT_SETTINGS")
            return {"tunnel_id":config["tunnel_id"]}
    return {}

def harden():
    if sys.platform=="linux":
        import resource
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        libc=ctypes.CDLL(None,use_errno=True)
        if libc.prctl(4,0,0,0,0) or libc.prctl(38,1,0,0,0): # dumpable=0; no_new_privs
            raise RuntimeError("PROCESS_HARDENING_FAILED")

def secret_file(path):
    path=Path(path)
    if not path.exists():
        path.write_bytes(secrets.token_bytes(32));path.chmod(0o600)
    if path.is_symlink() or len(path.read_bytes())!=32: raise RuntimeError("INVALID_LOCAL_KEY")
    return path.read_bytes()

def broker_policy(store):
    from .broker import BrokerPolicy
    p=store.read(); sources={s.source_id for s in p.sources if s.collect}
    return BrokerPolicy(mode=p.mode,enabled_sources=sources,addon_slugs={x.split(":",1)[1] for x in sources if x.startswith("addon:")},entity_ids=set(p.entity_ids),collect=p.collection_enabled,disclose_names=p.disclose_names,version=p.version)

def initialize(data,profile):
    from .policy import PolicyStore, LocalPolicy
    store=PolicyStore(data/"public/policy.json")
    if not store.path.exists():
        store.write(LocalPolicy(mode=profile,installation_id=secrets.token_hex(16)))
    return store

async def broker_worker(data,profile,ready=None):
    from .archive import Archive
    from .redaction import Redactor
    from .broker import ReadBroker
    from .collector import Collector
    from .admin import AdminService
    from .ipc import AdminIPCServer
    harden();store=initialize(data,profile)
    token=None
    fd=os.environ.pop("HAD_TOKEN_FD",None)
    if fd is not None:
        with os.fdopen(int(fd),"rb") as pipe: raw=pipe.read(8193)
        if len(raw)>8192: raise RuntimeError("CREDENTIAL_LIMIT")
        token=raw.decode() if profile=="live" else None
    redactor=Redactor(secret_file(data/"private/redaction.key"))
    p=store.read()
    from .storage_budget import archive_budget
    archive=Archive(data/"public/archive.sqlite",redactor,max_bytes=archive_budget(p.max_bytes),retention_days=p.retention_days)
    broker=ReadBroker(lambda:broker_policy(store),redactor,token=token)
    del token
    admin=AdminService(archive,store,broker,profile)
    ipc=AdminIPCServer(data/"ipc/admin.sock",admin.handlers(),admin_uid=UI_UID,admin_gid=UI_UID)
    await ipc.start()
    collector=Collector(broker,archive,timezone=store.read().timezone)
    async def permissions():
        while True:
            for name in ("archive.sqlite","archive.sqlite-wal","archive.sqlite-shm","policy.json"):
                path=data/"public"/name
                if path.exists(): path.chmod(0o640)
            await asyncio.sleep(.5)
    if ready: ready.set()
    try: await asyncio.gather(collector.run(),permissions())
    finally: collector.stop();await ipc.close();await broker.close();archive.close()

def create_query(data):
    from .archive import Archive
    from .policy import PolicyStore
    from .cursors import CursorCodec
    from .query import QueryService
    archive=Archive.open_readonly(data/"public/archive.sqlite")
    from .storage_budget import audit_budget
    def audit(item):
        path=data/"query/audit.jsonl"
        # Small fixed audit buffer within aggregate archive budget. Never log body/query.
        if path.exists() and path.stat().st_size>audit_budget(PolicyStore(data/"public/policy.json").read().max_bytes)-1024:
            path.unlink()
        with path.open("a",encoding="utf-8") as out: out.write(json.dumps(item,separators=(",",":"))+"\n")
    return QueryService(archive,PolicyStore(data/"public/policy.json"),CursorCodec(secret_file(data/"query/cursor.key")),audit)

async def query_worker(data):
    import uvicorn
    from .mcp_server import create_app
    from .auth import TokenVerifier
    harden();service=create_query(data)
    def verifier(config):
        path=data/"query/introspection.secret"
        secret=path.read_text().strip() if path.exists() else None
        return TokenVerifier(config,introspection_secret=secret)
    server=uvicorn.Server(uvicorn.Config(create_app(service,verifier),host="127.0.0.1",port=8000,proxy_headers=False,access_log=False,log_level="critical"))
    await server.serve()

async def ui_worker(data,web_dir,options):
    import uvicorn
    from .ui import create_ui,AdminGate
    from .ipc import AdminIPCClient
    harden()
    # No HA token or redaction key needed by UI.
    app=create_ui(AdminIPCClient(data/"ipc/admin.sock"),gate=AdminGate(options.get("ingress_admin_id","")),web_dir=web_dir,audit_path=data/"query/audit.jsonl")
    await uvicorn.Server(uvicorn.Config(app,host="0.0.0.0",port=8099,proxy_headers=False,access_log=False,log_level="critical")).serve()

def read_transport_file(path,limit=8192):
    """Fixed local config path, bounded regular file, no symlink following."""
    import stat
    path=Path(path)
    if path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode):
        raise RuntimeError("INVALID_TRANSPORT_SETTINGS")
    flags=os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)
    fd=os.open(path,flags)
    with os.fdopen(fd,"rb") as source:
        body=source.read(limit+1)
    if len(body)>limit:raise RuntimeError("TRANSPORT_SETTINGS_LIMIT")
    return body

def relay_settings(data):
    from .relay import validate_gateway
    config=json.loads(read_transport_file(data/"transport/relay.json"))
    if not isinstance(config,dict) or set(config)!={"origin"} or not isinstance(config["origin"],str):
        raise RuntimeError("INVALID_TRANSPORT_SETTINGS")
    origin=validate_gateway(config["origin"])
    key=read_transport_file(data/"transport/relay-device-key").decode("utf-8")
    if not key or any(ord(c)<33 or ord(c)==127 for c in key):raise RuntimeError("INVALID_TRANSPORT_SETTINGS")
    return origin,key

async def relay_worker(data):
    from .relay import RelayClient
    harden()
    origin,key=relay_settings(data)
    client=RelayClient(origin,key)
    del key
    await client.run()

async def demo(data,web_dir):
    import uvicorn
    from .archive import Archive
    from .redaction import Redactor
    from .broker import ReadBroker
    from .admin import AdminService
    from .ui import create_ui,AdminGate
    from .mcp_server import create_app
    # Demo intentionally has no HA credentials, no broker IPC and no remote binding.
    os.environ.pop("SUPERVISOR_TOKEN",None)
    for name in ("private","public","query"): (data/name).mkdir(parents=True,exist_ok=True)
    store=initialize(data,"import_only")
    archive=Archive(data/"public/archive.sqlite",Redactor(secret_file(data/"private/redaction.key")))
    broker=ReadBroker(lambda:broker_policy(store),archive.redactor)
    admin=AdminService(archive,store,broker)
    ui=create_ui(admin,gate=AdminGate(demo=True),web_dir=web_dir)
    mcp=create_app(create_query(data))
    await asyncio.gather(uvicorn.Server(uvicorn.Config(ui,host="127.0.0.1",port=8099,access_log=False,proxy_headers=False,log_level="critical")).serve(),uvicorn.Server(uvicorn.Config(mcp,host="127.0.0.1",port=8000,access_log=False,proxy_headers=False,log_level="critical")).serve())

def clean_environment():
    # No inherited credentials, proxies, arbitrary Python module paths or logging config.
    return {"PATH":"/usr/local/bin:/usr/bin:/bin","LANG":"C.UTF-8","PYTHONUNBUFFERED":"1","PYTHONDONTWRITEBYTECODE":"1","PYTHONPATH":str(Path(__file__).resolve().parents[1])}

def bootstrap(data,profile,options,web_dir):
    if sys.platform!="linux" or os.geteuid()!=0: raise RuntimeError("LINUX_ROOT_BOOTSTRAP_REQUIRED; use --demo for local import-only testing")
    harden();os.umask(0o027)
    token_pipe=os.environ.pop("HAD_BOOTSTRAP_TOKEN_FD",None)
    # All root metadata changes finish before any unprivileged child is spawned.
    # Neither symlinks nor hardlinks in a prior worker's storage may affect an
    # image inode or another role's credential during restart.
    transport=prepare_bootstrap_storage(data,profile)
    def spawn(role,uid,gid,env=None,pass_fds=()):
        def drop():
            os.setgroups([UI_UID] if role=="broker" else []);os.setgid(gid);os.setuid(uid);harden()
        args=[sys.executable,"-m","ha_diagnostics.runtime","--role",role,"--data",str(data),"--web",str(web_dir),"--profile",profile]
        environment=clean_environment() | (env or {})
        if role=="ui": environment["HAD_ADMIN_ID"]=options.get("ingress_admin_id","")
        return subprocess.Popen(args,env=environment,preexec_fn=drop,pass_fds=pass_fds)
    if token_pipe is not None:r=int(token_pipe)
    else:
        r,w=os.pipe();os.close(w)
    children=[spawn("broker",BROKER_UID,READ_GROUP,{"HAD_TOKEN_FD":str(r)},(r,))];os.close(r)
    try:
        deadline=time.monotonic()+30
        while not (data/"public/archive.sqlite").exists() or not (data/"ipc/admin.sock").exists():
            if children[0].poll() is not None or time.monotonic()>deadline: raise RuntimeError("BROKER_START_FAILED")
            time.sleep(.1)
        children.extend([spawn("query",QUERY_UID,READ_GROUP),spawn("ui",UI_UID,UI_UID)])
        if transport.get("relay"):
            children.append(spawn("relay",TRANSPORT_UID,TRANSPORT_UID))
        if "tunnel_id" in transport:
            tunnel_id=transport["tunnel_id"]
            key_path=data/"transport/control-plane-api-key"
            environment=clean_environment()|{"CONTROL_PLANE_TUNNEL_ID":tunnel_id,"MCP_SERVER_URL":"http://127.0.0.1:8000/mcp","CONTROL_PLANE_POLL_CHANNELS":"main","HARPOON_TARGETS":"","HEALTH_LISTEN_ADDR":"127.0.0.1:0","CONTROL_PLANE_MAX_INFLIGHT_REQUESTS":"2"}
            def drop_transport(): os.setgroups([]);os.setgid(TRANSPORT_UID);os.setuid(TRANSPORT_UID);harden()
            import platform
            machine=platform.machine();arch="arm64" if machine=="aarch64" else "amd64" if machine=="x86_64" else "unsupported"
            binary=web_dir.parent/"tunnel"/arch/"tunnel-client-runtime"
            if not binary.is_file(): raise RuntimeError("TUNNEL_BINARY_UNAVAILABLE")
            children.append(subprocess.Popen([str(binary),"run","--control-plane.api-key=file:"+str(key_path)],env=environment,preexec_fn=drop_transport,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
        while all(p.poll() is None for p in children): time.sleep(.5)
        raise RuntimeError("WORKER_STOPPED")
    finally:
        for p in children:
            if p.poll() is None:p.terminate()
        for p in children:
            try:p.wait(timeout=5)
            except subprocess.TimeoutExpired:p.kill()

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--demo",action="store_true")
    parser.add_argument("--role",choices=["broker","query","ui","relay"])
    parser.add_argument("--data",type=Path,default=Path("/data"))
    parser.add_argument("--web",type=Path,default=Path(__file__).resolve().parents[2]/"web")
    parser.add_argument("--profile",choices=["import_only","live"],default=os.environ.get("HAD_PROFILE","import_only"))
    args=parser.parse_args();data=Path(os.path.abspath(args.data))
    try:
        if sys.platform=="linux" and not args.role and not args.demo and os.environ.get("HAD_BOOTSTRAP_CLEAN")!="1":
            # unsetenv cannot erase Linux's original /proc/environ. Replace bootstrap
            # process before any long-lived worker, passing live credentials only by FD.
            token=os.environ.get("SUPERVISOR_TOKEN","") if args.profile=="live" else ""
            if len(token.encode())>8192:raise RuntimeError("CREDENTIAL_LIMIT")
            r,w=os.pipe();os.set_inheritable(r,True)
            if token:os.write(w,token.encode())
            os.close(w)
            environment=clean_environment()|{"HAD_BOOTSTRAP_CLEAN":"1","HAD_BOOTSTRAP_TOKEN_FD":str(r),"HAD_PROFILE":args.profile}
            os.execve(sys.executable,[sys.executable,"-m","ha_diagnostics.runtime",*sys.argv[1:]],environment)
        if args.demo: asyncio.run(demo(data,args.web));return
        if args.role=="broker":asyncio.run(broker_worker(data,args.profile))
        elif args.role=="query":asyncio.run(query_worker(data))
        elif args.role=="ui":asyncio.run(ui_worker(data,args.web,{"ingress_admin_id":os.environ.get("HAD_ADMIN_ID","")}))
        elif args.role=="relay":asyncio.run(relay_worker(data))
        else:
            options=read_bootstrap_options(data)
            bootstrap(data,args.profile,options,args.web)
    except KeyboardInterrupt: pass
    except Exception:
        # No tracebacks or credentials in process output.
        print("HA-Diagnostics: STARTUP_OR_RUNTIME_FAILED; consult local acceptance runbook.",file=sys.stderr);raise SystemExit(1)

if __name__=="__main__":main()

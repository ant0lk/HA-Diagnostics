import json

import pytest

from ha_diagnostics.local_setup import provision
from ha_diagnostics import runtime


def test_relay_worker_reads_fixed_files_and_sanitized_environment(tmp_path, monkeypatch):
    provision(tmp_path, relay_origin="https://relay.example.test",relay_device_key="SYNTHETIC_RELAY_KEY")
    assert runtime.relay_settings(tmp_path)==("https://relay.example.test","SYNTHETIC_RELAY_KEY")
    monkeypatch.setenv("SUPERVISOR_TOKEN","SYNTHETIC_HA_KEY")
    monkeypatch.setenv("CONTROL_PLANE_API_KEY","SYNTHETIC_TUNNEL_KEY")
    monkeypatch.setenv("HAD_TOKEN_FD","100")
    clean=runtime.clean_environment()
    assert not {"SUPERVISOR_TOKEN","CONTROL_PLANE_API_KEY","HAD_TOKEN_FD"}&set(clean)
    assert "SYNTHETIC" not in json.dumps(clean)


@pytest.mark.parametrize("config",[
    {"origin":"http://relay.example.test"},
    {"origin":"https://relay.example.test/path"},
    {"origin":"https://relay.example.test","url":"http://supervisor/core/restart"},
    [],
])
def test_relay_settings_reject_paths_and_extra_config(tmp_path,config):
    (tmp_path/"transport").mkdir()
    (tmp_path/"transport/relay.json").write_text(json.dumps(config))
    (tmp_path/"transport/relay-device-key").write_text("synthetic-key")
    with pytest.raises((RuntimeError,ValueError)):runtime.relay_settings(tmp_path)


async def test_relay_worker_uses_its_device_key_only(tmp_path,monkeypatch):
    import ha_diagnostics.relay as relay
    provision(tmp_path,relay_origin="https://relay.example.test",relay_device_key="SYNTHETIC_RELAY_KEY")
    monkeypatch.setattr(runtime,"harden",lambda:None)
    used=[]
    class StubRelay:
        def __init__(self,origin,key):used.append((origin,key))
        async def run(self):used.append("running")
    monkeypatch.setattr(relay,"RelayClient",StubRelay)
    await runtime.relay_worker(tmp_path)
    assert used==[("https://relay.example.test","SYNTHETIC_RELAY_KEY"),"running"]


def test_bootstrap_spawns_relay_under_transport_uid_without_ha_fd(tmp_path,monkeypatch):
    provision(tmp_path,relay_origin="https://relay.example.test",relay_device_key="SYNTHETIC_RELAY_KEY")
    monkeypatch.setattr(runtime.sys,"platform","linux")
    monkeypatch.setattr(runtime.os,"geteuid",lambda:0,raising=False)
    monkeypatch.setattr(runtime,"harden",lambda:None)
    monkeypatch.delenv("HAD_BOOTSTRAP_TOKEN_FD",raising=False)
    calls=[]
    def prepare(data,profile):
        (data/"public").mkdir();(data/"ipc").mkdir()
        calls.append(("prepared",None,None))
        return {"relay":True}
    monkeypatch.setattr(runtime,"prepare_bootstrap_storage",prepare)
    class Process:
        def __init__(self,role):self.role=role
        def poll(self):return 1 if self.role=="relay" else None
        def terminate(self):pass
        def wait(self,timeout):return 0
    def popen(args,**kwargs):
        role=args[args.index("--role")+1]
        calls.append((role,args,kwargs))
        if role=="broker":
            (tmp_path/"public/archive.sqlite").touch()
            (tmp_path/"ipc/admin.sock").touch()
        return Process(role)
    monkeypatch.setattr(runtime.subprocess,"Popen",popen)
    with pytest.raises(RuntimeError,match="WORKER_STOPPED"):
        runtime.bootstrap(tmp_path,"import_only",{},tmp_path/"web")
    assert calls[0][0]=="prepared"
    role,args,kwargs=next(c for c in calls if c[0]=="relay")
    assert kwargs["pass_fds"]==()
    assert not {"SUPERVISOR_TOKEN","HAD_TOKEN_FD"}&set(kwargs["env"])
    assert "SYNTHETIC" not in json.dumps(args)+json.dumps(kwargs["env"])
    identity=[]
    monkeypatch.setattr(runtime.os,"setgroups",lambda groups:identity.append(("groups",groups)),raising=False)
    monkeypatch.setattr(runtime.os,"setgid",lambda gid:identity.append(("gid",gid)),raising=False)
    monkeypatch.setattr(runtime.os,"setuid",lambda uid:identity.append(("uid",uid)),raising=False)
    kwargs["preexec_fn"]()
    assert identity==[("groups",[]),("gid",10004),("uid",10004)]

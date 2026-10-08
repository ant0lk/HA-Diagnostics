import asyncio
import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx
import pytest

from gateway.local_enrollment import EnrollmentDenied,EnrollmentStore,main as gateway_cli
from gateway.ha_diagnostics_gateway import create_gateway
from gateway.ha_diagnostics_gateway import Gateway
from ha_diagnostics.auth import Principal
from ha_diagnostics.local_setup import SetupError,enroll_relay,main as addon_cli
from ha_diagnostics.policy import LocalPolicy,PolicyStore

INSTALLATION="installation_fixture_12345"


def store_at(data,*,clock=lambda:1000.):
    policies=PolicyStore(data/"policy.json")
    policies.write(LocalPolicy(installation_id=INSTALLATION))
    return EnrollmentStore(data,policies,clock=clock)


def test_cli_prints_path_only_and_state_stores_code_hash(tmp_path,capsys):
    store_at(tmp_path)
    assert gateway_cli(["--data",str(tmp_path),"issue","--ttl","300"])==0
    code=(tmp_path/"enrollment-code.private").read_text()
    state=json.loads((tmp_path/"enrollment-state.json").read_text())
    captured=capsys.readouterr()
    assert len(code)==64 and code not in captured.out+captured.err
    assert "ENROLLMENT_CODE_FILE=" in captured.out
    assert state["code_hash"]==hashlib.sha256(code.encode()).hexdigest()
    assert code not in json.dumps(state) and state["expires_at"]-state["issued_at"]==300
    assert not (tmp_path/"device-channel-key").exists()


def test_single_use_key_is_unique_and_code_file_removed(tmp_path):
    store=store_at(tmp_path)
    path=store.issue()
    code=path.read_text()
    result=store.consume({"installation_id":INSTALLATION,"code":code})
    assert len(result["device_key"])==64 and result["device_key"]!=code
    assert (tmp_path/"device-channel-key").read_text()==result["device_key"]
    assert not path.exists()
    with pytest.raises(EnrollmentDenied):store.consume({"installation_id":INSTALLATION,"code":code})
    assert json.loads((tmp_path/"enrollment-state.json").read_text())["used"] is True


@pytest.mark.parametrize("kind",["wrong_code","wrong_id","expired","future","extra","wrong_type"])
def test_invalid_enrollment_never_issues_key_or_exposes_secret(tmp_path,kind,capsys):
    now=[1000.]
    store=store_at(tmp_path,clock=lambda:now[0])
    code=store.issue(ttl=300).read_text()
    request={"installation_id":INSTALLATION,"code":code}
    if kind=="wrong_code":request["code"]="f"*64
    if kind=="wrong_id":request["installation_id"]="other_installation_12345"
    if kind=="expired":now[0]=1300.
    if kind=="future":now[0]=999.
    if kind=="extra":request["url"]="http://supervisor/core/restart"
    if kind=="wrong_type":request["code"]=False
    with pytest.raises(EnrollmentDenied) as error:store.consume(request)
    assert str(error.value)=="ENROLLMENT_DENIED"
    assert code not in str(error.value)+capsys.readouterr().out
    assert not (tmp_path/"device-channel-key").exists()


def test_issue_rotation_and_invalidation_remove_old_channel_key(tmp_path):
    store=store_at(tmp_path)
    first=store.issue().read_text()
    key=store.consume({"installation_id":INSTALLATION,"code":first})["device_key"]
    second=store.issue().read_text()
    assert second!=first and not (tmp_path/"device-channel-key").exists()
    new=store.consume({"installation_id":INSTALLATION,"code":second})["device_key"]
    assert new!=key
    store.invalidate()
    assert not any((tmp_path/name).exists() for name in ("device-channel-key","enrollment-state.json","enrollment-code.private"))


@pytest.mark.parametrize("ttl",[0,301,True])
def test_ttl_bounded_and_default_local_id_rejected(tmp_path,ttl):
    store=store_at(tmp_path)
    with pytest.raises(EnrollmentDenied):store.issue(ttl)
    store.policies.write(LocalPolicy())
    with pytest.raises(EnrollmentDenied):store.issue()


async def test_gateway_finite_enroll_endpoint_and_dynamic_revocation_cancels_pending(tmp_path):
    store=store_at(tmp_path)
    # create_gateway uses the current clock for enrollment; replace for fixture.
    code=store.issue().read_text()
    gateway=create_gateway(tmp_path)
    gateway.enrollment=store
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=gateway.app()),base_url="https://gateway.example.test") as client:
        response=await client.post("/channel/enroll",json={"installation_id":INSTALLATION,"code":code})
        assert response.status_code==200 and response.headers["Cache-Control"]=="no-store"
        key=response.json()["device_key"]
        denied=await client.post("/channel/enroll",json={"installation_id":INSTALLATION,"code":code})
        assert denied.status_code==401 and denied.json()=={"error":"ENROLLMENT_DENIED"}
        assert (await client.get("/channel/enroll")).status_code==405
        assert (await client.post("/channel/enroll",content=b"x"*1025)).status_code==401
        task=asyncio.create_task(client.post("/mcp",json={"jsonrpc":"2.0","id":1,"method":"tools/list"}))
        for _ in range(100):
            if gateway.pending:break
            await asyncio.sleep(.001)
        assert gateway.pending
        store.invalidate()
        # File reload gates every channel request; old key immediately denied.
        assert (await client.post("/channel/result",headers={"Authorization":"Bearer "+key},json={})).status_code==401
        result=await asyncio.wait_for(task,1)
        assert result.status_code==503 and result.json()["error"]=="CHANNEL_REVOKED"
        assert not gateway.pending


def setup_addon(data):
    (data/"public").mkdir()
    PolicyStore(data/"public/policy.json").write(LocalPolicy(installation_id=INSTALLATION))


def test_addon_enrollment_only_fixed_https_request_and_private_storage(tmp_path,capsys):
    setup_addon(tmp_path)
    sent=[]
    key="d"*64
    def upstream(request):
        sent.append(request)
        assert json.loads(request.content)=={"installation_id":INSTALLATION,"code":"a"*64}
        return httpx.Response(200,json={"installation_id":INSTALLATION,"device_key":key})
    with httpx.Client(transport=httpx.MockTransport(upstream)) as client:
        enroll_relay(tmp_path,"https://gateway.example.test","a"*64,client=client)
    assert len(sent)==1 and sent[0].method=="POST"
    assert str(sent[0].url)=="https://gateway.example.test/channel/enroll"
    assert "Authorization" not in sent[0].headers
    assert (tmp_path/"transport/relay-device-key").read_text()==key
    metadata=(tmp_path/"transport/relay.json").read_text()
    assert key not in metadata and "a"*64 not in metadata
    assert "a"*64 not in capsys.readouterr().out


@pytest.mark.parametrize("kind",["redirect","huge","wrong_id","extra","wrong_type","duplicate"])
def test_addon_enrollment_response_refused_before_secret_saved(tmp_path,kind):
    setup_addon(tmp_path)
    sent=[]
    def upstream(request):
        sent.append(request)
        if kind=="redirect":return httpx.Response(302,headers={"Location":"https://attacker.example.test/stolen"})
        if kind=="huge":return httpx.Response(200,content=b"x"*2049)
        if kind=="duplicate":return httpx.Response(200,content=(f'{{"installation_id":"{INSTALLATION}","device_key":"'+"d"*64+'","device_key":"'+"e"*64+'"}').encode())
        body={"installation_id":INSTALLATION,"device_key":"d"*64}
        if kind=="wrong_id":body["installation_id"]="other_installation_12345"
        if kind=="extra":body["url"]="http://supervisor/core/restart"
        if kind=="wrong_type":body["device_key"]=False
        return httpx.Response(200,json=body)
    with httpx.Client(transport=httpx.MockTransport(upstream)) as client:
        with pytest.raises(SetupError,match="ENROLLMENT_DENIED"):
            enroll_relay(tmp_path,"https://gateway.example.test","a"*64,client=client)
    assert len(sent)==1 and not (tmp_path/"transport/relay-device-key").exists()


def test_addon_cli_code_getpass_and_never_output(tmp_path,monkeypatch,capsys):
    setup_addon(tmp_path)
    captured=[]
    monkeypatch.setattr("builtins.input",lambda _:"https://gateway.example.test")
    monkeypatch.setattr("getpass.getpass",lambda _:"a"*64)
    monkeypatch.setattr("ha_diagnostics.local_setup.enroll_relay",lambda data,origin,code:captured.append((origin,code)))
    assert addon_cli(["--data",str(tmp_path),"--enroll-relay"])==0
    output=capsys.readouterr()
    assert "a"*64 not in output.out+output.err and "CHANNEL_ENROLLED" in output.out
    assert captured==[("https://gateway.example.test","a"*64)]


def test_addon_tunnel_conflict_does_not_send_code(tmp_path):
    setup_addon(tmp_path)
    (tmp_path/"transport").mkdir()
    (tmp_path/"transport/tunnel.json").write_text('{"tunnel_id":"tunnel_fixture12345"}')
    with httpx.Client(transport=httpx.MockTransport(lambda request:pytest.fail("must not send"))) as client:
        with pytest.raises(SetupError,match="TRANSPORT_CONFLICT"):
            enroll_relay(tmp_path,"https://gateway.example.test","a"*64,client=client)


def test_concurrent_code_consumption_issues_exactly_one_key(tmp_path):
    store=store_at(tmp_path)
    code=store.issue().read_text()
    def consume(_):
        independent=EnrollmentStore(tmp_path,store.policies,clock=lambda:1000.)
        try:return independent.consume({"installation_id":INSTALLATION,"code":code})
        except EnrollmentDenied:return None
    with ThreadPoolExecutor(max_workers=2) as executor:
        results=list(executor.map(consume,range(2)))
    valid=[r for r in results if r]
    assert len(valid)==1 and (tmp_path/"device-channel-key").read_text()==valid[0]["device_key"]


def test_policy_installation_change_invalidates_previous_code(tmp_path):
    store=store_at(tmp_path)
    code=store.issue().read_text()
    store.policies.write(LocalPolicy(installation_id="other_installation_12345"))
    with pytest.raises(EnrollmentDenied):
        store.consume({"installation_id":"other_installation_12345","code":code})
    assert not (tmp_path/"device-channel-key").exists()


def authorized_gateway(tmp_path,*,scopes=frozenset({"diagnostics:read","history:read","artifacts:read"}),verifier=None):
    policy=PolicyStore(tmp_path/"policy.json")
    policy.write(LocalPolicy(installation_id=INSTALLATION,owner_sub="fixture-owner",remote_enabled=True))
    class Verifier:
        async def verify(self,token):
            return Principal("fixture-owner",scopes,time.time()+300)
    return Gateway(policy,"d"*64,verifier_factory=lambda config:verifier or Verifier())


async def test_global_admission_rejects_third_before_jwks_work(tmp_path):
    release=asyncio.Event()
    called=[]
    class SlowVerifier:
        async def verify(self,token):
            called.append(token)
            await release.wait()
            return Principal("fixture-owner",frozenset({"diagnostics:read"}),time.time()+300)
    gateway=authorized_gateway(tmp_path,verifier=SlowVerifier())
    body={"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_diagnostics_status","arguments":{}}}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=gateway.app()),base_url="https://gateway.example.test") as client:
        tasks=[asyncio.create_task(client.post("/mcp",json=body,headers={"Authorization":"Bearer synthetic"})) for _ in range(2)]
        try:
            for _ in range(100):
                if len(called)==2:break
                await asyncio.sleep(.001)
            assert len(called)==2
            third=await client.post("/mcp",json=body,headers={"Authorization":"Bearer synthetic-third"})
            assert third.status_code==429 and third.headers["Retry-After"]=="1"
            assert len(called)==2
            release.set()
            for _ in range(100):
                if len(gateway.pending)==2:break
                await asyncio.sleep(.001)
            for item in gateway.pending.values():item.future.set_result({"status":200,"body":{"ok":True}})
            results=await asyncio.gather(*tasks)
            assert all(r.status_code==200 for r in results) and gateway.mcp_active==0
        finally:
            for task in tasks:task.cancel()
            await asyncio.gather(*tasks,return_exceptions=True)


async def test_valid_oauth_rate_limit_and_incident_requires_both_scopes(tmp_path):
    gateway=authorized_gateway(tmp_path)
    gateway.tool_calls.extend([time.monotonic()]*30)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=gateway.app()),base_url="https://gateway.example.test") as client:
        body={"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_diagnostics_status","arguments":{}}}
        denied=await client.post("/mcp",json=body,headers={"Authorization":"Bearer synthetic"})
        assert denied.status_code==429 and denied.json()=={"error":"RATE_LIMITED"} and not gateway.pending
    gateway=authorized_gateway(tmp_path,scopes=frozenset({"diagnostics:read"}))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=gateway.app()),base_url="https://gateway.example.test") as client:
        body["params"]["name"]="get_incident_context"
        denied=await client.post("/mcp",json=body,headers={"Authorization":"Bearer synthetic"})
        assert denied.status_code==401 and not gateway.pending and not gateway.tool_calls


async def test_enrollment_admission_is_two_and_code_not_consumed_by_third(tmp_path):
    store=store_at(tmp_path)
    code=store.issue().read_text()
    gateway=create_gateway(tmp_path);gateway.enrollment=store
    release=asyncio.Event()
    async def slow_body():
        yield b"{"
        await release.wait()
        yield b"broken"
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=gateway.app()),base_url="https://gateway.example.test") as client:
        tasks=[asyncio.create_task(client.post("/channel/enroll",content=slow_body())) for _ in range(2)]
        try:
            for _ in range(100):
                if gateway.enrollment_active==2:break
                await asyncio.sleep(.001)
            third=await client.post("/channel/enroll",json={"installation_id":INSTALLATION,"code":code})
            assert third.status_code==429 and third.headers["Retry-After"]=="1"
            assert not (tmp_path/"device-channel-key").exists()
            release.set()
            responses=await asyncio.gather(*tasks)
            assert all(r.status_code==401 for r in responses) and gateway.enrollment_active==0
            enrolled=await client.post("/channel/enroll",json={"installation_id":INSTALLATION,"code":code})
            assert enrolled.status_code==200
        finally:
            for task in tasks:task.cancel()
            await asyncio.gather(*tasks,return_exceptions=True)


async def test_mcp_body_deadline_releases_admission_before_any_jwks(tmp_path,monkeypatch):
    import gateway.ha_diagnostics_gateway as module
    gateway=authorized_gateway(tmp_path)
    original=asyncio.wait_for
    async def shortened(awaitable,timeout):
        return await original(awaitable,.02 if timeout==30 else timeout)
    monkeypatch.setattr(module.asyncio,"wait_for",shortened)
    blocked=asyncio.Event()
    async def slow_body():
        yield b"{"
        await blocked.wait()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=gateway.app()),base_url="https://gateway.example.test") as client:
        response=await client.post("/mcp",content=slow_body())
        assert response.status_code==503 and gateway.mcp_active==0 and not gateway.pending

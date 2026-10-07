import asyncio
import importlib.util
import time
import pytest
import httpx
from ha_diagnostics.relay import RelayClient,validate_gateway
from ha_diagnostics.policy import LocalPolicy,PolicyStore
from pathlib import Path
from ha_diagnostics.auth import Principal
from ha_diagnostics.mcp_server import create_app
from test_query import context

spec=importlib.util.spec_from_file_location('gateway_module',Path('gateway/ha_diagnostics_gateway.py'))
import sys
gateway=importlib.util.module_from_spec(spec);sys.modules[spec.name]=gateway;spec.loader.exec_module(gateway)

@pytest.mark.parametrize('url',['http://example.com','https://example.com/path','https://user:pass@example.com','https://example.com?a=1','https://example.com#frag'])
def test_fixed_gateway_https_only(url):
    with pytest.raises(ValueError):validate_gateway(url)

@pytest.mark.asyncio
async def test_request_replay_expiry_and_no_arbitrary_path(tmp_path):
    policy=PolicyStore(tmp_path/'policy.json');policy.write(LocalPolicy())
    g=gateway.Gateway(policy,'d'*40);app=g.app()
    public=httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://gateway.example')
    seen=[]
    def local_response(r):
        seen.append(r)
        return httpx.Response(200,json={'jsonrpc':'2.0','id':1,'result':{'tools':[]}})
    relay=RelayClient('https://gateway.example','d'*40,client=public,local=httpx.AsyncClient(transport=httpx.MockTransport(local_response)))
    task=asyncio.create_task(public.post('/mcp',json={'jsonrpc':'2.0','id':1,'method':'tools/list','params':{}}))
    await asyncio.sleep(.01);await relay.step();response=await task
    assert response.status_code==200 and len(seen)==1
    assert str(seen[0].url)=='http://127.0.0.1:8000/mcp' and seen[0].method=='POST'
    assert not g.pending
    assert (await public.get('/channel/poll',headers={'Authorization':'Bearer wrong'})).status_code==401
    assert (await public.post('/channel/result',headers={'Authorization':'Bearer '+'d'*40},json={'request_id':'old','nonce':'old','status':200,'body':{},'content_type':'application/json'})).status_code==400
    denied=await public.post('/mcp',json={'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':'restart','arguments':{}}});assert denied.status_code==401
    await public.aclose();await relay.local.aclose()


class FixtureVerifier:
    def __init__(self,config):pass
    async def verify(self,token):
        return Principal('owner',frozenset({'diagnostics:read','history:read','artifacts:read'}),time.time()+300)


class ArtifactVerifier(FixtureVerifier):
    async def verify(self,token):
        return Principal('owner',frozenset({'artifacts:read'}),time.time()+300)


def modern_request(method,name=None,arguments=None):
    from mcp_types import PROTOCOL_VERSION_META_KEY,CLIENT_CAPABILITIES_META_KEY,CLIENT_INFO_META_KEY
    params={'_meta':{PROTOCOL_VERSION_META_KEY:'2026-07-28',CLIENT_CAPABILITIES_META_KEY:{},CLIENT_INFO_META_KEY:{'name':'relay-fixture','version':'1'}}}
    headers={'MCP-Protocol-Version':'2026-07-28','MCP-Method':method}
    if name is not None:
        params.update(name=name,arguments=arguments or {})
        headers.update({'MCP-Name':name,'Authorization':'Bearer synthetic-relay-fixture'})
    return {'jsonrpc':'2.0','id':17,'method':method,'params':params},headers


async def through_relay(public,relay,g,body,headers):
    task=asyncio.create_task(public.post('/mcp',json=body,headers=headers))
    async def wait_for_queue():
        while g.queue.empty() and not task.done():await asyncio.sleep(0)
    await asyncio.wait_for(wait_for_queue(),3)
    if not task.done():await asyncio.wait_for(relay.step(),3)
    return await asyncio.wait_for(task,3)


@pytest.mark.asyncio
async def test_modern_protocol_through_gateway_relay_real_sdk(context):
    from mcp_types import HEADER_MISMATCH
    archive,policy,service,_=context
    artifact=archive.store_artifact('text','Relay evidence; token=RELAY_CANARY',approved=True)
    app=create_app(service,ArtifactVerifier)
    g=gateway.Gateway(policy,'d'*40,verifier_factory=FixtureVerifier)
    async with app.lifespan(app.app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=g.app()),base_url='https://gateway.example') as public:
            seen=[]
            async def record(request):seen.append(request)
            local=httpx.AsyncClient(transport=httpx.ASGITransport(app=app),event_hooks={'request':[record]})
            relay=RelayClient('https://gateway.example','d'*40,client=public,local=local)
            try:
                # Self-contained modern list and artifact-scoped call, with no
                # initialize or session. Both execute the installed SDK.
                body,headers=modern_request('tools/list')
                listed=await through_relay(public,relay,g,body,headers)
                assert listed.status_code==200,listed.text
                assert len(listed.json()['result']['tools'])==10
                body,headers=modern_request('tools/call','read_artifact',{'artifact_id':artifact})
                result=await through_relay(public,relay,g,body,headers)
                assert result.status_code==200,result.text
                assert result.json()['result']['isError'] is False
                assert 'Relay evidence' in result.json()['result']['structuredContent']['data']['content']
                assert 'RELAY_CANARY' not in result.text
                assert seen[-1].headers['mcp-name']=='read_artifact'
                assert seen[-1].headers['mcp-method']=='tools/call'
                assert str(seen[-1].url)=='http://127.0.0.1:8000/mcp'
                assert 'mcp-session-id' not in result.headers
                # Do not repair disagreement using values from the JSON body.
                bad_headers=headers|{'MCP-Name':'query_logs'}
                rejected=await through_relay(public,relay,g,body,bad_headers)
                assert rejected.status_code==400,rejected.text
                assert rejected.json()['error']['code']==HEADER_MISMATCH
                assert seen[-1].headers['mcp-name']=='query_logs'
                missing_method={key:value for key,value in headers.items() if key!='MCP-Method'}
                rejected=await through_relay(public,relay,g,body,missing_method)
                assert rejected.status_code==400 and rejected.json()['error']['code']==HEADER_MISMATCH
                assert 'mcp-method' not in seen[-1].headers
                # Duplicates cannot survive conversion to an envelope mapping:
                # the gateway rejects them before queuing or reaching the SDK.
                before=len(seen)
                duplicate=list(headers.items())+[('mcp-name','query_logs')]
                rejected=await through_relay(public,relay,g,body,duplicate)
                assert rejected.status_code==400 and rejected.json()['error']['code']==HEADER_MISMATCH
                assert len(seen)==before and not g.pending and g.queue.empty()
                for protocol in [None,'2025-11-25']:
                    wrong=dict(headers)
                    if protocol is None:wrong.pop('MCP-Protocol-Version')
                    else:wrong['MCP-Protocol-Version']=protocol
                    rejected=await through_relay(public,relay,g,body,wrong)
                    assert rejected.status_code==400 and rejected.json()['error']['code']==HEADER_MISMATCH
                    assert len(seen)==before and not g.pending and g.queue.empty()
                # Legacy notification acknowledgements carry no JSON body.
                notification={'jsonrpc':'2.0','method':'notifications/initialized'}
                acknowledged=await through_relay(public,relay,g,notification,{'MCP-Protocol-Version':'2025-11-25'})
                assert acknowledged.status_code==202 and acknowledged.content==b''
            finally:await local.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize('status',[403,429])
async def test_local_auth_and_rate_response_headers_survive_relay(context,status):
    _,policy,service,_=context
    if status==429:
        for _ in range(30):service.check_rate()
    app=create_app(service,ArtifactVerifier if status==403 else FixtureVerifier)
    g=gateway.Gateway(policy,'d'*40,verifier_factory=FixtureVerifier)
    async with app.lifespan(app.app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=g.app()),base_url='https://gateway.example') as public:
            local=httpx.AsyncClient(transport=httpx.ASGITransport(app=app))
            relay=RelayClient('https://gateway.example','d'*40,client=public,local=local)
            try:
                body,headers=modern_request('tools/call','get_diagnostics_status')
                response=await through_relay(public,relay,g,body,headers)
                assert response.status_code==status,response.text
                assert response.headers['cache-control']=='no-store'
                if status==403:
                    assert 'insufficient_scope' in response.headers['www-authenticate']
                    assert 'resource_metadata' in response.headers['www-authenticate']
                else:assert int(response.headers['retry-after'])>=1
            finally:await local.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize('routing',[{'mcp-protocol-version':'2026-07-28','url':'https://elsewhere.example'},
                                    {'mcp-protocol-version':'2026-07-28','authorization':'Bearer synthetic'},
                                    {'mcp-protocol-version':'2026-07-28','mcp-name':'read_artifact\r\nHost: elsewhere.example'},
                                    {'mcp-method':'tools/list'}])
async def test_relay_rejects_nonfinite_or_unsafe_header_carrier(routing):
    packet={'request_id':'fixture','nonce':'fixture','expires_at':time.time()+20,
            'body':{'jsonrpc':'2.0','id':1,'method':'tools/list','params':{}},
            'authorization':'','routing_headers':routing}
    called=[]
    local=httpx.AsyncClient(transport=httpx.MockTransport(lambda request:called.append(request)))
    public=httpx.AsyncClient(transport=httpx.MockTransport(lambda request:httpx.Response(200,json=packet)))
    relay=RelayClient('https://gateway.example','d'*40,client=public,local=local)
    try:
        with pytest.raises(ValueError,match='CHANNEL_INVALID_HEADERS'):await relay.step()
        assert not called
    finally:await public.aclose();await local.aclose()

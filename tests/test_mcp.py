import json
import time
import httpx
import pytest
from jsonschema import validate
from ha_diagnostics.mcp_server import create_app,tool_definitions
from ha_diagnostics.auth import Principal
from test_query import context

class Verifier:
    def __init__(self,config):pass
    async def verify(self,token):return Principal('owner',frozenset({'diagnostics:read','history:read','artifacts:read'}),time.time()+300)

def test_finite_schemas():
    tools=tool_definitions();assert len(tools)==10
    for t in tools:
        assert t.input_schema['additionalProperties'] is False and t.output_schema['additionalProperties'] is False
        assert t.annotations.read_only_hint and not t.annotations.destructive_hint
        assert t.meta['securitySchemes'][0]['type']=='oauth2'

@pytest.mark.asyncio
async def test_real_sdk_http_initialize_list_and_call(context):
    a,store,service,p=context
    app=create_app(service,Verifier)
    headers={'Accept':'application/json, text/event-stream','Content-Type':'application/json','MCP-Protocol-Version':'2025-11-25'}
    async with app.lifespan(app.app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://127.0.0.1:8000') as c:
            r=await c.post('/mcp',headers=headers,json={'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'test','version':'1'}}})
            assert r.status_code==200,r.text
            assert r.json()['result']['serverInfo']['version']=='1.0.0-alpha.1'
            listed=await c.post('/mcp',headers=headers,json={'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}})
            assert len(listed.json()['result']['tools'])==10
            denied=await c.post('/mcp',headers=headers,json={'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'get_diagnostics_status','arguments':{}}})
            assert denied.status_code==401 and 'resource_metadata' in denied.headers['www-authenticate']
            got=await c.post('/mcp',headers=headers|{'Authorization':'Bearer synthetic-token'},json={'jsonrpc':'2.0','id':4,'method':'tools/call','params':{'name':'get_diagnostics_status','arguments':{}}})
            result=got.json()['result'];assert result.get('isError') is False,result
            validate(result['structuredContent'],tool_definitions()[0].output_schema)
            invalid=await c.post('/mcp',headers=headers|{'Authorization':'Bearer synthetic-token'},json={'jsonrpc':'2.0','id':5,'method':'tools/call','params':{'name':'get_diagnostics_status','arguments':{'url':'http://supervisor/core/restart'}}})
            assert invalid.json()['error']['code']==-32602,invalid.text
            unknown=await c.post('/mcp',headers=headers|{'Authorization':'Bearer synthetic-token'},json={'jsonrpc':'2.0','id':6,'method':'tools/call','params':{'name':'restart','arguments':{}}})
            assert unknown.json()['error']['code']==-32601
            body=await c.post('/mcp',headers=headers,content='x'*32769);assert body.status_code==413
            rebind=await c.post('/mcp',headers=headers|{'Host':'evil.example'},json={'jsonrpc':'2.0','id':7,'method':'tools/list','params':{}});assert rebind.status_code==421
            discovery=await c.get('/.well-known/oauth-protected-resource');assert discovery.status_code==200

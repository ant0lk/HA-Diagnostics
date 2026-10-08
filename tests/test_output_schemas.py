"""Every published tool output validates real cleaned fixture results."""
import copy
import json
import time

import httpx
import pytest
from jsonschema import ValidationError as JsonSchemaError, validate
from pydantic import ValidationError

from ha_diagnostics.auth import Principal
from ha_diagnostics.mcp_server import create_app, tool_definitions
from ha_diagnostics.schemas import OUTPUTS
from ha_diagnostics.timeutil import utc_now
from test_query import context


@pytest.mark.asyncio
async def test_all_ten_outputs_validate_real_fixture_results(context):
    archive,store,service,principal=context
    now=utc_now()
    archive.append_transition({"source_id":"entities","entity_ref":"ent_abc","event_time":"2026-10-07T10:05:00Z","observed_at":now,"old_state":False,"new_state":0,"origin":"state_changed","safe_attributes":{"battery":0}})
    archive.upsert_metadata({"kind":"entity_snapshot","entity_ref":"ent_abc","observed_at":now,"safe_fields":{"state":False,"last_changed":"2026-10-07T10:05:00Z"},"origin":"current_snapshot"})
    artifact=archive.store_artifact("text","Synthetic imported fixture",approved=True)
    record=archive.query_logs(["core"],"2026-10-07T09:00:00Z","2026-10-07T11:00:00Z")["records"][0]["record_id"]
    interval={"from":"2026-10-07T09:00:00Z","to":"2026-10-07T11:00:00Z"}
    arguments={
        "get_diagnostics_status":{},"find_devices":{"query":"dev_abc"},
        "get_device_context":{"device_ref":"dev_abc"},
        "query_logs":{"source_ids":["core"],**interval},
        "get_log_record":{"record_id":record,"before":1,"after":1},
        "get_entity_history":{"entity_refs":["ent_abc"],**interval},
        "get_incident_context":{"device_ref":"dev_abc",**interval},
        "summarize_errors":{"source_ids":["core"],**interval},
        "list_artifacts":{},"read_artifact":{"artifact_id":artifact},
    }
    definitions={tool.name:tool for tool in tool_definitions()}
    for name,args in arguments.items():
        result=await service.call(name,args,principal)
        assert result["error_code"] is None,(name,result)
        OUTPUTS[name].model_validate(result)
        validate(result,definitions[name].output_schema)
        wrong=copy.deepcopy(result);wrong["data"]["unexpected_secret"]="synthetic_canary"
        with pytest.raises(ValidationError):OUTPUTS[name].model_validate(wrong)
        with pytest.raises(JsonSchemaError):validate(wrong,definitions[name].output_schema)
        failure=copy.deepcopy(result);failure.update(data={},coverage=[],error_code="ACCESS_DENIED",next_cursor=None)
        OUTPUTS[name].model_validate(failure)
        validate(failure,definitions[name].output_schema)


def test_incident_oauth_advertises_both_required_scopes():
    tool=next(t for t in tool_definitions() if t.name=="get_incident_context")
    assert tool.meta["securitySchemes"][0]["scopes"]==["diagnostics:read","history:read"]


class LimitedScopeVerifier:
    def __init__(self,config):pass
    async def verify(self,token):
        return Principal("owner",frozenset({"diagnostics:read"}),time.time()+300)


@pytest.mark.asyncio
async def test_http_scope_denial_and_rate_limit_before_sdk_queries(context):
    archive,store,service,principal=context
    app=create_app(service,LimitedScopeVerifier)
    headers={"Accept":"application/json, text/event-stream","Content-Type":"application/json","Authorization":"Bearer synthetic"}
    async with app.lifespan(app.app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url="http://127.0.0.1:8000") as client:
            denied=await client.post("/mcp",headers=headers,json={"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_incident_context","arguments":{"device_ref":"dev_abc","from":"2026-10-07T09:00:00Z","to":"2026-10-07T11:00:00Z"}}})
            assert denied.status_code==403
            assert "history:read" in denied.headers["www-authenticate"]
            for _ in range(30):service.check_rate()
            limited=await client.post("/mcp",headers=headers,json={"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_diagnostics_status","arguments":{}}})
            assert limited.status_code==429
            assert int(limited.headers["retry-after"])>=1


@pytest.mark.asyncio
async def test_auth_inflight_limit_rejects_before_verifier(context):
    _,_,service,_=context
    app=create_app(service,LimitedScopeVerifier)
    await app.inflight.acquire();await app.inflight.acquire()
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url="http://127.0.0.1:8000") as client:
            response=await client.post("/mcp",headers={"Authorization":"Bearer synthetic"},content=b"{}");assert response.status_code==429
            assert response.headers["retry-after"]=="1"
    finally:
        app.inflight.release();app.inflight.release()


class ArtifactsOnlyVerifier:
    def __init__(self,config):pass
    async def verify(self,token):
        return Principal("owner",frozenset({"artifacts:read"}),time.time()+300)


@pytest.mark.asyncio
async def test_modern_sdk_per_request_artifact_scope_and_header_consistency(context):
    from mcp_types import PROTOCOL_VERSION_META_KEY,CLIENT_CAPABILITIES_META_KEY,CLIENT_INFO_META_KEY,HEADER_MISMATCH
    archive,store,service,_=context
    artifact=archive.store_artifact("text","Synthetic modern MCP fixture",approved=True)
    app=create_app(service,ArtifactsOnlyVerifier)
    metadata={PROTOCOL_VERSION_META_KEY:"2026-07-28",CLIENT_CAPABILITIES_META_KEY:{},CLIENT_INFO_META_KEY:{"name":"fixture-modern-client","version":"1"}}
    headers={"Accept":"application/json, text/event-stream","Content-Type":"application/json","Authorization":"Bearer synthetic-artifact","MCP-Protocol-Version":"2026-07-28","MCP-Method":"tools/call","MCP-Name":"read_artifact"}
    body={"jsonrpc":"2.0","id":19,"method":"tools/call","params":{"name":"read_artifact","arguments":{"artifact_id":artifact},"_meta":metadata}}
    async with app.lifespan(app.app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url="http://127.0.0.1:8000") as client:
            # Modern path is self-contained: no initialize or session ID.
            response=await client.post("/mcp",headers=headers,json=body)
            assert response.status_code==200,response.text
            result=response.json()["result"]
            assert result["structuredContent"]["data"]["content"]=="Synthetic modern MCP fixture"
            assert not result.get("isError",False)
            assert "mcp-session-id" not in response.headers
            validate(result["structuredContent"],OUTPUTS["read_artifact"].model_json_schema(by_alias=True))
            mismatch=await client.post("/mcp",headers=headers|{"MCP-Name":"query_logs"},json=body)
            assert mismatch.status_code==400,mismatch.text
            assert mismatch.json()["error"]["code"]==HEADER_MISMATCH
            # Compact params are not the pinned SDK wire; auth recognizes their
            # artifact scope and SDK rejects the framing instead of false403.
            compact=await client.post("/mcp",headers=headers,json=body["params"])
            assert compact.status_code==400,compact.text

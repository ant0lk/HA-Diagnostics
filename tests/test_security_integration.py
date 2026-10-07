"""Cross-component regressions found while reviewing the separated workers."""
import json
import time

import pytest

from ha_diagnostics.archive import Archive
from ha_diagnostics.auth import Principal
from ha_diagnostics.cursors import CursorCodec
from ha_diagnostics.policy import LocalPolicy, PolicyStore, SourcePolicy
from ha_diagnostics.query import QueryService
from ha_diagnostics.redaction import Redactor
from ha_diagnostics.timeutil import utc_now

@pytest.mark.parametrize('entity_id',['geo_location.fixture','zone.home'])
def test_geographic_domains_are_not_permitted_diagnostic_entities(entity_id):
    with pytest.raises(ValueError):LocalPolicy(entity_ids=[entity_id])


@pytest.fixture
def security_context(tmp_path):
    archive = Archive(tmp_path / "archive.sqlite", Redactor(b"r" * 32), min_free_bytes=0)
    archive.register_source("entities", kind="history")
    archive.register_source("core", kind="log")
    observed = utc_now()
    archive.append_transition({"source_id": "entities", "entity_ref": "ent_fixture", "old_state": "off",
        "new_state": "PRIVATE_HISTORY_CANARY", "event_time": "2026-10-07T12:00:00Z", "observed_at": observed})
    archive.upsert_metadata({"device_ref": "dev_fixture", "entity_refs": ["ent_fixture"], "name": "PRIVATE_DEVICE_CANARY",
        "observed_at": observed, "related_source_ids": ["core"], "mapping_origin": "exact_registry"})
    archive.ingest_logs("core", "fixture_boot", "2026-10-07T12:00:00Z INFO PRIVATE_LOG_CANARY", observed)
    store = PolicyStore(tmp_path / "policy.json")
    store.write(LocalPolicy(remote_enabled=True, owner_sub="fixture_owner", entity_refs=["ent_fixture"],
        sources=[SourcePolicy(source_id="core", collect=True, disclose=True), SourcePolicy(source_id="entities", collect=True, disclose=False)]))
    service = QueryService(Archive.open_readonly(tmp_path / "archive.sqlite"), store, CursorCodec(b"c" * 32))
    principal = Principal("fixture_owner", frozenset({"diagnostics:read", "history:read", "artifacts:read"}), time.time() + 300)
    yield archive, store, service, principal
    service.archive.close()
    archive.close()


async def test_collected_but_not_disclosed_history_cannot_leave_mcp(security_context):
    _, _, service, principal = security_context
    result = await service.call("get_entity_history", {"entity_refs": ["ent_fixture"],
        "from": "2026-10-07T11:00:00Z", "to": "2026-10-07T13:00:00Z"}, principal)
    assert result["error_code"] == "ACCESS_DENIED"
    assert result["data"] == {} and "PRIVATE_HISTORY_CANARY" not in json.dumps(result)


async def test_collected_but_not_disclosed_device_mapping_hidden(security_context):
    _, _, service, principal = security_context
    result = await service.call("get_device_context", {"device_ref": "dev_fixture"}, principal)
    assert result["error_code"] == "ACCESS_DENIED"
    result = await service.call("find_devices", {"query": "dev_fixture"}, principal)
    assert result["data"]["devices"] == []
    assert "PRIVATE_DEVICE_CANARY" not in json.dumps(result)


async def test_owner_revokes_during_computed_result_before_disclosure(security_context, monkeypatch):
    _, store, service, principal = security_context
    original = service.archive.query_logs
    def revoke_after_read(*args, **kwargs):
        result = original(*args, **kwargs)
        store.write(store.read().model_copy(update={"remote_enabled": False}))
        return result
    monkeypatch.setattr(service.archive, "query_logs", revoke_after_read)
    result = await service.call("query_logs", {"source_ids": ["core"], "from": "2026-10-07T11:00:00Z", "to": "2026-10-07T13:00:00Z"}, principal)
    assert result["error_code"] == "ACCESS_DENIED" and result["data"] == {}
    assert "PRIVATE_LOG_CANARY" not in json.dumps(result)


async def test_source_disclosure_changes_during_result_before_send(security_context, monkeypatch):
    _, store, service, principal = security_context
    original = service.archive.query_logs
    def stop_disclosing_after_read(*args, **kwargs):
        result = original(*args, **kwargs)
        changed = store.read().model_copy(update={"sources": [SourcePolicy(source_id="core", collect=True, disclose=False)]})
        store.write(changed)
        return result
    monkeypatch.setattr(service.archive, "query_logs", stop_disclosing_after_read)
    result = await service.call("query_logs", {"source_ids": ["core"], "from": "2026-10-07T11:00:00Z", "to": "2026-10-07T13:00:00Z"}, principal)
    assert result["error_code"] == "POLICY_CHANGED" and result["data"] == {}
    assert "PRIVATE_LOG_CANARY" not in json.dumps(result)

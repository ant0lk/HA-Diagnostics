"""Connection panel contracts using HA fixtures, including disabled registry entries."""
from datetime import datetime, timedelta, timezone
import json

import httpx
import pytest
from pydantic import ValidationError

from ha_diagnostics.broker import BrokerError
from ha_diagnostics.connection import (ConnectionArgs, ConnectionEdit, ConnectionPanel,
    ConnectionStore, automatic_scale, metric_kind, quality_level)
from ha_diagnostics.export_sources import DemoExportSources
from ha_diagnostics.exporter import ExportService
from ha_diagnostics.ipc import ADMIN_OPERATIONS, IPCEnvelope
from ha_diagnostics.redaction import Redactor
from ha_diagnostics.ui import AdminGate, create_ui

NOW = datetime(2026, 10, 12, 4, 0, tzinfo=timezone.utc)


class Sources(DemoExportSources):
    def __init__(self):
        self.registry_reads = 0
        self.state_reads = 0
        self.fail_states = self.fail_registry = False
        self.rows = [
            {"id": "signal", "entity_id": "sensor.living_linkquality", "device_id": "device", "original_name": "Linkquality"},
            {"id": "disabled", "entity_id": "sensor.disabled_signal_strength", "disabled_by": "integration", "device_id": "device"},
            {"id": "custom", "entity_id": "sensor.temperature", "original_name": "Температура"},
            {"id": "switch", "entity_id": "switch.signal_strength"}]
        self.states = [
            {"entity_id": "sensor.living_linkquality", "state": "215", "attributes": {"unit_of_measurement": "lqi", "friendly_name": "Связь гостиной", "password": "DO_NOT_EXPOSE"},
             "last_updated": (NOW - timedelta(days=2)).isoformat(), "last_reported": (NOW - timedelta(seconds=12)).isoformat()},
            {"entity_id": "sensor.temperature", "state": "23", "attributes": {"unit_of_measurement": "°C"}, "last_updated": NOW.isoformat()},
            {"entity_id": "binary_sensor.gateway_connectivity", "state": "off", "attributes": {"device_class": "connectivity"}, "last_updated": NOW.isoformat()},
            {"entity_id": "sensor.random_name", "state": "-85", "attributes": {"device_class": "signal_strength", "unit_of_measurement": "dBm"}, "last_updated": NOW.isoformat()},
        ]

    async def registry(self, label):
        self.registry_reads += 1
        if self.fail_registry:
            raise BrokerError("UPSTREAM_UNAVAILABLE")
        if label == "entities":
            return self.rows
        if label == "devices":
            return [{"id": "device", "name": "Датчик", "area_id": "living"}]
        return [{"area_id": "living", "name": "Гостиная"}]

    async def snapshot(self, label):
        if label != "home_assistant/states":
            return await super().snapshot(label)
        self.state_reads += 1
        if self.fail_states:
            raise BrokerError("UPSTREAM_UNAVAILABLE")
        return self.states

    @staticmethod
    def scrub_known_secret(text):
        return text.replace("SOURCE_SECRET", "[REDACTED]")


@pytest.mark.parametrize("scale,values,expected", [
    ("lqi", [-1, 0, 50, 51, 101, 102, 152, 153, 203, 204, 255, 256], [None, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, None]),
    ("dbm", [-131, -100, -90, -80, -70, -60, 0, 1], [None, 1, 2, 3, 4, 5, 5, None]),
    ("percent", [-1, 0, 19.9, 20, 40, 60, 80, 100, 101], [None, 1, 1, 2, 3, 4, 5, 5, None]),
    ("snr", [-1, 5, 10, 20, 30], [1, 2, 3, 4, 5]),
    ("latency", [-1, 20, 20.1, 50, 50.1, 100.1, 250, 250.1], [None, 5, 4, 4, 3, 2, 2, 1]),
    ("packet_loss", [-1, 0, 1, 1.1, 5.1, 10.1, 25.1, 100, 101], [None, 5, 5, 4, 3, 2, 1, 1, None]),
])
def test_five_levels_at_boundaries(scale, values, expected):
    assert [quality_level(str(value), scale) for value in values] == expected


def test_unknown_values_inversion_and_seconds_are_not_miscoloured():
    for value in (None, "unknown", "nan", "inf", "invalid", ""):
        assert quality_level(value, "lqi") is None
    assert quality_level("215", "lqi", assumed=True) is None
    assert quality_level("unavailable", "lqi") == 1
    assert quality_level("off", "none", "connectivity") == 1
    assert quality_level("on", "none", "connectivity") == 5
    assert quality_level("on", "none", "disconnection") == 1
    assert quality_level("off", "none", "disconnection") == 5
    assert quality_level("offline", "none", "disconnection") == 1
    assert quality_level("online", "none", "disconnection") == 5
    assert quality_level("0.05", "latency", unit="s") == 4
    assert metric_kind("switch.linkquality", {}, {}) is None
    assert metric_kind("sensor.temperature", {}, {}) is None
    assert metric_kind("sensor.door_lqi", {}, {}) == "lqi"
    assert metric_kind("sensor.router_last_seen", {}, {}) == "last_seen"
    assert automatic_scale("signal", "%") == "percent"
    assert automatic_scale("lqi", "W") == "none"
    assert automatic_scale("signal", "°C") == "none"


@pytest.mark.asyncio
async def test_registry_disabled_entries_states_and_real_report_timestamp(tmp_path):
    sources = Sources()
    panel = ConnectionPanel(sources, Redactor(b"C" * 32), tmp_path / "panel.json", clock=lambda: NOW)
    data = await panel.panel(ConnectionArgs())
    rows = {row["entity_id"]: row for row in data["objects"]}
    assert set(rows) == {"sensor.living_linkquality", "sensor.disabled_signal_strength", "binary_sensor.gateway_connectivity", "sensor.random_name"}
    assert rows["sensor.living_linkquality"]["timestamp_source"] == "last_reported"
    assert rows["sensor.living_linkquality"]["updated_at"] == "2026-10-12T03:59:48Z"
    assert rows["sensor.living_linkquality"]["level"] == 5
    assert rows["sensor.living_linkquality"]["device_name"] == "Датчик"
    assert rows["sensor.living_linkquality"]["room_name"] == "Гостиная"
    assert rows["sensor.disabled_signal_strength"]["disabled"] is True
    assert rows["sensor.disabled_signal_strength"]["state"] is None
    assert rows["sensor.disabled_signal_strength"]["updated_at"] is None
    assert rows["sensor.random_name"]["scale"] == "dbm"
    assert rows["sensor.random_name"]["level"] == 2
    assert "DO_NOT_EXPOSE" not in json.dumps(data)
    await panel.panel(ConnectionArgs())
    assert sources.state_reads == 1 and sources.registry_reads == 3
    await panel.panel(ConnectionArgs(force=True))
    assert sources.state_reads == 2 and sources.registry_reads == 6


@pytest.mark.asyncio
async def test_hide_restore_custom_scale_restart_rename_and_removal(tmp_path):
    sources = Sources()
    key = Redactor(b"C" * 32)
    path = tmp_path / "panel.json"
    panel = ConnectionPanel(sources, key, path, clock=lambda: NOW)
    catalog = await panel.catalog(ConnectionArgs())
    refs = {row["entity_id"]: row["object_ref"] for row in catalog["objects"]}
    ref = refs["sensor.living_linkquality"]
    await panel.edit(ConnectionEdit(object_ref=ref, action="hide"))
    await panel.edit(ConnectionEdit(object_ref=refs["sensor.temperature"], action="add", scale="percent"))
    restarted = ConnectionPanel(sources, key, path, clock=lambda: NOW)
    data = await restarted.panel(ConnectionArgs())
    rows = {row["entity_id"]: row for row in data["objects"]}
    assert rows["sensor.living_linkquality"]["hidden"] is True
    assert rows["sensor.temperature"]["custom"] is True
    assert rows["sensor.temperature"]["level"] == 2
    await restarted.edit(ConnectionEdit(object_ref=ref, action="show"))
    sources.rows[2]["entity_id"] = "sensor.renamed_temperature"
    sources.states[1]["entity_id"] = "sensor.renamed_temperature"
    data = await restarted.panel(ConnectionArgs(force=True))
    row = next(row for row in data["objects"] if row["custom"])
    assert row["entity_id"] == "sensor.renamed_temperature"
    assert row["object_ref"] == refs["sensor.temperature"]
    sources.rows.pop(2)
    sources.states.pop(1)
    data = await restarted.panel(ConnectionArgs(force=True))
    row = next(row for row in data["objects"] if row["custom"])
    assert row["missing"] and row["state"] is None
    data = await restarted.edit(ConnectionEdit(object_ref=row["object_ref"], action="remove"))
    assert not any(row["custom"] for row in data["objects"])


@pytest.mark.asyncio
async def test_failed_reads_keep_a_dated_snapshot_and_registry_gap(tmp_path):
    sources = Sources()
    panel = ConnectionPanel(sources, Redactor(b"C" * 32), tmp_path / "panel.json", clock=lambda: NOW)
    first = await panel.panel(ConnectionArgs())
    sources.fail_states = sources.fail_registry = True
    failed = await panel.panel(ConnectionArgs(force=True))
    assert failed["objects"] == first["objects"]
    assert failed["states_error"] and failed["registry_error"]
    assert failed["observed_at"] == first["observed_at"]
    fresh = ConnectionPanel(sources, Redactor(b"C" * 32), tmp_path / "other.json", clock=lambda: NOW)
    assert (await fresh.panel(ConnectionArgs()))["observed_at"] is None


@pytest.mark.asyncio
async def test_invalid_settings_are_preserved_and_no_unknown_refs_can_be_added(tmp_path):
    path = tmp_path / "panel.json"
    path.write_text("broken settings", encoding="utf-8")
    panel = ConnectionPanel(Sources(), Redactor(b"C" * 32), path, clock=lambda: NOW)
    data = await panel.panel(ConnectionArgs())
    assert data["settings_error"] == "CONNECTION_SETTINGS_INVALID"
    with pytest.raises(BrokerError, match="CONNECTION_SETTINGS_INVALID"):
        await panel.edit(ConnectionEdit(object_ref=data["objects"][0]["object_ref"], action="hide"))
    assert path.read_text() == "broken settings"
    with pytest.raises(BrokerError, match="CONNECTION_OBJECT_NOT_FOUND"):
        await panel.edit(ConnectionEdit(object_ref="[HA_CONNECTION_0000000000000000]", action="add"))
    with pytest.raises(ValidationError):
        ConnectionEdit(object_ref="http://arbitrary.example/", action="add")
    with pytest.raises(ValidationError):
        ConnectionArgs(url="http://arbitrary.example/")


@pytest.mark.asyncio
async def test_timestamp_fallback_and_scrubbing_do_not_use_poll_time(tmp_path):
    sources = Sources()
    sources.states[0]["last_reported"] = "invalid"
    sources.states[0]["attributes"]["friendly_name"] = "SOURCE_SECRET"
    sources.states[0]["state"] = "SOURCE_SECRET"
    panel = ConnectionPanel(sources, Redactor(b"C" * 32), tmp_path / "panel.json", clock=lambda: NOW)
    row = next(row for row in (await panel.panel(ConnectionArgs()))["objects"] if row["entity_id"] == "sensor.living_linkquality")
    assert row["updated_at"] == "2026-10-10T04:00:00Z"
    assert row["timestamp_source"] == "last_updated"
    assert row["name"] == row["state"] == "[REDACTED]"
    assert row["level"] is None
    sources.states[0].pop("last_updated")
    assert next(row for row in (await panel.panel(ConnectionArgs(force=True)))["objects"] if row["entity_id"] == "sensor.living_linkquality")["updated_at"] is None


@pytest.mark.asyncio
async def test_owner_routes_csrf_validation_and_ipc_operations(tmp_path):
    service = ExportService(tmp_path / "exports", Sources(), Redactor(b"C" * 32), min_free_bytes=0, clock=lambda: NOW)
    gate = AdminGate("owner")
    app = create_ui(service, gate=gate, web_dir="web")
    headers = {"X-Remote-User-Id": "owner", "X-Ingress-Path": "/ingress", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": gate.csrf}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=("172.30.32.2", 1234)), base_url="http://localhost") as client:
        assert (await client.get("/api/connection")).status_code == 403
        assert (await client.get("/api/connection/catalog")).status_code == 403
        result = await client.get("/api/connection", headers=headers)
        assert result.status_code == 200 and result.headers["cache-control"] == "no-store"
        ref = result.json()["objects"][0]["object_ref"]
        for query in ("?force=1", "?force=true&force=false", "?url=http://evil.example"):
            assert (await client.get("/api/connection" + query, headers=headers)).status_code == 400
        catalog = await client.get("/api/connection/catalog", headers=headers)
        assert len(catalog.json()["objects"]) > len(result.json()["objects"])
        body = {"op": "set_connection_object", "args": {"object_ref": ref, "action": "hide"}}
        no_csrf = {key: value for key, value in headers.items() if key != "X-CSRF-Token"}
        assert (await client.post("/api/action", headers=no_csrf, json=body)).status_code == 403
        saved = await client.post("/api/action", headers=headers, json=body)
        assert saved.status_code == 200
        assert next(row for row in saved.json()["objects"] if row["object_ref"] == ref)["hidden"]
    for op in ("connection_objects", "connection_catalog", "set_connection_object"):
        assert op in ADMIN_OPERATIONS and op in service.handlers()
        assert IPCEnvelope(op=op, args={}).op == op
    await service.close()


@pytest.mark.asyncio
async def test_explicit_neutral_scale_and_failed_save_preserve_choices(tmp_path, monkeypatch):
    panel = ConnectionPanel(Sources(), Redactor(b"C" * 32), tmp_path / "panel.json", clock=lambda: NOW)
    data = await panel.panel(ConnectionArgs())
    ref = next(row["object_ref"] for row in data["objects"] if row["entity_id"] == "binary_sensor.gateway_connectivity")
    data = await panel.edit(ConnectionEdit(object_ref=ref, action="add", scale="none"))
    assert next(row["level"] for row in data["objects"] if row["object_ref"] == ref) is None
    before = (tmp_path / "panel.json").read_bytes()
    def fail_write(_):
        raise OSError("fixture disk failure")
    monkeypatch.setattr(panel.store, "write", fail_write)
    with pytest.raises(BrokerError, match="CONNECTION_SAVE_FAILED"):
        await panel.edit(ConnectionEdit(object_ref=ref, action="hide"))
    assert (tmp_path / "panel.json").read_bytes() == before
    assert not next(row["hidden"] for row in (await panel.panel(ConnectionArgs()))["objects"] if row["object_ref"] == ref)


def test_storage_rejects_hardlinks_and_bounded_reads(tmp_path):
    import os
    path = tmp_path / "panel.json"
    original = tmp_path / "original.json"
    original.write_text("{}", encoding="utf-8")
    os.link(original, path)
    with pytest.raises(ValueError, match="UNSAFE_CONNECTION_STORAGE"):
        ConnectionStore(path).read()
    path.unlink()
    path.write_bytes(b" " * (256 * 1024 + 1))
    with pytest.raises(ValueError, match="CONNECTION_SETTINGS_LIMIT"):
        ConnectionStore(path).read()

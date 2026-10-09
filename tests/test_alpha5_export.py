"""Alpha 5 contracts against saved fixtures and fixed mock read APIs."""
import asyncio
import hashlib
import json
from pathlib import Path
import zipfile

import httpx
import pytest

from ha_diagnostics.broker import BrokerError
from ha_diagnostics.export_configuration import ConfigurationReader
from ha_diagnostics.export_insights import LogCoverage, host_resources, network_context
from ha_diagnostics.export_sources import DemoExportSources, ExportSources, SourceResult, MAX_STATISTIC_IDS
from ha_diagnostics.exporter import ExportService, StartExportArgs
from ha_diagnostics.redaction import Redactor

ENTRY = "a" * 32
DEVICE = "b" * 32
TOKEN = "ALPHA5_SUPERVISOR_CANARY"
SECRET = "ALPHA5_PASSWORD_CANARY"


class ExpandedFixtures(DemoExportSources):
    version = "2026.9.4"
    fail_config = False
    config_value = 0
    reverse_registry = False

    async def snapshot(self, label):
        if label == "system/core":
            return {"version": self.version, "arch": "amd64", "machine": "generic-x86-64", "update_available": False}
        if label == "system/network":
            return {"interfaces": [{"interface": "enp1s0", "connected": True, "ipv6": {
                "address": ["fe80::1234%enp1s0/64", "fd00::1234/64"], "gateway": "fe80::1%enp1s0"},
                "ipv4": {"address": ["192.168.12.2/24"], "gateway": "192.168.12.1"}}]}
        return await super().snapshot(label)

    async def registry(self, label):
        if label == "devices":
            rows = [{"id": DEVICE, "config_entries": [ENTRY], "model": "Fixture device"},
                    {"id": "c" * 32, "config_entries": [], "model": "Other fixture device"}]
            return list(reversed(rows)) if self.reverse_registry else rows
        if label == "entities":
            return [{"entity_id": "sensor.fixture", "device_id": DEVICE}]
        if label == "integrations":
            return [{"entry_id": ENTRY, "domain": "demo", "state": "loaded"}]
        return []

    async def traces(self, domain):
        return [{"domain": domain, "item_id": "fixture", "run_id": "run1", "timestamp": {"start": "2026-10-08T11:00:00Z"}}]

    async def trace(self, domain, item_id, run_id):
        return {"domain": domain, "item_id": item_id, "run_id": run_id,
            "trace": {"action/0": [{"result": {"enabled": False, "count": 0},
                "changed_variables": {"password": SECRET}}]}, "config": {"sequence": []},
            "context": {"id": "context1", "parent_id": "parent1"}, "error": "fixture exception"}

    async def device(self, entry_id, device_id):
        if device_id == DEVICE:
            return {"entry_id": entry_id, "device_id": device_id, "battery": 0, "enabled": False, "password": SECRET}
        raise BrokerError("NOT_SUPPORTED")

    async def supplemental(self, label):
        if label == "statistics/metadata":
            return [{"statistic_id": f"sensor.energy_{n:03d}", "has_sum": True} for n in range(70)]
        if label == "home_assistant/repairs":
            return {"issues": [{"domain": "demo", "severity": "warning", "ignored": False, "issue_id": "fixture"}]}
        if label == "home_assistant/notifications":
            return [{"notification_id": "fixture", "message": "password=" + SECRET}]
        return await super().supplemental(label)

    async def statistics(self, ids, start, end):
        self.statistics_request = (ids, start, end)
        return {identifier: [{"start": 1791470000, "sum": 0, "change": -1}] for identifier in ids}

    async def configurations(self):
        from ha_diagnostics.export_configuration import ConfigurationDocument
        if self.fail_config:
            return [ConfigurationDocument("configuration/home_assistant/yaml/001", "configuration.yaml", error="CONFIG_PERMISSION_DENIED")]
        return [ConfigurationDocument("configuration/home_assistant/yaml/001", "configuration.yaml",
            {"source_path": "configuration.yaml", "configuration": {"fixture": self.config_value, "password": SECRET}})]

    async def logs(self, source):
        yield b"2026-10-08T10:00:00Z INFO first\n2026-10-08T11:00:00Z INFO last\n"


async def build(service):
    job = await service.start(StartExportArgs())
    await service._task
    assert service.jobs[job["export_id"]]["status"] == "ready", service.jobs[job["export_id"]]
    return service.directory / (job["export_id"] + ".zip")


async def test_all_new_sources_host_passport_coverage_statistics_and_redaction(tmp_path):
    sources = ExpandedFixtures()
    service = ExportService(tmp_path / "exports", sources, Redactor(b"k" * 32), min_free_bytes=0)
    try:
        path = await build(service)
        with zipfile.ZipFile(path) as bundle:
            names = bundle.namelist()
            assert {"system/overview.json", "system/overview.txt", "system/resources.json", "system/health.json",
                "system/host_services.json", "system/disk_usage.json", "system/swap.json", "system/jobs.json",
                "system/repositories.json", "system/network_context.json", "home_assistant/repairs.json",
                "home_assistant/notifications.json", "home_assistant/system_log.json", "registries/floors.json",
                "registries/labels.json", "traces/automation/0001.json", "traces/script/0001.json",
                f"devices/{DEVICE}/{ENTRY}.json", "statistics/metadata.json", "statistics/last_7_days.json",
                "history/coverage.json", "comparison/changes.json", "comparison/changes.txt"} <= set(names)
            manifest = json.loads(bundle.read("manifest.json"))
            all_bytes = b"\n".join(bundle.read(name) for name in names)
            assert SECRET.encode() not in all_bytes
            for source in manifest["sources"]:
                if source["file"]:
                    data = bundle.read(source["file"])
                    assert source["bytes"] == len(data)
                    assert source["sha256"] == hashlib.sha256(data).hexdigest()
            overview = json.loads(bundle.read("system/overview.json"))
            assert overview["sections"]["system/core"]["version"] == "2026.9.4"
            assert overview["sections"]["system/resources"]["memory"]["total_bytes"] == 8 * 1024 ** 3
            assert json.loads(bundle.read("comparison/changes.json"))["previous"]["status"] == "no_previous_archive"
            trace = json.loads(bundle.read("traces/automation/0001.json"))
            assert trace["trace"]["action/0"][0]["result"] == {"enabled": False, "count": 0}
            assert trace["context"]["parent_id"] == "parent1"
            selection = next(r for r in manifest["sources"] if r["source"] == "statistics/selection")
            assert selection["status"] == "partial" and selection["reason"] == "STATISTIC_SELECTION_LIMIT"
            assert len(sources.statistics_request[0]) == MAX_STATISTIC_IDS
            coverage = next(r for r in manifest["sources"] if r["source"] == "core")["coverage_details"]
            assert coverage["timestamped_lines"] == 2
            assert coverage["first_written_timestamp_utc"].startswith("2026-10-08T10:00:00")
            assert coverage["last_written_timestamp_utc"].startswith("2026-10-08T11:00:00")
    finally:
        await service.close()


async def test_comparison_tracks_config_and_versions_ignores_registry_order_and_marks_gaps(tmp_path):
    sources = ExpandedFixtures()
    service = ExportService(tmp_path / "exports", sources, Redactor(b"k" * 32), min_free_bytes=0)
    try:
        await build(service)
        sources.reverse_registry = True
        path = await build(service)
        with zipfile.ZipFile(path) as bundle:
            assert json.loads(bundle.read("comparison/changes.json"))["changes"] == []
        sources.version = "2026.10.0"
        sources.config_value = -7
        path = await build(service)
        with zipfile.ZipFile(path) as bundle:
            changes = json.loads(bundle.read("comparison/changes.json"))["changes"]
            assert {r["source"] for r in changes} == {"system/core", "configuration:homeassistant_config:configuration.yaml"}
            core = next(r for r in changes if r["source"] == "system/core")
            assert core["before"]["version"] == "2026.9.4" and core["after"]["version"] == "2026.10.0"
        sources.fail_config = True
        path = await build(service)
        with zipfile.ZipFile(path) as bundle:
            changes = json.loads(bundle.read("comparison/changes.json"))["changes"]
            assert all(c["kind"] != "removed" for c in changes)
            assert any(c["kind"] == "not_comparable_source_unavailable" for c in changes)
    finally:
        await service.close()


class HealthWS:
    def __init__(self, *, interrupted=False, wrong_id=False):
        self.sent = []
        self.rows = [{"type": "auth_required"}, {"type": "auth_ok"},
            {"id": 1, "type": "result", "success": True, "result": None},
            {"id": 2 if wrong_id else 1, "type": "event", "event": {"type": "initial", "data": {
                "demo": {"info": {"reachability": {"type": "pending"}}}}}},
            {"id": 1, "type": "event", "event": {"type": "update", "domain": "demo", "key": "reachability",
                "success": True, "data": False}},
            {"id": 1, "type": "event", "event": {"type": "finish"}}]
        if interrupted:
            self.rows.pop()
    async def __aenter__(self): return self
    async def __aexit__(self, *args): pass
    async def send(self, message): self.sent.append(json.loads(message))
    async def recv(self):
        if not self.rows:
            raise OSError(TOKEN)
        return json.dumps(self.rows.pop(0))


@pytest.mark.parametrize("interrupted", [False, True])
async def test_system_health_subscription_updates_finish_and_partial_connection(interrupted):
    ws = HealthWS(interrupted=interrupted)
    sources = ExportSources(TOKEN, websocket_connector=lambda *a, **kw: ws)
    try:
        result = await sources.supplemental("system/health")
        if interrupted:
            assert isinstance(result, SourceResult) and result.status == "partial" and result.reason == "CONNECTION_LOST"
            result = result.value
        assert result["demo"]["info"]["reachability"] is False
        assert ws.sent[-1] == {"id": 1, "type": "system_health/info"}
    finally:
        await sources.close()


async def test_system_health_rejects_unsolicited_id():
    sources = ExportSources(TOKEN, websocket_connector=lambda *a, **kw: HealthWS(wrong_id=True))
    try:
        with pytest.raises(BrokerError, match="UPSTREAM_FORMAT"):
            await sources.supplemental("system/health")
    finally:
        await sources.close()


@pytest.mark.parametrize("command", [
    {"type": "call_service", "domain": "light", "service": "turn_on"},
    {"type": "trace/debug/stop", "domain": "automation", "item_id": "x"},
    {"type": "recorder/update_statistics_issues"}, {"type": "repairs/ignore_issue"},
    {"type": "config/device_registry/update"}, {"type": "system_health/info", "url": "https://evil.test"},
    {"type": "trace/list", "domain": "shell"}, {"type": "trace/get", "domain": "automation", "run_id": "x"},
    {"type": "recorder/statistics_during_period", "statistic_ids": ["sensor.x"], "period": "day",
     "start_time": "2026-09-01T00:00:00Z", "end_time": "2026-10-01T00:00:00Z"},
])
def test_new_websocket_allowlist_rejects_mutations_arbitrary_parameters_and_unbounded_ranges(command):
    with pytest.raises(BrokerError, match="OPERATION_DENIED"):
        ExportSources.validate_websocket(command)


async def test_device_diagnostics_only_uses_fixed_get_and_valid_native_ids():
    requests = []
    sources = ExportSources(TOKEN, transport=httpx.MockTransport(lambda r: requests.append(r) or httpx.Response(200, json={})))
    try:
        await sources.device(ENTRY, DEVICE)
        assert requests[0].method == "GET" and requests[0].url.path == f"/core/api/diagnostics/config_entry/{ENTRY}/device/{DEVICE}"
        with pytest.raises(BrokerError, match="OPERATION_DENIED"):
            await sources.device(ENTRY, "../../secret")
        assert len(requests) == 1
    finally:
        await sources.close()


def test_network_metadata_retains_ipv6_scopes_and_subnet_relationships_without_addresses():
    raw = {"interfaces": [{"interface": "eth0", "ipv6": {"address": ["fe80::1/64", "fd00:1234::1/64", "fd00:1234::2/80"]},
        "ipv4": {"address": ["192.168.3.2/24", "192.168.3.3/24"]}}]}
    result = network_context(raw, Redactor(b"k" * 32))
    assert {r["scope"] for r in result["addresses"]} == {"link_local", "unique_local", "private"}
    ipv4 = [r for r in result["addresses"] if r["family"] == 4]
    assert ipv4[0]["subnet_ref"] == ipv4[1]["subnet_ref"]
    assert len(result["subnet_relations"]) == 1
    assert "192.168" not in json.dumps(result) and "fd00" not in json.dumps(result) and "fe80" not in json.dumps(result)


def test_log_coverage_does_not_guess_unknown_timezone_or_hide_truncation_quality():
    coverage = LogCoverage(None)
    coverage.add("2026-10-08 11:00:00 INFO local")
    coverage.add("2026-10-08T12:00:00Z INFO explicit")
    assert coverage.as_dict()["timestamped_lines"] == 1
    assert coverage.as_dict()["lines_without_usable_timestamp"] == 1


def test_configuration_follows_only_referenced_blueprints_dashboards_and_jinja_without_execution(tmp_path):
    def write(name, text):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    write("configuration.yaml", """automation: !include automations.yaml
lovelace:
  dashboards:
    demo:
      mode: yaml
      filename: dashboards/demo.yaml
template:
  - sensor:
      - state: "{% from 'macros.jinja' import value %}{{ value() }}"
""")
    write("automations.yaml", "- use_blueprint:\n    path: demo/test.yaml\n    input:\n      target: 0\n")
    write("blueprints/automation/demo/test.yaml", "blueprint:\n  domain: automation\naction:\n  - value: !input target\n")
    write("dashboards/demo.yaml", "views: []\n")
    write("custom_templates/macros.jinja", "{% from 'nested.jinja' import value %}\n{% macro value() %}0{% endmacro %}")
    write("custom_templates/nested.jinja", "{% macro value() %}{{ dangerous() }}{% endmacro %}")
    write("custom_templates/unreferenced.jinja", "UNREFERENCED_CANARY")
    before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    documents = ConfigurationReader(tmp_path).collect()
    origins = {d.origin for d in documents if not d.error}
    assert {"blueprints/automation/demo/test.yaml", "dashboards/demo.yaml", "custom_templates/macros.jinja",
            "custom_templates/nested.jinja"} <= origins
    assert "custom_templates/unreferenced.jinja" not in origins
    assert any(d.value and "dangerous()" in str(d.value) for d in documents)
    assert before == {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}


@pytest.mark.parametrize("reference", ["../../outside.jinja", "../../secrets.yaml", ".storage/auth", "file.txt"])
def test_template_dependencies_cannot_escape_roots_or_read_secret_and_non_template_files(tmp_path, reference):
    (tmp_path / "configuration.yaml").write_text("value: \"{% from '" + reference + "' import value %}\"")
    documents = ConfigurationReader(tmp_path).collect()
    assert any(d.error == "CONFIG_PATH_DENIED" for d in documents)


def test_dynamic_jinja_import_is_an_explicit_gap(tmp_path):
    (tmp_path / "configuration.yaml").write_text('value: "{% from variable_path import value %}"')
    assert any(d.error == "CONFIG_DYNAMIC_REFERENCE" for d in ConfigurationReader(tmp_path).collect())


async def test_import_only_never_reads_proc_resources():
    def forbidden():
        pytest.fail("import-only read resources")
    sources = ExportSources(None, resource_reader=forbidden)
    try:
        with pytest.raises(BrokerError, match="SOURCE_UNAVAILABLE"):
            await sources.resources()
    finally:
        await sources.close()


def test_host_resources_preserves_host_memory_and_separate_container_limits(tmp_path, monkeypatch):
    from ha_diagnostics import export_insights
    values = {"cpu": "processor : 0\nmodel name : Fixture CPU\nprocessor : 1\nSerial : SERIAL_CANARY\n",
        "memory": "MemTotal: 8388608 kB\nMemAvailable: 0 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n",
        "memory_limit": "1073741824", "cpu_limit": "100000 100000"}
    files = {}
    for kind, text in values.items():
        path = tmp_path / kind
        path.write_text(text)
        files[kind] = str(path)
    monkeypatch.setattr(export_insights, "RESOURCE_FILES", files)
    result = host_resources()
    assert result["cpu"]["logical_processors"] == 2
    assert result["cpu"]["models"] == ["Fixture CPU"]
    assert result["memory"]["total_bytes"] == 8 * 1024 ** 3
    assert result["memory"]["available_bytes"] == 0
    assert result["container_limits"]["memory_limit"] == "1073741824"
    assert "SERIAL_CANARY" not in json.dumps(result)


async def test_selection_limits_and_unsupported_device_are_visible_without_stopping_other_sources(tmp_path, monkeypatch):
    import ha_diagnostics.exporter as exporter
    monkeypatch.setattr(exporter, "MAX_TRACE_READS", 2)
    monkeypatch.setattr(exporter, "MAX_DEVICE_READS", 2)
    class Many(ExpandedFixtures):
        async def traces(self, domain):
            return [{"domain": domain, "item_id": "fixture", "run_id": str(n),
                "timestamp": {"start": f"2026-10-08T{n:02d}:00:00Z"}} for n in range(5)]
        async def registry(self, label):
            if label == "devices":
                return [{"id": f"{n:032x}", "config_entries": [ENTRY]} for n in range(3)]
            return await super().registry(label)
    service = ExportService(tmp_path / "exports", Many(), Redactor(b"k" * 32), min_free_bytes=0)
    try:
        path = await build(service)
        with zipfile.ZipFile(path) as bundle:
            manifest = json.loads(bundle.read("manifest.json"))
            sources = {r["source"]: r for r in manifest["sources"]}
            assert sources["traces/automation/index"]["status"] == "partial"
            assert sources["devices/index"]["status"] == "partial"
            index = json.loads(bundle.read("traces/automation/index.json"))
            assert [r["run_id"] for r in index["selected_runs"]] == ["4", "3"]
            assert index["omitted_runs"] == 3
            assert len([r for r in sources if r.startswith("devices/")]) == 3  # Two attempts and the index.
            assert sources[f"devices/{0:032x}/{ENTRY}"]["reason"] == "NOT_SUPPORTED"
            assert "logs/core.log" in bundle.namelist()
    finally:
        await service.close()


async def test_alpha4_baseline_and_corrupt_baseline_do_not_prevent_ready_export(tmp_path):
    sources = ExpandedFixtures()
    service = ExportService(tmp_path / "exports", sources, Redactor(b"k" * 32), min_free_bytes=0)
    try:
        path = await build(service)
        # Model the actual Alpha 4 format: source records and sanitized files, without a comparison snapshot.
        with zipfile.ZipFile(path) as bundle:
            files = {name: bundle.read(name) for name in bundle.namelist() if name != "comparison/snapshot.json"}
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as bundle:
            for name, body in files.items():
                bundle.writestr(name, body)
        sources.version = "2026.10.0"
        path = await build(service)
        with zipfile.ZipFile(path) as bundle:
            changes = json.loads(bundle.read("comparison/changes.json"))
            assert changes["previous"]["basis"] == "sanitized_alpha4_files"
            assert any(c["source"] == "system/core" and c["kind"] == "changed" for c in changes["changes"])
        path.write_bytes(b"damaged archive")
        path = await build(service)
        with zipfile.ZipFile(path) as bundle:
            assert json.loads(bundle.read("comparison/changes.json"))["previous"]["status"] == "previous_archive_unreadable_or_limit"
            assert "logs/core.log" in bundle.namelist()
    finally:
        await service.close()


async def test_redaction_key_change_disables_comparison(tmp_path):
    service = ExportService(tmp_path / "exports", ExpandedFixtures(), Redactor(b"k" * 32), min_free_bytes=0)
    await build(service)
    await service.close()
    service = ExportService(tmp_path / "exports", ExpandedFixtures(), Redactor(b"n" * 32), min_free_bytes=0)
    try:
        path = await build(service)
        with zipfile.ZipFile(path) as bundle:
            diff = json.loads(bundle.read("comparison/changes.json"))
            assert diff["previous"]["status"] == "redaction_key_changed" and not diff["changes"]
    finally:
        await service.close()


async def test_partial_log_records_exact_written_boundary_and_checksums(tmp_path):
    class Partial(ExpandedFixtures):
        async def logs(self, source):
            yield b"2026-10-08T10:00:00Z INFO retained\npassword=UNFINISHED_SECRET_CANARY"
            raise BrokerError("CONNECTION_LOST")
    service = ExportService(tmp_path / "exports", Partial(), Redactor(b"k" * 32), min_free_bytes=0)
    try:
        path = await build(service)
        with zipfile.ZipFile(path) as bundle:
            manifest = json.loads(bundle.read("manifest.json"))
            record = next(r for r in manifest["sources"] if r["source"] == "core")
            assert record["status"] == "partial"
            assert record["truncation"]["written_bytes"] == len(bundle.read("logs/core.log"))
            assert record["truncation"]["received_bytes"] > record["bytes"]
            assert record["truncation"]["last_written_timestamp_utc"].startswith("2026-10-08T10:00:00")
            assert b"UNFINISHED_SECRET_CANARY" not in bundle.read("logs/core.log")
    finally:
        await service.close()

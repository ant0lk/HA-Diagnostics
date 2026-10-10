"""ZIP export contracts, using mock HA APIs rather than a live HA instance."""
import asyncio
import hashlib
import io
import json
import os
from pathlib import Path
import time
import zipfile

import httpx
import pytest

from ha_diagnostics.broker import BrokerError
from ha_diagnostics.export_sources import ALL_LOG_ENTRIES, DemoExportSources, ExportSources
from ha_diagnostics.export_configuration import ConfigurationReader
from ha_diagnostics.exporter import ExportArgs, ExportService, StartExportArgs, STRUCTURE_FILE
from ha_diagnostics.ipc import AdminIPCServer, IPCError
from ha_diagnostics.redaction import Redactor
from ha_diagnostics.ui import AdminGate, create_ui

TOKEN = "EXPORT_SUPERVISOR_CANARY"
ENTRY_ID = "01JABCDEFGHJKMNPQRSTVWXYZ1"


class RegistryWS:
    def __init__(self):
        self.sent = []
        self.count = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def send(self, message):
        self.sent.append(json.loads(message))

    async def recv(self):
        self.count += 1
        if self.count == 1:
            return json.dumps({"type": "auth_required"})
        if self.count == 2:
            return json.dumps({"type": "auth_ok"})
        command = self.sent[-1]["type"]
        if command == "system_health/info":
            if self.count == 3:
                return json.dumps({"id": 1, "type": "result", "success": True, "result": None})
            return json.dumps({"id": 1, "type": "event", "event": {"type": "initial", "data": {}} if
                self.count == 4 else {"type": "finish"}})
        if command == "config_entries/get":
            rows = [{"entry_id": ENTRY_ID, "domain": "matter"}]
        elif command == "config/device_registry/list":
            rows = [{"id": "d" * 32, "name": "Bedroom", "config_entries": [ENTRY_ID]}]
        elif command == "config/entity_registry/list":
            rows = [{"entity_id": "sensor.fixture", "device_id": "d" * 32, "config_entry_id": ENTRY_ID}]
        elif command == "repairs/list_issues":
            rows = {"issues": []}
        elif command == "recorder/validate_statistics":
            rows = {}
        elif command.startswith(("trace/", "recorder/")) or command in {"system_log/list", "persistent_notification/get"}:
            rows = []
        else:
            rows = [{"area_id": "bedroom", "name": "Bedroom"}]
        return json.dumps({"id": 1, "type": "result", "success": True, "result": rows})


def sources_fixture(*, fail_supervisor=False, many_lines=False, configuration_root=None):
    requests, sockets = [], []
    def handler(request):
        requests.append(request)
        assert request.url.host == "supervisor" and request.method == "GET"
        assert request.headers["Authorization"] == "Bearer " + TOKEN
        path = request.url.path
        if path == "/addons":
            return httpx.Response(200, json={"result": "ok", "data": {"addons": [
                {"slug": "fixture_matter", "installed": True},
                {"slug": "stopped_addon", "installed": True, "state": "stopped"},
                {"slug": "not_installed", "installed": False}]}})
        if path.endswith("/logs"):
            assert request.headers["Range"] == ALL_LOG_ENTRIES
            assert dict(request.url.params) == {"no_colors": ""}
            if fail_supervisor and path == "/supervisor/logs":
                return httpx.Response(403, text=TOKEN)
            text = "INFO context\n" * (50101 if many_lines and path == "/core/logs" else 1)
            text += "password=ZIP_PASSWORD_CANARY\n" + TOKEN + "\n"
            text += "-----BEGIN PRIVATE KEY-----\nZIP_PEM_BODY_CANARY\n-----END PRIVATE KEY-----\n"
            return httpx.Response(200, text=text)
        if "/history/period/" in path:
            return httpx.Response(200, json=[[{"entity_id": "sensor.fixture", "state": 0,
                "attributes": {"temperature": -7, "flag": False, "empty": "", "token": TOKEN}}]])
        if "/logbook/" in path:
            return httpx.Response(200, json=[{"entity_id": "sensor.fixture", "message": "unavailable"}])
        if path.startswith("/addons/"):
            return httpx.Response(200, json={"result": "ok", "data": {
                "state": "started", "options": {"custom_field": "ZIP_OPTION_CANARY", "log_level": "info",
                    "flag": False, "offset": -7, "count": 0, "empty": ""},
                "schema": {"custom_field": "password", "log_level": "str"},
                "boot": "auto", "watchdog": False, "network": {"5580/tcp": 5580}, "enabled": False}})
        return httpx.Response(200, json={"version": "fixture", "time_zone": "Asia/Tomsk", "temperature": -7,
            "flag": False, "count": 0, "empty": "", "password": "ZIP_PASSWORD_CANARY", "token": TOKEN})
    def ws(*args, **kwargs):
        assert args[0] == "ws://supervisor/core/websocket"
        socket = RegistryWS();sockets.append(socket);return socket
    reader = ConfigurationReader(configuration_root) if configuration_root else None
    return ExportSources(TOKEN, transport=httpx.MockTransport(handler), websocket_connector=ws,
                         configuration_reader=reader, resource_reader=lambda: {
                             "cpu": {"models": ["Fixture CPU"], "logical_processors": 4},
                             "memory": {"total_bytes": 8589934592}, "sources": {"cpu": {"status": "ok"}}}), requests, sockets


async def finish(service):
    result = await service.start(StartExportArgs())
    await service._task
    job = await service.job_status(ExportArgs(export_id=result["export_id"]))
    assert job["status"] == "ready", job
    return job, service.directory / (job["export_id"] + ".zip")


async def test_complete_zip_contains_all_sources_24h_history_checksums_and_no_secrets(tmp_path):
    root = tmp_path / "homeassistant"
    (root / ".storage").mkdir(parents=True)
    (root / "configuration.yaml").write_text("default_config: {}\nrecorder:\n  purge_keep_days: 10\n")
    (root / ".storage/core.config_entries").write_text(json.dumps({"version": 1, "data": {"entries": [
        {"entry_id": ENTRY_ID, "domain": "matter", "data": {"password": TOKEN},
         "options": {"scan_interval": 30, "enabled": False}}]}}))
    sources, requests, sockets = sources_fixture(fail_supervisor=True, many_lines=True, configuration_root=root)
    service = ExportService(tmp_path / "exports", sources, Redactor(b"r" * 32), min_free_bytes=0)
    try:
        job, path = await finish(service)
        with zipfile.ZipFile(path) as archive:
            assert archive.testzip() is None
            names = archive.namelist()
            manifest = json.loads(archive.read("manifest.json"))
            assert {"README.txt", STRUCTURE_FILE, "system/core.json", "system/network.json", "registries/devices.json",
                    "logs/core.log", "logs/host.log", "logs/addon/fixture_matter.log",
                    "logs/addon/stopped_addon.log"} <= set(names)
            assert len([n for n in names if n.startswith("history/") and n[8:10].isdigit()]) == 24
            assert len([n for n in names if n.startswith("logbook/")]) == 24
            assert "not_installed" not in " ".join(names)
            assert archive.read("logs/core.log").count(b"INFO context\n") == 50101
            contents = b"\n".join(archive.read(n) for n in names)
            for secret in (TOKEN, "ZIP_PASSWORD_CANARY", "ZIP_PEM_BODY_CANARY", "ZIP_OPTION_CANARY"):
                assert secret.encode() not in contents
            assert b"sensor.fixture" not in contents
            for source in manifest["sources"]:
                if source["file"]:
                    data = archive.read(source["file"])
                    assert hashlib.sha256(data).hexdigest() == source["sha256"]
                    assert len(data) == source["bytes"]
            issue = next(s for s in manifest["sources"] if s["source"] == "supervisor")
            assert issue["status"] == "unavailable" and issue["reason"] == "PERMISSION_DENIED"
            assert job["issues"] == 1
            structure = archive.read(STRUCTURE_FILE)
            assert job["filename"].encode() in structure
            assert manifest["archive_filename"] == job["filename"]
            assert manifest["kind"] == "manual"
            assert manifest["structure"]["bytes"] == len(structure)
            assert manifest["structure"]["sha256"] == hashlib.sha256(structure).hexdigest()
            history = json.loads(archive.read("history/00.json"))[0][0]
            assert history["state"] == 0
            assert history["attributes"] == {"temperature": -7, "flag": False, "empty": "", "token": "[REDACTED]"}
            a, b = manifest["history"]["from"], manifest["history"]["to"]
            from datetime import datetime, timedelta
            assert datetime.fromisoformat(b) - datetime.fromisoformat(a) == timedelta(hours=24)
            assert manifest["history"]["coverage"] == "recorder_retention_and_exclusions_unknown"
            assert f"integrations/{ENTRY_ID}.json" in names
            addon = json.loads(archive.read("configuration/addons/fixture_matter.json"))
            assert addon["options"] == {"custom_field": "[REDACTED]", "log_level": "info",
                "flag": False, "offset": -7, "count": 0, "empty": ""}
            assert addon["boot"] == "auto" and addon["watchdog"] is False
            assert addon["network"] == {"5580/tcp": 5580}
            entries = json.loads(archive.read("configuration/integrations/entries.json"))["configuration"]["entries"]
            assert entries[0]["entry_id"] == ENTRY_ID
            assert entries[0]["options"] == {"scan_interval": 30, "enabled": False}
            assert entries[0]["data"]["password"] == "[REDACTED]"
            assert "configuration/index.json" in names
            devices = json.loads(archive.read("registries/devices.json"))
            entities = json.loads(archive.read("registries/entities.json"))
            assert devices[0]["id"] == entities[0]["device_id"]
            assert devices[0]["config_entries"] == [entities[0]["config_entry_id"]]
            assert devices[0]["name"] != "Bedroom"
        assert all(len(s.sent) == 2 and s.sent[0]["type"] == "auth" for s in sockets)
        assert len([r for r in requests if "/history/period/" in r.url.path]) == 24
        assert not list(service.directory.glob("*.partial"))
        assert not list(service.directory.glob("*.log"))
    finally:
        await service.close()


@pytest.mark.parametrize("method,path,params,log", [
    ("POST", "/core/restart", {}, False), ("GET", "/core/restart", {}, False),
    ("GET", "/core/api/config", {"url": "https://evil.test"}, False),
    ("GET", "/addons/../core/info", {}, False), ("GET", "/addons/%2e%2e/logs", {"no_colors": ""}, True),
    ("GET", "/host/logs/follow", {"no_colors": ""}, True),
    ("GET", "/core/api/camera_proxy/camera.private", {}, False),
    ("GET", "/core/api/history/period/2026-10-08T00:00:00", {"end_time": "2026-10-09T00:00:00"}, False),
    ("GET", "/core/api/history/period/2026-10-08T00:00:00Z", {"end_time": "2026-10-09T00:00:00Z"}, False),
])
def test_export_network_allowlist_rejects_control_proxy_traversal_and_large_intervals(method,path,params,log):
    with pytest.raises(BrokerError):
        ExportSources.validate_request(method, path, params, log)


async def test_redirect_does_not_send_credential_to_another_origin():
    sent = []
    sources = ExportSources(TOKEN, transport=httpx.MockTransport(lambda r: sent.append(r) or
        httpx.Response(302, headers={"Location": "https://evil.test/"}, text=TOKEN)))
    with pytest.raises(BrokerError, match="UPSTREAM_REDIRECT_DENIED"):
        await sources.snapshot("system/core")
    assert len(sent) == 1
    await sources.close()


async def test_ui_create_download_access_csrf_and_traversal(tmp_path):
    service = ExportService(tmp_path / "exports", DemoExportSources(), Redactor(b"r" * 32),
                            demo=True, min_free_bytes=0)
    app = create_ui(service, gate=AdminGate(demo=True), web_dir="web", export_dir=service.directory)
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app,client=("127.0.0.1",42)),
                                    base_url="http://127.0.0.1:8099") as client:
            status = (await client.get("/api/status")).json()
            assert status["workflow"] == "zip_export"
            body = {"op": "start_export", "args": {"history_hours": 24}}
            assert (await client.post("/api/action", json=body)).status_code == 403
            headers = {"X-CSRF-Token": status["csrf"], "Origin": "http://127.0.0.1:8099"}
            schedule_body = {"op": "set_export_schedule", "args": {"enabled": False, "time": "04:15"}}
            assert (await client.post("/api/action", json=schedule_body)).status_code == 403
            assert (await client.post("/api/action", headers=headers, json=schedule_body)).status_code == 200
            assert (await client.get("/api/status")).json()["schedule"]["time"] == "04:15"
            assert (await client.post("/api/action", headers=headers,
                json={"op": "set_export_schedule", "args": {"enabled": True, "time": "25:00"}})).status_code == 400
            response = await client.post("/api/action", headers=headers, json=body)
            assert response.status_code == 200, response.text
            job = response.json()
            await service._task
            url = "/api/exports/" + job["export_id"] + "/download"
            download = await client.get(url)
            assert download.status_code == 200
            assert download.headers["content-type"] == "application/zip"
            assert "attachment;" in download.headers["content-disposition"]
            assert download.headers["cache-control"] == "no-store"
            with zipfile.ZipFile(io.BytesIO(download.content)) as archive:
                assert json.loads(archive.read("manifest.json"))["demo"] is True
            assert (await client.get("/api/exports/invalid/download")).status_code == 404
            assert (await client.post("/api/action", headers=headers,
                json={"op": "start_export", "args": {"history_hours": 7, "path": "/config"}})).status_code == 400
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app,client=("203.0.113.2",42)),
                                    base_url="http://localhost") as attacker:
            assert (await attacker.get(url,headers={"X-Remote-User-Id": "owner"})).status_code == 403
    finally:
        await service.close()


async def test_unavailable_live_source_and_query_uid_cannot_export(tmp_path):
    sources = ExportSources(None)
    service = ExportService(tmp_path / "exports", sources, Redactor(b"r" * 32), min_free_bytes=0)
    assert (await service.status(None))["available"] is False
    with pytest.raises(BrokerError, match="SOURCE_UNAVAILABLE"):
        await service.start(StartExportArgs())
    ipc = AdminIPCServer(tmp_path / "export.sock", service.handlers())
    with pytest.raises(IPCError, match="IPC_FORBIDDEN"):
        await ipc.dispatch(10002, {"op": "start_export", "args": {}})
    assert not service.jobs
    await service.close()


async def test_single_job_cancel_removes_unfinished_zip_and_allows_retry(tmp_path):
    class Slow(DemoExportSources):
        async def snapshot(self, label):
            await asyncio.Event().wait()
    service = ExportService(tmp_path / "exports", Slow(), Redactor(b"r" * 32), min_free_bytes=0)
    job = await service.start(StartExportArgs())
    await asyncio.sleep(0)
    with pytest.raises(BrokerError, match="EXPORT_BUSY"):
        await service.start(StartExportArgs())
    assert (await service.cancel(ExportArgs(export_id=job["export_id"]))) ["status"] == "cancelled"
    assert not list(service.directory.glob("*.partial"))
    assert not list(service.directory.glob("*.zip"))
    service.sources = DemoExportSources()
    await finish(service)
    await service.close()


async def test_interrupted_logs_keep_partial_file_and_explicit_gap(tmp_path):
    class Broken(DemoExportSources):
        async def logs(self, source):
            yield b"INFO first complete line\npassword=UNFINISHED_SECRET_CANARY"
            raise BrokerError("CONNECTION_LOST")
    service = ExportService(tmp_path / "exports", Broken(), Redactor(b"r" * 32), min_free_bytes=0)
    _, path = await finish(service)
    with zipfile.ZipFile(path) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        logs = [s for s in manifest["sources"] if s["file"] and s["file"].endswith(".log")]
        assert all(s["status"] == "partial" and s["reason"] == "CONNECTION_LOST" for s in logs)
        assert archive.read("logs/core.log") == b"INFO first complete line\n"
    await service.close()


async def test_budget_overflow_is_visible_without_corrupting_archive(tmp_path):
    service = ExportService(tmp_path / "exports", DemoExportSources(), Redactor(b"r" * 32),
                            max_source_bytes=256, max_export_bytes=1000, min_free_bytes=0)
    job, path = await finish(service)
    assert job["issues"] > 0
    with zipfile.ZipFile(path) as archive:
        assert archive.testzip() is None
        manifest = json.loads(archive.read("manifest.json"))
        assert any(s.get("reason") == "EXPORT_SIZE_LIMIT" for s in manifest["sources"])
        assert sum(s["bytes"] for s in manifest["sources"]) <= 1000
    await service.close()


async def test_completed_exports_restore_and_keep_last_three(tmp_path):
    service = ExportService(tmp_path / "exports", DemoExportSources(), Redactor(b"r" * 32), min_free_bytes=0)
    ids = [(await finish(service))[0]["export_id"] for _ in range(4)]
    assert len(list(service.directory.glob("*.zip"))) == 3
    assert ids[0] not in service.jobs
    await service.close()
    restored = ExportService(service.directory, DemoExportSources(), Redactor(b"r" * 32), min_free_bytes=0)
    assert set(restored.jobs) == set(ids[1:])
    await restored.download(ExportArgs(export_id=ids[-1]))
    path = service.directory / (ids[-1] + ".zip")
    os.utime(path, (time.time() - 90000, time.time() - 90000))
    restored._cleanup()
    assert path.exists()  # Count-based retention no longer expires archives after 24 hours.
    await restored.close()


async def test_disk_low_rejects_start_before_any_request(tmp_path):
    service = ExportService(tmp_path / "exports", DemoExportSources(), Redactor(b"r" * 32),
                            min_free_bytes=2**63)
    with pytest.raises(BrokerError, match="DISK_LOW"):
        await service.start(StartExportArgs())
    assert not service.jobs
    await service.close()


async def test_cancel_before_worker_starts_does_not_leave_collecting_state(tmp_path):
    service = ExportService(tmp_path / "exports", DemoExportSources(), Redactor(b"r" * 32), min_free_bytes=0)
    job = await service.start(StartExportArgs())
    result = await service.cancel(ExportArgs(export_id=job["export_id"]))
    assert result["status"] == "cancelled"
    assert not list(service.directory.iterdir())
    await finish(service)
    await service.close()


async def test_api_error_envelope_is_a_gap_even_with_http_200():
    sources = ExportSources(TOKEN, transport=httpx.MockTransport(lambda r:
        httpx.Response(200, json={"result": "error", "message": TOKEN})))
    with pytest.raises(BrokerError, match="UPSTREAM_UNAVAILABLE"):
        await sources.snapshot("system/core")
    await sources.close()


def test_zip_bootstrap_runs_only_export_and_ui_with_token_fd_separated(tmp_path, monkeypatch):
    from ha_diagnostics import runtime
    monkeypatch.setattr(runtime.sys, "platform", "linux")
    monkeypatch.setattr(runtime.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(runtime, "harden", lambda: None)
    monkeypatch.delenv("HAD_BOOTSTRAP_TOKEN_FD", raising=False)
    def prepare(data):
        (data / "ipc").mkdir()
        (data / "exports").mkdir()
    monkeypatch.setattr(runtime, "prepare_export_storage", prepare)
    calls = []
    class Process:
        def __init__(self, role):self.role = role
        def poll(self):return 1 if self.role == "ui" else None
        def terminate(self):pass
        def wait(self, timeout):return 0
    def popen(args, **kwargs):
        role = args[args.index("--role") + 1]
        calls.append((role, args, kwargs))
        if role == "export":
            (tmp_path / "ipc/export.sock").touch()
        return Process(role)
    monkeypatch.setattr(runtime.subprocess, "Popen", popen)
    with pytest.raises(RuntimeError, match="WORKER_STOPPED"):
        runtime.bootstrap_export(tmp_path, "live", {"ingress_admin_id": "owner"}, tmp_path / "web")
    assert [c[0] for c in calls] == ["export", "ui"]
    assert calls[0][2]["pass_fds"]
    assert calls[1][2]["pass_fds"] == ()
    assert "HAD_TOKEN_FD" not in calls[1][2]["env"]
    assert calls[1][2]["env"]["HAD_ADMIN_ID"] == "owner"
    assert all("SUPERVISOR_TOKEN" not in c[2]["env"] for c in calls)
    assert all(c[1][c[1].index("--workflow") + 1] == "zip_export" for c in calls)


def test_published_zip_sources_and_ui_match_main_sources():
    root = Path(__file__).resolve().parents[1]
    for name in ("runtime.py", "ui.py", "ipc.py", "exporter.py", "export_sources.py", "export_schedule.py", "export_configuration.py", "export_insights.py", "yandex_history.py"):
        assert (root / "src/ha_diagnostics" / name).read_bytes() == (
            root / "ha_diagnostics_live/app/src/ha_diagnostics" / name).read_bytes(), name
    for name in ("index.html", "app.js", "style.css"):
        assert (root / "web" / name).read_bytes() == (root / "ha_diagnostics_live/app/web" / name).read_bytes(), name

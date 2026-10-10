"""Yandex availability contracts with fake API/clock, never a real account."""
import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import zipfile

import httpx
import pytest
from pydantic import ValidationError

from ha_diagnostics.broker import BrokerError
from ha_diagnostics.exporter import ExportService, StartExportArgs
from ha_diagnostics.export_sources import DemoExportSources
from ha_diagnostics.export_schedule import ScheduleArgs
from ha_diagnostics.ipc import AdminIPCServer, IPCError
from ha_diagnostics.redaction import Redactor
from ha_diagnostics.ui import AdminGate, create_ui
from ha_diagnostics.yandex_history import (API_ORIGIN, YandexAPI, YandexArgs,
    YandexHistory, MAX_RESPONSE_BYTES, MAX_DEVICES)

TOKEN = "YANDEX_SECRET_CANARY_123456"
REDACTOR = Redactor(b"y" * 32)


class Clock:
    def __init__(self):
        self.now = datetime(2026, 10, 10, 0, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.now

    def advance(self, seconds=60):
        self.now += timedelta(seconds=seconds)


class API:
    def __init__(self):
        self.catalog = [{"id": "device-one", "name": "Private bedroom", "type": "devices.types.light"},
                        {"id": "device-two", "name": "Private bridge", "type": "devices.types.socket"}]
        self.states = {"device-one": "online", "device-two": "offline"}
        self.error = None
        self.called = asyncio.Event()
        self.block = None
        self.reads = 0

    async def devices(self):
        self.called.set()
        if self.block:
            await self.block.wait()
        if self.error:
            raise BrokerError(self.error)
        return self.catalog

    async def availability(self, device_id):
        self.reads += 1
        state = self.states[device_id]
        if state.startswith("YANDEX_"):
            raise BrokerError(state)
        return state

    async def close(self):
        pass


async def connected(tmp_path):
    clock, api = Clock(), API()
    history = YandexHistory(tmp_path / "private", REDACTOR, clock=clock, api_factory=lambda token: api)
    await history.configure(YandexArgs(enabled=True, token=TOKEN))
    return history, clock, api


async def test_compressed_transitions_and_polling_uncertainty(tmp_path):
    history, clock, api = await connected(tmp_path)
    try:
        await history.poll_once()
        clock.advance()
        await history.poll_once()
        clock.advance()
        api.states["device-one"] = "offline"
        await history.poll_once()
        clock.advance()
        api.states["device-one"] = "online"
        await history.poll_once()
        value = await history.export_snapshot()
        ref = REDACTOR.alias("YANDEX_DEVICE", "device-one")
        events = [e for e in value["events"] if e["device_ref"] == ref]
        assert [e["status"] for e in events] == ["online", "offline", "online"]
        assert [e["kind"] for e in events] == ["initial", "transition", "transition"]
        assert events[0]["observed_at"] == "2026-10-10T00:00:00.000000Z"
        assert events[0]["last_observed_at"] == "2026-10-10T00:01:00.000000Z"
        assert events[1]["change_window"] == {"after": "2026-10-10T00:01:00.000000Z", "by": "2026-10-10T00:02:00.000000Z"}
        assert events[2]["previous_status"] == "offline"
        assert history.status()["counts"] == {"offline": 1, "online": 1}
        stored = history.store.path.read_bytes()
        for secret in [TOKEN.encode(), b"Private bedroom", b"device-one"]:
            assert secret not in stored
        assert TOKEN not in json.dumps(value) and TOKEN not in json.dumps(history.status())
    finally:
        await history.close()


async def test_api_outage_is_gap_and_recovery_is_not_fabricated_offline(tmp_path):
    history, clock, api = await connected(tmp_path)
    try:
        await history.poll_once()
        for _ in range(2):
            clock.advance()
            api.error = "YANDEX_NETWORK_ERROR"
            await history.poll_once()
        value = await history.export_snapshot()
        assert value["coverage"]["gaps"][0]["is_open"]
        clock.advance()
        api.error = None
        await history.poll_once()
        value = await history.export_snapshot()
        events = [e for e in value["events"] if e["device_ref"] == REDACTOR.alias("YANDEX_DEVICE", "device-one")]
        assert [e["status"] for e in events] == ["online", "unknown", "online"]
        assert events[-1]["kind"] == "resumed"
        gaps = value["coverage"]["gaps"]
        assert len(gaps) == 1 and not gaps[0]["is_open"]
        assert (gaps[0]["from_at"], gaps[0]["to_at"]) == ("2026-10-10T00:00:00.000000Z", "2026-10-10T00:03:00.000000Z")
        assert value["coverage"]["error"] is None
    finally:
        await history.close()


async def test_per_device_error_does_not_hide_successful_observations(tmp_path):
    history, clock, api = await connected(tmp_path)
    try:
        api.states["device-one"] = "YANDEX_DEVICE_NOT_FOUND"
        await history.poll_once()
        value = await history.export_snapshot()
        assert {d["status"] for d in value["devices"]} == {"unknown", "offline"}
        assert all(d["present"] for d in value["devices"])  # GET 404 is not a complete catalog removal.
        assert value["coverage"]["error"] == "YANDEX_DEVICE_NOT_FOUND"
    finally:
        await history.close()


async def test_restart_retains_history_and_marks_downtime(tmp_path):
    history, clock, api = await connected(tmp_path)
    await history.poll_once()
    session = history.settings.session_id
    await history.close()
    clock.advance(600)
    history = YandexHistory(tmp_path / "private", REDACTOR, clock=clock, api_factory=lambda token: api)
    try:
        assert history.settings.session_id == session and history.settings.token.get_secret_value() == TOKEN
        assert history.status()["stale"]
        await history.poll_once()
        value = await history.export_snapshot()
        assert any(e["reason"] == "COLLECTOR_RESTART" and e["status"] == "unknown" for e in value["events"])
        assert value["coverage"]["gaps"][0]["from_at"] == "2026-10-10T00:00:00.000000Z"
        assert value["coverage"]["gaps"][0]["to_at"] == "2026-10-10T00:10:00.000000Z"
        assert not value["coverage"]["gaps"][0]["is_open"]
    finally:
        await history.close()


async def test_removal_readdition_rename_and_token_sessions(tmp_path):
    history, clock, api = await connected(tmp_path)
    try:
        await history.poll_once()
        original = history.settings.session_id
        clock.advance()
        api.catalog.pop()
        api.catalog[0]["name"] = "Renamed private device"
        await history.poll_once()
        value = await history.export_snapshot()
        removed = next(d for d in value["devices"] if d["device_ref"] == REDACTOR.alias("YANDEX_DEVICE", "device-two"))
        assert not removed["present"] and removed["status"] == "removed"
        assert value["devices"][0]["name"] != "Renamed private device"
        clock.advance()
        api.catalog.append({"id": "device-two", "name": "Back", "type": "devices.types.socket"})
        await history.poll_once()
        value = await history.export_snapshot()
        assert any(e["previous_status"] == "removed" and e["kind"] == "resumed" for e in value["events"])
        await history.configure(YandexArgs(enabled=True, token="OTHER_ACCOUNT_TOKEN_123456"))
        assert history.settings.session_id != original
        assert history.status()["last_poll_at"] is None
        await history.poll_once()
        value = await history.export_snapshot()
        assert len({e["session_id"] for e in value["events"]}) == 2
        assert all(not d["present"] for d in value["devices"] if d["session_id"] == original)
    finally:
        await history.close()


async def test_retention_clips_boundary_and_reports_capacity_eviction(tmp_path, monkeypatch):
    history, clock, api = await connected(tmp_path)
    try:
        await history.poll_once()
        clock.advance(2 * 86400)
        await history.configure(YandexArgs(enabled=True, retention_days=1))
        await history.poll_once()
        value = await history.export_snapshot()
        assert not any(e["observed_at"] < value["coverage"]["retained_from"] for e in value["events"])
        monkeypatch.setattr("ha_diagnostics.yandex_history.MAX_EVENTS", 3)
        for state in ["offline", "online", "offline", "online"]:
            clock.advance()
            api.states["device-one"] = state
            await history.poll_once()
        value = await history.export_snapshot()
        assert len(value["events"]) <= 3 and value["coverage"]["storage_evictions"] > 0
        # A steady device can reconstruct its boundary after the oldest row is evicted.
        assert history.status()["devices"] == 2
    finally:
        await history.close()


async def test_collector_runs_without_panel_and_settings_interrupt_network(tmp_path):
    history, clock, api = await connected(tmp_path)
    try:
        api.block = asyncio.Event()
        await history.start()
        await asyncio.wait_for(api.called.wait(), 2)
        snapshot = await asyncio.wait_for(history.export_snapshot(), .5)
        assert not snapshot["events"]  # ZIP snapshot never waits for the cloud.
        await asyncio.wait_for(history.configure(YandexArgs(enabled=False)), 1)
        assert not history.settings.enabled and history._task and not history._task.done()
        api.block = None
        api.called.clear()
        await history.configure(YandexArgs(enabled=True))
        await asyncio.wait_for(api.called.wait(), 2)
        await asyncio.sleep(0)
        assert history.status()["devices"] == 2
    finally:
        await history.close()


async def test_clock_correction_pauses_observations_until_time_recovers(tmp_path):
    history, clock, api = await connected(tmp_path)
    try:
        await history.poll_once()
        clock.advance(-60)
        await history.poll_once()
        assert history.status()["error"] == "YANDEX_CLOCK_INVALID"
        assert history.status()["counts"] == {"unknown": 2}
        clock.advance(120)
        await history.poll_once()
        assert history.status()["error"] is None
    finally:
        await history.close()


@pytest.mark.parametrize("bad", [{"enabled": True, "poll_seconds": 29}, {"enabled": True, "retention_days": 366},
    {"enabled": "true"}, {"enabled": True, "url": "https://evil.example"},
    {"enabled": True, "token": "has spaces in token"}, {"enabled": True, "token": "x" * 8193}])
def test_settings_are_bounded_and_strict(bad):
    with pytest.raises(ValidationError):
        YandexArgs.model_validate(bad)


async def test_corrupt_settings_disable_polling_without_losing_history(tmp_path):
    history, clock, api = await connected(tmp_path)
    await history.poll_once()
    await history.close()
    (tmp_path / "private/yandex-settings.json").write_text('{"enabled":true,"token":"bad"}')
    history = YandexHistory(tmp_path / "private", REDACTOR, clock=clock, api_factory=lambda token: api)
    try:
        assert not history.settings.enabled and history.status()["error"] == "YANDEX_SETTINGS_INVALID"
        value = await history.export_snapshot()
        assert len(value["events"]) == 2
        assert value["coverage"]["error"] == "YANDEX_SETTINGS_INVALID"
    finally:
        await history.close()


@pytest.mark.parametrize("status,code", [(401, "YANDEX_AUTH_FAILED"), (403, "YANDEX_AUTH_FAILED"),
    (429, "YANDEX_RATE_LIMIT"), (500, "YANDEX_API_UNAVAILABLE"), (302, "YANDEX_REDIRECT_DENIED")])
async def test_http_errors_never_include_upstream_text_or_forward_token(status, code):
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(status, text=TOKEN, headers={"Location": "https://evil.example", "Retry-After": "120"})
    api = YandexAPI(TOKEN, transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(BrokerError) as caught:
            await api.devices()
        assert caught.value.code == code and TOKEN not in str(caught.value)
        assert len(requests) == 1 and requests[0].url.host == "api.iot.yandex.net"
        assert requests[0].method == "GET" and requests[0].headers["Authorization"] == "Bearer " + TOKEN
        if status == 429:
            assert api.retry_after == 120
    finally:
        await api.close()


async def test_fixed_resources_validate_catalog_and_device_status():
    calls = []
    payload = {"status": "ok", "devices": [{"id": "lamp_1", "name": "Lamp", "capabilities": [{"value": TOKEN}]}]}
    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(200, json=payload)
    api = YandexAPI(TOKEN, transport=httpx.MockTransport(handler))
    try:
        assert await api.devices() == [{"id": "lamp_1", "name": "Lamp", "type": "unknown"}]
        payload = {"status": "ok", "id": "lamp_1", "state": "online", "capabilities": [{"on": False}]}
        assert await api.availability("lamp_1") == "online"  # off is independent of offline.
        payload["state"] = {"online": True}
        with pytest.raises(BrokerError, match="YANDEX_API_FORMAT"):
            await api.availability("lamp_1")
        for path in ["https://evil.example", "/v1.0/devices/../user/info"]:
            with pytest.raises(BrokerError, match="OPERATION_DENIED"):
                await api._get(path)
        with pytest.raises(BrokerError, match="OPERATION_DENIED"):
            await api.availability("../user/info")
        payload = {"status": "ok", "devices": [{"id": "a"}, {"id": "a"}]}
        with pytest.raises(BrokerError, match="YANDEX_API_FORMAT"):
            await api.devices()
        payload = {"status": "ok", "devices": [{"id": str(i)} for i in range(MAX_DEVICES + 1)]}
        with pytest.raises(BrokerError, match="YANDEX_DEVICE_LIMIT"):
            await api.devices()
    finally:
        await api.close()


async def test_response_limit_and_transport_failure_are_safe():
    api = YandexAPI(TOKEN, transport=httpx.MockTransport(lambda request: httpx.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1))))
    try:
        with pytest.raises(BrokerError, match="YANDEX_RESPONSE_LIMIT"):
            await api.devices()
    finally:
        await api.close()
    def fail(request):
        raise httpx.ConnectError(TOKEN)
    api = YandexAPI(TOKEN, transport=httpx.MockTransport(fail))
    try:
        with pytest.raises(BrokerError, match="YANDEX_NETWORK_ERROR"):
            await api.devices()
    finally:
        await api.close()


async def test_manual_and_daily_zips_include_history_checksums_and_no_token(tmp_path):
    history, clock, api = await connected(tmp_path)
    class Sources(DemoExportSources):
        async def logs(self, source):
            yield ("INFO " + TOKEN + "\n").encode()
    service = ExportService(tmp_path / "exports", Sources(), REDACTOR,
        clock=clock, min_free_bytes=0, demo=True, yandex_history=history)
    try:
        await history.poll_once()
        clock.advance()
        api.states["device-one"] = "offline"
        await history.poll_once()
        for kind in ["manual", "automatic"]:
            if kind == "manual":
                job = await service.start(StartExportArgs())
            else:
                service._observe_timezone({"time_zone": "UTC"})
                await service.set_schedule(ScheduleArgs(enabled=True, time="00:00"))
                job = await service.run_scheduled()
            await service._task
            assert service.jobs[job["export_id"]]["status"] == "ready"
            with zipfile.ZipFile(service.directory / (job["export_id"] + ".zip")) as archive:
                manifest = json.loads(archive.read("manifest.json"))
                assert manifest["kind"] == kind
                for name in ["yandex/devices.json", "yandex/availability_history.json", "yandex/coverage.json"]:
                    record = next(s for s in manifest["sources"] if s["file"] == name)
                    assert record["sha256"] == hashlib.sha256(archive.read(name)).hexdigest()
                value = json.loads(archive.read("yandex/availability_history.json"))
                assert any(e["previous_status"] == "online" and e["status"] == "offline" for e in value["events"])
                assert "availability_history.json" in archive.read("ARCHIVE_STRUCTURE.txt").decode()
                assert all(TOKEN.encode() not in archive.read(name) for name in archive.namelist())
            assert api.reads == 4  # ZIP creation does not poll the network.
    finally:
        await service.close()


async def test_unconfigured_source_is_explicit_and_not_a_failure(tmp_path):
    service = ExportService(tmp_path / "exports", DemoExportSources(), REDACTOR, demo=True, min_free_bytes=0)
    try:
        job = await service.start(StartExportArgs())
        await service._task
        with zipfile.ZipFile(service.directory / (job["export_id"] + ".zip")) as archive:
            coverage = json.loads(archive.read("yandex/coverage.json"))
            assert not coverage["configured"] and not coverage["enabled"]
            assert "yandex/availability_history.json" not in archive.namelist()
            assert service.jobs[job["export_id"]]["issues"] == 0
        with pytest.raises(BrokerError, match="YANDEX_DEMO_DISABLED"):
            await service.set_yandex(YandexArgs(enabled=True, token=TOKEN))
    finally:
        await service.close()


async def test_owner_only_connection_endpoint_and_ipc_hide_secrets(tmp_path):
    history, clock, api = await connected(tmp_path)
    service = ExportService(tmp_path / "exports", DemoExportSources(), REDACTOR,
        min_free_bytes=0, yandex_history=history)
    gate = AdminGate(demo=True)
    app = create_ui(service, gate=gate, web_dir="web", export_dir=service.directory)
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=("127.0.0.1", 42)), base_url="http://127.0.0.1:8099") as client:
            body = {"enabled": True, "token": TOKEN, "poll_seconds": 90, "retention_days": 7}
            assert (await client.post("/api/yandex", json=body)).status_code == 403
            headers = {"X-CSRF-Token": gate.csrf, "Origin": "http://127.0.0.1:8099"}
            response = await client.post("/api/yandex", headers=headers, json=body)
            assert response.status_code == 200 and TOKEN not in response.text
            assert response.json()["poll_seconds"] == 90
            assert (await client.get("/api/status")).json()["yandex"]["configured"]
            body["url"] = "https://evil.example"
            rejected = await client.post("/api/yandex", headers=headers, json=body)
            assert rejected.status_code == 400 and TOKEN not in rejected.text
            assert (await client.post("/api/yandex", headers=headers, content=b"x" * 16385)).status_code == 413
            assert (await client.post("/api/yandex", headers=headers | {"Origin": "https://evil.example"}, json={"enabled": False})).status_code == 403
        ipc = AdminIPCServer(tmp_path / "unused.sock", service.handlers())
        with pytest.raises(IPCError, match="IPC_FORBIDDEN"):
            await ipc.dispatch(10002, {"op": "set_yandex", "args": {"enabled": False}})
        result = await ipc.dispatch(10003, {"op": "set_yandex", "args": {"enabled": False}})
        assert not result["enabled"] and TOKEN not in json.dumps(result)
        if os.name != "nt":
            assert (tmp_path / "private/yandex-settings.json").stat().st_mode & 0o077 == 0
    finally:
        await service.close()


async def test_rate_limit_backs_off_and_stops_the_remaining_fleet(tmp_path):
    history, clock, api = await connected(tmp_path)
    try:
        api.catalog = [{"id": f"dev{i}", "name": "Device", "type": "devices.types.socket"} for i in range(20)]
        api.states = {d["id"]: "YANDEX_RATE_LIMIT" for d in api.catalog}
        api.retry_after = 120
        # This stub sets Retry-After when the actual request receives its 429.
        original = api.availability
        async def rate_limited(device):
            api.retry_after = 120
            return await original(device)
        api.availability = rate_limited
        await history.poll_once()
        assert api.reads <= 4
        assert history.status()["retry_seconds"] == 120
        clock.advance(120)
        await history.poll_once()
        assert history.status()["retry_seconds"] == 240
        assert all(e["status"] == "unknown" for e in (await history.export_snapshot())["events"])
        api.states = {d["id"]: "online" for d in api.catalog}
        clock.advance(240)
        await history.poll_once()
        assert history.status()["retry_seconds"] == 0
    finally:
        await history.close()


async def test_invalid_inventory_cannot_remove_previously_added_devices(tmp_path):
    clock = Clock()
    payload = {"status": "ok", "devices": [{"id": "lamp"}]}
    def handler(request):
        return httpx.Response(200, json=payload if request.url.path.endswith("user/info") else
            {"status": "ok", "id": "lamp", "state": "online"})
    history = YandexHistory(tmp_path / "private", REDACTOR, clock=clock,
        api_factory=lambda token: YandexAPI(token, transport=httpx.MockTransport(handler)))
    try:
        await history.configure(YandexArgs(enabled=True, token=TOKEN))
        await history.poll_once()
        clock.advance()
        payload = {"status": "ok", "devices": [{"id": "bad/path"}]}
        await history.poll_once()
        value = await history.export_snapshot()
        assert value["devices"][0]["present"] and value["devices"][0]["status"] == "unknown"
        assert all(e["status"] != "removed" for e in value["events"])
    finally:
        await history.close()


async def test_rebuilt_retention_boundary_cannot_overwrite_another_device(tmp_path):
    history, clock, api = await connected(tmp_path)
    try:
        await history.poll_once()
        old_ids = [e["event_id"] for e in (await history.export_snapshot())["events"]]
        clock.advance(31 * 86400)
        history.store.prune(clock(), 30)
        session = history.settings.session_id
        with history.store.db:
            for device in ["device-two", "device-one"]:
                from ha_diagnostics.yandex_history import stamp
                history.store.observe(session, REDACTOR.alias("YANDEX_DEVICE", device), api.states[device], stamp(clock()))
        value = await history.export_snapshot()
        assert len(value["events"]) == 2
        assert all(e["event_id"] > max(old_ids) for e in value["events"])
        assert {e["device_ref"]: e["status"] for e in value["events"]} == {
            REDACTOR.alias("YANDEX_DEVICE", "device-one"): "online",
            REDACTOR.alias("YANDEX_DEVICE", "device-two"): "offline"}
    finally:
        await history.close()


async def test_optional_corrupt_yandex_database_does_not_block_ha_zip(tmp_path):
    private = tmp_path / "private"
    private.mkdir()
    (private / "yandex-history.sqlite").write_bytes(b"corrupt database")
    service = ExportService(tmp_path / "exports", DemoExportSources(), REDACTOR, demo=True, min_free_bytes=0)
    try:
        assert service.yandex is None
        job = await service.start(StartExportArgs())
        await service._task
        assert service.jobs[job["export_id"]]["status"] == "ready"
        with zipfile.ZipFile(service.directory / (job["export_id"] + ".zip")) as archive:
            manifest = json.loads(archive.read("manifest.json"))
            source = next(s for s in manifest["sources"] if s["source"] == "yandex/coverage")
            assert source["status"] == "unavailable" and source["reason"] == "YANDEX_STORAGE_UNAVAILABLE"
            assert "home_assistant/config.json" in archive.namelist()
    finally:
        await service.close()

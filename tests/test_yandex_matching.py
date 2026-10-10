"""Identity, observation, privacy and owner-channel contracts with fake sources."""
from datetime import datetime, timedelta, timezone
import json
import zipfile

import httpx
import pytest

from ha_diagnostics.broker import BrokerError
from ha_diagnostics.exporter import ExportService, StartExportArgs
from ha_diagnostics.export_sources import DemoExportSources
from ha_diagnostics.ipc import AdminIPCServer, IPCError
from ha_diagnostics.redaction import Redactor
from ha_diagnostics.ui import AdminGate, create_ui
from ha_diagnostics.yandex_history import YandexHistory, YandexArgs, YandexEventsArgs, stamp
from ha_diagnostics.yandex_matching import CandidateArgs, LinkArgs, IdentityRuleArgs, MatchingArgs

TOKEN = "YANDEX_MATCHING_SECRET_123456"
HA_TOKEN = "HOME_ASSISTANT_MATCHING_SECRET_123456"
REDACTOR = Redactor(b"m" * 32)


class Clock:
    def __init__(self):
        self.now = datetime(2026, 10, 10, 0, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.now

    def advance(self, seconds=60):
        self.now += timedelta(seconds=seconds)


class HA(DemoExportSources):
    def __init__(self):
        self.fail = False
        self.calls = []
        self.registries = {
            "entities": [
                {"id": "registry-lamp", "entity_id": "light.bedroom", "platform": "matter",
                 "device_id": "ha-lamp", "name": "Светильник"},
                {"id": "registry-other", "entity_id": "light.other", "platform": "matter",
                 "device_id": "ha-other", "name": "Светильник"},
                {"id": "registry-socket", "entity_id": "switch.socket", "platform": "mqtt",
                 "device_id": "ha-socket", "name": "Розетка"},
                {"id": "registry-link", "entity_id": "binary_sensor.lamp_connection", "platform": "mqtt",
                 "device_id": "ha-lamp", "name": "Связь светильника"}],
            "devices": [{"id": "ha-lamp", "area_id": "bedroom", "name": "Светильник"},
                {"id": "ha-other", "area_id": "kitchen", "name": "Светильник"},
                {"id": "ha-socket", "area_id": "bedroom", "name": "Розетка"}],
            "areas": [{"area_id": "bedroom", "name": "Спальня"}, {"area_id": "kitchen", "name": "Кухня"}]}
        self.states = [
            {"entity_id": "light.bedroom", "state": "off", "attributes": {"friendly_name": "Светильник"}},
            {"entity_id": "light.other", "state": "on", "attributes": {}},
            {"entity_id": "switch.socket", "state": "on", "attributes": {}},
            {"entity_id": "binary_sensor.lamp_connection", "state": "on", "attributes": {"device_class": "connectivity"}},
            {"entity_id": "sensor.virtual", "state": "12", "attributes": {"friendly_name": "Виртуальный датчик"}}]

    scrub_known_secret = staticmethod(lambda text: text.replace(HA_TOKEN, "[REDACTED]"))

    async def registry(self, label):
        self.calls.append(("registry", label))
        if self.fail:
            raise BrokerError("UPSTREAM_UNAVAILABLE")
        return self.registries.get(label, [])

    async def snapshot(self, label):
        if label == "home_assistant/states":
            self.calls.append(("snapshot", label))
            if self.fail:
                raise BrokerError("UPSTREAM_UNAVAILABLE")
            return self.states
        return await super().snapshot(label)


class API:
    def __init__(self):
        self.catalog = [
            {"id": "y-lamp", "name": "Светильник", "type": "devices.types.light",
             "home_name": "Квартира", "room_name": "Спальня", "skill_id": "skill-ha", "external_id": "light.bedroom"},
            {"id": "y-other", "name": "Светильник", "type": "devices.types.light",
             "home_name": "Квартира", "room_name": "Спальня", "skill_id": "skill-other", "external_id": "light.bedroom"}]
        self.states = {"y-lamp": "online", "y-other": "offline"}

    async def devices(self):
        return self.catalog

    async def availability(self, device):
        if self.states[device].startswith("YANDEX_"):
            raise BrokerError(self.states[device])
        return self.states[device]

    async def close(self):
        pass


@pytest.fixture
async def setup(tmp_path):
    clock, api, ha = Clock(), API(), HA()
    history = YandexHistory(tmp_path / "private", REDACTOR, clock=clock, api_factory=lambda token: api)
    history.matcher.sources = ha
    await history.configure(YandexArgs(enabled=True, token=TOKEN))
    await history.poll_once()
    yield history, clock, api, ha
    await history.close()


def entity_ref(history, entity_id="light.bedroom"):
    return next(ref for ref, entity in history.matcher.entities.items() if entity["entity_id"] == entity_id)


def device_ref(device="y-lamp"):
    return REDACTOR.alias("YANDEX_DEVICE", device)


def link_args(history, entity=None, method="manual", device="y-lamp"):
    return LinkArgs(session_id=history.settings.session_id, device_ref=device_ref(device),
        entity_ref=entity or entity_ref(history), method=method)


def rule_args(history, **changes):
    return IdentityRuleArgs(**({"session_id": history.settings.session_id, "skill_id": "skill-ha", "enabled": True} | changes))


async def test_exact_ids_need_an_owner_rule_and_are_scoped_to_skill_and_session(setup):
    history, clock, api, ha = setup
    before = await history.panel_links(MatchingArgs())
    assert all(row["comparison"] == "unlinked" for row in before["devices"])
    await history.set_identity_rule(rule_args(history))
    after = await history.panel_links(MatchingArgs())
    lamp = next(row for row in after["devices"] if row["device_ref"] == device_ref())
    other = next(row for row in after["devices"] if row["device_ref"] == device_ref("y-other"))
    assert lamp["method"] == "exact" and lamp["comparison"] == "match" and lamp["ha_status"] == "available"
    assert other["comparison"] == "unlinked"  # Same external ID in a different namespace.
    old_rule = rule_args(history)
    await history.configure(YandexArgs(enabled=True, token="NEW_YANDEX_ACCOUNT_TOKEN_123456"))
    with pytest.raises(BrokerError, match="YANDEX_CONNECTION_CHANGED"):
        await history.set_identity_rule(old_rule)
    await history.poll_once()
    assert all(row["comparison"] == "unlinked" for row in (await history.panel_links(MatchingArgs()))["devices"])


async def test_exact_prefix_manual_override_and_explicit_unlink(setup):
    history, clock, api, ha = setup
    api.catalog[0]["external_id"] = "home-1:light.bedroom"
    clock.advance()
    await history.poll_once()
    await history.set_identity_rule(rule_args(history, external_prefix="home-2:"))
    assert history.matcher.link(history.settings.session_id, device_ref()) is None
    await history.set_identity_rule(rule_args(history, external_prefix="home-1:"))
    assert history.matcher.link(history.settings.session_id, device_ref())["method"] == "exact"
    await history.set_link(link_args(history, entity_ref(history, "light.other")))
    await history.set_identity_rule(rule_args(history, external_prefix="home-1:"))
    assert history.matcher.link(history.settings.session_id, device_ref())["method"] == "manual"
    await history.set_identity_rule(rule_args(history, enabled=False))
    assert history.matcher.link(history.settings.session_id, device_ref())["method"] == "manual"
    await history.set_identity_rule(rule_args(history, external_prefix="home-1:"))
    await history.set_link(LinkArgs(session_id=history.settings.session_id, device_ref=device_ref(), entity_ref=None))
    clock.advance()
    await history.poll_once()
    assert history.matcher.link(history.settings.session_id, device_ref())["method"] == "blocked"


async def test_suggestions_rank_room_and_type_but_never_auto_confirm(setup):
    history, clock, api, ha = setup
    args = CandidateArgs(session_id=history.settings.session_id, device_ref=device_ref())
    candidates = (await history.candidates(args))["candidates"]
    assert candidates[0]["entity_ref"] == entity_ref(history)
    assert candidates[0]["reasons"] == ["type", "name", "room"]
    assert len(candidates) == 2
    assert history.matcher.link(history.settings.session_id, device_ref()) is None
    with pytest.raises(BrokerError, match="YANDEX_CANDIDATE_CHANGED"):
        await history.set_link(link_args(history, entity_ref(history, "switch.socket"), "suggestion"))
    await history.set_link(link_args(history, method="suggestion"))
    assert history.matcher.link(history.settings.session_id, device_ref())["method"] == "suggestion"


async def test_saved_identity_survives_entity_rename_and_restart_without_name_matching(setup, tmp_path):
    history, clock, api, ha = setup
    await history.set_identity_rule(rule_args(history))
    ref = entity_ref(history)
    ha.registries["entities"][0].update(entity_id="light.renamed", name="Другое имя")
    ha.states[0]["entity_id"] = "light.renamed"
    clock.advance(301)
    await history.poll_once()
    assert entity_ref(history, "light.renamed") == ref
    await history.close()
    restarted = YandexHistory(tmp_path / "private", REDACTOR, clock=clock, api_factory=lambda token: api)
    restarted.matcher.sources = ha
    try:
        await restarted.poll_once()
        row = next(row for row in (await restarted.panel_links(MatchingArgs()))["devices"] if row["device_ref"] == device_ref())
        assert row["ha_entity_ref"] == ref and row["comparison"] == "match" and row["method"] == "exact"
    finally:
        await restarted.close()


async def test_recreated_entity_and_changed_provider_id_require_new_confirmation(setup):
    history, clock, api, ha = setup
    await history.set_identity_rule(rule_args(history))
    original = entity_ref(history)
    ha.registries["entities"][0]["id"] = "new-registry-lamp"
    clock.advance(301)
    await history.poll_once()
    row = next(row for row in (await history.panel_links(MatchingArgs()))["devices"] if row["device_ref"] == device_ref())
    assert row["ha_entity_ref"] == original and row["ha_reason"] == "HA_ENTITY_MISSING" and row["comparison"] == "unknown"
    await history.set_link(link_args(history))
    api.catalog[0]["external_id"] = "different-device"
    clock.advance()
    await history.poll_once()
    row = next(row for row in (await history.panel_links(MatchingArgs()))["devices"] if row["device_ref"] == device_ref())
    assert row["ha_reason"] == "YANDEX_IDENTITY_CHANGED" and row["comparison"] == "unknown"


async def test_unique_id_fallback_is_stable_and_scoped_to_integration(setup):
    history, clock, api, ha = setup
    first = ha.registries["entities"][0]
    first.pop("id")
    first.update(unique_id="lamp-hardware-key", config_entry_id="matter-instance")
    second = ha.registries["entities"][1]
    second.pop("id")
    second.update(unique_id="lamp-hardware-key", config_entry_id="different-matter-instance")
    clock.advance(301)
    await history.poll_once()
    ref = entity_ref(history)
    assert ref != entity_ref(history, "light.other")
    await history.set_link(link_args(history))
    first["entity_id"] = ha.states[0]["entity_id"] = "light.new_name"
    clock.advance(301)
    await history.poll_once()
    assert entity_ref(history, "light.new_name") == ref
    assert history.matcher.comparison(history.settings.session_id, device_ref(), "online", 60)["comparison"] == "match"


async def test_private_display_labels_scrub_both_tokens_and_ids_are_not_truncated(setup):
    history, clock, api, ha = setup
    api.catalog[0].update(name="Свет " + HA_TOKEN, external_id="light.bedroom" + "x" * 1100)
    ha.states[0]["attributes"]["friendly_name"] = "Свет " + TOKEN + " " + HA_TOKEN
    clock.advance()
    await history.poll_once()
    await history.set_link(link_args(history))
    clock.advance()
    await history.poll_once()
    panel = json.dumps(await history.panel_links(MatchingArgs()), ensure_ascii=False)
    panel += json.dumps(await history.panel_events(YandexEventsArgs()), ensure_ascii=False)
    private = history.store.ui_path.read_bytes()
    for token in (TOKEN, HA_TOKEN):
        assert token not in panel and token.encode() not in private
    assert history.matcher.identity(history.settings.session_id, device_ref())["external_id"] is None
    with pytest.raises(BrokerError, match="YANDEX_IDENTITY_RULE_REJECTED"):
        await history.set_identity_rule(rule_args(history, external_prefix=TOKEN))


async def test_history_records_ha_only_changes_and_preserves_original_snapshot(setup):
    history, clock, api, ha = setup
    original = (await history.panel_events(YandexEventsArgs()))["events"]
    assert all(row["comparison"] == "unlinked" for row in original)
    await history.set_link(link_args(history))
    clock.advance()
    await history.poll_once()
    matched = next(row for row in (await history.panel_events(YandexEventsArgs()))["events"] if row["ha_entity_ref"])
    assert matched["kind"] == "comparison" and matched["status"] == "online" and matched["comparison"] == "match"
    clock.advance()
    await history.poll_once()
    assert next(row for row in (await history.panel_events(YandexEventsArgs()))["events"] if row["event_id"] == matched["event_id"]) == matched
    ha.states[0]["state"] = "unavailable"
    clock.advance()
    await history.poll_once()
    events = (await history.panel_events(YandexEventsArgs()))["events"]
    newest = events[0]
    assert newest["status"] == "online" and newest["kind"] == "comparison" and newest["comparison"] == "mismatch"
    assert newest["ha_status"] == "unavailable" and newest["ha_observed_at"] == stamp(clock())
    assert next(row for row in events if row["event_id"] == matched["event_id"]) == matched
    assert next(row for row in events if row["event_id"] == original[0]["event_id"]) == original[0]
    await history.set_link(link_args(history, entity_ref(history, "light.other")))
    clock.advance()
    await history.poll_once()
    assert next(row for row in (await history.panel_events(YandexEventsArgs()))["events"] if row["event_id"] == newest["event_id"]) == newest


@pytest.mark.parametrize("state,attrs,expected", [
    ("off", {}, "available"), ("unavailable", {}, "unavailable"), ("unknown", {}, "unknown"),
    ("on", {"assumed_state": True}, "unknown"), ("on", {"device_class": "connectivity"}, "available")])
async def test_ha_operating_state_is_not_connectivity(setup, state, attrs, expected):
    history, clock, api, ha = setup
    await history.set_link(link_args(history))
    ha.states[0].update(state=state, attributes=attrs)
    clock.advance()
    await history.poll_once()
    event = (await history.panel_events(YandexEventsArgs()))["events"][0]
    assert event["ha_status"] == expected
    assert event["comparison"] == {"available": "match", "unavailable": "mismatch", "unknown": "unknown"}[expected]


async def test_connectivity_sensor_can_be_selected_and_virtual_entities_can_be_linked(setup):
    history, clock, api, ha = setup
    await history.set_link(link_args(history, entity_ref(history, "binary_sensor.lamp_connection")))
    ha.states[3]["state"] = "off"
    clock.advance()
    await history.poll_once()
    assert (await history.panel_events(YandexEventsArgs()))["events"][0]["ha_status"] == "unavailable"
    virtual = history.matcher.entities[entity_ref(history, "sensor.virtual")]
    assert not virtual["stable"]
    await history.set_link(link_args(history, virtual["entity_ref"]))
    clock.advance()
    await history.poll_once()
    assert (await history.panel_events(YandexEventsArgs()))["events"][0]["ha_status"] == "available"


async def test_source_failure_staleness_and_yandex_errors_are_not_mismatches(setup):
    history, clock, api, ha = setup
    await history.set_link(link_args(history))
    ha.fail = True
    clock.advance()
    await history.poll_once()
    event = (await history.panel_events(YandexEventsArgs()))["events"][0]
    assert event["comparison"] == "unknown" and event["ha_reason"] == "HA_SOURCE_UNAVAILABLE"
    assert event["reason"] is None
    ha.fail = False
    clock.advance()
    await history.poll_once()
    clock.advance(200)
    comparison = history.matcher.comparison(history.settings.session_id, device_ref(), "online", 60)
    assert comparison["comparison"] == "unknown" and comparison["ha_reason"] == "HA_OBSERVATION_STALE"
    api.states["y-lamp"] = "YANDEX_NETWORK_ERROR"
    await history.poll_once()
    event = next(row for row in (await history.export_snapshot())["events"] if row["status"] == "unknown" and row["reason"] == "YANDEX_NETWORK_ERROR")
    assert event["comparison"] == "unknown" and event["reason"] == "YANDEX_NETWORK_ERROR"


async def test_legacy_events_have_no_retroactive_comparison_and_retention_prunes_private_labels(setup):
    history, clock, api, ha = setup
    with history.store.db:
        history.store.db.execute("DELETE FROM ha_comparisons")
        history.store.db.execute("DELETE FROM local_ui.comparison_labels")
    await history.set_link(link_args(history))
    events = (await history.panel_events(YandexEventsArgs()))["events"]
    assert all(row["ha_reason"] == "HA_NOT_OBSERVED" and row["comparison"] == "unknown" for row in events)
    clock.advance()
    await history.poll_once()
    assert history.store.db.execute("SELECT COUNT(*) FROM local_ui.comparison_labels").fetchone()[0]
    clock.advance(31 * 86400)
    history.store.prune(clock(), 30)
    assert history.store.db.execute("SELECT COUNT(*) FROM ha_comparisons").fetchone()[0] == 0
    assert history.store.db.execute("SELECT COUNT(*) FROM local_ui.comparison_labels").fetchone()[0] == 0


async def test_owner_only_matching_routes_csrf_and_ipc(setup, tmp_path):
    history, clock, api, ha = setup
    service = ExportService(tmp_path / "exports", ha, REDACTOR, min_free_bytes=0, yandex_history=history, clock=clock)
    gate = AdminGate("owner")
    app = create_ui(service, gate=gate, web_dir="web")
    try:
        for peer, owner, allowed in [("198.51.100.2", "owner", False), ("172.30.32.2", "other", False), ("172.30.32.2", "owner", True)]:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=(peer, 42)), base_url="http://localhost") as client:
                headers = {"X-Remote-User-Id": owner}
                response = await client.get("/api/yandex/links", headers=headers)
                assert response.status_code == (200 if allowed else 403)
                assert response.headers["Cache-Control"] == "no-store" and TOKEN not in response.text and HA_TOKEN not in response.text
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=("172.30.32.2", 42)), base_url="http://localhost") as client:
            headers = {"X-Remote-User-Id": "owner", "X-Ingress-Path": "/api/hassio_ingress/test", "Sec-Fetch-Site": "same-origin"}
            query = {"session_id": history.settings.session_id, "device_ref": device_ref()}
            assert (await client.get("/api/yandex/candidates", params=query, headers=headers)).status_code == 200
            for url in ("/api/yandex/links?url=evil", "/api/yandex/candidates?device_ref=bad", "/api/yandex/candidates?session_id=a&session_id=b"):
                assert (await client.get(url, headers=headers)).status_code == 400
            body = {"op": "set_yandex_link", "args": link_args(history).model_dump()}
            assert (await client.post("/api/action", headers=headers, json=body)).status_code == 403
            headers["X-CSRF-Token"] = gate.csrf
            assert (await client.post("/api/action", headers=headers, json=body)).status_code == 200
            body["args"]["url"] = "https://evil.example"
            assert (await client.post("/api/action", headers=headers, json=body)).status_code == 400
        ipc = AdminIPCServer(tmp_path / "unused.sock", service.handlers())
        for op in ("yandex_links", "yandex_candidates", "set_yandex_link", "set_yandex_identity_rule"):
            with pytest.raises(IPCError, match="IPC_FORBIDDEN"):
                await ipc.dispatch(10002, {"op": op, "args": {}})
        assert (await ipc.dispatch(10003, {"op": "yandex_links", "args": {}}))["devices"]
        assert all(kind == "registry" and label in {"entities", "devices", "areas"} or kind == "snapshot" and label == "home_assistant/states" for kind, label in ha.calls)
    finally:
        await service.close()


async def test_comparison_exports_only_aliases_and_never_private_identities(setup, tmp_path):
    history, clock, api, ha = setup
    await history.set_identity_rule(rule_args(history))
    clock.advance()
    await history.poll_once()
    snapshot = await history.export_snapshot()
    text = json.dumps(snapshot, ensure_ascii=False)
    for private in (TOKEN, HA_TOKEN, "light.bedroom", "registry-lamp", "y-lamp", "skill-ha", "Светильник", "Спальня", "Квартира"):
        assert private not in text
        assert private.encode() not in history.store.path.read_bytes()
    service = ExportService(tmp_path / "exports", ha, REDACTOR, min_free_bytes=0, yandex_history=history, clock=clock)
    try:
        job = await service.start(StartExportArgs())
        await service._task
        assert service.jobs[job["export_id"]]["status"] == "ready"
        with zipfile.ZipFile(service.directory / (job["export_id"] + ".zip")) as archive:
            yandex = b"".join(archive.read(name) for name in archive.namelist() if name.startswith("yandex/"))
            for private in (TOKEN, HA_TOKEN, "light.bedroom", "y-lamp", "skill-ha", "Светильник"):
                assert private.encode() not in yandex
            events = json.loads(archive.read("yandex/availability_history.json"))
            assert events["schema_version"] == 2 and any(event["comparison"] == "match" for event in events["events"])
            assert not any("sqlite" in name or "links" in name or "identity_rules" in name for name in archive.namelist())
    finally:
        await service.close()

"""Late bindings, as-of Recorder comparisons and whole-history filtering."""
import asyncio
from datetime import timedelta
import json

import httpx
import pytest
from pydantic import ValidationError

from ha_diagnostics.broker import BrokerError
from ha_diagnostics.export_sources import ExportSources
from ha_diagnostics.exporter import ExportService
from ha_diagnostics.ui import AdminGate, create_ui
from ha_diagnostics.yandex_backfill import instant, MAX_HISTORY_STATES
from ha_diagnostics.yandex_history import YandexHistory, YandexArgs, YandexEventsArgs, stamp
from test_yandex_matching import API, HA, Clock, REDACTOR, TOKEN, HA_TOKEN, device_ref, entity_ref, link_args, rule_args


class RecorderHA(HA):
    def __init__(self):
        super().__init__()
        self.rows = {}
        self.history_calls = []
        self.history_failure = False
        self.payload = None
        self.waiting, self.release = asyncio.Event(), None

    async def entity_history(self, entity_id, start, end):
        self.history_calls.append((entity_id, start, end))
        self.waiting.set()
        if self.release:
            await self.release.wait()
        if self.history_failure:
            raise BrokerError(TOKEN + HA_TOKEN)
        if self.payload is not None:
            return self.payload
        rows = sorted(self.rows.get(entity_id, []), key=lambda row: instant(row["last_updated"]))
        prior = [row for row in rows if instant(row["last_updated"]) <= instant(start)]
        within = [row for row in rows if instant(start) < instant(row["last_updated"]) < instant(end)]
        result = prior[-1:] + within
        return [result] if result else []


@pytest.fixture
async def recorder(tmp_path):
    clock, api, ha = Clock(), API(), RecorderHA()
    history = YandexHistory(tmp_path / "private", REDACTOR, clock=clock, api_factory=lambda token: api)
    history.matcher.sources = ha
    await history.configure(YandexArgs(enabled=True, token=TOKEN))
    await history.poll_once()
    yield history, clock, api, ha
    await history.close()


def state(at, value, entity_id="light.bedroom", **attrs):
    return {"entity_id": entity_id, "state": value, "attributes": attrs,
        "last_updated": stamp(at), "last_changed": stamp(at)}


async def lamp_events(history, **args):
    feed = await history.panel_events(YandexEventsArgs(**args))
    return [row for row in feed["events"] if row["device_name"] == "Светильник" and row["ha_entity_ref"]]


@pytest.mark.parametrize("method", ["manual", "suggestion", "exact"])
async def test_all_three_late_bindings_use_historical_not_current_status(recorder, method):
    history, clock, api, ha = recorder
    first_at = clock()
    ha.rows["light.bedroom"] = [state(first_at - timedelta(seconds=30), "off"),
        state(first_at + timedelta(seconds=30), "unavailable")]
    original_ids = [row[0] for row in history.store.db.execute("SELECT event_id FROM events")]
    api.states["y-lamp"] = "offline"
    clock.advance()
    await history.poll_once()
    last_at = clock()
    clock.advance()
    if method == "exact":
        await history.set_identity_rule(rule_args(history))
    else:
        await history.set_link(link_args(history, method=method))
    pending = await lamp_events(history)
    assert all(row["comparison"] == "unknown" and row["ha_reason"] == "HA_HISTORY_PENDING" for row in pending)
    await history.backfill.task
    events = await lamp_events(history)
    assert [(row["observed_at"], row["ha_status"], row["comparison"]) for row in events] == [
        (stamp(last_at), "unavailable", "match"), (stamp(first_at), "available", "match")]
    assert all(row["ha_origin"] == "history" and row["ha_retrieved_at"] == stamp(clock()) and row["method"] == method for row in events)
    assert events[-1]["event_id"] in original_ids
    assert history.matcher.entities[entity_ref(history)]["ha_status"] == "available"
    # Other skills/devices are not backfilled by this device's link.
    other = [dict(row) for row in history.store.db.execute("SELECT c.* FROM ha_comparisons c JOIN events e ON e.event_id=c.event_id WHERE e.device_ref=?", (device_ref("y-other"),))]
    assert all(row["comparison"] == "unlinked" for row in other)
    assert len(ha.history_calls) == 1
    assert ha.history_calls[0][0] == "light.bedroom"


async def test_missing_history_is_linked_unknown_and_retries_without_fabricating_past(recorder):
    history, clock, api, ha = recorder
    at = clock()
    await history.set_link(link_args(history))
    await history.backfill.task
    missing = (await lamp_events(history))[0]
    assert missing["ha_reason"] == "HA_HISTORY_EMPTY" and missing["comparison"] == "unknown"
    assert missing["ha_entity_ref"] == entity_ref(history) and missing["ha_status"] == "unknown"
    assert missing["ha_observed_at"] is None
    await history.backfill.task
    assert len(ha.history_calls) == 1
    ha.rows["light.bedroom"] = [state(at - timedelta(seconds=5), "unavailable")]
    clock.advance(301)
    await history.panel_events(YandexEventsArgs())
    await history.backfill.task
    restored = (await lamp_events(history))[0]
    assert restored["ha_status"] == "unavailable" and restored["comparison"] == "mismatch"
    assert restored["ha_observed_at"] == stamp(at)


async def test_future_states_and_other_entities_do_not_supply_missing_past(recorder):
    history, clock, api, ha = recorder
    at = clock()
    ha.payload = [[state(at + timedelta(seconds=30), "unavailable"), state(at - timedelta(seconds=5), "on", "light.other")]]
    clock.advance(60)
    await history.set_link(link_args(history))
    await history.backfill.task
    row = (await lamp_events(history))[0]
    assert row["ha_status"] == "unknown" and row["ha_reason"] == "HA_HISTORY_EMPTY"
    assert not (await history.panel_events(YandexEventsArgs(comparison="mismatch")))["events"]


async def test_attribute_change_uses_last_updated_and_unknown_is_not_a_mismatch(recorder):
    history, clock, api, ha = recorder
    at = clock()
    changed = state(at + timedelta(seconds=30), "off", assumed_state=True)
    changed["last_changed"] = stamp(at - timedelta(seconds=30))
    ha.rows["light.bedroom"] = [state(at - timedelta(seconds=30), "off"), changed]
    api.states["y-lamp"] = "offline"
    clock.advance()
    await history.poll_once()
    await history.set_link(link_args(history))
    await history.backfill.task
    rows = await lamp_events(history)
    assert rows[0]["comparison"] == "unknown" and rows[0]["ha_reason"] == "HA_UNKNOWN_STATE"
    assert rows[1]["comparison"] == "match"
    assert not (await history.panel_events(YandexEventsArgs(comparison="mismatch")))["events"]


@pytest.mark.parametrize("entity_id,attrs,expected", [
    ("light.bedroom", {}, "available"),
    ("binary_sensor.lamp_connection", {"device_class": "connectivity"}, "unavailable")])
async def test_historical_off_uses_the_selected_availability_source(recorder, entity_id, attrs, expected):
    history, clock, api, ha = recorder
    ha.rows[entity_id] = [state(clock() - timedelta(seconds=30), "off", entity_id, **attrs)]
    await history.set_link(link_args(history, entity_ref(history, entity_id)))
    await history.backfill.task
    assert (await lamp_events(history))[0]["ha_status"] == expected


async def test_failed_history_read_does_not_leak_payload_or_mark_devices_offline(recorder):
    history, clock, api, ha = recorder
    ha.history_failure = True
    await history.set_link(link_args(history))
    await history.backfill.task
    row = (await lamp_events(history))[0]
    assert row["ha_reason"] == "HA_HISTORY_UNAVAILABLE" and row["comparison"] == "unknown"
    assert row["status"] == "online"
    serialized = json.dumps(await history.export_snapshot())
    assert TOKEN not in serialized and HA_TOKEN not in serialized and "light.bedroom" not in serialized


@pytest.mark.parametrize("payload,reason", [
    ({"error": TOKEN}, "HA_HISTORY_INVALID"),
    ([[{"entity_id": "light.bedroom", "state": "on", "last_updated": "not-a-date"}]], "HA_HISTORY_INVALID"),
    ([[{"entity_id": "light.bedroom"}] * (MAX_HISTORY_STATES + 1)], "HA_HISTORY_LIMIT")])
async def test_unusable_history_stays_unknown(recorder, payload, reason):
    history, clock, api, ha = recorder
    ha.payload = payload
    await history.set_link(link_args(history))
    await history.backfill.task
    row = (await lamp_events(history))[0]
    assert row["ha_reason"] == reason and row["comparison"] == "unknown"


async def test_remap_during_read_discards_the_old_mapping_result(recorder):
    history, clock, api, ha = recorder
    at = clock()
    ha.rows = {"light.bedroom": [state(at - timedelta(seconds=30), "unavailable")],
        "light.other": [state(at - timedelta(seconds=30), "off", "light.other")]}
    ha.release = asyncio.Event()
    await history.set_link(link_args(history))
    await ha.waiting.wait()
    await history.set_link(link_args(history, entity_ref(history, "light.other")))
    ha.release.set()
    await history.backfill.task
    row = (await lamp_events(history))[0]
    assert row["ha_entity_ref"] == entity_ref(history, "light.other") and row["comparison"] == "match"
    assert [call[0] for call in ha.history_calls] == ["light.bedroom", "light.other"]


async def test_unlink_during_read_does_not_apply_an_outdated_status(recorder):
    history, clock, api, ha = recorder
    ha.rows["light.bedroom"] = [state(clock() - timedelta(seconds=30), "unavailable")]
    ha.release = asyncio.Event()
    await history.set_link(link_args(history))
    await ha.waiting.wait()
    args = link_args(history).model_copy(update={"entity_ref": None})
    await history.set_link(args)
    ha.release.set()
    await history.backfill.task
    # No status from the cancelled relation may be written or left pending.
    feed = await history.panel_events(YandexEventsArgs())
    assert feed["history_pending"] == 0
    assert all(row["ha_status"] == "unknown" and row["comparison"] == "unlinked" for row in feed["events"])


async def test_account_change_during_read_discards_results(recorder):
    history, clock, api, ha = recorder
    ha.release = asyncio.Event()
    await history.set_link(link_args(history))
    await ha.waiting.wait()
    old_session = history.settings.session_id
    await history.configure(YandexArgs(enabled=True, token=TOKEN + "other"))
    ha.release.set()
    await history.backfill.task
    assert not (await history.panel_events(YandexEventsArgs()))["events"]
    assert all(row[0] == "unknown" for row in history.store.db.execute("SELECT ha_status FROM ha_comparisons c JOIN events e ON e.event_id=c.event_id WHERE e.session_id=?", (old_session,)))


async def test_retention_during_read_does_not_recreate_pruned_events(recorder):
    history, clock, api, ha = recorder
    ha.release = asyncio.Event()
    await history.set_link(link_args(history))
    await ha.waiting.wait()
    clock.advance(31 * 86400)
    history.store.prune(clock(), 30)
    ha.release.set()
    await history.backfill.task
    assert history.store.db.execute("SELECT COUNT(*) FROM ha_comparisons").fetchone()[0] == 0
    assert history.store.db.execute("SELECT COUNT(*) FROM local_ui.comparison_labels").fetchone()[0] == 0


async def test_backfill_migrates_alpha7_database_without_losing_observed_snapshots(recorder):
    history, clock, api, ha = recorder
    original = [dict(row) for row in history.store.db.execute("SELECT * FROM ha_comparisons")]
    with history.store.db:
        history.store.db.execute("ALTER TABLE ha_comparisons DROP COLUMN ha_origin")
        history.store.db.execute("ALTER TABLE ha_comparisons DROP COLUMN ha_retrieved_at")
    directory = history.settings_store.directory
    await history.close()
    restored = YandexHistory(directory, REDACTOR, clock=clock, api_factory=lambda token: api)
    restored.matcher.sources = ha
    try:
        assert [dict(row) for row in restored.store.db.execute("SELECT * FROM ha_comparisons")] == original
        ha.rows["light.bedroom"] = [state(clock() - timedelta(seconds=30), "off")]
        await restored.matcher.refresh()
        await restored.set_link(link_args(restored))
        await restored.backfill.task
        assert (await lamp_events(restored))[0]["comparison"] == "match"
    finally:
        await restored.close()


async def test_known_observed_comparisons_survive_later_remapping(recorder):
    history, clock, api, ha = recorder
    await history.set_link(link_args(history))
    await history.backfill.task
    clock.advance()
    await history.poll_once()
    recorded = (await lamp_events(history))[0]
    assert recorded["ha_origin"] == "observed" and recorded["comparison"] == "match"
    await history.set_link(link_args(history, entity_ref(history, "light.other")))
    await history.backfill.task
    rows = await lamp_events(history)
    assert next(row for row in rows if row["event_id"] == recorded["event_id"]) == recorded


async def test_legacy_and_restart_fill_old_links_and_use_bounded_windows(recorder, tmp_path):
    history, clock, api, ha = recorder
    at = clock()
    ha.rows["light.bedroom"] = [state(at - timedelta(seconds=30), "off")]
    api.states["y-lamp"] = "offline"
    clock.advance(3601)
    await history.poll_once()
    with history.store.db:
        history.store.db.execute("DELETE FROM ha_comparisons")
        history.store.db.execute("DELETE FROM local_ui.comparison_labels")
    # Persist a pre-existing link without running backfill, as on an upgrade.
    history.matcher.set_link(link_args(history), history.settings.session_id)
    directory = history.settings_store.directory
    await history.close()
    restored = YandexHistory(directory, REDACTOR, clock=clock, api_factory=lambda token: api)
    restored.matcher.sources = ha
    try:
        await restored.panel_events(YandexEventsArgs())
        await restored.backfill.task
        rows = await lamp_events(restored)
        assert len(rows) == 2 and {row["comparison"] for row in rows} == {"match", "mismatch"}
        assert len(ha.history_calls) == 2
        assert all(timedelta(0) < instant(end) - instant(start) <= timedelta(hours=1) for _, start, end in ha.history_calls)
        snapshot = await restored.export_snapshot()
        assert snapshot["coverage"]["schema_version"] == 3
        assert all(row["ha_origin"] == "history" for row in snapshot["events"] if row["ha_entity_ref"])
    finally:
        await restored.close()


async def test_filter_is_applied_before_pagination_and_excludes_unknown(recorder):
    history, clock, api, ha = recorder
    ha.rows["light.bedroom"] = [state(clock() - timedelta(seconds=30), "off")]
    for status in ["offline", "online", "offline", "online", "offline"]:
        api.states["y-lamp"] = status
        clock.advance()
        await history.poll_once()
    await history.set_link(link_args(history))
    await history.backfill.task
    all_events = (await history.panel_events(YandexEventsArgs()))["events"]
    for verdict in ["match", "mismatch"]:
        expected = [row for row in all_events if row["comparison"] == verdict]
        loaded, cursor = [], None
        while True:
            feed = await history.panel_events(YandexEventsArgs(comparison=verdict, limit=2, before_event_id=cursor))
            assert feed["comparison"] == verdict and feed["history_pending"] == 0
            loaded.extend(feed["events"])
            cursor = feed["next_before_event_id"]
            if cursor is None:
                break
        assert loaded == expected and len(loaded) == 3
    assert any(row["comparison"] == "unlinked" for row in all_events)


async def test_filter_owner_route_and_strict_queries(recorder, tmp_path):
    history, clock, api, ha = recorder
    service = ExportService(tmp_path / "exports", ha, REDACTOR, min_free_bytes=0, yandex_history=history, clock=clock)
    gate = AdminGate("owner")
    app = create_ui(service, gate=gate, web_dir="web")
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=("172.30.32.2", 42)), base_url="http://localhost") as client:
            headers = {"X-Remote-User-Id": "owner"}
            response = await client.get("/api/yandex/events?comparison=mismatch&limit=1", headers=headers)
            assert response.status_code == 200 and response.json()["events"] == []
            assert response.headers["Cache-Control"] == "no-store"
            for query in ["comparison=unknown", "comparison=match&comparison=mismatch", "limit=1x", "comparison=match&url=https://evil", "before_event_id=0"]:
                assert (await client.get("/api/yandex/events?" + query, headers=headers)).status_code == 400
            assert (await client.get("/api/yandex/events?comparison=match", headers={"X-Remote-User-Id": "other"})).status_code == 403
    finally:
        await service.close()
    for value in ["unknown", "MATCH", None, 1]:
        with pytest.raises(ValidationError):
            YandexEventsArgs(comparison=value)


async def test_filtered_history_read_has_fixed_origin_and_no_write_capability():
    requests = []
    source = ExportSources(HA_TOKEN, transport=httpx.MockTransport(lambda request:
        requests.append(request) or httpx.Response(200, json=[])))
    start, end = "2026-10-10T00:00:00Z", "2026-10-10T00:01:00Z"
    try:
        assert await source.entity_history("light.bedroom", start, end) == []
        request = requests[0]
        assert request.method == "GET" and str(request.url).startswith("http://supervisor/core/api/history/period/")
        assert dict(request.url.params) == {"end_time": end, "filter_entity_id": "light.bedroom", "significant_changes_only": "0"}
        for entity_id in ["light.a,light.b", "https://evil.test", "light.a?token=" + HA_TOKEN, "light.a\n", "light.*", "sensor." + "x" * 256]:
            with pytest.raises(BrokerError):
                await source.entity_history(entity_id, start, end)
        assert len(requests) == 1
        params = dict(request.url.params)
        for method, path, query in [("POST", request.url.path, params),
                ("GET", "/core/api/logbook/" + start, params),
                ("GET", request.url.path, params | {"skip_initial_state": "1"}),
                ("GET", request.url.path, params | {"end_time": "2026-10-11T00:00:00Z"}),
                ("GET", request.url.path, params | {"significant_changes_only": "1"})]:
            with pytest.raises(BrokerError):
                source.validate_request(method, path, query, False)
    finally:
        await source.close()

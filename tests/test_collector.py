import asyncio
import json

import httpx
import pytest

from ha_diagnostics.archive import Archive
from ha_diagnostics.broker import BrokerPolicy, ReadBroker
from ha_diagnostics.broker import BrokerError
from ha_diagnostics.collector import Collector
from ha_diagnostics.redaction import Redactor


@pytest.fixture
def archive(tmp_path):
    value = Archive(tmp_path / "archive.sqlite", Redactor(b"r" * 32), min_free_bytes=0)
    value.register_source("core")
    value.register_source("entities", kind="state")
    yield value
    value.close()


def fake_collector(archive, batches, boots=None):
    batches = iter(batches)
    boots = iter(boots or ["a" * 32] * 20)
    latest_boot = ["a" * 32]
    def upstream(request):
        if request.url.path == "/host/logs/boots":
            latest_boot[0] = next(boots)
            return httpx.Response(200, json={"result": "ok", "data": {"0": latest_boot[0]}})
        return httpx.Response(200, text=next(batches))
    broker = ReadBroker(BrokerPolicy(mode="live", enabled_sources={"core", "entities"}, entity_ids={"sensor.fixture"}),
        archive.redactor, "synthetic-manager-credential", transport=httpx.MockTransport(upstream))
    observed = iter([f"2026-10-07T12:{n:02}:00Z" for n in range(50)])
    return Collector(broker, archive, clock=lambda: next(observed))


async def test_overlap_replay_preserves_real_duplicate_occurrences(archive):
    repeated = "2026-10-07T12:00:00Z ERROR identical\n"
    collector = fake_collector(archive, [repeated * 2, repeated * 2 + "2026-10-07T12:01:00Z INFO new\n"])
    await collector.collect_logs_once("core")
    await collector.collect_logs_once("core")
    rows = archive.db.execute("SELECT sanitized_message,occurrence FROM logs ORDER BY seq").fetchall()
    assert len(rows) == 3
    assert rows[0]["occurrence"] == 1 and rows[1]["occurrence"] == 2
    assert any(row["reason"] == "parse_uncertainty" for row in archive.db.execute("SELECT * FROM coverage"))
    await collector.broker.close()


async def test_boot_change_and_rotation_create_gaps(archive):
    collector = fake_collector(archive, ["2026-10-07T12:00:00Z INFO before\n", "2026-10-07T12:01:00Z INFO after\n"], ["a" * 32, "b" * 32])
    await collector.collect_logs_once("core")
    result = await collector.collect_logs_once("core")
    assert result["boot_changed"] is True
    boot_ids = {row[0] for row in archive.db.execute("SELECT DISTINCT boot_id FROM logs")}
    assert len(boot_ids) == 2
    assert any(row[0] == "source_retention" for row in archive.db.execute("SELECT reason FROM coverage"))
    await collector.broker.close()


async def test_reconnect_backfill_marks_loss_without_complete_claim(archive):
    collector = fake_collector(archive, ["2026-10-07T12:00:00Z INFO recovered\n"])
    archive.set_cursor("core", {"boot_id": "a" * 32, "observed_at": "2026-10-07T11:59:00Z", "disconnected": True})
    await collector.collect_logs_once("core")
    rows = archive.db.execute("SELECT status,reason FROM coverage").fetchall()
    assert any(row["reason"] == "connection_lost" for row in rows)
    assert all(row["status"] != "complete" for row in rows)
    await collector.broker.close()


async def test_backfill_keeps_multiline_trace_and_info(archive):
    text = "2026-10-07T12:00:00Z INFO context\n2026-10-07T12:00:01Z ERROR failure\nTraceback (most recent call last):\n  File fixture.py, line 1\nValueError: synthetic\n2026-10-07T12:00:02Z WARNING fallback\n"
    collector = fake_collector(archive, [text])
    await collector.collect_logs_once("core")
    rows = archive.db.execute("SELECT level,sanitized_message FROM logs ORDER BY seq").fetchall()
    assert [row["level"] for row in rows] == ["INFO", "ERROR", "WARNING"]
    assert "Traceback" in rows[1]["sanitized_message"] and "ValueError: synthetic" in rows[1]["sanitized_message"]
    await collector.broker.close()


def test_atomic_snapshot_is_metadata_then_deltas_preserve_false_zero_null(archive):
    broker = ReadBroker(BrokerPolicy(), archive.redactor)
    collector = Collector(broker, archive, clock=lambda: "2026-10-07T12:00:00Z")
    ref = "ent_fixture"
    collector.ingest_entity_event({"a": {ref: {"s": 0, "lc": 1791374400}}, "c": {}, "r": []}, initial=True)
    assert archive.db.execute("SELECT COUNT(*) FROM transitions").fetchone()[0] == 0
    for n, value in enumerate([False, None, "", "unavailable"], 1):
        collector.ingest_entity_event({"a": {}, "c": {ref: {"+": {"s": value, "lc": 1791374400 + n}}}, "r": []})
    transitions = [json.loads(row[0]) for row in archive.db.execute("SELECT payload FROM transitions ORDER BY seq")]
    assert [row["new_state"] for row in transitions] == [False, None, "", "unavailable"]
    assert transitions[0]["old_state"] == 0 and type(transitions[0]["old_state"]) is int
    assert transitions[1]["old_state"] is False


async def test_metadata_timezone_uses_ha_timezone(archive):
    def upstream(request):
        return httpx.Response(200, json={"result": "ok", "data": {"time_zone": "Asia/Krasnoyarsk", "version": "2026.9.4", "latitude": 55}})
    broker = ReadBroker(BrokerPolicy(mode="live", enabled_sources={"metadata"}), archive.redactor,
        "fixture-token", transport=httpx.MockTransport(upstream))
    collector = Collector(broker, archive, clock=lambda: "2026-10-07T12:00:00Z")
    await collector.collect_metadata_once()
    assert collector.timezone == "Asia/Krasnoyarsk"
    payload = archive.db.execute("SELECT payload FROM metadata").fetchone()[0]
    assert "latitude" not in payload
    await broker.close()


async def test_low_disk_stops_upstream_collection_before_request(archive, monkeypatch):
    sent = []
    broker = ReadBroker(BrokerPolicy(mode="live", enabled_sources={"core"}), archive.redactor,
        "synthetic-token", transport=httpx.MockTransport(lambda request: sent.append(request)))
    collector = Collector(broker, archive)
    monkeypatch.setattr(archive, "check_disk", lambda: False)
    with pytest.raises(BrokerError, match="DISK_LOW"):
        await collector.collect_logs_once("core")
    assert sent == [] and collector.last_error["storage"] == "DISK_LOW"
    await broker.close()


async def test_open_traceback_waits_across_poll_and_restart(archive):
    prefix = "2026-10-07T12:00:00Z INFO before\n"
    pending = "2026-10-07T12:00:01Z ERROR failure\nTraceback (most recent call last):\n  File fixture.py, line 1\n"
    collector = fake_collector(archive, [prefix + pending, prefix + pending + "ValueError: synthetic\n"])
    await collector.collect_logs_once("core")
    assert archive.db.execute("SELECT COUNT(*) FROM logs").fetchone()[0] == 1
    cursor = archive.get_cursor("core")
    assert "Traceback" in cursor["pending_text"]
    restarted = Collector(collector.broker, archive, clock=lambda: "2026-10-07T12:01:00Z")
    await restarted.collect_logs_once("core")
    messages = [r[0] for r in archive.db.execute("SELECT sanitized_message FROM logs ORDER BY seq")]
    assert len(messages) == 2 and "ValueError: synthetic" in messages[-1]
    assert "Traceback" in messages[-1] and archive.get_cursor("core")["pending_text"] == ""
    await collector.broker.close()


async def test_lost_pending_traceback_is_preserved_as_truncated_with_gap(archive):
    pending = "2026-10-07T12:00:01Z ERROR failure\nTraceback (most recent call last):\n  File fixture.py, line 1\n"
    collector = fake_collector(archive, [pending, "2026-10-07T12:01:00Z INFO rotated\n"])
    await collector.collect_logs_once("core")
    await collector.collect_logs_once("core")
    row = archive.db.execute("SELECT sanitized_message,truncated FROM logs WHERE level='ERROR'").fetchone()
    assert "Traceback" in row[0] and row[1] == 1
    assert archive.db.execute("SELECT COUNT(*) FROM coverage WHERE reason='parse_uncertainty'").fetchone()[0]
    await collector.broker.close()


async def test_initial_history_backfill_covers_24h_and_live_events_keep_flowing(archive, monkeypatch):
    broker = ReadBroker(BrokerPolicy(mode="live", enabled_sources={"entities"}, entity_ids={"sensor.fixture"}),
                        archive.redactor, "synthetic-credential")
    collector = Collector(broker, archive, clock=lambda: "2026-10-07T12:00:00Z")
    blocked = asyncio.Event()
    received = asyncio.Event()
    captured = []
    async def backfill(entities, start, end):
        captured.append((entities, start, end))
        await blocked.wait()
    async def events(entities):
        yield {"a": {"ent_fixture": {"s": 0, "lc": 1791374400}}}
        yield {"c": {"ent_fixture": {"+": {"s": False, "lu": 1791374401}}}}
        received.set()
        await blocked.wait()
    monkeypatch.setattr(collector, "backfill_history", backfill)
    monkeypatch.setattr(broker, "watch_entities", events)
    task = asyncio.create_task(collector._entities_loop())
    try:
        await asyncio.wait_for(received.wait(), 1)
        await asyncio.sleep(0)
        assert captured == [(["sensor.fixture"], "2026-10-06T12:00:00Z", "2026-10-07T12:00:00Z")]
        payload = json.loads(archive.db.execute("SELECT payload FROM transitions").fetchone()[0])
        assert payload["old_state"] == 0 and payload["new_state"] is False
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await broker.close()


async def test_recorder_backfill_requests_bounded_hourly_windows(archive):
    sent = []
    def upstream(request):
        sent.append(request)
        return httpx.Response(200, json=[])
    broker = ReadBroker(BrokerPolicy(mode="live", enabled_sources={"entities"}, entity_ids={"sensor.fixture"}),
                        archive.redactor, "synthetic-credential", transport=httpx.MockTransport(upstream))
    collector = Collector(broker, archive, clock=lambda: "2026-10-07T12:00:00Z")
    await collector.backfill_history(["sensor.fixture"], "2026-10-05T12:00:00Z", "2026-10-07T12:00:00Z")
    assert len(sent) == 24 and all(r.method == "GET" for r in sent)
    assert sent[0].url.path.endswith("2026-10-06T12:00:00+00:00")
    assert sent[-1].url.params["end_time"] == "2026-10-07T12:00:00+00:00"
    # Storage compacts identical adjacent coverage; the externally visible
    # interval and its uncertainty must survive, independent of row count.
    coverage=archive.coverage(['entities'],'2026-10-06T12:00:00Z','2026-10-07T12:00:00Z',now='2026-10-07T12:00:00Z')[0]
    assert coverage['status']=='unknown'
    from ha_diagnostics.timeutil import parse_explicit
    assert parse_explicit(coverage['gaps'][0]['from'])==parse_explicit('2026-10-06T12:00:00Z')
    assert parse_explicit(coverage['gaps'][-1]['to'])==parse_explicit('2026-10-07T12:00:00Z')
    await broker.close()


async def test_live_start_resolves_ha_timezone_before_first_naive_log(archive):
    sent=[]
    def upstream(request):
        sent.append(request.url.path)
        if request.url.path=="/core/api/config":
            return httpx.Response(200,json={"time_zone":"Asia/Krasnoyarsk"})
        if request.url.path=="/host/logs/boots":
            return httpx.Response(200,json={"result":"ok","data":{"0":"a"*32}})
        if request.url.path.startswith("/core/logs"):
            return httpx.Response(200,text="2026-10-07 19:00:00 INFO local naive\n")
        return httpx.Response(200,json={"result":"ok","data":{}})
    broker=ReadBroker(BrokerPolicy(mode="live",enabled_sources={"core","metadata"}),archive.redactor,
                      "synthetic-credential",transport=httpx.MockTransport(upstream))
    collector=Collector(broker,archive,clock=lambda:"2026-10-07T12:01:00Z",timezone="UTC")
    task=asyncio.create_task(collector.run())
    try:
        async def observed():
            while archive.db.execute("SELECT COUNT(*) FROM logs").fetchone()[0]==0:
                await asyncio.sleep(.01)
        await asyncio.wait_for(observed(),2)
        row=archive.db.execute("SELECT event_time_utc,time_quality FROM logs").fetchone()
        assert row[0]=="2026-10-07T12:00:00.000000Z" and row[1]=="assumed_timezone"
        assert sent.index("/core/api/config")<next(i for i,p in enumerate(sent) if p.startswith("/core/logs"))
    finally:
        task.cancel()
        await asyncio.gather(task,return_exceptions=True)
        await broker.close()

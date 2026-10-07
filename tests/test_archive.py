import sqlite3
import json
from datetime import timedelta
from ha_diagnostics.timeutil import parse_explicit,format_utc

import pytest

from ha_diagnostics.archive import Archive, parse_log_records, SCHEMA, SCHEMA_VERSION
from ha_diagnostics.timeutil import utc_now
from ha_diagnostics.redaction import Redactor

FROM = "2026-10-07T00:00:00Z"
TO = "2026-10-08T00:00:00Z"
OBSERVED = "2026-10-07T14:40:00Z"


@pytest.fixture
def archive(tmp_path):
    instance = Archive(tmp_path / "archive.sqlite", Redactor(b"fixture-installation-key-32-bytes!"), min_free_bytes=0)
    yield instance
    instance.close()


def test_occurrence_dedup_preserves_true_identical_repeats(archive):
    line = "2026-10-07T14:35:00Z ERROR [fixture.component] repeated timeout"
    result = archive.ingest_logs("core", "boot_1", line + "\n" + line, OBSERVED)
    assert result["inserted"] == 2
    replay = archive.ingest_logs("core", "boot_1", line + "\n" + line + "\n" + line, "2026-10-07T14:40:01Z", overlap=True)
    assert replay["deduplicated"] == 2
    assert replay["inserted"] == 1
    records = archive.query_logs(["core"], FROM, TO)["records"]
    assert sorted(r["occurrence"] for r in records) == [1, 2, 3]
    assert any(gap["reason"] == "parse_uncertainty" for gap in archive.coverage(["core"], FROM, TO, now=TO)[0]["gaps"])


def test_backfill_exceeds_last_100_and_growing_2048_tail(archive):
    lines = [f"2026-10-07T14:35:00Z INFO [fixture.component] record_{n}" for n in range(2500)]
    archive.ingest_logs("addon:fixture", "boot_1:rotation_0", "\n".join(lines), OBSERVED)
    result = archive.ingest_logs("addon:fixture", "boot_1:rotation_0", "\n".join(lines + ["2026-10-07T14:36:00Z ERROR fresh"]), "2026-10-07T14:41:00Z", overlap=True)
    assert result["deduplicated"] == 2500
    assert result["inserted"] == 1
    assert len(archive.query_logs(["addon:fixture"], FROM, TO, query="record_0")["records"]) == 1


def test_multiline_traceback_unknown_lines_and_levels(archive):
    text = "2026-10-07T14:35:00Z ERROR [fixture] issue\nTraceback (most recent call last):\n  File \"fixture.py\", line 1\n    raise RuntimeError()\nRuntimeError: failure\nplain unknown line\n2026-10-07T14:36:00Z WARNING follow-up"
    parsed = parse_log_records(text, OBSERVED)
    assert len(parsed) == 3
    assert "RuntimeError: failure" in parsed[0]["sanitized_message"]
    assert parsed[1]["event_time_utc"] is None
    archive.ingest_logs("core", "boot_1", text, OBSERVED)
    records = archive.query_logs(["core"], FROM, TO)["records"]
    assert {r["level"] for r in records} == {"ERROR", "WARNING", "UNKNOWN"}
    unknown = next(r for r in records if r["level"] == "UNKNOWN")
    assert unknown["selection_time_basis"] == "observation_only"


def test_exclusive_end_and_deterministic_event_time_pagination(archive):
    archive.ingest_logs("core", "boot_1", "2026-10-07T14:36:00Z INFO later\n2026-10-07T14:35:00Z INFO earlier\n2026-10-07T14:37:00Z ERROR boundary", OBSERVED)
    first = archive.query_logs(["core"], "2026-10-07T14:35:00Z", "2026-10-07T14:37:00Z", limit=1)
    second = archive.query_logs(["core"], "2026-10-07T14:35:00Z", "2026-10-07T14:37:00Z", limit=1, after=first["next_after"])
    assert "earlier" in first["records"][0]["sanitized_message"]
    assert "later" in second["records"][0]["sanitized_message"]
    assert second["next_after"] is None


def test_secrets_never_enter_sqlite_and_ro_has_no_credentials(archive):
    archive.ingest_logs("core", "boot_1", "2026-10-07T14:35:00Z ERROR password=fixture_canary", OBSERVED)
    archive.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    assert b"fixture_canary" not in archive.path.read_bytes()
    reader = Archive.open_readonly(archive.path)
    try:
        assert reader.redactor is None
        assert reader.query_logs(["core"], FROM, TO)["records"]
        with pytest.raises(PermissionError):
            reader.clear()
        with pytest.raises(sqlite3.OperationalError):
            reader.db.execute("DELETE FROM logs")
    finally:
        reader.close()


def test_snapshot_does_not_create_transition_and_falsy_states_preserved(archive):
    archive.upsert_metadata({"kind": "entity_snapshot", "entity_ref": "ent_fixture", "observed_at": OBSERVED, "safe_fields": {"state": False}, "origin": "current_snapshot"})
    assert not archive.query_history(["ent_fixture"], FROM, TO)["records"]
    for value in [0, False, None, "", "unknown", "unavailable"]:
        archive.append_transition({"source_id": "entities", "entity_ref": "ent_fixture", "event_time": "2026-10-07T14:35:00Z", "observed_at": OBSERVED, "old_state": False, "new_state": value, "last_changed": "2026-10-07T14:35:00Z", "last_updated": "2026-10-07T14:35:01Z", "origin": "recorder", "old_state_known": True})
    rows = archive.query_history(["ent_fixture"], FROM, TO)["records"]
    assert sorted(json.dumps(r["new_state"]) for r in rows) == sorted(json.dumps(v) for v in [0, False, None, "", "unknown", "unavailable"])
    assert all(r["last_changed"] != r["last_updated"] for r in rows)


def test_boot_rotation_clock_jump_and_future_gaps(archive):
    archive.ingest_logs("core", "boot_1", "2026-10-07T14:35:00Z INFO before", OBSERVED)
    archive.ingest_logs("core", "boot_2", "2026-10-07T14:00:00Z INFO after", "2026-10-07T14:41:00Z", overlap=True)
    coverage = archive.coverage(["core"], FROM, TO, now="2026-10-07T20:00:00Z")[0]
    reasons = {g["reason"] for g in coverage["gaps"]}
    assert {"boot_change", "clock_jump", "future_interval"} <= reasons
    assert coverage["status"] != "complete"


def test_revoked_source_hides_record_context(archive):
    archive.ingest_logs("core", "boot_1", "2026-10-07T14:35:00Z INFO fixture", OBSERVED)
    record = archive.query_logs(["core"], FROM, TO)["records"][0]
    assert archive.get_log_record(record["record_id"], allowed_source_ids=["supervisor"]) is None
    archive.set_source_enabled("core", False)
    assert archive.get_log_record(record["record_id"]) is None
    with pytest.raises(ValueError, match="SOURCE_UNAVAILABLE"):
        archive.query_logs(["core"], FROM, TO)


def test_quota_eviction_keeps_gap_and_invalidates_positions(tmp_path):
    limited = Archive(tmp_path / "small.sqlite", Redactor(b"fixture-installation-key-32-bytes!"), max_bytes=256 * 1024, min_free_bytes=0)
    try:
        text = "\n".join(f"2026-10-07T14:35:00Z ERROR item_{i} " + "x" * 2000 for i in range(160))
        limited.ingest_logs("core", "boot_1", text, OBSERVED)
        assert limited.storage_bytes() <= limited.max_bytes
        assert limited.generation > 0
        assert limited.db.execute("SELECT COUNT(*) FROM coverage WHERE reason='quota_eviction'").fetchone()[0] > 0
    finally:
        limited.close()


def test_summary_counts_repeated_errors_with_unknown_baseline(archive):
    archive.ingest_logs("core", "boot_1", "2026-10-07T14:35:00Z ERROR [fixture] timeout 1\n2026-10-07T14:36:00Z ERROR [fixture] timeout 2", OBSERVED)
    output = archive.summarize_errors(["core"], "2026-10-07T14:00:00Z", "2026-10-07T15:00:00Z")
    assert output["groups"][0]["count"] == 2
    assert output["groups"][0]["baseline_comparison"] == "not_found_in_available_baseline"
    assert output["baseline"]["from"] == "2026-10-07T13:00:00.000000Z"


def test_collector_cursor_fields_and_metadata_survive(archive):
    cursor = {"boot_id": "boot_fixture", "rotation_epoch": 2, "observed_at": OBSERVED, "tail": ["a" * 64] * 128, "disconnected": True, "upstream_cursor": None, "truncated": False, "deduplication_basis": "bounded_polling"}
    archive.set_cursor("addon:fixture", cursor)
    assert archive.get_cursor("addon:fixture") == cursor
    archive.upsert_metadata({"device_ref": "dev_fixture", "observed_at": OBSERVED, "safe_fields": {"model": "fixture"}, "related_source_ids": ["core"], "entity_refs": ["ent_fixture"], "name": archive.redactor.alias("DEVICE", "fixture")})
    metadata = archive.get_metadata("dev_fixture")[0]
    assert metadata["safe_fields"]["model"] == "fixture"
    assert metadata["related_source_ids"] == ["core"]


def test_recorder_backfill_dedup_preserves_state_types_and_live_repeats(archive):
    original = {"source_id": "entities", "entity_ref": "ent_fixture", "event_time": "2026-10-07T14:35:00Z", "observed_at": OBSERVED, "new_state": False, "old_state": None, "origin": "recorder", "boundary_state": False}
    first = archive.append_transition(original)
    repeated = archive.append_transition(original | {"observed_at": "2026-10-07T14:41:00Z"})
    assert repeated == first
    zero = archive.append_transition(original | {"new_state": 0})
    boundary = archive.append_transition(original | {"boundary_state": True})
    assert len({first, zero, boundary}) == 3
    live_one = archive.append_transition(original | {"origin": "state_changed"})
    live_two = archive.append_transition(original | {"origin": "state_changed"})
    assert live_one != live_two
    assert len(archive.query_history(["ent_fixture"], FROM, TO)["records"]) == 5


def test_incident_combined_cursor_preserves_order_and_no_unrelated_evidence(archive):
    archive.ingest_logs("core", "boot_1", "2026-10-07T14:36:00Z ERROR second\n2026-10-07T14:38:00Z INFO fourth", OBSERVED)
    archive.ingest_logs("supervisor", "boot_1", "2026-10-07T14:36:00Z ERROR unrelated", OBSERVED)
    for entity, when, state in [("ent_fixture", "2026-10-07T14:35:00Z", "on"), ("ent_fixture", "2026-10-07T14:37:00Z", "unavailable"), ("ent_other", "2026-10-07T14:36:00Z", "unavailable")]:
        archive.append_transition({"source_id": "entities", "entity_ref": entity, "event_time": when, "observed_at": OBSERVED, "new_state": state, "origin": "state_changed"})
    archive.upsert_metadata({"entity_ref": "ent_fixture", "kind": "entity_snapshot", "safe_fields": {"state": "off"}, "observed_at": OBSERVED})
    pages, after = [], None
    for _ in range(5):
        page = archive.query_incident(["ent_fixture"], ["core"], FROM, TO, limit=1, after=after)
        assert page["coverage"]
        pages.extend(page["timeline"])
        after = page["next_after"]
        if after is None:
            break
    assert len(pages) == 4
    assert [row["evidence_kind"] for row in pages] == ["state", "log", "state", "log"]
    assert len({row["record_id"] for row in pages}) == 4
    assert all(row.get("entity_ref") != "ent_other" and row["source_id"] != "supervisor" for row in pages)
    assert sorted((row["event_time_utc"], row["record_id"]) for row in pages) == [(row["event_time_utc"], row["record_id"]) for row in pages]
    with pytest.raises(ValueError, match="INVALID_POSITION"):
        archive.query_incident(["ent_fixture"], ["core"], FROM, TO, after={"sql": "DROP TABLE logs"})


def test_metadata_queries_do_not_lose_device_mapping_to_snapshot_volume(archive):
    archive.upsert_metadata({"kind": "installation", "observed_at": OBSERVED, "safe_fields": {"core": {"version": "fixture_version"}}, "timezone": "Asia/Tomsk"})
    archive.upsert_metadata({"device_ref": "dev_fixture", "entity_refs": ["ent_fixture_0", "ent_fixture_1"], "observed_at": OBSERVED, "related_source_ids": ["core"]})
    for index in range(1100):
        archive.upsert_metadata({"kind": "entity_snapshot", "entity_ref": f"ent_fixture_{index}", "observed_at": "2026-10-07T14:41:00Z", "safe_fields": {"state": index}, "origin": "current_snapshot"})
    assert archive.get_device_metadata()[0]["device_ref"] == "dev_fixture"
    assert archive.get_installation_metadata()["safe_fields"]["core"]["version"] == "fixture_version"
    snapshots = archive.get_entity_snapshots(["ent_fixture_0", "ent_fixture_1099"])
    assert {row["entity_ref"] for row in snapshots} == {"ent_fixture_0", "ent_fixture_1099"}
    assert {row["safe_fields"]["state"] for row in snapshots} == {0, 1099}
    assert archive.query_incident([f"ent_fixture_{i}" for i in range(1000)], [], FROM, TO)["timeline"] == []
    with pytest.raises(ValueError, match="QUERY_TOO_LARGE"):
        archive.get_entity_snapshots(["ent_fixture_0"] * 1001)


def test_incident_missing_log_source_keeps_available_history_and_marks_gap(archive):
    archive.append_transition({"source_id": "entities", "entity_ref": "ent_fixture", "event_time": "2026-10-07T14:35:00Z", "observed_at": OBSERVED, "new_state": "unavailable", "origin": "state_changed"})
    result = archive.query_incident(["ent_fixture"], ["core"], FROM, TO)
    assert len(result["timeline"]) == 1
    assert result["timeline"][0]["evidence_kind"] == "state"
    assert any(item.get("source_id") == "core" and item["status"] == "unavailable" for item in result["coverage"])


def test_fts_only_indexes_cleaned_text_and_logger_and_literal_api(archive):
    archive.append_log({"source_id":"core","boot_id":"boot_fixture","event_time_utc":"2026-10-07T14:35:00Z","observed_at":OBSERVED,"level":"ERROR","logger":"fixture.logger password=canary_logger","sanitized_message":"synthetic needle password=canary_message"})
    assert archive.db.execute("SELECT COUNT(*) FROM logs_fts WHERE logs_fts MATCH ?", ('"needle"',)).fetchone()[0] == 1
    for secret in ("canary_logger", "canary_message"):
        assert archive.db.execute("SELECT COUNT(*) FROM logs_fts WHERE logs_fts MATCH ?", ('"'+secret+'"',)).fetchone()[0] == 0
    archive.db.execute("CREATE VIRTUAL TABLE test_fts_vocab USING fts5vocab(logs_fts,'row')")
    terms=[row[0] for row in archive.db.execute("SELECT term FROM test_fts_vocab")]
    assert not any("canary" in term for term in terms)
    assert not archive.query_logs(["core"],FROM,TO,query="needle OR password")["records"]
    archive.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    data=archive.path.read_bytes()
    assert b"canary_message" not in data and b"canary_logger" not in data


def test_fts_update_retention_and_clear_consistency(archive):
    archive.ingest_logs("core","boot_fixture","2026-10-07T14:35:00Z INFO fixture_fts_first",OBSERVED)
    archive.db.execute("UPDATE logs SET sanitized_message='fixture_fts_updated'")
    archive.db.commit()
    assert archive.db.execute("SELECT COUNT(*) FROM logs_fts WHERE logs_fts MATCH ?", ('"fixture_fts_first"',)).fetchone()[0] == 0
    assert archive.db.execute("SELECT COUNT(*) FROM logs_fts WHERE logs_fts MATCH ?", ('"fixture_fts_updated"',)).fetchone()[0] == 1
    result=archive.enforce_retention(now="2026-10-20T00:00:00Z")
    assert result["removed"] >= 1
    assert archive.db.execute("SELECT COUNT(*) FROM logs_fts WHERE logs_fts MATCH ?", ('"fixture_fts_updated"',)).fetchone()[0] == 0
    archive.db.execute("INSERT INTO logs_fts(logs_fts,rank) VALUES('integrity-check',1)")
    archive.ingest_logs("core","boot_fixture","2026-10-20T14:35:00Z INFO clear_fixture","2026-10-20T14:40:00Z")
    archive.clear()
    assert archive.db.execute("SELECT COUNT(*) FROM logs_fts WHERE logs_fts MATCH ?", ('"clear_fixture"',)).fetchone()[0] == 0
    archive.db.execute("INSERT INTO logs_fts(logs_fts,rank) VALUES('integrity-check',1)")


def test_existing_version_one_archive_migrates_and_rebuilds_fts(tmp_path):
    path=tmp_path / "legacy.sqlite"
    legacy=sqlite3.connect(path)
    legacy.executescript(SCHEMA)
    legacy.execute("INSERT INTO sources VALUES('core','log','',1,NULL,NULL,'available','1')")
    legacy.execute("INSERT INTO logs(record_id,source_id,boot_id,event_time_utc,observed_at,time_quality,level,sanitized_message,fingerprint,content_hash,occurrence,redaction_version,truncated) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",("rec_legacy","core","boot_legacy","2026-10-07T14:35:00.000000Z",utc_now(),"source_timestamp","INFO","sanitized legacy migrationneedle","a"*64,"b"*64,1,"1",0))
    legacy.execute("PRAGMA user_version=1")
    legacy.commit();legacy.close()
    writer=Archive(path,Redactor(b"fixture-installation-key-32-bytes!"),min_free_bytes=0)
    try:
        assert writer.db.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 2
        assert writer.db.execute("SELECT COUNT(*) FROM logs_fts WHERE logs_fts MATCH 'migrationneedle'").fetchone()[0] == 1
        writer.db.execute("INSERT INTO logs_fts(logs_fts,rank) VALUES('integrity-check',1)")
        writer.db.commit()
        reader=Archive.open_readonly(path)
        try:
            assert reader.get_log_record("rec_legacy")["record"]["sanitized_message"] == "sanitized legacy migrationneedle"
        finally:reader.close()
    finally:writer.close()


def test_fts_migration_keeps_older_sqlite_feature_compatibility(tmp_path,monkeypatch):
    # Exercise the Debian-bookworm feature gate on this newer host engine.
    # This does not claim the base image itself was executed.
    monkeypatch.setattr(sqlite3,"sqlite_version_info",(3,40,1))
    monkeypatch.setattr(sqlite3,"sqlite_version","3.40.1")
    archive=Archive(tmp_path/"old-feature.sqlite",Redactor(b"fixture-installation-key-32-bytes!"),min_free_bytes=0)
    try:
        archive.ingest_logs("core","boot_fixture","2026-10-07T14:35:00Z INFO compatiblefts",OBSERVED)
        assert archive.db.execute("SELECT COUNT(*) FROM logs_fts WHERE logs_fts MATCH 'compatiblefts'").fetchone()[0] == 1
        capabilities=archive.fts_capabilities()
        assert not capabilities["secure_delete_supported"]
        assert not capabilities["secure_delete_enabled"]
        assert capabilities["physical_erasure_guaranteed"] is False
        archive.clear()
        assert archive.db.execute("SELECT COUNT(*) FROM logs_fts WHERE logs_fts MATCH 'compatiblefts'").fetchone()[0] == 0
    finally:archive.close()


def test_coverage_sweep_handles_ten_thousand_intervals_and_worst_overlay(archive):
    start=parse_explicit(FROM)
    rows=[]
    for index in range(10000):
        rows.append(("core",format_utc(start+timedelta(seconds=index*5)),format_utc(start+timedelta(seconds=(index+1)*5)),"partial","parse_uncertainty","bounded_polling",0))
    # Simulate existing pre-compaction coverage; no timing threshold tied to host.
    archive.db.executemany("INSERT INTO coverage(source_id,from_time,to_time,status,reason,ingestion_basis,dropped_count) VALUES(?,?,?,?,?,?,?)",rows)
    archive.db.commit()
    end=format_utc(start+timedelta(seconds=50000))
    output=archive.coverage(["core"],FROM,end,now=TO)[0]
    assert output["status"] == "partial"
    assert len(output["gaps"]) == 1
    assert output["gaps"][0]["from"] == format_utc(start)
    assert output["gaps"][0]["to"] == end
    archive.add_coverage("core",format_utc(start+timedelta(seconds=100)),format_utc(start+timedelta(seconds=110)),"unavailable","permission_denied","upstream_denied")
    stronger=archive.coverage(["core"],FROM,end,now=TO)[0]
    assert stronger["status"] == "unavailable"
    assert [gap["status"] for gap in stronger["gaps"]] == ["partial","unavailable","partial"]


def test_zero_loss_compaction_keeps_nonzero_counts_and_severity(archive):
    archive.add_coverage("core","2026-10-07T00:00:00Z","2026-10-07T00:00:05Z","partial","parse_uncertainty","poll")
    archive.add_coverage("core","2026-10-07T00:00:05Z","2026-10-07T00:00:10Z","partial","parse_uncertainty","poll")
    assert archive.db.execute("SELECT COUNT(*) FROM coverage").fetchone()[0] == 1
    for left,right in [(10,15),(15,20)]:
        archive.add_coverage("core",f"2026-10-07T00:00:{left:02d}Z",f"2026-10-07T00:00:{right:02d}Z","partial","backpressure","bounded_queue",dropped_count=3)
    assert archive.db.execute("SELECT SUM(dropped_count) FROM coverage").fetchone()[0] == 6
    result=archive.coverage(["core"],"2026-10-07T00:00:00Z","2026-10-07T00:00:20Z",now=TO)[0]
    loss=[gap for gap in result["gaps"] if gap["reason"] == "backpressure"]
    assert len(loss) == 1 and sum(gap["dropped_count"] for gap in loss) == 6


def test_coverage_overlay_retains_whole_loss_marker_counts_once(archive):
    archive.add_coverage("core","2026-10-07T00:00:00Z","2026-10-07T00:01:00Z","partial","startup_limit","bounded_backfill")
    archive.add_coverage("core","2026-10-07T00:00:10Z","2026-10-07T00:00:40Z","partial","quota_eviction","archive_eviction",dropped_count=5)
    archive.add_coverage("core","2026-10-07T00:00:20Z","2026-10-07T00:00:30Z","unavailable","permission_denied","upstream_denied")
    archive.add_coverage("core","2026-10-07T00:00:25Z","2026-10-07T00:00:50Z","partial","backpressure","bounded_queue",dropped_count=7)
    output=archive.coverage(["core"],"2026-10-07T00:00:00Z","2026-10-07T00:01:00Z",now=TO)[0]
    assert output["status"] == "unavailable"
    assert sum(gap["dropped_count"] for gap in output["gaps"]) == 12
    assert [gap["reason"] for gap in output["gaps"]] == ["startup_limit","permission_denied","startup_limit"]
    clipped=archive.coverage(["core"],"2026-10-07T00:00:26Z","2026-10-07T00:00:29Z",now=TO)[0]
    # Counts represent whole intersecting markers; their sub-second positions
    # are unknown, and intersecting them must neither hide nor duplicate them.
    assert sum(gap["dropped_count"] for gap in clipped["gaps"]) == 12

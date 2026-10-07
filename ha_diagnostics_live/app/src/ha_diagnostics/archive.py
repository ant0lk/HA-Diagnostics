"""Cleaned SQLite archive. Query workers open mode=ro and never need a secret key.

All SQL is fixed and parameterized. ``after`` is an internal row position, not a
client cursor: the MCP layer signs it with subject, policy, filters and generation.
Coverage is conservative; absent records never imply a complete interval.
"""
from __future__ import annotations

import hashlib
import heapq
import json
import os
import re
import shutil
import sqlite3
import time
import uuid
from collections import Counter
from datetime import timedelta
from pathlib import Path

from .redaction import Redactor
from .timeutil import format_utc, parse_explicit, source_time, utc_now, validate_interval

SCHEMA_VERSION = 2
ID = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$")
SOURCE_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL", "UNKNOWN"})
REASONS = frozenset({"startup_limit", "source_retention", "connection_lost", "collector_stopped", "quota_eviction", "backpressure", "permission_denied", "parse_uncertainty", "future_interval", "clock_jump", "rotation", "boot_change", "disk_low", "history_unknown", "snapshot_only"})
SCHEMA = """
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
INSERT OR IGNORE INTO settings VALUES('generation','0');
CREATE TABLE IF NOT EXISTS sources(source_id TEXT PRIMARY KEY,kind TEXT NOT NULL,local_ref TEXT NOT NULL,enabled INTEGER NOT NULL,collected_since TEXT,latest_observed_at TEXT,status TEXT NOT NULL,parser_version TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS logs(seq INTEGER PRIMARY KEY,record_id TEXT UNIQUE NOT NULL,source_id TEXT NOT NULL,boot_id TEXT NOT NULL,cursor TEXT,event_time_utc TEXT,observed_at TEXT NOT NULL,time_quality TEXT NOT NULL,source_timestamp TEXT,source_offset TEXT,precision TEXT,timestamp_origin TEXT,level TEXT NOT NULL,logger TEXT,sanitized_message TEXT NOT NULL,fingerprint TEXT NOT NULL,content_hash TEXT NOT NULL,occurrence INTEGER NOT NULL,redaction_version TEXT NOT NULL,truncated INTEGER NOT NULL,UNIQUE(source_id,boot_id,event_time_utc,content_hash,occurrence));
CREATE INDEX IF NOT EXISTS logs_time ON logs(source_id,event_time_utc,seq);
CREATE INDEX IF NOT EXISTS logs_observed ON logs(source_id,observed_at,seq);
CREATE INDEX IF NOT EXISTS logs_retention ON logs(observed_at);
CREATE INDEX IF NOT EXISTS logs_fingerprint ON logs(source_id,fingerprint,event_time_utc);
CREATE TABLE IF NOT EXISTS coverage(seq INTEGER PRIMARY KEY,source_id TEXT NOT NULL,from_time TEXT NOT NULL,to_time TEXT NOT NULL,status TEXT NOT NULL,reason TEXT,ingestion_basis TEXT NOT NULL,dropped_count INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS coverage_time ON coverage(source_id,from_time,to_time);
CREATE TABLE IF NOT EXISTS cursors(source_id TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tails(source_id TEXT NOT NULL,boot_id TEXT NOT NULL,value TEXT NOT NULL,PRIMARY KEY(source_id,boot_id));
CREATE TABLE IF NOT EXISTS transitions(seq INTEGER PRIMARY KEY,record_id TEXT UNIQUE NOT NULL,entity_ref TEXT NOT NULL,source_id TEXT NOT NULL,event_time_utc TEXT,observed_at TEXT NOT NULL,payload TEXT NOT NULL,is_snapshot INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS transitions_time ON transitions(entity_ref,event_time_utc,seq);
CREATE INDEX IF NOT EXISTS transitions_retention ON transitions(observed_at);
CREATE TABLE IF NOT EXISTS metadata(seq INTEGER PRIMARY KEY,snapshot_id TEXT UNIQUE NOT NULL,device_ref TEXT,observed_at TEXT NOT NULL,payload TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS metadata_device ON metadata(device_ref,observed_at);
CREATE INDEX IF NOT EXISTS metadata_retention ON metadata(observed_at);
CREATE TABLE IF NOT EXISTS artifacts(seq INTEGER PRIMARY KEY,artifact_id TEXT UNIQUE NOT NULL,kind TEXT NOT NULL,imported_at TEXT NOT NULL,sanitized_content TEXT NOT NULL,sanitized_content_hash TEXT NOT NULL,approved INTEGER NOT NULL,source_time_range TEXT,coverage_notes TEXT NOT NULL,approved_fields TEXT NOT NULL);
"""
FTS_MIGRATION = """
BEGIN IMMEDIATE;
CREATE VIRTUAL TABLE IF NOT EXISTS logs_fts USING fts5(
  sanitized_message,logger,content='logs',content_rowid='seq',
  tokenize='unicode61'
);
CREATE TRIGGER IF NOT EXISTS logs_fts_insert AFTER INSERT ON logs BEGIN
  INSERT INTO logs_fts(rowid,sanitized_message,logger)
  VALUES(new.seq,new.sanitized_message,new.logger);
END;
CREATE TRIGGER IF NOT EXISTS logs_fts_delete AFTER DELETE ON logs BEGIN
  INSERT INTO logs_fts(logs_fts,rowid,sanitized_message,logger)
  VALUES('delete',old.seq,old.sanitized_message,old.logger);
END;
CREATE TRIGGER IF NOT EXISTS logs_fts_update AFTER UPDATE ON logs BEGIN
  INSERT INTO logs_fts(logs_fts,rowid,sanitized_message,logger)
  VALUES('delete',old.seq,old.sanitized_message,old.logger);
  INSERT INTO logs_fts(rowid,sanitized_message,logger)
  VALUES(new.seq,new.sanitized_message,new.logger);
END;
-- FTS_SECURE_DELETE_SETTING
INSERT INTO logs_fts(logs_fts) VALUES('rebuild');
PRAGMA user_version=2;
COMMIT;
"""


def _id(value: str) -> str:
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise ValueError("INVALID_ID")
    return value


def _source_id(value: str) -> str:
    if not isinstance(value, str) or not SOURCE_ID.fullmatch(value):
        raise ValueError("INVALID_SOURCE_ID")
    return value


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _overlap(previous: list[str], incoming: list[str]) -> int:
    """Longest prior suffix matching the incoming prefix, linear in tail size."""
    if not previous or not incoming:
        return 0
    # Polling may replay a growing 50k window, not only a prefix matching the tail.
    # Find the old retained tail anywhere in that window without quadratic scans.
    pattern = previous[-2048:]
    failure = [0] * len(pattern)
    for i in range(1, len(pattern)):
        j = failure[i - 1]
        while j and pattern[i] != pattern[j]:
            j = failure[j - 1]
        if pattern[i] == pattern[j]:
            j += 1
        failure[i] = j
    matched = 0
    for position, value in enumerate(incoming):
        while matched and pattern[matched] != value:
            matched = failure[matched - 1]
        if pattern[matched] == value:
            matched += 1
        if matched == len(pattern):
            return position + 1
    pattern = incoming[:2048]
    combined = pattern + ["\0"] + previous[-2048:]
    prefix = [0] * len(combined)
    for i in range(1, len(combined)):
        j = prefix[i - 1]
        while j and combined[i] != combined[j]:
            j = prefix[j - 1]
        if combined[i] == combined[j]:
            j += 1
        prefix[i] = j
    return min(prefix[-1], len(pattern))


def parse_log_records(text: str, observed_at: str, timezone: str = "UTC") -> list[dict]:
    """Preserve all levels and timestamp-less text; collect indented tracebacks."""
    if not isinstance(text, str) or len(text.encode("utf-8")) > 20 * 1024 * 1024:
        raise ValueError("BACKFILL_TOO_LARGE")
    observed_at = format_utc(parse_explicit(observed_at))
    lines = text.splitlines()
    if len(lines) > 50000:
        raise ValueError("BACKFILL_TOO_LARGE")
    records: list[dict] = []
    traceback = False
    for line in lines:
        timing = source_time(line, timezone)
        starts = timing["timestamp_origin"] == "source"
        continuation = bool(records and not starts and (traceback or line.startswith((" ", "\t", "Traceback (", "During handling of", "The above exception"))))
        if continuation:
            records[-1]["_lines"].append(line)
        else:
            level = re.search(r"\b(DEBUG|INFO|WARNING|ERROR|CRITICAL|WARN)\b", line)
            logger = re.search(r"\[([^]\r\n]{1,200})\]", line)
            records.append({**timing, "observed_at": observed_at, "level": ("WARNING" if level and level.group(1) == "WARN" else level.group(1)) if level else "UNKNOWN", "logger": logger.group(1) if logger else None, "_lines": [line]})
        if starts:
            traceback = "Traceback (" in line
        elif "Traceback (" in line:
            traceback = True
        elif traceback and line and not line.startswith((" ", "\t", "During handling of", "The above exception")):
            # Exception terminator is included; the next plain line becomes a record.
            traceback = False
    for record in records:
        record["sanitized_message"] = "\n".join(record.pop("_lines"))
    return records


class Archive:
    def __init__(self, path: str | Path, redactor: Redactor, *, max_bytes: int = 512 * 1024 * 1024,
                 retention_days: int = 7, min_free_bytes: int = 256 * 1024 * 1024):
        if max_bytes < 128 * 1024 or not 1 <= retention_days <= 365 or min_free_bytes < 0:
            raise ValueError("INVALID_STORAGE_LIMIT")
        self.path = Path(path)
        if self.path.is_symlink():
            raise ValueError("UNSAFE_STORAGE_PATH")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.redactor, self.readonly = redactor, False
        self.max_bytes, self.retention_days, self.min_free_bytes = max_bytes, retention_days, min_free_bytes
        self._last_retention = 0.0
        self.db = sqlite3.connect(str(self.path), timeout=5)
        self.db.row_factory = sqlite3.Row
        previous_version = self.db.execute("PRAGMA user_version").fetchone()[0]
        if previous_version not in {0, 1, SCHEMA_VERSION}:
            self.db.close()
            raise ValueError("UNSUPPORTED_ARCHIVE_SCHEMA")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA secure_delete=ON")
        self.db.execute("PRAGMA auto_vacuum=FULL")
        self.db.execute("PRAGMA wal_autocheckpoint=128")
        self.db.executescript(SCHEMA)
        self.db.commit()
        if previous_version < SCHEMA_VERSION:
            try:
                secure_setting = "INSERT INTO logs_fts(logs_fts,rank) VALUES('secure-delete',1);" if sqlite3.sqlite_version_info >= (3,42,0) else ""
                self.db.executescript(FTS_MIGRATION.replace("-- FTS_SECURE_DELETE_SETTING",secure_setting))
            except sqlite3.Error:
                self.db.rollback()
                self.db.close()
                raise ValueError("ARCHIVE_MIGRATION_FAILED") from None

    def fts_capabilities(self) -> dict:
        """Feature detection is local; physical storage erasure is never promised."""
        row=self.db.execute("SELECT v FROM logs_fts_config WHERE k='secure-delete'").fetchone()
        return {"index":"fts5","schema_version":SCHEMA_VERSION,"sqlite_version":sqlite3.sqlite_version,
                "secure_delete_supported":sqlite3.sqlite_version_info >= (3,42,0),
                "secure_delete_enabled":bool(row and row[0]),"physical_erasure_guaranteed":False}

    @classmethod
    def open_readonly(cls, path: str | Path) -> "Archive":
        obj = cls.__new__(cls)
        obj.path, obj.redactor, obj.readonly = Path(path), None, True
        obj.db = sqlite3.connect(obj.path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)
        obj.db.row_factory = sqlite3.Row
        obj.db.execute("PRAGMA query_only=ON")
        if obj.db.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
            obj.db.close()
            raise ValueError("UNSUPPORTED_ARCHIVE_SCHEMA")
        return obj

    def close(self) -> None:
        self.db.close()

    @property
    def generation(self) -> int:
        return int(self.db.execute("SELECT value FROM settings WHERE key='generation'").fetchone()[0])

    def _write(self) -> None:
        if self.readonly:
            raise PermissionError("READ_ONLY_ARCHIVE")

    def _safe(self, value: object) -> object:
        self._write()
        return self.redactor.clean_json(value)

    def register_source(self, source_id: str, kind: str = "log", local_ref: str = "", enabled: bool = True) -> None:
        self._write()
        _source_id(source_id)
        if not isinstance(enabled, bool):
            raise ValueError("INVALID_SOURCE")
        self.db.execute("INSERT INTO sources VALUES(?,?,?,?,NULL,NULL,'unknown','1') ON CONFLICT(source_id) DO UPDATE SET kind=excluded.kind,local_ref=excluded.local_ref,enabled=excluded.enabled", (source_id, self.redactor.clean_text(kind, 40), self.redactor.clean_text(local_ref, 200), int(enabled)))
        self.db.commit()

    def set_source_enabled(self, source_id: str, enabled: bool) -> None:
        self._write()
        if not isinstance(enabled, bool):
            raise ValueError("INVALID_SOURCE")
        self.db.execute("UPDATE sources SET enabled=? WHERE source_id=?", (int(enabled), _source_id(source_id)))
        self.db.execute("UPDATE settings SET value=CAST(value AS INTEGER)+1 WHERE key='generation'")
        self.db.commit()

    def source_status(self) -> list[dict]:
        return [dict(row) | {"enabled": bool(row["enabled"])} for row in self.db.execute("SELECT * FROM sources ORDER BY source_id")]

    def local_log_preview(self) -> list[dict]:
        """Fixed owner-local sample. No arbitrary SQL, source path or remote tool."""
        rows=self.db.execute("SELECT record_id,source_id,observed_at,sanitized_message,truncated FROM logs ORDER BY seq DESC LIMIT 10").fetchall()
        return [dict(row) | {"sanitized_message":row['sanitized_message'][:2000],"truncated":bool(row['truncated']) or len(row['sanitized_message'])>2000} for row in rows]

    def _source(self, source_id: str, create: bool = False) -> None:
        _source_id(source_id)
        row = self.db.execute("SELECT enabled FROM sources WHERE source_id=?", (source_id,)).fetchone()
        if row is None and create:
            self.register_source(source_id)
        elif row is None or not row["enabled"]:
            raise ValueError("SOURCE_UNAVAILABLE")

    def set_cursor(self, source_id: str, cursor: dict) -> None:
        self._write()
        _source_id(source_id)
        # Store only explicit collector keys. Never raw URLs/headers/body.
        allowed = {"cursor", "boot_id", "observed_at", "event_time_utc", "status", "count", "source_id", "from", "to", "rotation_epoch", "tail", "disconnected", "upstream_cursor", "truncated", "deduplication_basis", "pending_text", "pending_observed_at", "pending_boot_id"}
        clean = self.redactor.clean_json(cursor, approved_fields=allowed)
        if "pending_text" in clean and (not isinstance(clean["pending_text"], str) or len(clean["pending_text"]) > 4096):
            raise ValueError("CURSOR_TOO_LARGE")
        encoded = _json(clean)
        if len(encoded) > 16384:
            raise ValueError("CURSOR_TOO_LARGE")
        self.db.execute("INSERT OR REPLACE INTO cursors VALUES(?,?)", (source_id, encoded))
        self.db.commit()

    def get_cursor(self, source_id: str) -> dict | None:
        row = self.db.execute("SELECT value FROM cursors WHERE source_id=?", (_source_id(source_id),)).fetchone()
        return json.loads(row[0]) if row else None

    def add_coverage(self, source_id: str, from_: str, to: str, status: str, reason: str | None = None,
                     ingestion_basis: str = "observed", dropped_count: int = 0) -> None:
        self._write()
        _source_id(source_id)
        start, end = format_utc(parse_explicit(from_)), format_utc(parse_explicit(to))
        if end <= start or status not in {"complete", "partial", "unknown", "unavailable"} or reason is not None and reason not in REASONS:
            raise ValueError("INVALID_COVERAGE")
        if isinstance(dropped_count, bool) or not isinstance(dropped_count, int) or dropped_count < 0:
            raise ValueError("INVALID_COVERAGE")
        basis=self.redactor.clean_text(ingestion_basis,100)
        if dropped_count == 0:
            # Joining equal zero-loss intervals preserves severity and meaning.
            # Never absorb a nonzero loss marker: its count belongs to that row.
            matches=self.db.execute("SELECT seq,from_time,to_time FROM coverage WHERE source_id=? AND status=? AND reason IS ? AND ingestion_basis=? AND dropped_count=0 AND from_time<=? AND to_time>=? ORDER BY from_time,seq",(source_id,status,reason,basis,end,start)).fetchall()
            if matches:
                start=min(start,min(row["from_time"] for row in matches))
                end=max(end,max(row["to_time"] for row in matches))
                keep=matches[0]["seq"]
                self.db.execute("UPDATE coverage SET from_time=?,to_time=? WHERE seq=?",(start,end,keep))
                for row in matches[1:]:self.db.execute("DELETE FROM coverage WHERE seq=?",(row["seq"],))
                self.db.commit()
                return
        self.db.execute("INSERT INTO coverage(source_id,from_time,to_time,status,reason,ingestion_basis,dropped_count) VALUES(?,?,?,?,?,?,?)", (source_id, start, end, status, reason, basis, dropped_count))
        self.db.commit()

    def coverage(self, source_ids: list[str], from_: str, to: str, *, now: str | None = None) -> list[dict]:
        start, end = validate_interval(from_, to)
        current = format_utc(parse_explicit(now)) if now else utc_now()
        outputs = []
        rank = {"complete": 0, "unknown": 1, "partial": 2, "unavailable": 3}
        for source in source_ids:
            _source_id(source)
            rows = [dict(r) for r in self.db.execute("SELECT * FROM coverage WHERE source_id=? AND to_time>? AND from_time<? ORDER BY from_time,seq", (source, start, end))]
            # Sweep interval boundaries; max severity is maintained in a heap.
            # The tie-break matches the former first row at equal severity.
            events: dict[str,list[tuple[int,int]]] = {start:[],end:[]}
            for index,row in enumerate(rows):
                left,right=max(start,row["from_time"]),min(end,row["to_time"])
                events.setdefault(left,[]).append((1,index))
                events.setdefault(right,[]).append((-1,index))
            if start < current < end:
                events.setdefault(current,[])
            gaps, worst = [], "complete"
            ordered = sorted(events)
            active=set();heap=[];pending_losses={};pending_total=0
            for left, right in zip(ordered, ordered[1:]):
                for operation,index in events[left]:
                    if operation == -1:
                        active.discard(index)
                        pending_total-=pending_losses.pop(index,0)
                for operation,index in events[left]:
                    if operation == 1:
                        active.add(index);heapq.heappush(heap,(-rank[rows[index]["status"]],index))
                        if rows[index]["dropped_count"]:
                            pending_losses[index]=rows[index]["dropped_count"]
                            pending_total+=rows[index]["dropped_count"]
                while heap and heap[0][1] not in active:heapq.heappop(heap)
                marker=heap[0][1] if heap else None
                chosen=rows[marker] if marker is not None else None
                status = chosen["status"] if chosen else "unknown"
                reason = chosen["reason"] if chosen else "unobserved"
                if left >= current:
                    status, reason = "partial", "future_interval"
                if pending_total and status == "complete":
                    # An old/inconsistent complete marker with losses cannot
                    # claim completeness. New collectors mark such gaps partial.
                    status,reason="partial","backpressure"
                if rank[status] > rank[worst]:
                    worst = status
                if status != "complete":
                    # Assign each intersecting marker's whole known loss count
                    # once, even when a worse/earlier marker masks its reason.
                    # This is not a timestamp-level count for a clipped gap.
                    gap={"from": left, "to": right, "status": status, "reason": reason, "ingestion_basis": chosen["ingestion_basis"] if chosen else "none", "dropped_count": pending_total}
                    pending_losses.clear();pending_total=0
                    identity={k:v for k,v in gap.items() if k not in {"from","to","dropped_count"}}
                    same=bool(gaps and gaps[-1]["to"] == left and {k:v for k,v in gaps[-1].items() if k not in {"from","to","dropped_count"}} == identity)
                    if same:
                        gaps[-1]["to"]=right
                        gaps[-1]["dropped_count"]+=gap["dropped_count"]
                    else:gaps.append(gap)
            outputs.append({"source_id": source, "from": start, "to": end, "status": worst, "gaps": gaps})
        return outputs

    def append_log(self, record: dict, *, enforce_retention: bool = True) -> bool:
        self._write()
        source = _source_id(record["source_id"])
        boot = str(record.get("boot_id") or "boot_unknown")
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", boot):
            raise ValueError("INVALID_BOOT_ID")
        self._source(source, create=True)
        observed = format_utc(parse_explicit(record["observed_at"]))
        event = format_utc(parse_explicit(record["event_time_utc"])) if record.get("event_time_utc") is not None else None
        raw = record.get("sanitized_message", record.get("message", ""))
        message = self.redactor.clean_text(raw)
        level = record.get("level", "UNKNOWN")
        if level not in LEVELS:
            raise ValueError("INVALID_LOG_LEVEL")
        content_hash = hashlib.sha256(message.encode()).hexdigest()
        # Exact sanitized examples survive normalization; error groups remain component-specific.
        logger = self.redactor.clean_text(record["logger"], 200) if record.get("logger") else None
        normalized = re.sub(r"\b\d{4}-\d{2}-\d{2}[T ][\d:.,+Z-]+", "[TIME]", message)
        normalized = re.sub(r"\b\d+(?:\.\d+)?\b", "[NUMBER]", normalized)
        fingerprint = hashlib.sha256((level + "\0" + (logger or "") + "\0" + normalized).encode()).hexdigest()
        occurrence = record.get("occurrence")
        if occurrence is None:
            row = self.db.execute("SELECT MAX(occurrence) FROM logs WHERE source_id=? AND boot_id=? AND event_time_utc IS ? AND content_hash=?", (source, boot, event, content_hash)).fetchone()
            occurrence = (row[0] or 0) + 1
        if isinstance(occurrence, bool) or not isinstance(occurrence, int) or not 1 <= occurrence <= 10**12:
            raise ValueError("INVALID_OCCURRENCE")
        # SQLite UNIQUE treats NULL specially; use an explicit check for unknown event times.
        exists = self.db.execute("SELECT 1 FROM logs WHERE source_id=? AND boot_id=? AND event_time_utc IS ? AND content_hash=? AND occurrence=?", (source, boot, event, content_hash, occurrence)).fetchone()
        if exists:
            return False
        record_id = "rec_" + uuid.uuid4().hex
        cursor = self.redactor.clean_text(str(record["cursor"]), 256) if record.get("cursor") is not None else None
        time_quality = record.get("time_quality", "source_timestamp" if event else "unknown")
        if time_quality not in {"source_timestamp", "assumed_timezone", "unknown", "parse_error", "clock_jump"}:
            raise ValueError("INVALID_TIME_QUALITY")
        offset, precision, origin = record.get("source_offset"), record.get("precision", "unknown"), record.get("timestamp_origin", "source" if event else "absent")
        if offset is not None and not re.fullmatch(r"[+-]\d{4}", offset) or precision not in {"unknown", "second", "fraction"} or origin not in {"source", "absent", "recorder", "event", "snapshot"}:
            raise ValueError("INVALID_TIME_METADATA")
        self.db.execute("INSERT INTO logs(record_id,source_id,boot_id,cursor,event_time_utc,observed_at,time_quality,source_timestamp,source_offset,precision,timestamp_origin,level,logger,sanitized_message,fingerprint,content_hash,occurrence,redaction_version,truncated) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (record_id, source, boot, cursor, event, observed, time_quality, self.redactor.clean_text(str(record["source_timestamp"]), 100) if record.get("source_timestamp") else None, offset, precision, origin, level, logger, message, fingerprint, content_hash, occurrence, self.redactor.version, int(len(raw) > 16000 or bool(record.get("truncated")))))
        self.db.execute("UPDATE sources SET collected_since=COALESCE(collected_since,?),latest_observed_at=?,status='available' WHERE source_id=?", (observed, observed, source))
        if enforce_retention:
            self.db.commit()
            self._maybe_retention(observed)
        return True

    def ingest_logs(self, source_id: str, boot_id: str, text: str, observed_at: str, *, timezone: str = "UTC", overlap: bool = False, cursor: str | None = None, continuity: str = "unknown") -> dict:
        self._write()
        source = _source_id(source_id)
        boot = str(boot_id)
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", boot):
            raise ValueError("INVALID_BOOT_ID")
        records = parse_log_records(text, observed_at, timezone)
        clean = []
        for record in records:
            record["sanitized_message"] = self.redactor.clean_text(record["sanitized_message"])
            identity = hashlib.sha256(((record["event_time_utc"] or "unknown") + "\0" + record["sanitized_message"]).encode()).hexdigest()
            clean.append(identity)
        old = self.db.execute("SELECT boot_id,value FROM tails WHERE source_id=? ORDER BY rowid DESC LIMIT 1", (source,)).fetchone()
        previous = json.loads(old["value"]) if old and old["boot_id"] == boot else []
        skip = _overlap(previous, clean) if overlap else 0
        inserted = 0
        last = self.db.execute("SELECT event_time_utc,observed_at FROM logs WHERE source_id=? ORDER BY seq DESC LIMIT 1", (source,)).fetchone()
        if old and old["boot_id"] != boot and last:
            self._gap_point(source, last["observed_at"], observed_at, "boot_change")
        elif overlap and not skip and previous and last:
            self._gap_point(source, last["observed_at"], observed_at, "connection_lost")
        if skip and cursor is None and len(set(clean[:skip])) < len(clean[:skip]):
            self._gap_point(source, last["observed_at"] if last else observed_at, observed_at, "parse_uncertainty")
        previous_event = last["event_time_utc"] if last else None
        for record in records[skip:]:
            event = record["event_time_utc"]
            if event and previous_event and parse_explicit(event) < parse_explicit(previous_event) - timedelta(minutes=5):
                record["time_quality"] = "clock_jump"
                self._gap_point(source, previous_event, event, "clock_jump")
            if event:
                previous_event = event
            inserted += int(self.append_log(record | {"source_id": source, "boot_id": boot, "cursor": cursor}, enforce_retention=False))
        tail = (previous + clean[skip:])[-2048:]
        self.db.execute("DELETE FROM tails WHERE source_id=? AND boot_id!=?", (source, boot))
        self.db.execute("INSERT OR REPLACE INTO tails VALUES(?,?,?)", (source, boot, _json(tail)))
        self.db.commit()
        self.enforce_retention(now=observed_at)
        # Polling overlap is not a verified source cursor and never establishes completeness.
        return {"inserted": inserted, "deduplicated": skip, "status": "unknown" if continuity != "complete" or cursor is None else "complete", "deduplication_basis": "cursor" if cursor else "bounded_suffix_overlap", "limitations": ["No source cursor: identical overlap cannot prove occurrence continuity."] if cursor is None and overlap else []}

    def _gap_point(self, source: str, first: str, second: str, reason: str) -> None:
        left, right = sorted((parse_explicit(first), parse_explicit(second)))
        if left == right:
            right += timedelta(microseconds=1)
        self.add_coverage(source, format_utc(left), format_utc(right), "partial", reason)

    def _bounded_read(self):
        deadline = time.monotonic() + 5
        self.db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)

    def query_logs(self, source_ids: list[str], from_: str, to: str, levels: list[str] | None = None, query: str | None = None, limit: int = 200, after: int | None = None) -> dict:
        start, end = validate_interval(from_, to)
        if not 1 <= len(source_ids) <= 10 or not 1 <= limit <= 200 or after is not None and (isinstance(after, bool) or not isinstance(after, int) or after < 0):
            raise ValueError("QUERY_TOO_LARGE")
        for source in source_ids:
            self._source(source)
        if levels is not None and (not levels or any(level not in LEVELS for level in levels)):
            raise ValueError("INVALID_LOG_LEVEL")
        if query is not None and (not isinstance(query, str) or not 1 <= len(query) <= 200):
            raise ValueError("QUERY_TOO_LARGE")
        placeholders = ",".join("?" for _ in source_ids)
        # Unknown event timestamps are selected by observation and marked as such.
        sql = f"SELECT * FROM logs WHERE source_id IN ({placeholders}) AND COALESCE(event_time_utc,observed_at)>=? AND COALESCE(event_time_utc,observed_at)<?"
        args: list = [*source_ids, start, end]
        if levels:
            sql += " AND level IN (" + ",".join("?" for _ in levels) + ")"
            args.extend(levels)
        if query:
            sql += " AND instr(lower(sanitized_message),lower(?))>0"
            args.append(query)
        # Stable ingestion order for internal pagination; MCP timeline may sort page output.
        if after is not None:
            position = self.db.execute("SELECT COALESCE(event_time_utc,observed_at),record_id FROM logs WHERE seq=?", (after,)).fetchone()
            if position is None:
                raise ValueError("CURSOR_EXPIRED")
            sql += " AND (COALESCE(event_time_utc,observed_at)>? OR (COALESCE(event_time_utc,observed_at)=? AND record_id>?))"
            args.extend((position[0], position[0], position[1]))
        sql += " ORDER BY COALESCE(event_time_utc,observed_at),record_id LIMIT ?"
        args.append(limit + 1)
        self._bounded_read()
        try:
            rows = self.db.execute(sql, args).fetchall()
        except sqlite3.OperationalError:
            raise ValueError("QUERY_TIMEOUT") from None
        finally:
            self.db.set_progress_handler(None, 0)
        output = [self._log(row) for row in rows[:limit]]
        return {"records": output, "next_after": rows[limit - 1]["seq"] if len(rows) > limit else None, "coverage": self.coverage(source_ids, start, end), "generation": self.generation}

    def _log(self, row: sqlite3.Row) -> dict:
        result = dict(row)
        result.pop("content_hash", None)
        result.pop("seq", None)
        result["truncated"] = bool(result["truncated"])
        result["local_locator"] = result["source_id"] + " / " + result["record_id"]
        result["selection_time_basis"] = "event" if result["event_time_utc"] else "observation_only"
        return result

    def get_log_record(self, record_id: str, before: int = 0, after: int = 0, allowed_source_ids: list[str] | None = None) -> dict | None:
        _id(record_id)
        if not 0 <= before <= 20 or not 0 <= after <= 20:
            raise ValueError("QUERY_TOO_LARGE")
        row = self.db.execute("SELECT l.* FROM logs l JOIN sources s USING(source_id) WHERE record_id=? AND s.enabled=1", (record_id,)).fetchone()
        if row is None or allowed_source_ids is not None and row["source_id"] not in allowed_source_ids:
            return None
        preceding = self.db.execute("SELECT * FROM logs WHERE source_id=? AND seq<? ORDER BY seq DESC LIMIT ?", (row["source_id"], row["seq"], before)).fetchall()
        following = self.db.execute("SELECT * FROM logs WHERE source_id=? AND seq>? ORDER BY seq LIMIT ?", (row["source_id"], row["seq"], after)).fetchall()
        return {"record": self._log(row), "before": [self._log(r) for r in reversed(preceding)], "after": [self._log(r) for r in following]}

    def append_transition(self, record: dict) -> str:
        self._write()
        entity = _id(record["entity_ref"])
        source = _source_id(record.get("source_id", "src_history"))
        self._source(source, create=True)
        observed = format_utc(parse_explicit(record["observed_at"]))
        event = format_utc(parse_explicit(record.get("event_time_utc", record.get("event_time")))) if record.get("event_time_utc", record.get("event_time")) is not None else None
        cleaned = self._safe(record)
        # Recorder repeats the same historical observation during overlapping
        # backfill. Observation time is not a new event. Live events deliberately
        # do not use this rule: equal values/timestamps can be genuine repeats.
        if cleaned.get("origin") == "recorder" and event is not None:
            boundary = cleaned.get("boundary_state", False)
            state = json.dumps(cleaned.get("new_state"), sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
            candidates = self.db.execute("SELECT record_id,payload FROM transitions WHERE source_id=? AND entity_ref=? AND event_time_utc=? AND json_extract(payload,'$.origin')='recorder'", (source, entity, event))
            for candidate in candidates:
                previous = json.loads(candidate["payload"])
                prior_state = json.dumps(previous.get("new_state"), sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
                if prior_state == state and previous.get("boundary_state", False) == boundary:
                    return candidate["record_id"]
        record_id = "rec_" + uuid.uuid4().hex
        self.db.execute("INSERT INTO transitions(record_id,entity_ref,source_id,event_time_utc,observed_at,payload,is_snapshot) VALUES(?,?,?,?,?,?,?)", (record_id, entity, source, event, observed, _json(cleaned), int(record.get("is_snapshot", False))))
        self.db.commit()
        self._maybe_retention(observed)
        return record_id

    def query_history(self, entity_refs: list[str], from_: str, to: str, limit: int = 500, after: int | None = None) -> dict:
        start, end = validate_interval(from_, to)
        if not 1 <= len(entity_refs) <= 20 or not 1 <= limit <= 500:
            raise ValueError("QUERY_TOO_LARGE")
        for entity in entity_refs:
            _id(entity)
        marks = ",".join("?" for _ in entity_refs)
        args = [*entity_refs, start, end]
        sql = f"SELECT t.* FROM transitions t JOIN sources s USING(source_id) WHERE entity_ref IN ({marks}) AND COALESCE(event_time_utc,observed_at)>=? AND COALESCE(event_time_utc,observed_at)<? AND s.enabled=1"
        if after is not None:
            if isinstance(after, bool) or not isinstance(after, int) or after < 0:
                raise ValueError("INVALID_POSITION")
            position = self.db.execute("SELECT COALESCE(event_time_utc,observed_at),record_id FROM transitions WHERE seq=?", (after,)).fetchone()
            if position is None:
                raise ValueError("CURSOR_EXPIRED")
            sql += " AND (COALESCE(event_time_utc,observed_at)>? OR (COALESCE(event_time_utc,observed_at)=? AND record_id>?))"
            args.extend((position[0], position[0], position[1]))
        rows = self.db.execute(sql + " ORDER BY COALESCE(event_time_utc,observed_at),record_id LIMIT ?", (*args, limit + 1)).fetchall()
        def transition(row):
            return json.loads(row["payload"]) | {"record_id": row["record_id"], "is_snapshot": bool(row["is_snapshot"]), "event_time_utc": row["event_time_utc"], "observed_at": row["observed_at"]}
        boundary = []
        for entity in entity_refs:
            row = self.db.execute("SELECT t.* FROM transitions t JOIN sources s USING(source_id) WHERE entity_ref=? AND event_time_utc<? AND is_snapshot=0 AND s.enabled=1 ORDER BY event_time_utc DESC,seq DESC LIMIT 1", (entity, start)).fetchone()
            if row:
                boundary.append(transition(row) | {"boundary_state": True})
        sources = list(dict.fromkeys(row["source_id"] for row in rows))
        return {"records": [transition(row) for row in rows[:limit]], "boundary_states": boundary, "next_after": rows[limit - 1]["seq"] if len(rows) > limit else None, "coverage": self.coverage(sources, start, end) if sources else [{"from": start, "to": end, "status": "unknown", "reason": "history_unknown"}], "generation": self.generation}

    def query_incident(self, entity_refs: list[str], source_ids: list[str], from_: str, to: str,
                       limit: int = 200, after: dict | None = None) -> dict:
        """One bounded chronological page across state evidence and selected logs.

        ``after`` is an internal composite key and must be wrapped in the MCP
        subject/policy/filter-bound cursor. Snapshot metadata never enters this
        timeline. Association of a log with a device is supplied by the caller;
        temporal proximity itself makes no causal claim.
        """
        start, end = validate_interval(from_, to)
        if not 1 <= len(entity_refs) <= 1000 or len(source_ids) > 10 or isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
            raise ValueError("QUERY_TOO_LARGE")
        for ref in entity_refs:
            _id(ref)
        available_sources, unavailable_sources = [], []
        for source in source_ids:
            _source_id(source)
            status = self.db.execute("SELECT enabled FROM sources WHERE source_id=?", (source,)).fetchone()
            (available_sources if status and status["enabled"] else unavailable_sources).append(source)
        if after is not None:
            if not isinstance(after, dict) or set(after) != {"time", "record_id"}:
                raise ValueError("INVALID_POSITION")
            position_time = format_utc(parse_explicit(after["time"]))
            position_id = _id(after["record_id"])
        entity_marks = ",".join("?" for _ in entity_refs)
        parts = [f"SELECT t.seq,t.record_id,'state' AS evidence_kind,COALESCE(t.event_time_utc,t.observed_at) AS selection_time,t.source_id FROM transitions t JOIN sources s USING(source_id) WHERE t.entity_ref IN ({entity_marks}) AND COALESCE(t.event_time_utc,t.observed_at)>=? AND COALESCE(t.event_time_utc,t.observed_at)<? AND t.is_snapshot=0 AND s.enabled=1"]
        arguments = [*entity_refs, start, end]
        if available_sources:
            source_marks = ",".join("?" for _ in available_sources)
            parts.append(f"SELECT l.seq,l.record_id,'log' AS evidence_kind,COALESCE(l.event_time_utc,l.observed_at) AS selection_time,l.source_id FROM logs l JOIN sources s USING(source_id) WHERE l.source_id IN ({source_marks}) AND COALESCE(l.event_time_utc,l.observed_at)>=? AND COALESCE(l.event_time_utc,l.observed_at)<? AND s.enabled=1")
            arguments.extend((*available_sources, start, end))
        sql = "WITH selected AS (" + " UNION ALL ".join(parts) + ") SELECT * FROM selected"
        if after is not None:
            sql += " WHERE selection_time>? OR (selection_time=? AND record_id>?)"
            arguments.extend((position_time, position_time, position_id))
        sql += " ORDER BY selection_time,record_id LIMIT ?"
        arguments.append(limit + 1)
        self._bounded_read()
        try:
            rows = self.db.execute(sql, arguments).fetchall()
            timeline = []
            for position in rows[:limit]:
                table = "logs" if position["evidence_kind"] == "log" else "transitions"
                row = self.db.execute(f"SELECT * FROM {table} WHERE seq=?", (position["seq"],)).fetchone()
                if position["evidence_kind"] == "log":
                    item = self._log(row)
                else:
                    item = json.loads(row["payload"]) | {"record_id": row["record_id"], "entity_ref": row["entity_ref"], "source_id": row["source_id"], "event_time_utc": row["event_time_utc"], "observed_at": row["observed_at"], "is_snapshot": False, "selection_time_basis": "event" if row["event_time_utc"] else "observation_only", "local_locator": row["source_id"] + " / " + row["record_id"]}
                timeline.append(item | {"evidence_kind": position["evidence_kind"]})
            boundary_states = []
            for ref in entity_refs:
                row = self.db.execute("SELECT t.* FROM transitions t JOIN sources s USING(source_id) WHERE entity_ref=? AND event_time_utc<? AND is_snapshot=0 AND s.enabled=1 ORDER BY event_time_utc DESC,record_id DESC LIMIT 1", (ref, start)).fetchone()
                if row:
                    boundary_states.append(json.loads(row["payload"]) | {"record_id": row["record_id"], "event_time_utc": row["event_time_utc"], "observed_at": row["observed_at"], "boundary_state": True})
            history_sources = [row[0] for row in self.db.execute(f"SELECT DISTINCT t.source_id FROM transitions t JOIN sources s USING(source_id) WHERE t.entity_ref IN ({entity_marks}) AND s.enabled=1", entity_refs)]
        except sqlite3.OperationalError:
            raise ValueError("QUERY_TIMEOUT") from None
        finally:
            self.db.set_progress_handler(None, 0)
        sources = list(dict.fromkeys([*available_sources, *history_sources]))
        coverage = self.coverage(sources, start, end) if sources else []
        for source in unavailable_sources:
            coverage.append({"source_id": source, "from": start, "to": end, "status": "unavailable", "gaps": [{"from": start, "to": end, "status": "unavailable", "reason": "source_unavailable", "ingestion_basis": "none", "dropped_count": 0}]})
        if not history_sources:
            coverage.append({"from": start, "to": end, "status": "unknown", "reason": "history_unknown"})
        next_after = {"time": rows[limit - 1]["selection_time"], "record_id": rows[limit - 1]["record_id"]} if len(rows) > limit else None
        return {"timeline": timeline, "boundary_states": boundary_states, "coverage": coverage, "next_after": next_after, "generation": self.generation}

    def upsert_metadata(self, record: dict) -> str:
        self._write()
        observed = format_utc(parse_explicit(record["observed_at"]))
        device = _id(record["device_ref"]) if record.get("device_ref") else None
        cleaned = self._safe(record)
        snapshot = "snap_" + uuid.uuid4().hex
        self.db.execute("INSERT INTO metadata(snapshot_id,device_ref,observed_at,payload) VALUES(?,?,?,?)", (snapshot, device, observed, _json(cleaned)))
        self.db.commit()
        self._maybe_retention(observed)
        return snapshot

    def get_metadata(self, device_ref: str | None = None) -> list[dict]:
        if device_ref:
            rows = self.db.execute("SELECT * FROM metadata WHERE device_ref=? ORDER BY observed_at DESC,seq DESC LIMIT 1", (_id(device_ref),)).fetchall()
        else:
            rows = self.db.execute("SELECT m.* FROM metadata m WHERE seq IN (SELECT MAX(seq) FROM metadata GROUP BY COALESCE(device_ref,json_extract(payload,'$.entity_ref'),json_extract(payload,'$.kind'),'installation')) ORDER BY seq DESC LIMIT 1024").fetchall()
        return [json.loads(row["payload"]) | {"snapshot_id": row["snapshot_id"], "observed_at": row["observed_at"]} for row in rows]

    def get_device_metadata(self) -> list[dict]:
        """Latest selected-device mappings, independent of state snapshot volume."""
        rows = self.db.execute("SELECT m.* FROM metadata m WHERE seq IN (SELECT MAX(seq) FROM metadata WHERE device_ref IS NOT NULL GROUP BY device_ref) ORDER BY observed_at DESC,device_ref LIMIT 1000").fetchall()
        return [json.loads(row["payload"]) | {"snapshot_id": row["snapshot_id"], "observed_at": row["observed_at"]} for row in rows]

    def get_entity_snapshots(self, entity_refs: list[str]) -> list[dict]:
        if not 1 <= len(entity_refs) <= 1000:
            raise ValueError("QUERY_TOO_LARGE")
        for ref in entity_refs:
            _id(ref)
        marks = ",".join("?" for _ in entity_refs)
        rows = self.db.execute(f"SELECT m.* FROM metadata m WHERE seq IN (SELECT MAX(seq) FROM metadata WHERE json_extract(payload,'$.kind')='entity_snapshot' AND json_extract(payload,'$.entity_ref') IN ({marks}) GROUP BY json_extract(payload,'$.entity_ref')) ORDER BY observed_at DESC,seq DESC LIMIT 1000", entity_refs).fetchall()
        return [json.loads(row["payload"]) | {"snapshot_id": row["snapshot_id"], "observed_at": row["observed_at"]} for row in rows]

    def get_installation_metadata(self) -> dict | None:
        row = self.db.execute("SELECT * FROM metadata WHERE json_extract(payload,'$.kind')='installation' ORDER BY observed_at DESC,seq DESC LIMIT 1").fetchone()
        return json.loads(row["payload"]) | {"snapshot_id": row["snapshot_id"], "observed_at": row["observed_at"]} if row else None

    def store_artifact(self, kind: str, sanitized_content: str, *, approved: bool = False, source_time_range: dict | None = None, coverage_notes: list[str] | None = None, approved_fields: list[str] | None = None) -> str:
        self._write()
        if kind not in {"log", "text", "json"} or not isinstance(approved, bool):
            raise ValueError("INVALID_ARTIFACT")
        # Callers must pass preview-cleaned JSON; text has a final defense-in-depth pass.
        clean = self.redactor.clean_text(sanitized_content, None) if kind != "json" else _json(self.redactor.clean_json(json.loads(sanitized_content), approved_fields=set(approved_fields) if approved_fields is not None else None))
        if len(clean.encode()) > 20 * 1024 * 1024:
            raise ValueError("IMPORT_TOO_LARGE")
        artifact = "art_" + uuid.uuid4().hex
        now = utc_now()
        self.db.execute("INSERT INTO artifacts(artifact_id,kind,imported_at,sanitized_content,sanitized_content_hash,approved,source_time_range,coverage_notes,approved_fields) VALUES(?,?,?,?,?,?,?,?,?)", (artifact, kind, now, clean, hashlib.sha256(clean.encode()).hexdigest(), int(approved), _json(source_time_range) if source_time_range else None, _json(coverage_notes or ["Imported data does not prove continuous coverage."]), _json(approved_fields or [])))
        self.db.commit()
        self.enforce_retention(now=now)
        if not self.db.execute("SELECT 1 FROM artifacts WHERE artifact_id=?", (artifact,)).fetchone():
            raise ValueError("ARTIFACT_EXCEEDS_STORAGE_QUOTA")
        return artifact

    def approve_artifact(self, artifact_id: str, approved: bool) -> None:
        self._write()
        if not isinstance(approved, bool):
            raise ValueError("INVALID_ARTIFACT")
        self.db.execute("UPDATE artifacts SET approved=? WHERE artifact_id=?", (int(approved), _id(artifact_id)))
        self.db.execute("UPDATE settings SET value=CAST(value AS INTEGER)+1 WHERE key='generation'")
        self.db.commit()

    def delete_artifact(self, artifact_id: str) -> None:
        self._write()
        self.db.execute("DELETE FROM artifacts WHERE artifact_id=?", (_id(artifact_id),))
        self.db.execute("UPDATE settings SET value=CAST(value AS INTEGER)+1 WHERE key='generation'")
        self.db.commit()
        self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def list_artifacts(self, kind: str | None = None, limit: int = 20, after: int | None = None, approved_only: bool = True) -> dict:
        if not 1 <= limit <= 20 or kind is not None and kind not in {"log", "text", "json"}:
            raise ValueError("QUERY_TOO_LARGE")
        sql, args = "SELECT * FROM artifacts WHERE 1=1", []
        if approved_only:
            sql += " AND approved=1"
        if kind:
            sql += " AND kind=?"
            args.append(kind)
        if after is not None:
            if not isinstance(after, int) or isinstance(after, bool) or after < 0:
                raise ValueError("INVALID_POSITION")
            sql += " AND seq>?"
            args.append(after)
        rows = self.db.execute(sql + " ORDER BY seq LIMIT ?", (*args, limit + 1)).fetchall()
        artifacts = []
        for row in rows[:limit]:
            item = dict(row)
            item.pop("sanitized_content")
            item.pop("seq")
            item["approved"] = bool(item["approved"])
            for field in ("source_time_range", "coverage_notes", "approved_fields"):
                item[field] = json.loads(item[field]) if item[field] else None
            artifacts.append(item)
        return {"artifacts": artifacts, "next_after": rows[limit - 1]["seq"] if len(rows) > limit else None, "generation": self.generation}

    def read_artifact(self, artifact_id: str, offset: int = 0, max_chars: int = 16000, approved_only: bool = True) -> dict | None:
        _id(artifact_id)
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0 or not 1 <= max_chars <= 16000:
            raise ValueError("QUERY_TOO_LARGE")
        row = self.db.execute("SELECT * FROM artifacts WHERE artifact_id=?" + (" AND approved=1" if approved_only else ""), (artifact_id,)).fetchone()
        if not row:
            return None
        content = row["sanitized_content"]
        if offset > len(content):
            raise ValueError("INVALID_OFFSET")
        end = min(offset + max_chars, len(content))
        return {"artifact_id": artifact_id, "kind": row["kind"], "content": content[offset:end], "offset": offset, "end_offset": end, "total_chars": len(content), "next_offset": end if end < len(content) else None, "truncated": end < len(content), "untrusted_data": True, "local_locator": artifact_id + " / " + str(offset)}

    def summarize_errors(self, source_ids: list[str], from_: str, to: str, limit: int = 50, after: str | None = None) -> dict:
        start, end = validate_interval(from_, to)
        if not 1 <= len(source_ids) <= 10 or not 1 <= limit <= 50:
            raise ValueError("QUERY_TOO_LARGE")
        for source in source_ids:
            self._source(source)
        if after is not None and not re.fullmatch(r"[a-f0-9]{64}", after):
            raise ValueError("INVALID_POSITION")
        baseline_end = start
        baseline_start = format_utc(parse_explicit(start) - (parse_explicit(end) - parse_explicit(start)))
        marks = ",".join("?" for _ in source_ids)
        args = [*source_ids, start, end]
        sql = f"SELECT fingerprint,logger,level,COUNT(*) AS count,MIN(COALESCE(event_time_utc,observed_at)) AS first_seen,MAX(COALESCE(event_time_utc,observed_at)) AS last_seen FROM logs WHERE source_id IN ({marks}) AND COALESCE(event_time_utc,observed_at)>=? AND COALESCE(event_time_utc,observed_at)<? AND level IN ('ERROR','CRITICAL')"
        if after:
            sql += " AND fingerprint>?"
            args.append(after)
        self._bounded_read()
        try:
            rows = self.db.execute(sql + " GROUP BY fingerprint,logger,level ORDER BY fingerprint LIMIT ?", (*args, limit + 1)).fetchall()
            groups = []
            baseline_coverage = self.coverage(source_ids, baseline_start, baseline_end)
            complete = all(item["status"] == "complete" for item in baseline_coverage)
            for row in rows[:limit]:
                samples = self.db.execute(f"SELECT * FROM logs WHERE source_id IN ({marks}) AND fingerprint=? AND COALESCE(event_time_utc,observed_at)>=? AND COALESCE(event_time_utc,observed_at)<? ORDER BY COALESCE(event_time_utc,observed_at),record_id LIMIT 3", (*source_ids, row["fingerprint"], start, end)).fetchall()
                count = self.db.execute(f"SELECT COUNT(*) FROM logs WHERE source_id IN ({marks}) AND fingerprint=? AND COALESCE(event_time_utc,observed_at)>=? AND COALESCE(event_time_utc,observed_at)<?", (*source_ids, row["fingerprint"], baseline_start, baseline_end)).fetchone()[0]
                groups.append(dict(row) | {"examples": [self._log(sample) for sample in samples], "baseline_count": count, "baseline_comparison": "previously_observed" if count else "not_found_in_complete_baseline" if complete else "not_found_in_available_baseline", "fingerprint_version": "1"})
        except sqlite3.OperationalError:
            raise ValueError("QUERY_TIMEOUT") from None
        finally:
            self.db.set_progress_handler(None, 0)
        return {"groups": groups, "next_after": rows[limit - 1]["fingerprint"] if len(rows) > limit else None, "coverage": self.coverage(source_ids, start, end), "baseline": {"from": baseline_start, "to": baseline_end, "coverage": baseline_coverage}, "generation": self.generation}

    def clear(self) -> None:
        """Local-owner deletion of diagnostic data; retain local source configuration."""
        self._write()
        for table in ("logs", "transitions", "metadata", "artifacts", "coverage", "cursors", "tails"):
            self.db.execute(f"DELETE FROM {table}")
        self.db.execute("UPDATE sources SET collected_since=NULL,latest_observed_at=NULL,status='unknown'")
        self.db.execute("UPDATE settings SET value=CAST(value AS INTEGER)+1 WHERE key='generation'")
        self.db.commit()
        self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self.db.execute("VACUUM")

    clear_all = clear

    def storage_bytes(self) -> int:
        return sum(p.stat().st_size for p in (self.path, Path(str(self.path) + "-wal"), Path(str(self.path) + "-shm")) if p.exists())

    def _maybe_retention(self, now: str) -> None:
        if self.storage_bytes() > self.max_bytes or time.monotonic() - self._last_retention >= 30:
            self.enforce_retention(now=now)
            self._last_retention = time.monotonic()

    def check_disk(self) -> bool:
        self._write()
        usage = shutil.disk_usage(self.path.parent)
        return usage.free >= self.min_free_bytes and usage.free >= usage.total * .05

    def enforce_retention(self, *, now: str | None = None) -> dict:
        self._write()
        current = parse_explicit(now) if now else parse_explicit(utc_now())
        cutoff = format_utc(current - timedelta(days=self.retention_days))
        removed = 0
        affected = self.db.execute("SELECT source_id,MIN(COALESCE(event_time_utc,observed_at)),MAX(COALESCE(event_time_utc,observed_at)),COUNT(*) FROM logs WHERE observed_at<? GROUP BY source_id", (cutoff,)).fetchall()
        for table, column in (("logs", "observed_at"), ("transitions", "observed_at"), ("metadata", "observed_at"), ("artifacts", "imported_at")):
            removed += self.db.execute(f"DELETE FROM {table} WHERE {column}<?", (cutoff,)).rowcount
        for source, first, last, count in affected:
            self._gap_point(source, first, format_utc(parse_explicit(last) + timedelta(microseconds=1)), "source_retention")
        self.db.commit()
        self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        while self.storage_bytes() > self.max_bytes:
            candidates = []
            for table, column in (("logs", "observed_at"), ("transitions", "observed_at"), ("metadata", "observed_at"), ("artifacts", "imported_at")):
                row = self.db.execute(f"SELECT seq,{column} FROM {table} ORDER BY {column},seq LIMIT 1").fetchone()
                if row:
                    candidates.append((row[1], table, row[0]))
            if not candidates:
                break
            _, table, seq = min(candidates)
            if table == "logs":
                rows = self.db.execute("SELECT * FROM logs WHERE seq>=? ORDER BY seq LIMIT 128", (seq,)).fetchall()
                by_source: dict[str, list] = {}
                for row in rows:
                    by_source.setdefault(row["source_id"], []).append(row)
                for source, group in by_source.items():
                    times = [r["event_time_utc"] or r["observed_at"] for r in group]
                    self.add_coverage(source, min(times), format_utc(parse_explicit(max(times)) + timedelta(microseconds=1)), "partial", "quota_eviction", "archive_eviction", len(group))
                self.db.execute("DELETE FROM logs WHERE seq IN (" + ",".join("?" for _ in rows) + ")", [row["seq"] for row in rows])
                removed += len(rows)
            else:
                self.db.execute(f"DELETE FROM {table} WHERE seq=?", (seq,))
                removed += 1
            self.db.commit()
            self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self.db.execute("VACUUM")
            self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        if removed:
            self.db.execute("UPDATE settings SET value=CAST(value AS INTEGER)+1 WHERE key='generation'")
            # Tail hashes from evicted windows cannot substantiate reconnect overlap.
            self.db.execute("DELETE FROM tails")
            self.db.commit()
            self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self.db.execute("VACUUM")
            self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return {"removed": removed, "storage_bytes": self.storage_bytes(), "quota_satisfied": self.storage_bytes() <= self.max_bytes, "generation": self.generation}

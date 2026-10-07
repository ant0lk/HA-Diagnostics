"""Bounded local-admin import: raw bytes are never written to disk.

Parsing/sanitization runs in a disposable process with a deadline and Linux
resource limits. Preview contains only cleaned material; approval is local-only.
"""
from __future__ import annotations

import hashlib
import json
import multiprocessing
import re
import time
import unicodedata
import uuid
from dataclasses import dataclass

from .archive import Archive
from .redaction import Redactor, SAFE_KEYS
from .timeutil import source_time

MAX_IMPORT_BYTES = 20 * 1024 * 1024


def _validate_filename(filename: str) -> str:
    if not isinstance(filename, str) or not 1 <= len(filename) <= 200:
        raise ValueError("INVALID_FILENAME")
    if any(ord(c) < 32 for c in filename) or any(c in filename for c in "/\\%:") or ".." in filename or unicodedata.normalize("NFKC", filename) != filename:
        raise ValueError("INVALID_FILENAME")
    extension = filename.rsplit(".", 1)[-1].lower()
    if extension not in {"log", "txt", "json"}:
        raise ValueError("UNSUPPORTED_IMPORT_TYPE")
    return {"log": "log", "txt": "text", "json": "json"}[extension]


def _pairs(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _parse_clean(data: bytes, kind: str, key: bytes, zone: str, approved_fields: frozenset[str]) -> dict:
    if not isinstance(data, bytes) or not data or len(data) > MAX_IMPORT_BYTES:
        raise ValueError("IMPORT_TOO_LARGE")
    if b"\0" in data:
        raise ValueError("BINARY_IMPORT_REJECTED")
    if data.startswith((b"PK\x03\x04", b"%PDF-", b"\x7fELF", b"MZ", b"#!", b"\x89PNG", b"\xff\xd8\xff")):
        raise ValueError("UNSUPPORTED_IMPORT_CONTENT")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ValueError("UTF8_IMPORT_REQUIRED") from None
    if sum(ord(c) < 32 and c not in "\r\n\t" for c in text) > max(1, len(text) // 100):
        raise ValueError("BINARY_IMPORT_REJECTED")
    redactor = Redactor(key)
    removed = []
    source_range = None
    if kind == "json":
        try:
            parsed = json.loads(text, object_pairs_hook=_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("INVALID_JSON_NUMBER")))
        except (json.JSONDecodeError, RecursionError):
            raise ValueError("INVALID_JSON") from None
        if not isinstance(parsed, (dict, list)):
            raise ValueError("JSON_CONTAINER_REQUIRED")
        cleaned = redactor.clean_json(parsed, approved_fields=approved_fields, removed_fields=removed)
        content = json.dumps(cleaned, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        notes = ["Imported JSON is untrusted data; timestamps are not inferred from upload time.", "Only approved diagnostic field names are retained."]
    else:
        # A JSON diagnostic renamed .txt must receive structured sanitization.
        # Ambiguous/malformed JSON is rejected rather than bypassing its allowlist.
        json_candidate = text.lstrip().startswith("{") or bool(re.match(r'^\[\s*(?:[\{\["\-]|\d(?:\s*[,\]])|true\b|false\b|null\b|\])', text.lstrip()))
        if json_candidate:
            try:
                parsed = json.loads(text, object_pairs_hook=_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("INVALID_JSON_NUMBER")))
            except (json.JSONDecodeError, RecursionError):
                raise ValueError("IMPORT_CONTENT_TYPE_MISMATCH") from None
            cleaned = redactor.clean_json(parsed, approved_fields=approved_fields, removed_fields=removed)
            content = json.dumps(cleaned, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
            return {"kind": "json", "sanitized_content": content, "sanitized_content_hash": hashlib.sha256(content.encode()).hexdigest(), "removed_fields": removed[:200], "source_time_range": None, "coverage_notes": ["JSON detected by content; diagnostic field allowlist applied.", "Imported JSON is untrusted data; timestamps are not inferred from upload time."], "approved_fields": sorted(approved_fields)}
        content = redactor.clean_text(text, None)
        if len(text.splitlines()) > 50000:
            raise ValueError("IMPORT_LINE_LIMIT_EXCEEDED")
        times, unknown = [], 0
        for line in text.splitlines():
            result = source_time(line, zone)
            if result["event_time_utc"]:
                times.append(result["event_time_utc"])
            else:
                unknown += 1
        if times:
            source_range = {"first_event_time": min(times), "last_event_time": max(times), "interval_semantics": "observed_extent_not_coverage"}
        notes = ["Imported log is untrusted data and does not prove continuous coverage."]
        if unknown:
            notes.append(f"{unknown} lines have no unambiguous source timestamp; upload time is not event time.")
    if len(content.encode("utf-8")) > MAX_IMPORT_BYTES:
        raise ValueError("SANITIZED_IMPORT_TOO_LARGE")
    return {"kind": kind, "sanitized_content": content, "sanitized_content_hash": hashlib.sha256(content.encode()).hexdigest(), "removed_fields": removed[:200], "source_time_range": source_range, "coverage_notes": notes, "approved_fields": sorted(approved_fields)}


def _worker(connection, data: bytes, kind: str, key: bytes, zone: str, fields: frozenset[str]) -> None:
    try:
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
            resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except ImportError:
            pass  # Windows development: deadline + size limits, no RLIMIT support.
        result = _parse_clean(data, kind, key, zone, fields)
        connection.send({"ok": True, "data": result})
    except Exception as error:
        # Error values from parser are fixed codes. Do not serialize exception text.
        safe = str(error) if isinstance(error, ValueError) and re.fullmatch(r"[A-Z_]{1,80}", str(error)) else "IMPORT_REJECTED"
        connection.send({"ok": False, "error": safe})
    finally:
        connection.close()


@dataclass(frozen=True)
class ImportPreview:
    preview_id: str
    kind: str
    sanitized_content: str
    sanitized_content_hash: str
    removed_fields: tuple[str, ...]
    source_time_range: dict | None
    coverage_notes: tuple[str, ...]
    approved_fields: tuple[str, ...]

    def public_preview(self, max_chars: int = 16000) -> dict:
        if not 1 <= max_chars <= 16000:
            raise ValueError("INVALID_PREVIEW_LIMIT")
        return {"preview_id": self.preview_id, "kind": self.kind, "content": self.sanitized_content[:max_chars], "truncated": len(self.sanitized_content) > max_chars, "removed_fields": list(self.removed_fields), "coverage_notes": list(self.coverage_notes), "source_time_range": self.source_time_range, "sha256": self.sanitized_content_hash, "untrusted_data": True}


class ImportService:
    """Use only from the local broker/admin API, never register as an MCP tool."""
    def __init__(self, archive: Archive, *, timezone: str = "UTC", timeout_seconds: float = 10):
        if archive.readonly:
            raise ValueError("IMPORT_REQUIRES_LOCAL_WRITER")
        if not 0.1 <= timeout_seconds <= 30:
            raise ValueError("INVALID_IMPORT_TIMEOUT")
        self.archive, self.timezone, self.timeout_seconds = archive, timezone, timeout_seconds
        self._previews: dict[str, tuple[float, ImportPreview]] = {}

    def preview(self, filename: str, data: bytes, *, approved_fields: set[str] | frozenset[str] | None = None) -> ImportPreview:
        kind = _validate_filename(filename)
        if not isinstance(data, bytes) or not data or len(data) > MAX_IMPORT_BYTES:
            raise ValueError("IMPORT_TOO_LARGE")
        fields = SAFE_KEYS if approved_fields is None else frozenset(approved_fields)
        if any(field not in SAFE_KEYS for field in fields):
            raise ValueError("UNSAFE_APPROVED_FIELD")
        self._expire()
        if len(self._previews) >= 2:
            raise ValueError("TOO_MANY_IMPORT_PREVIEWS")
        context = multiprocessing.get_context("spawn")
        receiver, sender = context.Pipe(duplex=False)
        process = context.Process(target=_worker, args=(sender, data, kind, self.archive.redactor._key, self.timezone, fields), daemon=True)
        process.start()
        sender.close()
        try:
            if not receiver.poll(self.timeout_seconds):
                raise ValueError("IMPORT_TIMEOUT")
            result = receiver.recv()
        except (EOFError, OSError):
            raise ValueError("IMPORT_WORKER_FAILED") from None
        finally:
            receiver.close()
            process.join(timeout=.1)
            if process.is_alive():
                process.terminate()
                process.join(timeout=1)
        if not result["ok"]:
            raise ValueError(result["error"])
        raw = result["data"]
        preview_id = "preview_" + uuid.uuid4().hex
        preview = ImportPreview(preview_id, raw["kind"], raw["sanitized_content"], raw["sanitized_content_hash"], tuple(raw["removed_fields"]), raw["source_time_range"], tuple(raw["coverage_notes"]), tuple(raw["approved_fields"]))
        self._previews[preview_id] = (time.monotonic() + 300, preview)
        return preview

    def _expire(self) -> None:
        now = time.monotonic()
        self._previews = {key: entry for key, entry in self._previews.items() if entry[0] > now}

    def commit(self, preview_id: str, *, share_with_chatgpt: bool = False) -> str:
        if not isinstance(share_with_chatgpt, bool):
            raise ValueError("INVALID_IMPORT_APPROVAL")
        self._expire()
        entry = self._previews.pop(preview_id, None)
        if entry is None:
            raise ValueError("PREVIEW_NOT_FOUND")
        preview = entry[1]
        return self.archive.store_artifact(preview.kind, preview.sanitized_content, approved=share_with_chatgpt, source_time_range=preview.source_time_range, coverage_notes=list(preview.coverage_notes), approved_fields=list(preview.approved_fields))

    def cancel(self, preview_id: str) -> None:
        self._previews.pop(preview_id, None)

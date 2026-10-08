"""On-demand ZIP creation, with explicit gaps and no raw temporary files."""
from __future__ import annotations

import asyncio
import codecs
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import time
import zipfile
from datetime import datetime, timedelta, timezone

from pydantic import BaseModel, ConfigDict, Field

from . import __version__
from .broker import BrokerError, SLUG_PATTERN
from .export_sources import ENTRY_ID_PATTERN, JSON_SOURCES, LOG_SOURCES, REGISTRY_COMMANDS
from .redaction import IDENTIFIER_KEY, SECRET_KEY, Redactor

EXPORT_ID = r"^export_[a-f0-9]{32}$"
MAX_SOURCE_BYTES = 128 * 1024 * 1024
MAX_EXPORT_BYTES = 512 * 1024 * 1024
MIN_FREE_BYTES = 100 * 1024 * 1024
MAX_LINE_CHARS = 1024 * 1024
RETENTION_SECONDS = 24 * 60 * 60
MAX_EXPORTS = 3
EXCLUDED_KEYS = {"options", "schema", "latitude", "longitude", "gps", "location",
                 "config_dir", "external_url", "internal_url", "data_path"}
PEM_BEGIN = re.compile(r"-----BEGIN [^-]*(?:PRIVATE KEY|CERTIFICATE)-----")
PEM_END = re.compile(r"-----END [^-]+-----")


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class EmptyExportArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class StartExportArgs(EmptyExportArgs):
    # The owner selected the last 24 hours. This is fixed for each export.
    history_hours: int = Field(default=24, ge=24, le=24)


class ExportArgs(EmptyExportArgs):
    export_id: str = Field(pattern=EXPORT_ID)


class ExportSanitizer:
    """Keep diagnostic fields while excluding settings and known secrets.

    Native registry IDs are retained for joins; human labels, network addresses
    and entity IDs use the existing stable local pseudonyms. No keys are copied
    from /config, .storage, the Recorder database or this app's credential files.
    """
    def __init__(self, redactor: Redactor, scrub_known_secret):
        self.redactor = redactor
        self.scrub_known_secret = scrub_known_secret

    def text(self, value: str) -> str:
        return self.redactor.clean_text(self.scrub_known_secret(value), max_chars=None)

    def json(self, value):
        count = 0
        def walk(item, depth=0):
            nonlocal count
            count += 1
            if depth > 64 or count > 1_000_000:
                raise BrokerError("UPSTREAM_LIMIT")
            if item is None or isinstance(item, (bool, int, float)):
                return item
            if isinstance(item, str):
                return self.text(item)
            if isinstance(item, list):
                return [walk(v, depth + 1) for v in item]
            if isinstance(item, dict):
                result = {}
                for key, raw in item.items():
                    if not isinstance(key, str) or len(key) > 200:
                        raise BrokerError("UPSTREAM_FORMAT")
                    safe_key = self.text(key)
                    if SECRET_KEY.search(key) or key.lower() in EXCLUDED_KEYS:
                        result[safe_key] = "[REDACTED]"
                    elif key in {"id", "device_id", "entry_id", "config_entry_id"}:
                        # A device's registry id and entity.device_id must join.
                        result[safe_key] = walk(raw, depth + 1)
                    elif IDENTIFIER_KEY.fullmatch(key) and isinstance(raw, str) and raw:
                        kind = "ENTITY" if key == "entity_id" else "IDENTIFIER"
                        # Addresses inside strings are normalized by Redactor.
                        result[safe_key] = self.text(raw) if key in {"ip", "ip_address", "mac", "mac_address", "address"} else self.redactor.alias(kind, raw)
                    else:
                        result[safe_key] = walk(raw, depth + 1)
                return result
            raise BrokerError("UPSTREAM_FORMAT")
        return walk(value)

    def log_line(self, line: str, inside_pem: bool) -> tuple[str, bool]:
        # Line-based streaming must not leak a multiline PEM body.
        if inside_pem or PEM_BEGIN.search(line):
            ends = bool(PEM_END.search(line))
            return ("[SECRET_REDACTED]\n" if not inside_pem else "", not ends)
        return self.text(line), False


class ExportService:
    def __init__(self, directory: Path, sources, redactor: Redactor, *, demo=False,
                 max_source_bytes=MAX_SOURCE_BYTES, max_export_bytes=MAX_EXPORT_BYTES,
                 min_free_bytes=MIN_FREE_BYTES):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        if self.directory.is_symlink() or not self.directory.is_dir():
            raise ValueError("UNSAFE_EXPORT_STORAGE")
        self.sources = sources
        self.sanitizer = ExportSanitizer(redactor, sources.scrub_known_secret)
        self.demo = demo
        self.max_source_bytes = max_source_bytes
        self.max_export_bytes = max_export_bytes
        self.min_free_bytes = min_free_bytes
        self.jobs = {}
        self._task = None
        self._total_bytes = 0
        self._bytes_since_disk_check = 0
        self._restore()

    def _restore(self):
        # Resume downloads of finished exports after a worker restart.
        for path in sorted(self.directory.glob("export_*.zip"), key=lambda p: p.lstat().st_mtime)[-MAX_EXPORTS:]:
            export_id = path.stem
            if not re.fullmatch(EXPORT_ID, export_id) or path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode) or path.lstat().st_nlink != 1:
                continue
            try:
                with zipfile.ZipFile(path) as archive:
                    if archive.getinfo("manifest.json").file_size > 2 * 1024 * 1024:
                        continue
                    manifest = json.loads(archive.read("manifest.json"))
                if manifest.get("export_id") != export_id:
                    continue
                self.jobs[export_id] = {"export_id": export_id, "status": "ready",
                    "started_at": manifest["started_at"], "finished_at": manifest["finished_at"],
                    "demo": manifest.get("demo", False), "history_hours": 24,
                    "completed_sources": len(manifest["sources"]), "current_source": None,
                    "bytes": path.stat().st_size, "filename": self._filename(export_id),
                    "issues": sum(s["status"] != "ok" for s in manifest["sources"])}
            except (OSError, ValueError, KeyError, zipfile.BadZipFile):
                continue
        self._cleanup()

    def _cleanup(self, remove_terminal=False):
        cutoff = time.time() - RETENTION_SECONDS
        ready = sorted((j for j in self.jobs.values() if j["status"] == "ready"),
                       key=lambda j: j["started_at"], reverse=True)
        keep = {j["export_id"] for j in ready[:MAX_EXPORTS]}
        for path in self.directory.iterdir():
            if not re.fullmatch(r"export_[a-f0-9]{32}\.(?:zip|partial)", path.name) or path.is_symlink():
                continue
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                continue
            running = self.jobs.get(path.stem, {}).get("status") == "collecting"
            if (not running and (info.st_mtime < cutoff or path.suffix == ".partial")
                    or path.suffix == ".zip" and path.stem not in keep):
                path.unlink(missing_ok=True)
                self.jobs.pop(path.stem, None)
        # Terminal state without a downloadable file need not accumulate forever.
        for export_id in list(self.jobs):
            if remove_terminal and self.jobs[export_id]["status"] in {"failed", "cancelled"}:
                self.jobs.pop(export_id)

    @staticmethod
    def _filename(export_id):
        return "ha-diagnostics-" + export_id[7:] + ".zip"

    async def request(self, op, args):
        # Same schema/allowlist in demo as the kernel-authenticated IPC worker.
        if op not in self.handlers():
            raise BrokerError("OPERATION_DENIED")
        schema, callback = self.handlers()[op]
        return await callback(schema.model_validate(args))

    def handlers(self):
        return {"admin_status": (EmptyExportArgs, self.status),
                "start_export": (StartExportArgs, self.start),
                "export_status": (ExportArgs, self.job_status),
                "export_download": (ExportArgs, self.download),
                "cancel_export": (ExportArgs, self.cancel),
                "delete_export": (ExportArgs, self.delete)}

    async def status(self, args):
        self._cleanup()
        return {"workflow": "zip_export", "version": __version__, "time": now_utc(),
            "available": self.sources.available, "demo": self.demo, "history_hours": 24,
            "exports": [dict(j) for j in reversed(list(self.jobs.values()))],
            "limits": {"source_bytes": self.max_source_bytes, "export_bytes": self.max_export_bytes,
                       "retention_hours": 24}}

    def _job(self, args):
        if args.export_id not in self.jobs:
            raise BrokerError("EXPORT_NOT_FOUND")
        return self.jobs[args.export_id]

    async def job_status(self, args):
        return dict(self._job(args))

    async def start(self, args):
        if self._task is not None and not self._task.done():
            raise BrokerError("EXPORT_BUSY")
        if not self.sources.available:
            raise BrokerError("SOURCE_UNAVAILABLE")
        self._cleanup(remove_terminal=True)
        self._disk_check()
        export_id = "export_" + secrets.token_hex(16)
        job = {"export_id": export_id, "status": "collecting", "started_at": now_utc(),
               "finished_at": None, "history_hours": args.history_hours, "demo": self.demo,
               "completed_sources": 0, "current_source": None, "bytes": 0, "issues": 0,
               "filename": self._filename(export_id)}
        self.jobs[export_id] = job
        self._task = asyncio.create_task(self._build(job), name="diagnostic-zip")
        return dict(job)

    async def download(self, args):
        self._cleanup()
        job = self._job(args)
        if job["status"] != "ready":
            raise BrokerError("EXPORT_NOT_READY")
        path = self.directory / (args.export_id + ".zip")
        if not path.is_file() or path.is_symlink():
            raise BrokerError("EXPORT_NOT_FOUND")
        return dict(job)

    async def cancel(self, args):
        job = self._job(args)
        if job["status"] == "collecting" and self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            # A task cancelled before its first step never enters _build/finally.
            job.update(status="cancelled", finished_at=now_utc(), current_source=None)
        return dict(job)

    async def delete(self, args):
        job = self._job(args)
        if job["status"] == "collecting":
            raise BrokerError("EXPORT_BUSY")
        (self.directory / (args.export_id + ".zip")).unlink(missing_ok=True)
        self.jobs.pop(args.export_id)
        return {"deleted": True}

    def _disk_check(self):
        if shutil.disk_usage(self.directory).free < self.min_free_bytes:
            raise BrokerError("DISK_LOW")

    def _write(self, target, body: bytes):
        if self._total_bytes + len(body) > self.max_export_bytes:
            raise BrokerError("EXPORT_SIZE_LIMIT")
        if self._bytes_since_disk_check >= 256 * 1024:
            self._disk_check()
            self._bytes_since_disk_check = 0
        target.write(body)
        self._total_bytes += len(body)
        self._bytes_since_disk_check += len(body)

    async def _json_source(self, archive, job, records, label, read, *, interval=None):
        job["current_source"] = label
        record = {"source": label, "file": label + ".json", "status": "ok",
                  "observed_at": now_utc(), "bytes": 0, "sha256": None}
        if interval:
            record.update(interval)
            record["coverage"] = "recorder_retention_and_exclusions_unknown"
        raw = None
        try:
            self._disk_check()
            raw = await read()
            safe = self.sanitizer.json(raw)
            body = (json.dumps(safe, ensure_ascii=False, allow_nan=False, indent=2) + "\n").encode()
            if len(body) > self.max_source_bytes:
                raise BrokerError("SOURCE_SIZE_LIMIT")
            if self._total_bytes + len(body) > self.max_export_bytes:
                raise BrokerError("EXPORT_SIZE_LIMIT")
            with archive.open(record["file"], "w", force_zip64=True) as out:
                self._write(out, body)
            record["bytes"] = len(body)
            record["sha256"] = hashlib.sha256(body).hexdigest()
        except BrokerError as error:
            record.update(status="unavailable", reason=error.code, file=None)
        except (ValueError, RecursionError):
            record.update(status="unavailable", reason="UPSTREAM_FORMAT", file=None)
        records.append(record)
        job["completed_sources"] += 1
        job["issues"] += int(record["status"] != "ok")
        await asyncio.sleep(0)
        return raw if record["status"] == "ok" else None

    async def _log_source(self, archive, job, records, source):
        label = "logs/" + source.replace(":", "/")
        job["current_source"] = label
        record = {"source": source, "file": label + ".log", "status": "ok", "bytes": 0,
                  "observed_at": now_utc(), "coverage": "all_retained_entries_requested",
                  "historical_completeness": "unknown", "lines": 0}
        digest = hashlib.sha256()
        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        pending = ""
        inside_pem = False
        received = 0
        stream = self.sources.logs(source)
        with archive.open(record["file"], "w", force_zip64=True) as out:
            def emit(line):
                nonlocal inside_pem
                safe, inside_pem = self.sanitizer.log_line(line, inside_pem)
                body = safe.encode()
                if record["bytes"] + len(body) > self.max_source_bytes:
                    raise BrokerError("SOURCE_SIZE_LIMIT")
                self._write(out, body)
                digest.update(body)
                record["bytes"] += len(body)
                record["lines"] += safe.count("\n")
            try:
                async for chunk in stream:
                    received += len(chunk)
                    if received > self.max_source_bytes:
                        raise BrokerError("SOURCE_SIZE_LIMIT")
                    pending += decoder.decode(chunk)
                    parts = pending.splitlines(keepends=True)
                    pending = ""
                    if parts and not parts[-1].endswith("\n"):
                        pending = parts.pop()
                    if len(pending) > MAX_LINE_CHARS or any(len(line) > MAX_LINE_CHARS for line in parts):
                        raise BrokerError("LOG_RECORD_TOO_LARGE")
                    for line in parts:
                        emit(line)
                    job["bytes"] = self._total_bytes
                    await asyncio.sleep(0)
                pending += decoder.decode(b"", final=True)
                if pending:
                    emit(pending)
            except BrokerError as error:
                record.update(status="partial" if record["bytes"] else "unavailable", reason=error.code)
            finally:
                await stream.aclose()
        record["sha256"] = digest.hexdigest()
        records.append(record)
        job["completed_sources"] += 1
        job["issues"] += int(record["status"] != "ok")

    async def _build(self, job):
        export_id = job["export_id"]
        partial = self.directory / (export_id + ".partial")
        final = self.directory / (export_id + ".zip")
        self._total_bytes = 0
        self._bytes_since_disk_check = 0
        records = []
        try:
            # Exclusive create, no credential or raw staging files on disk.
            with partial.open("xb") as file, zipfile.ZipFile(file, "w", compression=zipfile.ZIP_DEFLATED,
                    compresslevel=1, allowZip64=True) as archive:
                partial.chmod(0o640)
                addons = None
                for label in JSON_SOURCES:
                    raw = await self._json_source(archive, job, records, label,
                        lambda label=label: self.sources.snapshot(label))
                    if label == "addons/catalog":
                        addons = raw
                integrations = None
                for label in REGISTRY_COMMANDS:
                    raw = await self._json_source(archive, job, records, "registries/" + label,
                        lambda label=label: self.sources.registry(label))
                    if label == "integrations":
                        integrations = raw
                if isinstance(addons, dict):
                    addons = addons.get("addons", [])
                slugs = sorted({a["slug"] for a in addons or [] if isinstance(a, dict)
                    and isinstance(a.get("slug"), str) and re.fullmatch(SLUG_PATTERN, a["slug"])
                    and a["slug"] != "self" and a.get("installed", True)})
                for slug in slugs:
                    for kind in ("info", "stats"):
                        await self._json_source(archive, job, records, f"addons/{slug}/{kind}",
                            lambda slug=slug, kind=kind: self.sources.addon(slug, kind))
                for entry in integrations or []:
                    entry_id = entry.get("entry_id") if isinstance(entry, dict) else None
                    if isinstance(entry_id, str) and re.fullmatch(ENTRY_ID_PATTERN, entry_id):
                        await self._json_source(archive, job, records, f"integrations/{entry_id}",
                            lambda entry_id=entry_id: self.sources.integration(entry_id))
                end = datetime.fromisoformat(job["started_at"].replace("Z", "+00:00"))
                start = end - timedelta(hours=job["history_hours"])
                for kind in ("history", "logbook"):
                    for hour in range(job["history_hours"]):
                        a = (start + timedelta(hours=hour)).isoformat()
                        b = (start + timedelta(hours=hour + 1)).isoformat()
                        await self._json_source(archive, job, records, f"{kind}/{hour:02d}",
                            lambda kind=kind, a=a, b=b: self.sources.history(kind, a, b),
                            interval={"from": a, "to": b})
                for source in (*LOG_SOURCES, *("addon:" + slug for slug in slugs)):
                    await self._log_source(archive, job, records, source)
                finished_at = now_utc()
                manifest = {"schema_version": 1, "product_version": __version__, "export_id": export_id,
                    "demo": self.demo, "started_at": job["started_at"], "finished_at": finished_at,
                    "history": {"from": start.isoformat(), "to": end.isoformat(), "hours": 24,
                        "coverage": "recorder_retention_and_exclusions_unknown"},
                    "log_scope": "all_retained_entries_exposed_by_supervisor",
                    "limits": {"source_bytes": self.max_source_bytes, "export_bytes": self.max_export_bytes},
                    "redacted": True, "sources": records,
                    "notes": ["This is a diagnostic bundle, not a Home Assistant backup.",
                        "Snapshots were read at different times; the bundle is not an atomic snapshot.",
                        "Purged logs and Recorder exclusions cannot be recovered.",
                        "No /config files, .storage, credentials, database or media are copied.",
                        "Known secrets are removed; review the ZIP before sharing."]}
                archive.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
                archive.writestr("README.txt", self._readme(manifest))
            self._disk_check()
            os.replace(partial, final)
            job.update(status="ready", finished_at=finished_at, current_source=None,
                       bytes=final.stat().st_size)
            self._cleanup()
        except asyncio.CancelledError:
            job.update(status="cancelled", finished_at=now_utc(), current_source=None)
        except Exception as error:
            job.update(status="failed", finished_at=now_utc(), current_source=None,
                       error=error.code if isinstance(error, BrokerError) else "EXPORT_FAILED")
        finally:
            partial.unlink(missing_ok=True)

    @staticmethod
    def _readme(manifest):
        issues = [s for s in manifest["sources"] if s["status"] != "ok"]
        return ("HA-Diagnostics — диагностический ZIP\n"
            + ("ДЕМОНСТРАЦИОННЫЕ ДАННЫЕ, не реальная установка Home Assistant.\n" if manifest["demo"] else "")
            + f"Версия: {__version__}\nИстория и журнал событий: последние 24 часа.\n"
            + "Логи: все записи, сохранённые и доступные через Supervisor на момент чтения.\n"
            + "manifest.json содержит интервалы, результаты чтений, размеры и SHA-256 файлов.\n"
            + f"Недоступных или частично собранных источников: {len(issues)}.\n"
            + "Данные Recorder могут отсутствовать из-за исключений или удаления истории.\n"
            + "Архив не является резервной копией HA. Конфигурационные файлы, базы и секреты не копируются.\n"
            + "Распознаваемые секреты удалены; проверьте содержимое перед передачей другим людям.\n\n"
            + "\n".join(f"{s['source']}: {s['status']} ({s.get('reason', '')})" for s in issues) + "\n")

    async def close(self):
        if self._task and not self._task.done():
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        await self.sources.close()

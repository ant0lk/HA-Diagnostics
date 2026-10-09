"""Manual and daily ZIP creation, with explicit gaps and no raw staging files."""
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
from zoneinfo import ZoneInfo

from pydantic import BaseModel, ConfigDict, Field

from . import __version__
from .broker import BrokerError, SLUG_PATTERN
from .export_sources import (DEVICE_ID_PATTERN, ENTRY_ID_PATTERN, JSON_SOURCES, LOG_SOURCES,
    REGISTRY_COMMANDS, WS_SOURCES, MAX_TRACE_READS, MAX_DEVICE_READS, MAX_STATISTIC_IDS, SourceResult, bounded_id)
from .export_insights import (LogCoverage, history_coverage, network_context, overview_section,
                              overview_text, comparison_record, comparison_key, pick)
from .export_schedule import ExportSchedule, ScheduleArgs, ScheduleStore
from .redaction import IDENTIFIER_KEY, SECRET_KEY, Redactor

EXPORT_ID = r"^export_[a-f0-9]{32}$"
MAX_SOURCE_BYTES = 128 * 1024 * 1024
MAX_EXPORT_BYTES = 512 * 1024 * 1024
MIN_FREE_BYTES = 100 * 1024 * 1024
MAX_LINE_CHARS = 1024 * 1024
EXPORT_LIMITS = {"manual": 3, "automatic": 7}
STRUCTURE_FILE = "ARCHIVE_STRUCTURE.txt"
EXCLUDED_KEYS = {"options", "schema", "latitude", "longitude", "gps", "location",
                 "config_dir", "external_url", "internal_url", "data_path"}
PEM_BEGIN = re.compile(r"-----BEGIN [^-]*(?:PRIVATE KEY|CERTIFICATE)-----")
PEM_END = re.compile(r"-----END [^-]+-----")
CONFIG_SECRET_KEY = re.compile(r"(?:password|passwd|secret|token|api[_-]?key|credential|cookie|authorization|"
    r"pairing[_-]?code|setup[_-]?code|pin[_-]?code|qr[_-]?code|bindkey|linkkey|network[_-]?key|"
    r"private[_-]?key|encryption[_-]?key|auth[_-]?key|certfile|keyfile|certificate|"
    r"^(?:key|psk|pin|code|pass|auth|authentication|username|user|login)$)", re.I)
ADDON_CONFIG_FIELDS = {"slug", "name", "version", "state", "options", "schema", "network", "host_network",
    "network_description", "boot", "boot_config", "startup", "auto_update", "watchdog", "protected",
    "ingress", "ingress_port", "ingress_panel", "audio_input", "audio_output", "devices", "uart", "usb",
    "gpio", "video", "apparmor", "privileged", "full_access", "hassio_api", "hassio_role", "homeassistant_api",
    "services_role", "system_managed", "system_managed_config_entry", "webui", "url"}


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
    """Keep diagnostic fields and redact configuration before writing it.

    Native registry IDs are retained for joins; human labels, network addresses
    and entity IDs use the existing stable local pseudonyms. No keys are copied
    from authentication stores, the Recorder database or this app's private files.
    """
    def __init__(self, redactor: Redactor, scrub_known_secret):
        self.redactor = redactor
        self.scrub_known_secret = scrub_known_secret

    def text(self, value: str) -> str:
        return self.redactor.clean_text(self.scrub_known_secret(value), max_chars=None)

    @staticmethod
    def _secret_schema(descriptor):
        return isinstance(descriptor, str) and bool(re.search(r"password|secret|token|credential", descriptor, re.I))

    def json(self, value, *, configuration=False):
        count = 0
        # Secret-typed addon options may have arbitrary names. Collect their
        # values first so repeated copies inside descriptions are also removed.
        secrets_found = set()
        inspected = 0
        def inspect(item, descriptor=None, depth=0, sensitive=False):
            nonlocal inspected
            inspected += 1
            if depth > 64 or inspected > 1_000_000:
                raise BrokerError("UPSTREAM_LIMIT")
            sensitive = sensitive or self._secret_schema(descriptor)
            if isinstance(item, str) and sensitive and item:
                secrets_found.add(item)
                if len(secrets_found) > 1024:
                    raise BrokerError("UPSTREAM_LIMIT")
            elif isinstance(item, list):
                child_schema = descriptor[0] if isinstance(descriptor, list) and descriptor else None
                for child in item:
                    inspect(child, child_schema, depth + 1, sensitive)
            elif isinstance(item, dict):
                for key, raw in item.items():
                    if not isinstance(key, str):
                        raise BrokerError("UPSTREAM_FORMAT")
                    if key == "schema":
                        continue
                    child_schema = descriptor.get(key) if isinstance(descriptor, dict) else None
                    if key == "options" and isinstance(item.get("schema"), (dict, list)):
                        child_schema = item["schema"]
                    inspect(raw, child_schema, depth + 1, sensitive or bool(CONFIG_SECRET_KEY.search(key)))
        if configuration:
            inspect(value)
        replacements = sorted((v for v in secrets_found if len(v) >= 4), key=len, reverse=True)
        def clean(text):
            if text in secrets_found:
                return "[REDACTED]"
            for secret in replacements:
                text = text.replace(secret, "[REDACTED]")
            return self.text(text)
        def walk(item, depth=0, descriptor=None, schema_only=False):
            nonlocal count
            count += 1
            if depth > 64 or count > 1_000_000:
                raise BrokerError("UPSTREAM_LIMIT")
            if item is None or isinstance(item, (bool, int, float)):
                return item
            if isinstance(item, str):
                return clean(item)
            if isinstance(item, list):
                child_schema = descriptor[0] if isinstance(descriptor, list) and descriptor else None
                return [walk(v, depth + 1, child_schema, schema_only) for v in item]
            if isinstance(item, dict):
                result = {}
                for key, raw in item.items():
                    if not isinstance(key, str) or len(key) > 200:
                        raise BrokerError("UPSTREAM_FORMAT")
                    safe_key = self.text(key)
                    child_schema = descriptor.get(key) if isinstance(descriptor, dict) else None
                    excluded = key.lower() in EXCLUDED_KEYS and not (configuration and key.lower() in
                        {"options", "schema", "config_dir", "data_path", "external_url", "internal_url"})
                    if not schema_only and (SECRET_KEY.search(key) or excluded or
                            configuration and (CONFIG_SECRET_KEY.search(key) or self._secret_schema(child_schema))):
                        result[safe_key] = "[REDACTED]"
                    elif configuration and key == "schema":
                        result[safe_key] = walk(raw, depth + 1, schema_only=True)
                    elif key in {"id", "device_id", "entry_id", "config_entry_id"}:
                        # A device's registry id and entity.device_id must join.
                        result[safe_key] = walk(raw, depth + 1)
                    elif not schema_only and (IDENTIFIER_KEY.fullmatch(key) or
                            configuration and key in {"title", "alias"}) and isinstance(raw, str) and raw:
                        kind = "ENTITY" if key == "entity_id" else "IDENTIFIER"
                        # Addresses inside strings are normalized by Redactor.
                        result[safe_key] = clean(raw) if key in {"ip", "ip_address", "mac", "mac_address", "address"} else self.redactor.alias(kind, raw)
                    else:
                        if configuration and key == "options" and isinstance(item.get("schema"), (dict, list)):
                            child_schema = item["schema"]
                        result[safe_key] = walk(raw, depth + 1, child_schema, schema_only)
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
                 min_free_bytes=MIN_FREE_BYTES, schedule_path=None, clock=None):
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
        self._scheduler_task = None
        self._schedule_changed = asyncio.Event()
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._timezone_observed = False
        self._schedule_error = None
        self.schedule_store = ScheduleStore(schedule_path or
            self.directory.parent / "private" / "export-schedule.json")
        try:
            self.schedule = self.schedule_store.read()
        except (OSError, ValueError):
            # A damaged saved setting must not re-enable a disabled schedule.
            self.schedule = ExportSchedule(enabled=False)
            self._schedule_error = "SCHEDULE_SETTINGS_INVALID"
        self._total_bytes = 0
        self._bytes_since_disk_check = 0
        self._overview = {}
        self._comparison = {}
        self._versions = {}
        self._inventories = {}
        self._restore()
        if self.schedule.last_run_status == "collecting":
            # Retry an interrupted unfinished build after a restart. Finished
            # ZIPs, including those later deleted by the owner, keep their mark.
            try:
                if self.jobs.get(self.schedule.last_export_id, {}).get("status") == "ready":
                    self._save_schedule(last_run_status="ready")
                else:
                    self._save_schedule(last_run_date=None, last_export_id=None, last_run_status=None)
            except BrokerError:
                self._schedule_error = "SCHEDULE_SAVE_FAILED"

    def _restore(self):
        # Resume downloads of finished exports after a worker restart.
        for path in sorted(self.directory.glob("export_*.zip"), key=lambda p: p.lstat().st_mtime):
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
                kind = manifest.get("kind", "manual")
                if kind not in EXPORT_LIMITS:
                    continue
                for field in ("started_at", "finished_at"):
                    parsed = datetime.fromisoformat(manifest[field].replace("Z", "+00:00"))
                    if parsed.tzinfo is None:
                        raise ValueError("INVALID_EXPORT_TIMESTAMP")
                self.jobs[export_id] = {"export_id": export_id, "status": "ready",
                    "started_at": manifest["started_at"], "finished_at": manifest["finished_at"],
                    "kind": kind, "scheduled_date": manifest.get("scheduled_date"),
                    "demo": manifest.get("demo", False), "history_hours": 24,
                    "completed_sources": len(manifest["sources"]), "current_source": None,
                    "bytes": path.stat().st_size, "filename": self._filename(export_id),
                    "issues": sum(s["status"] != "ok" for s in manifest["sources"])}
            except (OSError, ValueError, KeyError, TypeError, AttributeError, zipfile.BadZipFile):
                continue
        self._cleanup()

    def _cleanup(self, remove_terminal=False):
        ready = sorted((j for j in self.jobs.values() if j["status"] == "ready"),
                       key=lambda j: j["started_at"], reverse=True)
        keep = set()
        for kind, limit in EXPORT_LIMITS.items():
            keep.update(j["export_id"] for j in [j for j in ready if j["kind"] == kind][:limit])
        for path in self.directory.iterdir():
            if not re.fullmatch(r"export_[a-f0-9]{32}\.(?:zip|partial)", path.name) or path.is_symlink():
                continue
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                continue
            running = self.jobs.get(path.stem, {}).get("status") == "collecting"
            if (not running and path.suffix == ".partial"
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
                "delete_export": (ExportArgs, self.delete),
                "set_export_schedule": (ScheduleArgs, self.set_schedule)}

    async def status(self, args):
        self._cleanup()
        return {"workflow": "zip_export", "version": __version__, "time": now_utc(),
            "available": self.sources.available, "demo": self.demo, "history_hours": 24,
            "exports": [dict(j) for j in sorted(self.jobs.values(),
                key=lambda j: j["started_at"], reverse=True)],
            "schedule": self.schedule_status(),
            "limits": {"source_bytes": self.max_source_bytes, "export_bytes": self.max_export_bytes,
                       "manual_exports": EXPORT_LIMITS["manual"],
                       "automatic_exports": EXPORT_LIMITS["automatic"]}}

    def schedule_status(self):
        return self.schedule.model_dump() | {
            "timezone_origin": "observed_ha_config" if self._timezone_observed else
                "cached_ha_config" if self.schedule.timezone else "unknown",
            "next_run_at": self.schedule.next_run(self._clock()),
            "error": self._schedule_error}

    def _save_schedule(self, **updates):
        schedule = ExportSchedule.model_validate(self.schedule.model_dump() | updates)
        try:
            self.schedule_store.write(schedule)
        except (OSError, ValueError):
            raise BrokerError("SCHEDULE_SAVE_FAILED") from None
        self.schedule = schedule

    async def set_schedule(self, args):
        self._save_schedule(enabled=args.enabled, time=args.time)
        self._schedule_error = None
        self._schedule_changed.set()
        return self.schedule_status()

    def _observe_timezone(self, config):
        zone = config.get("time_zone") if isinstance(config, dict) else None
        if not isinstance(zone, str):
            raise BrokerError("SCHEDULE_TIMEZONE_UNAVAILABLE")
        try:
            ExportSchedule(timezone=zone)
        except ValueError:
            raise BrokerError("SCHEDULE_TIMEZONE_UNAVAILABLE") from None
        if zone != self.schedule.timezone:
            self._save_schedule(timezone=zone)
        self._timezone_observed = True

    async def start_scheduler(self):
        if self._scheduler_task is None or self._scheduler_task.done():
            self._scheduler_task = asyncio.create_task(self._scheduler_loop(), name="daily-diagnostic-zip")

    async def _scheduler_loop(self):
        refresh_at = 0
        while True:
            self._schedule_changed.clear()
            try:
                if self.sources.available and time.monotonic() >= refresh_at and (
                        self._task is None or self._task.done()):
                    refresh_at = time.monotonic() + 300
                    try:
                        self._observe_timezone(await self.sources.snapshot("home_assistant/config"))
                        if self._schedule_error == "SCHEDULE_TIMEZONE_UNAVAILABLE":
                            self._schedule_error = None
                    except BrokerError as error:
                        self._schedule_error = error.code if error.code == "SCHEDULE_SAVE_FAILED" else "SCHEDULE_TIMEZONE_UNAVAILABLE"
                await self.run_scheduled()
            except BrokerError as error:
                self._schedule_error = error.code
            except Exception:
                self._schedule_error = "SCHEDULE_FAILED"
            try:
                await asyncio.wait_for(self._schedule_changed.wait(), timeout=30)
            except asyncio.TimeoutError:
                pass

    async def run_scheduled(self):
        if not self.schedule.enabled or not self.schedule.timezone:
            return None
        now = self._clock()
        day = now.astimezone(ZoneInfo(self.schedule.timezone)).date()
        if self.schedule.last_run_date and self.schedule.last_run_date >= day.isoformat():
            return None
        if now < self.schedule.due_at(day) or (self._task is not None and not self._task.done()):
            return None
        # Ready archives also prevent a duplicate if settings were restored
        # from an older copy. Deleted ZIPs never clear the persistent run mark.
        if any(j["kind"] == "automatic" and j.get("scheduled_date") == day.isoformat()
               for j in self.jobs.values()):
            self._save_schedule(last_run_date=day.isoformat(), last_run_status="ready")
            return None
        result = await self._start(StartExportArgs(), kind="automatic", scheduled_date=day.isoformat())
        self._schedule_error = None
        return result

    def _job(self, args):
        if args.export_id not in self.jobs:
            raise BrokerError("EXPORT_NOT_FOUND")
        return self.jobs[args.export_id]

    async def job_status(self, args):
        return dict(self._job(args))

    async def start(self, args):
        return await self._start(args, kind="manual")

    async def _start(self, args, *, kind, scheduled_date=None):
        if self._task is not None and not self._task.done():
            raise BrokerError("EXPORT_BUSY")
        if not self.sources.available:
            raise BrokerError("SOURCE_UNAVAILABLE")
        self._cleanup(remove_terminal=True)
        self._disk_check()
        export_id = "export_" + secrets.token_hex(16)
        if kind == "automatic":
            # Persist before starting, so a restart cannot create a second ZIP
            # for this local date. A failed/cancelled attempt is shown in the UI.
            self._save_schedule(last_run_date=scheduled_date, last_export_id=export_id,
                                last_run_status="collecting")
        job = {"export_id": export_id, "status": "collecting",
               "started_at": self._clock().astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
               "kind": kind, "scheduled_date": scheduled_date,
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
            if job["kind"] == "automatic":
                self._save_schedule(last_run_status="cancelled")
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

    async def _json_source(self, archive, job, records, label, read, *, interval=None,
                           configuration=False, origin=None):
        job["current_source"] = label
        record = {"source": label, "file": label + ".json", "status": "ok",
                  "observed_at": now_utc(), "bytes": 0, "sha256": None}
        if interval:
            record.update(interval)
            record["coverage"] = "recorder_retention_and_exclusions_unknown"
        if origin:
            record["origin"] = self.sanitizer.text(origin)
        raw = None
        try:
            self._disk_check()
            raw = await read()
            if isinstance(raw, SourceResult):
                record.update(status=raw.status)
                if raw.reason:
                    record["reason"] = raw.reason
                raw = raw.value
            safe = self.sanitizer.json(raw, configuration=configuration)
            body = (json.dumps(safe, ensure_ascii=False, allow_nan=False, indent=2) + "\n").encode()
            if len(body) > self.max_source_bytes:
                raise BrokerError("SOURCE_SIZE_LIMIT")
            if self._total_bytes + len(body) > self.max_export_bytes:
                raise BrokerError("EXPORT_SIZE_LIMIT")
            with archive.open(record["file"], "w", force_zip64=True) as out:
                self._write(out, body)
            record["bytes"] = len(body)
            record["sha256"] = hashlib.sha256(body).hexdigest()
            if interval:
                record["coverage_details"] = history_coverage(raw, label.split("/", 1)[0], self.sanitizer)
            section = overview_section(label, safe)
            if section is not None:
                self._overview[label] = section
            comparison = comparison_record(label, safe, record.get("origin"))
            if comparison:
                key, digest = comparison
                self._comparison[key] = {"sha256": digest, "status": record["status"], "source": label}
                if key.startswith(("system/", "addons/")):
                    self._versions[key] = pick(safe, ("version", "arch", "machine", "board", "repository"))
            if label.startswith("registries/") and isinstance(safe, list):
                id_key = {"entities": "entity_id", "integrations": "entry_id", "areas": "area_id",
                          "floors": "floor_id", "labels": "label_id"}.get(label.split("/")[1], "id")
                ids = sorted({r[id_key] for r in safe if isinstance(r, dict) and isinstance(r.get(id_key), str)})
                self._inventories[label] = {"ids": ids[:4096], "truncated": len(ids) > 4096}
        except BrokerError as error:
            record.update(status="unavailable", reason=error.code, file=None)
        except (ValueError, RecursionError):
            record.update(status="unavailable", reason="UPSTREAM_FORMAT", file=None)
        records.append(record)
        key = comparison_key(label, record.get("origin"))
        if record["file"] is None and key:
            self._comparison[key] = {"sha256": None, "status": "unavailable", "source": label}
        job["completed_sources"] += 1
        job["issues"] += int(record["status"] != "ok")
        await asyncio.sleep(0)
        return raw if record["file"] else None

    async def _text_source(self, archive, job, records, label, text):
        record = {"source": label, "file": label + ".txt", "status": "ok", "observed_at": now_utc(),
                  "bytes": 0, "sha256": None}
        try:
            self._disk_check()
            body = self.sanitizer.text(text).encode()
            if len(body) > self.max_source_bytes:
                raise BrokerError("SOURCE_SIZE_LIMIT")
            if self._total_bytes + len(body) > self.max_export_bytes:
                raise BrokerError("EXPORT_SIZE_LIMIT")
            with archive.open(record["file"], "w", force_zip64=True) as out:
                self._write(out, body)
            record.update(bytes=len(body), sha256=hashlib.sha256(body).hexdigest())
        except (BrokerError, ValueError) as error:
            record.update(status="unavailable", reason=error.code if isinstance(error, BrokerError) else "UPSTREAM_FORMAT", file=None)
        records.append(record)
        job["completed_sources"] += 1
        job["issues"] += int(record["status"] != "ok")
        await asyncio.sleep(0)

    async def _configuration_sources(self, archive, job, records, slugs):
        try:
            documents = await self.sources.configurations()
        except BrokerError as error:
            from .export_configuration import ConfigurationDocument
            documents = [ConfigurationDocument("configuration/home_assistant/files", "/homeassistant",
                                               error=error.code)]
        for document in documents:
            async def read(document=document):
                if document.error:
                    raise BrokerError(document.error)
                return document.value
            await self._json_source(archive, job, records, document.label, read,
                                    configuration=True, origin="homeassistant_config:" + document.origin)
        async def index():
            return {"schema_version": 1, "scope": "saved_configuration_at_collection_time",
                "sources": [dict(r) for r in records if r["source"].startswith("configuration/")],
                "installed_addons": slugs,
                "saved_file_selection": {"yaml_entrypoint": "configuration.yaml",
                    "optional_yaml": ["automations.yaml", "scripts.yaml", "scenes.yaml", "customize.yaml", "ui-lovelace.yaml"],
                    "storage": ["core.config_entries", "core.config", "lovelace", "lovelace_dashboards",
                        "input_boolean", "input_number", "input_select", "input_text", "input_datetime", "counter",
                        "timer", "schedule", "zone", "person"],
                    "file_bytes_limit": 4 * 1024 * 1024, "total_bytes_limit": 32 * 1024 * 1024,
                    "file_count_limit": 256},
                "home_assistant_overview": {"runtime_configuration": "home_assistant/config.json",
                    "core": "system/core.json", "supervisor": "system/supervisor.json", "os": "system/os.json",
                    "network": "system/network.json", "states": "home_assistant/states.json",
                    "devices": "registries/devices.json", "entities": "registries/entities.json",
                    "integration_status": "registries/integrations.json"},
                "notes": ["Saved files can differ from settings currently loaded by Home Assistant.",
                    "YAML includes are separate documents; secret/env tags and templates are not evaluated.",
                    "Referenced blueprints, YAML dashboards and literal Jinja imports are separate documents.",
                    "Dynamic template imports cannot be resolved without executing templates and are recorded as gaps.",
                    "Missing optional helper/dashboard stores mean no saved store was found.",
                    "Integration data/options come from the saved core.config_entries store, not diagnostics support.",
                    "Addon settings come from Supervisor info; private addon files and external includes are not read.",
                    "Empty addon options may mean no settings or upstream redaction; completeness is not asserted.",
                    "Authentication stores, secrets.yaml, databases, certificates and media are excluded."]}
        await self._json_source(archive, job, records, "configuration/index", index, configuration=True)

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
        coverage = LogCoverage(self.schedule.timezone if self._timezone_observed else None)
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
                if safe:
                    coverage.add(line)
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
        record["coverage_details"] = coverage.as_dict()
        record["received_bytes"] = received
        if record["status"] != "ok":
            record["truncation"] = {"written_bytes": record["bytes"], "written_lines": record["lines"],
                "received_bytes": received, "reason": record["reason"], "last_written_timestamp_utc": coverage.last}
        records.append(record)
        job["completed_sources"] += 1
        job["issues"] += int(record["status"] != "ok")

    async def _expanded_sources(self, archive, job, records, devices, end):
        metadata = None
        for label in WS_SOURCES:
            raw = await self._json_source(archive, job, records, label,
                lambda label=label: self.sources.supplemental(label), configuration=True)
            if label == "statistics/metadata":
                metadata = raw
        for domain in ("automation", "script"):
            traces = await self._json_source(archive, job, records, f"traces/{domain}/list",
                lambda domain=domain: self.sources.traces(domain), configuration=True)
            if traces is None:
                continue
            if not isinstance(traces, list):
                async def invalid():
                    raise BrokerError("UPSTREAM_FORMAT")
                await self._json_source(archive, job, records, f"traces/{domain}/index", invalid)
                continue
            valid = {(t["item_id"], t["run_id"]): t for t in traces if isinstance(t, dict) and
                t.get("domain") == domain and bounded_id(t.get("item_id"), 128) and bounded_id(t.get("run_id"), 128)}
            # Read the most recent retained runs first, with deterministic names independent of upstream IDs.
            ordered = sorted(valid, key=lambda k: str((valid[k].get("timestamp") or {}).get("start", ""))
                if isinstance(valid[k].get("timestamp"), dict) else "", reverse=True)
            selected = ordered[:MAX_TRACE_READS]
            index = []
            for number, (item_id, run_id) in enumerate(selected, 1):
                label = f"traces/{domain}/{number:04d}"
                await self._json_source(archive, job, records, label,
                    lambda domain=domain, item_id=item_id, run_id=run_id: self.sources.trace(domain, item_id, run_id),
                    configuration=True)
                index.append({"item_id": item_id, "run_id": run_id, "file": records[-1]["file"],
                              "status": records[-1]["status"], "reason": records[-1].get("reason")})
            value = {"domain": domain, "retained_runs": len(traces), "valid_unique_runs": len(valid),
                "read_limit": MAX_TRACE_READS, "selected_runs": index, "omitted_runs": len(ordered) - len(selected),
                "invalid_runs": len(traces) - len(valid), "coverage": "retained_traces_only_not_24h_complete"}
            limited = len(ordered) > MAX_TRACE_READS or len(traces) != len(valid)
            async def trace_index(value=value, limited=limited):
                return SourceResult(value, "partial", "TRACE_SELECTION_LIMIT_OR_FORMAT") if limited else value
            await self._json_source(archive, job, records, f"traces/{domain}/index", trace_index, configuration=True)

        pairs = sorted({(entry_id, device["id"]) for device in devices or [] if isinstance(device, dict) and
            isinstance(device.get("id"), str) and re.fullmatch(DEVICE_ID_PATTERN, device["id"]) and
            isinstance(device.get("config_entries"), list) for entry_id in device["config_entries"]
            if isinstance(entry_id, str) and re.fullmatch(ENTRY_ID_PATTERN, entry_id)})
        index = []
        for entry_id, device_id in pairs[:MAX_DEVICE_READS]:
            label = f"devices/{device_id}/{entry_id}"
            await self._json_source(archive, job, records, label,
                lambda entry_id=entry_id, device_id=device_id: self.sources.device(entry_id, device_id), configuration=True)
            index.append({"entry_id": entry_id, "device_id": device_id, "file": records[-1]["file"],
                          "status": records[-1]["status"], "reason": records[-1].get("reason")})
        value = {"pairs": index, "available_pairs": len(pairs), "read_limit": MAX_DEVICE_READS,
                 "registry_available": devices is not None, "omitted_pairs": max(0, len(pairs) - MAX_DEVICE_READS)}
        async def device_index():
            return SourceResult(value, "partial", "DEVICE_SELECTION_LIMIT") if len(pairs) > MAX_DEVICE_READS else value
        await self._json_source(archive, job, records, "devices/index", device_index)

        rows = metadata if isinstance(metadata, list) else []
        ids = list(dict.fromkeys(row["statistic_id"] for row in sorted((r for r in rows if isinstance(r, dict)),
            key=lambda r: (not r.get("has_sum", False), str(r.get("statistic_id", ""))))
            if bounded_id(row.get("statistic_id"))))
        selected = ids[:MAX_STATISTIC_IDS]
        start = end - timedelta(days=7)
        selection = {"selected_ids": selected, "available_ids": len(ids), "limit": MAX_STATISTIC_IDS,
                     "omitted_ids": max(0, len(ids) - len(selected)), "metadata_available": metadata is not None,
                     "from": start.isoformat(), "to": end.isoformat(), "period": "day",
                     "selection": "sum_statistics_first_then_identifier", "retention_and_exclusions": "unknown"}
        async def statistics_selection():
            return SourceResult(selection, "partial", "STATISTIC_SELECTION_LIMIT") if len(ids) > len(selected) else selection
        await self._json_source(archive, job, records, "statistics/selection", statistics_selection)
        if selected:
            async def statistics():
                value = await self.sources.statistics(selected, start.isoformat(), end.isoformat())
                return {"from": start.isoformat(), "to": end.isoformat(), "period": "day", "statistics": value}
            await self._json_source(archive, job, records, "statistics/last_7_days", statistics)

    def _previous_snapshot(self, job):
        candidates = sorted((j for j in self.jobs.values() if j["status"] == "ready" and
            j.get("demo", False) == self.demo and j["started_at"] <= job["started_at"]),
            key=lambda j: j["started_at"], reverse=True)
        if not candidates:
            return {"status": "no_previous_archive"}, None
        previous = candidates[0]
        info = {"export_id": previous["export_id"], "started_at": previous["started_at"], "status": "available"}
        path = self.directory / (previous["export_id"] + ".zip")
        try:
            if path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode) or path.lstat().st_nlink != 1:
                raise ValueError()
            with zipfile.ZipFile(path) as bundle:
                total = 0
                def read(name):
                    nonlocal total
                    entry = bundle.getinfo(name)
                    total += entry.file_size
                    if entry.file_size > 4 * 1024 * 1024 or total > 32 * 1024 * 1024:
                        raise ValueError()
                    return json.loads(bundle.read(entry))
                if "comparison/snapshot.json" in bundle.namelist():
                    value = read("comparison/snapshot.json")
                    if value.get("schema_version") != 1 or not isinstance(value.get("fingerprints"), dict):
                        raise ValueError()
                    if not all(isinstance(key, str) and isinstance(row, dict) and row.get("status") in {"ok", "partial", "unavailable"}
                            and (row.get("sha256") is None or isinstance(row["sha256"], str) and re.fullmatch(r"[a-f0-9]{64}", row["sha256"]))
                            for key, row in value["fingerprints"].items()):
                        raise ValueError()
                    if not isinstance(value.get("versions", {}), dict) or not isinstance(value.get("inventories", {}), dict):
                        raise ValueError()
                    for row in value.get("inventories", {}).values():
                        if not isinstance(row, dict) or not isinstance(row.get("ids"), list) or not all(isinstance(i, str) for i in row["ids"]):
                            raise ValueError()
                    if value.get("key_ref") != self.sanitizer.redactor.alias("KEY_CHECK", "snapshot"):
                        return info | {"status": "redaction_key_changed"}, None
                    return info, value
                # Alpha 4 archives are supported; read only their already sanitized bounded JSON entries.
                manifest = read("manifest.json")
                snapshot = {"fingerprints": {}, "versions": {}, "inventories": {}}
                for record in manifest["sources"]:
                    label, filename = record.get("source", ""), record.get("file")
                    if not isinstance(label, str) or not label.startswith(("configuration/", "registries/", "system/", "addons/")):
                        continue
                    key = comparison_key(label, record.get("origin"))
                    if key is None:
                        continue
                    if not filename or record.get("status") != "ok":
                        if key:
                            snapshot["fingerprints"][key] = {"sha256": None, "status": "unavailable", "source": label}
                        continue
                    safe = read(filename)
                    comparison = comparison_record(label, safe, record.get("origin"))
                    if comparison:
                        key, digest = comparison
                        snapshot["fingerprints"][key] = {"sha256": digest, "status": "ok", "source": label}
                        if key.startswith(("system/", "addons/")):
                            snapshot["versions"][key] = pick(safe, ("version", "arch", "machine", "board", "repository"))
                return info | {"basis": "sanitized_alpha4_files", "identifier_key_continuity": "unknown"}, snapshot
        except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError, RuntimeError, zipfile.BadZipFile):
            return info | {"status": "previous_archive_unreadable_or_limit"}, None

    async def _summary_sources(self, archive, job, records):
        overview = {"schema_version": 1, "observed_at": job["started_at"], "sections": self._overview,
            "source_status": [dict(r) for r in records if r["source"] in self._overview or r["source"] in
                {"system/host", "system/resources", "system/hardware", "system/network", "system/health"}],
            "notes": ["Sources were read at different times. Missing characteristics are unknown.",
                      "Kernel-visible totals in a VM describe the guest; container limits are separate."]}
        async def read_overview():
            return overview
        await self._json_source(archive, job, records, "system/overview", read_overview)
        await self._text_source(archive, job, records, "system/overview", overview_text(overview))
        # Copy before writing the derived sections: comparison data never compares itself.
        snapshot = {"schema_version": 1, "key_ref": self.sanitizer.redactor.alias("KEY_CHECK", "snapshot"),
            "fingerprints": dict(self._comparison), "versions": dict(self._versions),
            "inventories": dict(self._inventories), "source_status": {r["source"]: r["status"] for r in records}}
        previous, baseline = self._previous_snapshot(job)
        changes, inventory_changes = [], {}
        if baseline is not None:
            old = baseline["fingerprints"]
            statuses = snapshot["source_status"]
            config_complete = all(r["status"] == "ok" for r in records if r["source"].startswith("configuration/"))
            for key in sorted(set(old) | set(snapshot["fingerprints"])):
                before, after = old.get(key), snapshot["fingerprints"].get(key)
                if before and after and before.get("status") == after.get("status") == "ok":
                    if before.get("sha256") == after.get("sha256"):
                        continue
                    kind = "changed"
                elif after and after.get("status") != "ok" or before and before.get("status") != "ok":
                    kind = "not_comparable_source_unavailable"
                elif before and not after:
                    enumerated = config_complete if key.startswith("configuration:") else (
                        key.startswith("addons/") and statuses.get("addons/catalog") == "ok")
                    kind = "removed" if enumerated else "not_observed_enumeration_unavailable"
                else:
                    kind = "newly_observed"
                change = {"source": key, "kind": kind}
                if key in snapshot["versions"] or key in baseline.get("versions", {}):
                    change.update(before=baseline.get("versions", {}).get(key), after=snapshot["versions"].get(key))
                changes.append(change)
            for key, current in snapshot["inventories"].items():
                prior = baseline.get("inventories", {}).get(key)
                if prior and not prior.get("truncated") and not current["truncated"]:
                    added, removed = set(current["ids"]) - set(prior["ids"]), set(prior["ids"]) - set(current["ids"])
                    if added or removed:
                        inventory_changes[key] = {"added": sorted(added), "removed": sorted(removed)}
        diff = {"schema_version": 1, "previous": previous, "current_export_id": job["export_id"],
                "interval": {"from": previous.get("started_at"), "to": job["started_at"]},
                "changes": changes, "inventory_changes": inventory_changes,
                "notes": ["Comparison shows differences between observations, not the exact time or cause of change.",
                          "Volatile stats, states, logs and available-update versions are excluded.",
                          "Secrets are redacted before comparison; changes to hidden secrets are not observable."]}
        async def read_snapshot():
            return snapshot
        async def read_diff():
            return diff
        await self._json_source(archive, job, records, "comparison/snapshot", read_snapshot)
        await self._json_source(archive, job, records, "comparison/changes", read_diff)
        await self._text_source(archive, job, records, "comparison/changes",
            "HA-Diagnostics — изменения относительно предыдущего архива\n" + json.dumps(diff, ensure_ascii=False, indent=2) + "\n")

    async def _build(self, job):
        export_id = job["export_id"]
        partial = self.directory / (export_id + ".partial")
        final = self.directory / (export_id + ".zip")
        self._total_bytes = 0
        self._bytes_since_disk_check = 0
        self._overview, self._comparison, self._versions, self._inventories = {}, {}, {}, {}
        records = []
        try:
            # Exclusive create, no credential or raw staging files on disk.
            with partial.open("xb") as file, zipfile.ZipFile(file, "w", compression=zipfile.ZIP_DEFLATED,
                    compresslevel=1, allowZip64=True) as archive:
                partial.chmod(0o640)
                addons = None
                expected_entities = set()
                raw_network = None
                for label in JSON_SOURCES:
                    raw = await self._json_source(archive, job, records, label,
                        lambda label=label: self.sources.snapshot(label))
                    if label == "addons/catalog":
                        addons = raw
                    if label == "system/network":
                        raw_network = raw
                    if label == "home_assistant/states" and isinstance(raw, list):
                        expected_entities = {self.sanitizer.redactor.alias("ENTITY", row["entity_id"])
                            for row in raw if isinstance(row, dict) and isinstance(row.get("entity_id"), str)}
                    if label == "home_assistant/config" and raw is not None:
                        try:
                            self._observe_timezone(raw)
                        except BrokerError as error:
                            self._schedule_error = error.code
                await self._json_source(archive, job, records, "system/resources", self.sources.resources)
                async def read_network_context():
                    if raw_network is None:
                        raise BrokerError("NETWORK_SOURCE_UNAVAILABLE")
                    value = network_context(raw_network, self.sanitizer.redactor)
                    return SourceResult(value, "partial", "NETWORK_ADDRESS_LIMIT") if value["omitted_addresses"] else value
                await self._json_source(archive, job, records, "system/network_context", read_network_context)
                raw_network = None
                integrations = None
                devices = None
                for label in REGISTRY_COMMANDS:
                    raw = await self._json_source(archive, job, records, "registries/" + label,
                        lambda label=label: self.sources.registry(label))
                    if label == "integrations":
                        integrations = raw
                    if label == "devices":
                        devices = raw
                if isinstance(addons, dict):
                    addons = addons.get("addons", [])
                if not isinstance(addons, list):
                    addons = []
                slugs = sorted({a["slug"] for a in addons or [] if isinstance(a, dict)
                    and isinstance(a.get("slug"), str) and re.fullmatch(SLUG_PATTERN, a["slug"])
                    and a["slug"] != "self" and a.get("installed", True)})
                for slug in slugs:
                    for kind in ("info", "stats"):
                        raw = await self._json_source(archive, job, records, f"addons/{slug}/{kind}",
                            lambda slug=slug, kind=kind: self.sources.addon(slug, kind))
                        if kind == "info":
                            async def addon_configuration(raw=raw):
                                if not isinstance(raw, dict):
                                    raise BrokerError("ADDON_CONFIGURATION_UNAVAILABLE")
                                return {key: value for key, value in raw.items() if key in ADDON_CONFIG_FIELDS}
                            await self._json_source(archive, job, records, f"configuration/addons/{slug}",
                                addon_configuration, configuration=True, origin=f"supervisor:/addons/{slug}/info")
                await self._configuration_sources(archive, job, records, slugs)
                for entry in integrations or []:
                    entry_id = entry.get("entry_id") if isinstance(entry, dict) else None
                    if isinstance(entry_id, str) and re.fullmatch(ENTRY_ID_PATTERN, entry_id):
                        await self._json_source(archive, job, records, f"integrations/{entry_id}",
                            lambda entry_id=entry_id: self.sources.integration(entry_id))
                end = datetime.fromisoformat(job["started_at"].replace("Z", "+00:00"))
                await self._expanded_sources(archive, job, records, devices, end)
                start = end - timedelta(hours=job["history_hours"])
                for kind in ("history", "logbook"):
                    for hour in range(job["history_hours"]):
                        a = (start + timedelta(hours=hour)).isoformat()
                        b = (start + timedelta(hours=hour + 1)).isoformat()
                        await self._json_source(archive, job, records, f"{kind}/{hour:02d}",
                            lambda kind=kind, a=a, b=b: self.sources.history(kind, a, b),
                            interval={"from": a, "to": b})
                async def read_history_coverage():
                    windows = [r for r in records if re.fullmatch(r"history/\d{2}", r["source"])]
                    returned = {entity for r in windows for entity in r.get("coverage_details", {}).get("entities", {})}
                    missing = sorted(expected_entities - returned)
                    return {"from": start.isoformat(), "to": end.isoformat(), "requested_windows": 24,
                        "successful_windows": sum(r["status"] == "ok" for r in windows),
                        "currently_known_entities": len(expected_entities), "entities_seen_in_history": len(returned),
                        "entities_without_returned_records": missing[:4096], "entity_list_truncated": len(missing) > 4096,
                        "per_window_entity_lists_truncated": any(r.get("coverage_details", {}).get("entity_list_truncated") for r in windows),
                        "notes": ["No returned record does not prove exclusion or absence of events.",
                                  "Recorder purge/retention and exclusions are not inferred from an empty response."]}
                await self._json_source(archive, job, records, "history/coverage", read_history_coverage)
                for source in (*LOG_SOURCES, *("addon:" + slug for slug in slugs)):
                    await self._log_source(archive, job, records, source)
                await self._summary_sources(archive, job, records)
                finished_at = now_utc()
                structure = self._structure(job["filename"],
                    [*archive.namelist(), "manifest.json", "README.txt", STRUCTURE_FILE]).encode("utf-8")
                manifest = {"schema_version": 1, "product_version": __version__, "export_id": export_id,
                    "archive_filename": job["filename"], "kind": job["kind"],
                    "scheduled_date": job["scheduled_date"],
                    "structure": {"file": STRUCTURE_FILE, "bytes": len(structure),
                                  "sha256": hashlib.sha256(structure).hexdigest()},
                    "demo": self.demo, "started_at": job["started_at"], "finished_at": finished_at,
                    "history": {"from": start.isoformat(), "to": end.isoformat(), "hours": 24,
                        "coverage": "recorder_retention_and_exclusions_unknown"},
                    "log_scope": "all_retained_entries_exposed_by_supervisor",
                    "limits": {"source_bytes": self.max_source_bytes, "export_bytes": self.max_export_bytes,
                        "traces_per_domain": MAX_TRACE_READS, "device_diagnostics": MAX_DEVICE_READS,
                        "statistic_ids": MAX_STATISTIC_IDS, "statistics_days": 7, "statistics_period": "day"},
                    "redacted": True, "sources": records,
                    "notes": ["This is a diagnostic bundle, not a Home Assistant backup.",
                        "Snapshots were read at different times; the bundle is not an atomic snapshot.",
                        "Purged logs and Recorder exclusions cannot be recovered.",
                        "Configuration contains sanitized parsed YAML and selected saved UI/integration settings.",
                        "System overview and comparison are derived from the collected sanitized observations.",
                        "Trace and device diagnostics coverage depends on retention, permissions and integration support.",
                        "Statistics contain up to 64 selected series for 7 days, not all retained statistics.",
                        "No background load sampling or event subscription is enabled in this release.",
                        "No raw files, authentication stores, secrets.yaml, databases or media are copied.",
                        "Known secrets are removed; review the ZIP before sharing."]}
                archive.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
                archive.writestr("README.txt", self._readme(manifest))
                archive.writestr(STRUCTURE_FILE, structure)
            self._disk_check()
            os.replace(partial, final)
            job.update(status="ready", finished_at=finished_at, current_source=None,
                       bytes=final.stat().st_size)
            if job["kind"] == "automatic":
                try:
                    self._save_schedule(last_run_status="ready")
                except BrokerError:
                    self._schedule_error = "SCHEDULE_SAVE_FAILED"
            self._cleanup()
        except asyncio.CancelledError:
            job.update(status="cancelled", finished_at=now_utc(), current_source=None)
        except Exception as error:
            job.update(status="failed", finished_at=now_utc(), current_source=None,
                       error=error.code if isinstance(error, BrokerError) else "EXPORT_FAILED")
            if job["kind"] == "automatic":
                self._schedule_error = job["error"]
                try:
                    self._save_schedule(last_run_status="failed")
                except BrokerError:
                    self._schedule_error = "SCHEDULE_SAVE_FAILED"
        finally:
            partial.unlink(missing_ok=True)

    @staticmethod
    def _structure(filename, names):
        tree = {}
        for name in sorted(set(names)):
            node = tree
            for part in name.strip("/").split("/"):
                node = node.setdefault(part, {})
        lines = ["HA-Diagnostics — структура диагностического ZIP", f"Название архива: {filename}",
            "Все папки и файлы, фактически включённые в этот ZIP, перечислены ниже.",
            "manifest.json: результаты чтений, интервалы, пропуски и SHA-256.",
            "README.txt: описание набора. Этот файл: карта содержимого для поиска данных.",
            "Недоступные источники могут отсутствовать в дереве; причины находятся в manifest.json.",
            "", filename]
        def walk(node, prefix=""):
            items = sorted(node.items(), key=lambda item: (not bool(item[1]), item[0]))
            for index, (name, children) in enumerate(items):
                last = index == len(items) - 1
                lines.append(prefix + ("└── " if last else "├── ") + name + ("/" if children else ""))
                if children:
                    walk(children, prefix + ("    " if last else "│   "))
        walk(tree)
        return "\n".join(lines) + "\n"

    @staticmethod
    def _readme(manifest):
        issues = [s for s in manifest["sources"] if s["status"] != "ok"]
        return ("HA-Diagnostics — диагностический ZIP\n"
            + ("ДЕМОНСТРАЦИОННЫЕ ДАННЫЕ, не реальная установка Home Assistant.\n" if manifest["demo"] else "")
            + f"Версия: {__version__}\nИстория и журнал событий: последние 24 часа.\n"
            + f"Название архива: {manifest['archive_filename']}\n"
            + f"Сбор: {'автоматический по расписанию' if manifest['kind'] == 'automatic' else 'ручной'}.\n"
            + "Логи: все записи, сохранённые и доступные через Supervisor на момент чтения.\n"
            + "configuration/: настройки HA, YAML и подключённые файлы, data/options интеграций, опции дополнений.\n"
            + "configuration/index.json: источники настроек, пути, результаты чтения и ограничения.\n"
            + "system/overview.json и .txt: Система / Устройство и окружение — паспорт хоста, версии, ресурсы и дополнения.\n"
            + "system/: System Health, службы хоста, диск, swap, задания и репозитории, признаки сетевых адресов.\n"
            + "traces/: сохранённые трассы автоматизаций и скриптов; devices/: доступная диагностика устройств.\n"
            + "home_assistant/: Repairs, постоянные уведомления и сводка System Log.\n"
            + "statistics/: метаданные, проблемы статистики и до 64 рядов за 7 дней с шагом день.\n"
            + "comparison/: изменения конфигурации, установленных версий и реестров относительно предыдущего ZIP.\n"
            + "history/coverage.json и coverage_details в manifest: наблюдаемое покрытие и границы обрезки.\n"
            + "manifest.json содержит интервалы, результаты чтений, размеры и SHA-256 файлов.\n"
            + f"{STRUCTURE_FILE} содержит название ZIP и полное дерево его папок и файлов.\n"
            + f"Недоступных или частично собранных источников: {len(issues)}.\n"
            + "Данные Recorder могут отсутствовать из-за исключений или удаления истории.\n"
            + "Сохранённая конфигурация может отличаться от загруженной в HA; шаблоны и !secret не вычисляются.\n"
            + "Архив не является резервной копией HA. Сырые файлы, auth-хранилища, базы и secrets.yaml не копируются.\n"
            + "Распознаваемые секреты удалены; проверьте содержимое перед передачей другим людям.\n\n"
            + "\n".join(f"{s['source']}: {s['status']} ({s.get('reason', '')})" for s in issues) + "\n")

    async def close(self):
        if self._scheduler_task and not self._scheduler_task.done():
            self._scheduler_task.cancel()
            await asyncio.gather(self._scheduler_task, return_exceptions=True)
        if self._task and not self._task.done():
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        await self.sources.close()

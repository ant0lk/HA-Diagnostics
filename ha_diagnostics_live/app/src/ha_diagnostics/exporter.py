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
from .export_sources import ENTRY_ID_PATTERN, JSON_SOURCES, LOG_SOURCES, REGISTRY_COMMANDS
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
        except BrokerError as error:
            record.update(status="unavailable", reason=error.code, file=None)
        except (ValueError, RecursionError):
            record.update(status="unavailable", reason="UPSTREAM_FORMAT", file=None)
        records.append(record)
        job["completed_sources"] += 1
        job["issues"] += int(record["status"] != "ok")
        await asyncio.sleep(0)
        return raw if record["status"] == "ok" else None

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
                    if label == "home_assistant/config" and raw is not None:
                        try:
                            self._observe_timezone(raw)
                        except BrokerError as error:
                            self._schedule_error = error.code
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
                    "limits": {"source_bytes": self.max_source_bytes, "export_bytes": self.max_export_bytes},
                    "redacted": True, "sources": records,
                    "notes": ["This is a diagnostic bundle, not a Home Assistant backup.",
                        "Snapshots were read at different times; the bundle is not an atomic snapshot.",
                        "Purged logs and Recorder exclusions cannot be recovered.",
                        "Configuration contains sanitized parsed YAML and selected saved UI/integration settings.",
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

"""Read-only Yandex availability polling and persistent, sanitized observations.

The user API exposes current availability, not a transition feed. Times below
are observation times; gaps and polling uncertainty must travel with the ZIP.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from .broker import BrokerError
from .ipc import _json_loads

API_ORIGIN = "https://api.iot.yandex.net"
DEVICE_ID = r"[A-Za-z0-9_-]{1,200}"
MAX_DEVICES = 1000
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_EVENTS = 30_000
MAX_GAPS = 5000


def stamp(value):
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


class YandexArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    enabled: bool
    poll_seconds: int = Field(default=60, ge=30, le=3600)
    retention_days: int = Field(default=30, ge=1, le=365)
    token: SecretStr | None = None

    @field_validator("token")
    @classmethod
    def valid_token(cls, value):
        if value is not None:
            token = value.get_secret_value()
            if not 16 <= len(token) <= 8192 or not re.fullmatch(r"[A-Za-z0-9._~+/=-]+", token):
                raise ValueError("YANDEX_TOKEN_INVALID")
        return value


class YandexSettings(YandexArgs):
    enabled: bool = False
    session_id: str | None = Field(default=None, pattern=r"^ys_[a-f0-9]{32}$")


class YandexSettingsStore:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.directory.is_symlink() or not self.directory.is_dir():
            raise ValueError("UNSAFE_YANDEX_STORAGE")
        self.path = self.directory / "yandex-settings.json"

    def read(self):
        try:
            fd = os.open(self.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                         | getattr(os, "O_NONBLOCK", 0))
        except FileNotFoundError:
            return YandexSettings()
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if self.path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("UNSAFE_YANDEX_STORAGE")
            body = source.read(16385)
        if len(body) > 16384:
            raise ValueError("YANDEX_SETTINGS_LIMIT")
        settings = YandexSettings.model_validate(_json_loads(body))
        if settings.enabled and (settings.token is None or settings.session_id is None):
            raise ValueError("YANDEX_TOKEN_REQUIRED")
        return settings

    def write(self, settings):
        if self.path.exists() or self.path.is_symlink():
            info = self.path.lstat()
            if self.path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("UNSAFE_YANDEX_STORAGE")
        body = settings.model_dump(mode="json")
        # SecretStr hides the token everywhere except this one private file.
        body["token"] = settings.token.get_secret_value() if settings.token else None
        temporary = self.directory / (".yandex-settings-" + secrets.token_hex(16))
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "wb") as target:
                target.write((json.dumps(body) + "\n").encode())
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary, self.path)
        finally:
            temporary.unlink(missing_ok=True)


class YandexAPI:
    """Two fixed GET resources; no redirects, proxy inheritance or controls."""
    def __init__(self, token, *, transport=None):
        self._token = token
        self.retry_after = 0
        self.client = httpx.AsyncClient(transport=transport, follow_redirects=False,
            trust_env=False, timeout=httpx.Timeout(10), limits=httpx.Limits(max_connections=4))

    async def _get(self, path):
        if path != "/v1.0/user/info" and not re.fullmatch(r"/v1\.0/devices/" + DEVICE_ID, path):
            raise BrokerError("OPERATION_DENIED")
        try:
            async with self.client.stream("GET", API_ORIGIN + path,
                    headers={"Authorization": "Bearer " + self._token}) as response:
                if response.status_code in {401, 403}:
                    raise BrokerError("YANDEX_AUTH_FAILED")
                if response.status_code == 429:
                    raw = response.headers.get("Retry-After", "60")
                    self.retry_after = min(3600, max(60, int(raw) if raw.isdecimal() and len(raw) < 8 else 60))
                    raise BrokerError("YANDEX_RATE_LIMIT")
                if 300 <= response.status_code < 400:
                    raise BrokerError("YANDEX_REDIRECT_DENIED")
                if response.status_code == 404:
                    raise BrokerError("YANDEX_DEVICE_NOT_FOUND")
                if response.status_code != 200:
                    raise BrokerError("YANDEX_API_UNAVAILABLE")
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > MAX_RESPONSE_BYTES:
                        raise BrokerError("YANDEX_RESPONSE_LIMIT")
            value = _json_loads(bytes(body))
            if not isinstance(value, dict) or value.get("status") != "ok":
                raise BrokerError("YANDEX_API_FORMAT")
            return value
        except (httpx.HTTPError, OSError):
            raise BrokerError("YANDEX_NETWORK_ERROR") from None
        except BrokerError:
            raise
        except Exception:
            raise BrokerError("YANDEX_API_FORMAT") from None

    async def devices(self):
        value = await self._get("/v1.0/user/info")
        rows = value.get("devices")
        if not isinstance(rows, list):
            raise BrokerError("YANDEX_API_FORMAT")
        if len(rows) > MAX_DEVICES:
            raise BrokerError("YANDEX_DEVICE_LIMIT")
        seen = set()
        result = []
        for row in rows:
            device_id = row.get("id") if isinstance(row, dict) else None
            if not isinstance(device_id, str) or not re.fullmatch(DEVICE_ID, device_id) or device_id in seen:
                raise BrokerError("YANDEX_API_FORMAT")
            seen.add(device_id)
            # Do not ingest capabilities, scenarios, rooms or household data.
            result.append({"id": device_id,
                "name": row.get("name") if isinstance(row.get("name"), str) else device_id,
                "type": row.get("type") if isinstance(row.get("type"), str) else "unknown"})
        return result

    async def availability(self, device_id):
        if not isinstance(device_id, str) or not re.fullmatch(DEVICE_ID, device_id):
            raise BrokerError("OPERATION_DENIED")
        value = await self._get("/v1.0/devices/" + device_id)
        if value.get("id") != device_id or value.get("state") not in ("online", "offline"):
            raise BrokerError("YANDEX_API_FORMAT")
        return value["state"]

    async def close(self):
        await self.client.aclose()


class AvailabilityStore:
    """Only pseudonymous metadata and availability; no raw API responses."""
    def __init__(self, directory):
        self.path = Path(directory) / "yandex-history.sqlite"
        for path in (self.path, Path(str(self.path) + "-journal")):
            if path.exists() or path.is_symlink():
                info = path.lstat()
                if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError("UNSAFE_YANDEX_STORAGE")
        # Pin the initial regular file before SQLite opens it in a private dir.
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.close(fd)
        self.path.chmod(0o600)
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            PRAGMA journal_mode=DELETE;
            PRAGMA secure_delete=ON;
            CREATE TABLE IF NOT EXISTS devices (
              session_id TEXT, device_ref TEXT, name TEXT, type TEXT, present INTEGER,
              first_seen_at TEXT, last_seen_at TEXT, status TEXT, last_observed_at TEXT,
              last_confirmed_status TEXT, event_id INTEGER,
              PRIMARY KEY(session_id,device_ref));
            CREATE TABLE IF NOT EXISTS events (
              event_id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, device_ref TEXT,
              status TEXT, observed_at TEXT, last_observed_at TEXT,
              previous_observed_at TEXT, previous_status TEXT, kind TEXT, reason TEXT);
            CREATE INDEX IF NOT EXISTS events_device ON events(session_id,device_ref,event_id);
            CREATE TABLE IF NOT EXISTS gaps (
              gap_id INTEGER PRIMARY KEY, from_at TEXT, to_at TEXT, reason TEXT, is_open INTEGER);
            CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY,value TEXT);
        """)

    def meta(self, key):
        row = self.db.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def set_meta(self, key, value):
        self.db.execute("INSERT OR REPLACE INTO metadata VALUES (?,?)", (key, str(value)))

    def observe(self, session, ref, status, at, reason=None):
        row = self.db.execute("SELECT * FROM devices WHERE session_id=? AND device_ref=?", (session, ref)).fetchone()
        if row is None:
            return
        updated = 0
        if row["status"] == status:
            # Compress consecutive observations without claiming exact uptime.
            updated = self.db.execute("UPDATE events SET last_observed_at=? WHERE event_id=? AND session_id=? AND device_ref=? AND status=? AND reason IS ?",
                                     (at, row["event_id"], session, ref, status, reason)).rowcount
        if not updated:
            kind = "gap" if status == "unknown" else "retained_boundary" if row["status"] == status else "initial" if row["status"] is None else \
                "removed" if status == "removed" else "resumed" if row["status"] in {"unknown", "removed"} else "transition"
            cursor = self.db.execute("INSERT INTO events VALUES (NULL,?,?,?,?,?,?,?,?,?)",
                (session, ref, status, at, at, row["last_observed_at"], row["status"], kind, reason))
            self.db.execute("UPDATE devices SET event_id=? WHERE session_id=? AND device_ref=?",
                            (cursor.lastrowid, session, ref))
        self.db.execute("UPDATE devices SET status=?,last_observed_at=?,last_confirmed_status=COALESCE(?,last_confirmed_status) WHERE session_id=? AND device_ref=?",
                        (status, at, status if status in {"online", "offline"} else None, session, ref))

    def inventory(self, session, devices, at):
        known = {r[0] for r in self.db.execute("SELECT device_ref FROM devices WHERE session_id=? AND present=1", (session,))}
        incoming = {d["device_ref"] for d in devices}
        with self.db:
            for ref in known - incoming:
                self.observe(session, ref, "removed", at, "DEVICE_REMOVED_FROM_CATALOG")
                self.db.execute("UPDATE devices SET present=0,last_seen_at=? WHERE session_id=? AND device_ref=?", (at, session, ref))
            for device in devices:
                self.db.execute("""INSERT INTO devices(session_id,device_ref,name,type,present,first_seen_at,last_seen_at)
                    VALUES (?,?,?,?,1,?,?) ON CONFLICT(session_id,device_ref) DO UPDATE SET
                    name=excluded.name,type=excluded.type,present=1,last_seen_at=excluded.last_seen_at""",
                    (session, device["device_ref"], device["name"], device["type"], at, at))

    def gap(self, reason, at):
        with self.db:
            last = self.db.execute("SELECT * FROM gaps ORDER BY gap_id DESC LIMIT 1").fetchone()
            since = self.meta("last_poll_at") or at
            if last and last["reason"] == reason and last["to_at"] == since:
                self.db.execute("UPDATE gaps SET to_at=?,is_open=1 WHERE gap_id=?", (at, last["gap_id"]))
            else:
                self.db.execute("UPDATE gaps SET to_at=?,is_open=0 WHERE is_open=1", (since,))
                self.db.execute("INSERT INTO gaps VALUES (NULL,?,?,?,1)", (since, at, reason))
            for row in self.db.execute("SELECT session_id,device_ref FROM devices WHERE present=1").fetchall():
                self.observe(row["session_id"], row["device_ref"], "unknown", at, reason)
            self.set_meta("last_poll_at", at)

    def finish_poll(self, at, error, complete=True):
        with self.db:
            self.set_meta("last_poll_at", at)
            self.set_meta("last_error", error or "")
            self.db.execute("UPDATE gaps SET to_at=?,is_open=? WHERE is_open=1", (at, int(not complete)))
            if error is None:
                self.set_meta("last_successful_poll_at", at)

    def prune(self, now, retention_days):
        cutoff = stamp(now - timedelta(days=retention_days))
        with self.db:
            self.db.execute("DELETE FROM events WHERE last_observed_at<?", (cutoff,))
            self.db.execute("DELETE FROM gaps WHERE to_at<? AND is_open=0", (cutoff,))
            self.db.execute("DELETE FROM devices WHERE present=0 AND last_seen_at<?", (cutoff,))
            for table, key, limit in (("events", "event_id", MAX_EVENTS), ("gaps", "gap_id", MAX_GAPS)):
                count = self.db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                if count > limit:
                    self.db.execute(f"DELETE FROM {table} WHERE {key} IN (SELECT {key} FROM {table} ORDER BY {key} LIMIT ?)", (count - limit,))
                    self.set_meta("storage_evictions", int(self.meta("storage_evictions") or 0) + count - limit)
            self.db.execute("DELETE FROM devices WHERE present=0 AND NOT EXISTS (SELECT 1 FROM events WHERE events.session_id=devices.session_id AND events.device_ref=devices.device_ref)")
            self.set_meta("retained_from", cutoff)

    def snapshot(self, settings, now):
        self.prune(now, settings.retention_days)
        cutoff = self.meta("retained_from")
        devices = [dict(r) for r in self.db.execute("SELECT * FROM devices ORDER BY session_id,device_ref")]
        for device in devices:
            device.pop("event_id")
            device["present"] = bool(device["present"])
            if device["last_observed_at"] is None:
                device["status"] = "unknown"
                device["freshness"] = "never_observed"
            elif device["present"] and not 0 <= (now - datetime.fromisoformat(device["last_observed_at"].replace("Z", "+00:00"))).total_seconds() <= settings.poll_seconds * 2 + 30:
                device["status"] = "unknown"
                device["freshness"] = "stale"
            else:
                device["freshness"] = "observed"
        events = [dict(r) for r in self.db.execute("SELECT * FROM events ORDER BY event_id")]
        for event in events:
            # Preserve the boundary state, without exporting time outside retention.
            event["started_before_retention"] = event["observed_at"] < cutoff
            if event["started_before_retention"]:
                event["observed_at"] = cutoff
            if event["previous_observed_at"] and event["previous_observed_at"] < cutoff:
                event["previous_observed_at"] = None
            event["change_window"] = {"after": event["previous_observed_at"], "by": event["observed_at"]}
        gaps = [dict(r) for r in self.db.execute("SELECT * FROM gaps ORDER BY gap_id")]
        for gap in gaps:
            gap["from_at"] = max(gap["from_at"], cutoff)
            gap["is_open"] = bool(gap["is_open"])
            if gap["is_open"]:
                gap["to_at"] = stamp(now)
        return {"devices": devices, "events": events, "coverage": {
            "schema_version": 1, "enabled": settings.enabled, "configured": settings.token is not None,
            "session_id": settings.session_id, "poll_seconds": settings.poll_seconds,
            "retention_days": settings.retention_days, "retained_from": cutoff, "exported_at": stamp(now),
            "last_poll_at": self.meta("last_poll_at"), "last_successful_poll_at": self.meta("last_successful_poll_at"),
            "error": self.meta("last_error") or None, "gaps": gaps,
            "storage_evictions": int(self.meta("storage_evictions") or 0),
            "limits": {"devices": MAX_DEVICES, "events": MAX_EVENTS, "gaps": MAX_GAPS},
            "time_basis": "local_observation_of_yandex_reported_availability",
            "notes": ["No history before connection is available from these API methods.",
                "A transition was detected between previous_observed_at and observed_at; its exact time is unknown.",
                "Repeated equal states are compressed; last_observed_at is the last confirming poll.",
                "Short changes between polls can be missed. Yandex reports cloud availability, not a direct network probe.",
                "Unknown denotes a collection gap, not device offline. Removed denotes absence in a complete catalog.",
                "Each replacement token starts a separate session to avoid joining different accounts."]}}

    def close(self):
        self.db.close()


class YandexHistory:
    def __init__(self, directory, redactor, *, clock=None, api_factory=None, demo=False):
        self.redactor = redactor
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.settings_store = YandexSettingsStore(directory)
        self._settings_error = None
        try:
            self.settings = self.settings_store.read()
        except Exception:
            self.settings = YandexSettings()
            self._settings_error = "YANDEX_SETTINGS_INVALID"
        self.store = AvailabilityStore(directory)
        self.api_factory = api_factory or YandexAPI
        self.api = None
        self.demo = demo
        self._task = None
        self._changed = asyncio.Event()
        self._lock = asyncio.Lock()
        self._configuration_lock = asyncio.Lock()
        self._startup = True
        self._retry_seconds = 0
        self._retired_tokens = []

    def scrub_known_secret(self, text):
        tokens = self._retired_tokens + ([self.settings.token.get_secret_value()] if self.settings.token else [])
        for token in tokens:
            text = text.replace(token, "[REDACTED]")
        return text

    async def configure(self, args):
        if self.demo and (args.enabled or args.token is not None):
            raise BrokerError("YANDEX_DEMO_DISABLED")
        # Interrupt an in-flight network cycle so owner settings do not wait
        # behind up to two minutes of device reads.
        async with self._configuration_lock:
            running = self._task is not None
            if self._task and not self._task.done():
                self._task.cancel()
                await asyncio.gather(self._task, return_exceptions=True)
            try:
                return await self._configure(args)
            finally:
                if running:
                    await self.start()

    async def _configure(self, args):
        async with self._lock:
            token = args.token or self.settings.token
            if args.enabled and token is None:
                raise BrokerError("YANDEX_TOKEN_REQUIRED")
            settings = YandexSettings(enabled=args.enabled, poll_seconds=args.poll_seconds,
                retention_days=args.retention_days, token=token,
                session_id="ys_" + secrets.token_hex(16) if args.token else self.settings.session_id)
            try:
                self.settings_store.write(settings)
            except (OSError, ValueError):
                raise BrokerError("YANDEX_SAVE_FAILED") from None
            if args.token is not None:
                if self.settings.token:
                    self._retired_tokens.append(self.settings.token.get_secret_value())
                    self._retired_tokens = self._retired_tokens[-16:]
                if self.settings.token or self.store.meta("last_poll_at"):
                    self.store.gap("CONNECTION_CHANGED", stamp(self.clock()))
                with self.store.db:
                    self.store.db.execute("UPDATE devices SET present=0")
                    self.store.db.execute("DELETE FROM metadata WHERE key IN ('last_poll_at','last_successful_poll_at','last_error')")
            elif not args.enabled and self.settings.enabled:
                self.store.gap("COLLECTION_PAUSED", stamp(self.clock()))
            self.settings = settings
            self._startup = True
            self._settings_error = None
            if self.api is not None:
                await self.api.close()
                self.api = None
            self._retry_seconds = 0
            self.store.prune(self.clock(), settings.retention_days)
            self._changed.set()
        return self.status()

    def status(self):
        # Do not send history or secrets in the periodically refreshed panel.
        rows = self.store.db.execute("SELECT status,COUNT(*) AS count FROM devices WHERE present=1 AND session_id=? GROUP BY status", (self.settings.session_id,)).fetchall()
        counts = {r["status"] or "unknown": r["count"] for r in rows}
        last = self.store.meta("last_poll_at")
        stale = bool(last and not 0 <= (self.clock() - datetime.fromisoformat(last.replace("Z", "+00:00"))).total_seconds() <= self.settings.poll_seconds * 2 + 30)
        return {"enabled": self.settings.enabled, "configured": self.settings.token is not None,
            "available": not self.demo, "poll_seconds": self.settings.poll_seconds,
            "retention_days": self.settings.retention_days, "devices": sum(counts.values()),
            "counts": {"unknown": sum(counts.values())} if stale else counts,
            "stale": stale, "last_poll_at": last,
            "last_successful_poll_at": self.store.meta("last_successful_poll_at"),
            "error": self._settings_error or self.store.meta("last_error") or None,
            "retry_seconds": self._retry_seconds}

    async def start(self):
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run(), name="yandex-device-availability")

    async def poll_once(self):
        async with self._lock:
            if not self.settings.enabled or self.demo:
                self.store.prune(self.clock(), self.settings.retention_days)
                return
            at = stamp(self.clock())
            last = self.store.meta("last_poll_at")
            if last and at < last:
                self._settings_error = "YANDEX_CLOCK_INVALID"
                return
            if self._startup:
                if self.store.meta("last_poll_at"):
                    self.store.gap("COLLECTOR_RESTART", at)
                self._startup = False
            else:
                last = self.store.meta("last_poll_at")
                if last and (self.clock() - datetime.fromisoformat(last.replace("Z", "+00:00"))).total_seconds() > self.settings.poll_seconds * 2 + 30:
                    self.store.gap("POLLING_DELAY", at)
            if self.api is None:
                self.api = self.api_factory(self.settings.token.get_secret_value())
            if hasattr(self.api, "retry_after"):
                self.api.retry_after = 0
            session = self.settings.session_id
            errors = []
            complete = False
            try:
                async with asyncio.timeout(120):
                    catalog = await self.api.devices()
                    safe = [{"device_ref": self.redactor.alias("YANDEX_DEVICE", d["id"]),
                        "name": self.redactor.alias("IDENTIFIER", self.scrub_known_secret(d["name"])),
                        "type": d["type"] if re.fullmatch(r"devices\.types\.[a-z_.]{1,80}", d["type"]) else "unknown"} for d in catalog]
                    self.store.inventory(session, safe, stamp(self.clock()))
                    semaphore = asyncio.Semaphore(4)
                    fatal = None
                    async def read(device, metadata):
                        nonlocal fatal
                        async with semaphore:
                            try:
                                if fatal:
                                    raise BrokerError(fatal)
                                state = await self.api.availability(device["id"])
                                reason = None
                            except BrokerError as error:
                                state, reason = "unknown", error.code
                                errors.append(reason)
                                if reason in {"YANDEX_AUTH_FAILED", "YANDEX_RATE_LIMIT"}:
                                    fatal = reason
                            with self.store.db:
                                self.store.observe(session, metadata["device_ref"], state, stamp(self.clock()), reason)
                    await asyncio.gather(*(read(d, s) for d, s in zip(catalog, safe)))
                    complete = True
            except (BrokerError, TimeoutError) as error:
                code = error.code if isinstance(error, BrokerError) else "YANDEX_POLL_TIMEOUT"
                self.store.gap(code, stamp(self.clock()))
                errors.append(code)
            error = next((e for e in errors if e in {"YANDEX_AUTH_FAILED", "YANDEX_RATE_LIMIT"}), errors[0] if errors else None)
            self.store.finish_poll(stamp(self.clock()), error, complete)
            self._settings_error = None
            self.store.prune(self.clock(), self.settings.retention_days)
            self._retry_seconds = min(3600, max(self.settings.poll_seconds, self._retry_seconds * 2, getattr(self.api, "retry_after", 0))) if errors else 0

    async def _run(self):
        while True:
            self._changed.clear()
            try:
                await self.poll_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                # Never include upstream text, exception repr or credentials.
                self._settings_error = "YANDEX_STORAGE_UNAVAILABLE"
            try:
                await asyncio.wait_for(self._changed.wait(), timeout=self._retry_seconds or self.settings.poll_seconds)
            except TimeoutError:
                pass

    async def export_snapshot(self):
        # One database snapshot shared by all ZIP files. Polling is independent
        # of ZIP creation; archive construction never initiates network polling.
        # SQLite reads/writes run synchronously on this event loop; no await
        # splits this snapshot, even while the collector waits for the network.
        value = self.store.snapshot(self.settings, self.clock())
        if self._settings_error:
            value["coverage"]["error"] = self._settings_error
        value["coverage"]["demo"] = self.demo
        return value

    async def close(self):
        if self._task and not self._task.done():
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        if self.api is not None:
            await self.api.close()
        self.store.close()

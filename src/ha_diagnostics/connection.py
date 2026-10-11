"""Owner-local connection indicators; no HA writes or remote query capability."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .broker import BrokerError

ENTITY_ID = r"^[a-z_][a-z0-9_]*\.[a-z0-9_]+$"
OBJECT_REF = r"^\[HA_CONNECTION_[a-f0-9]{16}\]$"
MAX_ENTITIES = 5000
SETTINGS_BYTES = 256 * 1024
Scale = Literal["auto", "lqi", "dbm", "percent", "snr", "latency", "packet_loss", "none"]


class ConnectionArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    force: bool = False


class ConnectionEdit(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    object_ref: str = Field(pattern=OBJECT_REF)
    action: Literal["hide", "show", "add", "remove"]
    scale: Scale = "auto"


class SavedObject(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    object_ref: str = Field(pattern=OBJECT_REF)
    entity_id: str = Field(pattern=ENTITY_ID, max_length=256)
    name: str = Field(max_length=256)
    scale: Scale = "auto"


class ConnectionSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    hidden: list[str] = Field(default_factory=list, max_length=MAX_ENTITIES)
    custom: list[SavedObject] = Field(default_factory=list, max_length=200)


class ConnectionStore:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.path.parent.is_symlink() or not self.path.parent.is_dir():
            raise ValueError("UNSAFE_CONNECTION_STORAGE")

    def read(self):
        try:
            fd = os.open(self.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                         | getattr(os, "O_NONBLOCK", 0))
        except FileNotFoundError:
            return ConnectionSettings()
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if self.path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("UNSAFE_CONNECTION_STORAGE")
            body = source.read(SETTINGS_BYTES + 1)
        if len(body) > SETTINGS_BYTES:
            raise ValueError("CONNECTION_SETTINGS_LIMIT")
        settings = ConnectionSettings.model_validate_json(body)
        if any(not re.fullmatch(OBJECT_REF, ref) for ref in settings.hidden):
            raise ValueError("CONNECTION_SETTINGS_INVALID")
        return settings

    def write(self, settings):
        if self.path.is_symlink():
            raise ValueError("UNSAFE_CONNECTION_STORAGE")
        if self.path.exists():
            info = self.path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("UNSAFE_CONNECTION_STORAGE")
        body = (settings.model_dump_json(indent=2) + "\n").encode()
        if len(body) > SETTINGS_BYTES:
            raise ValueError("CONNECTION_SETTINGS_LIMIT")
        temporary = self.path.parent / (".connection-" + secrets.token_hex(16))
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "wb") as target:
                target.write(body)
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary, self.path)
        finally:
            temporary.unlink(missing_ok=True)


def parsed_time(value):
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return result.astimezone(timezone.utc) if result.tzinfo else None
    except (ValueError, OverflowError):
        return None


def iso(value):
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def metric_kind(entity_id, registry, attrs):
    if entity_id.split(".")[0] not in {"sensor", "binary_sensor"}:
        return None
    device_class = attrs.get("device_class") or registry.get("device_class") or registry.get("original_device_class")
    labels = "_".join(str(value or "") for value in (entity_id.partition(".")[2],
        registry.get("translation_key"), registry.get("name"), registry.get("original_name"), attrs.get("friendly_name")))
    labels = re.sub(r"[^\w]+", "_", labels.casefold().replace("ё", "е"))
    def has(pattern):
        return bool(re.search(r"(?:^|_)(?:" + pattern + r")(?:_|$)", labels))
    if has("linkquality|link_quality|lqi|качество_связи"):
        return "lqi"
    if has("rssi|received_signal_strength"):
        return "rssi"
    if device_class == "signal_strength" or has("signal_strength|wifi_signal|wi_fi_signal|уровень_сигнала|сила_сигнала"):
        return "signal"
    if has("signal_quality|качество_сигнала"):
        return "percent"
    if has("snr|signal_to_noise|signal_noise_ratio"):
        return "snr"
    if has("packet_loss|packets_loss|потеря_пакетов|потери_пакетов"):
        return "packet_loss"
    if has("latency|round_trip_time|rtt|ping_time|задержка"):
        return "latency"
    if has("last_seen|lastseen|последняя_активность"):
        return "last_seen"
    if has("disconnected|offline|connection_problem|connection_lost|потеря_связи"):
        return "disconnection"
    if device_class == "connectivity" or has("connectivity|connection|connected|online|availability|available|доступность|подключение|связь"):
        return "connectivity"
    return None


def automatic_scale(kind, unit):
    unit = (unit or "").casefold()
    if kind in {"lqi", "rssi", "signal", "percent"}:
        if unit == "%":
            return "percent"
        if unit == "dbm":
            return "dbm"
        if unit == "lqi" or kind == "lqi" and not unit:
            return "lqi"
        if kind in {"rssi", "signal"} and not unit:
            return "dbm"
        if kind == "percent" and not unit:
            return "percent"
    if kind == "snr" and unit in {"", "db"}:
        return "snr"
    if kind == "latency" and unit in {"", "ms", "s", "мс", "с"}:
        return "latency"
    if kind == "packet_loss" and unit in {"", "%"}:
        return "packet_loss"
    return "none"


def quality_level(state, scale, kind=None, unit=None, *, assumed=False):
    if assumed or state is None or state in {"unknown", "none", "", "[REDACTED]"}:
        return None
    state = state.casefold()
    if state == "unavailable":
        return 1
    if kind in {"connectivity", "disconnection"} and scale == "none":
        if state in {"online", "connected", "available"}:
            return 5
        if state in {"offline", "disconnected"}:
            return 1
        good = state in {"on", "true", "1"}
        bad = state in {"off", "false", "0"}
        if good or bad:
            return 5 if good != (kind == "disconnection") else 1
        return None
    if scale == "none":
        return None
    try:
        value = float(state)
    except (ValueError, TypeError):
        return None
    if not math.isfinite(value):
        return None
    if scale in {"lqi", "percent", "packet_loss"} and not 0 <= value <= (255 if scale == "lqi" else 100):
        return None
    if scale == "dbm":
        if not -130 <= value <= 0:
            return None
        return 1 + sum(value >= boundary for boundary in (-90, -80, -70, -60))
    if scale == "lqi":
        return 1 + sum(value >= boundary for boundary in (51, 102, 153, 204))
    if scale == "percent":
        return 1 + sum(value >= boundary for boundary in (20, 40, 60, 80))
    if scale == "snr":
        return 1 + sum(value >= boundary for boundary in (5, 10, 20, 30))
    if scale == "latency":
        if value < 0:
            return None
        value *= 1000 if (unit or "").casefold() in {"s", "с"} else 1
        return 5 - sum(value > boundary for boundary in (20, 50, 100, 250))
    if scale == "packet_loss":
        return 5 - sum(value > boundary for boundary in (1, 5, 10, 25))
    return None


class ConnectionPanel:
    def __init__(self, sources, redactor, path, *, clock=None):
        self.sources, self.redactor = sources, redactor
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.store = ConnectionStore(path)
        self.settings_error = None
        try:
            self.settings = self.store.read()
        except (OSError, ValueError):
            self.settings = ConnectionSettings()
            self.settings_error = "CONNECTION_SETTINGS_INVALID"
        self.entities = {}
        self.states = {}
        self.registry_at = self.observed_at = self.attempted_at = None
        self.registry_error = self.states_error = None
        self._refresh_lock = asyncio.Lock()
        self._edit_lock = asyncio.Lock()

    def label(self, value, limit=256):
        return self.sources.scrub_known_secret(value)[:limit] if isinstance(value, str) else None

    def ref(self, entity_id, row):
        key = ["registry", row["id"]] if row.get("id") else ["unique", entity_id.split(".")[0],
            row.get("platform"), row.get("config_entry_id"), row["unique_id"]] if row.get("unique_id") else ["entity_id", entity_id]
        return self.redactor.alias("HA_CONNECTION", json.dumps(key, sort_keys=True))

    async def refresh(self, force=False):
        async with self._refresh_lock:
            now = self.clock()
            if not force and self.attempted_at and 0 <= (now - self.attempted_at).total_seconds() < 15:
                return
            self.attempted_at = now
            if not self.sources.available:
                self.states_error = "SOURCE_UNAVAILABLE"
                self.registry_error = "SOURCE_UNAVAILABLE"
                return
            try:
                async with asyncio.timeout(20):
                    if force or self.registry_at is None or not 0 <= (now - self.registry_at).total_seconds() < 300:
                        results = await asyncio.gather(*(self.sources.registry(key)
                            for key in ("entities", "devices", "areas")), return_exceptions=True)
                        registry, devices, areas = results
                        if not isinstance(registry, list) or len(registry) > MAX_ENTITIES:
                            self.registry_error = "CONNECTION_REGISTRY_UNAVAILABLE"
                        else:
                            device_map = {row["id"]: row for row in devices if isinstance(row, dict) and isinstance(row.get("id"), str)} if isinstance(devices, list) else {}
                            area_map = {row["area_id"]: row for row in areas if isinstance(row, dict) and isinstance(row.get("area_id"), str)} if isinstance(areas, list) else {}
                            entities = {}
                            for row in registry:
                                entity_id = row.get("entity_id") if isinstance(row, dict) else None
                                if not isinstance(entity_id, str) or len(entity_id) > 256 or not re.fullmatch(ENTITY_ID, entity_id):
                                    continue
                                device = device_map.get(row.get("device_id"), {})
                                area = area_map.get(row.get("area_id") or device.get("area_id"), {})
                                ref = self.ref(entity_id, row)
                                entities[ref] = {"object_ref": ref, "entity_id": entity_id,
                                    "name": self.label(row.get("name") or row.get("original_name")) or entity_id,
                                    "device_name": self.label(device.get("name_by_user") or device.get("name")),
                                    "room_name": self.label(area.get("name")),
                                    "disabled": bool(row.get("disabled_by") or device.get("disabled_by")), "registry": row}
                            self.entities = entities
                            self.registry_at = self.clock()
                            self.registry_error = None if all(isinstance(result, list) for result in results) else "CONNECTION_LABELS_UNAVAILABLE"
                    try:
                        states = await self.sources.snapshot("home_assistant/states")
                        if not isinstance(states, list) or len(states) > 20000:
                            raise BrokerError("CONNECTION_STATES_INVALID")
                        self.states = {row["entity_id"]: row for row in states if isinstance(row, dict)
                            and isinstance(row.get("entity_id"), str) and len(row["entity_id"]) <= 256
                            and re.fullmatch(ENTITY_ID, row["entity_id"])}
                        self.observed_at = self.clock()
                        self.states_error = None
                    except Exception:
                        self.states_error = "SOURCE_UNAVAILABLE"
                    # Remove state-only objects that disappeared; disabled objects stay in the registry.
                    self.entities = {ref: entity for ref, entity in self.entities.items() if entity["registry"]
                        or entity["entity_id"] in self.states}
                    registered = {entity["entity_id"] for entity in self.entities.values()}
                    for entity_id in self.states.keys() - registered:
                        ref = self.ref(entity_id, {})
                        self.entities[ref] = {"object_ref": ref, "entity_id": entity_id, "name": entity_id,
                            "device_name": None, "room_name": None, "disabled": False, "registry": {}}
                    if len(self.entities) > MAX_ENTITIES:
                        self.states_error = "CONNECTION_ENTITY_LIMIT"
                        self.entities = {}
            except (TimeoutError, OSError, ValueError, TypeError):
                self.states_error = "SOURCE_UNAVAILABLE"

    def _row(self, entity, custom=None, *, missing=False):
        ref, entity_id = entity["object_ref"], entity["entity_id"]
        source = self.states.get(entity_id, {}) if not missing else {}
        attrs = source.get("attributes")
        attrs = attrs if isinstance(attrs, dict) else {}
        kind = metric_kind(entity_id, entity.get("registry", {}), attrs)
        unit = self.label(attrs.get("unit_of_measurement"), 32)
        scale = custom.scale if custom else "auto"
        scale = automatic_scale(kind, unit) if scale == "auto" else scale
        state = self.label(source.get("state"), 512)
        # Repeated equal states can be reported without changing last_updated.
        stamp = parsed_time(source.get("last_reported"))
        stamp_source = "last_reported" if stamp else "last_updated"
        stamp = stamp or parsed_time(source.get("last_updated"))
        return {key: value for key, value in entity.items() if key != "registry"} | {
            "name": self.label(attrs.get("friendly_name")) or entity["name"],
            "hidden": ref in self.settings.hidden, "custom": custom is not None,
            "automatic": kind is not None, "state": state, "unit": unit,
            "updated_at": iso(stamp) if stamp else None, "timestamp_source": stamp_source if stamp else None,
            "scale": scale, "level": None if custom and custom.scale == "none" else
                quality_level(state, scale, kind, unit, assumed=attrs.get("assumed_state") is True),
            "missing": missing, "assumed": attrs.get("assumed_state") is True}

    async def panel(self, args):
        await self.refresh(args.force)
        custom = {entry.object_ref: entry for entry in self.settings.custom}
        objects = []
        for ref, entity in self.entities.items():
            row = self._row(entity, custom.get(ref))
            if row["automatic"] or row["custom"] or row["hidden"]:
                objects.append(row)
        for ref in custom.keys() - self.entities.keys():
            saved = custom[ref]
            objects.append(self._row({"object_ref": ref, "entity_id": saved.entity_id, "name": saved.name,
                "device_name": None, "room_name": None, "disabled": False}, saved, missing=True))
        objects.sort(key=lambda row: (row["device_name"] or row["name"], row["entity_id"]))
        return {"time": iso(self.clock()), "observed_at": iso(self.observed_at) if self.observed_at else None,
            "states_error": self.states_error, "registry_error": self.registry_error,
            "settings_error": self.settings_error, "objects": objects}

    async def catalog(self, args):
        await self.refresh(args.force)
        rows = []
        for entity in self.entities.values():
            source = self.states.get(entity["entity_id"], {})
            attrs = source.get("attributes", {})
            attrs = attrs if isinstance(attrs, dict) else {}
            rows.append({key: entity[key] for key in ("object_ref", "entity_id", "disabled", "device_name", "room_name")}
                | {"name": self.label(attrs.get("friendly_name")) or entity["name"]})
        return {"objects": rows, "states_error": self.states_error, "registry_error": self.registry_error}

    async def edit(self, args):
        async with self._edit_lock:
            await self.refresh()
            custom = {entry.object_ref: entry for entry in self.settings.custom}
            hidden = set(self.settings.hidden)
            entity = self.entities.get(args.object_ref)
            if args.object_ref not in hidden and args.object_ref not in custom and entity is None:
                raise BrokerError("CONNECTION_OBJECT_NOT_FOUND")
            if self.settings_error:
                # Preserve a damaged/unsafe settings file instead of silently replacing it.
                raise BrokerError("CONNECTION_SETTINGS_INVALID")
            if args.action == "hide":
                hidden.add(args.object_ref)
            elif args.action == "show":
                hidden.discard(args.object_ref)
            elif args.action == "remove":
                custom.pop(args.object_ref, None)
            else:
                if entity is None:
                    raise BrokerError("CONNECTION_OBJECT_NOT_FOUND")
                custom[args.object_ref] = SavedObject(object_ref=args.object_ref, entity_id=entity["entity_id"],
                    name=entity["name"], scale=args.scale)
                hidden.discard(args.object_ref)
            try:
                updated = ConnectionSettings(hidden=sorted(hidden), custom=list(custom.values()))
                self.store.write(updated)
            except (OSError, ValueError):
                raise BrokerError("CONNECTION_SAVE_FAILED") from None
            self.settings = updated
            return await self.panel(ConnectionArgs())

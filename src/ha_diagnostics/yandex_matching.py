"""Owner-approved identities and read-only HA availability comparisons.

Provider IDs and labels stay in the private UI database. History contains only
pseudonymous references, availability, provenance and observation timestamps.
"""
from __future__ import annotations

import asyncio
from datetime import datetime
from difflib import SequenceMatcher
import json
import re
import secrets

from pydantic import BaseModel, ConfigDict, Field

from .broker import BrokerError

ENTITY_ID = r"[a-z_][a-z0-9_]*\.[a-z0-9_]+"
DEVICE_REF = r"\[YANDEX_DEVICE_[a-f0-9]{16}\]"
ENTITY_REF = r"\[HA_MATCH_[a-f0-9]{16}\]"
MAX_HA_ENTITIES = 5000
REGISTRY_SECONDS = 300


def availability(row, domain):
    """The same interpretation for current states and full Recorder states."""
    if row is None:
        return "unknown", "HA_ENTITY_MISSING"
    attrs = row.get("attributes", {})
    attrs = attrs if isinstance(attrs, dict) else {}
    state = row.get("state")
    connectivity = attrs.get("device_class") == "connectivity" and domain == "binary_sensor"
    if not isinstance(state, str) or not state or state == "unknown" or attrs.get("assumed_state") is True:
        return "unknown", "HA_UNKNOWN_STATE"
    if state == "unavailable" or connectivity and state == "off":
        return "unavailable", None
    if not connectivity or state == "on":
        return "available", None
    return "unknown", "HA_UNKNOWN_STATE"


def timestamp(now):
    return now.isoformat(timespec="microseconds").replace("+00:00", "Z")


def normalized(value):
    return " ".join(re.findall(r"\w+", (value or "").casefold().replace("ё", "е")))


def compatible(kind, entity):
    suffix = kind.removeprefix("devices.types.").split(".")[0]
    domains = {"light": {"light"}, "socket": {"switch"}, "switch": {"switch"},
        "sensor": {"sensor", "binary_sensor", "event"}, "smart_meter": {"sensor"},
        "thermostat": {"climate"}, "thermostat_ac": {"climate"}, "humidifier": {"humidifier"},
        "purifier": {"fan"}, "fan": {"fan"}, "openable": {"cover"}, "vacuum_cleaner": {"vacuum"},
        "camera": {"camera"}, "media_device": {"media_player"}, "smart_speaker": {"media_player"}}
    return entity["domain"] in domains.get(suffix, set())


class MatchingArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)


class CandidateArgs(MatchingArgs):
    device_ref: str = Field(pattern="^" + DEVICE_REF + "$")
    session_id: str = Field(pattern=r"^ys_[a-f0-9]{32}$")


class LinkArgs(CandidateArgs):
    entity_ref: str | None = Field(default=None, pattern="^" + ENTITY_REF + "$")
    method: str = Field(default="manual", pattern=r"^(manual|suggestion)$")


class IdentityRuleArgs(MatchingArgs):
    session_id: str = Field(pattern=r"^ys_[a-f0-9]{32}$")
    skill_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,200}$")
    enabled: bool
    external_prefix: str = Field(default="", max_length=256, pattern=r"^[A-Za-z0-9_.:/-]*$")


class HomeAssistantMatcher:
    def __init__(self, store, redactor, clock, scrub):
        self.store, self.db, self.redactor = store, store.db, redactor
        self.clock, self.scrub = clock, scrub
        self.sources = None
        self.entities = {}
        self.identities = {}
        self.catalog_at = self.observed_at = None
        self.error = None
        self._disabled_ids = set()
        self._refresh_lock = asyncio.Lock()
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS local_ui.identities (
              session_id TEXT, device_ref TEXT, skill_id TEXT, external_id TEXT, identity_key TEXT,
              PRIMARY KEY(session_id,device_ref));
            CREATE TABLE IF NOT EXISTS local_ui.ha_links (
              session_id TEXT, device_ref TEXT, entity_ref TEXT, method TEXT, identity_key TEXT,
              revision TEXT, updated_at TEXT, PRIMARY KEY(session_id,device_ref));
            CREATE TABLE IF NOT EXISTS local_ui.identity_rules (
              session_id TEXT, skill_id TEXT, external_prefix TEXT,
              PRIMARY KEY(session_id,skill_id));
            CREATE TABLE IF NOT EXISTS ha_comparisons (
              event_id INTEGER PRIMARY KEY, ha_entity_ref TEXT, ha_status TEXT, ha_observed_at TEXT,
              comparison TEXT, ha_reason TEXT, method TEXT, mapping_revision TEXT);
            CREATE TABLE IF NOT EXISTS local_ui.comparison_labels (
              event_id INTEGER PRIMARY KEY, ha_name TEXT);
        """)
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(ha_comparisons)")}
        with self.db:
            if "ha_origin" not in columns:
                self.db.execute("ALTER TABLE ha_comparisons ADD COLUMN ha_origin TEXT NOT NULL DEFAULT 'observed'")
            if "ha_retrieved_at" not in columns:
                self.db.execute("ALTER TABLE ha_comparisons ADD COLUMN ha_retrieved_at TEXT")

    def label(self, value):
        return self.scrub(value)[:256] if isinstance(value, str) and value else None

    async def refresh(self, *, force=False):
        async with self._refresh_lock:
            now = self.clock()
            if not force and self.observed_at and 0 <= (now - self.observed_at).total_seconds() < 30:
                return
            if self.sources is None or not self.sources.available:
                self.error = "HA_SOURCE_UNAVAILABLE"
                return
            try:
                async with asyncio.timeout(20):
                    if self.catalog_at is None or not 0 <= (now - self.catalog_at).total_seconds() < REGISTRY_SECONDS:
                        results = await asyncio.gather(*(self.sources.registry(key)
                            for key in ("entities", "devices", "areas")))
                        if any(not isinstance(rows, list) for rows in results):
                            raise BrokerError("HA_CATALOG_INVALID")
                        self._catalog(*results)
                        self.catalog_at = self.clock()
                    states = await self.sources.snapshot("home_assistant/states")
                    if not isinstance(states, list) or len(states) > 20000:
                        raise BrokerError("HA_STATES_INVALID")
                    indexed = {row["entity_id"]: row for row in states if isinstance(row, dict)
                        and isinstance(row.get("entity_id"), str)}
                    registered = {entity["entity_id"] for entity in self.entities.values()}
                    for entity_id in indexed.keys() - registered - self._disabled_ids:
                        if re.fullmatch(ENTITY_ID, entity_id):
                            ref = self.redactor.alias("HA_MATCH", json.dumps(["entity_id", entity_id]))
                            self.entities[ref] = {"entity_ref": ref, "entity_id": entity_id, "name": entity_id,
                                "device_name": None, "room_name": None, "domain": entity_id.split(".")[0],
                                "platform": None, "stable": False}
                    if len(self.entities) > MAX_HA_ENTITIES:
                        raise BrokerError("HA_ENTITY_LIMIT")
                    for entity in self.entities.values():
                        row = indexed.get(entity["entity_id"])
                        attrs = row.get("attributes", {}) if row else {}
                        attrs = attrs if isinstance(attrs, dict) else {}
                        if attrs.get("friendly_name"):
                            entity["name"] = self.label(attrs["friendly_name"]) or entity["name"]
                        state, reason = availability(row, entity["domain"])
                        entity.update(ha_status=state, reason=reason)
                    self.observed_at, self.error = self.clock(), None
            except asyncio.CancelledError:
                raise
            except Exception as error:
                # Do not expose provider payloads, exception messages or tokens.
                self.error = error.code if isinstance(error, BrokerError) and error.code in {
                    "HA_CATALOG_INVALID", "HA_STATES_INVALID", "HA_ENTITY_LIMIT"} else "HA_SOURCE_UNAVAILABLE"

    def _catalog(self, registry, devices, areas):
        if len(registry) > MAX_HA_ENTITIES:
            raise BrokerError("HA_ENTITY_LIMIT")
        device_map = {row["id"]: row for row in devices if isinstance(row, dict) and isinstance(row.get("id"), str)}
        area_map = {row["area_id"]: row for row in areas if isinstance(row, dict) and isinstance(row.get("area_id"), str)}
        incoming = {}
        self._disabled_ids = {row.get("entity_id") for row in registry if isinstance(row, dict)
            and isinstance(row.get("entity_id"), str) and row.get("disabled_by")}
        for row in registry:
            entity_id = row.get("entity_id") if isinstance(row, dict) else None
            if not isinstance(entity_id, str) or not re.fullmatch(ENTITY_ID, entity_id) or row.get("disabled_by"):
                continue
            domain = entity_id.split(".")[0]
            stable = isinstance(row.get("id"), str) and bool(row["id"])
            key = ["registry", row["id"]] if stable else ["unique", domain, row.get("platform"),
                row.get("config_entry_id"), row.get("unique_id")] if row.get("unique_id") else ["entity_id", entity_id]
            stable = stable or bool(row.get("unique_id"))
            ref = self.redactor.alias("HA_MATCH", json.dumps(key, sort_keys=True))
            device = device_map.get(row.get("device_id"), {})
            area = area_map.get(row.get("area_id") or device.get("area_id"), {})
            previous = self.entities.get(ref, {})
            incoming[ref] = {"entity_ref": ref, "entity_id": entity_id,
                "name": self.label(row.get("name") or row.get("original_name") or device.get("name_by_user")
                    or device.get("name") or entity_id),
                "device_name": self.label(device.get("name_by_user") or device.get("name")),
                "room_name": self.label(area.get("name")), "domain": domain,
                "platform": self.label(row.get("platform")), "stable": stable,
                "ha_status": previous.get("ha_status", "unknown"), "reason": previous.get("reason")}
        self.entities = incoming

    def inventory(self, session, catalog):
        with self.db:
            for device in catalog:
                ref = self.redactor.alias("YANDEX_DEVICE", device["id"])
                skill = device.get("skill_id")
                skill = skill if isinstance(skill, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,200}", skill) and self.scrub(skill) == skill else None
                external = device.get("external_id")
                external = external if isinstance(external, str) and 0 < len(external) <= 1024 and external.isprintable() and self.scrub(external) == external else None
                key = self.redactor.alias("PROVIDER_ID", json.dumps([skill, external]))
                self.db.execute("INSERT OR REPLACE INTO local_ui.identities VALUES (?,?,?,?,?)",
                    (session, ref, skill, external, key))

    def identity(self, session, ref):
        row = self.db.execute("SELECT * FROM local_ui.identities WHERE session_id=? AND device_ref=?", (session, ref)).fetchone()
        return dict(row) if row else None

    def link(self, session, ref):
        row = self.db.execute("SELECT * FROM local_ui.ha_links WHERE session_id=? AND device_ref=?", (session, ref)).fetchone()
        return dict(row) if row else None

    def apply_exact(self, session):
        # A provider's ID namespace is trusted only after the owner enables its
        # rule for this account/session and this HA installation.
        if self.error or self.catalog_at is None:
            return
        rules = {row["skill_id"]: row["external_prefix"] for row in self.db.execute(
            "SELECT * FROM local_ui.identity_rules WHERE session_id=?", (session,))}
        by_id = {entity["entity_id"]: entity for entity in self.entities.values()}
        with self.db:
            for row in self.db.execute("SELECT i.* FROM local_ui.identities i JOIN devices d ON d.session_id=i.session_id AND d.device_ref=i.device_ref WHERE i.session_id=? AND d.present=1", (session,)).fetchall():
                if self.link(session, row["device_ref"]) is not None or row["skill_id"] not in rules:
                    continue
                prefix, external = rules[row["skill_id"]], row["external_id"] or ""
                if not external.startswith(prefix):
                    continue
                entity = by_id.get(external[len(prefix):])
                if entity and entity["stable"]:
                    self._write_link(session, row["device_ref"], entity["entity_ref"], "exact", row["identity_key"])

    def _write_link(self, session, ref, entity_ref, method, identity_key):
        self.db.execute("INSERT OR REPLACE INTO local_ui.ha_links VALUES (?,?,?,?,?,?,?)",
            (session, ref, entity_ref, method, identity_key, secrets.token_hex(16), timestamp(self.clock())))

    def _device(self, session, ref):
        row = self.db.execute("SELECT d.*,l.device_name,l.room_name FROM devices d LEFT JOIN local_ui.labels l ON l.session_id=d.session_id AND l.device_ref=d.device_ref WHERE d.session_id=? AND d.device_ref=? AND d.present=1", (session, ref)).fetchone()
        if row is None:
            raise BrokerError("YANDEX_DEVICE_NOT_FOUND")
        return dict(row)

    def suggestions(self, session, ref):
        device = self._device(session, ref)
        if self.error:
            return []
        name, room = normalized(device["device_name"]), normalized(device["room_name"])
        candidates = []
        for entity in self.entities.values():
            if not compatible(device["type"], entity):
                continue
            names = [normalized(entity["name"]), normalized(entity["device_name"])]
            similarity = max(SequenceMatcher(None, name, other).ratio() if name and other else 0 for other in names)
            same_room = bool(room and room == normalized(entity["room_name"]))
            if similarity < .45 or similarity < .65 and not same_room:
                continue
            reasons = ["type"]
            if similarity == 1:
                reasons.append("name")
            elif similarity >= .65:
                reasons.append("similar_name")
            if same_room:
                reasons.append("room")
            candidates.append({"entity_ref": entity["entity_ref"], "reasons": reasons,
                "score": round(similarity * 70 + (20 if same_room else 0) + 10)})
        return sorted(candidates, key=lambda row: (-row["score"], row["entity_ref"]))[:5]

    def set_link(self, args, session):
        if args.session_id != session:
            raise BrokerError("YANDEX_CONNECTION_CHANGED")
        self._device(session, args.device_ref)
        identity = self.identity(session, args.device_ref)
        if args.entity_ref:
            if self.error or args.entity_ref not in self.entities:
                raise BrokerError("HA_ENTITY_NOT_FOUND")
            if args.method == "suggestion" and args.entity_ref not in {
                    candidate["entity_ref"] for candidate in self.suggestions(session, args.device_ref)}:
                raise BrokerError("YANDEX_CANDIDATE_CHANGED")
        with self.db:
            self._write_link(session, args.device_ref, args.entity_ref,
                args.method if args.entity_ref else "blocked", identity["identity_key"] if identity else None)

    def set_rule(self, args, session):
        if args.session_id != session:
            raise BrokerError("YANDEX_CONNECTION_CHANGED")
        if self.scrub(args.external_prefix) != args.external_prefix:
            raise BrokerError("YANDEX_IDENTITY_RULE_REJECTED")
        if not self.db.execute("SELECT 1 FROM local_ui.identities WHERE session_id=? AND skill_id=?", (session, args.skill_id)).fetchone():
            raise BrokerError("YANDEX_SKILL_NOT_FOUND")
        with self.db:
            # Changing a rule drops only links created by it. Owner choices win.
            self.db.execute("DELETE FROM local_ui.ha_links WHERE session_id=? AND method='exact' AND device_ref IN (SELECT device_ref FROM local_ui.identities WHERE session_id=? AND skill_id=?)", (session, session, args.skill_id))
            self.db.execute("DELETE FROM local_ui.identity_rules WHERE session_id=? AND skill_id=?", (session, args.skill_id))
            if args.enabled:
                self.db.execute("INSERT INTO local_ui.identity_rules VALUES (?,?,?)", (session, args.skill_id, args.external_prefix))
        self.apply_exact(session)

    def comparison(self, session, ref, status, poll_seconds):
        link, identity = self.link(session, ref), self.identity(session, ref)
        result = {"ha_entity_ref": link["entity_ref"] if link else None,
            "ha_status": "unknown", "ha_observed_at": None, "comparison": "unknown",
            "ha_reason": "UNLINKED", "method": link["method"] if link and link["entity_ref"] else None,
            "mapping_revision": link["revision"] if link else None, "ha_name": None}
        if not link or not link["entity_ref"]:
            result["comparison"] = "unlinked"
            return result
        if identity is None or link["identity_key"] != identity["identity_key"]:
            result["ha_reason"] = "YANDEX_IDENTITY_CHANGED"
            return result
        entity = self.entities.get(link["entity_ref"])
        if entity is None:
            result["ha_reason"] = "HA_ENTITY_MISSING"
            return result
        result["ha_name"] = entity["name"]
        if self.error or self.observed_at is None:
            result["ha_reason"] = self.error or "HA_NOT_OBSERVED"
            return result
        if not 0 <= (self.clock() - self.observed_at).total_seconds() <= poll_seconds * 2 + 30:
            result["ha_reason"] = "HA_OBSERVATION_STALE"
            return result
        result.update(ha_status=entity["ha_status"], ha_observed_at=timestamp(self.observed_at), ha_reason=entity["reason"])
        if status in {"online", "offline"} and result["ha_status"] in {"available", "unavailable"}:
            result["comparison"] = "match" if (status == "online") == (result["ha_status"] == "available") else "mismatch"
        return result

    def record(self, event_id, comparison):
        keys = ("ha_entity_ref", "ha_status", "ha_observed_at", "comparison", "ha_reason", "method", "mapping_revision",
                "ha_origin", "ha_retrieved_at")
        values = {"ha_origin": "observed", "ha_retrieved_at": None, **comparison}
        self.db.execute("INSERT OR REPLACE INTO ha_comparisons (event_id," + ",".join(keys) + ") VALUES (" +
            ",".join("?" for _ in range(len(keys) + 1)) + ")", (event_id, *(values[key] for key in keys)))
        self.db.execute("INSERT OR REPLACE INTO local_ui.comparison_labels VALUES (?,?)", (event_id, comparison["ha_name"]))

    def event_comparison(self, event_id, *, labels=False):
        row = self.db.execute("SELECT * FROM ha_comparisons WHERE event_id=?", (event_id,)).fetchone()
        if row is None:
            value = {"ha_entity_ref": None, "ha_status": "unknown", "ha_observed_at": None,
                "comparison": "unknown", "ha_reason": "HA_NOT_OBSERVED", "method": None, "mapping_revision": None,
                "ha_origin": "observed", "ha_retrieved_at": None}
            return value | {"ha_name": None} if labels else value
        value = dict(row)
        value.pop("event_id")
        if labels:
            row = self.db.execute("SELECT ha_name FROM local_ui.comparison_labels WHERE event_id=?", (event_id,)).fetchone()
            value["ha_name"] = self.label(row[0]) if row else None
        return value

    def panel(self, settings):
        self.apply_exact(settings.session_id)
        now = self.clock()
        devices = []
        for row in self.db.execute("SELECT d.*,l.device_name,l.home_name,l.room_name FROM devices d LEFT JOIN local_ui.labels l ON l.session_id=d.session_id AND l.device_ref=d.device_ref WHERE d.session_id=? AND d.present=1 ORDER BY l.device_name,d.device_ref", (settings.session_id,)):
            row = dict(row)
            observed = row["last_observed_at"]
            stale = observed is None or not 0 <= (now - datetime.fromisoformat(observed.replace("Z", "+00:00"))).total_seconds() <= settings.poll_seconds * 2 + 30
            status = "unknown" if stale else row["status"]
            identity = self.identity(settings.session_id, row["device_ref"]) or {}
            devices.append({"device_ref": row["device_ref"], "device_name": self.label(row["device_name"]) or row["name"],
                "home_name": self.label(row["home_name"]), "room_name": self.label(row["room_name"]),
                "status": status, "observed_at": observed, "skill_id": identity.get("skill_id"),
                "external_id": identity.get("external_id"),
                **self.comparison(settings.session_id, row["device_ref"], status, settings.poll_seconds)})
        rules = [dict(row) for row in self.db.execute("SELECT skill_id,external_prefix FROM local_ui.identity_rules WHERE session_id=?", (settings.session_id,))]
        return {"session_id": settings.session_id, "devices": devices,
            "entities": [{key: ("unknown" if key == "ha_status" and self.error else value)
                for key, value in entity.items() if key != "reason"} for entity in self.entities.values()],
            "rules": rules, "ha_observed_at": timestamp(self.observed_at) if self.observed_at else None,
            "ha_error": self.error, "entity_limit": MAX_HA_ENTITIES}

    def prune(self):
        self.db.execute("DELETE FROM ha_comparisons WHERE NOT EXISTS (SELECT 1 FROM events WHERE events.event_id=ha_comparisons.event_id)")
        self.db.execute("DELETE FROM local_ui.comparison_labels WHERE NOT EXISTS (SELECT 1 FROM events WHERE events.event_id=comparison_labels.event_id)")
        for table in ("identities", "ha_links"):
            self.db.execute(f"DELETE FROM local_ui.{table} WHERE NOT EXISTS (SELECT 1 FROM devices WHERE devices.session_id={table}.session_id AND devices.device_ref={table}.device_ref)")
        self.db.execute("DELETE FROM local_ui.identity_rules WHERE NOT EXISTS (SELECT 1 FROM local_ui.identities i WHERE i.session_id=identity_rules.session_id AND i.skill_id=identity_rules.skill_id)")

"""Bounded trusted collection; coverage describes what was actually observed."""
from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from .broker import BrokerError, ReadBroker
from .timeutil import SOURCE_TIMESTAMP


def split_open_traceback(text: str) -> tuple[str, str]:
    """Withhold a visibly incomplete final Python traceback across polls."""
    offset = 0
    record_start = 0
    lines = text.splitlines(keepends=True)
    for line in lines:
        if SOURCE_TIMESTAMP.match(line):
            record_start = offset
        offset += len(line)
    tail = text[record_start:]
    if "Traceback (" not in tail:
        return text, ""
    final = next((line for line in reversed(tail.splitlines()) if line.strip()), "")
    if final.startswith((" ", "\t", "Traceback (", "During handling of", "The above exception")):
        return text[:record_start], tail
    return text, ""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def epoch_time(value: Any) -> str | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")
        except (ValueError, OverflowError, OSError):
            pass
    return None


class Collector:
    """Single archive writer in the broker process, never in MCP/query.

    Cursorless polling is the deliberate alpha fallback until follow/cursors
    are verified on the actual HA target. The read-only follow adapter exists
    in broker, but polling never claims continuous historical completeness.
    """

    def __init__(self, broker: ReadBroker, archive: Any, *, poll_seconds: float = 5.0,
                 metadata_seconds: float = 300.0, clock: Callable[[], str] = utc_now,
                 timezone: str = "UTC"):
        from zoneinfo import ZoneInfo
        ZoneInfo(timezone)
        self.broker = broker
        self.archive = archive
        self.poll_seconds = max(1.0, poll_seconds)
        self.metadata_seconds = max(10.0, metadata_seconds)
        self.clock = clock
        self.timezone = timezone
        self._tasks: dict[str, asyncio.Task[Any]] = {}
        self._stopped = asyncio.Event()
        self._states: dict[str, dict[str, Any]] = {}
        self._entity_selection: tuple[str, ...] = ()
        self.last_error: dict[str, str] = {}

    def _coverage(self, source: str, start: str, end: str, *, status: str = "partial",
                  reason: str | None = None, basis: str = "observed", dropped: int = 0) -> None:
        if datetime.fromisoformat(end.replace("Z", "+00:00")) <= datetime.fromisoformat(start.replace("Z", "+00:00")):
            # Empty intervals cannot evidence completeness.
            return
        self.archive.add_coverage(source, start, end, status, reason=reason,
                                  ingestion_basis=basis, dropped_count=dropped)

    def _disk_available(self) -> bool:
        try:
            healthy = self.archive.check_disk()
        except OSError:
            healthy = False
        if not healthy:
            self.last_error["storage"] = "DISK_LOW"
        else:
            self.last_error.pop("storage", None)
        return healthy

    async def collect_metadata_once(self) -> None:
        if not self._disk_available():
            raise BrokerError("DISK_LOW")
        observed = self.clock()
        payload = await self.broker.execute({"op": "metadata"})
        config = payload.get("config", {})
        configured_zone = config.get("time_zone")
        if configured_zone:
            from zoneinfo import ZoneInfo
            ZoneInfo(configured_zone)
            self.timezone = configured_zone
        self.archive.upsert_metadata({"observed_at": observed, "kind": "installation", "safe_fields": payload,
                                      "timezone": self.timezone, "mapping_origin": "exact_registry",
                                      "timezone_origin": "observed_ha_config" if configured_zone else "local_configuration_unverified"})
        policy = self.broker.policy
        if "entities" in policy.enabled_sources:
            catalog = await self.broker.execute({"op": "device_catalog"})
            entity_map = {e.get("entity_id"): e for e in catalog.get("entities", [])}
            entries = {e.get("entry_id"): e for e in catalog.get("integrations", [])}
            for device in catalog.get("devices", []):
                device_id = device.get("id")
                entities = [e for e in entity_map.values() if e.get("device_id") == device_id]
                refs = [self.broker.ref("entity", e["entity_id"]) for e in entities]
                integration_ids = {e.get("config_entry_id") for e in entities}
                integrations = [entries[v] for v in integration_ids if v in entries]
                name = device.get("name_by_user") or device.get("name")
                self.archive.upsert_metadata({"observed_at": observed,
                    "device_ref": self.broker.ref("device", str(device_id)), "entity_refs": refs,
                    "integration_ref": self.broker.ref("integration", ",".join(sorted(str(v) for v in integration_ids))),
                    "name": name or self.broker.redactor.alias("device", str(device_id)),
                    "safe_fields": {k: v for k, v in device.items() if k not in {"id", "area_id", "config_entries", "config_entry_id"}},
                    "integrations": [{k: v for k, v in i.items() if k != "entry_id"} for i in integrations],
                    "mapping_origin": "exact_registry", "related_source_ids": ["core"] if "core" in policy.enabled_sources else []})

    async def collect_logs_once(self, source_id: str) -> dict[str, Any]:
        """Restart-safe bounded overlap poll; rotation/boot changes create gaps."""
        if not self._disk_available():
            raise BrokerError("DISK_LOW")
        observed = self.clock()
        previous = self.archive.get_cursor(source_id) or {}
        actual_boot = None
        try:
            boots = await self.broker.execute({"op": "boots"})
            actual_boot = boots.get("0")
        except BrokerError:
            pass
        boot = actual_boot or previous.get("boot_id") or "unknown_boot"
        response = await self.broker.execute({"op": "logs", "source_id": source_id, "lines": 50_000,
                                             **({"boot_id": actual_boot} if actual_boot else {})})
        text = response["text"]
        hashes = [hashlib.sha256(line.encode()).hexdigest() for line in text.splitlines()]
        old_tail = previous.get("tail", [])
        boot_changed = bool(previous and previous.get("boot_id") != boot)
        rotation = bool(old_tail and hashes and not set(old_tail) & set(hashes))
        start = previous.get("observed_at", observed)
        if boot_changed or rotation:
            self._coverage(source_id, start, observed, reason="source_retention", basis="boot_or_rotation_detected")
        elif previous and previous.get("disconnected"):
            self._coverage(source_id, start, observed, reason="connection_lost", basis="bounded_reconnect_backfill")
        elif previous:
            self._coverage(source_id, start, observed, status="partial", reason="parse_uncertainty", basis="cursorless_bounded_polling")
        epoch = int(previous.get("rotation_epoch", 0)) + int(rotation and not boot_changed)
        logical_boot = f"{boot}:rotation_{epoch}"
        pending_before = previous.get("pending_text", "")
        if pending_before and (boot_changed or rotation or pending_before not in text):
            from .archive import parse_log_records
            for record in parse_log_records(pending_before, previous.get("pending_observed_at", observed), self.timezone):
                self.archive.append_log(record | {"source_id": source_id,
                    "boot_id": previous.get("pending_boot_id", logical_boot), "truncated": True})
            self._coverage(source_id, previous.get("pending_observed_at", start), observed,
                           reason="parse_uncertainty", basis="incomplete_traceback_lost")
        complete_text, pending = split_open_traceback(text)
        if len(pending.encode("utf-8")) > 4096:
            # Oversized incomplete records use the archive's bounded truncation;
            # no potentially unbounded pending traceback is retained in cursors.
            complete_text, pending = text, ""
            self._coverage(source_id, start, observed, reason="parse_uncertainty",
                           basis="incomplete_traceback_exceeds_pending_limit")
        result = self.archive.ingest_logs(source_id, logical_boot, complete_text, observed,
                                         timezone=self.timezone, overlap=bool(previous and not boot_changed and not rotation))
        self.archive.set_cursor(source_id, {"boot_id": boot, "rotation_epoch": epoch,
            "observed_at": observed, "tail": hashes[-32:], "disconnected": False,
            "upstream_cursor": response.get("cursor"), "truncated": response["truncated"],
            "deduplication_basis": response["deduplication_basis"],
            "pending_text": pending, "pending_observed_at": observed if pending else None,
            "pending_boot_id": logical_boot if pending else None})
        if not previous or response["truncated"]:
            # Earlier source coverage is inherently unknown after bounded startup.
            earlier = (datetime.fromisoformat(observed.replace("Z", "+00:00")) - timedelta(days=1)).isoformat().replace("+00:00", "Z")
            self._coverage(source_id, earlier, observed, reason="startup_limit", basis="bounded_backfill")
        return {"boot_id": logical_boot, "result": result, "truncated": response["truncated"],
                "rotation_detected": rotation, "boot_changed": boot_changed}

    async def backfill_history(self, entity_ids: list[str], start: str, end: str) -> None:
        from_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
        # Never query arbitrarily old Recorder history at startup/reconnect.
        from_dt = max(from_dt, end_dt - timedelta(hours=24))
        while from_dt < end_dt:
            to_dt = min(from_dt + timedelta(hours=1), end_dt)
            for offset in range(0, len(entity_ids), 20):
                response = await self.broker.execute({"op": "history", "entity_ids": entity_ids[offset:offset + 20],
                    "from": from_dt.isoformat(), "to": to_dt.isoformat()})
                for state in response["states"]:
                    when = state.get("last_updated", state.get("last_changed"))
                    if not when:
                        continue
                    self.archive.append_transition({"source_id": "entities", "entity_ref": state["entity_ref"],
                        "old_state": None, "new_state": state.get("state"), "event_time": when,
                        "last_changed": state.get("last_changed"), "last_updated": state.get("last_updated"),
                        "observed_at": self.clock(), "safe_attributes": state.get("safe_attributes", {}),
                        "origin": "recorder", "boundary_state": state["boundary_state"],
                        "old_state_known": False})
            self._coverage("entities", from_dt.isoformat(), to_dt.isoformat(), status="unknown",
                           reason="source_retention", basis="recorder_exclusions_retention_unknown")
            from_dt = to_dt

    def ingest_entity_event(self, event: dict[str, Any], *, initial: bool = False) -> None:
        observed = self.clock()
        for ref, compressed in event.get("a", {}).items():
            state = {"state": compressed.get("s"), "last_changed": epoch_time(compressed.get("lc")),
                     "last_updated": epoch_time(compressed.get("lu", compressed.get("lc")))}
            self._states[ref] = state
            self.archive.upsert_metadata({"kind": "entity_snapshot", "entity_ref": ref, "observed_at": observed,
                                          "safe_fields": state, "origin": "current_snapshot"})
            if not initial:
                self.archive.append_transition({"source_id": "entities", "entity_ref": ref, "old_state": None,
                    "new_state": state["state"], "event_time": state["last_updated"] or observed,
                    "observed_at": observed, "origin": "state_changed", "old_state_known": False,
                    "safe_attributes": {}, "time_quality": "source_timestamp" if state["last_updated"] else "observed_only"})
        for ref, changes in event.get("c", {}).items():
            before = self._states.get(ref, {})
            additions = changes.get("+", {})
            after = dict(before)
            if "s" in additions:
                after["state"] = additions["s"]
            if "lc" in additions:
                after["last_changed"] = epoch_time(additions["lc"])
                # Core omits lu when last_changed == last_updated.
                after["last_updated"] = after["last_changed"]
            elif "lu" in additions:
                after["last_updated"] = epoch_time(additions["lu"])
            self._states[ref] = after
            self.archive.append_transition({"source_id": "entities", "entity_ref": ref,
                "old_state": before.get("state"), "new_state": after.get("state"),
                "event_time": after.get("last_updated") or observed, "last_changed": after.get("last_changed"),
                "last_updated": after.get("last_updated"), "observed_at": observed,
                "origin": "state_changed", "old_state_known": bool(before), "safe_attributes": {},
                "time_quality": "source_timestamp" if after.get("last_updated") else "observed_only"})
        for ref in event.get("r", []):
            before = self._states.pop(ref, {})
            self.archive.append_transition({"source_id": "entities", "entity_ref": ref,
                "old_state": before.get("state"), "new_state": None, "event_time": observed,
                "observed_at": observed, "origin": "state_changed", "old_state_known": bool(before),
                "safe_attributes": {}, "removed": True, "time_quality": "observed_only"})

    async def _logs_loop(self, source: str) -> None:
        failures = 0
        while not self._stopped.is_set():
            try:
                await self.collect_logs_once(source)
                self.last_error.pop(source, None)
                failures = 0
            except asyncio.CancelledError:
                raise
            except BrokerError as exc:
                self.last_error[source] = exc.code
                previous = self.archive.get_cursor(source) or {}
                now = self.clock()
                self._coverage(source, previous.get("observed_at", now), now,
                    status="unavailable", reason="permission_denied" if exc.code == "PERMISSION_DENIED" else "disk_low" if exc.code == "DISK_LOW" else "connection_lost")
                previous["disconnected"] = True
                self.archive.set_cursor(source, previous)
                failures = min(failures + 1, 5)
            except Exception:
                # Archive quota/low disk and parse failures must not expose raw data.
                self.last_error[source] = "COLLECTION_DEGRADED"
                failures = min(failures + 1, 5)
            await asyncio.sleep(min(60, self.poll_seconds * 2 ** failures))

    async def _entities_loop(self) -> None:
        while not self._stopped.is_set():
            entities = sorted(self.broker.policy.entity_ids)
            now = self.clock()
            previous = self.archive.get_cursor("entities") or {}
            start = previous.get("observed_at", (datetime.fromisoformat(now.replace("Z", "+00:00")) - timedelta(hours=24)).isoformat().replace("+00:00", "Z"))
            backfill_task = None
            try:
                # Subscription opens first with atomic snapshot. Recorder follows
                # inside the stream so source events are bounded by WS max_queue.
                initial = True
                async for event in self.broker.watch_entities(entities):
                    if initial:
                        self._coverage("entities", start, self.clock(), reason="connection_lost" if previous else "startup_limit", basis="subscription_reconnect")
                        self.ingest_entity_event(event, initial=True)
                        # Continue draining live events while bounded Recorder
                        # backfill runs; max_queue must not hide hours of events.
                        backfill_task = asyncio.create_task(self.backfill_history(entities, start, self.clock()))
                        initial = False
                    else:
                        self.ingest_entity_event(event)
                    self.archive.set_cursor("entities", {"observed_at": self.clock(), "disconnected": False})
                raise BrokerError("CONNECTION_LOST")
            except asyncio.CancelledError:
                raise
            except BrokerError as exc:
                self.last_error["entities"] = exc.code
                self._coverage("entities", start, self.clock(), reason="connection_lost", basis="subscription_interrupted")
                await asyncio.sleep(self.poll_seconds)
            except Exception:
                self.last_error["entities"] = "COLLECTION_DEGRADED"
                await asyncio.sleep(self.poll_seconds)
            finally:
                if backfill_task is not None:
                    if not backfill_task.done():
                        backfill_task.cancel()
                    outcome = await asyncio.gather(backfill_task, return_exceptions=True)
                    if outcome and isinstance(outcome[0], Exception) and not isinstance(outcome[0], asyncio.CancelledError):
                        self.last_error["history"] = "BACKFILL_INCOMPLETE"

    async def _metadata_loop(self) -> None:
        while not self._stopped.is_set():
            try:
                await self.collect_metadata_once()
                self.last_error.pop("metadata", None)
            except asyncio.CancelledError:
                raise
            except BrokerError as exc:
                self.last_error["metadata"] = exc.code
            except Exception:
                self.last_error["metadata"] = "COLLECTION_DEGRADED"
            await asyncio.sleep(self.metadata_seconds)

    async def run(self) -> None:
        initial_metadata_attempted = False
        try:
            while not self._stopped.is_set():
                policy = self.broker.policy
                desired = set(policy.enabled_sources) if policy.mode == "live" and policy.collect else set()
                disk_ok = self._disk_available()
                if not disk_ok:
                    desired = set()
                if not policy.entity_ids:
                    desired.discard("entities")
                if not desired:
                    initial_metadata_attempted = False
                if "metadata" in desired and not initial_metadata_attempted:
                    # Resolve the HA zone before parsing a first naive log
                    # timestamp. A failed read retains explicitly configured
                    # local zone and records an unavailable metadata source.
                    initial_metadata_attempted = True
                    try:
                        await self.collect_metadata_once()
                    except BrokerError as exc:
                        self.last_error["metadata"] = exc.code
                    except Exception:
                        self.last_error["metadata"] = "COLLECTION_DEGRADED"
                    # Policy may have been edited while upstream reads waited.
                    continue
                selection = tuple(sorted(policy.entity_ids))
                if selection != self._entity_selection and "entities" in self._tasks:
                    task = self._tasks.pop("entities")
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    self._states.clear()
                self._entity_selection = selection
                for source in set(self._tasks) - desired:
                    task = self._tasks.pop(source)
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    cursor = self.archive.get_cursor(source) or {}
                    self._coverage(source, cursor.get("observed_at", self.clock()), self.clock(), reason="collector_stopped" if disk_ok else "disk_low")
                for source in desired - set(self._tasks):
                    target = self._entities_loop() if source == "entities" else self._metadata_loop() if source == "metadata" else self._logs_loop(source)
                    self._tasks[source] = asyncio.create_task(target, name=f"collector:{source}")
                await asyncio.sleep(1)
        finally:
            for task in self._tasks.values():
                task.cancel()
            await asyncio.gather(*self._tasks.values(), return_exceptions=True)
            self._tasks.clear()

    def stop(self) -> None:
        self._stopped.set()

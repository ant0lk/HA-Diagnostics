"""Fill previously unlinked observations using bounded, read-only HA history.

Only the status effective at the Yandex observation time is used. Current HA
states and future Recorder entries cannot supply a missing historical status.
"""
from __future__ import annotations

import asyncio
from bisect import bisect_right
from datetime import datetime, timedelta, timezone

from .broker import BrokerError
from .yandex_matching import availability, timestamp

RETRY_SECONDS = 300
MAX_HISTORY_STATES = 20000
WINDOW = timedelta(hours=1)
EPSILON = timedelta(microseconds=1)


def instant(value):
    if not isinstance(value, str):
        raise ValueError()
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError()
    return result.astimezone(timezone.utc)


class AvailabilityBackfill:
    def __init__(self, matcher, settings):
        self.matcher, self.settings = matcher, settings
        self.db, self.store, self.clock = matcher.db, matcher.store, matcher.clock
        self.task = None
        self._requested = self._closed = False

    def _changed(self):
        self.store.set_meta("ha_history_revision", str(int(self.store.meta("ha_history_revision") or 0) + 1))

    def schedule(self):
        if self._closed:
            return
        # Mark old events as linked immediately; network reads run in the
        # background so saving a link does not wait for the entire retention.
        self._prepare()
        self._requested = True
        if self.task is None or self.task.done():
            self.task = asyncio.create_task(self._run(), name="yandex-ha-history-backfill")

    def _prepare(self):
        settings, now = self.settings(), self.clock()
        cutoff = timestamp(now - timedelta(days=settings.retention_days))
        rows = self.db.execute("""SELECT e.event_id,e.device_ref,e.status,e.observed_at,
            l.entity_ref,l.method,l.revision,l.identity_key,i.identity_key AS current_identity,
            c.ha_origin,c.mapping_revision,c.ha_retrieved_at,c.ha_reason,c.ha_entity_ref
            FROM events e JOIN local_ui.ha_links l
              ON l.session_id=e.session_id AND l.device_ref=e.device_ref
            LEFT JOIN local_ui.identities i
              ON i.session_id=e.session_id AND i.device_ref=e.device_ref
            LEFT JOIN ha_comparisons c ON c.event_id=e.event_id
            WHERE e.session_id=? AND e.status IN ('online','offline') AND e.observed_at>=?
              AND l.entity_ref IS NOT NULL
              AND (c.event_id IS NULL OR c.comparison='unlinked' OR c.ha_origin='history')
            ORDER BY l.device_ref,e.observed_at,e.event_id""", (settings.session_id, cutoff)).fetchall()
        groups, changed = {}, False
        with self.db:
            # Undo retrospective associations explicitly removed by the owner.
            # Actual snapshots collected while linked remain untouched.
            removed = self.db.execute("""SELECT c.event_id FROM ha_comparisons c
                JOIN events e ON e.event_id=c.event_id
                LEFT JOIN local_ui.ha_links l ON l.session_id=e.session_id AND l.device_ref=e.device_ref
                WHERE e.session_id=? AND c.ha_origin='history' AND c.ha_entity_ref IS NOT NULL
                  AND l.entity_ref IS NULL""", (settings.session_id,)).fetchall()
            for row in removed:
                self.matcher.record(row["event_id"], {"ha_entity_ref": None, "ha_status": "unknown",
                    "ha_observed_at": None, "comparison": "unlinked", "ha_reason": "UNLINKED",
                    "method": None, "mapping_revision": None, "ha_name": None,
                    "ha_origin": "history", "ha_retrieved_at": None})
                changed = True
            for row in rows:
                entity = self.matcher.entities.get(row["entity_ref"])
                reason = "YANDEX_IDENTITY_CHANGED" if row["identity_key"] != row["current_identity"] else (
                    "HA_ENTITY_MISSING" if entity is None else "HA_HISTORY_PENDING")
                same_link = row["ha_origin"] == "history" and row["mapping_revision"] == row["revision"]
                if same_link and row["ha_retrieved_at"]:
                    if row["ha_reason"] not in {"HA_HISTORY_UNAVAILABLE", "HA_HISTORY_EMPTY", "HA_HISTORY_INVALID",
                            "HA_HISTORY_LIMIT", "HA_ENTITY_MISSING", "YANDEX_IDENTITY_CHANGED"}:
                        continue
                    age = (now - instant(row["ha_retrieved_at"])).total_seconds()
                    if 0 <= age < RETRY_SECONDS and reason == "HA_HISTORY_PENDING":
                        continue
                if not same_link or row["ha_reason"] != reason:
                    value = {"ha_entity_ref": row["entity_ref"], "ha_status": "unknown", "ha_observed_at": None,
                        "comparison": "unknown", "ha_reason": reason, "method": row["method"],
                        "mapping_revision": row["revision"], "ha_name": entity["name"] if entity else None,
                        "ha_origin": "history", "ha_retrieved_at": None if entity else timestamp(now)}
                    self.matcher.record(row["event_id"], value)
                    changed = True
                if reason != "HA_HISTORY_PENDING":
                    continue
                key = (row["device_ref"], row["entity_ref"], row["revision"], entity["entity_id"])
                groups.setdefault(key, []).append(dict(row))
            if changed:
                self._changed()
        jobs = []
        for (ref, entity_ref, revision, entity_id), events in groups.items():
            batch = []
            for event in events:
                at = instant(event["observed_at"])
                if batch and at - instant(batch[0]["observed_at"]) > WINDOW - EPSILON * 2:
                    jobs.append(self._job(settings.session_id, ref, entity_ref, revision, entity_id, batch))
                    batch = []
                batch.append(event)
            if batch:
                jobs.append(self._job(settings.session_id, ref, entity_ref, revision, entity_id, batch))
        # Fill recent events first. One request at a time bounds Recorder load.
        return sorted(jobs, key=lambda job: job["events"][-1]["observed_at"], reverse=True)

    @staticmethod
    def _job(session, ref, entity_ref, revision, entity_id, events):
        return {"session": session, "ref": ref, "entity_ref": entity_ref, "revision": revision,
            "entity_id": entity_id, "events": events,
            "start": instant(events[0]["observed_at"]) - EPSILON,
            "end": instant(events[-1]["observed_at"]) + EPSILON}

    def _valid(self, job):
        if self.settings().session_id != job["session"]:
            return False
        link = self.matcher.link(job["session"], job["ref"])
        identity = self.matcher.identity(job["session"], job["ref"])
        entity = self.matcher.entities.get(job["entity_ref"])
        return bool(link and identity and entity and link["revision"] == job["revision"]
            and link["identity_key"] == identity["identity_key"] and entity["entity_id"] == job["entity_id"])

    @staticmethod
    def _states(payload, entity_id, end):
        if not isinstance(payload, list) or any(not isinstance(group, list) for group in payload):
            raise BrokerError("HA_HISTORY_INVALID")
        if sum(len(group) for group in payload) > MAX_HISTORY_STATES:
            raise BrokerError("HA_HISTORY_LIMIT")
        states = []
        for group in payload:
            for row in group:
                if not isinstance(row, dict):
                    raise BrokerError("HA_HISTORY_INVALID")
                if row.get("entity_id") != entity_id:
                    continue
                try:
                    at = instant(row.get("last_updated", row.get("last_changed")))
                except (ValueError, TypeError):
                    raise BrokerError("HA_HISTORY_INVALID") from None
                if not isinstance(row.get("attributes", {}), dict):
                    raise BrokerError("HA_HISTORY_INVALID")
                if at < end:
                    states.append((at, row))
        return sorted(states, key=lambda state: state[0])

    def _finish(self, job, states=(), reason=None):
        # A link, account, entity ID or retention may change during a read.
        if not self._valid(job):
            return
        times = [state[0] for state in states]
        now, settings = self.clock(), self.settings()
        cutoff = timestamp(now - timedelta(days=settings.retention_days))
        changed = False
        with self.db:
            for event in job["events"]:
                old = self.db.execute("SELECT c.* FROM ha_comparisons c JOIN events e ON e.event_id=c.event_id WHERE c.event_id=? AND e.observed_at>=?",
                    (event["event_id"], cutoff)).fetchone()
                if old is None or old["ha_origin"] != "history" or old["mapping_revision"] != job["revision"]:
                    continue
                index = bisect_right(times, instant(event["observed_at"])) - 1
                row = states[index][1] if index >= 0 and reason is None else None
                ha_status, ha_reason = availability(row, job["entity_id"].split(".")[0]) if row else (
                    "unknown", reason or "HA_HISTORY_EMPTY")
                verdict = "unknown"
                if ha_status in {"available", "unavailable"}:
                    verdict = "match" if (event["status"] == "online") == (ha_status == "available") else "mismatch"
                value = {"ha_entity_ref": job["entity_ref"], "ha_status": ha_status,
                    "ha_observed_at": event["observed_at"] if row else None, "comparison": verdict,
                    "ha_reason": ha_reason, "method": event["method"], "mapping_revision": job["revision"],
                    "ha_name": self.matcher.entities[job["entity_ref"]]["name"],
                    "ha_origin": "history", "ha_retrieved_at": timestamp(now)}
                self.matcher.record(event["event_id"], value)
                changed = True
            if changed:
                self._changed()

    async def _run(self):
        while self._requested:
            self._requested = False
            jobs = self._prepare()
            for index, job in enumerate(jobs):
                if not self._valid(job):
                    continue
                try:
                    sources = self.matcher.sources
                    if sources is None or not sources.available:
                        raise BrokerError("HA_HISTORY_UNAVAILABLE")
                    async with asyncio.timeout(90):
                        payload = await sources.entity_history(job["entity_id"], timestamp(job["start"]), timestamp(job["end"]))
                    self._finish(job, self._states(payload, job["entity_id"], job["end"]))
                except asyncio.CancelledError:
                    raise
                except Exception as error:
                    reason = error.code if isinstance(error, BrokerError) and error.code in {
                        "HA_HISTORY_INVALID", "HA_HISTORY_LIMIT", "UPSTREAM_LIMIT"} else "HA_HISTORY_UNAVAILABLE"
                    if reason == "UPSTREAM_LIMIT":
                        reason = "HA_HISTORY_LIMIT"
                    self._finish(job, reason=reason)
                    if reason == "HA_HISTORY_UNAVAILABLE":
                        for remaining in jobs[index + 1:]:
                            self._finish(remaining, reason=reason)
                        break
                await asyncio.sleep(.1)

    async def close(self):
        self._closed = True
        if self.task and not self.task.done():
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)

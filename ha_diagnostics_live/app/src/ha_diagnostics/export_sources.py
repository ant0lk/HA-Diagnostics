"""Finite read-only sources for an owner-requested diagnostic ZIP.

This client lives in the credential worker. It is never exposed as an MCP
tool or an HTTP proxy; the browser can only start the fixed collection plan.
"""
from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import AsyncIterator

import httpx
from pydantic import SecretStr

from .broker import BrokerError, FixedOriginConnect, SLUG_PATTERN
from .export_configuration import ConfigurationDocument, ConfigurationReader
from .export_insights import host_resources

ORIGIN = "http://supervisor"
WS_ORIGIN = "ws://supervisor/core/websocket"
ALL_LOG_ENTRIES = "entries=:0:18446744073709551615"
JSON_LIMIT = 32 * 1024 * 1024
LOG_SOURCES = ("core", "supervisor", "host", "dns", "audio", "cli", "observer", "multicast")
JSON_SOURCES = {
    "system/core": "/core/info", "system/supervisor": "/supervisor/info",
    "system/os": "/os/info", "system/host": "/host/info",
    "system/network": "/network/info", "system/hardware": "/hardware/info",
    "system/resolution": "/resolution/info", "system/boots": "/host/logs/boots",
    "system/dns": "/dns/info", "system/audio": "/audio/info",
    "system/cli": "/cli/info", "system/observer": "/observer/info",
    "system/multicast": "/multicast/info", "system/core_stats": "/core/stats",
    "system/supervisor_stats": "/supervisor/stats",
    "system/host_services": "/host/services", "system/disk_usage": "/host/disks/default/usage",
    "system/swap": "/os/config/swap", "system/jobs": "/jobs/info",
    "system/repositories": "/store/repositories",
    "home_assistant/config": "/core/api/config",
    "home_assistant/states": "/core/api/states",
    "home_assistant/services": "/core/api/services",
    "home_assistant/events": "/core/api/events", "addons/catalog": "/addons",
}
REGISTRY_COMMANDS = {
    "devices": "config/device_registry/list",
    "entities": "config/entity_registry/list",
    "areas": "config/area_registry/list",
    "integrations": "config_entries/get",
    "floors": "config/floor_registry/list", "labels": "config/label_registry/list",
}
ENTRY_ID_PATTERN = r"(?:[a-f0-9]{32}|[0-9A-HJKMNP-TV-Z]{26})"
DEVICE_ID_PATTERN = r"[a-f0-9]{32}"
WS_SOURCES = {"home_assistant/repairs": "repairs/list_issues",
              "home_assistant/notifications": "persistent_notification/get",
              "home_assistant/system_log": "system_log/list", "system/health": "system_health/info",
              "statistics/metadata": "recorder/list_statistic_ids",
              "statistics/issues": "recorder/validate_statistics"}
MAX_TRACE_READS = 200
MAX_DEVICE_READS = 128
MAX_STATISTIC_IDS = 64
WS_TIMEOUT = 90


@dataclass
class SourceResult:
    value: object
    status: str = "ok"
    reason: str | None = None


def bounded_id(value, limit=255):
    return isinstance(value, str) and 0 < len(value) <= limit and not any(ord(c) < 32 for c in value)


def history_interval(start: str, end: str) -> None:
    try:
        a = datetime.fromisoformat(start.replace("Z", "+00:00"))
        b = datetime.fromisoformat(end.replace("Z", "+00:00"))
        if a.tzinfo is None or b.tzinfo is None or not timedelta(0) < b - a <= timedelta(hours=1):
            raise ValueError()
    except (ValueError, TypeError):
        raise BrokerError("INVALID_INTERVAL") from None


class ExportSources:
    def __init__(self, token: str | None, *, transport=None, websocket_connector=FixedOriginConnect,
                 configuration_reader=None, resource_reader=host_resources):
        self._token = SecretStr(token) if token else None
        self._client = httpx.AsyncClient(transport=transport, follow_redirects=False,
            trust_env=False, timeout=httpx.Timeout(60, connect=5))
        self._ws_connector = websocket_connector
        self._configuration_reader = configuration_reader or ConfigurationReader()
        self._resource_reader = resource_reader

    @property
    def available(self) -> bool:
        return bool(self._token)

    def scrub_known_secret(self, text: str) -> str:
        return text.replace(self._token.get_secret_value(), "[SECRET_REDACTED]") if self._token else text

    def _headers(self, log: bool = False) -> dict[str, str]:
        if not self._token:
            raise BrokerError("SOURCE_UNAVAILABLE")
        headers = {"Authorization": "Bearer " + self._token.get_secret_value()}
        if log:
            headers.update({"Accept": "text/x-log", "Range": ALL_LOG_ENTRIES})
        return headers

    @staticmethod
    def validate_request(method: str, path: str, params: dict, log: bool) -> None:
        if method != "GET" or any(c in path for c in ("?", "#", "%", "\\")) or ".." in path:
            raise BrokerError("OPERATION_DENIED")
        if log:
            allowed = path in {f"/{s}/logs" for s in LOG_SOURCES} or bool(
                re.fullmatch(r"/addons/[a-z0-9][a-z0-9_-]{0,127}/logs", path))
            if allowed and params == {"no_colors": ""}:
                return
        elif not params and (path in JSON_SOURCES.values() or re.fullmatch(
                r"/addons/[a-z0-9][a-z0-9_-]{0,127}/(?:info|stats)", path) or re.fullmatch(
                r"/core/api/diagnostics/config_entry/" + ENTRY_ID_PATTERN +
                r"(?:/device/" + DEVICE_ID_PATTERN + r")?", path)):
            return
        elif not log:
            match = re.fullmatch(r"/core/api/(history/period|logbook)/(.+)", path)
            if match and params == {"end_time": params.get("end_time")}:
                history_interval(match[2], params["end_time"])
                return
        raise BrokerError("OPERATION_DENIED")

    @staticmethod
    def _check_response(response: httpx.Response) -> None:
        if response.status_code in {401, 403}:
            raise BrokerError("PERMISSION_DENIED")
        if 300 <= response.status_code < 400:
            raise BrokerError("UPSTREAM_REDIRECT_DENIED")
        if response.status_code == 404:
            raise BrokerError("NOT_SUPPORTED")
        if not 200 <= response.status_code < 300:
            raise BrokerError("UPSTREAM_UNAVAILABLE")

    async def _json(self, path: str, params: dict | None = None):
        params = params or {}
        self.validate_request("GET", path, params, False)
        try:
            async with asyncio.timeout(90), self._client.stream("GET", ORIGIN + path,
                    params=params, headers=self._headers()) as response:
                self._check_response(response)
                body = bytearray()
                async for chunk in response.aiter_bytes(65536):
                    body.extend(chunk)
                    if len(body) > JSON_LIMIT:
                        raise BrokerError("UPSTREAM_LIMIT")
                value = json.loads(body)
                if isinstance(value, dict) and value.get("result") == "error":
                    raise BrokerError("UPSTREAM_UNAVAILABLE")
                if isinstance(value, dict) and "result" in value and "data" in value:
                    if value["result"] != "ok":
                        raise BrokerError("UPSTREAM_UNAVAILABLE")
                    value = value["data"]
                return value
        except BrokerError:
            raise
        except (ValueError, RecursionError):
            raise BrokerError("UPSTREAM_FORMAT") from None
        except Exception:
            raise BrokerError("UPSTREAM_UNAVAILABLE") from None

    async def snapshot(self, label: str):
        if label not in JSON_SOURCES:
            raise BrokerError("OPERATION_DENIED")
        return await self._json(JSON_SOURCES[label])

    async def addon(self, slug: str, kind: str):
        if not re.fullmatch(SLUG_PATTERN, slug) or slug == "self" or kind not in {"info", "stats"}:
            raise BrokerError("OPERATION_DENIED")
        return await self._json(f"/addons/{slug}/{kind}")

    async def integration(self, entry_id: str):
        if not re.fullmatch(ENTRY_ID_PATTERN, entry_id):
            raise BrokerError("OPERATION_DENIED")
        return await self._json("/core/api/diagnostics/config_entry/" + entry_id)

    async def configurations(self):
        self._headers()  # Never read the live mount in import-only mode.
        return await asyncio.to_thread(self._configuration_reader.collect)

    async def resources(self):
        self._headers()
        value = await asyncio.to_thread(self._resource_reader)
        if not any(row.get("status") == "ok" for row in value.get("sources", {}).values()):
            raise BrokerError("RESOURCE_UNAVAILABLE")
        return value

    async def device(self, entry_id, device_id):
        if not re.fullmatch(ENTRY_ID_PATTERN, entry_id) or not re.fullmatch(DEVICE_ID_PATTERN, device_id):
            raise BrokerError("OPERATION_DENIED")
        return await self._json(f"/core/api/diagnostics/config_entry/{entry_id}/device/{device_id}")

    async def supplemental(self, label):
        if label not in WS_SOURCES:
            raise BrokerError("OPERATION_DENIED")
        result = await self._websocket({"type": WS_SOURCES[label]})
        value = result.value if isinstance(result, SourceResult) else result
        expected = dict if label in {"home_assistant/repairs", "system/health", "statistics/issues"} else list
        if not isinstance(value, expected) or label == "home_assistant/repairs" and not isinstance(value.get("issues"), list):
            raise BrokerError("UPSTREAM_FORMAT")
        return result

    async def traces(self, domain):
        result = await self._websocket({"type": "trace/list", "domain": domain})
        if not isinstance(result, list):
            raise BrokerError("UPSTREAM_FORMAT")
        return result

    async def trace(self, domain, item_id, run_id):
        result = await self._websocket({"type": "trace/get", "domain": domain, "item_id": item_id, "run_id": run_id})
        if not isinstance(result, dict):
            raise BrokerError("UPSTREAM_FORMAT")
        return result

    async def statistics(self, ids, start, end):
        result = await self._websocket({"type": "recorder/statistics_during_period", "statistic_ids": ids,
                                     "start_time": start, "end_time": end, "period": "day"})
        if not isinstance(result, dict):
            raise BrokerError("UPSTREAM_FORMAT")
        return result

    async def history(self, kind: str, start: str, end: str):
        if kind not in {"history", "logbook"}:
            raise BrokerError("OPERATION_DENIED")
        history_interval(start, end)
        prefix = "history/period" if kind == "history" else "logbook"
        return await self._json(f"/core/api/{prefix}/{start}", {"end_time": end})

    async def logs(self, source: str) -> AsyncIterator[bytes]:
        if source in LOG_SOURCES:
            path = f"/{source}/logs"
        elif source.startswith("addon:") and re.fullmatch(SLUG_PATTERN, source[6:]) and source[6:] != "self":
            path = f"/addons/{source[6:]}/logs"
        else:
            raise BrokerError("OPERATION_DENIED")
        params = {"no_colors": ""}
        self.validate_request("GET", path, params, True)
        try:
            async with asyncio.timeout(300), self._client.stream("GET", ORIGIN + path,
                    params=params, headers=self._headers(log=True)) as response:
                self._check_response(response)
                async for chunk in response.aiter_bytes(65536):
                    yield chunk
        except BrokerError:
            raise
        except TimeoutError:
            raise BrokerError("SOURCE_TIMEOUT") from None
        except Exception:
            raise BrokerError("CONNECTION_LOST") from None

    async def registry(self, label: str):
        if label not in REGISTRY_COMMANDS:
            raise BrokerError("OPERATION_DENIED")
        value = await self._websocket({"type": REGISTRY_COMMANDS[label]})
        if not isinstance(value, list):
            raise BrokerError("UPSTREAM_FORMAT")
        return value

    @staticmethod
    def validate_websocket(command):
        kind = command.get("type")
        if kind in {*REGISTRY_COMMANDS.values(), *WS_SOURCES.values()} and set(command) == {"type"}:
            return
        if kind in {"trace/list", "trace/get"} and command.get("domain") in {"automation", "script"}:
            if kind == "trace/list" and set(command) == {"type", "domain"}:
                return
            if kind == "trace/get" and set(command) == {"type", "domain", "item_id", "run_id"} and all(
                    bounded_id(command.get(key), 128) for key in ("item_id", "run_id")):
                return
        if kind == "recorder/statistics_during_period" and set(command) == {
                "type", "statistic_ids", "start_time", "end_time", "period"} and command.get("period") == "day":
            ids = command["statistic_ids"]
            if isinstance(ids, list) and 0 < len(ids) <= MAX_STATISTIC_IDS and all(bounded_id(i) for i in ids):
                try:
                    start = datetime.fromisoformat(command["start_time"].replace("Z", "+00:00"))
                    end = datetime.fromisoformat(command["end_time"].replace("Z", "+00:00"))
                    if start.tzinfo and end.tzinfo and timedelta(0) < end - start <= timedelta(days=7):
                        return
                except (ValueError, TypeError, AttributeError):
                    pass
        raise BrokerError("OPERATION_DENIED")

    async def _websocket(self, command):
        self.validate_websocket(command)
        self._headers()
        health = None
        received = 0
        try:
            async with asyncio.timeout(WS_TIMEOUT), self._ws_connector(WS_ORIGIN, max_size=JSON_LIMIT, max_queue=1,
                    open_timeout=5, close_timeout=3, proxy=None) as ws:
                async def receive():
                    nonlocal received
                    body = await ws.recv()
                    received += len(body.encode() if isinstance(body, str) else body)
                    if received > JSON_LIMIT:
                        raise BrokerError("UPSTREAM_LIMIT")
                    result = json.loads(body)
                    if not isinstance(result, dict):
                        raise BrokerError("UPSTREAM_FORMAT")
                    return result
                required = await receive()
                if required.get("type") != "auth_required":
                    raise BrokerError("UPSTREAM_FORMAT")
                await ws.send(json.dumps({"type": "auth", "access_token": self._token.get_secret_value()}))
                ack = await receive()
                if ack.get("type") != "auth_ok":
                    raise BrokerError("PERMISSION_DENIED")
                await ws.send(json.dumps({"id": 1, **command}))
                result = await receive()
                if result.get("id") != 1 or result.get("type") != "result":
                    raise BrokerError("UPSTREAM_FORMAT")
                if result.get("success") is not True:
                    error = result.get("error") or {}
                    raise BrokerError("PERMISSION_DENIED" if isinstance(error, dict) and error.get("code") in {
                        "unauthorized", "forbidden"} else "NOT_SUPPORTED")
                if command["type"] != "system_health/info":
                    return result.get("result")
                for _ in range(4096):
                    event = await receive()
                    if event.get("id") != 1 or event.get("type") != "event" or not isinstance(event.get("event"), dict):
                        raise BrokerError("UPSTREAM_FORMAT")
                    event = event["event"]
                    kind = event.get("type")
                    if kind == "initial" and health is None and isinstance(event.get("data"), dict):
                        health = event["data"]
                    elif kind == "update" and health is not None:
                        domain, key = event.get("domain"), event.get("key")
                        if not isinstance(health.get(domain), dict) or not isinstance(health[domain].get("info"), dict) or not isinstance(key, str):
                            raise BrokerError("UPSTREAM_FORMAT")
                        health[domain]["info"][key] = event.get("data") if event.get("success") is True else {
                            "type": "failed", "error": "upstream_check_failed"}
                    elif kind == "finish" and health is not None:
                        return health
                    else:
                        raise BrokerError("UPSTREAM_FORMAT")
                raise BrokerError("UPSTREAM_LIMIT")
        except BrokerError as error:
            if health is not None:
                return SourceResult(health, "partial", error.code)
            raise
        except TimeoutError:
            if health is not None:
                return SourceResult(health, "partial", "SOURCE_TIMEOUT")
            raise BrokerError("SOURCE_TIMEOUT") from None
        except Exception:
            if health is not None:
                return SourceResult(health, "partial", "CONNECTION_LOST")
            raise BrokerError("UPSTREAM_UNAVAILABLE") from None

    async def close(self):
        self._token = None
        await self._client.aclose()


class DemoExportSources:
    """Explicitly labelled fixtures; never attempts to contact Home Assistant."""
    available = True
    scrub_known_secret = staticmethod(lambda text: text)

    async def snapshot(self, label):
        if label == "addons/catalog":
            return {"addons": [{"slug": "fixture_matter", "name": "Demo Matter", "installed": True}]}
        if label == "home_assistant/states":
            return [{"entity_id": "sensor.demo", "state": "unavailable", "attributes": {"unit_of_measurement": "W"}}]
        return {"demo": True, "version": "fixture", "time_zone": "Asia/Tomsk",
                "components": ["demo", "automation", "recorder"]}

    async def registry(self, label):
        return [{"entity_id": "sensor.demo", "platform": "demo"}] if label == "entities" else []

    async def addon(self, slug, kind):
        return {"slug": slug, "state": "started", "demo": True, "boot": "auto",
                "watchdog": True, "network": {"5580/tcp": 5580},
                "options": {"log_level": "info", "enable_feature": False, "password": "demo-hidden"},
                "schema": {"log_level": "str", "enable_feature": "bool", "password": "password"}}

    async def configurations(self):
        return [ConfigurationDocument("configuration/home_assistant/yaml/001", "configuration.yaml",
                {"source_path": "configuration.yaml", "demo": True,
                 "configuration": {"default_config": None, "recorder": {"purge_keep_days": 10},
                    "automation": {"yaml_tag": "!include", "value": "automations.yaml"}}}),
                ConfigurationDocument("configuration/integrations/entries", ".storage/core.config_entries",
                {"source_path": ".storage/core.config_entries", "demo": True, "configuration": {"entries": [
                    {"entry_id": "01JABCDEFGHJKMNPQRSTVWXYZ1", "domain": "demo", "source": "user",
                     "data": {"host": "demo-host", "password": "demo-hidden"},
                     "options": {"scan_interval": 30, "enabled": False}}]}})]

    async def resources(self):
        return {"demo": True, "scope": "fixture", "cpu": {"logical_processors": 4, "models": ["Demo CPU"]},
                "memory": {"total_bytes": 8 * 1024 ** 3}, "container_limits": {}, "sources": {}}

    async def supplemental(self, label):
        if label == "home_assistant/repairs":
            return {"issues": []}
        if label == "statistics/issues":
            return {}
        if label == "system/health":
            return {"homeassistant": {"info": {"version": "fixture", "installation_type": "Home Assistant OS"}}}
        return []

    async def traces(self, domain):
        return []

    async def trace(self, domain, item_id, run_id):
        return {"demo": True, "domain": domain, "item_id": item_id, "run_id": run_id}

    async def device(self, entry_id, device_id):
        return {"demo": True}

    async def statistics(self, ids, start, end):
        return {}

    async def integration(self, entry_id):
        return {"demo": True}

    async def history(self, kind, start, end):
        if kind == "history":
            return [[{"entity_id": "sensor.demo", "state": "unavailable", "last_changed": start}]]
        return [{"when": start, "entity_id": "sensor.demo", "message": "Demo device unavailable"}]

    async def logs(self, source):
        now = datetime.now(timezone.utc).isoformat()
        yield (f"{now} INFO Demo log: {source}\n{now} ERROR Demo failure token=fixture-secret\n").encode()

    async def close(self):
        pass

"""Trusted finite read adapters. No remote caller can choose a URL or route.

The manager token is broad: this module limits protocol requests, not arbitrary
code execution in this process. Keep this module in the separate broker UID.
"""
from __future__ import annotations

import asyncio
import codecs
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, AsyncIterator, Callable, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr, TypeAdapter, field_validator, model_validator
from websockets.asyncio.client import connect
from websockets.exceptions import InvalidStatus

SUPERVISOR_URL = "http://supervisor"
CORE_WEBSOCKET_URL = "ws://supervisor/core/websocket"
MAX_LOG_BYTES = 20 * 1024 * 1024
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_LINES = 50_000
ENTITY_PATTERN = r"^[a-z][a-z0-9_]*\.[a-z0-9_]+$"
SLUG_PATTERN = r"^[a-z0-9][a-z0-9_-]{0,127}$"


class BrokerError(Exception):
    """Only a fixed safe code is exposed, never an upstream message/URL."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class FixedOriginConnect(connect):
    """Never follow a handshake redirect before exchanging HA credentials."""

    def process_redirect(self, exc: Exception) -> Exception | str:
        if isinstance(exc, InvalidStatus) and 300 <= exc.response.status_code < 400:
            return BrokerError("UPSTREAM_REDIRECT_DENIED")
        return exc


@dataclass
class BrokerPolicy:
    mode: Literal["import_only", "live"] = "import_only"
    enabled_sources: set[str] = field(default_factory=set)
    addon_slugs: set[str] = field(default_factory=set)
    entity_ids: set[str] = field(default_factory=set)
    collect: bool = True
    disclose_names: bool = False
    version: int = 1

    def validate(self) -> None:
        if self.mode not in {"import_only", "live"}:
            raise BrokerError("POLICY_INVALID")
        if len(self.entity_ids) > 1000 or len(self.addon_slugs) > 100:
            raise BrokerError("POLICY_INVALID")
        if any(not re.fullmatch(ENTITY_PATTERN, v) for v in self.entity_ids):
            raise BrokerError("POLICY_INVALID")
        if any(not re.fullmatch(SLUG_PATTERN, v) or v == "self" for v in self.addon_slugs):
            raise BrokerError("POLICY_INVALID")
        valid = {"core", "supervisor", "entities", "metadata"} | {f"addon:{v}" for v in self.addon_slugs}
        if not self.enabled_sources <= valid:
            raise BrokerError("POLICY_INVALID")


class StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class MetadataRead(StrictRequest):
    op: Literal["metadata"]


class AddonCatalogRead(StrictRequest):
    op: Literal["addon_catalog"]


class DeviceCatalogRead(StrictRequest):
    op: Literal["device_catalog"]


class EntityCatalogRead(StrictRequest):
    op: Literal["entity_catalog"]


class BootRead(StrictRequest):
    op: Literal["boots"]


class LogRead(StrictRequest):
    op: Literal["logs"]
    source_id: str = Field(min_length=1, max_length=140)
    lines: int = Field(default=MAX_LINES, ge=1000, le=MAX_LINES)
    boot_id: str | None = Field(default=None, pattern=r"^(?:0|[0-9a-f]{32})$")


class StateRead(StrictRequest):
    op: Literal["states"]
    entity_ids: list[Annotated[str, Field(pattern=ENTITY_PATTERN)]] = Field(min_length=1, max_length=1000)


class HistoryRead(StrictRequest):
    op: Literal["history"]
    entity_ids: list[Annotated[str, Field(pattern=ENTITY_PATTERN)]] = Field(min_length=1, max_length=20)
    from_: str = Field(alias="from", max_length=40)
    to: str = Field(max_length=40)

    @field_validator("from_", "to")
    @classmethod
    def explicit_time(cls, value: str) -> str:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("ISO8601 time required") from None
        if parsed.tzinfo is None:
            raise ValueError("explicit timezone required")
        return parsed.astimezone(timezone.utc).isoformat()

    @model_validator(mode="after")
    def interval(self) -> HistoryRead:
        span = datetime.fromisoformat(self.to) - datetime.fromisoformat(self.from_)
        if span <= timedelta(0) or span > timedelta(hours=1):
            raise ValueError("history interval must be within one hour")
        return self


BrokerRequest = Annotated[MetadataRead | AddonCatalogRead | DeviceCatalogRead | EntityCatalogRead | BootRead | LogRead | StateRead | HistoryRead, Field(discriminator="op")]
REQUEST_ADAPTER = TypeAdapter(BrokerRequest)


class ReadBroker:
    """Only the broker holds HA credentials. The query worker reads its archive.

    Inject an HTTP transport/WebSocket connector for tests, never a destination
    from IPC/MCP. Destination is deliberately fixed to HA's internal proxy.
    """

    def __init__(self, policy: BrokerPolicy | Callable[[], BrokerPolicy], redactor: Any,
                 token: str | None = None, *, transport: httpx.AsyncBaseTransport | None = None,
                 websocket_connector: Callable[..., Any] = FixedOriginConnect):
        self._policy_provider = policy if callable(policy) else lambda: policy
        initial = self.policy
        self._token = SecretStr(token) if token and initial.mode == "live" else None
        self.redactor = redactor
        self._client = httpx.AsyncClient(transport=transport, follow_redirects=False, trust_env=False,
                                       timeout=httpx.Timeout(30.0, connect=5.0), limits=httpx.Limits(max_connections=8))
        self._ws_connector = websocket_connector

    @property
    def policy(self) -> BrokerPolicy:
        value = self._policy_provider()
        value.validate()
        if value.mode != "live" and hasattr(self, "_token"):
            self._token = None
        return value

    async def close(self) -> None:
        self._token = None
        await self._client.aclose()

    def _live(self) -> BrokerPolicy:
        policy = self.policy
        if policy.mode != "live" or not self._token:
            raise BrokerError("SOURCE_UNAVAILABLE")
        return policy

    def _source(self, source_id: str) -> str:
        policy = self._live()
        if not policy.collect or source_id not in policy.enabled_sources:
            raise BrokerError("SOURCE_DENIED")
        if source_id in {"core", "supervisor"}:
            return f"/{source_id}/logs"
        if source_id.startswith("addon:"):
            slug = source_id[6:]
            if slug in policy.addon_slugs and re.fullmatch(SLUG_PATTERN, slug):
                return f"/addons/{slug}/logs"
        raise BrokerError("SOURCE_DENIED")

    def _entities(self, entity_ids: list[str]) -> BrokerPolicy:
        policy = self._live()
        if not policy.collect or "entities" not in policy.enabled_sources:
            raise BrokerError("SOURCE_DENIED")
        if not entity_ids or not set(entity_ids) <= policy.entity_ids:
            raise BrokerError("SOURCE_DENIED")
        if any(not re.fullmatch(ENTITY_PATTERN, v) for v in entity_ids):
            raise BrokerError("SOURCE_DENIED")
        return policy

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        self._live()
        assert self._token is not None
        return {"Authorization": "Bearer " + self._token.get_secret_value(), **(extra or {})}

    def _validate_request(self, method: str, path: str, params: dict[str, str], headers: dict[str, str]) -> None:
        """Defense in depth at the final network boundary, not just tool schema."""
        self._live()
        if method != "GET" or any(c in path for c in ("?", "#", "%", "\\")) or ".." in path:
            raise BrokerError("OPERATION_DENIED")
        if set(headers) - {"Authorization", "Accept", "Range"}:
            raise BrokerError("OPERATION_DENIED")
        fixed = {"/core/info", "/supervisor/info", "/os/info", "/host/info", "/core/api/config", "/core/api/states", "/addons", "/host/logs/boots"}
        if path in fixed:
            if params or set(headers) - {"Authorization"}:
                raise BrokerError("OPERATION_DENIED")
            if path in {"/core/info", "/supervisor/info", "/os/info", "/host/info", "/core/api/config"} and "metadata" not in self.policy.enabled_sources:
                raise BrokerError("SOURCE_DENIED")
            if path == "/host/logs/boots" and not self.policy.enabled_sources:
                raise BrokerError("SOURCE_DENIED")
            return
        match = re.fullmatch(r"(/core/logs|/supervisor/logs|/addons/([a-z0-9_-]+)/logs)(?:/boots/(0|[0-9a-f]{32}))?(/follow)?", path)
        if match:
            base, slug, _, _ = match.groups()
            source = f"addon:{slug}" if slug else base.split("/")[1]
            self._source(source)
            if params != {"no_colors": ""} or headers.get("Accept") != "text/x-log":
                raise BrokerError("OPERATION_DENIED")
            if not re.fullmatch(r"entries=:-[0-9]{1,5}:[0-9]{1,5}", headers.get("Range", "")):
                raise BrokerError("OPERATION_DENIED")
            skip, count = map(int, headers["Range"].removeprefix("entries=:-").split(":"))
            if not 1000 <= count <= MAX_LINES or skip != count - 1:
                raise BrokerError("OPERATION_DENIED")
            return
        if path.startswith("/core/api/states/"):
            entity = path.removeprefix("/core/api/states/")
            self._entities([entity])
            if not params and set(headers) == {"Authorization"}:
                return
        if path.startswith("/core/api/history/period/"):
            if set(params) != {"filter_entity_id", "end_time", "no_attributes"} or params["no_attributes"] != "":
                raise BrokerError("OPERATION_DENIED")
            self._entities(params["filter_entity_id"].split(","))
            try:
                HistoryRead(op="history", entity_ids=params["filter_entity_id"].split(","),
                            **{"from": path.removeprefix("/core/api/history/period/"), "to": params["end_time"]})
            except ValueError:
                raise BrokerError("OPERATION_DENIED") from None
            if set(headers) == {"Authorization"}:
                return
        raise BrokerError("OPERATION_DENIED")

    async def _get(self, path: str, *, params: dict[str, str] | None = None,
                   extra_headers: dict[str, str] | None = None, text: bool = False) -> tuple[Any, bool]:
        params = params or {}
        headers = self._headers(extra_headers)
        self._validate_request("GET", path, params, headers)
        cap = MAX_LOG_BYTES if text else MAX_JSON_BYTES
        try:
            async with self._client.stream("GET", SUPERVISOR_URL + path, params=params, headers=headers) as response:
                if 300 <= response.status_code < 400:
                    raise BrokerError("UPSTREAM_REDIRECT_DENIED")
                if response.status_code in {401, 403}:
                    raise BrokerError("PERMISSION_DENIED")
                if response.status_code == 404:
                    raise BrokerError("SOURCE_UNAVAILABLE")
                if not 200 <= response.status_code < 300:
                    raise BrokerError("UPSTREAM_UNAVAILABLE")
                chunks = bytearray()
                truncated = False
                async for chunk in response.aiter_bytes():
                    self._validate_request("GET", path, params, headers)
                    if len(chunks) + len(chunk) > cap:
                        chunks.extend(chunk[:cap - len(chunks)])
                        truncated = True
                        break
                    chunks.extend(chunk)
                if truncated and not text:
                    raise BrokerError("UPSTREAM_LIMIT")
                self._validate_request("GET", path, params, headers)
                if text:
                    return self.redactor.clean_text(self._known_text(bytes(chunks).decode("utf-8", errors="replace")), max_chars=None), truncated
                result = json.loads(chunks)
                if isinstance(result, dict) and "result" in result and "data" in result:
                    if result["result"] != "ok":
                        raise BrokerError("UPSTREAM_UNAVAILABLE")
                    result = result["data"]
                return result, truncated
        except BrokerError:
            raise
        except (httpx.HTTPError, json.JSONDecodeError, UnicodeError, ValueError):
            raise BrokerError("UPSTREAM_UNAVAILABLE") from None

    def _safe_fields(self, value: dict[str, Any], fields: set[str]) -> dict[str, Any]:
        safe = {k: self._known_values(value[k]) for k in fields if k in value}
        return self.redactor.clean_json(safe, approved_fields=fields)

    def _known_text(self, value: str) -> str:
        if self._token and self._token.get_secret_value():
            return value.replace(self._token.get_secret_value(), "[SECRET_REDACTED]")
        return value

    def _known_values(self, value: Any) -> Any:
        if isinstance(value, str):
            return self._known_text(value)
        if isinstance(value, list):
            return [self._known_values(v) for v in value]
        if isinstance(value, dict):
            return {self._known_text(k): self._known_values(v) for k, v in value.items()}
        return value

    def ref(self, kind: str, value: Any) -> str:
        """Machine-safe stable IDs derived from the same local correlation key."""
        prefix = {"entity": "ent", "device": "dev", "integration": "int", "context": "ctx"}[kind]
        digest = self.redactor.alias(kind, value).rsplit("_", 1)[-1].strip("]")
        return f"{prefix}_{digest}"

    async def execute(self, payload: dict[str, Any]) -> Any:
        try:
            request = REQUEST_ADAPTER.validate_python(payload)
        except ValueError:
            raise BrokerError("INVALID_REQUEST") from None
        self._live()
        if isinstance(request, LogRead):
            path = self._source(request.source_id)
            if request.boot_id:
                path += "/boots/" + request.boot_id
            value, truncated = await self._get(path, params={"no_colors": ""}, extra_headers={"Accept": "text/x-log", "Range": f"entries=:-{request.lines - 1}:{request.lines}"}, text=True)
            lines = value.splitlines(keepends=True)
            if len(lines) > request.lines:
                lines = lines[-request.lines:]
                truncated = True
            return {"text": "".join(lines), "truncated": truncated, "cursor": None,
                    "deduplication_basis": "ordered_overlap_without_upstream_cursor"}
        if isinstance(request, MetadataRead):
            if "metadata" not in self.policy.enabled_sources:
                raise BrokerError("SOURCE_DENIED")
            data: dict[str, Any] = {}
            fields = {"version", "arch", "state", "time_zone", "timezone", "operating_system", "machine", "supported"}
            for label, path in (("core", "/core/info"), ("supervisor", "/supervisor/info"), ("os", "/os/info"), ("host", "/host/info"), ("config", "/core/api/config")):
                if "metadata" not in self.policy.enabled_sources:
                    raise BrokerError("SOURCE_DENIED")
                try:
                    value, _ = await self._get(path)
                    data[label] = self._safe_fields(value, fields) if isinstance(value, dict) else {}
                except BrokerError as exc:
                    data[label] = {"error": exc.code}
            if "metadata" not in self._live().enabled_sources:
                raise BrokerError("SOURCE_DENIED")
            return data
        if isinstance(request, AddonCatalogRead):
            value, _ = await self._get("/addons")
            addons = value.get("addons", []) if isinstance(value, dict) else []
            return [self._safe_fields(v, {"slug", "name", "version", "state", "installed"}) for v in addons[:100] if isinstance(v, dict) and re.fullmatch(SLUG_PATTERN, str(v.get("slug", "")))]
        if isinstance(request, EntityCatalogRead):
            # Local owner discovery, not an MCP operation. No state/attributes
            # or sensitive domain leaves this read adapter's finite projection.
            from .policy import SENSITIVE_DOMAINS
            values, _ = await self._get("/core/api/states")
            if not isinstance(values, list):
                raise BrokerError("UPSTREAM_FORMAT")
            entities = []
            for state in values:
                if not isinstance(state, dict):
                    continue
                entity = state.get("entity_id", "")
                if not isinstance(entity, str) or not re.fullmatch(ENTITY_PATTERN, entity) or entity.split(".")[0] in SENSITIVE_DOMAINS:
                    continue
                entities.append({"entity_id": entity, "entity_ref": self.ref("entity", entity), "domain": entity.split(".")[0]})
            return {"entities": entities[:1000], "truncated": len(entities) > 1000,
                    "excluded_domains": sorted(SENSITIVE_DOMAINS)}
        if isinstance(request, BootRead):
            if not self.policy.enabled_sources & {"core", "supervisor", "metadata"} and not any(v.startswith("addon:") for v in self.policy.enabled_sources):
                raise BrokerError("SOURCE_DENIED")
            value, _ = await self._get("/host/logs/boots")
            if not isinstance(value, dict):
                raise BrokerError("UPSTREAM_FORMAT")
            return {str(k): v for k, v in value.items() if re.fullmatch(r"-?[0-9]{1,4}", str(k)) and isinstance(v, str) and re.fullmatch(r"[0-9a-f]{32}", v)}
        if isinstance(request, StateRead):
            self._entities(request.entity_ids)
            states = []
            for entity_id in request.entity_ids:
                value, _ = await self._get("/core/api/states/" + entity_id)
                states.append(self.safe_state(value))
            return states
        if isinstance(request, HistoryRead):
            self._entities(request.entity_ids)
            value, _ = await self._get("/core/api/history/period/" + request.from_, params={"filter_entity_id": ",".join(request.entity_ids), "end_time": request.to, "no_attributes": ""})
            if not isinstance(value, list):
                raise BrokerError("UPSTREAM_FORMAT")
            start, end = datetime.fromisoformat(request.from_), datetime.fromisoformat(request.to)
            result = []
            for sequence in value:
                if not isinstance(sequence, list):
                    continue
                previous = None
                for state in sequence:
                    if not isinstance(state, dict) or state.get("entity_id") not in request.entity_ids:
                        continue
                    try:
                        when = datetime.fromisoformat(str(state.get("last_updated", state.get("last_changed", ""))).replace("Z", "+00:00"))
                    except ValueError:
                        continue
                    if when.tzinfo is None or when >= end:
                        continue
                    safe = self.safe_state(state)
                    if when < start:
                        previous = safe
                    else:
                        result.append({**safe, "boundary_state": False})
                if previous is not None:
                    result.append({**previous, "boundary_state": True})
            return {"states": result, "coverage_status": "unknown", "reason": "recorder_retention_and_exclusions_unknown"}
        if isinstance(request, DeviceCatalogRead):
            return await self._catalog()
        raise BrokerError("OPERATION_DENIED")

    def safe_state(self, value: Any) -> dict[str, Any]:
        if not isinstance(value, dict) or not isinstance(value.get("entity_id"), str):
            raise BrokerError("UPSTREAM_FORMAT")
        entity_id = value["entity_id"]
        self._entities([entity_id])
        result = self._safe_fields(value, {"state", "last_changed", "last_updated"})
        result["entity_ref"] = self.ref("entity", entity_id)
        safe_attributes = {"unit_of_measurement", "device_class", "state_class"}
        attrs = value.get("attributes", {})
        result["safe_attributes"] = self._safe_fields(attrs, safe_attributes) if isinstance(attrs, dict) else {}
        context = value.get("context")
        if isinstance(context, dict) and context.get("id"):
            result["context_ref"] = self.ref("context", str(context["id"]))
        return result

    async def _open_ws(self) -> Any:
        self._live()
        return self._ws_connector(CORE_WEBSOCKET_URL, max_size=MAX_JSON_BYTES, max_queue=32,
                                  open_timeout=5, close_timeout=3, ping_interval=20, proxy=None)

    async def _auth_ws(self, ws: Any) -> None:
        self._live()
        required = json.loads(await asyncio.wait_for(ws.recv(), 10))
        if required.get("type") != "auth_required":
            raise BrokerError("UPSTREAM_FORMAT")
        self._live()
        assert self._token is not None
        await ws.send(json.dumps({"type": "auth", "access_token": self._token.get_secret_value()}))
        result = json.loads(await asyncio.wait_for(ws.recv(), 10))
        if result.get("type") != "auth_ok":
            raise BrokerError("PERMISSION_DENIED")

    async def _catalog(self) -> dict[str, Any]:
        policy = self._live()
        if "entities" not in policy.enabled_sources:
            raise BrokerError("SOURCE_DENIED")
        result: dict[str, Any] = {}
        commands = {"devices": "config/device_registry/list", "entities": "config/entity_registry/list", "areas": "config/area_registry/list", "integrations": "config_entries/get"}
        fields = {"devices": {"id", "area_id", "config_entries", "config_entry_id", "manufacturer", "model", "sw_version", "disabled_by"}, "entities": {"entity_id", "device_id", "config_entry_id", "platform", "disabled_by", "area_id"}, "areas": {"area_id"}, "integrations": {"entry_id", "domain", "state", "disabled_by"}}
        if policy.disclose_names:
            for allowed in fields.values():
                allowed.update({"name", "name_by_user", "original_name", "title"})
        try:
            async with await self._open_ws() as ws:
                await self._auth_ws(ws)
                for index, (label, command) in enumerate(commands.items(), 1):
                    if "entities" not in self.policy.enabled_sources:
                        raise BrokerError("SOURCE_DENIED")
                    await ws.send(json.dumps({"id": index, "type": command}))
                    response = json.loads(await asyncio.wait_for(ws.recv(), 10))
                    if "entities" not in self._live().enabled_sources:
                        raise BrokerError("SOURCE_DENIED")
                    if response.get("id") != index or response.get("type") != "result" or response.get("success") is not True:
                        raise BrokerError("UPSTREAM_FORMAT")
                    values = response.get("result", [])
                    if not isinstance(values, list) or len(values) > 10000:
                        raise BrokerError("UPSTREAM_LIMIT")
                    rows = []
                    for value in values:
                        if not isinstance(value, dict):
                            continue
                        safe = self._safe_fields(value, fields[label])
                        # Native registry IDs stay only inside trusted catalog /
                        # local owner discovery. Collector emits machine refs.
                        for native_id in {"id", "entity_id", "device_id", "entry_id", "config_entry_id", "area_id"} & fields[label]:
                            if isinstance(value.get(native_id), str):
                                safe[native_id] = self._known_text(value[native_id])
                        rows.append(safe)
                    result[label] = rows
        except BrokerError:
            raise
        except Exception:
            raise BrokerError("UPSTREAM_UNAVAILABLE") from None
        # Filter all metadata to the selected entities before it reaches archive.
        if "entities" not in self._live().enabled_sources:
            raise BrokerError("SOURCE_DENIED")
        result["entities"] = [e for e in result["entities"] if e.get("entity_id") in self.policy.entity_ids]
        device_ids = {e.get("device_id") for e in result["entities"]}
        result["devices"] = [d for d in result["devices"] if d.get("id") in device_ids]
        entry_ids = {e.get("config_entry_id") for e in result["entities"]}
        area_ids = {e.get("area_id") for e in result["entities"]} | {d.get("area_id") for d in result["devices"]}
        result["integrations"] = [e for e in result["integrations"] if e.get("entry_id") in entry_ids]
        result["areas"] = [a for a in result["areas"] if a.get("area_id") in area_ids]
        return result

    async def follow_logs(self, source_id: str, *, boot_id: str | None = None) -> AsyncIterator[str]:
        """Complete cleaned lines, bounded pending buffer, read policy per chunk."""
        request = LogRead(op="logs", source_id=source_id, boot_id=boot_id)
        path = self._source(source_id) + ("/boots/" + boot_id if boot_id else "") + "/follow"
        headers = self._headers({"Accept": "text/x-log", "Range": f"entries=:-{request.lines - 1}:{request.lines}"})
        params = {"no_colors": ""}
        self._validate_request("GET", path, params, headers)
        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        pending = ""
        try:
            async with self._client.stream("GET", SUPERVISOR_URL + path, params=params, headers=headers, timeout=httpx.Timeout(35, connect=5)) as response:
                if response.status_code in {401, 403}:
                    raise BrokerError("PERMISSION_DENIED")
                if 300 <= response.status_code < 400:
                    raise BrokerError("UPSTREAM_REDIRECT_DENIED")
                if not 200 <= response.status_code < 300:
                    raise BrokerError("UPSTREAM_UNAVAILABLE")
                async for chunk in response.aiter_bytes(chunk_size=65536):
                    self._source(source_id)
                    pending += decoder.decode(chunk)
                    if len(pending) > 1024 * 1024:
                        raise BrokerError("UPSTREAM_LIMIT")
                    while "\n" in pending:
                        line, pending = pending.split("\n", 1)
                        yield self.redactor.clean_text(self._known_text(line + "\n"), max_chars=None)
                pending += decoder.decode(b"", final=True)
                if pending:
                    yield self.redactor.clean_text(self._known_text(pending), max_chars=None)
        except BrokerError:
            raise
        except Exception:
            raise BrokerError("CONNECTION_LOST") from None

    async def watch_entities(self, entity_ids: list[str]) -> AsyncIterator[dict[str, Any]]:
        """Selected atomic snapshot + state changes from subscribe_entities.

        Emits compressed messages for the trusted collector only; attributes are
        removed before output. Initial snapshots never become fake transitions.
        """
        self._entities(entity_ids)
        try:
            async with await self._open_ws() as ws:
                await self._auth_ws(ws)
                self._entities(entity_ids)
                await ws.send(json.dumps({"id": 1, "type": "subscribe_entities", "entity_ids": entity_ids}))
                ack = json.loads(await asyncio.wait_for(ws.recv(), 10))
                if ack.get("type") != "result" or ack.get("success") is not True or ack.get("id") != 1:
                    raise BrokerError("UPSTREAM_FORMAT")
                while True:
                    self._entities(entity_ids)
                    raw = json.loads(await asyncio.wait_for(ws.recv(), 60))
                    self._entities(entity_ids)
                    if raw.get("type") != "event" or raw.get("id") != 1:
                        raise BrokerError("UPSTREAM_FORMAT")
                    event = raw.get("event", {})
                    if not isinstance(event, dict):
                        raise BrokerError("UPSTREAM_FORMAT")
                    # Never forward unselected IDs or arbitrary attributes.
                    safe: dict[str, Any] = {"a": {}, "c": {}, "r": []}
                    for category in ("a", "c"):
                        items = event.get(category, {})
                        if not isinstance(items, dict):
                            continue
                        for entity_id, item in items.items():
                            if entity_id not in entity_ids or entity_id not in self.policy.entity_ids:
                                continue
                            ref = self.ref("entity", entity_id)
                            if category == "a" and isinstance(item, dict):
                                safe[category][ref] = self._safe_fields(item, {"s", "lc", "lu"})
                            elif isinstance(item, dict):
                                change = item.get("+", {})
                                if isinstance(change, dict):
                                    safe[category][ref] = {"+": self._safe_fields(change, {"s", "lc", "lu"})}
                    safe["r"] = [self.ref("entity", e) for e in event.get("r", []) if e in entity_ids]
                    yield safe
        except BrokerError:
            raise
        except Exception:
            raise BrokerError("CONNECTION_LOST") from None

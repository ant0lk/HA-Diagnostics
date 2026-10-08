"""Local admin-only framed IPC. MCP/query UID has no broker capability.

The kernel authenticates peers using SO_PEERCRED on Linux. A claim in JSON or
HTTP headers is never accepted as a caller identity. Socket path is configured
at bootstrap, not supplied by a remote request.
"""
from __future__ import annotations

import asyncio
import inspect
import json
import os
import socket
import stat
import struct
from pathlib import Path
from typing import Any, Awaitable, Callable, Literal

from pydantic import BaseModel, ConfigDict, Field

MAX_FRAME = 30 * 1024 * 1024
ADMIN_UID = 10003
QUERY_UID = 10002
ADMIN_OPERATIONS = frozenset({"admin_status", "discover_sources", "discover_entities", "import_preview",
    "import_commit", "set_policy", "revoke_access", "delete_archive", "pause_collection", "read_local_artifact", "approve_artifact", "delete_artifact", "read_evidence", "tunnel_status", "save_tunnel",
    "start_export", "export_status", "export_download", "cancel_export", "delete_export", "set_export_schedule"})


class IPCError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class EmptyArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class IPCEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    op: Literal["admin_status", "discover_sources", "discover_entities", "import_preview", "import_commit",
                "set_policy", "revoke_access", "delete_archive", "pause_collection", "read_local_artifact", "approve_artifact", "delete_artifact", "read_evidence", "tunnel_status", "save_tunnel",
                "start_export", "export_status", "export_download", "cancel_export", "delete_export", "set_export_schedule"]
    args: dict[str, Any] = Field(default_factory=dict)


def peer_uid(peer: Any) -> int:
    """Fail closed outside a Linux AF_UNIX socket with kernel credentials."""
    if not hasattr(socket, "SO_PEERCRED") or peer is None or getattr(peer, "family", None) != socket.AF_UNIX:
        raise IPCError("IPC_PEER_UNVERIFIED")
    try:
        _, uid, _ = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        return uid
    except (OSError, struct.error, AttributeError):
        raise IPCError("IPC_PEER_UNVERIFIED") from None


def validate_json_limits(value: Any, *, max_depth: int = 64, max_nodes: int = 100_000) -> None:
    count = 0
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > max_depth or count > max_nodes:
            raise IPCError("IPC_LIMIT")
        if isinstance(item, dict):
            pending.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            pending.extend((v, depth + 1) for v in item)


def _json_loads(payload: bytes) -> Any:
    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise IPCError("IPC_INVALID_REQUEST")
            result[key] = value
        return result
    try:
        value = json.loads(payload, object_pairs_hook=reject_duplicate,
                           parse_constant=lambda _: (_ for _ in ()).throw(IPCError("IPC_INVALID_REQUEST")))
        validate_json_limits(value)
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise IPCError("IPC_INVALID_REQUEST") from None


async def read_frame(reader: asyncio.StreamReader) -> bytes:
    try:
        size = struct.unpack("!I", await asyncio.wait_for(reader.readexactly(4), 10))[0]
        if not 1 <= size <= MAX_FRAME:
            raise IPCError("IPC_LIMIT")
        return await asyncio.wait_for(reader.readexactly(size), 30)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError):
        raise IPCError("IPC_INCOMPLETE") from None


async def write_frame(writer: asyncio.StreamWriter, value: Any) -> None:
    try:
        payload = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
    except (TypeError, ValueError):
        raise IPCError("IPC_INVALID_RESPONSE") from None
    if len(payload) > MAX_FRAME:
        raise IPCError("IPC_LIMIT")
    writer.write(struct.pack("!I", len(payload)) + payload)
    await asyncio.wait_for(writer.drain(), 10)


Handler = tuple[type[BaseModel], Callable[[BaseModel], Any | Awaitable[Any]]]


class AdminIPCServer:
    def __init__(self, path: str | Path, handlers: dict[str, Handler], *, admin_uid: int = ADMIN_UID,
                 admin_gid: int = ADMIN_UID, max_concurrency: int = 4):
        if admin_uid == QUERY_UID or admin_uid <= 0:
            raise ValueError("IPC_UNSAFE_UID")
        if set(handlers) - ADMIN_OPERATIONS:
            raise ValueError("IPC_UNSAFE_OPERATION")
        for schema, _ in handlers.values():
            if schema.model_config.get("extra") != "forbid" or schema.model_config.get("strict") is not True:
                raise ValueError("IPC_SCHEMA_NOT_STRICT")
        self.path = Path(path)
        self.handlers = handlers
        self.admin_uid, self.admin_gid = admin_uid, admin_gid
        self._server: asyncio.Server | None = None
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._max_connections = max_concurrency
        self._connections = 0

    async def dispatch(self, uid: int, payload: dict[str, Any]) -> Any:
        if uid != self.admin_uid:
            raise IPCError("IPC_FORBIDDEN")
        try:
            validate_json_limits(payload)
            envelope = IPCEnvelope.model_validate(payload)
            if envelope.op not in self.handlers:
                raise IPCError("IPC_OPERATION_UNAVAILABLE")
            schema, callback = self.handlers[envelope.op]
            args = schema.model_validate(envelope.args)
        except ValueError:
            raise IPCError("IPC_INVALID_REQUEST") from None
        try:
            async with self._semaphore:
                result = callback(args)
                return await result if inspect.isawaitable(result) else result
        except IPCError:
            raise
        except Exception as exc:
            from .broker import BrokerError
            if isinstance(exc,BrokerError) and envelope.op in {
                    "start_export","export_status","export_download","cancel_export","delete_export","set_export_schedule"}:
                raise IPCError(exc.code) from None
            # Import text, upstream exceptions and credentials never appear here.
            raise IPCError("IPC_OPERATION_FAILED") from None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        admitted = False
        try:
            if self._connections >= self._max_connections:
                raise IPCError("IPC_BUSY")
            self._connections += 1
            admitted = True
            uid = peer_uid(writer.get_extra_info("socket"))
            if uid != self.admin_uid:
                raise IPCError("IPC_FORBIDDEN")
            payload = _json_loads(await read_frame(reader))
            result = await self.dispatch(uid, payload)
            await write_frame(writer, {"ok": True, "result": result})
        except IPCError as exc:
            try:
                await write_frame(writer, {"ok": False, "error": exc.code})
            except Exception:
                pass
        finally:
            if admitted:
                self._connections -= 1
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    async def start(self) -> None:
        if os.name != "posix" or not hasattr(socket, "SO_PEERCRED"):
            raise IPCError("IPC_LINUX_REQUIRED")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists() or self.path.is_symlink():
            entry = self.path.lstat()
            if not stat.S_ISSOCK(entry.st_mode) or entry.st_uid != os.getuid():
                raise IPCError("IPC_UNSAFE_PATH")
            self.path.unlink()
        self._server = await asyncio.start_unix_server(self._handle, path=self.path, limit=65536)
        os.chmod(self.path, 0o660)
        os.chown(self.path, os.getuid(), self.admin_gid)

    async def close(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        if self.path.exists() and stat.S_ISSOCK(self.path.lstat().st_mode) and self.path.lstat().st_uid == os.getuid():
            self.path.unlink()


class AdminIPCClient:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    async def request(self, op: str, args: dict[str, Any] | None = None) -> Any:
        try:
            envelope = IPCEnvelope.model_validate({"op": op, "args": args or {}})
        except ValueError:
            raise IPCError("IPC_INVALID_REQUEST") from None
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_unix_connection(self.path), 5)
            try:
                await write_frame(writer, envelope.model_dump())
                response = _json_loads(await read_frame(reader))
                if not isinstance(response, dict) or response.get("ok") is not True:
                    # Only known server codes are safe. Never show an untrusted body.
                    raise IPCError("IPC_REQUEST_DENIED")
                return response.get("result")
            finally:
                writer.close()
                await writer.wait_closed()
        except IPCError:
            raise
        except (OSError, asyncio.TimeoutError):
            raise IPCError("IPC_UNAVAILABLE") from None

import asyncio
import json
import socket
import struct

import pytest
from pydantic import BaseModel, ConfigDict

from ha_diagnostics.ipc import AdminIPCServer, EmptyArgs, IPCError, MAX_FRAME, _json_loads, peer_uid, read_frame


async def test_query_uid_and_foreign_uid_cannot_invoke_admin_or_upstream():
    called = []
    server = AdminIPCServer("unused", {"discover_sources": (EmptyArgs, lambda args: called.append(args))})
    for uid in (10002, 10001, 0, 10100):
        with pytest.raises(IPCError, match="IPC_FORBIDDEN"):
            await server.dispatch(uid, {"op": "discover_sources", "args": {}})
    assert called == []


@pytest.mark.parametrize("payload", [
    {"op": "restart", "args": {}}, {"op": "proxy", "args": {"url": "http://supervisor"}},
    {"op": "discover_sources", "args": {"path": "/core/restart"}},
    {"op": "discover_sources", "args": {}, "uid": 10003},
    {"op": "discover_sources", "args": {}, "sql": "DROP TABLE logs"},
])
async def test_unknown_fields_commands_never_reach_callback(payload):
    called = []
    server = AdminIPCServer("unused", {"discover_sources": (EmptyArgs, lambda args: called.append(args))})
    with pytest.raises(IPCError):
        await server.dispatch(10003, payload)
    assert called == []


async def test_callback_error_never_echoes_import_or_credential():
    def callback(args):
        raise RuntimeError("SUPERVISOR_TOKEN=synthetic-secret imported body")
    server = AdminIPCServer("unused", {"admin_status": (EmptyArgs, callback)})
    with pytest.raises(IPCError) as error:
        await server.dispatch(10003, {"op": "admin_status", "args": {}})
    assert str(error.value) == "IPC_OPERATION_FAILED"


def test_server_rejects_query_identity_and_unstrict_schema_at_construction():
    with pytest.raises(ValueError, match="IPC_UNSAFE_UID"):
        AdminIPCServer("unused", {}, admin_uid=10002)
    class Unsafe(BaseModel):
        model_config = ConfigDict(extra="allow")
    with pytest.raises(ValueError, match="IPC_SCHEMA_NOT_STRICT"):
        AdminIPCServer("unused", {"admin_status": (Unsafe, lambda args: {})})
    with pytest.raises(ValueError, match="IPC_UNSAFE_OPERATION"):
        AdminIPCServer("unused", {"shell": (EmptyArgs, lambda args: {})})


def test_peer_credential_cannot_be_json_or_tcp_identity():
    for identity in (None, {"uid": 10003}, socket.socket(socket.AF_INET, socket.SOCK_STREAM)):
        try:
            with pytest.raises((IPCError, AttributeError)):
                peer_uid(identity)
        finally:
            if isinstance(identity, socket.socket):
                identity.close()


async def test_frame_size_is_checked_before_reading_body():
    reader = asyncio.StreamReader()
    reader.feed_data(struct.pack("!I", MAX_FRAME + 1))
    with pytest.raises(IPCError, match="IPC_LIMIT"):
        await read_frame(reader)


@pytest.mark.parametrize("payload", [b'{"op":"admin_status","op":"delete_archive"}', b'{"value":NaN}', b'\xff'])
def test_duplicate_keys_nonfinite_and_invalid_encoding_rejected(payload):
    with pytest.raises(IPCError, match="IPC_INVALID_REQUEST"):
        _json_loads(payload)


def test_deep_json_is_bounded():
    deep = "[" * 70 + "0" + "]" * 70
    with pytest.raises(IPCError, match="IPC_LIMIT"):
        _json_loads(deep.encode())

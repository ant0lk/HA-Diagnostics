import asyncio
import json

import httpx
import pytest

from ha_diagnostics.broker import BrokerError, BrokerPolicy, FixedOriginConnect, ReadBroker
from ha_diagnostics.redaction import Redactor

TOKEN = "synthetic-manager-credential-do-not-export"


def make_broker(handler, policy=None, **kwargs):
    policy = policy or BrokerPolicy(mode="live", enabled_sources={"core", "supervisor", "metadata", "entities", "addon:fixture_matter"},
        addon_slugs={"fixture_matter"}, entity_ids={"light.fixture", "sensor.fixture"})
    return ReadBroker(policy, Redactor(b"r" * 32), TOKEN, transport=httpx.MockTransport(handler), **kwargs)


@pytest.mark.parametrize("payload", [
    {"op": "call_service", "domain": "light", "service": "turn_on"},
    {"op": "restart"}, {"op": "logger.set_level"}, {"op": "config/device_registry/update"},
    {"op": "proxy", "url": "http://supervisor/core/restart"},
    {"op": "logs", "source_id": "core", "url": "http://example.test"},
    {"op": "logs", "source_id": "core", "lines": True},
    {"op": "logs", "source_id": "core", "path": "../secret"},
    {"op": "states", "entity_ids": ["light.fixture"], "headers": {"Host": "attacker.test"}},
    {"op": "history", "entity_ids": ["light.fixture"], "from": "2026-10-07T00:00:00", "to": "2026-10-07T01:00:00Z"},
])
async def test_invalid_operation_rejected_before_upstream(payload):
    sent = []
    broker = make_broker(lambda request: sent.append(request) or httpx.Response(200, text=""))
    with pytest.raises(BrokerError, match="INVALID_REQUEST"):
        await broker.execute(payload)
    assert sent == []
    await broker.close()


@pytest.mark.parametrize("method,path,params", [
    ("POST", "/core/restart", {}), ("PUT", "/core/api/states/light.fixture", {}),
    ("GET", "/core/restart", {}), ("GET", "/core/api/camera_proxy/camera.fixture", {}),
    ("GET", "/core/api/config?x=1", {}), ("GET", "/core/api/hassio_auth/password_reset", {}),
    ("GET", "/addons/fixture_matter/options/config", {}), ("GET", "/addons/%252e%252e/logs", {}),
    ("GET", "/host/logs", {}), ("GET", "/core/info", {"method": "restart"}),
])
async def test_network_boundary_allowlist(method, path, params):
    sent = []
    broker = make_broker(lambda request: sent.append(request) or httpx.Response(200, json={}))
    with pytest.raises(BrokerError):
        broker._validate_request(method, path, params, broker._headers())
    assert not sent
    await broker.close()


async def test_import_mode_does_not_retain_or_use_injected_credential():
    sent = []
    broker = make_broker(lambda req: sent.append(req), BrokerPolicy())
    assert broker._token is None
    with pytest.raises(BrokerError, match="SOURCE_UNAVAILABLE"):
        await broker.execute({"op": "addon_catalog"})
    assert not sent
    await broker.close()


async def test_redirect_denied_with_no_follow_and_no_credential_output():
    sent = []
    def handler(request):
        sent.append(request)
        return httpx.Response(302, headers={"Location": "https://attacker.test/?token=" + TOKEN}, text=TOKEN)
    broker = make_broker(handler)
    with pytest.raises(BrokerError) as error:
        await broker.execute({"op": "logs", "source_id": "core"})
    assert str(error.value) == "UPSTREAM_REDIRECT_DENIED"
    assert len(sent) == 1 and sent[0].url.host == "supervisor"
    assert TOKEN not in str(error.value)
    await broker.close()


async def test_unknown_source_and_unselected_entity_denied():
    sent = []
    broker = make_broker(lambda req: sent.append(req))
    for payload in ({"op": "logs", "source_id": "addon:other"}, {"op": "logs", "source_id": "addon:../core"},
                    {"op": "states", "entity_ids": ["light.other"]}):
        with pytest.raises(BrokerError, match="SOURCE_DENIED"):
            await broker.execute(payload)
    assert not sent
    await broker.close()


async def test_50k_bounded_range_and_all_levels_not_last_100():
    text = "2026-10-07T12:00:00Z INFO context\n" * 10001 + "password=synthetic-password\n" + TOKEN
    sent = []
    def handler(request):
        sent.append(request)
        return httpx.Response(200, text=text)
    broker = make_broker(handler)
    result = await broker.execute({"op": "logs", "source_id": "core"})
    assert sent[0].headers["Range"] == "entries=:-49999:50000"
    assert sent[0].method == "GET" and sent[0].url.path == "/core/logs"
    assert len(result["text"].splitlines()) == 10003
    assert "synthetic-password" not in result["text"] and TOKEN not in result["text"]
    assert result["cursor"] is None
    await broker.close()


async def test_state_values_and_safe_attributes_are_preserved():
    values = iter([0, False, None, "", "unavailable", "unknown"])
    broker = make_broker(lambda request: httpx.Response(200, json={"entity_id": "sensor.fixture", "state": next(values),
        "last_changed": "2026-10-07T12:00:00Z", "last_updated": "2026-10-07T12:01:00Z",
        "attributes": {"unit_of_measurement": "W", "latitude": 55.0, "password": "synthetic-secret"}}))
    results = []
    for _ in range(6):
        results.append((await broker.execute({"op": "states", "entity_ids": ["sensor.fixture"]}))[0])
    assert [r["state"] for r in results] == [0, False, None, "", "unavailable", "unknown"]
    assert type(results[0]["state"]) is int and type(results[1]["state"]) is bool
    assert all(r["safe_attributes"] == {"unit_of_measurement": "W"} for r in results)
    assert all(r["entity_ref"].startswith("ent_") for r in results)
    await broker.close()


async def test_history_is_half_open_and_recorder_unknown():
    sent = []
    states = [{"entity_id": "light.fixture", "state": s, "last_changed": t, "last_updated": t} for s, t in
        [("off", "2026-10-07T11:59:59Z"), ("unavailable", "2026-10-07T12:00:00Z"), ("on", "2026-10-07T13:00:00Z")]]
    broker = make_broker(lambda request: sent.append(request) or httpx.Response(200, json=[states]))
    result = await broker.execute({"op": "history", "entity_ids": ["light.fixture"], "from": "2026-10-07T19:00:00+07:00", "to": "2026-10-07T20:00:00+07:00"})
    assert {v["state"] for v in result["states"]} == {"off", "unavailable"}
    assert next(v for v in result["states"] if v["state"] == "off")["boundary_state"] is True
    assert result["coverage_status"] == "unknown"
    assert set(sent[0].url.params) == {"filter_entity_id", "end_time", "no_attributes"}
    assert "significant_changes_only" not in sent[0].url.params
    await broker.close()


async def test_metadata_coordinates_paths_and_upstream_error_text_removed():
    def handler(request):
        if request.url.path == "/host/info":
            raise httpx.ConnectError(TOKEN + " raw upstream password=hidden", request=request)
        return httpx.Response(200, json={"result": "ok", "data": {"version": "2026.9.4", "time_zone": "Asia/Krasnoyarsk",
            "latitude": 55, "longitude": 85, "config_dir": "/config", "token": TOKEN}})
    broker = make_broker(handler)
    result = await broker.execute({"op": "metadata"})
    encoded = json.dumps(result)
    assert TOKEN not in encoded and "latitude" not in encoded and "/config" not in encoded
    assert result["config"]["time_zone"] == "Asia/Krasnoyarsk"
    assert result["host"] == {"error": "UPSTREAM_UNAVAILABLE"}
    await broker.close()


async def test_revocation_is_checked_each_handler_invocation():
    policy = BrokerPolicy(mode="live", enabled_sources={"core"})
    sent = []
    broker = make_broker(lambda req: sent.append(req) or httpx.Response(200, text="fixture"), policy)
    await broker.execute({"op": "logs", "source_id": "core"})
    policy.enabled_sources.clear()
    with pytest.raises(BrokerError, match="SOURCE_DENIED"):
        await broker.execute({"op": "logs", "source_id": "core"})
    assert len(sent) == 1
    await broker.close()


async def test_switch_to_import_drops_retained_live_credential():
    policy = BrokerPolicy(mode="live", enabled_sources={"core"})
    broker = make_broker(lambda request: httpx.Response(200, text="fixture"), policy)
    assert broker._token is not None
    policy.mode = "import_only"
    with pytest.raises(BrokerError, match="SOURCE_UNAVAILABLE"):
        await broker.execute({"op": "logs", "source_id": "core"})
    assert broker._token is None
    await broker.close()


async def test_inflight_disable_discards_response_before_archive_or_output():
    policy = BrokerPolicy(mode="live", enabled_sources={"core"})
    def upstream(request):
        policy.enabled_sources.clear()
        return httpx.Response(200, text="fixture private after revoke")
    broker = make_broker(upstream, policy)
    with pytest.raises(BrokerError, match="SOURCE_DENIED"):
        await broker.execute({"op": "logs", "source_id": "core"})
    await broker.close()


class FakeWS:
    def __init__(self, messages):
        self.messages = iter(messages)
        self.sent = []
    async def __aenter__(self):
        return self
    async def __aexit__(self, *args):
        pass
    async def recv(self):
        return json.dumps(next(self.messages))
    async def send(self, message):
        self.sent.append(json.loads(message))


async def test_atomic_selected_subscription_and_credential_not_forwarded():
    ws = FakeWS([{"type": "auth_required"}, {"type": "auth_ok"}, {"id": 1, "type": "result", "success": True},
        {"id": 1, "type": "event", "event": {"a": {"sensor.fixture": {"s": 0, "lc": 1791374400, "a": {"password": "secret"}}, "camera.private": {"s": "secret"}}}}])
    broker = make_broker(lambda req: httpx.Response(200), websocket_connector=lambda *a, **kw: ws)
    stream = broker.watch_entities(["sensor.fixture"])
    event = await anext(stream)
    assert len(event["a"]) == 1
    assert list(event["a"].values())[0]["s"] == 0
    assert "secret" not in json.dumps(event) and TOKEN not in json.dumps(event)
    assert ws.sent[1] == {"id": 1, "type": "subscribe_entities", "entity_ids": ["sensor.fixture"]}
    assert all(m["type"] in {"auth", "subscribe_entities"} for m in ws.sent)
    await stream.aclose()
    await broker.close()


async def test_local_discovery_excludes_sensitive_domains_and_state_content():
    broker = make_broker(lambda request: httpx.Response(200, json=[
        {"entity_id": "sensor.fixture", "state": TOKEN, "attributes": {"password": "secret"}},
        {"entity_id": "camera.private", "state": "secret"}, {"entity_id": "person.private", "state": "home"}]))
    result = await broker.execute({"op": "entity_catalog"})
    assert [e["entity_id"] for e in result["entities"]] == ["sensor.fixture"]
    assert TOKEN not in json.dumps(result) and "state" not in result["entities"][0]
    await broker.close()


async def test_real_websocket_redirect_is_never_followed():
    """A real HTTP upgrade response cannot redirect a credential-bearing socket."""
    visits = []

    async def redirected(reader, writer):
        visits.append("redirect_target")
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    target = await asyncio.start_server(redirected, "127.0.0.1", 0)
    target_port = target.sockets[0].getsockname()[1]

    async def original(reader, writer):
        visits.append("fixed_origin")
        request = await reader.readuntil(b"\r\n\r\n")
        assert TOKEN.encode() not in request
        response = ("HTTP/1.1 302 Found\r\nLocation: ws://127.0.0.1:" + str(target_port) +
                    "/stolen\r\nContent-Length: 0\r\n\r\n")
        writer.write(response.encode("ascii"))
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    origin = await asyncio.start_server(original, "127.0.0.1", 0)
    origin_port = origin.sockets[0].getsockname()[1]
    try:
        async with target, origin:
            with pytest.raises(BrokerError, match="UPSTREAM_REDIRECT_DENIED"):
                async with FixedOriginConnect(f"ws://127.0.0.1:{origin_port}/fixed", proxy=None,
                                              open_timeout=2):
                    pytest.fail("redirected upgrade accepted")
            assert visits == ["fixed_origin"]
    finally:
        target.close()
        origin.close()
        await target.wait_closed()
        await origin.wait_closed()


async def test_websocket_policy_disabled_during_auth_wait_sends_no_credential():
    policy = BrokerPolicy(mode="live", enabled_sources={"entities"}, entity_ids={"sensor.fixture"})
    class RevokedAuthWS(FakeWS):
        async def recv(self):
            policy.mode = "import_only"
            return json.dumps({"type": "auth_required"})
    ws = RevokedAuthWS([])
    broker = make_broker(lambda req: httpx.Response(200), policy,
                         websocket_connector=lambda *a, **kw: ws)
    stream = broker.watch_entities(["sensor.fixture"])
    with pytest.raises(BrokerError, match="SOURCE_UNAVAILABLE"):
        await anext(stream)
    assert not ws.sent and broker._token is None
    await stream.aclose()
    await broker.close()


async def test_catalog_source_disabled_during_last_response_is_discarded():
    policy = BrokerPolicy(mode="live", enabled_sources={"entities"}, entity_ids={"sensor.fixture"})
    class RevokedCatalogWS(FakeWS):
        async def recv(self):
            value = await super().recv()
            if json.loads(value).get("id") == 4:
                policy.enabled_sources.clear()
            return value
    ws = RevokedCatalogWS([{"type": "auth_required"}, {"type": "auth_ok"}] +
                          [{"id": i, "type": "result", "success": True, "result": []} for i in range(1, 5)])
    broker = make_broker(lambda req: httpx.Response(200), policy,
                         websocket_connector=lambda *a, **kw: ws)
    with pytest.raises(BrokerError, match="SOURCE_DENIED"):
        await broker.execute({"op": "device_catalog"})
    assert all(m["type"] in {"auth", "config/device_registry/list", "config/entity_registry/list",
                            "config/area_registry/list", "config_entries/get"} for m in ws.sent)
    await broker.close()

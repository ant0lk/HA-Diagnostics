"""Owner UI provisioning in the transport role; no HA or broker credentials."""
import json
import os
import sys
from pathlib import Path
from pydantic import Field, SecretStr
from .policy import Strict
from .schemas import Empty
from .local_setup import SetupError, _directory, _write_fixed, _validate_secret, _unsafe_link


class TunnelArgs(Strict):
    tunnel_id: str = Field(pattern=r"^tunnel_[a-zA-Z0-9]{8,100}$")
    runtime_key: SecretStr


class TransportSetup:
    def __init__(self, data):
        self.data = Path(data)
        self.restart_required = False

    async def status(self, args):
        directory = self.data / "transport"
        result = {"available": True, "configured": False, "tunnel_id": "",
                  "restart_required": self.restart_required, "connection_verified": False}
        if (directory / "relay.json").exists():
            return result | {"available": False, "reason": "TRANSPORT_CONFLICT"}
        for name in ("tunnel-settings.json", "tunnel.json"):
            path = directory / name
            if path.exists():
                from .runtime import read_transport_file
                config = json.loads(read_transport_file(path, 16384))
                tunnel_id = config.get("tunnel_id", "")
                from .local_setup import TUNNEL_PATTERN
                if not isinstance(tunnel_id, str) or not TUNNEL_PATTERN.fullmatch(tunnel_id):
                    raise SetupError("INVALID_TUNNEL_ID")
                return result | {"configured": True, "tunnel_id": tunnel_id}
        return result

    async def save(self, args):
        if sys.platform == "linux" and os.geteuid() != 10004:
            raise SetupError("TRANSPORT_ROLE_REQUIRED")
        key = args.runtime_key.get_secret_value()
        _validate_secret(key)
        directory = _directory(self.data, "transport")
        if _unsafe_link(directory / "relay.json") or (directory / "relay.json").exists():
            raise SetupError("TRANSPORT_CONFLICT")
        # One atomic file: ID and key can never be paired with different saves.
        _write_fixed(directory, "tunnel-settings.json",
                     json.dumps({"tunnel_id": args.tunnel_id, "runtime_key": key}).encode())
        self.restart_required = True
        return {"saved": True, "restart_required": True}

    def handlers(self):
        return {"tunnel_status": (Empty, self.status), "save_tunnel": (TunnelArgs, self.save)}

    async def request(self, op, args):
        schema, callback = self.handlers()[op]
        return await callback(schema.model_validate(args))

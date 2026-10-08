"""Owner-local secret provisioning. Values are prompted, never CLI arguments.

Linux production use requires root inside the app container. Windows supports
local development only; its ACL/isolation still requires separate verification.
This helper never contacts HA, OpenAI, or an IdP and never registers a server.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import warnings

import httpx
from pydantic import BaseModel,ConfigDict,Field

TUNNEL_PATTERN = re.compile(r"^tunnel_[a-zA-Z0-9]{8,100}$")


class SetupError(Exception):
    """Fixed non-sensitive diagnostics only."""


class ChannelEnrollmentResponse(BaseModel):
    model_config=ConfigDict(extra="forbid",strict=True)
    installation_id:str=Field(pattern=r"^[a-zA-Z0-9_-]{16,80}$")
    device_key:str=Field(pattern=r"^[0-9a-f]{64}$")


def _prompt_secret(prompt: str) -> str:
    # getpass otherwise silently falls back to potentially echoed stdin on a
    # redirected/non-interactive terminal. A secret must never use that fallback.
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        return getpass.getpass(prompt)


def _unsafe_link(path: Path) -> bool:
    return path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)())


def _root_directory(data: Path) -> Path:
    data = Path(os.path.abspath(data))
    for part in [*reversed(data.parents), data]:
        if _unsafe_link(part):
            raise SetupError("UNSAFE_STORAGE_PATH")
    if not data.is_dir():
        raise SetupError("STORAGE_DIRECTORY_REQUIRED")
    return data


def _directory(data: Path, name: str) -> Path:
    root = _root_directory(data)
    path = root / name
    if _unsafe_link(path):
        raise SetupError("UNSAFE_STORAGE_PATH")
    path.mkdir(mode=0o700, exist_ok=True)
    if not path.is_dir():
        raise SetupError("UNSAFE_STORAGE_PATH")
    path.chmod(0o700)
    return path


def _validate_secret(value: str) -> bytes:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 8192:
        raise SetupError("INVALID_SECRET")
    if any(ord(c) < 33 or ord(c) == 127 for c in value):
        raise SetupError("INVALID_SECRET")
    return value.encode("utf-8")


def _write_fixed(directory: Path, filename: str, payload: bytes) -> None:
    """Atomic exclusive file; no configurable relative path or symlink follows."""
    if filename not in {"tunnel-settings.json", "tunnel.json", "control-plane-api-key", "introspection.secret", "relay.json", "relay-device-key"}:
        raise SetupError("UNSAFE_SECRET_PATH")
    target = directory / filename
    if _unsafe_link(directory) or _unsafe_link(target):
        raise SetupError("UNSAFE_STORAGE_PATH")
    if target.exists() and not stat.S_ISREG(target.lstat().st_mode):
        raise SetupError("UNSAFE_STORAGE_PATH")
    temporary = ".setup_" + secrets.token_hex(16)
    directory_fd = None
    descriptor = None
    temp_path = directory / temporary
    try:
        if sys.platform == "linux":
            directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=directory_fd)
        else:
            descriptor = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            descriptor = None
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
            os.chmod(output.fileno(), 0o600) if sys.platform == "linux" else None
        if directory_fd is not None:
            os.replace(temporary, filename, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            os.fsync(directory_fd)
        else:
            os.replace(temp_path, target)
            target.chmod(0o600)
    except (OSError, ValueError):
        raise SetupError("SECRET_WRITE_FAILED") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            if directory_fd is not None:
                os.unlink(temporary, dir_fd=directory_fd)
            elif temp_path.exists():
                temp_path.unlink()
        except FileNotFoundError:
            pass
        if directory_fd is not None:
            os.close(directory_fd)


def provision(data: Path, *, tunnel_id: str | None = None, tunnel_key: str | None = None,
              introspection_secret: str | None = None, relay_origin: str | None = None,
              relay_device_key: str | None = None) -> None:
    """Write fixed files only after all values validate, without external calls."""
    if sys.platform == "linux" and os.geteuid() != 0:
        raise SetupError("LOCAL_ROOT_REQUIRED")
    if sys.platform not in {"linux", "win32"}:
        raise SetupError("UNSUPPORTED_SETUP_PLATFORM")
    data = _root_directory(data)
    if (data / "transport/tunnel-settings.json").exists():
        raise SetupError("USE_PANEL_TUNNEL_SETTINGS")
    if bool(tunnel_id) != bool(tunnel_key):
        raise SetupError("TUNNEL_ID_AND_KEY_REQUIRED")
    if tunnel_id and not TUNNEL_PATTERN.fullmatch(tunnel_id):
        raise SetupError("INVALID_TUNNEL_ID")
    if bool(relay_origin) != bool(relay_device_key):
        raise SetupError("RELAY_ORIGIN_AND_KEY_REQUIRED")
    if tunnel_id and relay_origin:
        raise SetupError("TRANSPORT_CONFLICT")
    if relay_origin:
        from .relay import validate_gateway
        try:
            if any(ord(c) < 33 or ord(c) > 126 for c in relay_origin):
                raise ValueError()
            relay_origin = validate_gateway(relay_origin)
        except (ValueError, TypeError):
            raise SetupError("INVALID_GATEWAY_ORIGIN") from None
    if ((relay_origin and (data / "transport/tunnel.json").exists()) or
            (tunnel_id and (data / "transport/relay.json").exists())):
        raise SetupError("TRANSPORT_CONFLICT")
    key_bytes = _validate_secret(tunnel_key) if tunnel_key else None
    relay_bytes = _validate_secret(relay_device_key) if relay_device_key else None
    introspection_bytes = _validate_secret(introspection_secret) if introspection_secret else None
    if key_bytes is not None:
        directory = _directory(data, "transport")
        _write_fixed(directory, "control-plane-api-key", key_bytes)
        _write_fixed(directory, "tunnel.json", json.dumps({"tunnel_id": tunnel_id}, separators=(",", ":")).encode())
    if relay_bytes is not None:
        directory = _directory(data, "transport")
        _write_fixed(directory, "relay-device-key", relay_bytes)
        _write_fixed(directory, "relay.json", json.dumps({"origin": relay_origin}, separators=(",", ":")).encode())
    if introspection_bytes is not None:
        _write_fixed(_directory(data, "query"), "introspection.secret", introspection_bytes)


def enroll_relay(data: Path,origin: str,code: str,*,client=None) -> None:
    """One fixed HTTPS enrollment request, then fixed transport secret storage."""
    from .policy import PolicyStore
    from .relay import validate_gateway
    if sys.platform=="linux" and os.geteuid()!=0:raise SetupError("LOCAL_ROOT_REQUIRED")
    data=_root_directory(data)
    if (data/"transport/tunnel.json").exists():raise SetupError("TRANSPORT_CONFLICT")
    if not isinstance(code,str) or not re.fullmatch(r"[0-9a-f]{64}",code):raise SetupError("ENROLLMENT_DENIED")
    try:
        if any(ord(c)<33 or ord(c)>126 for c in origin):raise ValueError()
        origin=validate_gateway(origin)
    except (ValueError,TypeError):raise SetupError("INVALID_GATEWAY_ORIGIN") from None
    installation=PolicyStore(data/"public/policy.json").read().installation_id
    if not re.fullmatch(r"[a-zA-Z0-9_-]{16,80}",installation):raise SetupError("LOCAL_INSTALLATION_REQUIRED")
    # Validate secret destinations before consuming the remote one-time code.
    directory=_directory(data,"transport")
    for name in ("relay.json","relay-device-key"):
        target=directory/name
        if _unsafe_link(target) or target.exists() and not stat.S_ISREG(target.lstat().st_mode):
            raise SetupError("UNSAFE_STORAGE_PATH")
    owned=client is None
    client=client or httpx.Client(timeout=httpx.Timeout(10,connect=5),follow_redirects=False,trust_env=False)
    try:
        with client.stream("POST",origin+"/channel/enroll",json={"installation_id":installation,"code":code},
                           headers={"Accept":"application/json"},follow_redirects=False) as response:
            if response.status_code!=200:raise SetupError("ENROLLMENT_DENIED")
            raw=bytearray()
            for chunk in response.iter_bytes():
                raw.extend(chunk)
                if len(raw)>2048:raise SetupError("ENROLLMENT_DENIED")
        def unique_pairs(values):
            result={}
            for key,value in values:
                if key in result:raise ValueError()
                result[key]=value
            return result
        parsed=json.loads(raw,object_pairs_hook=unique_pairs,
                          parse_constant=lambda _:(_ for _ in ()).throw(ValueError()))
        result=ChannelEnrollmentResponse.model_validate(parsed)
        if result.installation_id!=installation:raise SetupError("ENROLLMENT_DENIED")
        provision(data,relay_origin=origin,relay_device_key=result.device_key)
    except (httpx.HTTPError,ValueError,UnicodeError,RecursionError):
        raise SetupError("ENROLLMENT_DENIED") from None
    finally:
        if owned:client.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Локальная настройка секретов HA-Diagnostics; секреты не передаются аргументами.")
    parser.add_argument("--data", type=Path, default=Path("/data"))
    parser.add_argument("--enroll-relay",action="store_true",help="Одноразовый pairing code через скрытый ввод; Tunnel не затрагивается.")
    args = parser.parse_args(argv)
    try:
        # Validate storage / privilege before asking for any sensitive input.
        _root_directory(args.data)
        if sys.platform == "linux" and os.geteuid() != 0:
            raise SetupError("LOCAL_ROOT_REQUIRED")
        if args.enroll_relay:
            origin=input("HTTPS origin личного relay: ").strip()
            code=_prompt_secret("Одноразовый enrollment code: ")
            enroll_relay(args.data,origin,code)
            print("CHANNEL_ENROLLED; local runtime restart and real connection acceptance are still required.")
            return 0
        tunnel_id = input("Tunnel ID (Enter — пропустить): ").strip()
        tunnel_key = _prompt_secret("Runtime API key Tunnel: ") if tunnel_id else None
        relay_origin = input("HTTPS origin личного relay (Enter — пропустить): ").strip() if not tunnel_id else ""
        relay_device_key = _prompt_secret("Device key личного relay: ") if relay_origin else None
        introspection_secret = _prompt_secret("Client secret IdP для introspection (Enter — пропустить): ") or None
        provision(args.data, tunnel_id=tunnel_id or None, tunnel_key=tunnel_key,
                  introspection_secret=introspection_secret, relay_origin=relay_origin or None,
                  relay_device_key=relay_device_key)
        print("LOCAL_SETTINGS_SAVED; runtime restart and real connection acceptance are still required.")
        return 0
    except (SetupError, OSError, EOFError, KeyboardInterrupt, getpass.GetPassWarning):
        print("LOCAL_SETUP_FAILED; no secret values were printed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Owner-local single-use device-channel enrollment. This is not an OAuth server."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time

from pydantic import BaseModel, ConfigDict, Field
from ha_diagnostics.policy import PolicyStore

FILES = frozenset({"enrollment-state.json", "enrollment-code.private", "device-channel-key", ".enrollment.lock"})
INSTALLATION_PATTERN = r"^[a-zA-Z0-9_-]{16,80}$"


class EnrollmentDenied(Exception):
    def __init__(self):
        super().__init__("ENROLLMENT_DENIED")


class EnrollmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    installation_id: str = Field(pattern=INSTALLATION_PATTERN)
    code: str = Field(pattern=r"^[0-9a-f]{64}$")


class EnrollmentResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    installation_id: str = Field(pattern=INSTALLATION_PATTERN)
    device_key: str = Field(pattern=r"^[0-9a-f]{64}$")


class EnrollmentState(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    installation_id: str = Field(pattern=INSTALLATION_PATTERN)
    code_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    issued_at: float
    expires_at: float
    used: bool = False


def strict_json(raw: bytes):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise EnrollmentDenied()
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(EnrollmentDenied()))
    except (ValueError, UnicodeError, RecursionError):
        raise EnrollmentDenied() from None


class EnrollmentStore:
    """Fixed bounded private files and an OS lock across gateway/owner CLI."""

    def __init__(self, data: Path, policies: PolicyStore, *, clock=time.time):
        self.data = Path(os.path.abspath(data))
        self.policies = policies
        self.clock = clock
        for part in [*reversed(self.data.parents), self.data]:
            if part.is_symlink() or bool(getattr(part, "is_junction", lambda: False)()):
                raise EnrollmentDenied()
        if not self.data.is_dir():
            raise EnrollmentDenied()

    def _path(self, name):
        if name not in FILES:
            raise EnrollmentDenied()
        path = self.data / name
        if path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)()):
            raise EnrollmentDenied()
        return path

    def _read(self, name, *, required=True):
        path = self._path(name)
        if not path.exists() and not required:
            return None
        descriptor = None
        try:
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 2048:
                raise EnrollmentDenied()
            if os.name == "posix" and (info.st_mode & 0o077 or
                    os.geteuid() != 0 and info.st_uid != os.geteuid()):
                raise EnrollmentDenied()
            raw = os.read(descriptor, 2049)
            if len(raw) > 2048:
                raise EnrollmentDenied()
            return raw
        except OSError:
            raise EnrollmentDenied() from None
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _write(self, name, raw: bytes):
        target = self._path(name)
        if len(raw) > 2048 or target.exists() and not stat.S_ISREG(target.lstat().st_mode):
            raise EnrollmentDenied()
        temporary = self.data / (".enrollment_" + secrets.token_hex(16))
        descriptor = None
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                 getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(descriptor, "wb") as output:
                descriptor = None
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            temporary.chmod(0o600)
            if os.name == "posix" and os.geteuid() == 0:
                owner = self.data.stat()
                os.chown(temporary, owner.st_uid, owner.st_gid)
            os.replace(temporary, target)
        except OSError:
            raise EnrollmentDenied() from None
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary.exists():
                temporary.unlink()

    def _remove(self, name):
        path = self._path(name)
        try:
            path.unlink()
        except FileNotFoundError:
            pass

    @contextmanager
    def _lock(self):
        path = self._path(".enrollment.lock")
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 1:
                raise EnrollmentDenied()
            if os.name == "posix":
                if info.st_mode & 0o077:
                    raise EnrollmentDenied()
                if os.geteuid() == 0:
                    owner = self.data.stat()
                    os.fchown(descriptor, owner.st_uid, owner.st_gid)
                elif info.st_uid != os.geteuid():
                    raise EnrollmentDenied()
                import fcntl
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            else:
                import msvcrt
                if info.st_size == 0:
                    os.write(descriptor, b"0")
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            yield
        finally:
            # Closing releases either OS lock, including on exceptions.
            os.close(descriptor)

    def issue(self, ttl: int = 300) -> Path:
        if type(ttl) is not int or not 1 <= ttl <= 300:
            raise EnrollmentDenied()
        installation = self.policies.read().installation_id
        if not re.fullmatch(INSTALLATION_PATTERN, installation):
            raise EnrollmentDenied()
        code = secrets.token_hex(32)
        now = float(self.clock())
        state = EnrollmentState(installation_id=installation,
                                code_hash=hashlib.sha256(code.encode("ascii")).hexdigest(),
                                issued_at=now, expires_at=now + ttl)
        with self._lock():
            # Starting a fresh enrollment revokes the previous channel first.
            self._remove("device-channel-key")
            self._write("enrollment-code.private", code.encode("ascii"))
            self._write("enrollment-state.json", state.model_dump_json().encode())
        return self.data / "enrollment-code.private"

    def invalidate(self):
        with self._lock():
            for name in ("device-channel-key", "enrollment-state.json", "enrollment-code.private"):
                self._remove(name)

    def consume(self, payload) -> dict:
        try:
            request = EnrollmentRequest.model_validate(payload)
            with self._lock():
                state = EnrollmentState.model_validate(strict_json(self._read("enrollment-state.json")))
                now = float(self.clock())
                installation = self.policies.read().installation_id
                digest = hashlib.sha256(request.code.encode("ascii")).hexdigest()
                if (state.used or not state.issued_at <= now < state.expires_at or
                        not 0 < state.expires_at - state.issued_at <= 300 or
                        request.installation_id != installation or state.installation_id != installation or
                        not secrets.compare_digest(digest, state.code_hash)):
                    raise EnrollmentDenied()
                # Consume before issuing the key: a write failure never allows
                # replay. Owner can issue a fresh code after local repair.
                state.used = True
                self._write("enrollment-state.json", state.model_dump_json().encode())
                self._remove("enrollment-code.private")
                key = secrets.token_hex(32)
                self._write("device-channel-key", key.encode("ascii"))
                return EnrollmentResponse(installation_id=installation, device_key=key).model_dump()
        except (ValueError, TypeError, OSError, EnrollmentDenied):
            raise EnrollmentDenied() from None


def main(argv=None):
    parser = argparse.ArgumentParser(description="Owner-local device-channel pairing; no secrets in stdout.")
    parser.add_argument("--data", type=Path, default=Path("/data"))
    parser.add_argument("action", choices=["issue", "invalidate"])
    parser.add_argument("--ttl", type=int, default=300)
    args = parser.parse_args(argv)
    try:
        store = EnrollmentStore(args.data, PolicyStore(args.data / "policy.json"))
        if args.action == "issue":
            path = store.issue(args.ttl)
            print("ENROLLMENT_CODE_FILE=" + str(path))
        else:
            store.invalidate()
            print("CHANNEL_REVOKED")
        return 0
    except (EnrollmentDenied, OSError, ValueError):
        print("ENROLLMENT_OPERATION_FAILED", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

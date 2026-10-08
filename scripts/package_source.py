"""Build a reviewable source ZIP from a finite allowlist, without owner documents.

No local state, credentials, vendor cache, Git metadata, input specifications or
existing dist artifact is included. This selection is not an unknown-secret
detector; source and synthetic fixtures must still be reviewed before delivery.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import zipfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = "1.0.0-alpha.3"
ROOT_FILES = {".gitignore", "README.md", "CHANGELOG.md", "Dockerfile.import", "pyproject.toml",
              "repository.yaml", "requirements.in", "requirements.lock", "requirements-dev.in",
              "requirements-dev.lock", "supply-chain.lock.json"}
DOC_FILES = {"FEASIBILITY.md", "INSTALL.md", "LIVE_ACCEPTANCE.md", "SECURITY.md",
             "ACCEPTANCE.md", "QUICKSTART.md", "ZIP_EXPORT.md"}
VERIFICATION_FILES = {"local-checks.json", "pytest-junit.xml"}
DIRS = {"src", "schemas", "web", "tests", "plugin", "containers/ha-app", "deploy", "gateway", "scripts"}
CONTAINER_FILES = {"VERIFICATION.json", "tunnel-env.json", "SBOM.md"}
SUFFIXES = {".py", ".json", ".yaml", ".yml", ".md", ".html", ".css", ".js", ".svg", ".lock", ".in"}
SKIP_DIRS = {"__pycache__", ".pytest_cache", ".git", ".venv", ".local-data", "dist", "vendor", "node_modules"}
SECRET_FILES = {"AGENTS.md", "TECHNICAL_SPEC.md", "ARCHITECTURE.md", "CHATGPT_PROMPT.md", "options.json", "policy.json",
                "tunnel.json", "relay.json", "control-plane-api-key", "device-channel-key", ".env"}


def candidate_paths() -> list[Path]:
    paths = [ROOT / name for name in ROOT_FILES if (ROOT / name).is_file()]
    paths.extend(ROOT / "docs" / name for name in DOC_FILES if (ROOT / "docs" / name).is_file())
    paths.extend(ROOT / "docs/verification" / name for name in VERIFICATION_FILES if (ROOT / "docs/verification" / name).is_file())
    paths.extend(ROOT / "containers" / name for name in CONTAINER_FILES if (ROOT / "containers" / name).is_file())
    adr = ROOT / "docs/adr"
    if adr.is_dir():
        paths.extend(path for path in adr.glob("[0-9][0-9][0-9][0-9]-*.md") if path.is_file())
    for directory in DIRS:
        for path in (ROOT / directory).rglob("*"):
            relative = path.relative_to(ROOT)
            if any(part in SKIP_DIRS for part in relative.parts):
                continue
            if path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)()):
                raise ValueError("SOURCE_LINK_FORBIDDEN")
            if not path.is_file():
                continue
            if path.name in SECRET_FILES or path.suffix.lower() in {".key", ".secret", ".sqlite", ".db", ".pem"}:
                raise ValueError("STATE_OR_SECRET_FILE_IN_SOURCE_DIRECTORY")
            if path.suffix.lower() in SUFFIXES or path.name in {"Dockerfile", "Containerfile"}:
                paths.append(path)
            elif relative.parts[:2] == ("tests", "fixtures") and path.suffix.lower() in {".log", ".txt"}:
                paths.append(path)
    return sorted(set(paths), key=lambda path: path.relative_to(ROOT).as_posix())


def build(output_name: str = "source") -> Path:
    if re.fullmatch(r"source[a-z0-9-]*", output_name) is None:
        raise ValueError("INVALID_SOURCE_OUTPUT_NAME")
    output = ROOT / "dist" / output_name
    if output.exists():
        raise FileExistsError("Refusing to overwrite existing source evidence")
    paths = candidate_paths()
    required = {"pyproject.toml", "requirements.lock", "requirements-dev.lock", "src/ha_diagnostics/runtime.py",
                "tests/test_mcp.py", "schemas/tools.json", "gateway/ha_diagnostics_gateway.py"}
    if not required.issubset({path.relative_to(ROOT).as_posix() for path in paths}):
        raise ValueError("INCOMPLETE_SOURCE_ALLOWLIST")
    if len(paths) > 512:
        raise ValueError("SOURCE_FILE_LIMIT")
    files: dict[str, bytes] = {}
    total = 0
    for path in paths:
        for ancestor in [path, *path.parents]:
            if ancestor == ROOT.parent:
                break
            if ancestor.is_symlink() or bool(getattr(ancestor, "is_junction", lambda: False)()):
                raise ValueError("SOURCE_LINK_FORBIDDEN")
        relative = path.relative_to(ROOT).as_posix()
        if PurePosixPath(relative).is_absolute() or any(ord(char) < 32 for char in relative):
            raise ValueError("UNSAFE_ARCHIVE_NAME")
        if path.stat().st_size > 10 * 1024 * 1024:
            raise ValueError("SOURCE_FILE_SIZE_LIMIT")
        payload = path.read_bytes()
        payload.decode("utf-8-sig")  # No arbitrary executable/binary payloads.
        files[relative] = payload
        total += len(payload)
    if total > 32 * 1024 * 1024:
        raise ValueError("SOURCE_TOTAL_SIZE_LIMIT")
    files["SOURCE_STATUS.json"] = (json.dumps({
        "version": VERSION, "source_files": len(paths), "owner_input_documents_included": False,
        "credentials_or_local_state_selected": False, "vendor_binaries_included": False,
        "container_build_verified_by_packaging": False, "ha_os_install_verified_by_packaging": False,
        "chatgpt_connection_verified_by_packaging": False,
        "review_required": "Finite source allowlist and synthetic fixtures; not a guarantee against unknown secrets.",
    }, indent=2) + "\n").encode("utf-8")
    files["SHA256SUMS"] = ("\n".join(hashlib.sha256(value).hexdigest() + "  " + name
                                      for name, value in sorted(files.items())) + "\n").encode("ascii")
    output.mkdir(parents=True)
    archive = output / ("HA-Diagnostics-" + VERSION + "-source.zip")
    prefix = "HA-Diagnostics-" + VERSION + "-source/"
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for name, payload in sorted(files.items()):
            info = zipfile.ZipInfo(prefix + name, date_time=(2026, 10, 7, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            bundle.writestr(info, payload)
    (output / "SHA256SUMS").write_text(hashlib.sha256(archive.read_bytes()).hexdigest() + "  " + archive.name + "\n", encoding="ascii")
    print("SOURCE_PACKAGE_CREATED; input specifications, owner instructions, vendor cache and local state excluded.")
    return archive


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-name", default="source", help="New source-prefixed directory inside dist; existing output is refused")
    build(parser.parse_args().output_name)

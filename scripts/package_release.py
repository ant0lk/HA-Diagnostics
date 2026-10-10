"""Stage standalone HA app build contexts without copying local state or secrets."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = "1.0.0-alpha.6"
TEMPLATES = ROOT / "containers" / "ha-app"


def copy_tree(source: Path, target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    if not source.exists():
        return
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise ValueError("Source symlinks are not deliverable")
        if any(part in {"__pycache__", ".pytest_cache", "node_modules"} for part in path.parts):
            continue
        if path.is_file() and path.suffix not in {".pyc", ".pyo"}:
            relative = path.relative_to(source)
            destination = target / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, destination)


def stage(with_tunnel: bool = False) -> Path:
    output = ROOT / "dist" / "ha-addons"
    if output.exists():
        raise FileExistsError(f"Refusing to overwrite {output}")
    if not (ROOT / "requirements.lock").is_file():
        raise ValueError("A hash-pinned requirements.lock is required")
    output.mkdir(parents=True)
    shutil.copy2(ROOT / "repository.yaml", output / "repository.yaml")
    for name, profile in (("ha_diagnostics", "import_only"), ("ha_diagnostics_live", "live")):
        target = output / name
        target.mkdir()
        for common in ("Dockerfile", "README.md", "DOCS.md", "CHANGELOG.md"):
            shutil.copy2(TEMPLATES / common, target / common)
        copy_tree(ROOT / "ha_diagnostics/translations", target / "translations")
        # Supervisor recursively discovers config.yaml files in Git repositories.
        # Templates must not shadow the standalone apps with the same slug.
        config = TEMPLATES / ("live-profile/config.yaml.in" if profile == "live" else "config.yaml.in")
        shutil.copy2(config, target / "config.yaml")
        app = target / "app"
        app.mkdir()
        shutil.copy2(ROOT / "requirements.lock", app / "requirements.lock")
        for directory in ("src", "schemas", "web"):
            copy_tree(ROOT / directory, app / directory)
        (app / "tunnel").mkdir()
        if with_tunnel:
            # Local verification/extraction uses only pinned artifacts from the supply lock.
            from verify_supply_chain import extract_tunnel
            for arch in ("amd64", "arm64"):
                extract_tunnel(arch, app / "tunnel" / arch)
        (target / ".dockerignore").write_text("**/__pycache__/\n**/*.pyc\n", encoding="ascii")
    (output / "BUILD_STATUS.json").write_text(json.dumps({"version": VERSION, "contexts_staged": True,
        "container_build_verified": False, "ha_os_install_verified": False,
        "tags": [f"ha-diagnostics-import:{VERSION}", f"ha-diagnostics-live:{VERSION}"],
        "tunnel_bytes_included": with_tunnel}, indent=2) + "\n", encoding="utf-8")
    checksums = []
    for path in sorted(output.rglob("*")):
        if path.is_file():
            checksums.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(output).as_posix()}")
    (output / "SHA256SUMS").write_text("\n".join(checksums) + "\n", encoding="ascii")
    print(f"Staged {output}. Docker builds and HA OS installation remain unverified.")
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--with-tunnel", action="store_true", help="Include verified locally downloaded runtime bytes")
    stage(parser.parse_args().with_tunnel)

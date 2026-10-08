"""Package approved plugin files; connection metadata requires real local input."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
VERSION = "1.0.0-alpha.3"


def dump(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def package(registered_id: str | None = None, mcp_url: str | None = None) -> Path:
    if registered_id and mcp_url:
        raise ValueError("Choose a registered connection or portable endpoint")
    if registered_id and not re.fullmatch(r"plugin_asdk_app[a-zA-Z0-9_]{1,128}", registered_id):
        raise ValueError("A real ChatGPT registered server technical ID is required")
    if mcp_url:
        parts = urlsplit(mcp_url)
        if (parts.scheme != "https" or not parts.hostname or parts.username or parts.password
                or parts.query or parts.fragment or parts.path != "/mcp"
                or parts.hostname in {"localhost", "127.0.0.1", "::1"}):
            raise ValueError("Use a credential-free HTTPS /mcp URL")
    flavor = "registered" if registered_id else "portable" if mcp_url else "skills-only"
    output = ROOT / "dist" / f"plugin-{flavor}"
    target = output / "ha-diagnostics"
    if target.exists():
        raise FileExistsError(f"Refusing to overwrite existing package: {target}")
    target.mkdir(parents=True)
    for name in ("plugin.json", "README.md"):
        shutil.copy2(ROOT / "plugin" / name, target / name)
    shutil.copytree(ROOT / "plugin" / "skills", target / "skills")
    manifest = json.loads((target / "plugin.json").read_text(encoding="utf-8"))
    if manifest["version"] != VERSION:
        raise ValueError("Product version mismatch")
    from jsonschema import Draft202012Validator
    plugin_schema = json.loads((ROOT / "plugin/schemas/plugin.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator(plugin_schema).validate(manifest)
    if registered_id:
        manifest["extensions"]["com.openai"]["apps"] = "./.app.json"
        dump(target / ".app.json", {"apps": {"ha_diagnostics": {"id": registered_id}}})
    elif mcp_url:
        mcp_config = {"$schema": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
                      "mcpServers": {"ha_diagnostics": {"type": "streamable-http", "url": mcp_url}}}
        mcp_schema = json.loads((ROOT / "plugin/schemas/mcp.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator(mcp_schema).validate(mcp_config)
        dump(target / "mcp.json", mcp_config)
    dump(target / "plugin.json", manifest)
    dump(output / "marketplace.json", {
        "name": "ha-diagnostics-private", "interface": {"displayName": "HA-Diagnostics private alpha"},
        "plugins": [{"name": "ha-diagnostics", "source": {"source": "local", "path": "./ha-diagnostics"},
                     "policy": {"installation": "AVAILABLE", "authentication": "ON_INSTALL"},
                     "category": "Productivity"}]})
    archive = output / f"ha-diagnostics-{VERSION}-{flavor}.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(target.rglob("*")):
            if path.is_symlink():
                raise ValueError("Symlinks are forbidden in plugin packages")
            if path.is_file():
                name = path.relative_to(target).as_posix()
                info = zipfile.ZipInfo(name, date_time=(2026, 10, 7, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                zf.writestr(info, path.read_bytes())
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (output / "SHA256SUMS").write_text(f"{digest}  {archive.name}\n", encoding="ascii")
    print(f"Created {flavor} package: {archive}. Registration and live access have not been verified.")
    return archive


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registered-server-id")
    parser.add_argument("--mcp-url")
    args = parser.parse_args()
    package(args.registered_server_id, args.mcp_url)


if __name__ == "__main__":
    main()

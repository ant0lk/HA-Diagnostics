"""Produce a lock inventory; optional installed pip-audit, never installs/fixes.

This is a Python lock SBOM, not an OCI image SBOM or an assertion that packages
are vulnerability-free. Only names, versions, lock hashes and installed version
matches are recorded. Owner data, environment values and installation paths are
not collected. An audit explicitly opted into here queries a public advisory
service with the public package names and versions from requirements.lock.
"""
from __future__ import annotations

import argparse
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
VERSION = "1.0.0-alpha.4"
AUDIT_VERSION = "2.10.1"
PIN = re.compile(r"^([A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9_,.-]+\])?==([A-Za-z0-9_.+!-]+)(?:\s*;\s*(.+?))?(?:\s+\\)?$")
HASH = re.compile(r"^\s+--hash=sha256:([a-f0-9]{64})(?:\s+\\)?$")


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def locked_components(lock: Path) -> list[dict]:
    rows: list[dict] = []
    current = None
    for line in lock.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        pin = PIN.fullmatch(line)
        if pin:
            current = {"name": normalize(pin[1]), "version": pin[2], "marker": pin[3] or "", "hashes": []}
            rows.append(current)
            continue
        hash_match = HASH.fullmatch(line)
        if hash_match and current is not None:
            current["hashes"].append(hash_match[1])
            continue
        raise ValueError("UNSUPPORTED_LOCK_LINE")
    if not rows or any(not item["hashes"] for item in rows):
        raise ValueError("UNHASHED_REQUIREMENT")
    if len({item["name"] for item in rows}) != len(rows):
        raise ValueError("DUPLICATE_REQUIREMENT")
    return rows


def sbom(lock: Path) -> dict:
    components = []
    for item in locked_components(lock):
        try:
            installed = metadata.version(item["name"])
        except metadata.PackageNotFoundError:
            installed = "not-installed"
        purl = "pkg:pypi/" + item["name"] + "@" + quote(item["version"], safe="")
        components.append({
            "type": "library", "bom-ref": purl, "name": item["name"],
            "version": item["version"], "purl": purl,
            "properties": [
                {"name": "ha-diagnostics:installed-version", "value": installed},
                {"name": "ha-diagnostics:installed-version-match", "value": str(installed == item["version"]).lower()},
                {"name": "ha-diagnostics:requirement-marker", "value": item["marker"]},
                {"name": "ha-diagnostics:allowed-distribution-sha256", "value": ",".join(item["hashes"])},
            ],
        })
    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {
            "component": {"type": "application", "name": "HA-Diagnostics", "version": VERSION},
            "properties": [
                {"name": "ha-diagnostics:inventory-scope", "value": "requirements.lock; Python dependencies only; no OCI OS packages, Tunnel binary, installed file hashes or dependency graph"},
                {"name": "ha-diagnostics:lock-sha256", "value": hashlib.sha256(lock.read_bytes()).hexdigest()},
                {"name": "ha-diagnostics:verification", "value": "Lock entries and current interpreter version matches; vulnerability audit is a separate optional action"},
            ],
        },
        "components": components,
    }


def audit(lock: Path, output: Path) -> int:
    try:
        version = metadata.version("pip-audit")
    except metadata.PackageNotFoundError:
        print("AUDIT_UNAVAILABLE: install a separately reviewed hash-pinned pip-audit toolchain.")
        return 2
    if version != AUDIT_VERSION:
        print("AUDIT_VERSION_UNVERIFIED: expected pip-audit " + AUDIT_VERSION)
        return 2
    # Fixed service/arguments, no pip execution, no upgrades. No inherited index,
    # proxy credentials, tool flags or user-provided advisory URL.
    command = [sys.executable, "-m", "pip_audit", "-r", str(lock),
               "--require-hashes", "--no-deps", "--disable-pip", "--strict",
               "--vulnerability-service", "pypi", "--timeout", "15",
               "--progress-spinner", "off", "--format", "json", "--output", str(output)]
    environment = {key: value for key, value in os.environ.items()
                   if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL"}}
    try:
        result = subprocess.run(command, cwd=ROOT, env=environment, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180,
                                check=False)
    except (OSError, subprocess.TimeoutExpired):
        print("AUDIT_FAILED: process unavailable or timed out; no dependency was changed.")
        return 2
    if not output.is_file():
        print("AUDIT_FAILED: no report; no dependency was changed.")
        return 2
    if result.returncode == 0:
        print("AUDIT_COMPLETED_NO_KNOWN_ADVISORIES: this does not prove absence of unknown vulnerabilities.")
        return 0
    print("AUDIT_NONZERO: inspect the local report; no dependency was changed.")
    return result.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", action="store_true", help="Explicitly query public advisories with a preinstalled reviewed pip-audit2.10.1")
    args = parser.parse_args()
    directory = ROOT / "dist/sbom"
    directory.mkdir(parents=True, exist_ok=True)
    inventory = directory / "python-lock.cdx.json"
    report = directory / "python-audit.json"
    if inventory.exists() or (args.audit and report.exists()):
        raise ValueError("OUTPUT_EXISTS: preserve the existing evidence before another run")
    lock = ROOT / "requirements.lock"
    document = sbom(lock)
    inventory.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("PYTHON_LOCK_SBOM_CREATED: " + str(len(document["components"])) + " components; image SBOM remains required.")
    return audit(lock, report) if args.audit else 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Verify pinned local Tunnel bytes and safe extraction; never execute artifacts."""
from __future__ import annotations

import argparse
import hashlib
import json
import stat
import zipfile
import urllib.request
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def download_pinned(arch: str) -> None:
    lock = json.loads((ROOT / "supply-chain.lock.json").read_text(encoding="utf-8"))
    release = lock["tunnel"]["version"]
    if release != "0.0.16":
        raise ValueError("Review downloader before changing the pinned release")
    cache = ROOT / "containers/vendor"
    cache.mkdir(parents=True, exist_ok=True)
    item = lock["tunnel"]["artifacts"][arch]
    for field in ("archive", "sbom", "licenses"):
        asset = item[field]
        filename = asset["name"]
        if Path(filename).name != filename:
            raise ValueError("Invalid locked filename")
        target = cache / filename
        if target.is_symlink():
            raise ValueError("Cache symlink forbidden")
        if target.exists():
            if digest(target.read_bytes()) != asset["sha256"]:
                raise ValueError("Existing cache has mismatched checksum; preserve and investigate")
            continue
        url = f"https://github.com/openai/tunnel-client/releases/download/v{release}/{filename}"
        with urllib.request.urlopen(url, timeout=30) as reply:
            # GitHub release download redirects to its signed release CDN.
            data = reply.read(64 * 1024 * 1024 + 1)
        if len(data) > 64 * 1024 * 1024 or digest(data) != asset["sha256"]:
            raise ValueError("Downloaded bytes exceed bound or differ from pinned SHA256")
        with target.open("xb") as out:
            out.write(data)


def verify(arch: str) -> tuple[dict, Path]:
    lock = json.loads((ROOT / "supply-chain.lock.json").read_text(encoding="utf-8"))
    item = lock["tunnel"]["artifacts"][arch]
    cache = ROOT / "containers" / "vendor"
    for field in ("archive", "sbom", "licenses"):
        resource = item[field]
        path = cache / resource["name"]
        if not path.is_file() or digest(path.read_bytes()) != resource["sha256"]:
            raise ValueError(f"Missing or mismatched pinned {field}: {path.name}")
    archive = cache / item["archive"]["name"]
    sbom_data = (cache / item["sbom"]["name"]).read_bytes()
    licenses_data = (cache / item["licenses"]["name"]).read_bytes()
    sbom = json.loads(sbom_data)
    if sbom.get("spdxVersion") != "SPDX-2.3":
        raise ValueError("Expected release SPDX 2.3 sidecar")
    inventory = {row["fileName"]: next((c["checksumValue"] for c in row["checksums"] if c["algorithm"] == "SHA256"), None)
                 for row in sbom["files"]}
    with zipfile.ZipFile(archive) as zf:
        seen: set[str] = set()
        total = 0
        for member in zf.infolist():
            relative = PurePosixPath(member.filename)
            mode = member.external_attr >> 16
            if (relative.is_absolute() or ".." in relative.parts or "\\" in member.filename
                    or "\x00" in member.filename or member.filename in seen
                    or (mode and stat.S_ISLNK(mode)) or member.is_dir()):
                raise ValueError("Unsafe or duplicate archive member")
            seen.add(member.filename)
            total += member.file_size
            if total > 64 * 1024 * 1024:
                raise ValueError("Uncompressed archive exceeds bound")
            data = zf.read(member)
            if member.filename == item["sbom"]["name"]:
                if data != sbom_data:
                    raise ValueError("Embedded SBOM differs from published sidecar")
            elif member.filename == item["licenses"]["name"]:
                if data != licenses_data:
                    raise ValueError("Embedded licenses differ")
            elif inventory.get(member.filename) != digest(data):
                raise ValueError("SPDX file inventory does not match archive")
        if digest(zf.read("tunnel-client-runtime")) != item["binary_sha256"]:
            raise ValueError("Pinned executable checksum mismatch")
        binary = zf.read("tunnel-client-runtime")
        if binary[:4] != b"\x7fELF" or binary[4] != 2 or int.from_bytes(binary[18:20], "little") != {"amd64": 62, "arm64": 183}[arch]:
            raise ValueError("Wrong ELF architecture")
    return item, archive


def extract_tunnel(arch: str, destination: Path) -> None:
    _, archive = verify(arch)
    destination.mkdir(parents=True, exist_ok=False)
    with zipfile.ZipFile(archive) as zf:
        for member in zf.infolist():
            target = destination / member.filename
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(zf.read(member))
            target.chmod(0o555 if member.filename == "tunnel-client-runtime" else 0o444)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=("amd64", "arm64", "all"), default="all")
    parser.add_argument("--download", action="store_true", help="Explicitly download exact pinned release bytes; never execute")
    args = parser.parse_args()
    for arch in (("amd64", "arm64") if args.arch == "all" else (args.arch,)):
        if args.download:
            download_pinned(arch)
        verify(arch)
        print(f"{arch}: SHA256, embedded sidecars, SPDX inventory, ELF machine verified; execution/provenance not verified")

"""Check the files Supervisor discovers in the published Git repository."""
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_published_app_configs_have_unique_slugs_and_complete_build_contexts():
    tracked = subprocess.check_output(
        ["git", "ls-files", "-z"], cwd=ROOT
    ).decode().split("\0")
    configs = [ROOT / p for p in tracked if Path(p).name in
               {"config.yaml", "config.yml", "config.json"} and (ROOT / p).is_file()]
    assert configs
    slugs = set()
    for config in configs:
        slug = re.search(r"^slug:\s*(\S+)", config.read_text(encoding="utf-8"), re.M)
        assert slug, config
        assert slug[1] not in slugs, f"Duplicate app slug: {config}"
        slugs.add(slug[1])
        dockerfile = config.parent / "Dockerfile"
        assert dockerfile.is_file(), config
        for source in re.findall(r"^COPY\s+(\S+)\s+", dockerfile.read_text(), re.M):
            assert (config.parent / source).exists(), f"Missing build input: {source} in {config.parent}"

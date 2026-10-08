"""Configuration collection/privacy contracts; no live Home Assistant reads."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import zipfile

import pytest
import yaml

from ha_diagnostics.broker import BrokerError
from ha_diagnostics.export_configuration import ConfigurationReader, parse_configuration_yaml
from ha_diagnostics.export_sources import DemoExportSources, ExportSources
from ha_diagnostics.exporter import ExportService, StartExportArgs, ExportSanitizer
from ha_diagnostics.redaction import Redactor


def write(root, path, value):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(value, encoding="utf-8")


def storage(root, key, value):
    write(root, ".storage/" + key, json.dumps({"version": 1, "minor_version": 5, "key": key, "data": value}))


def fixture(root):
    write(root, "configuration.yaml", """default_config: {}
homeassistant:
  time_zone: Asia/Tomsk
  packages: !include_dir_named packages
automation: !include automations.yaml
script: !include scripts.yaml
mqtt:
  password: !secret mqtt_password
  network_key: [1, 2, 3, 4]
http:
  use_x_forwarded_for: true
recorder:
  purge_keep_days: 7
""")
    write(root, "automations.yaml", "- alias: Private automation\n  triggers: []\n  actions: []\n  mode: single\n")
    write(root, "scripts.yaml", "test:\n  sequence: []\n  enabled: false\n  offset: -7\n  count: 0\n  empty: ''\n  spaces: '  '\n")
    write(root, "packages/lights.yaml", "light: !include nested/lights.yaml\n")
    write(root, "packages/nested/lights.yaml", "- platform: demo\n  password: YAML_SECRET_CANARY\n")
    write(root, "secrets.yaml", "mqtt_password: SECRETS_FILE_CANARY\n")
    write(root, "unreferenced.yaml", "password: UNREFERENCED_FILE_CANARY\n")
    storage(root, "core.config_entries", {"entries": [{"entry_id": "a" * 32, "domain": "mqtt", "source": "user",
        "disabled_by": None, "data": {"broker": "192.168.1.3", "port": 1883, "username": "USER_CANARY",
        "password": "ENTRY_SECRET_CANARY"}, "options": {"scan_interval": 0, "enabled": False}}]})
    storage(root, "core.config", {"time_zone": "Asia/Tomsk", "unit_system": "metric", "latitude": 42})
    storage(root, "input_number", {"items": [{"id": "test", "min": -7, "max": 30, "step": 0.5}]})
    storage(root, "lovelace_dashboards", {"items": [{"id": "demo", "url_path": "demo-dashboard"}]})
    storage(root, "lovelace.demo", {"config": {"views": [{"title": "Private dashboard", "cards": []}]}})
    storage(root, "auth", {"credentials": ["AUTH_FILE_CANARY"]})
    write(root, "home-assistant_v2.db", "RECORDER_DB_CANARY")


class SavedSources(DemoExportSources):
    def __init__(self, reader):
        self.reader = reader

    async def configurations(self):
        return await asyncio.to_thread(self.reader.collect)


async def test_configuration_zip_contains_saved_yaml_integrations_helpers_dashboards_and_index(tmp_path):
    root = tmp_path / "homeassistant"
    fixture(root)
    before = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in root.rglob("*") if p.is_file()}
    service = ExportService(tmp_path / "exports", SavedSources(ConfigurationReader(root)),
                            Redactor(b"k" * 32), min_free_bytes=0)
    try:
        job = await service.start(StartExportArgs())
        await service._task
        assert service.jobs[job["export_id"]]["status"] == "ready"
        with zipfile.ZipFile(service.directory / (job["export_id"] + ".zip")) as bundle:
            names = bundle.namelist()
            manifest = json.loads(bundle.read("manifest.json"))
            index = json.loads(bundle.read("configuration/index.json"))
            assert index["home_assistant_overview"]["runtime_configuration"] in names
            assert {r["file"] for r in index["sources"] if r["file"]} == {
                n for n in names if n.startswith("configuration/") and n != "configuration/index.json"}
            values = {json.loads(bundle.read(n))["source_path"]: json.loads(bundle.read(n))
                for n in names if n.startswith("configuration/home_assistant/")}
            assert "packages/nested/lights.yaml" in values
            assert len([v for v in values if v == "packages/nested/lights.yaml"]) == 1
            assert values["configuration.yaml"]["configuration"]["recorder"]["purge_keep_days"] == 7
            assert values["configuration.yaml"]["configuration"]["mqtt"]["password"] == "[REDACTED]"
            assert values["scripts.yaml"]["configuration"]["test"] == {
                "sequence": [], "enabled": False, "offset": -7, "count": 0, "empty": "", "spaces": "  "}
            assert ".storage/input_number" in values and ".storage/lovelace.demo" in values
            entries = json.loads(bundle.read("configuration/integrations/entries.json"))["configuration"]["entries"]
            assert entries[0]["entry_id"] == "a" * 32
            assert entries[0]["options"] == {"scan_interval": 0, "enabled": False}
            assert entries[0]["data"]["port"] == 1883
            contents = b"\n".join(bundle.read(n) for n in names)
            for secret in ("YAML_SECRET_CANARY", "ENTRY_SECRET_CANARY", "SECRETS_FILE_CANARY", "USER_CANARY",
                           "AUTH_FILE_CANARY", "RECORDER_DB_CANARY", "UNREFERENCED_FILE_CANARY"):
                assert secret.encode() not in contents
            assert not any(n.endswith((".yaml", ".db")) for n in names)
            for source in manifest["sources"]:
                if source["file"]:
                    assert hashlib.sha256(bundle.read(source["file"])).hexdigest() == source["sha256"]
            assert all(r["status"] == "ok" for r in index["sources"])
        assert before == {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in root.rglob("*") if p.is_file()}
    finally:
        await service.close()


def test_secret_typed_arbitrary_addon_fields_nested_lists_and_reused_values_are_removed():
    sanitizer = ExportSanitizer(Redactor(b"k" * 32), lambda text: text)
    safe = sanitizer.json({"options": {"opaque": "OPAQUE_SECRET_CANARY", "rows": [
        {"value": "NESTED_SECRET_CANARY", "port": 0}], "count": 0, "enabled": False, "offset": -7, "empty": ""},
        "schema": {"opaque": "password?", "rows": [{"value": "password", "port": "int"}]},
        "description": "opaque=OPAQUE_SECRET_CANARY, nested=NESTED_SECRET_CANARY"}, configuration=True)
    assert safe["options"]["opaque"] == "[REDACTED]"
    assert safe["options"]["rows"] == [{"value": "[REDACTED]", "port": 0}]
    assert safe["options"]["count"] == 0 and safe["options"]["enabled"] is False
    assert safe["schema"]["opaque"] == "password?"
    assert "SECRET_CANARY" not in json.dumps(safe)


@pytest.mark.parametrize("include", ["../outside.yaml", "/etc/passwd", "secrets.yaml", ".storage/auth",
                                     "home-assistant_v2.db", "folder/../../outside.yaml"])
def test_include_never_reads_outside_root_or_secret_stores(tmp_path, include):
    root = tmp_path / "ha"
    write(root, "configuration.yaml", "value: !include " + include + "\n")
    write(tmp_path, "outside.yaml", "value: OUTSIDE_SECRET_CANARY")
    docs = ConfigurationReader(root).collect()
    assert any(d.error == "CONFIG_PATH_DENIED" for d in docs)
    assert "OUTSIDE_SECRET_CANARY" not in repr(docs)


def test_hardlinked_config_file_is_rejected(tmp_path):
    root = tmp_path / "ha"
    root.mkdir()
    outside = tmp_path / "outside.yaml"
    outside.write_text("value: HARDLINK_CANARY")
    os.link(outside, root / "configuration.yaml")
    docs = ConfigurationReader(root).collect()
    assert any(d.origin == "configuration.yaml" and d.error == "CONFIG_LINK_DENIED" for d in docs)
    assert "HARDLINK_CANARY" not in repr(docs)


def test_directory_symlink_is_rejected(tmp_path):
    root = tmp_path / "ha"
    write(root, "configuration.yaml", "value: !include nested/file.yaml")
    outside = tmp_path / "outside"
    write(outside, "file.yaml", "value: SYMLINK_CANARY")
    try:
        (root / "nested").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Creating a real symlink requires OS permission")
    docs = ConfigurationReader(root).collect()
    assert any(d.error == "CONFIG_LINK_DENIED" for d in docs)
    assert "SYMLINK_CANARY" not in repr(docs)


@pytest.mark.parametrize("text,reason", [
    ("a: &a [*a]", "CONFIG_STRUCTURE_LIMIT"),
    ("a: 1\na: 2", "CONFIG_DUPLICATE_KEY"),
    ("value: [", "CONFIG_FORMAT"),
    ("a: " + "[" * 70 + "0" + "]" * 70, "CONFIG_STRUCTURE_LIMIT"),
])
def test_malformed_recursive_and_deep_yaml_fails_with_safe_code(text, reason):
    with pytest.raises(BrokerError, match=reason):
        parse_configuration_yaml(text)


def test_python_tags_env_secret_and_templates_are_never_evaluated(monkeypatch):
    monkeypatch.setenv("CONFIG_TEST_SECRET", "ENV_CANARY")
    value, includes, tags = parse_configuration_yaml("""value: !!python/object/apply:os.system ['echo EXEC_CANARY']
environment: !env_var CONFIG_TEST_SECRET
reference: !secret SECRET_REFERENCE_CANARY
template: '{{ states("sensor.demo") }}'
on: true
""")
    assert "EXEC_CANARY" not in repr(value) and "ENV_CANARY" not in repr(value)
    assert "SECRET_REFERENCE_CANARY" not in repr(value)
    assert value["template"] == '{{ states("sensor.demo") }}'
    assert value["on"] is True and not includes and tags


def test_configuration_byte_and_file_limits_report_gaps(tmp_path):
    fixture(tmp_path)
    docs = ConfigurationReader(tmp_path, max_file_bytes=20).collect()
    assert any(d.error == "CONFIG_FILE_SIZE_LIMIT" for d in docs)
    docs = ConfigurationReader(tmp_path, max_total_bytes=100).collect()
    assert any(d.error == "CONFIG_TOTAL_SIZE_LIMIT" for d in docs)
    docs = ConfigurationReader(tmp_path, max_files=16).collect()
    assert any(d.error == "CONFIG_FILE_LIMIT" for d in docs)


def test_yaml_aliases_cannot_expand_a_small_file_into_an_unbounded_document():
    text = "value: &long '" + "x" * (1024 * 1024) + "'\nlist: [" + ", ".join(["*long"] * 16) + "]"
    with pytest.raises(BrokerError, match="CONFIG_EXPANSION_LIMIT"):
        parse_configuration_yaml(text)


def test_expanded_configuration_is_bounded_across_multiple_small_files(tmp_path):
    write(tmp_path, "configuration.yaml", "first: !include first.yaml\nsecond: !include second.yaml")
    storage(tmp_path, "core.config_entries", {"entries": []})
    repeated = "value: &v abcdefgh\nrepeats: [" + ", ".join(["*v"] * 100) + "]"
    write(tmp_path, "first.yaml", repeated)
    write(tmp_path, "second.yaml", repeated)
    assert sum(p.stat().st_size for p in tmp_path.rglob("*") if p.is_file()) < 2000
    documents = ConfigurationReader(tmp_path, max_total_bytes=2000).collect()
    assert any(d.error == "CONFIG_TOTAL_SIZE_LIMIT" for d in documents)


def test_permission_denied_while_checking_path_is_a_source_gap(tmp_path, monkeypatch):
    fixture(tmp_path)
    reader = ConfigurationReader(tmp_path)
    original = reader._link
    def unreadable(path):
        if path.name == "configuration.yaml":
            raise PermissionError("PRIVATE_OS_ERROR_CANARY")
        return original(path)
    monkeypatch.setattr(reader, "_link", unreadable)
    documents = reader.collect()
    assert any(d.origin == "configuration.yaml" and d.error == "CONFIG_PERMISSION_DENIED" for d in documents)
    assert any(d.origin == ".storage/core.config_entries" and d.error is None for d in documents)
    assert "PRIVATE_OS_ERROR_CANARY" not in repr(documents)


async def test_missing_mount_and_broken_file_do_not_prevent_zip_download(tmp_path):
    service = ExportService(tmp_path / "exports", SavedSources(ConfigurationReader(tmp_path / "missing")),
                            Redactor(b"k" * 32), min_free_bytes=0)
    try:
        job = await service.start(StartExportArgs())
        await service._task
        assert service.jobs[job["export_id"]]["status"] == "ready"
        with zipfile.ZipFile(service.directory / (job["export_id"] + ".zip")) as bundle:
            assert "logs/core.log" in bundle.namelist()
            index = json.loads(bundle.read("configuration/index.json"))
            assert any(r["status"] == "unavailable" and r["reason"] == "CONFIG_NOT_FOUND" for r in index["sources"])
            assert "configuration/addons/fixture_matter.json" in bundle.namelist()
    finally:
        await service.close()


async def test_import_only_does_not_read_live_configuration(tmp_path):
    class ForbiddenReader:
        def collect(self):
            pytest.fail("import-only touched Home Assistant configuration")
    sources = ExportSources(None, configuration_reader=ForbiddenReader())
    try:
        with pytest.raises(BrokerError, match="SOURCE_UNAVAILABLE"):
            await sources.configurations()
    finally:
        await sources.close()


def test_live_package_mounts_homeassistant_config_read_only_and_import_profile_does_not():
    root = Path(__file__).resolve().parents[1]
    for name in ("ha_diagnostics_live/config.yaml", "containers/ha-app/live-profile/config.yaml.in"):
        config = yaml.safe_load((root / name).read_text(encoding="utf-8"))
        assert config["map"] == [{"type": "homeassistant_config", "read_only": True, "path": "/homeassistant"}]
        assert config["full_access"] is False and config["docker_api"] is False
    assert yaml.safe_load((root / "containers/ha-app/config.yaml.in").read_text(encoding="utf-8"))["map"] == []

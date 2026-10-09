"""Bounded reads of saved HA configuration, never a filesystem proxy.

Only the export worker uses this reader. YAML is composed as data: no secret,
environment, template or Python tag is evaluated. Raw bytes never leave RAM.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import date, datetime
import json
import os
from pathlib import Path
import re
import stat

import yaml
from yaml.nodes import MappingNode, ScalarNode, SequenceNode

from .broker import BrokerError

CONFIG_ROOT = Path("/homeassistant")
MAX_CONFIG_FILE_BYTES = 4 * 1024 * 1024
MAX_CONFIG_TOTAL_BYTES = 32 * 1024 * 1024
MAX_CONFIG_FILES = 256
MAX_CONFIG_NODES = 100_000
MAX_EXPANDED_CHARS = 8 * 1024 * 1024
MAX_DIRECTORY_ENTRIES = 4096
YAML_SUFFIXES = {".yaml", ".yml"}
OPTIONAL_YAML = ("automations.yaml", "scripts.yaml", "scenes.yaml", "customize.yaml", "ui-lovelace.yaml")
STORAGE_KEYS = ("core.config", "lovelace", "lovelace_dashboards", "input_boolean", "input_number",
                "input_select", "input_text", "input_datetime", "counter", "timer", "schedule", "zone", "person")
INCLUDE_TAGS = {"!include", "!include_dir_list", "!include_dir_named",
                "!include_dir_merge_list", "!include_dir_merge_named"}
FORBIDDEN_NAMES = re.compile(r"(?:secret|credential|password|token|private[_-]?key)", re.I)
JINJA_REFERENCE = re.compile(r"\{%[-+]?\s*(?:from|import|include|extends)\s+(['\"])([^'\"\r\n]+)\1")
JINJA_STATEMENT = re.compile(r"\{%[-+]?\s*(?:from|import|include|extends)\b")


@dataclass
class ConfigurationDocument:
    label: str
    origin: str
    value: object = None
    error: str | None = None


class BoundedLoader(yaml.SafeLoader):
    """Bound composition itself, before expanding aliases or walking nodes."""
    def __init__(self, text):
        super().__init__(text)
        self.nodes = self.depth = 0

    def compose_node(self, parent, index):
        self.nodes += 1
        self.depth += 1
        try:
            if self.nodes > MAX_CONFIG_NODES or self.depth > 64:
                raise BrokerError("CONFIG_STRUCTURE_LIMIT")
            return super().compose_node(parent, index)
        finally:
            self.depth -= 1


def parse_configuration_yaml(text: str):
    """Preserve structure/tags and include references without running constructors."""
    loader = BoundedLoader(text)
    includes, unknown_tags, active = [], set(), set()
    count = expanded_chars = 0
    def convert(node, depth=0):
        nonlocal count, expanded_chars
        count += 1
        if isinstance(node, ScalarNode):
            expanded_chars += len(node.value)
        if isinstance(node, MappingNode):
            expanded_chars += sum(len(key.value) for key, _ in node.value if isinstance(key, ScalarNode))
        if expanded_chars > MAX_EXPANDED_CHARS:
            raise BrokerError("CONFIG_EXPANSION_LIMIT")
        if count > MAX_CONFIG_NODES or depth > 64 or id(node) in active:
            raise BrokerError("CONFIG_STRUCTURE_LIMIT")
        active.add(id(node))
        try:
            if node.tag in {"!secret", "!env_var"}:
                return {"yaml_tag": node.tag, "value": "[REDACTED]"}
            if node.tag == "!input" and isinstance(node, ScalarNode):
                return {"yaml_tag": node.tag, "value": node.value}
            if node.tag in INCLUDE_TAGS:
                if not isinstance(node, ScalarNode):
                    raise BrokerError("CONFIG_FORMAT")
                includes.append((node.tag, node.value))
                return {"yaml_tag": node.tag, "value": node.value}
            if node.tag not in {"tag:yaml.org,2002:" + tag for tag in
                    ("str", "null", "bool", "int", "float", "timestamp", "seq", "map", "merge")}:
                unknown_tags.add(node.tag)
                return {"yaml_tag": node.tag, "value": "[UNSUPPORTED_TAG_REDACTED]"}
            if isinstance(node, ScalarNode):
                if node.tag == "tag:yaml.org,2002:merge":
                    return node.value
                value = loader.construct_object(node)
                return value.isoformat() if isinstance(value, (date, datetime)) else value
            if isinstance(node, SequenceNode):
                return [convert(child, depth + 1) for child in node.value]
            if isinstance(node, MappingNode):
                result = {}
                for key_node, value_node in node.value:
                    if not isinstance(key_node, ScalarNode):
                        raise BrokerError("CONFIG_FORMAT")
                    key = key_node.value  # Keep numeric/device keys and YAML 1.1 'on' intact.
                    if key in result:
                        raise BrokerError("CONFIG_DUPLICATE_KEY")
                    result[key] = convert(value_node, depth + 1)
                return result
            raise BrokerError("CONFIG_FORMAT")
        finally:
            active.remove(id(node))
    try:
        node = loader.get_single_node()
        value = convert(node) if node is not None else None
        return value, includes, sorted(unknown_tags)
    except (yaml.YAMLError, ValueError, TypeError, RecursionError):
        raise BrokerError("CONFIG_FORMAT") from None
    finally:
        loader.dispose()


class ConfigurationReader:
    def __init__(self, root=CONFIG_ROOT, *, max_file_bytes=MAX_CONFIG_FILE_BYTES,
                 max_total_bytes=MAX_CONFIG_TOTAL_BYTES, max_files=MAX_CONFIG_FILES):
        # Test injection only; no UI, IPC, environment or MCP parameter chooses this path.
        self.root = Path(os.path.abspath(root))
        self.max_file_bytes, self.max_total_bytes, self.max_files = max_file_bytes, max_total_bytes, max_files

    @staticmethod
    def _link(path):
        return path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)())

    def _path(self, relative, *, storage=False):
        path = Path(os.path.abspath(self.root / relative))
        try:
            parts = path.relative_to(self.root).parts
        except ValueError:
            raise BrokerError("CONFIG_PATH_DENIED") from None
        if not parts or any("\\" in part or ":" in part or any(ord(c) < 32 for c in part) for part in parts):
            raise BrokerError("CONFIG_PATH_DENIED")
        if storage:
            allowed = {"core.config_entries", *STORAGE_KEYS}
            if len(parts) != 2 or parts[0] != ".storage" or not (parts[1] in allowed or
                    re.fullmatch(r"lovelace\.[a-zA-Z0-9_-]{1,128}", parts[1])):
                raise BrokerError("CONFIG_PATH_DENIED")
        elif any(p.startswith(".") or FORBIDDEN_NAMES.search(p) for p in parts):
            raise BrokerError("CONFIG_PATH_DENIED")
        current = self.root
        for part in (None, *parts):
            if part is not None:
                current /= part
            try:
                if self._link(current):
                    raise BrokerError("CONFIG_LINK_DENIED")
            except PermissionError:
                raise BrokerError("CONFIG_PERMISSION_DENIED") from None
            except OSError:
                raise BrokerError("CONFIG_READ_FAILED") from None
        return path

    def _read(self, relative, *, storage=False, template=False):
        path = self._path(relative, storage=storage)
        if template and (path.relative_to(self.root).parts[0] != "custom_templates" or path.suffix != ".jinja"):
            raise BrokerError("CONFIG_PATH_DENIED")
        if not storage and not template and path.suffix.lower() not in YAML_SUFFIXES:
            raise BrokerError("CONFIG_PATH_DENIED")
        # Linux dirfd traversal prevents parent-directory symlink races. Windows
        # fixtures additionally reject junctions and verify the opened file inode.
        fds = []
        try:
            if os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW"):
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY
                fds.append(os.open(self.root, flags))
                parts = path.relative_to(self.root).parts
                for part in parts[:-1]:
                    fds.append(os.open(part, flags, dir_fd=fds[-1]))
                fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fds[-1])
            else:
                fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0))
            with os.fdopen(fd, "rb") as file:
                before = os.fstat(file.fileno())
                if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                    raise BrokerError("CONFIG_LINK_DENIED")
                if before.st_size > self.max_file_bytes:
                    raise BrokerError("CONFIG_FILE_SIZE_LIMIT")
                if (before.st_dev, before.st_ino) != (path.lstat().st_dev, path.lstat().st_ino):
                    raise BrokerError("CONFIG_CHANGED")
                body = file.read(self.max_file_bytes + 1)
                after = os.fstat(file.fileno())
                if len(body) > self.max_file_bytes:
                    raise BrokerError("CONFIG_FILE_SIZE_LIMIT")
                if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                    raise BrokerError("CONFIG_CHANGED")
                self._path(relative, storage=storage)
                return body
        except FileNotFoundError:
            raise BrokerError("CONFIG_NOT_FOUND") from None
        except PermissionError:
            raise BrokerError("CONFIG_PERMISSION_DENIED") from None
        except OSError:
            raise BrokerError("CONFIG_READ_FAILED") from None
        finally:
            for fd in reversed(fds):
                os.close(fd)

    def _include_paths(self, parent, tag, reference):
        # HA treats relative includes as relative to the containing YAML file.
        if not reference or "\\" in reference or Path(reference).is_absolute():
            raise BrokerError("CONFIG_PATH_DENIED")
        relative = (parent / reference).as_posix()
        path = self._path(relative)
        if tag == "!include":
            return [path.relative_to(self.root).as_posix()]
        found, pending, scanned = [], [path], 0
        while pending:
            folder = pending.pop()
            self._path(folder.relative_to(self.root))
            try:
                with os.scandir(folder) as entries:
                    for entry in entries:
                        scanned += 1
                        if scanned > MAX_DIRECTORY_ENTRIES:
                            raise BrokerError("CONFIG_DIRECTORY_LIMIT")
                        if entry.name.startswith(".") or FORBIDDEN_NAMES.search(entry.name):
                            continue
                        candidate = Path(entry.path)
                        if self._link(candidate):
                            raise BrokerError("CONFIG_LINK_DENIED")
                        if entry.is_dir(follow_symlinks=False):
                            pending.append(candidate)
                        elif candidate.suffix.lower() in YAML_SUFFIXES:
                            found.append(candidate.relative_to(self.root).as_posix())
            except FileNotFoundError:
                raise BrokerError("CONFIG_NOT_FOUND") from None
            except PermissionError:
                raise BrokerError("CONFIG_PERMISSION_DENIED") from None
            except OSError:
                raise BrokerError("CONFIG_READ_FAILED") from None
        return sorted(found)

    @staticmethod
    def _dependencies(value, relative):
        found = []
        initial = "script" if Path(relative).name == "scripts.yaml" or relative.startswith("blueprints/script/") else "automation"
        def visit(item, domain=initial):
            if len(found) > MAX_CONFIG_FILES:
                raise BrokerError("CONFIG_FILE_LIMIT")
            if isinstance(item, dict):
                blueprint = item.get("use_blueprint")
                if isinstance(blueprint, dict):
                    path = blueprint.get("path")
                    if isinstance(path, str):
                        found.append(("blueprint", f"blueprints/{domain}/{path}"))
                if item.get("mode") == "yaml" and isinstance(item.get("filename"), str):
                    found.append(("yaml_dashboard", item["filename"]))
                for key, child in item.items():
                    current = "script" if key.split(" ", 1)[0] == "script" else (
                        "automation" if key.split(" ", 1)[0] == "automation" else domain)
                    visit(child, current)
            elif isinstance(item, list):
                for child in item:
                    visit(child, domain)
            elif isinstance(item, str):
                matches = list(JINJA_REFERENCE.finditer(item))
                found.extend(("jinja_template", "custom_templates/" + match[2]) for match in matches)
                if len(matches) < len(JINJA_STATEMENT.findall(item)):
                    found.append(("dynamic_jinja_reference", ""))
        visit(value)
        return list(dict.fromkeys(found))

    def collect(self):
        documents, total, expanded_total, attempted = [], 0, 0, 0
        def measured(value):
            nonlocal expanded_total
            # A small YAML file can repeat anchors in many documents. Bound
            # the aggregate parsed representation before retaining it in RAM.
            expanded_total += len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8"))
            if expanded_total > self.max_total_bytes:
                raise BrokerError("CONFIG_TOTAL_SIZE_LIMIT")
            return value
        def document(label, relative, *, storage=False, optional=False, template=False):
            nonlocal total, attempted
            attempted += 1
            try:
                if attempted > self.max_files:
                    raise BrokerError("CONFIG_FILE_LIMIT")
                body = self._read(relative, storage=storage, template=template)
                total += len(body)
                if total > self.max_total_bytes:
                    raise BrokerError("CONFIG_TOTAL_SIZE_LIMIT")
                text = body.decode("utf-8-sig")
                if template:
                    return ConfigurationDocument(label, relative, measured({"source_path": relative,
                        "template": text, "interpretation": "saved_jinja_source_not_evaluated"})), []
                if storage:
                    value = json.loads(text)
                    if not isinstance(value, dict) or not isinstance(value.get("data"), dict):
                        raise BrokerError("CONFIG_FORMAT")
                    if relative == ".storage/core.config_entries" and not isinstance(value["data"].get("entries"), list):
                        raise BrokerError("CONFIG_FORMAT")
                    return ConfigurationDocument(label, relative, measured({"source_path": relative,
                        "storage_version": value.get("version"), "storage_minor_version": value.get("minor_version"),
                        "configuration": value["data"]})), []
                value, includes, tags = parse_configuration_yaml(text)
                return ConfigurationDocument(label, relative, measured({"source_path": relative,
                    "configuration": value, "unresolved_tags": tags,
                    "interpretation": "saved_yaml_without_secret_environment_or_template_evaluation"})), includes
            except BrokerError as error:
                if optional and error.code == "CONFIG_NOT_FOUND":
                    return None, []
                return ConfigurationDocument(label, relative, error=error.code), []
            except (ValueError, TypeError, RecursionError):
                return ConfigurationDocument(label, relative, error="CONFIG_FORMAT"), []

        dependent_files = []
        def dependencies(entry):
            if entry and not entry.error:
                try:
                    edges = self._dependencies(entry.value.get("configuration", entry.value.get("template")), entry.origin)
                    entry.value["dependencies"] = [{"kind": kind, "target": target or None} for kind, target in edges]
                    measured(entry.value["dependencies"])
                    dependent_files.extend((target, False) for kind, target in edges if target)
                    if any(kind == "dynamic_jinja_reference" for kind, _ in edges):
                        documents.append(ConfigurationDocument(entry.label + "-references", entry.origin,
                                                             error="CONFIG_DYNAMIC_REFERENCE"))
                except BrokerError as error:
                    documents.append(ConfigurationDocument(entry.label + "-references", entry.origin, error=error.code))

        entry, _ = document("configuration/integrations/entries", ".storage/core.config_entries", storage=True)
        if entry:
            documents.append(entry)
        if attempted > self.max_files or max(total, expanded_total) > self.max_total_bytes:
            return documents
        dashboard_ids = []
        for key in STORAGE_KEYS:
            entry, _ = document("configuration/home_assistant/storage/" + key, ".storage/" + key,
                                storage=True, optional=True)
            if entry:
                documents.append(entry)
                dependencies(entry)
                if key == "lovelace_dashboards" and not entry.error:
                    items = entry.value["configuration"].get("items", [])
                    if isinstance(items, list):
                        dashboard_ids = [item["id"] for item in items if isinstance(item, dict)
                            and isinstance(item.get("id"), str) and re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", item["id"])]
            if attempted > self.max_files or max(total, expanded_total) > self.max_total_bytes:
                return documents
        for dashboard_id in sorted(set(dashboard_ids))[:self.max_files]:
            entry, _ = document("configuration/home_assistant/storage/lovelace." + dashboard_id,
                ".storage/lovelace." + dashboard_id, storage=True)
            documents.append(entry)
            dependencies(entry)
            if attempted > self.max_files or max(total, expanded_total) > self.max_total_bytes:
                return documents

        pending = deque([("configuration.yaml", False), *((path, True) for path in OPTIONAL_YAML), *dependent_files])
        dependent_files.clear()
        visited, number, references = set(), 0, 0
        while pending:
            relative, optional = pending.popleft()
            if relative in visited:
                continue
            visited.add(relative)
            number += 1
            label = f"configuration/home_assistant/yaml/{number:03d}"
            template = relative.startswith("custom_templates/") and relative.endswith(".jinja")
            entry, includes = document(label, relative, optional=optional, template=template)
            if entry:
                documents.append(entry)
                dependencies(entry)
            if attempted > self.max_files or max(total, expanded_total) > self.max_total_bytes:
                break
            for tag, reference in includes:
                references += 1
                if references > self.max_files or len(pending) > self.max_files:
                    number += 1
                    documents.append(ConfigurationDocument(f"configuration/home_assistant/yaml/{number:03d}",
                        relative, error="CONFIG_FILE_LIMIT"))
                    return documents
                try:
                    paths = self._include_paths(Path(relative).parent, tag, reference)
                    if len(paths) + len(pending) > self.max_files:
                        raise BrokerError("CONFIG_FILE_LIMIT")
                    pending.extend((path, False) for path in paths)
                except BrokerError as error:
                    number += 1
                    documents.append(ConfigurationDocument(f"configuration/home_assistant/yaml/{number:03d}",
                        (Path(relative).parent / reference).as_posix(), error=error.code))
            if len(pending) + len(dependent_files) > self.max_files:
                documents.append(ConfigurationDocument(label + "-references", relative, error="CONFIG_FILE_LIMIT"))
                break
            pending.extend(dependent_files)
            dependent_files.clear()
        return documents

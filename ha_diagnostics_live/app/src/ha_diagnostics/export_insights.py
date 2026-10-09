"""Bounded host observations and summaries; no shell or user-selected paths."""
from __future__ import annotations

import hashlib
import ipaddress
import json
from pathlib import Path

from .broker import BrokerError
from .timeutil import source_time

RESOURCE_FILES = {"cpu": "/proc/cpuinfo", "memory": "/proc/meminfo",
                  "memory_limit": "/sys/fs/cgroup/memory.max", "cpu_limit": "/sys/fs/cgroup/cpu.max"}
MAX_RESOURCE_BYTES = 1024 * 1024
MAX_SUMMARY_ITEMS = 256


def host_resources():
    result = {"scope": "kernel_visible_resources", "sources": {}, "cpu": {}, "memory": {},
              "container_limits": {}, "notes": [
                  "In a VM these are guest resources, not the physical hypervisor.",
                  "Container cgroup limits are separate from kernel-visible totals."]}
    for kind, filename in RESOURCE_FILES.items():
        try:
            with Path(filename).open("rb") as file:
                body = file.read(MAX_RESOURCE_BYTES + 1)
            if len(body) > MAX_RESOURCE_BYTES:
                raise BrokerError("RESOURCE_SIZE_LIMIT")
            text = body.decode("utf-8")
            if kind == "cpu":
                rows = [line.split(":", 1) for line in text.splitlines() if ":" in line]
                result["cpu"] = {"logical_processors": sum(key.strip() == "processor" for key, _ in rows),
                    "models": sorted({value.strip() for key, value in rows
                        if key.strip() in {"model name", "Hardware", "Processor"}})[:16]}
            elif kind == "memory":
                keys = {"MemTotal": "total_bytes", "MemAvailable": "available_bytes", "MemFree": "free_bytes",
                        "SwapTotal": "swap_total_bytes", "SwapFree": "swap_free_bytes"}
                for line in text.splitlines():
                    key, _, value = line.partition(":")
                    if key in keys:
                        number, unit = value.split()
                        if unit != "kB" or not number.isdecimal():
                            raise ValueError()
                        result["memory"][keys[key]] = int(number) * 1024
            else:
                result["container_limits"][kind] = text.strip()
            result["sources"][kind] = {"origin": filename, "status": "ok"}
        except (OSError, UnicodeError, ValueError, BrokerError):
            result["sources"][kind] = {"origin": filename, "status": "unavailable",
                                       "reason": "RESOURCE_UNAVAILABLE"}
    return result


class LogCoverage:
    def __init__(self, zone):
        self.zone = zone
        self.first = self.last = self.minimum = self.maximum = None
        self.timestamped = self.unparsed = self.assumed = 0

    def add(self, line):
        # Never interpret a local timestamp as UTC when its timezone is unknown.
        parsed = source_time(line[:128], self.zone or "Etc/Unknown")
        stamp = parsed["event_time_utc"]
        if stamp is None:
            self.unparsed += 1
            return
        self.timestamped += 1
        self.assumed += parsed["time_quality"] == "assumed_timezone"
        self.first = self.first or stamp
        self.last = stamp
        self.minimum = min(self.minimum or stamp, stamp)
        self.maximum = max(self.maximum or stamp, stamp)

    def as_dict(self):
        return {"first_written_timestamp_utc": self.first, "last_written_timestamp_utc": self.last,
                "earliest_timestamp_utc": self.minimum, "latest_timestamp_utc": self.maximum,
                "timestamped_lines": self.timestamped, "lines_without_usable_timestamp": self.unparsed,
                "assumed_timezone_lines": self.assumed, "assumed_timezone": self.zone,
                "basis": "written_log_lines_only", "historical_completeness": "unknown"}


def history_coverage(value, kind, sanitizer):
    rows = [row for group in value for row in group if isinstance(row, dict)] if (
        kind == "history" and isinstance(value, list) and all(isinstance(g, list) for g in value)) else (
        [row for row in value if isinstance(row, dict)] if isinstance(value, list) else [])
    entities, times = {}, []
    for row in rows:
        entity = row.get("entity_id")
        if isinstance(entity, str):
            ref = sanitizer.redactor.alias("ENTITY", entity)
            entities[ref] = entities.get(ref, 0) + 1
        stamp = row.get("last_updated", row.get("last_changed")) if kind == "history" else row.get("when")
        if isinstance(stamp, (int, float)):
            from datetime import datetime, timezone
            try:
                stamp = datetime.fromtimestamp(stamp, timezone.utc).isoformat()
            except (ValueError, OverflowError, OSError):
                stamp = None
        if isinstance(stamp, str):
            parsed = source_time(stamp, "Etc/Unknown")["event_time_utc"]
            if parsed:
                times.append(parsed)
    return {"returned_records": len(rows), "entity_count": len(entities),
            "entities": dict(sorted(entities.items())[:MAX_SUMMARY_ITEMS]),
            "entity_list_truncated": len(entities) > MAX_SUMMARY_ITEMS,
            "earliest_timestamp_utc": min(times, default=None), "latest_timestamp_utc": max(times, default=None),
            "basis": "returned_records_in_requested_window", "absence_does_not_prove_exclusion": True}


def network_context(value, redactor):
    """Preserve scope and subnet relationships while omitting address/prefix bits."""
    rows, subnets, invalid, omitted = [], {}, 0, 0
    interfaces = value.get("interfaces", []) if isinstance(value, dict) else []
    if not isinstance(interfaces, list):
        raise BrokerError("UPSTREAM_FORMAT")
    for interface in interfaces:
        if not isinstance(interface, dict):
            continue
        for family in ("ipv4", "ipv6"):
            config = interface.get(family, {})
            if not isinstance(config, dict):
                continue
            for role, values in (("address", config.get("address", [])),
                                 ("gateway", [config.get("gateway")]),
                                 ("nameserver", config.get("nameservers", []))):
                if not isinstance(values, list):
                    values = [values]
                for text in values:
                    if not isinstance(text, str) or not text:
                        continue
                    if len(rows) >= 512:
                        omitted += 1
                        continue
                    try:
                        address = ipaddress.ip_interface(text)
                        ip = address.ip
                        scope = ("link_local" if ip.is_link_local else "loopback" if ip.is_loopback else
                            "multicast" if ip.is_multicast else "unspecified" if ip.is_unspecified else
                            "unique_local" if ip.version == 6 and ip in ipaddress.ip_network("fc00::/7") else
                            "private" if ip.is_private else "global" if ip.is_global else "reserved")
                        row = {"interface": interface.get("interface"), "role": role,
                               "address_ref": redactor.alias("ADDRESS", str(ip).split("%", 1)[0]),
                               "family": ip.version, "scope": scope, "scope_id_present": "%" in text}
                        if "/" in text:
                            subnet = address.network
                            ref = redactor.alias("SUBNET", str(subnet))
                            subnets[ref] = subnet
                            row.update(prefix_length=subnet.prefixlen, subnet_ref=ref)
                        rows.append(row)
                    except ValueError:
                        invalid += 1
    relations = [{"subnet_ref": a, "contained_in": b} for a, x in subnets.items()
                 for b, y in subnets.items() if a != b and x.version == y.version and x.subnet_of(y)]
    return {"addresses": rows, "subnet_relations": relations, "invalid_addresses": invalid,
            "omitted_addresses": omitted, "address_limit": 512,
            "notes": ["Subnet references are local keyed pseudonyms; no address or network prefix bits are included.",
                      "Scope and configured addresses do not prove connectivity or Matter commissioning."]}


def pick(value, fields):
    return {key: value[key] for key in fields if key in value} if isinstance(value, dict) else {}


VERSION_FIELDS = ("version", "version_latest", "update_available", "arch", "machine", "state", "healthy", "supported")


def overview_section(label, value):
    if label == "system/host":
        return pick(value, ("operating_system", "kernel", "chassis", "virtualization", "agent_version",
                           "docker_version", "disk_total", "disk_used", "disk_free", "features", "boot_timestamp"))
    if label == "system/os":
        return pick(value, (*VERSION_FIELDS, "board", "boot", "data_disk"))
    if label == "system/hardware":
        return {key: {"total": len(value[key]), "items": [pick(row,
                    ("name", "vendor", "model", "type", "subsystem", "driver", "dev_path", "size"))
                for row in value[key][:MAX_SUMMARY_ITEMS]], "truncated": len(value[key]) > MAX_SUMMARY_ITEMS}
                for key in ("devices", "drives") if isinstance(value, dict) and isinstance(value.get(key), list)}
    if label == "system/network" and isinstance(value, dict):
        interfaces = value.get("interfaces", [])
        return {"host_internet": value.get("host_internet"), "supervisor_internet": value.get("supervisor_internet"),
                "interfaces": [pick(row, ("interface", "type", "enabled", "connected", "primary", "ipv4", "ipv6"))
                    for row in interfaces[:MAX_SUMMARY_ITEMS]]} if isinstance(interfaces, list) else {}
    if label in {"system/host_services", "system/disk_usage", "system/swap"}:
        return value
    if label == "system/health" and isinstance(value, dict):
        return pick(value, ("homeassistant", "hassio", "recorder"))
    if label in {"system/resources", "system/network_context"}:
        return value
    if label in {"system/core", "system/supervisor", "system/dns", "system/audio", "system/cli", "system/observer", "system/multicast"}:
        return pick(value, VERSION_FIELDS)
    if label.startswith("addons/") and label.endswith("/info"):
        return pick(value, (*VERSION_FIELDS, "slug", "name", "boot", "auto_update", "watchdog", "repository"))
    if label == "registries/integrations" and isinstance(value, list):
        return {"total": len(value), "items": [pick(row, ("entry_id", "domain", "title", "state", "disabled_by"))
            for row in value[:MAX_SUMMARY_ITEMS]], "truncated": len(value) > MAX_SUMMARY_ITEMS}
    return None


def overview_text(value):
    lines = ["HA-Diagnostics — Система / Устройство и окружение", "Паспорт хоста Home Assistant",
             "Дата сбора: " + value["observed_at"], "",
             "Виртуальная машина показывает ресурсы гостя. Ограничения контейнера приведены отдельно.",
             "Недоступные характеристики не вычисляются из нагрузки или лимита памяти контейнера.", ""]
    for section, data in value["sections"].items():
        lines.extend([section + ":", json.dumps(data, ensure_ascii=False, indent=2), ""])
    lines.append("Результаты источников: см. system/overview.json и manifest.json.")
    return "\n".join(lines) + "\n"


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False,
                                   separators=(",", ":")).encode()).hexdigest()


def comparison_record(label, safe, origin=None):
    # Dynamic readings are excluded; configuration and inventories retain their content hash.
    if label.startswith("configuration/") and label != "configuration/index":
        if isinstance(safe, dict):
            safe = {key: value for key, value in safe.items() if key != "dependencies"}
        if origin:
            return "configuration:" + origin, fingerprint(safe)
        return label, fingerprint(safe)
    if label.startswith("registries/") and isinstance(safe, list):
        rows = [pick(row, tuple(k for k in row if k != "state")) for row in safe if isinstance(row, dict)]
        rows.sort(key=lambda row: json.dumps(row, sort_keys=True, ensure_ascii=False))
        return label, fingerprint(rows)
    if label in {"system/core", "system/supervisor", "system/os", "system/dns", "system/audio", "system/cli",
                  "system/observer", "system/multicast"} or label.startswith("addons/") and label.endswith("/info"):
        return label, fingerprint(pick(safe, ("version", "arch", "machine", "board", "slug", "repository")))
    return None


def comparison_key(label, origin=None):
    if label.startswith("configuration/") and label != "configuration/index":
        return "configuration:" + origin if origin else label
    if label.startswith("registries/") or label in {"system/core", "system/supervisor", "system/os", "system/dns",
            "system/audio", "system/cli", "system/observer", "system/multicast"} or (
            label.startswith("addons/") and label.endswith("/info")):
        return label
    return None

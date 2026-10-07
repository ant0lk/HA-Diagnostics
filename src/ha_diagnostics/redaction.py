"""Local layered sanitization. Unknown secrets remain an explicit residual risk."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

REDACTION_VERSION = "1"
MAX_TEXT = 16000
SECRET_KEY = re.compile(r"(?:password|passwd|secret|token|api[_-]?key|credential|cookie|authorization|setup[_-]?code|pin[_-]?code|qr[_-]?code|wifi[_-]?key|private[_-]?key)", re.I)
IDENTIFIER_KEY = re.compile(r"^(?:ip|ip_address|host|hostname|mac|mac_address|serial|serial_number|unique_id|entity_id|device_id|name|friendly_name|area|area_id|room|ssid|address)$", re.I)
SAFE_KEYS = frozenset("""data diagnostics devices entities integration integrations errors warnings status state old_state new_state attributes safe_attributes safe_fields related_source_ids version versions hardware software firmware model manufacturer type error message exception traceback level logger time timestamp event_time event_time_utc observed_at last_changed last_updated duration count code value unit available unavailable unknown connected port protocol reason kind boot_id cursor source_id time_quality source_timestamp source_offset precision timestamp_origin mapping_origin mapping_confidence source_ids entity_refs device_ref entity_ref integration_ref context_ref snapshot_id record_id sanitized_message fingerprint redaction_version truncated parse_error time_error source_time_range coverage_notes approved_fields name friendly_name area room entity_id device_id unique_id ip ip_address host hostname mac mac_address serial serial_number ssid address config_entries entries title domain entry_id disabled_by entity_category supported_features device_class state_class unit_of_measurement result success capabilities timezone time_zone timezone_origin is_snapshot ingestion_basis from to collected_since latest_observed_at parser_version enabled local_ref error_type exception_type retry timeout latency battery temperature humidity power voltage energy uptime platform connection state_changed availability description meta metadata network connections identifiers listeners observed collected schema_version config core supervisor os host boundary_state old_state_known origin removed rotation_epoch tail disconnected upstream_cursor deduplication_basis architecture arch machine operating_system hassos home_assistant supervisor_version version_latest version_supervisor version_hassos version_homeassistant update_supported healthy supported state running features hassio component components config_entry_id model_id sw_version hw_version name_by_user suggested_area connections units unit_system temperature pressure volume accumulated_precipitation wind_speed weight length mass uv_index license installation_type internal external docker agent""".split())
SAFE_REMOVED_NAMES = frozenset("password passwd secret access_token refresh_token token api_key cookie cookies authorization wifi_password mqtt_password credentials setup_code qr_code pin_code private_key".split())
KNOWN_PATTERNS = [
    re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    re.compile(r"\b(?:sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{8,}|github_pat_[A-Za-z0-9_]{8,})\b"),
    re.compile(r"\bMT:[A-Z0-9.\-]+", re.I),
    re.compile(r"(?i)-----BEGIN [^-]*(?:PRIVATE KEY|CERTIFICATE)-----.*?-----END [^-]+-----", re.S),
]
KEY_VALUE = re.compile(r'''(?ix)(\b(?:password|passwd|secret|access[_ -]?token|refresh[_ -]?token|token|api[_ -]?key|cookie|authorization|wifi[_ -]?(?:password|key)|mqtt[_ -]?(?:password|user(?:name)?)|setup[_ -]?code|pairing[_ -]?code|pin[_ -]?code|qr[_ -]?code)\b["']?\s*[=:]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;}]+)''')
ID_VALUE = re.compile(r'''(?ix)(\b(?:serial(?:[_ -]?number)?|unique[_ -]?id|device[_ -]?id|entity[_ -]?id|ssid)\b["']?\s*[=:]\s*)("[^"\r\n]*"|'[^'\r\n]*'|[^\s,;}]+)''')
URL = re.compile(r"https?://[^\s<>\"']+|mqtts?://[^\s<>\"']+", re.I)
MAC = re.compile(r"(?<![\w])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![\w])", re.I)
IPV4 = re.compile(r"(?<![\w])(?:\d{1,3}\.){3}\d{1,3}(?![\w])")
IPV6 = re.compile(r"(?<![\w])(?:[0-9a-f]{0,4}:){2,}[0-9a-f:.]{0,39}(?:%[A-Za-z0-9_.-]+)?", re.I)
ENTITY = re.compile(r"\b(?:light|switch|sensor|binary_sensor|climate|cover|fan|number|select|button|person|device_tracker|camera|alarm_control_panel|lock|media_player|automation|script|update)\.[A-Za-z0-9_]+\b")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


class Redactor:
    def __init__(self, key: bytes, version: str = REDACTION_VERSION):
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("REDACTION_KEY_TOO_SHORT")
        self._key, self.version = key, version

    def alias(self, kind: str, value: object) -> str:
        if isinstance(value, str) and re.fullmatch(r"\[[A-Z0-9_]{1,24}_[a-f0-9]{16}\]", value):
            return value
        kind = re.sub(r"[^A-Z0-9_]", "_", kind.upper())[:24]
        digest = hmac.new(self._key, (kind + "\0" + str(value)).encode("utf-8"), hashlib.sha256).hexdigest()[:16]
        return f"[{kind}_{digest}]"

    def _url(self, match: re.Match) -> str:
        if re.fullmatch(r"(?:https?|mqtts?)://\[(?:HOST|ADDRESS)_[a-f0-9]{16}\](?::\d{1,5})?/\[PATH\]", match.group(0), re.I):
            return match.group(0)
        try:
            url = urlsplit(match.group(0))
            raw_host = url.hostname or "unknown"
            try:
                host = self.alias("ADDRESS", str(ipaddress.ip_address(raw_host.split("%", 1)[0])))
            except ValueError:
                host = self.alias("HOST", raw_host.lower())
            port = f":{url.port}" if url.port is not None else ""
            # Paths can themselves be credentials; retain only transport context.
            return urlunsplit((url.scheme, host + port, "/[PATH]", "", ""))
        except ValueError:
            return "[URL_REDACTED]"

    def clean_text(self, value: str, max_chars: int | None = MAX_TEXT) -> str:
        if not isinstance(value, str):
            raise ValueError("TEXT_REQUIRED")
        if len(value) > 20 * 1024 * 1024:
            raise ValueError("INPUT_TOO_LARGE")
        text = value.replace("\x00", "[NUL]")
        for pattern in KNOWN_PATTERNS:
            text = pattern.sub("[SECRET_REDACTED]", text)
        text = KEY_VALUE.sub(lambda m: m.group(1) + "[SECRET_REDACTED]", text)
        text = ID_VALUE.sub(lambda m: m.group(1) + self.alias("ENTITY" if "entity" in m.group(1).lower() else "IDENTIFIER", m.group(2).strip("\"'")), text)
        text = URL.sub(self._url, text)
        text = MAC.sub(lambda m: self.alias("ADDRESS", m.group(0).lower().replace("-", ":")), text)
        def address(match: re.Match) -> str:
            try:
                normalized = str(ipaddress.ip_address(match.group(0).split("%", 1)[0]))
                return self.alias("ADDRESS", normalized)
            except ValueError:
                return match.group(0)
        text = IPV4.sub(address, text)
        text = IPV6.sub(address, text)
        text = ENTITY.sub(lambda m: self.alias("ENTITY", m.group(0)), text)
        text = EMAIL.sub(lambda m: self.alias("EMAIL", m.group(0).lower()), text)
        if max_chars is not None and len(text) > max_chars:
            text = text[:max_chars] + "\n[TRUNCATED]"
        return text

    def clean_json(self, value: object, *, approved_fields: set[str] | frozenset[str] | None = None,
                   removed_fields: list[str] | None = None, max_depth: int = 64, max_nodes: int = 100000) -> object:
        allowed = SAFE_KEYS if approved_fields is None else frozenset(approved_fields)
        counter = [0]
        def walk(item: object, depth: int) -> object:
            counter[0] += 1
            if depth > max_depth or counter[0] > max_nodes:
                raise ValueError("JSON_LIMIT_EXCEEDED")
            if item is None or isinstance(item, (bool, int, float)):
                return item
            if isinstance(item, str):
                if len(item) > MAX_TEXT:
                    raise ValueError("JSON_STRING_TOO_LONG")
                return self.clean_text(item)
            if isinstance(item, list):
                return [walk(v, depth + 1) for v in item]
            if isinstance(item, dict):
                result = {}
                for key, raw in item.items():
                    if not isinstance(key, str) or len(key) > 200:
                        raise ValueError("INVALID_JSON_KEY")
                    if SECRET_KEY.search(key) or key not in allowed:
                        if removed_fields is not None:
                            label = key if key in SAFE_REMOVED_NAMES else self.alias("FIELD", key)
                            if label not in removed_fields:
                                removed_fields.append(label)
                        continue
                    if IDENTIFIER_KEY.fullmatch(key) and raw is not None:
                        kind = "ENTITY" if key == "entity_id" else "ADDRESS" if key in {"ip", "ip_address", "mac", "mac_address", "address"} else "IDENTIFIER"
                        if isinstance(raw, (str, int)) and not isinstance(raw, bool) and raw != "":
                            if kind == "ADDRESS":
                                try:
                                    raw = str(ipaddress.ip_address(str(raw).split("%", 1)[0]))
                                except ValueError:
                                    raw = str(raw).lower().replace("-", ":")
                            raw = self.alias(kind, raw)
                    result[key] = walk(raw, depth + 1)
                return result
            raise ValueError("JSON_TYPE_UNSUPPORTED")
        return walk(value, 0)

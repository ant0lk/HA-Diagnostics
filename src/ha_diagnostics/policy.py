"""Local configuration. Only the broker writes; each read reloads the policy."""
from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator

SENSITIVE_DOMAINS = frozenset({"camera", "media_player", "person", "device_tracker", "geo_location", "zone", "alarm_control_panel", "lock", "image", "conversation", "tts", "stt"})

class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

class SourcePolicy(Strict):
    source_id: str = Field(min_length=1, max_length=100, pattern=r"^[a-zA-Z0-9_:-]+$")
    collect: bool = False
    disclose: bool = False

class OAuthConfig(Strict):
    issuer: str = ""
    resource: str = ""
    jwks_uri: str = ""
    introspection_uri: str = ""
    client_id: str = ""
    @field_validator("issuer", "resource", "jwks_uri", "introspection_uri")
    @classmethod
    def secure_url(cls, value):
        from urllib.parse import urlsplit
        if value:
            u = urlsplit(value)
            if u.scheme != "https" or not u.hostname or u.username or u.password or u.fragment or u.query:
                raise ValueError("INVALID_OAUTH_CONFIGURATION")
        return value

class LocalPolicy(Strict):
    schema_version: str = "1"
    installation_id: str = Field(default="local", pattern=r"^[a-zA-Z0-9_-]{1,80}$")
    version: int = Field(default=1, ge=1)
    mode: Literal["import_only", "live"] = "import_only"
    timezone: str = "UTC"
    remote_enabled: bool = False
    collection_enabled: bool = False
    sources: list[SourcePolicy] = Field(default_factory=list, max_length=200)
    entity_ids: list[str] = Field(default_factory=list, max_length=1000)
    entity_refs: list[str] = Field(default_factory=list, max_length=1000)
    owner_sub: str = Field(default="", max_length=300)
    disclose_names: bool = False
    retention_days: int = Field(default=7, ge=1, le=30)
    max_bytes: int = Field(default=512 * 1024**2, ge=8 * 1024**2, le=512 * 1024**2)
    oauth: OAuthConfig = Field(default_factory=OAuthConfig)
    @field_validator("entity_ids")
    @classmethod
    def safe_entities(cls, values):
        import re
        if len(set(values)) != len(values) or any(not re.fullmatch(r"[a-z_]+\.[a-z0-9_]+", x) or x.split(".")[0] in SENSITIVE_DOMAINS for x in values):
            raise ValueError("ENTITY_POLICY_DENIED")
        return values
    @field_validator("timezone")
    @classmethod
    def timezone_exists(cls, value):
        from zoneinfo import ZoneInfo
        ZoneInfo(value)
        return value

    def allowed_sources(self):
        return {s.source_id for s in self.sources if s.collect and s.disclose}

class PolicyStore:
    def __init__(self, path: Path | str):
        self.path = Path(path)
    def read(self) -> LocalPolicy:
        try:
            return LocalPolicy.model_validate_json(self.path.read_bytes())
        except (OSError, ValueError):
            return LocalPolicy() # fail closed, never continue with stale authorization
    def write(self, policy: LocalPolicy):
        current = self.read()
        policy = policy.model_copy(update={"version": current.version + 1})
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_suffix(".tmp")
        temp.write_text(policy.model_dump_json(indent=2), encoding="utf-8")
        os.replace(temp, self.path)
        return policy

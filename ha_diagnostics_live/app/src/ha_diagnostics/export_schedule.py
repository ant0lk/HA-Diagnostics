"""Persistent owner-local daily ZIP schedule; no Home Assistant writes."""
from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone
import json
import os
from pathlib import Path
import secrets
import stat
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, field_validator

DAILY_TIME = r"^(?:[01][0-9]|2[0-3]):[0-5][0-9]$"
EXPORT_ID = r"^export_[a-f0-9]{32}$"


class ScheduleArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    enabled: bool
    time: str = Field(pattern=DAILY_TIME)


class ExportSchedule(ScheduleArgs):
    enabled: bool = True
    time: str = "03:00"
    # Never silently schedule in UTC when the installation's zone is unknown.
    timezone: str | None = Field(default=None, max_length=100)
    last_run_date: str | None = None
    last_export_id: str | None = Field(default=None, pattern=EXPORT_ID)
    last_run_status: Literal["collecting", "ready", "failed", "cancelled"] | None = None

    @field_validator("timezone")
    @classmethod
    def known_timezone(cls, value):
        if value is not None:
            try:
                ZoneInfo(value)
            except (ValueError, ZoneInfoNotFoundError):
                raise ValueError("UNKNOWN_TIMEZONE") from None
        return value

    @field_validator("last_run_date")
    @classmethod
    def calendar_date(cls, value):
        if value is not None and date.fromisoformat(value).isoformat() != value:
            raise ValueError("INVALID_SCHEDULE_DATE")
        return value

    def due_at(self, day: date) -> datetime:
        # fold=0 picks the first repeated hour. A missing spring hour moves
        # forward by the DST gap when converted to UTC (02:30 -> 03:30).
        return datetime.combine(day, time.fromisoformat(self.time),
                                tzinfo=ZoneInfo(self.timezone)).astimezone(timezone.utc)

    def next_run(self, now: datetime) -> str | None:
        if not self.enabled or self.timezone is None:
            return None
        day = now.astimezone(ZoneInfo(self.timezone)).date()
        if self.last_run_date is not None:
            day = max(day, date.fromisoformat(self.last_run_date) + timedelta(days=1))
        # An overdue time today stays visible until the worker can start it.
        return self.due_at(day).isoformat().replace("+00:00", "Z")


class ScheduleStore:
    """Bounded reads and atomic replacement in the worker's private directory."""
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.path.parent.is_symlink() or not self.path.parent.is_dir():
            raise ValueError("UNSAFE_SCHEDULE_STORAGE")

    def read(self) -> ExportSchedule:
        try:
            descriptor = os.open(self.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                                 | getattr(os, "O_NONBLOCK", 0))
        except FileNotFoundError:
            return ExportSchedule()
        with os.fdopen(descriptor, "rb") as source:
            info = os.fstat(source.fileno())
            if self.path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("UNSAFE_SCHEDULE_STORAGE")
            body = source.read(8193)
        if len(body) > 8192:
            raise ValueError("SCHEDULE_SETTINGS_TOO_LARGE")
        return ExportSchedule.model_validate(json.loads(body))

    def write(self, schedule: ExportSchedule) -> None:
        if self.path.is_symlink():
            raise ValueError("UNSAFE_SCHEDULE_STORAGE")
        if self.path.exists():
            info = self.path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("UNSAFE_SCHEDULE_STORAGE")
        temporary = self.path.parent / (".export-schedule-" + secrets.token_hex(16))
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                 | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(descriptor, "wb") as target:
                target.write((schedule.model_dump_json(indent=2) + "\n").encode())
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary, self.path)
        finally:
            temporary.unlink(missing_ok=True)

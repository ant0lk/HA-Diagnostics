"""Explicit UTC intervals and source time parsing; never substitute observation time."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

UTC = timezone.utc
ISO_EXPLICIT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$")
SOURCE_TIMESTAMP = re.compile(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?(?:Z|[+-]\d{2}:?\d{2})?)")


def utc_now() -> str:
    return format_utc(datetime.now(UTC))


def format_utc(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("EXPLICIT_TIMEZONE_REQUIRED")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def parse_explicit(value: str) -> datetime:
    if not isinstance(value, str) or not ISO_EXPLICIT.fullmatch(value):
        raise ValueError("EXPLICIT_TIMEZONE_REQUIRED")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("INVALID_TIMESTAMP") from None
    return parsed.astimezone(UTC)


def validate_interval(from_: str, to: str, max_hours: int = 24) -> tuple[str, str]:
    start, end = parse_explicit(from_), parse_explicit(to)
    if end <= start or end - start > timedelta(hours=max_hours):
        raise ValueError("INVALID_TIME_RANGE")
    return format_utc(start), format_utc(end)


def localize(naive: datetime, zone: str, fold: int | None = None) -> datetime:
    """Require a choice for repeated local time, reject the missing spring hour."""
    try:
        tz = ZoneInfo(zone)
    except ZoneInfoNotFoundError:
        raise ValueError("UNKNOWN_TIMEZONE") from None
    if naive.tzinfo is not None:
        raise ValueError("LOCAL_NAIVE_TIME_REQUIRED")
    candidates = [naive.replace(tzinfo=tz, fold=n) for n in (0, 1)]
    valid = [d for d in candidates if d.astimezone(UTC).astimezone(tz).replace(tzinfo=None) == naive]
    if not valid:
        raise ValueError("NONEXISTENT_LOCAL_TIME")
    if len({d.utcoffset() for d in valid}) > 1:
        if fold not in (0, 1):
            raise ValueError("AMBIGUOUS_LOCAL_TIME")
        return candidates[fold]
    return valid[0]


def source_time(line: str, zone: str = "UTC") -> dict:
    match = SOURCE_TIMESTAMP.match(line)
    if not match:
        return {"event_time_utc": None, "source_timestamp": None, "source_offset": None,
                "precision": "unknown", "timestamp_origin": "absent", "time_quality": "unknown"}
    original = match.group(1)
    result = {"source_timestamp": original, "source_offset": None,
              "precision": "fraction" if "." in original or "," in original else "second",
              "timestamp_origin": "source", "event_time_utc": None, "time_quality": "parse_error"}
    try:
        parsed = datetime.fromisoformat(original.replace(",", ".").replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = localize(parsed, zone)
            result["time_quality"] = "assumed_timezone"
        else:
            result["time_quality"] = "source_timestamp"
        result["event_time_utc"] = format_utc(parsed)
        result["source_offset"] = parsed.strftime("%z")
    except ValueError as error:
        result["time_error"] = str(error)
    return result

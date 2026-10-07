from datetime import datetime

import pytest

from ha_diagnostics.timeutil import localize, parse_explicit, source_time, validate_interval


def test_tomsk_offset_and_exclusive_interval():
    assert parse_explicit("2026-10-07T21:35:00+07:00").hour == 14
    start, end = validate_interval("2026-10-07T21:35:00+07:00", "2026-10-07T21:36:00+07:00")
    assert start == "2026-10-07T14:35:00.000000Z"
    assert end == "2026-10-07T14:36:00.000000Z"


@pytest.mark.parametrize("value", ["21:35", "2026-10-07T21:35:00", "2026-10-07", "2026-10-32T21:35:00Z"])
def test_unanchored_or_invalid_time_rejected(value):
    with pytest.raises(ValueError):
        parse_explicit(value)


def test_dst_fold_and_gap_are_not_guessed():
    with pytest.raises(ValueError, match="AMBIGUOUS_LOCAL_TIME"):
        localize(datetime(2026, 11, 1, 1, 30), "America/New_York")
    with pytest.raises(ValueError, match="NONEXISTENT_LOCAL_TIME"):
        localize(datetime(2026, 3, 8, 2, 30), "America/New_York")
    earlier = localize(datetime(2026, 11, 1, 1, 30), "America/New_York", fold=0)
    later = localize(datetime(2026, 11, 1, 1, 30), "America/New_York", fold=1)
    assert earlier.utcoffset() != later.utcoffset()


def test_missing_timestamp_is_unknown_and_ambiguous_source_retained():
    assert source_time("INFO plain line")["event_time_utc"] is None
    result = source_time("2026-11-01 01:30:00 ERROR issue", "America/New_York")
    assert result["event_time_utc"] is None
    assert result["time_quality"] == "parse_error"
    assert source_time("2026-10-07 21:35:00 INFO", "Asia/Tomsk")["time_quality"] == "assumed_timezone"


def test_intervals_are_bounded_and_nonempty():
    with pytest.raises(ValueError, match="INVALID_TIME_RANGE"):
        validate_interval("2026-10-07T00:00:00Z", "2026-10-09T00:00:00Z")
    with pytest.raises(ValueError):
        validate_interval("2026-10-07T00:00:00Z", "2026-10-07T00:00:00Z")

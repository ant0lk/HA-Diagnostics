"""Daily ZIP scheduling and independent retention, without real HA or wall-clock waits."""
import asyncio
from datetime import datetime, timedelta, timezone
import json
import os
import time
import zipfile

import pytest

from ha_diagnostics.broker import BrokerError
from ha_diagnostics.exporter import ExportArgs, ExportService, StartExportArgs, STRUCTURE_FILE
from ha_diagnostics.export_schedule import ExportSchedule, ScheduleArgs
from ha_diagnostics.export_sources import DemoExportSources
from ha_diagnostics.ipc import ADMIN_UID, AdminIPCServer, IPCError
from ha_diagnostics.redaction import Redactor


class Clock:
    def __init__(self, value="2026-10-07T19:59:00+00:00"):
        self.now = datetime.fromisoformat(value)

    def __call__(self):
        return self.now


def service_at(tmp_path, clock, sources=None):
    return ExportService(tmp_path / "exports", sources or DemoExportSources(),
                         Redactor(b"r" * 32), demo=True, min_free_bytes=0, clock=clock)


async def test_default_daily_time_ha_timezone_once_per_local_day(tmp_path):
    clock = Clock()
    service = service_at(tmp_path, clock)
    try:
        assert service.schedule.enabled and service.schedule.time == "03:00"
        assert service.schedule.timezone is None
        assert await service.run_scheduled() is None
        service._observe_timezone(await service.sources.snapshot("home_assistant/config"))
        assert service.schedule.timezone == "Asia/Tomsk"
        assert service.schedule_status()["next_run_at"] == "2026-10-07T20:00:00Z"
        assert await service.run_scheduled() is None
        clock.now += timedelta(minutes=1)
        job = await service.run_scheduled()
        await service._task
        assert job["kind"] == "automatic" and job["scheduled_date"] == "2026-10-08"
        assert service.jobs[job["export_id"]]["status"] == "ready"
        assert await service.run_scheduled() is None
        await service.set_schedule(ScheduleArgs(enabled=True, time="04:00"))
        clock.now += timedelta(hours=1)
        assert await service.run_scheduled() is None  # Editing time cannot duplicate today's run.
        clock.now -= timedelta(days=1)
        assert await service.run_scheduled() is None  # Clock correction cannot replay a date.
        clock.now += timedelta(days=2)
        next_job = await service.run_scheduled()
        await service._task
        assert next_job["scheduled_date"] == "2026-10-09"
        assert len(service.jobs) == 2
    finally:
        await service.close()


async def test_settings_and_run_mark_survive_restart_and_zip_deletion(tmp_path):
    clock = Clock("2026-10-07T22:00:00+00:00")
    service = service_at(tmp_path, clock)
    service._observe_timezone({"time_zone": "Asia/Tomsk"})
    await service.set_schedule(ScheduleArgs(enabled=False, time="04:30"))
    await service.close()
    service = service_at(tmp_path, clock)
    try:
        assert not service.schedule.enabled and service.schedule.time == "04:30"
        assert service.schedule_status()["timezone_origin"] == "cached_ha_config"
        assert await service.run_scheduled() is None
        await service.set_schedule(ScheduleArgs(enabled=True, time="04:30"))
        job = await service.run_scheduled()
        await service._task
        await service.delete(ExportArgs(export_id=job["export_id"]))
    finally:
        await service.close()
    service = service_at(tmp_path, clock)
    try:
        assert service.schedule.last_run_date == "2026-10-08"
        assert await service.run_scheduled() is None
        clock.now += timedelta(days=4)
        job = await service.run_scheduled()  # Catch up today's date, without four backlog ZIPs.
        await service._task
        assert job["scheduled_date"] == "2026-10-12"
        assert len(service.jobs) == 1
    finally:
        await service.close()


async def test_scheduler_runs_without_panel_and_settings_wake_it(tmp_path):
    read = asyncio.Event()
    class Sources(DemoExportSources):
        async def snapshot(self, label):
            result = await super().snapshot(label)
            if label == "home_assistant/config":
                read.set()
            return result
    service = service_at(tmp_path, Clock(), Sources())
    try:
        await service.start_scheduler()
        task = service._scheduler_task
        await service.start_scheduler()
        assert service._scheduler_task is task
        await asyncio.wait_for(read.wait(), 2)
        assert not service.jobs
        await service.set_schedule(ScheduleArgs(enabled=True, time="02:58"))
        async def built():
            while service._task is None:
                await asyncio.sleep(0)
            await service._task
        await asyncio.wait_for(built(), 2)
        assert list(service.jobs.values())[0]["kind"] == "automatic"
    finally:
        await service.close()
    assert task.done()


@pytest.mark.parametrize("explicit_cancel", [False, True])
async def test_interrupted_auto_retries_after_restart_but_owner_cancel_does_not(tmp_path, explicit_cancel):
    class Slow(DemoExportSources):
        async def snapshot(self, label):
            await asyncio.Event().wait()
    clock = Clock("2026-10-07T20:00:00+00:00")
    service = service_at(tmp_path, clock, Slow())
    service._observe_timezone({"time_zone": "Asia/Tomsk"})
    job = await service.run_scheduled()
    await asyncio.sleep(0)
    if explicit_cancel:
        await service.cancel(ExportArgs(export_id=job["export_id"]))
    await service.close()
    service = service_at(tmp_path, clock)
    try:
        retry = await service.run_scheduled()
        if explicit_cancel:
            assert retry is None and service.schedule.last_run_status == "cancelled"
        else:
            assert retry["kind"] == "automatic"
            await service._task
            assert service.schedule.last_run_status == "ready"
    finally:
        await service.close()


async def test_manual_busy_defers_auto_and_disk_failure_can_retry(tmp_path):
    class Slow(DemoExportSources):
        async def snapshot(self, label):
            await asyncio.Event().wait()
    clock = Clock("2026-10-07T20:00:00+00:00")
    service = service_at(tmp_path, clock, Slow())
    try:
        service._observe_timezone({"time_zone": "Asia/Tomsk"})
        manual = await service.start(StartExportArgs())
        assert await service.run_scheduled() is None
        assert service.schedule.last_run_date is None
        await service.cancel(ExportArgs(export_id=manual["export_id"]))
        service.sources = DemoExportSources()
        service.min_free_bytes = 2**63
        with pytest.raises(BrokerError, match="DISK_LOW"):
            await service.run_scheduled()
        assert service.schedule.last_run_date is None
        service.min_free_bytes = 0
        auto = await service.run_scheduled()
        await service._task
        assert service.jobs[auto["export_id"]]["status"] == "ready"
    finally:
        await service.close()


async def test_retention_keeps_seven_auto_and_three_manual_after_restart(tmp_path):
    clock = Clock("2026-10-07T20:00:00+00:00")
    service = service_at(tmp_path, clock)
    service._observe_timezone({"time_zone": "Asia/Tomsk"})
    automatic, manual = [], []
    try:
        for day in range(8):
            job = await service.run_scheduled()
            await service._task
            automatic.append(job["export_id"])
            if day >= 4:
                clock.now += timedelta(seconds=1)
                job = await service.start(StartExportArgs())
                await service._task
                manual.append(job["export_id"])
            clock.now += timedelta(days=1)
        expected = set(automatic[-7:] + manual[-3:])
        assert set(service.jobs) == expected
        for path in service.directory.glob("*.zip"):
            old = time.time() - 14 * 86400
            os.utime(path, (old, old))
        service._cleanup()
        assert len(list(service.directory.glob("*.zip"))) == 10
    finally:
        await service.close()
    restored = service_at(tmp_path, clock)
    try:
        assert set(restored.jobs) == expected
        for export_id in expected:
            assert (await restored.download(ExportArgs(export_id=export_id)))["status"] == "ready"
        assert sum(j["kind"] == "automatic" for j in restored.jobs.values()) == 7
        assert sum(j["kind"] == "manual" for j in restored.jobs.values()) == 3
    finally:
        await restored.close()


async def test_alpha_two_zip_is_restored_as_manual(tmp_path):
    directory = tmp_path / "exports"
    directory.mkdir()
    export_id = "export_" + "a" * 32
    with zipfile.ZipFile(directory / (export_id + ".zip"), "w") as archive:
        archive.writestr("manifest.json", json.dumps({"export_id": export_id,
            "started_at": "2026-10-01T00:00:00Z", "finished_at": "2026-10-01T00:01:00Z", "sources": []}))
    service = service_at(tmp_path, Clock())
    assert (await service.download(ExportArgs(export_id=export_id)))["kind"] == "manual"
    await service.close()


async def test_structure_lists_actual_members_including_itself_and_missing_source(tmp_path):
    class Missing(DemoExportSources):
        async def snapshot(self, label):
            if label == "system/hardware":
                raise BrokerError("NOT_SUPPORTED")
            return await super().snapshot(label)
    service = service_at(tmp_path, Clock(), Missing())
    try:
        job = await service.start(StartExportArgs())
        await service._task
        with zipfile.ZipFile(service.directory / (job["export_id"] + ".zip")) as archive:
            text = archive.read(STRUCTURE_FILE).decode("utf-8")
            lines = text.split("\n" + job["filename"] + "\n", 1)[1].splitlines()
            actual, stack = set(), []
            for line in lines:
                branch = max(line.find("├── "), line.find("└── "))
                assert branch >= 0 and branch % 4 == 0
                name = line[branch + 4:]
                stack = stack[:branch // 4] + [name.rstrip("/")]
                if not name.endswith("/"):
                    actual.add("/".join(stack))
            assert actual == set(archive.namelist())
            assert STRUCTURE_FILE in actual and "system/hardware.json" not in actual
            assert "Название архива: " + job["filename"] in text
    finally:
        await service.close()


@pytest.mark.parametrize("args", [
    {"enabled": "true", "time": "03:00"}, {"enabled": True, "time": "3:00"},
    {"enabled": True, "time": "24:00"}, {"enabled": True, "time": "03:60"},
    {"enabled": True, "time": "03:00:00"},
    {"enabled": True, "time": "03:00", "timezone": "UTC"},
    {"enabled": True, "time": "03:00", "path": "/config"},
])
def test_schedule_settings_are_strict_and_have_no_remote_path_or_timezone(args):
    with pytest.raises(ValueError):
        ScheduleArgs.model_validate(args)


async def test_query_uid_cannot_change_schedule_and_atomic_save_failure_preserves_it(tmp_path, monkeypatch):
    service = service_at(tmp_path, Clock())
    try:
        ipc = AdminIPCServer(tmp_path / "export.sock", service.handlers())
        envelope = {"op": "set_export_schedule", "args": {"enabled": False, "time": "23:15"}}
        with pytest.raises(IPCError, match="IPC_FORBIDDEN"):
            await ipc.dispatch(10002, envelope)
        result = await ipc.dispatch(ADMIN_UID, envelope)
        assert result["time"] == "23:15" and result["enabled"] is False
        before = service.schedule_store.path.read_bytes()
        def fail(*args):
            raise OSError("fixture disk failure")
        monkeypatch.setattr("ha_diagnostics.export_schedule.os.replace", fail)
        with pytest.raises(BrokerError, match="SCHEDULE_SAVE_FAILED"):
            await service.set_schedule(ScheduleArgs(enabled=True, time="04:00"))
        assert service.schedule_store.path.read_bytes() == before
        assert service.schedule.time == "23:15" and not service.schedule.enabled
        assert not list(service.schedule_store.path.parent.glob(".export-schedule-*"))
    finally:
        await service.close()


async def test_corrupt_settings_disable_auto_until_owner_saves(tmp_path):
    private = tmp_path / "private"
    private.mkdir()
    (private / "export-schedule.json").write_text('{"enabled": false,')
    service = service_at(tmp_path, Clock())
    try:
        assert not service.schedule.enabled
        assert service.schedule_status()["error"] == "SCHEDULE_SETTINGS_INVALID"
        await service.set_schedule(ScheduleArgs(enabled=True, time="03:15"))
        assert service.schedule.enabled and service.schedule_status()["error"] is None
    finally:
        await service.close()


@pytest.mark.parametrize("day,expected", [
    ("2026-03-29", "2026-03-29T01:30:00+00:00"),  # Missing 02:30 shifts to 03:30.
    ("2026-10-25", "2026-10-25T00:30:00+00:00"),  # Repeated 02:30 uses the first occurrence.
])
def test_daily_time_handles_missing_and_repeated_dst_hours(day, expected):
    from datetime import date
    schedule = ExportSchedule(time="02:30", timezone="Europe/Berlin")
    assert schedule.due_at(date.fromisoformat(day)) == datetime.fromisoformat(expected)

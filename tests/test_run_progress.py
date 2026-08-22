"""Run progress tracking: heartbeats, the pid/phase columns, and reaping a crashed run.

The trigger for this was a real report of a run stuck at RUNNING forever: the process
that owned it had died (confirmed by `ps` finding no such pid), but nothing had ever told
the ``Run`` row. The on-disk lock releases automatically when its owning process dies --
even via SIGKILL -- so the *next* invocation was never actually blocked; the confusion was
purely a stale database row with no way to tell "still working" from "crashed a while ago"
apart.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import select

from domain_monitor.cli import _format_age, _running_detail_line
from domain_monitor.models import Run
from domain_monitor.service import (
    STALE_RUN_GRACE_HOURS,
    _heartbeat,
    pid_alive,
    reap_stale_runs,
    run_once,
)


def _dead_pid() -> int:
    """A pid essentially guaranteed not to correspond to a running process."""
    return 2**30 - 1


class TestPidAlive:
    def test_this_process_is_alive(self):
        import os

        assert pid_alive(os.getpid()) is True

    def test_an_implausible_pid_is_not_alive(self):
        assert pid_alive(_dead_pid()) is False


class TestHeartbeat:
    def test_updates_phase_pid_and_staged_hint(self, session, session_factory):
        run = Run(status=Run.STATUS_RUNNING)
        session.add(run)
        session.commit()

        _heartbeat(session_factory, run.id, phase="ACQUIRING .ch", pid=4242, staged=12_000)

        session.expire_all()
        refreshed = session.get(Run, run.id)
        assert refreshed.phase == "ACQUIRING .ch"
        assert refreshed.pid == 4242
        assert refreshed.staged_hint == 12_000
        assert refreshed.heartbeat_at is not None

    def test_a_missing_run_does_not_raise(self, session_factory):
        _heartbeat(session_factory, run_id=999_999, phase="X")  # must not raise

    def test_partial_updates_leave_other_fields_alone(self, session, session_factory):
        run = Run(status=Run.STATUS_RUNNING)
        session.add(run)
        session.commit()

        _heartbeat(session_factory, run.id, pid=111)
        _heartbeat(session_factory, run.id, phase="DIFFING")  # no pid this time

        session.expire_all()
        refreshed = session.get(Run, run.id)
        assert refreshed.pid == 111          # untouched by the second call
        assert refreshed.phase == "DIFFING"


class TestReapStaleRuns:
    def test_a_dead_pid_is_reaped(self, session):
        run = Run(status=Run.STATUS_RUNNING, pid=_dead_pid())
        session.add(run)
        session.commit()

        reaped = reap_stale_runs(session)

        assert [r.id for r in reaped] == [run.id]
        session.refresh(run)
        assert run.status == Run.STATUS_FAILED
        assert "no longer running" in run.error_message

    def test_a_live_pid_is_left_running(self, session):
        import os

        run = Run(status=Run.STATUS_RUNNING, pid=os.getpid())
        session.add(run)
        session.commit()

        reaped = reap_stale_runs(session)

        assert reaped == []
        session.refresh(run)
        assert run.status == Run.STATUS_RUNNING

    def test_a_pidless_run_within_the_grace_period_is_left_alone(self, session):
        """Predates pid tracking (or the writer died before its first heartbeat) --
        give it the benefit of the doubt for a while rather than failing it outright."""
        run = Run(
            status=Run.STATUS_RUNNING,
            started_at=dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1),
        )
        session.add(run)
        session.commit()

        reaped = reap_stale_runs(session)

        assert reaped == []
        session.refresh(run)
        assert run.status == Run.STATUS_RUNNING

    def test_a_pidless_run_past_the_grace_period_is_reaped(self, session):
        """This is exactly the reported incident: an old row from before pid tracking
        existed, sitting at RUNNING with no way to check it -- old enough that it cannot
        plausibly still be a real transfer in progress."""
        run = Run(
            status=Run.STATUS_RUNNING,
            started_at=dt.datetime.now(dt.timezone.utc)
            - dt.timedelta(hours=STALE_RUN_GRACE_HOURS + 1),
        )
        session.add(run)
        session.commit()

        reaped = reap_stale_runs(session)

        assert [r.id for r in reaped] == [run.id]
        session.refresh(run)
        assert run.status == Run.STATUS_FAILED
        assert "no heartbeat" in run.error_message

    def test_non_running_rows_are_untouched(self, session):
        run = Run(status=Run.STATUS_SUCCESS, pid=_dead_pid())
        session.add(run)
        session.commit()

        assert reap_stale_runs(session) == []
        session.refresh(run)
        assert run.status == Run.STATUS_SUCCESS


class TestRunOnceRecordsProgress:
    def test_a_successful_run_records_its_own_pid(self, config, session_factory):
        import os

        report = run_once(config, session_factory, zone_names={"ch": ["a.ch", "b.ch"]})
        assert report.status == Run.STATUS_SUCCESS

        with session_factory() as s:
            run = s.get(Run, report.run_id)
            assert run.pid == os.getpid()
            assert run.heartbeat_at is not None

    def test_run_once_reaps_a_stale_run_from_a_previous_crash(self, config, session_factory):
        with session_factory() as s:
            s.add(Run(status=Run.STATUS_RUNNING, pid=_dead_pid()))
            s.commit()
            stale_id = s.execute(
                select(Run.id).where(Run.status == Run.STATUS_RUNNING)
            ).scalar_one()

        run_once(config, session_factory, zone_names={"ch": ["a.ch"]})

        with session_factory() as s:
            stale = s.get(Run, stale_id)
            assert stale.status == Run.STATUS_FAILED


class TestStatusFormatting:
    def test_format_age_short(self):
        assert _format_age(5) == "5s"

    def test_format_age_minutes(self):
        assert _format_age(180) == "3m"

    def test_format_age_hours(self):
        assert _format_age(4 * 3600) == "4.0h"

    def test_negative_age_clamped_to_zero(self):
        """Clock skew between the heartbeat writer and the reader must not print
        nonsense like a negative age."""
        assert _format_age(-5) == "0s"

    def test_running_detail_line_reports_a_dead_pid(self):
        run = Run(
            id=1, status=Run.STATUS_RUNNING, phase="ACQUIRING .ch", staged_hint=500,
            pid=_dead_pid(), heartbeat_at=dt.datetime.now(dt.timezone.utc),
        )
        line = _running_detail_line(run, dt.datetime.now(dt.timezone.utc))
        assert "NOT RUNNING" in line
        assert "ACQUIRING .ch" in line
        assert "staged 500" in line

    def test_running_detail_line_with_no_progress_yet(self):
        run = Run(id=1, status=Run.STATUS_RUNNING)
        line = _running_detail_line(run, dt.datetime.now(dt.timezone.utc))
        assert "no heartbeat yet" in line
        assert "pid unknown" in line

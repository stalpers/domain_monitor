"""Run orchestration and the transaction strategy.

The ordering here is the whole point of the module:

1. acquire zones into staging;
2. **validate** -- nothing below runs until the data is proven complete and plausible;
3. diff, persist domain state and events, evaluate rules, persist matches;
4. **commit** -- detected changes are now durable;
5. deliver alerts;
6. record delivery outcome separately.

Alerting happens after the commit, deliberately. An SMTP outage must never cost us a
detected change: the events are already safe, and the failure is recorded as an ``Alert``
row with ``status=FAILED`` rather than by rolling anything back.

Conversely, any failure in steps 1-3 rolls the transaction back entirely, leaving domain
state exactly as it was. A run either observes the zone correctly or observes nothing.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
import sys
from dataclasses import dataclass, field

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool

from . import availability  # noqa: F401  (interface only; Phase 4 hook)
from .alerts import AlertError, console_alert, send_email, send_failure_email
from .config import Config
from .diff import DiffCounts, apply_diff
from .models import Alert, Run, utcnow
from .ngram import NgramModel, load_model
from .rules import Match, backfill, evaluate_events
from .zones import (
    ZoneError,
    clear_staging,
    hours_since_last_transfer,
    record_snapshot_stat,
    stage_zone,
    validate_transfer,
)

logger = logging.getLogger(__name__)


#: A RUNNING row with no ``pid`` predates this feature (or came from a platform where
#: liveness can't be checked). It gets a time-based grace period instead of an exact
#: check -- generous enough that no real transfer should hit it, since ``lifetime`` on
#: an AXFR alone defaults to an hour.
STALE_RUN_GRACE_HOURS = 6


def pid_alive(pid: int) -> bool:
    """Best-effort: is this process still running?

    POSIX only. ``os.kill(pid, 0)`` sends no signal, it just asks the kernel whether the
    pid exists and is ours to signal. On a platform where that check isn't meaningful
    (Windows), assume alive: a false "still running" costs a stale status line, while a
    false "dead" would incorrectly fail a run that is actually still in progress.
    """
    if sys.platform == "win32":
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True  # exists but not ours to signal (EPERM), or an ambiguous error
    return True


def reap_stale_runs(session: Session) -> list[Run]:
    """Fail any RUNNING row whose owning process is provably gone.

    The on-disk lock (``locking.process_lock``) is released by the OS the instant its
    owning process dies, even via SIGKILL or an OOM kill -- so a crashed run never blocks
    the *next* invocation from acquiring the lock and starting. But nothing else ever
    revisits the crashed run's own ``Run`` row, so without this it sits at RUNNING in
    ``domain-monitor status`` forever: indistinguishable from genuine, current progress.

    Called at the start of every run (so a crash is cleaned up automatically on the next
    attempt) and by ``domain-monitor status`` (so it's visible without waiting for one).
    """
    running = list(
        session.execute(select(Run).where(Run.status == Run.STATUS_RUNNING)).scalars()
    )
    reaped: list[Run] = []
    now = utcnow()
    for run in running:
        if run.pid is not None:
            if pid_alive(run.pid):
                continue
            reason = f"process {run.pid} is no longer running"
        else:
            started = run.started_at
            if started.tzinfo is None:
                started = started.replace(tzinfo=dt.timezone.utc)
            age_hours = (now - started).total_seconds() / 3600.0
            if age_hours < STALE_RUN_GRACE_HOURS:
                continue  # no pid recorded (pre-dates this feature); not old enough yet
            reason = f"no heartbeat and started {age_hours:.1f}h ago"

        run.status = Run.STATUS_FAILED
        run.finished_at = now
        run.error_message = f"orphaned: {reason} (the run crashed or was killed)"
        logger.warning("Run %d: marked FAILED -- %s", run.id, reason)
        reaped.append(run)

    if reaped:
        session.commit()
    return reaped


def _heartbeat(
    session_factory: sessionmaker[Session],
    run_id: int,
    *,
    phase: str | None = None,
    pid: int | None = None,
    staged: int | None = None,
) -> None:
    """Report progress on a run that is still going, through its own throwaway connection.

    Deliberately not the run's own session: staging plus diffing is one all-or-nothing
    transaction by design (see the module docstring), so writing progress through it
    would mean either committing early -- breaking that guarantee -- or writing into a
    transaction nobody else can see until it is already over, which defeats the point of
    a heartbeat. So this opens a second, independent connection instead, so a fresh
    ``domain-monitor status`` sees it immediately.

    Two things make that connection deliberately disposable rather than one borrowed
    from the normal pool:

    1. On SQLite, the main transaction can hold the one write lock for the entire run.
       ``timeout=0`` here means a blocked write fails instantly instead of sitting in
       SQLite's default multi-second busy-retry -- a dropped heartbeat is fine, five
       real seconds of it blocking the run five times over is not.
    2. That override must not leak into a *pooled* connection that gets handed to
       something else afterwards expecting the engine's normal timeout. ``NullPool``
       guarantees this connection is closed for good when the block below exits, never
       reused.

    Must never be allowed to fail the run it is reporting on.
    """
    try:
        bind = session_factory().get_bind()
        connect_args = {"timeout": 0} if bind.dialect.name == "sqlite" else {}
        hb_engine = create_engine(bind.url, poolclass=NullPool, connect_args=connect_args)
        try:
            values: dict[str, object] = {"heartbeat_at": utcnow()}
            if phase is not None:
                values["phase"] = phase
            if pid is not None:
                values["pid"] = pid
            if staged is not None:
                values["staged_hint"] = staged
            with hb_engine.begin() as conn:
                conn.execute(Run.__table__.update().where(Run.id == run_id).values(**values))
        finally:
            hb_engine.dispose()
    except Exception:  # noqa: BLE001 - a missed heartbeat must never fail the run
        logger.debug("Run %d: heartbeat update failed, continuing", run_id, exc_info=True)


@dataclass(slots=True)
class RunReport:
    run_id: int
    status: str
    counts: DiffCounts = field(default_factory=DiffCounts)
    matches: list[Match] = field(default_factory=list)
    transferred: bool = False
    skipped_reason: str = ""
    error: str = ""


def run_once(
    cfg: Config,
    session_factory: sessionmaker[Session],
    *,
    tlds: list[str] | None = None,
    dry_run: bool = False,
    send_mail: bool = True,
    force_transfer: bool = False,
    zone_names: dict[str, list[str]] | None = None,
) -> RunReport:
    """Execute one complete monitoring cycle.

    ``zone_names`` injects zone contents directly, bypassing acquisition. Tests use it;
    it is also the seam that makes the pipeline exercisable without a TSIG key.
    """
    target_tlds = tlds or cfg.tlds
    session = session_factory()
    reap_stale_runs(session)
    run = Run(started_at=utcnow(), status=Run.STATUS_RUNNING)
    session.add(run)
    session.commit()                      # the Run row exists even if everything fails
    report = RunReport(run_id=run.id, status=Run.STATUS_RUNNING)
    _heartbeat(session_factory, run.id, phase="STARTING", pid=os.getpid())

    try:
        # --- 1. acquire ---------------------------------------------------------
        results = []
        counts_by_tld: dict[str, int] = {}
        for tld in target_tlds:
            source = cfg.zones[tld]

            age = hours_since_last_transfer(session, tld)
            if (
                not force_transfer
                and zone_names is None
                and age is not None
                and age < cfg.min_transfer_interval_hours
            ):
                # Switch asks for at most one transfer per 24h. Enforced here rather
                # than left to whoever writes the crontab.
                report.skipped_reason = (
                    f".{tld}: last transfer {age:.1f}h ago, under the "
                    f"{cfg.min_transfer_interval_hours}h minimum interval"
                )
                logger.info("%s -- skipping", report.skipped_reason)
                continue

            injected = zone_names.get(tld) if zone_names else None
            _heartbeat(session_factory, run.id, phase=f"ACQUIRING .{tld}")
            result = stage_zone(
                session, run.id, source, names=injected,
                on_progress=lambda n, tld=tld: _heartbeat(
                    session_factory, run.id, phase=f"ACQUIRING .{tld}", staged=n
                ),
            )

            # --- 2. validate ----------------------------------------------------
            _heartbeat(session_factory, run.id, phase=f"VALIDATING .{tld}")
            validate_transfer(session, result, min_ratio=cfg.min_zone_ratio)
            results.append(result)
            counts_by_tld[tld] = result.name_count

        if not results:
            run.status = Run.STATUS_SKIPPED
            run.finished_at = utcnow()
            run.error_message = report.skipped_reason or "no zones transferred"
            session.commit()
            report.status = Run.STATUS_SKIPPED
            return report

        report.transferred = True
        transferred_tlds = [r.tld for r in results]

        # --- 3. diff, persist, evaluate ----------------------------------------
        _heartbeat(session_factory, run.id, phase="DIFFING")
        counts = apply_diff(session, run.id, transferred_tlds)
        report.counts = counts

        _heartbeat(session_factory, run.id, phase="EVALUATING RULES")
        matches: list[Match] = []
        if not counts.baseline:
            models = _load_models(session, transferred_tlds)
            matches = evaluate_events(
                session, run.id, counts.event_ids, cfg.enabled_rules(), models
            )
        report.matches = matches

        for result in results:
            record_snapshot_stat(session, result)

        run.zone_counts = json.dumps(counts_by_tld)
        run.zone_transferred_at = utcnow()
        run.added_count = counts.added
        run.removed_count = counts.removed
        run.returned_count = counts.returned
        run.matched_count = len(matches)
        run.status = Run.STATUS_SUCCESS
        run.finished_at = utcnow()

        clear_staging(session, run.id)

        if dry_run:
            session.rollback()
            logger.info(
                "Dry run: %d added / %d removed / %d returned / %d matches -- nothing written",
                counts.added, counts.removed, counts.returned, len(matches),
            )
            report.status = "DRY_RUN"
            return report

        # --- 4. commit ----------------------------------------------------------
        session.commit()
        report.status = Run.STATUS_SUCCESS

    except (ZoneError, Exception) as exc:
        session.rollback()
        message = str(exc)
        logger.error("Run %d failed: %s", run.id, message)
        # Reload the Run row; the rollback discarded our in-session changes to it.
        failed = session.get(Run, run.id)
        if failed is not None:
            failed.status = Run.STATUS_FAILED
            failed.finished_at = utcnow()
            failed.error_message = message[:4000]
            session.commit()
        report.status = Run.STATUS_FAILED
        report.error = message
        if send_mail and cfg.smtp.enabled:
            send_failure_email(cfg.smtp, run.id, message)
        return report
    finally:
        pass

    # --- 5/6. deliver, then record the outcome ---------------------------------
    if report.matches:
        _deliver(session, cfg, run.id, report.matches, send_mail=send_mail)
    session.close()
    return report


def run_backfill(
    cfg: Config,
    session_factory: sessionmaker[Session],
    *,
    only: str | None = None,
    dry_run: bool = False,
    send_mail: bool = False,
) -> RunReport:
    """Evaluate rules against the domains currently in the zone."""
    session = session_factory()
    reap_stale_runs(session)
    run = Run(started_at=utcnow(), status=Run.STATUS_RUNNING)
    session.add(run)
    session.commit()
    report = RunReport(run_id=run.id, status=Run.STATUS_RUNNING)
    _heartbeat(session_factory, run.id, phase="BACKFILLING", pid=os.getpid())

    try:
        models = _load_models(session, cfg.tlds)
        matches = backfill(session, run.id, cfg.enabled_rules(), only=only, models=models)
        report.matches = matches
        run.matched_count = len(matches)
        run.status = Run.STATUS_SUCCESS
        run.finished_at = utcnow()
        if dry_run:
            session.rollback()
            report.status = "DRY_RUN"
            return report
        session.commit()
        report.status = Run.STATUS_SUCCESS
    except Exception as exc:
        session.rollback()
        failed = session.get(Run, run.id)
        if failed is not None:
            failed.status = Run.STATUS_FAILED
            failed.finished_at = utcnow()
            failed.error_message = str(exc)[:4000]
            session.commit()
        report.status = Run.STATUS_FAILED
        report.error = str(exc)
        return report

    if report.matches:
        _deliver(session, cfg, run.id, report.matches, send_mail=send_mail)
    session.close()
    return report


def _deliver(
    session: Session, cfg: Config, run_id: int, matches: list[Match], *, send_mail: bool
) -> None:
    """Send alerts and record each channel's outcome.

    Runs after the state commit. Nothing in here can lose a detected change; the worst
    case is an ``Alert`` row saying delivery failed.
    """
    if cfg.console_alerts:
        console_alert(matches, run_id, cfg.timezone)
        session.add(Alert(
            run_id=run_id, channel="console", recipient="-", match_count=len(matches),
            sent_at=utcnow(), status=Alert.STATUS_SENT,
        ))

    if send_mail and cfg.smtp.enabled:
        record = Alert(
            run_id=run_id, channel="smtp", recipient=", ".join(cfg.smtp.recipients),
            match_count=len(matches), status=Alert.STATUS_PENDING,
        )
        session.add(record)
        try:
            send_email(matches, run_id, cfg.smtp, cfg.timezone)
        except AlertError as exc:
            record.status = Alert.STATUS_FAILED
            record.error_message = str(exc)[:4000]
            logger.error("Alert delivery failed (domain state is already committed): %s", exc)
        else:
            record.status = Alert.STATUS_SENT
            record.sent_at = utcnow()

    session.commit()


def _load_models(session: Session, tlds: list[str]) -> dict[str, NgramModel]:
    """Load each TLD's trained n-gram model, if one exists.

    Missing is not an error -- lexical scoring degrades gracefully with no model (see
    ``lexical.randomness_score``) rather than blocking a run on ``model build`` having
    been run first.
    """
    models: dict[str, NgramModel] = {}
    for tld in tlds:
        model = load_model(session, tld)
        if model is not None:
            models[tld] = model
    return models


def recent_runs(session: Session, limit: int = 10) -> list[Run]:
    from sqlalchemy import select

    return list(
        session.execute(select(Run).order_by(Run.id.desc()).limit(limit)).scalars()
    )


def last_successful_transfer(session: Session, tld: str) -> dt.datetime | None:
    from .models import ZoneSnapshotStat

    stat = session.get(ZoneSnapshotStat, tld)
    return stat.transferred_at if stat else None

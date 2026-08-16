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
from dataclasses import dataclass, field

from sqlalchemy.orm import Session, sessionmaker

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
    run = Run(started_at=utcnow(), status=Run.STATUS_RUNNING)
    session.add(run)
    session.commit()                      # the Run row exists even if everything fails
    report = RunReport(run_id=run.id, status=Run.STATUS_RUNNING)

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
            result = stage_zone(session, run.id, source, names=injected)

            # --- 2. validate ----------------------------------------------------
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
        counts = apply_diff(session, run.id, transferred_tlds)
        report.counts = counts

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
    run = Run(started_at=utcnow(), status=Run.STATUS_RUNNING)
    session.add(run)
    session.commit()
    report = RunReport(run_id=run.id, status=Run.STATUS_RUNNING)

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

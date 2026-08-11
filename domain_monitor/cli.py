"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from . import __version__
from .alerts import render_text
from .config import Config, ConfigError, load_config
from .database import create_all, create_db_engine, make_session_factory
from .locking import AlreadyRunning, process_lock
from .models import Run
from .service import recent_runs, run_backfill, run_once

logger = logging.getLogger("domain_monitor")


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        level=getattr(logging, level.upper(), logging.INFO),
        stream=sys.stderr,
    )


def _prepare(args: argparse.Namespace) -> tuple[Config, object]:
    cfg = load_config(args.env_file)
    _setup_logging(args.log_level or cfg.log_level)
    engine = create_db_engine(cfg.database_url)
    create_all(engine)
    return cfg, make_session_factory(engine)


def cmd_init(args: argparse.Namespace) -> int:
    cfg, _ = _prepare(args)
    print(f"Initialised {cfg.database_url}")
    print(f"Monitoring: {', '.join('.' + t for t in cfg.tlds)}")
    print(f"Rules loaded: {len(cfg.rules)} ({len(cfg.enabled_rules())} enabled)")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    cfg, session_factory = _prepare(args)
    tlds = [t.lower().lstrip(".") for t in (args.tld or [])] or None
    if tlds:
        unknown = set(tlds) - set(cfg.tlds)
        if unknown:
            raise ConfigError(
                f"--tld {', '.join(sorted(unknown))} not in MONITOR_TLDS ({', '.join(cfg.tlds)})"
            )

    try:
        with process_lock(cfg.lock_path):
            report = run_once(
                cfg, session_factory,
                tlds=tlds,
                dry_run=args.dry_run,
                send_mail=not args.no_email,
                force_transfer=args.force_transfer,
            )
    except AlreadyRunning as exc:
        logger.warning("%s", exc)
        return 0                      # not an error: the work is already being done

    if report.status == Run.STATUS_FAILED:
        logger.error("Run %d FAILED: %s", report.run_id, report.error)
        return 1
    if report.status == Run.STATUS_SKIPPED:
        logger.info("Run %d skipped: %s", report.run_id, report.skipped_reason)
        return 0

    counts = report.counts
    if counts.baseline:
        logger.info(
            "Run %d: baseline of %d domains established, no events emitted",
            report.run_id, counts.added,
        )
    else:
        logger.info(
            "Run %d: %d added / %d removed / %d returned / %d rule match(es)",
            report.run_id, counts.added, counts.removed, counts.returned,
            len(report.matches),
        )

    if args.dry_run and report.matches:
        print(render_text(report.matches, report.run_id, cfg.timezone))
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    cfg, session_factory = _prepare(args)

    if args.backfill:
        with process_lock(cfg.lock_path):
            report = run_backfill(
                cfg, session_factory,
                only=args.rule, dry_run=args.dry_run, send_mail=not args.no_email,
            )
        logger.info("Backfill run %d: %d match(es)", report.run_id, len(report.matches))
        if report.matches and (args.dry_run or not cfg.smtp.enabled):
            print(render_text(report.matches, report.run_id, cfg.timezone))
        return 0

    print(f"{len(cfg.rules)} rule(s), {len(cfg.enabled_rules())} enabled\n")
    for rule in cfg.rules:
        state = "enabled" if rule.enabled else "DISABLED"
        print(f"  {rule.name}  [{state}]")
        print(f"    {rule.description}")
        print(f"    pattern: {rule.regex.pattern}")
        print(f"    events:  {', '.join(sorted(rule.event_types))}")
        print()
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    from sqlalchemy import func, select

    from .models import Domain, DomainEvent, RuleMatch, ZoneSnapshotStat

    cfg, session_factory = _prepare(args)
    with session_factory() as session:
        domains = session.execute(select(func.count()).select_from(Domain)).scalar_one()
        in_zone = session.execute(
            select(func.count()).select_from(Domain).where(Domain.currently_in_zone.is_(True))
        ).scalar_one()
        events = session.execute(select(func.count()).select_from(DomainEvent)).scalar_one()
        matches = session.execute(select(func.count()).select_from(RuleMatch)).scalar_one()

        print(f"Domains known:   {domains:,}")
        print(f"  in zone:       {in_zone:,}")
        print(f"  out of zone:   {domains - in_zone:,}")
        print(f"Events recorded: {events:,}")
        print(f"Rule matches:    {matches:,}")

        stats = list(session.execute(select(ZoneSnapshotStat)).scalars())
        if stats:
            print("\nLast successful transfer:")
            for stat in stats:
                print(
                    f"  .{stat.tld:<4} {stat.name_count:>10,} names  "
                    f"{stat.transferred_at:%Y-%m-%d %H:%M UTC}  ({stat.duration_seconds:.1f}s)"
                )

        runs = recent_runs(session, args.limit)
        if runs:
            print("\nRecent runs:")
            for run in runs:
                counts = json.loads(run.zone_counts or "{}")
                zones = " ".join(f"{k}={v:,}" for k, v in counts.items())
                print(
                    f"  #{run.id:<5} {run.status:<8} {run.started_at:%Y-%m-%d %H:%M}  "
                    f"+{run.added_count} -{run.removed_count} ~{run.returned_count} "
                    f"match={run.matched_count}  {zones}"
                    + (f"  {run.error_message}" if run.error_message else "")
                )
    return 0


def cmd_test_email(args: argparse.Namespace) -> int:
    import datetime as dt

    from .alerts import send_email
    from .rules import Match

    cfg, _ = _prepare(args)
    if not cfg.smtp.enabled:
        raise ConfigError("SMTP_ENABLED is false; nothing to test")

    rule = cfg.enabled_rules()[0] if cfg.enabled_rules() else None
    if rule is None:
        raise ConfigError("no enabled rules to attribute a test alert to")

    fixture = [Match(
        domain_name="test-fixture.ch", tld="ch", event_type="ADDED_TO_ZONE",
        detected_at=dt.datetime.now(dt.timezone.utc), rule_name=rule.name,
        rule_description=rule.description, rule_pattern=rule.regex.pattern,
        matched_value="test-fixture",
    )]
    send_email(fixture, 0, cfg.smtp, cfg.timezone)
    print(f"Test alert sent to {', '.join(cfg.smtp.recipients)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="domain-monitor",
        description="Detect changes in the .ch and .li domain namespace.",
    )
    parser.add_argument("--version", action="version", version=f"domain-monitor {__version__}")
    parser.add_argument("--env-file", type=Path, default=Path(".env"))
    parser.add_argument("--log-level", default=None)

    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="create the database and validate configuration")
    p_init.set_defaults(func=cmd_init)

    p_run = sub.add_parser("run", help="run one monitoring cycle (the cron entry point)")
    p_run.add_argument("--dry-run", action="store_true", help="change nothing, send nothing")
    p_run.add_argument("--tld", action="append", help="limit to this TLD (repeatable)")
    p_run.add_argument("--no-email", action="store_true")
    p_run.add_argument(
        "--force-transfer", action="store_true",
        help="transfer even if the last one was inside the minimum interval",
    )
    p_run.set_defaults(func=cmd_run)

    p_rules = sub.add_parser("rules", help="list rules, or evaluate them against current state")
    p_rules.add_argument(
        "--backfill", action="store_true",
        help="evaluate rules against every in-zone domain, not just this run's events",
    )
    p_rules.add_argument("--rule", default=None, help="with --backfill, limit to this rule")
    p_rules.add_argument("--dry-run", action="store_true")
    p_rules.add_argument("--no-email", action="store_true")
    p_rules.set_defaults(func=cmd_rules)

    p_status = sub.add_parser("status", help="database contents and recent runs")
    p_status.add_argument("--limit", type=int, default=10)
    p_status.set_defaults(func=cmd_status)

    p_mail = sub.add_parser("test-email", help="send a fixture alert to verify SMTP")
    p_mail.set_defaults(func=cmd_test_email)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ConfigError as exc:
        _setup_logging("INFO")
        logger.error("Configuration error: %s", exc)
        return 2
    except KeyboardInterrupt:
        logger.warning("Interrupted")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

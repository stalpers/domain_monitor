"""Command-line interface."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import sys
from pathlib import Path

from . import __version__
from .alerts import render_text
from .config import Config, ConfigError, TypoRule, load_config
from .database import create_all, create_db_engine, make_session_factory
from .locking import AlreadyRunning, process_lock
from .models import Run
from .service import pid_alive, reap_stale_runs, recent_runs, run_backfill, run_once

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

    if args.export_features and report.status == Run.STATUS_SUCCESS and not report.counts.baseline:
        _export_features(session_factory, report.run_id, args.export_features)

    return 0


def _export_features(session_factory, run_id: int, out_path: Path) -> None:
    """Write a lexical-feature CSV row for every event this run evaluated.

    A watchlist hit is a strong-but-sparse signal; deliberately export *every* event, not
    only the ones that fired, so this can grow into a real labelled dataset over time
    (weak label = ``watchlist_fired``) for the classifier the project plan defers rather
    than builds now -- see ``scoring.py`` for why that deferral is deliberate.
    """
    import csv

    from sqlalchemy import select

    from .lexical import extract
    from .models import Domain, DomainEvent, RuleMatch

    with session_factory() as session:
        rows = session.execute(
            select(DomainEvent.event_type, Domain.name, Domain.tld)
            .join(Domain, Domain.id == DomainEvent.domain_id)
            .where(DomainEvent.run_id == run_id)
        ).all()
        hits: dict[str, list[tuple]] = {}
        for name, method, brand, score in session.execute(
            select(Domain.name, RuleMatch.method, RuleMatch.brand, RuleMatch.score)
            .join(Domain, Domain.id == RuleMatch.domain_id)
            .where(RuleMatch.run_id == run_id)
        ):
            hits.setdefault(name, []).append((method, brand, score))

    if not rows:
        logger.info("No events in run %d; nothing to export", run_id)
        return

    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        writer = None
        for event_type, name, tld in rows:
            label = name.rsplit(".", 1)[0] if "." in name else name
            row = {
                "domain": name, "tld": tld, "event_type": event_type,
                **extract(label).as_dict(),
                "watchlist_fired": bool(hits.get(name)),
                "methods": ";".join(sorted({m for m, _, _ in hits.get(name, []) if m})),
                "max_score": max(
                    (s for _, _, s in hits.get(name, []) if s is not None), default="",
                ),
            }
            if writer is None:
                writer = csv.DictWriter(fh, fieldnames=list(row.keys()))
                writer.writeheader()
            writer.writerow(row)
    logger.info("Exported %d feature row(s) to %s", len(rows), out_path)


def cmd_analyse(args: argparse.Namespace) -> int:
    """Score one name and show the full signal breakdown -- the tool for "why did/didn't
    this fire?" without reading code, and for tuning a watchlist before deploying it."""
    from .lexical import extract, randomness_score
    from .ngram import load_model
    from .scoring import Assessment, assess
    from .typosquat import Watchlist

    cfg, session_factory = _prepare(args)

    raw = args.name.lower()
    if "." in raw:
        label, tld = raw.rsplit(".", 1)
    else:
        label, tld = raw, (args.tld or (cfg.tlds[0] if cfg.tlds else None))

    with session_factory() as session:
        model = load_model(session, tld) if tld else None

    features = extract(label)
    print(f"Label: {label!r}  TLD: {'.' + tld if tld else '(unknown)'}")
    print(
        f"Lexical: length={features.length} entropy={features.entropy:.2f} bits/char "
        f"digits={features.digit_ratio:.2f} vowels={features.vowel_ratio:.2f} "
        f"max_consonant_run={features.max_consonant_run} is_idn={features.is_idn}"
    )
    if model is not None and model.trained:
        print(
            f"N-gram model: .{tld} trained on {model.sample_count:,} names, "
            f"likelihood={model.likelihood(label):.3f}"
        )
    else:
        print(f"N-gram model: none trained for .{tld} -- run `model build --tld {tld}`")
    print()

    def show(source: str, result: Assessment) -> None:
        print(f"[{source}] score={result.score:.2f}  fires={result.fires}")
        for sig in result.signals:
            print(f"    {sig.category:<10} {sig.name:<14} weight={sig.weight:.2f}  {sig.reason}")
            if sig.detail:
                print(f"               {sig.detail}")
        print()

    if args.brands:
        watchlist = Watchlist(brands=args.brands, max_distance=args.max_distance)
        show("ad-hoc --brands watchlist", assess(label, watchlist, model, tld=tld))
        return 0

    typo_rules = [r for r in cfg.rules if isinstance(r, TypoRule) and r.enabled]
    if not typo_rules:
        rscore = randomness_score(features, model)
        print(f"No typosquat rules configured and no --brands given.")
        print(f"Randomness score alone: {rscore:.2f} (enrichment only -- never alerts by itself)")
        return 0

    any_fired = False
    for r in typo_rules:
        result = assess(label, r.watchlist, model, tld=tld)
        any_fired = any_fired or result.fires
        show(r.name, result)
    if not any_fired:
        print("No watchlist signal from any rule. (A high lexical score alone never alerts.)")
    return 0


def cmd_model_build(args: argparse.Namespace) -> int:
    from .ngram import build_from_zone, save_model

    cfg, session_factory = _prepare(args)
    tlds = [t.lower().lstrip(".") for t in (args.tld or cfg.tlds)]

    with session_factory() as session:
        for tld in tlds:
            model = build_from_zone(session, tld, order=args.order)
            if not model.trained:
                logger.warning(
                    ".%s: no in-zone domains to train on yet -- run `run` first", tld
                )
                continue
            save_model(session, model)
            session.commit()
            print(
                f".{tld}: trained on {model.sample_count:,} names, "
                f"{model.vocab_size:,} distinct {model.order}-grams"
            )
    return 0


def cmd_model_show(args: argparse.Namespace) -> int:
    from .ngram import load_model

    cfg, session_factory = _prepare(args)
    tlds = [t.lower().lstrip(".") for t in (args.tld or cfg.tlds)]

    with session_factory() as session:
        for tld in tlds:
            model = load_model(session, tld)
            if model is None:
                print(f".{tld}: no model trained")
                continue
            print(
                f".{tld}: order={model.order} sample_count={model.sample_count:,} "
                f"vocab_size={model.vocab_size:,} mean_log_prob={model.mean_log_prob:.3f} "
                f"std_log_prob={model.std_log_prob:.3f}"
            )
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
        print(f"  {rule.name}  [{state}]  ({type(rule).__name__})")
        print(f"    {rule.description}")
        print(f"    {rule.pattern_summary}")
        print(f"    events:  {', '.join(sorted(rule.event_types))}")
        print()
    return 0


def _format_age(seconds: float) -> str:
    """Render a duration the way a human skims a status line, not a stopwatch."""
    if seconds < 0:
        seconds = 0
    if seconds < 90:
        return f"{seconds:.0f}s"
    minutes = seconds / 60
    if minutes < 90:
        return f"{minutes:.0f}m"
    return f"{minutes / 60:.1f}h"


def _running_detail_line(run: Run, now: dt.datetime) -> str:
    """One extra line for a RUNNING row: phase, progress, and whether its process is
    actually still alive -- the difference between "still working" and "crashed, and
    nobody has told the database yet" is invisible without this."""
    bits = []
    if run.phase:
        bits.append(run.phase)
    if run.staged_hint is not None:
        bits.append(f"staged {run.staged_hint:,}")

    if run.pid is not None:
        alive = pid_alive(run.pid)
        bits.append(f"pid {run.pid} ({'alive' if alive else 'NOT RUNNING'})")
    else:
        bits.append("pid unknown (predates progress tracking)")

    if run.heartbeat_at is not None:
        heartbeat = run.heartbeat_at
        if heartbeat.tzinfo is None:
            heartbeat = heartbeat.replace(tzinfo=dt.timezone.utc)
        age = (now - heartbeat).total_seconds()
        bits.append(f"heartbeat {_format_age(age)} ago")
    else:
        bits.append("no heartbeat yet")

    return "        " + "  ".join(bits)


def cmd_status(args: argparse.Namespace) -> int:
    from sqlalchemy import func, select

    from .models import Domain, DomainEvent, RuleMatch, ZoneSnapshotStat

    cfg, session_factory = _prepare(args)
    with session_factory() as session:
        # A run whose process is provably dead is fixed up right here, so a RUNNING row
        # never has to be taken on faith -- if it's still showing RUNNING after this,
        # its pid really is alive (or it predates pid tracking and isn't old enough yet
        # to call, see reap_stale_runs).
        reaped = reap_stale_runs(session)
        for run in reaped:
            print(f"Note: run #{run.id} was stuck at RUNNING; {run.error_message}\n")

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
            now = dt.datetime.now(dt.timezone.utc)
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
                if run.status == Run.STATUS_RUNNING:
                    print(_running_detail_line(run, now))
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
        rule_description=rule.description, rule_pattern=rule.pattern_summary,
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
    p_run.add_argument(
        "--export-features", type=Path, default=None, metavar="PATH",
        help="write a lexical-feature CSV row for every event this run evaluated",
    )
    p_run.set_defaults(func=cmd_run)

    p_analyse = sub.add_parser(
        "analyse", aliases=["analyze"],
        help="score one name and show the full signal breakdown",
    )
    p_analyse.add_argument("name", help="a label or a full domain, e.g. 'examp1e' or 'examp1e.ch'")
    p_analyse.add_argument("--tld", default=None, help="TLD to score against (default: inferred, or first MONITOR_TLDS)")
    p_analyse.add_argument(
        "--brands", nargs="+", default=None,
        help="score against this ad-hoc brand list instead of the configured rules",
    )
    p_analyse.add_argument("--max-distance", type=int, default=1)
    p_analyse.set_defaults(func=cmd_analyse)

    p_model = sub.add_parser("model", help="train and inspect the per-TLD n-gram baseline")
    model_sub = p_model.add_subparsers(dest="model_command", required=True)

    p_model_build = model_sub.add_parser(
        "build", help="train an n-gram model from the currently in-zone domains"
    )
    p_model_build.add_argument("--tld", action="append", help="limit to this TLD (repeatable)")
    p_model_build.add_argument("--order", type=int, default=3, help="n-gram order (default: 3)")
    p_model_build.set_defaults(func=cmd_model_build)

    p_model_show = model_sub.add_parser("show", help="show the trained model's statistics")
    p_model_show.add_argument("--tld", action="append", help="limit to this TLD (repeatable)")
    p_model_show.set_defaults(func=cmd_model_show)

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

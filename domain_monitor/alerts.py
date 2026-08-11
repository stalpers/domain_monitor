"""Alert rendering and delivery.

Two rules shape this module.

**Every alert states its rule.** Name, description, pattern and the matched text travel
with each finding, so a reader can tell why a domain was surfaced without going to the
config. An alert that cannot explain itself is noise.

**One aggregated message per run.** `.ch` sees on the order of a hundred removals a day;
one email per match is a mail-flood, not monitoring. The console channel still prints
each match individually, because a terminal is a different medium from an inbox.
"""

from __future__ import annotations

import datetime as dt
import logging
import smtplib
import zoneinfo
from collections import defaultdict
from email.message import EmailMessage

from .config import SmtpConfig
from .rules import Match

logger = logging.getLogger(__name__)


class AlertError(Exception):
    """Delivery failed. Never raised past the state commit."""


def _localise(value: object, timezone: str) -> str:
    if not isinstance(value, dt.datetime):
        return str(value)
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    try:
        local = value.astimezone(zoneinfo.ZoneInfo(timezone))
    except Exception:                                   # unknown tz name
        local = value
    return local.strftime("%Y-%m-%d %H:%M %Z")


def group_by_rule(matches: list[Match]) -> dict[str, list[Match]]:
    grouped: dict[str, list[Match]] = defaultdict(list)
    for match in matches:
        grouped[match.rule_name].append(match)
    return dict(grouped)


def subject_for(matches: list[Match]) -> str:
    rules = {m.rule_name for m in matches}
    if len(matches) == 1:
        only = matches[0]
        event = only.event_type or "MATCH"
        return f"[DOMAIN ALERT] {event} {only.display_name}"
    if len(rules) == 1:
        return f"[DOMAIN ALERT] {len(matches)} matches — {next(iter(rules))}"
    return f"[DOMAIN ALERT] {len(matches)} rule matches across {len(rules)} rules"


def render_text(matches: list[Match], run_id: int, timezone: str) -> str:
    """Plain-text body, grouped by rule. Shared by both channels."""
    lines = [
        f"{len(matches)} rule match(es) detected.",
        f"Run ID: {run_id}",
        "",
    ]
    for rule_name, group in group_by_rule(matches).items():
        lines.append("=" * 68)
        lines.append(f"Rule: {rule_name}")
        lines.append(f"Description: {group[0].rule_description}")
        lines.append(f"Pattern: {group[0].rule_pattern}")
        lines.append(f"Matches: {len(group)}")
        lines.append("")
        for match in sorted(group, key=lambda m: m.domain_name):
            event = match.event_type or "CURRENT (backfill)"
            lines.append(
                f"  {match.display_name:<40} {event:<20} "
                f"{_localise(match.detected_at, timezone)}"
            )
        lines.append("")

    lines.append("=" * 68)
    lines.append(
        "A domain leaving the zone is not proof that it is available to register. "
        "Zone state and registration state are different things."
    )
    return "\n".join(lines)


def console_alert(matches: list[Match], run_id: int, timezone: str) -> None:
    """Log each match individually; a terminal can take the detail."""
    for match in matches:
        logger.warning(
            "MATCH %s | event=%s | rule=%s | pattern=%s | matched=%s | detected=%s | run=%d",
            match.display_name,
            match.event_type or "CURRENT",
            match.rule_name,
            match.rule_pattern,
            match.matched_value,
            _localise(match.detected_at, timezone),
            run_id,
        )


def build_email(matches: list[Match], run_id: int, cfg: SmtpConfig, timezone: str) -> EmailMessage:
    message = EmailMessage()
    message["Subject"] = subject_for(matches)
    message["From"] = cfg.sender
    message["To"] = ", ".join(cfg.recipients)
    message.set_content(render_text(matches, run_id, timezone))
    return message


def send_email(matches: list[Match], run_id: int, cfg: SmtpConfig, timezone: str) -> None:
    """Deliver the aggregated message, or raise :class:`AlertError`."""
    if not cfg.enabled:
        raise AlertError("SMTP is not enabled")
    if not matches:
        return

    message = build_email(matches, run_id, cfg, timezone)
    try:
        if cfg.use_ssl:
            server: smtplib.SMTP = smtplib.SMTP_SSL(cfg.host, cfg.port, timeout=cfg.timeout)
        else:
            server = smtplib.SMTP(cfg.host, cfg.port, timeout=cfg.timeout)
        with server:
            server.ehlo()
            if cfg.starttls and not cfg.use_ssl:
                server.starttls()
                server.ehlo()
            if cfg.username:
                server.login(cfg.username, cfg.password)
            server.send_message(message)
    except (smtplib.SMTPException, OSError) as exc:
        raise AlertError(f"SMTP delivery to {cfg.host}:{cfg.port} failed: {exc}") from exc

    logger.info("Emailed %d match(es) to %s", len(matches), ", ".join(cfg.recipients))


def send_failure_email(cfg: SmtpConfig, run_id: int, error: str) -> None:
    """Tell someone when a run fails.

    A monitor that goes quiet because it is broken looks exactly like a monitor with
    nothing to report, which is the worst failure mode available to it.
    """
    if not cfg.enabled:
        return
    message = EmailMessage()
    message["Subject"] = f"[DOMAIN MONITOR] Run {run_id} FAILED"
    message["From"] = cfg.sender
    message["To"] = ", ".join(cfg.recipients)
    message.set_content(
        f"domain-monitor run {run_id} failed.\n\n{error}\n\n"
        "No domain state was changed. The next scheduled run will retry."
    )
    try:
        if cfg.use_ssl:
            server: smtplib.SMTP = smtplib.SMTP_SSL(cfg.host, cfg.port, timeout=cfg.timeout)
        else:
            server = smtplib.SMTP(cfg.host, cfg.port, timeout=cfg.timeout)
        with server:
            server.ehlo()
            if cfg.starttls and not cfg.use_ssl:
                server.starttls()
                server.ehlo()
            if cfg.username:
                server.login(cfg.username, cfg.password)
            server.send_message(message)
    except (smtplib.SMTPException, OSError) as exc:
        logger.error("Could not send failure notification: %s", exc)

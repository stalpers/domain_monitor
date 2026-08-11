"""Rule evaluation.

Rules run against **events**, not against the whole namespace. A run that sees 120
changes evaluates 120 names, regardless of the 2.6M sitting unchanged in the zone. That
is what keeps rule processing cheap enough to be irrelevant to runtime.

The exception is :func:`backfill`, which deliberately evaluates against current state.
Without it a rule added today would only ever see tomorrow's changes, and a new brand
rule would never notice the impersonating domain registered last month.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import DomainRule
from .models import Domain, DomainEvent, RuleMatch, utcnow
from .names import to_display

logger = logging.getLogger(__name__)

CHUNK = 5_000


@dataclass(slots=True)
class Match:
    """One rule firing on one domain, carrying everything an alert must state."""

    domain_name: str
    tld: str
    event_type: str | None
    detected_at: object
    rule_name: str
    rule_description: str
    rule_pattern: str
    matched_value: str

    @property
    def display_name(self) -> str:
        return to_display(self.domain_name)


def evaluate_events(
    session: Session, run_id: int, event_ids: list[int], rules: list[DomainRule]
) -> list[Match]:
    """Evaluate rules against this run's events, persisting every match.

    One event may match several rules; each match is recorded separately so an alert can
    say which rules fired and why.
    """
    if not event_ids or not rules:
        return []

    matches: list[Match] = []
    payload: list[dict] = []
    now = utcnow()

    for start in range(0, len(event_ids), CHUNK):
        chunk = event_ids[start : start + CHUNK]
        rows = session.execute(
            select(
                DomainEvent.id, DomainEvent.event_type, DomainEvent.detected_at,
                Domain.id, Domain.name, Domain.tld,
            )
            .join(Domain, Domain.id == DomainEvent.domain_id)
            .where(DomainEvent.id.in_(chunk))
        ).all()

        for event_id, event_type, detected_at, domain_id, name, tld in rows:
            for rule in rules:
                if not rule.enabled or not rule.applies_to(event_type):
                    continue
                matched = rule.matches(name)
                if matched is None:
                    continue
                payload.append({
                    "domain_id": domain_id,
                    "domain_event_id": event_id,
                    "run_id": run_id,
                    "rule_name": rule.name,
                    "rule_description": rule.description,
                    "rule_pattern": rule.regex.pattern,
                    "matched_value": matched[:255],
                    "created_at": now,
                })
                matches.append(Match(
                    domain_name=name, tld=tld, event_type=event_type,
                    detected_at=detected_at, rule_name=rule.name,
                    rule_description=rule.description,
                    rule_pattern=rule.regex.pattern, matched_value=matched,
                ))

    _persist(session, payload)
    if matches:
        logger.info("%d rule match(es) across %d event(s)", len(matches), len(event_ids))
    return matches


def backfill(
    session: Session, run_id: int, rules: list[DomainRule], *, only: str | None = None
) -> list[Match]:
    """Evaluate rules against every domain currently in the zone.

    Matches are recorded with ``domain_event_id = NULL``: this is a match against present
    state, not an observed change. Minting synthetic events for it would put things in
    the event log that never happened, and the log's value is that it is a truthful
    record of observations.
    """
    selected = [r for r in rules if r.enabled and (only is None or r.name == only)]
    if not selected:
        logger.warning("No enabled rules to backfill%s", f" matching {only!r}" if only else "")
        return []

    matches: list[Match] = []
    payload: list[dict] = []
    now = utcnow()
    scanned = 0

    stmt = (
        select(Domain.id, Domain.name, Domain.tld)
        .where(Domain.currently_in_zone.is_(True))
        .execution_options(yield_per=CHUNK)
    )
    for domain_id, name, tld in session.execute(stmt):
        scanned += 1
        for rule in selected:
            matched = rule.matches(name)
            if matched is None:
                continue
            payload.append({
                "domain_id": domain_id,
                "domain_event_id": None,
                "run_id": run_id,
                "rule_name": rule.name,
                "rule_description": rule.description,
                "rule_pattern": rule.regex.pattern,
                "matched_value": matched[:255],
                "created_at": now,
            })
            matches.append(Match(
                domain_name=name, tld=tld, event_type=None, detected_at=now,
                rule_name=rule.name, rule_description=rule.description,
                rule_pattern=rule.regex.pattern, matched_value=matched,
            ))

    _persist(session, payload)
    logger.info(
        "Backfill scanned %d in-zone domain(s) against %d rule(s): %d match(es)",
        scanned, len(selected), len(matches),
    )
    return matches


def _persist(session: Session, payload: list[dict]) -> None:
    for start in range(0, len(payload), CHUNK):
        session.bulk_insert_mappings(RuleMatch, payload[start : start + CHUNK])

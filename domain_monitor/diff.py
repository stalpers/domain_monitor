"""The diff: staged zone versus known domain state.

Computed in SQL, never in Python. Materialising two 2.6M-name sets costs roughly 600 MB
at peak on a machine that may only have a couple of gigabytes; SQL keeps the working set
bounded and behaves identically on SQLite and PostgreSQL.

Three transitions are produced:

``ADDED_TO_ZONE``
    A name in the staged zone that we have never seen. Note the name: it means the name
    is now delegated, **not** that it was necessarily just registered.
``REMOVED_FROM_ZONE``
    A name we believed was in the zone and which is not in the staged zone. It is a
    candidate for having been released, and nothing stronger -- a registered domain can
    lose its delegation and stay registered.
``RETURNED_TO_ZONE``
    A name we had marked as gone that is back.
"""

from __future__ import annotations

import datetime as dt
import logging
from dataclasses import dataclass, field

from sqlalchemy import and_, insert, select, update
from sqlalchemy.orm import Session

from .config import ADDED_TO_ZONE, REMOVED_FROM_ZONE, RETURNED_TO_ZONE
from .models import Domain, DomainEvent, ZoneStaging, utcnow
from .names import tld_of

logger = logging.getLogger(__name__)

CHUNK = 5_000


@dataclass(slots=True)
class DiffCounts:
    added: int = 0
    removed: int = 0
    returned: int = 0
    baseline: bool = False
    event_ids: list[int] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.added + self.removed + self.returned


def is_baseline(session: Session) -> bool:
    """True when no domain has ever been recorded.

    The first successful run establishes the baseline and must emit **zero** events.
    Otherwise the first run of a `.ch` monitor would produce 2.6M ``ADDED_TO_ZONE``
    events and try to email about them.
    """
    return session.execute(select(Domain.id).limit(1)).first() is None


def apply_diff(session: Session, run_id: int, tlds: list[str]) -> DiffCounts:
    """Compare staging against ``domains``, write state and events, return counts."""
    counts = DiffCounts()
    now = utcnow()

    if is_baseline(session):
        counts.baseline = True
        counts.added = _insert_baseline(session, run_id, now)
        logger.info("Baseline established: %d domains imported, no events emitted", counts.added)
        return counts

    counts.added, added_ids = _handle_new_names(session, run_id, now)
    counts.returned, returned_ids = _handle_returned(session, run_id, now)
    counts.removed, removed_ids = _handle_removed(session, run_id, now, tlds)
    _touch_still_present(session, run_id, now)

    counts.event_ids = added_ids + returned_ids + removed_ids
    logger.info(
        "Diff: %d added, %d returned, %d removed",
        counts.added, counts.returned, counts.removed,
    )
    return counts


def _staged_names(session: Session, run_id: int):
    return select(ZoneStaging.name).where(ZoneStaging.run_id == run_id)


def _insert_baseline(session: Session, run_id: int, now: dt.datetime) -> int:
    rows = session.execute(
        select(ZoneStaging.name, ZoneStaging.tld).where(ZoneStaging.run_id == run_id)
    )
    total = 0
    batch: list[dict] = []
    for name, tld in rows:
        batch.append({
            "name": name, "tld": tld, "first_seen_at": now, "last_seen_at": now,
            "currently_in_zone": True, "created_at": now, "updated_at": now,
        })
        if len(batch) >= CHUNK:
            session.bulk_insert_mappings(Domain, batch)
            total += len(batch)
            batch.clear()
    if batch:
        session.bulk_insert_mappings(Domain, batch)
        total += len(batch)
    return total


def _handle_new_names(session: Session, run_id: int, now: dt.datetime) -> tuple[int, list[int]]:
    """Staged names with no ``domains`` row: insert them and emit ADDED_TO_ZONE."""
    stmt = (
        select(ZoneStaging.name, ZoneStaging.tld)
        .outerjoin(Domain, Domain.name == ZoneStaging.name)
        .where(and_(ZoneStaging.run_id == run_id, Domain.id.is_(None)))
    )
    new_rows = session.execute(stmt).all()
    if not new_rows:
        return 0, []

    session.bulk_insert_mappings(Domain, [
        {
            "name": name, "tld": tld, "first_seen_at": now, "last_seen_at": now,
            "currently_in_zone": True, "created_at": now, "updated_at": now,
        }
        for name, tld in new_rows
    ])
    session.flush()

    names = [name for name, _ in new_rows]
    return len(new_rows), _emit_events(session, run_id, names, ADDED_TO_ZONE, now)


def _handle_returned(session: Session, run_id: int, now: dt.datetime) -> tuple[int, list[int]]:
    """Known-but-absent names that are back in the zone."""
    stmt = (
        select(Domain.name)
        .join(ZoneStaging, and_(ZoneStaging.name == Domain.name, ZoneStaging.run_id == run_id))
        .where(Domain.currently_in_zone.is_(False))
    )
    names = [row[0] for row in session.execute(stmt)]
    if not names:
        return 0, []

    for start in range(0, len(names), CHUNK):
        chunk = names[start : start + CHUNK]
        session.execute(
            update(Domain)
            .where(Domain.name.in_(chunk))
            .values(currently_in_zone=True, last_seen_at=now, updated_at=now)
        )
    return len(names), _emit_events(session, run_id, names, RETURNED_TO_ZONE, now)


def _handle_removed(
    session: Session, run_id: int, now: dt.datetime, tlds: list[str]
) -> tuple[int, list[int]]:
    """Names we believed delegated that are absent from the staged zone.

    Scoped to the TLDs actually transferred this run: with ``--tld ch`` every `.li`
    domain is missing from staging, and treating that as removal would be exactly the
    mass-removal bug in a different costume.
    """
    staged = _staged_names(session, run_id).scalar_subquery()
    stmt = select(Domain.name).where(
        and_(
            Domain.currently_in_zone.is_(True),
            Domain.tld.in_(tlds),
            Domain.name.not_in(staged),
        )
    )
    names = [row[0] for row in session.execute(stmt)]
    if not names:
        return 0, []

    for start in range(0, len(names), CHUNK):
        chunk = names[start : start + CHUNK]
        session.execute(
            update(Domain)
            .where(Domain.name.in_(chunk))
            .values(currently_in_zone=False, updated_at=now)
        )
    return len(names), _emit_events(session, run_id, names, REMOVED_FROM_ZONE, now)


def _touch_still_present(session: Session, run_id: int, now: dt.datetime) -> None:
    """Refresh ``last_seen_at`` for names that are simply still there."""
    staged = _staged_names(session, run_id).scalar_subquery()
    session.execute(
        update(Domain)
        .where(and_(Domain.currently_in_zone.is_(True), Domain.name.in_(staged)))
        .values(last_seen_at=now)
    )


def _emit_events(
    session: Session, run_id: int, names: list[str], event_type: str, now: dt.datetime
) -> list[int]:
    """Write one immutable event per name and return the new event ids."""
    if not names:
        return []

    ids_by_name: dict[str, int] = {}
    for start in range(0, len(names), CHUNK):
        chunk = names[start : start + CHUNK]
        rows = session.execute(select(Domain.id, Domain.name).where(Domain.name.in_(chunk)))
        ids_by_name.update({name: did for did, name in rows})

    payload = [
        {
            "domain_id": ids_by_name[name], "event_type": event_type,
            "detected_at": now, "run_id": run_id,
        }
        for name in names if name in ids_by_name
    ]
    if not payload:
        return []

    event_ids: list[int] = []
    for start in range(0, len(payload), CHUNK):
        chunk = payload[start : start + CHUNK]
        result = session.execute(insert(DomainEvent).returning(DomainEvent.id), chunk)
        event_ids.extend(int(row[0]) for row in result)
    return event_ids


def domain_tld(name: str) -> str:
    """Convenience re-export so callers do not reach into ``names`` for one helper."""
    return tld_of(name)

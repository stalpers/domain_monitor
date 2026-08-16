"""Zone acquisition and validation.

Two things here are load-bearing.

**Streaming.** ``dns.zone.from_xfr`` materialises the entire zone as a ``Zone`` object;
for `.ch` that is millions of nodes and gigabytes. This module iterates the messages
``dns.query.xfr`` yields and pushes names into a staging table in batches, so peak memory
is the batch size rather than the zone size.

**Validation.** Nothing downstream may run until a transfer has been proven complete and
plausible. A failed or truncated transfer that reaches the diff stage becomes millions of
spurious "removed" events and an email storm. This is the single most important safety
property in the system, and :func:`validate_transfer` is where it lives.
"""

from __future__ import annotations

import datetime as dt
import logging
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.tsigkeyring
import dns.zone
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from .config import ZoneSource
from .models import ZoneSnapshotStat, ZoneStaging
from .names import normalise_name

logger = logging.getLogger(__name__)

BATCH_SIZE = 10_000


class ZoneError(Exception):
    """The zone could not be obtained, or the result failed validation."""


@dataclass(slots=True)
class TransferResult:
    tld: str
    name_count: int
    duration_seconds: float
    complete: bool


def _iter_axfr_names(source: ZoneSource, timeout: float, lifetime: float) -> Iterator[str]:
    """Yield delegated names from a streaming AXFR.

    Only owner names carrying an ``NS`` RRset are delegations. The zone apex has its own
    ``NS`` records -- those are the zone's nameservers, not a delegation, and including
    them would put the TLD itself into the domain table.
    """
    if not (source.tsig_name and source.tsig_secret):
        raise ZoneError(
            f".{source.tld}: TSIG credentials are not configured "
            f"({source.tld.upper()}_TSIG_KEY_NAME / {source.tld.upper()}_TSIG_SECRET). "
            "Request a key from Switch: https://www.switch.ch/open-data/"
        )
    try:
        keyring = dns.tsigkeyring.from_text({source.tsig_name: source.tsig_secret})
    except Exception as exc:
        raise ZoneError(f".{source.tld}: TSIG secret is not valid: {exc}") from None

    origin = dns.name.from_text(f"{source.tld}.")
    apex = origin.to_text(omit_final_dot=True).lower()

    messages = dns.query.xfr(
        source.server, origin, keyring=keyring, keyalgorithm=source.tsig_algorithm,
        timeout=timeout, lifetime=lifetime, relativize=False,
    )
    for message in messages:
        for rrset in message.answer:
            if rrset.rdtype != dns.rdatatype.NS:
                continue
            owner = rrset.name.to_text(omit_final_dot=True).lower()
            if owner == apex:
                continue
            yield owner


def _iter_file_names(path: Path, tld: str) -> Iterator[str]:
    """Yield names from a one-per-line file.

    Exists so the pipeline is testable and operable without a TSIG key -- the AXFR path
    cannot be exercised in CI or in a restricted network.
    """
    if not path.exists():
        raise ZoneError(f".{tld}: zone file {path} not found")
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            yield line


def stage_zone(
    session: Session,
    run_id: int,
    source: ZoneSource,
    *,
    timeout: float = 30.0,
    lifetime: float = 3600.0,
    names: Iterable[str] | None = None,
) -> TransferResult:
    """Acquire one TLD's zone into the staging table.

    ``names`` overrides acquisition entirely and is used by tests. Returns counts rather
    than the names themselves -- the caller must not need them all in memory.
    """
    started = time.monotonic()
    complete = True

    if names is not None:
        stream: Iterable[str] = names
    elif source.uses_file:
        stream = _iter_file_names(source.file_path, source.tld)
    else:
        stream = _iter_axfr_names(source, timeout, lifetime)

    seen_in_batch: set[str] = set()
    batch: list[dict] = []
    total = 0

    try:
        for raw in stream:
            name = normalise_name(raw)
            if not name or name in seen_in_batch:
                continue
            seen_in_batch.add(name)
            batch.append({"run_id": run_id, "name": name, "tld": source.tld})
            if len(batch) >= BATCH_SIZE:
                session.bulk_insert_mappings(ZoneStaging, batch)
                total += len(batch)
                batch.clear()
                seen_in_batch.clear()
                logger.debug(".%s: staged %d names", source.tld, total)
    except ZoneError:
        raise
    except Exception as exc:
        # A transfer that dies part-way must be reported as incomplete, never silently
        # treated as "the zone is smaller today".
        complete = False
        logger.error(".%s: zone transfer failed after %d names: %s", source.tld, total, exc)
        raise ZoneError(f".{source.tld}: zone transfer failed: {exc}") from exc

    if batch:
        session.bulk_insert_mappings(ZoneStaging, batch)
        total += len(batch)

    duration = time.monotonic() - started
    logger.info(".%s: staged %d delegated names in %.1fs", source.tld, total, duration)
    return TransferResult(source.tld, total, duration, complete)


def validate_transfer(
    session: Session, result: TransferResult, *, min_ratio: float
) -> None:
    """Refuse to let a bad transfer reach the diff stage.

    Three gates, in increasing subtlety:

    1. the transfer completed rather than merely not raising;
    2. it produced at least one name;
    3. it is within ``min_ratio`` of the last successful transfer for this TLD.

    The third is the one that matters most. An empty transfer is obvious; a transfer that
    returns 40% of the zone looks entirely plausible and would generate 1.5M bogus
    ``REMOVED_FROM_ZONE`` events.
    """
    if not result.complete:
        raise ZoneError(f".{result.tld}: transfer did not complete")

    if result.name_count == 0:
        raise ZoneError(
            f".{result.tld}: transfer produced zero names. Refusing to treat this as "
            "every domain having been removed."
        )

    previous = session.get(ZoneSnapshotStat, result.tld)
    if previous is None:
        logger.info(
            ".%s: no previous transfer to compare against; accepting %d names as baseline",
            result.tld, result.name_count,
        )
        return

    ratio = result.name_count / previous.name_count if previous.name_count else 1.0
    if ratio < min_ratio:
        raise ZoneError(
            f".{result.tld}: transfer returned {result.name_count:,} names, only "
            f"{ratio:.1%} of the previous {previous.name_count:,}. This looks like a "
            f"partial transfer; refusing to generate "
            f"{previous.name_count - result.name_count:,} removal events."
        )
    logger.info(
        ".%s: %d names, %.1f%% of the previous transfer -- accepted",
        result.tld, result.name_count, ratio * 100,
    )


def record_snapshot_stat(session: Session, result: TransferResult) -> None:
    """Remember this transfer's size so the next one can be sanity-checked against it."""
    stat = session.get(ZoneSnapshotStat, result.tld)
    now = dt.datetime.now(dt.timezone.utc)
    if stat is None:
        session.add(
            ZoneSnapshotStat(
                tld=result.tld, name_count=result.name_count,
                transferred_at=now, duration_seconds=result.duration_seconds,
            )
        )
    else:
        stat.name_count = result.name_count
        stat.transferred_at = now
        stat.duration_seconds = result.duration_seconds


def hours_since_last_transfer(session: Session, tld: str) -> float | None:
    """Age of the last successful transfer, or ``None`` if there has never been one."""
    stat = session.get(ZoneSnapshotStat, tld)
    if stat is None:
        return None
    transferred = stat.transferred_at
    if transferred.tzinfo is None:
        transferred = transferred.replace(tzinfo=dt.timezone.utc)
    return (dt.datetime.now(dt.timezone.utc) - transferred).total_seconds() / 3600.0


def clear_staging(session: Session, run_id: int) -> None:
    session.execute(delete(ZoneStaging).where(ZoneStaging.run_id == run_id))


def staged_count(session: Session, run_id: int, tld: str | None = None) -> int:
    stmt = select(func.count()).select_from(ZoneStaging).where(ZoneStaging.run_id == run_id)
    if tld is not None:
        stmt = stmt.where(ZoneStaging.tld == tld)
    return int(session.execute(stmt).scalar_one())

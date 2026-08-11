"""SQLAlchemy models.

The spine is ``Domain -> DomainEvent -> RuleMatch -> Alert``: observation, then
interpretation, then notification, kept separate so a change to one does not require
redesigning the others.

``DomainEvent`` rows are immutable facts. ``Domain.currently_in_zone`` is a convenience
projection of the latest event, not the source of truth -- the event log is. That matters
operationally: the ``domains`` table can be rebuilt from a single zone transfer, but the
event history cannot be reconstructed from anything. It is the reason this project carries
Alembic migrations rather than just recreating the schema.

All timestamps are stored in UTC. ``TIMEZONE`` applies when rendering alerts, never here.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Base(DeclarativeBase):
    pass


class Domain(Base):
    __tablename__ = "domains"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    #: Always the normalised form -- lowercase, punycode. See ``names.normalise_name``.
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    tld: Mapped[str] = mapped_column(String(63), nullable=False, index=True)
    first_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    currently_in_zone: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    events: Mapped[list[DomainEvent]] = relationship(back_populates="domain")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Domain {self.name} in_zone={self.currently_in_zone}>"


class DomainEvent(Base):
    __tablename__ = "domain_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id"), nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    detected_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"), nullable=False, index=True)

    domain: Mapped[Domain] = relationship(back_populates="events")
    run: Mapped[Run] = relationship(back_populates="events")
    matches: Mapped[list[RuleMatch]] = relationship(back_populates="event")

    __table_args__ = (Index("ix_domain_events_domain_type", "domain_id", "event_type"),)


class RuleMatch(Base):
    __tablename__ = "rule_matches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    #: Always set. A match is always about a domain.
    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id"), nullable=False, index=True)

    #: Null for backfill matches. Evaluating a newly-added rule against the domains
    #: already in the zone is a match against *current state*, not against an observed
    #: change, and minting synthetic events for it would pollute the event log with
    #: things that never happened.
    domain_event_id: Mapped[int | None] = mapped_column(
        ForeignKey("domain_events.id"), nullable=True, index=True
    )

    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"), nullable=False, index=True)
    rule_name: Mapped[str] = mapped_column(String(255), nullable=False)
    rule_description: Mapped[str] = mapped_column(Text, nullable=False)
    rule_pattern: Mapped[str] = mapped_column(Text, nullable=False)
    matched_value: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    domain: Mapped[Domain] = relationship()
    event: Mapped[DomainEvent | None] = relationship(back_populates="matches")


class Run(Base):
    __tablename__ = "runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    started_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="RUNNING", index=True)

    zone_counts: Mapped[str] = mapped_column(Text, default="{}")   # JSON: {"ch": 2564228}
    #: When zone data was last actually transferred, as opposed to reused. Drives the
    #: once-per-24h guard.
    zone_transferred_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    added_count: Mapped[int] = mapped_column(Integer, default=0)
    removed_count: Mapped[int] = mapped_column(Integer, default=0)
    returned_count: Mapped[int] = mapped_column(Integer, default=0)
    matched_count: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    events: Mapped[list[DomainEvent]] = relationship(back_populates="run")
    alerts: Mapped[list[Alert]] = relationship(back_populates="run")

    STATUS_RUNNING = "RUNNING"
    STATUS_SUCCESS = "SUCCESS"
    STATUS_FAILED = "FAILED"
    STATUS_SKIPPED = "SKIPPED"


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    #: Scoped to the run, not the event: one aggregated message per run, never one email
    #: per match. A busy day on .ch is ~100 removals.
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"), nullable=False, index=True)
    channel: Mapped[str] = mapped_column(String(32), nullable=False)
    recipient: Mapped[str] = mapped_column(String(512), default="")
    match_count: Mapped[int] = mapped_column(Integer, default=0)
    sent_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="PENDING")
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    run: Mapped[Run] = relationship(back_populates="alerts")

    STATUS_SENT = "SENT"
    STATUS_FAILED = "FAILED"
    STATUS_PENDING = "PENDING"


class ZoneStaging(Base):
    """Scratch table holding one run's freshly transferred names.

    The diff is computed in SQL against this table rather than in Python. Holding two
    2.6M-name sets in memory costs ~600 MB at peak; this keeps the working set bounded by
    the insert batch size and works the same on SQLite and PostgreSQL.
    """

    __tablename__ = "zone_staging"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    tld: Mapped[str] = mapped_column(String(63), nullable=False, index=True)

    __table_args__ = (
        UniqueConstraint("run_id", "name", name="uq_zone_staging_run_name"),
        Index("ix_zone_staging_run_name", "run_id", "name"),
    )


class ZoneSnapshotStat(Base):
    """Per-TLD name counts of the last successful transfer.

    Kept so the next run can sanity-check the size of a fresh transfer against it. A
    partial transfer is more dangerous than an empty one, because it looks plausible.
    """

    __tablename__ = "zone_snapshot_stats"

    tld: Mapped[str] = mapped_column(String(63), primary_key=True)
    name_count: Mapped[int] = mapped_column(Integer, nullable=False)
    transferred_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    duration_seconds: Mapped[float] = mapped_column(Float, default=0.0)

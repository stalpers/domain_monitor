"""Engine and session management."""

from __future__ import annotations

import logging
from pathlib import Path

from sqlalchemy import Engine, create_engine, event, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from .models import Base

logger = logging.getLogger(__name__)


def create_db_engine(database_url: str, echo: bool = False) -> Engine:
    """Build an engine, creating the parent directory for a SQLite file if needed."""
    if database_url.startswith("sqlite:///"):
        path = Path(database_url.removeprefix("sqlite:///"))
        if path.parent and str(path.parent) not in ("", "."):
            path.parent.mkdir(parents=True, exist_ok=True)

    engine = create_engine(database_url, echo=echo, future=True)

    if engine.dialect.name == "sqlite":
        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_connection, _record):  # pragma: no cover - driver hook
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            # SQLite allows only one writer at a time; without this, a second
            # connection (e.g. the run's heartbeat write, or `domain-monitor status`)
            # fails immediately with "database is locked" instead of waiting briefly
            # for the long-running transfer transaction to free the write lock.
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.close()

    return engine


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, future=True, expire_on_commit=False)


def create_all(engine: Engine) -> None:
    """Create the schema directly.

    Alembic owns schema evolution in deployment; this exists for tests and for
    ``domain-monitor init`` on a fresh database.

    A genuinely empty database gets stamped at Alembic's head immediately after: it was
    just built straight from the current models, which is by definition what the latest
    migration produces, so a later ``alembic upgrade head`` must see nothing left to do
    rather than replay history against tables that already exist. Without this, *every*
    database ever created this way is invisible to Alembic (no ``alembic_version`` row at
    all) until the first real migration is run, at which point it tries to ``CREATE
    TABLE`` things that are already there and fails with ``DuplicateTable`` -- this is a
    real incident, not a hypothetical.

    Deliberately does **not** stamp a database that already had tables: an existing,
    unstamped database (any deployment from before this existed) may not match any single
    revision exactly, and guessing wrong here would silently skip a real migration later.
    That case needs a one-time manual ``alembic stamp <revision>`` -- see the README.
    """
    was_empty = not inspect(engine).get_table_names()
    Base.metadata.create_all(engine)
    if was_empty:
        _stamp_head(engine)


def _stamp_head(engine: Engine) -> None:
    """Write Alembic's version row directly, against the exact engine already in hand.

    Deliberately does **not** use ``alembic.command.stamp``: that runs
    ``migrations/env.py`` end to end, which re-derives its own database URL from the
    ``DATABASE_URL`` environment variable rather than using the one it's handed (see that
    module's docstring) -- so it can silently stamp a *different* database than the one
    ``engine`` actually points at, if the two ever disagree (a URL passed as a Python
    string rather than sourced from the environment, a test fixture, and so on). That
    already bit this exact feature during development.

    ``alembic_version`` is a fixed, tiny, documented table (one ``VARCHAR(32)`` primary
    key column) that Alembic itself creates and reads the same way regardless of dialect,
    so writing it directly is not a workaround -- it's what stamping actually is.
    """
    try:
        from alembic.config import Config
        from alembic.script import ScriptDirectory

        migrations_dir = Path(__file__).resolve().parent.parent / "migrations"
        if not migrations_dir.exists():
            return  # e.g. an install that doesn't ship migrations/; nothing to stamp against
        cfg = Config()
        cfg.set_main_option("script_location", str(migrations_dir))
        head = ScriptDirectory.from_config(cfg).get_current_head()
        if head is None:
            return
        with engine.begin() as conn:
            conn.execute(text(
                "CREATE TABLE IF NOT EXISTS alembic_version ("
                "version_num VARCHAR(32) NOT NULL, "
                "CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num))"
            ))
            conn.execute(text("DELETE FROM alembic_version"))
            conn.execute(
                text("INSERT INTO alembic_version (version_num) VALUES (:v)"), {"v": head}
            )
    except Exception:
        logger.warning(
            "Could not stamp the new database to the latest migration; run "
            "'alembic stamp head' manually before the next 'alembic upgrade head'",
            exc_info=True,
        )

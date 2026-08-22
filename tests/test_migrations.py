"""create_all() and Alembic must never disagree about a database's history.

Real incident: every database created via ``create_all()`` (every test, and
`domain-monitor init`/`run`/`status` in production) had no ``alembic_version`` row at
all. The first time anyone actually ran ``alembic upgrade head`` against a live database
-- exactly what the README instructs after adding a migration -- Alembic had no idea the
tables already existed and tried to ``CREATE TABLE domains`` again, failing with
``DuplicateTable``.
"""

from __future__ import annotations

from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import text

from domain_monitor.database import create_all, create_db_engine


def _current_head() -> str:
    migrations_dir = Path(__file__).resolve().parent.parent / "migrations"
    cfg = Config()
    cfg.set_main_option("script_location", str(migrations_dir))
    return ScriptDirectory.from_config(cfg).get_current_head()


class TestFreshDatabaseIsStamped:
    def test_a_new_database_is_stamped_at_head(self, tmp_path):
        engine = create_db_engine(f"sqlite:///{tmp_path}/db.sqlite")
        create_all(engine)

        with engine.connect() as conn:
            row = conn.execute(text("SELECT version_num FROM alembic_version")).fetchone()

        assert row is not None
        assert row[0] == _current_head()

    def test_stamping_means_alembic_upgrade_head_is_a_no_op(self, tmp_path):
        """The actual bug: without a stamp, `alembic upgrade head` tries to replay
        every migration from scratch against tables that already exist."""
        from alembic.runtime.migration import MigrationContext

        engine = create_db_engine(f"sqlite:///{tmp_path}/db.sqlite")
        create_all(engine)

        with engine.connect() as conn:
            context = MigrationContext.configure(conn)
            current = context.get_current_heads()

        assert current == (_current_head(),)


class TestExistingDatabaseIsNotTouched:
    def test_a_database_that_already_had_tables_is_not_stamped(self, tmp_path):
        """A pre-existing, unstamped database (any deployment from before this existed)
        must be left alone: guessing a revision for it could be wrong, silently skipping
        a real migration later. It needs a one-time manual `alembic stamp <revision>`."""
        engine = create_db_engine(f"sqlite:///{tmp_path}/db.sqlite")
        create_all(engine)  # first call: fresh, gets stamped

        with engine.connect() as conn:
            conn.execute(text("DROP TABLE alembic_version"))
            conn.commit()

        create_all(engine)  # second call: tables already exist -- must not re-stamp

        with engine.connect() as conn:
            exists = conn.execute(
                text(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name='alembic_version'"
                )
            ).fetchone()
        assert exists is None

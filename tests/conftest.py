import re

import pytest

from domain_monitor.config import (
    ADDED_TO_ZONE,
    REMOVED_FROM_ZONE,
    RETURNED_TO_ZONE,
    Config,
    DomainRule,
    SmtpConfig,
    ZoneSource,
)
from domain_monitor.database import create_all, create_db_engine, make_session_factory


def rule(name="Test rule", pattern=".", events=(ADDED_TO_ZONE,), enabled=True,
         description="a rule used in tests"):
    return DomainRule(
        name=name,
        description=description,
        regex=re.compile(pattern),
        event_types=frozenset(events),
        enabled=enabled,
    )


@pytest.fixture()
def engine(tmp_path):
    eng = create_db_engine(f"sqlite:///{tmp_path}/test.db")
    create_all(eng)
    return eng


@pytest.fixture()
def session_factory(engine):
    return make_session_factory(engine)


@pytest.fixture()
def session(session_factory):
    with session_factory() as s:
        yield s


@pytest.fixture()
def config(tmp_path):
    return Config(
        database_url=f"sqlite:///{tmp_path}/test.db",
        tlds=["ch"],
        timezone="Europe/Zurich",
        zones={
            "ch": ZoneSource(tld="ch"),
            "li": ZoneSource(tld="li"),
        },
        rules=[rule(events=(ADDED_TO_ZONE, REMOVED_FROM_ZONE, RETURNED_TO_ZONE))],
        smtp=SmtpConfig(),
        console_alerts=False,
        log_level="WARNING",
        lock_path=tmp_path / "lock",
        min_transfer_interval_hours=24,
        min_zone_ratio=0.5,
    )

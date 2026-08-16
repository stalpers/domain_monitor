"""The tests this system exists to pass.

A failed, empty or partial zone transfer must never be read as "every domain was
removed". With .ch at ~2.6M names, getting this wrong means millions of bogus
REMOVED_FROM_ZONE events, a corrupted event log, and an email storm -- and it would look
like a real incident rather than a bug.
"""

import pytest
from sqlalchemy import func, select

from domain_monitor.models import Domain, DomainEvent, Run, ZoneSnapshotStat
from domain_monitor.service import run_once
from domain_monitor.zones import TransferResult, ZoneError, validate_transfer

BASELINE = [f"d{i:05d}.ch" for i in range(1000)]


def counts(session):
    return {
        "domains": session.execute(select(func.count()).select_from(Domain)).scalar_one(),
        "in_zone": session.execute(
            select(func.count()).select_from(Domain).where(Domain.currently_in_zone.is_(True))
        ).scalar_one(),
        "events": session.execute(select(func.count()).select_from(DomainEvent)).scalar_one(),
    }


@pytest.fixture()
def seeded(config, session_factory):
    """A database with a 1000-domain baseline already established."""
    report = run_once(config, session_factory, zone_names={"ch": BASELINE})
    assert report.status == Run.STATUS_SUCCESS
    assert report.counts.baseline is True
    return config, session_factory


class TestValidateTransfer:
    def test_incomplete_transfer_rejected(self, session):
        result = TransferResult("ch", 1000, 1.0, complete=False)
        with pytest.raises(ZoneError, match="did not complete"):
            validate_transfer(session, result, min_ratio=0.5)

    def test_empty_transfer_rejected(self, session):
        result = TransferResult("ch", 0, 1.0, complete=True)
        with pytest.raises(ZoneError, match="zero names"):
            validate_transfer(session, result, min_ratio=0.5)

    def test_first_transfer_accepted_without_comparison(self, session):
        validate_transfer(session, TransferResult("ch", 1000, 1.0, True), min_ratio=0.5)

    def test_plausible_but_partial_transfer_rejected(self, session):
        """The dangerous one: 40% of the zone looks like a real answer."""
        session.add(ZoneSnapshotStat(tld="ch", name_count=2_564_228))
        session.commit()
        result = TransferResult("ch", 1_000_000, 60.0, complete=True)
        with pytest.raises(ZoneError, match="partial transfer"):
            validate_transfer(session, result, min_ratio=0.5)

    def test_normal_fluctuation_accepted(self, session):
        session.add(ZoneSnapshotStat(tld="ch", name_count=2_564_228))
        session.commit()
        validate_transfer(session, TransferResult("ch", 2_570_000, 60.0, True), min_ratio=0.5)

    def test_growth_accepted(self, session):
        session.add(ZoneSnapshotStat(tld="ch", name_count=1000))
        session.commit()
        validate_transfer(session, TransferResult("ch", 5000, 1.0, True), min_ratio=0.5)


class TestNoMassRemoval:
    """End-to-end: each failure mode must leave state untouched and the run FAILED."""

    def test_transfer_exception_changes_nothing(self, seeded, session_factory, monkeypatch):
        config, factory = seeded
        with factory() as s:
            before = counts(s)

        def boom(*a, **kw):
            raise ZoneError("simulated AXFR failure")

        monkeypatch.setattr("domain_monitor.service.stage_zone", boom)
        report = run_once(config, factory, zone_names={"ch": BASELINE})

        assert report.status == Run.STATUS_FAILED
        with factory() as s:
            assert counts(s) == before

    def test_empty_zone_changes_nothing(self, seeded, session_factory):
        config, factory = seeded
        with factory() as s:
            before = counts(s)

        report = run_once(config, factory, zone_names={"ch": []})

        assert report.status == Run.STATUS_FAILED
        assert "zero names" in report.error
        with factory() as s:
            after = counts(s)
        assert after == before
        assert after["in_zone"] == 1000        # not a single removal

    def test_partial_zone_changes_nothing(self, seeded, session_factory):
        """400 of 1000 names: a plausible-looking transfer that must still be refused."""
        config, factory = seeded
        with factory() as s:
            before = counts(s)

        report = run_once(config, factory, zone_names={"ch": BASELINE[:400]})

        assert report.status == Run.STATUS_FAILED
        assert "partial transfer" in report.error
        with factory() as s:
            after = counts(s)
        assert after == before
        assert after["events"] == 0            # zero REMOVED_FROM_ZONE events

    def test_failed_run_is_recorded_with_its_reason(self, seeded, session_factory):
        config, factory = seeded
        run_once(config, factory, zone_names={"ch": []})
        with factory() as s:
            run = s.execute(select(Run).order_by(Run.id.desc()).limit(1)).scalar_one()
        assert run.status == Run.STATUS_FAILED
        assert run.error_message
        assert run.finished_at is not None

    def test_a_genuine_removal_still_works(self, seeded, session_factory):
        """The guard must not be so blunt that real removals stop being detected."""
        config, factory = seeded
        report = run_once(config, factory, zone_names={"ch": BASELINE[:-5]})

        assert report.status == Run.STATUS_SUCCESS
        assert report.counts.removed == 5
        with factory() as s:
            assert counts(s)["in_zone"] == 995


class TestBaseline:
    def test_first_run_emits_no_events(self, config, session_factory):
        report = run_once(config, session_factory, zone_names={"ch": BASELINE})
        assert report.counts.baseline is True
        assert report.counts.added == 1000
        with session_factory() as s:
            assert counts(s)["events"] == 0

    def test_first_run_produces_no_matches(self, config, session_factory):
        """A .ch baseline is 2.6M names; rule-matching it would be an instant mail-flood."""
        report = run_once(config, session_factory, zone_names={"ch": BASELINE})
        assert report.matches == []

    def test_second_run_detects_changes_normally(self, config, session_factory):
        run_once(config, session_factory, zone_names={"ch": BASELINE})
        report = run_once(
            config, session_factory, zone_names={"ch": BASELINE[:-2] + ["brandnew.ch"]}
        )
        assert report.counts.baseline is False
        assert report.counts.added == 1
        assert report.counts.removed == 2


class TestTldScoping:
    def test_running_one_tld_does_not_remove_the_other(self, config, session_factory):
        """--tld ch must not read 'no .li names staged' as 'every .li domain vanished'."""
        config.tlds = ["ch", "li"]
        run_once(
            config, session_factory,
            zone_names={"ch": ["a.ch", "b.ch"], "li": ["x.li", "y.li"]},
        )
        report = run_once(
            config, session_factory, tlds=["ch"], zone_names={"ch": ["a.ch", "b.ch"]}
        )
        assert report.counts.removed == 0
        with session_factory() as s:
            still = s.execute(
                select(func.count()).select_from(Domain)
                .where(Domain.tld == "li", Domain.currently_in_zone.is_(True))
            ).scalar_one()
        assert still == 2

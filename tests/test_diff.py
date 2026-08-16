from sqlalchemy import select

from domain_monitor.config import ADDED_TO_ZONE, REMOVED_FROM_ZONE, RETURNED_TO_ZONE
from domain_monitor.models import Domain, DomainEvent, Run
from domain_monitor.service import run_once


def events_of(session, event_type=None):
    stmt = select(DomainEvent.event_type, Domain.name).join(Domain, Domain.id == DomainEvent.domain_id)
    if event_type:
        stmt = stmt.where(DomainEvent.event_type == event_type)
    return {(name, etype) for etype, name in session.execute(stmt)}


class TestTransitions:
    def test_added(self, config, session_factory):
        run_once(config, session_factory, zone_names={"ch": ["a.ch"]})
        report = run_once(config, session_factory, zone_names={"ch": ["a.ch", "b.ch"]})
        assert report.counts.added == 1
        with session_factory() as s:
            assert ("b.ch", ADDED_TO_ZONE) in events_of(s)

    def test_removed(self, config, session_factory):
        run_once(config, session_factory, zone_names={"ch": ["a.ch", "b.ch"]})
        report = run_once(config, session_factory, zone_names={"ch": ["a.ch"]})
        assert report.counts.removed == 1
        with session_factory() as s:
            assert ("b.ch", REMOVED_FROM_ZONE) in events_of(s)
            domain = s.execute(select(Domain).where(Domain.name == "b.ch")).scalar_one()
            assert domain.currently_in_zone is False

    def test_returned(self, config, session_factory):
        run_once(config, session_factory, zone_names={"ch": ["a.ch", "b.ch"]})
        run_once(config, session_factory, zone_names={"ch": ["a.ch"]})
        report = run_once(config, session_factory, zone_names={"ch": ["a.ch", "b.ch"]})
        assert report.counts.returned == 1
        assert report.counts.added == 0        # not a new domain; it is a returning one
        with session_factory() as s:
            assert ("b.ch", RETURNED_TO_ZONE) in events_of(s)

    def test_unchanged_produces_nothing(self, config, session_factory):
        run_once(config, session_factory, zone_names={"ch": ["a.ch", "b.ch"]})
        report = run_once(config, session_factory, zone_names={"ch": ["a.ch", "b.ch"]})
        assert report.counts.total == 0
        with session_factory() as s:
            assert events_of(s) == set()

    def test_readding_a_never_seen_name_is_added_not_returned(self, config, session_factory):
        run_once(config, session_factory, zone_names={"ch": ["a.ch"]})
        report = run_once(config, session_factory, zone_names={"ch": ["a.ch", "z.ch"]})
        assert (report.counts.added, report.counts.returned) == (1, 0)

    def test_repeated_runs_do_not_duplicate_domains(self, config, session_factory):
        for _ in range(3):
            run_once(config, session_factory, zone_names={"ch": ["a.ch", "b.ch"]})
        with session_factory() as s:
            assert s.execute(select(Domain)).scalars().all().__len__() == 2

    def test_last_seen_refreshed_for_still_present_names(self, config, session_factory):
        run_once(config, session_factory, zone_names={"ch": ["a.ch"]})
        with session_factory() as s:
            first = s.execute(select(Domain.last_seen_at)).scalar_one()
        run_once(config, session_factory, zone_names={"ch": ["a.ch"]})
        with session_factory() as s:
            second = s.execute(select(Domain.last_seen_at)).scalar_one()
        assert second >= first


class TestEventLog:
    def test_events_are_appended_never_replaced(self, config, session_factory):
        run_once(config, session_factory, zone_names={"ch": ["a.ch", "b.ch"]})
        run_once(config, session_factory, zone_names={"ch": ["a.ch"]})
        run_once(config, session_factory, zone_names={"ch": ["a.ch", "b.ch"]})
        with session_factory() as s:
            history = s.execute(
                select(DomainEvent.event_type)
                .join(Domain, Domain.id == DomainEvent.domain_id)
                .where(Domain.name == "b.ch")
                .order_by(DomainEvent.id)
            ).scalars().all()
        assert history == [REMOVED_FROM_ZONE, RETURNED_TO_ZONE]

    def test_events_carry_their_run_id(self, config, session_factory):
        run_once(config, session_factory, zone_names={"ch": ["a.ch"]})
        report = run_once(config, session_factory, zone_names={"ch": ["a.ch", "b.ch"]})
        with session_factory() as s:
            run_ids = set(s.execute(select(DomainEvent.run_id)).scalars())
        assert run_ids == {report.run_id}

    def test_run_counters_match_the_events(self, config, session_factory):
        run_once(config, session_factory, zone_names={"ch": ["a.ch", "b.ch", "c.ch"]})
        report = run_once(config, session_factory, zone_names={"ch": ["a.ch", "d.ch"]})
        with session_factory() as s:
            run = s.get(Run, report.run_id)
        assert (run.added_count, run.removed_count) == (1, 2)


class TestNormalisationInDiff:
    def test_unicode_and_punycode_are_the_same_domain(self, config, session_factory):
        """Otherwise every umlaut domain flaps add/remove on every single run."""
        run_once(config, session_factory, zone_names={"ch": ["zürich.ch"]})
        report = run_once(config, session_factory, zone_names={"ch": ["xn--zrich-kva.ch"]})
        assert report.counts.total == 0
        with session_factory() as s:
            names = set(s.execute(select(Domain.name)).scalars())
        assert names == {"xn--zrich-kva.ch"}

    def test_case_and_trailing_dot_are_normalised(self, config, session_factory):
        run_once(config, session_factory, zone_names={"ch": ["Example.CH."]})
        report = run_once(config, session_factory, zone_names={"ch": ["example.ch"]})
        assert report.counts.total == 0

    def test_www_is_a_real_domain_not_a_prefix(self, config, session_factory):
        """www.ch is registrable; stripping the prefix would corrupt it into 'ch'."""
        run_once(config, session_factory, zone_names={"ch": ["www.ch", "a.ch"]})
        with session_factory() as s:
            names = set(s.execute(select(Domain.name)).scalars())
        assert names == {"www.ch", "a.ch"}

    def test_duplicates_within_one_transfer_are_collapsed(self, config, session_factory):
        run_once(config, session_factory, zone_names={"ch": ["a.ch", "A.CH", "a.ch."]})
        with session_factory() as s:
            assert len(s.execute(select(Domain)).scalars().all()) == 1

from domain_monitor.ngram import (
    NgramModel,
    build_from_labels,
    build_from_zone,
    load_model,
    save_model,
)


class TestNgramModel:
    def test_untrained_model_reports_as_such(self):
        assert NgramModel(order=3, tld="ch").trained is False

    def test_trained_after_train_call(self):
        model = NgramModel(order=3, tld="ch")
        model.train(["example", "coop"])
        assert model.trained is True
        assert model.sample_count == 2

    def test_untrained_likelihood_is_neutral(self):
        assert NgramModel(order=3, tld="ch").likelihood("anything") == 0.5

    def test_likelihood_bounded_zero_to_one(self):
        model = build_from_labels(["example", "coop", "migros", "sbb"] * 10, tld="ch")
        for label in ["example", "xk4q9zv1p", "", "a"]:
            assert 0.0 <= model.likelihood(label) <= 1.0

    def test_near_zero_std_does_not_overflow(self):
        """Regression test: a low-diversity training corpus (few distinct words, each
        repeated) can collapse std_log_prob to a near-zero float that is not exactly
        0.0, so the `or 1.0` guard in finalise() does not catch it. Scoring a
        wildly-off-distribution label against that model used to raise
        OverflowError from math.exp -- which would have crashed a real run the first
        time it saw a name unlike anything in a small/sparse zone (e.g. an early .li
        deployment)."""
        model = build_from_labels(["example", "coop", "migros", "sbb"] * 10, tld="ch")
        assert model.std_log_prob < 1e-6          # confirms the degenerate precondition
        assert 0.0 <= model.likelihood("xk4q9zv1p8m3q7wtnb") <= 1.0

    def test_json_round_trip_preserves_scoring(self):
        model = build_from_labels(["example", "coop", "migros"] * 10, tld="ch")
        restored = NgramModel.from_json(model.to_json())
        assert restored.likelihood("example") == model.likelihood("example")
        assert restored.sample_count == model.sample_count
        assert restored.tld == "ch"

    def test_repeated_train_calls_accumulate(self):
        model = NgramModel(order=3, tld="ch")
        model.train(["example"])
        model.train(["coop"])
        assert model.sample_count == 2
        assert model.counts.get("exa", 0) == 1


class TestBuildFromLabels:
    def test_empty_input_stays_untrained(self):
        model = build_from_labels([], tld="ch")
        assert model.trained is False

    def test_order_is_respected(self):
        model = build_from_labels(["example"], order=2, tld="ch")
        assert model.order == 2
        assert all(len(k) == 2 for k in model.counts)


class TestPersistence:
    def test_save_and_load_round_trip(self, session):
        model = build_from_labels(["example", "coop", "migros"] * 5, tld="ch")
        save_model(session, model)
        session.commit()

        loaded = load_model(session, "ch")
        assert loaded is not None
        assert loaded.sample_count == model.sample_count
        assert loaded.likelihood("example") == model.likelihood("example")

    def test_missing_model_returns_none(self, session):
        assert load_model(session, "li") is None

    def test_save_twice_overwrites_not_duplicates(self, session):
        from sqlalchemy import func, select

        from domain_monitor.models import NgramModelRecord

        model = build_from_labels(["example"] * 5, tld="ch")
        save_model(session, model)
        session.commit()
        save_model(session, model)
        session.commit()

        count = session.execute(
            select(func.count()).select_from(NgramModelRecord)
        ).scalar_one()
        assert count == 1

    def test_models_are_independent_per_tld(self, session):
        ch_model = build_from_labels(["example"] * 5, tld="ch")
        li_model = build_from_labels(["andere"] * 5, tld="li")
        save_model(session, ch_model)
        save_model(session, li_model)
        session.commit()

        assert load_model(session, "ch").tld == "ch"
        assert load_model(session, "li").tld == "li"


class TestBuildFromZone:
    def test_trains_only_on_in_zone_domains_of_the_given_tld(self, session):
        from domain_monitor.models import Domain, utcnow

        now = utcnow()
        session.add_all([
            Domain(name="example.ch", tld="ch", currently_in_zone=True,
                   first_seen_at=now, last_seen_at=now),
            Domain(name="gone.ch", tld="ch", currently_in_zone=False,
                   first_seen_at=now, last_seen_at=now),
            Domain(name="andere.li", tld="li", currently_in_zone=True,
                   first_seen_at=now, last_seen_at=now),
        ])
        session.commit()

        model = build_from_zone(session, "ch")
        assert model.sample_count == 1     # "gone.ch" and the .li domain are excluded

    def test_empty_zone_stays_untrained(self, session):
        model = build_from_zone(session, "ch")
        assert model.trained is False

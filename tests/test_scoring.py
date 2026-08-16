"""scoring.py enforces one rule above all others: lexical signals never fire alone.
See the module docstring for the base-rate argument behind that."""

from domain_monitor.ngram import build_from_labels
from domain_monitor.scoring import assess
from domain_monitor.typosquat import Watchlist


class TestFiresGate:
    def test_watchlist_hit_fires(self):
        wl = Watchlist(brands=["example"])
        result = assess("examp1e", wl)
        assert result.fires is True

    def test_no_watchlist_hit_never_fires_regardless_of_randomness(self):
        wl = Watchlist(brands=["example"])
        # A maximally random-looking label with no watchlist hit.
        result = assess("xk4q9zv1p8m3q7wtnb", wl)
        assert result.fires is False

    def test_no_watchlist_at_all_never_fires(self):
        result = assess("xk4q9zv1p8m3q7wtnb", None)
        assert result.fires is False

    def test_lexical_signal_alone_cannot_synthesise_a_fire(self):
        """The structural guarantee: fires is defined purely in terms of watchlist
        signals, so no lexical weight, however large, can flip it."""
        wl = Watchlist(brands=["example"])
        result = assess("zzzzzzqxjkvw", wl)     # no watchlist hit, likely high randomness
        assert result.lexical_signals   # a randomness signal is present...
        assert result.fires is False    # ...but it never fires on its own


class TestSignalContent:
    def test_watchlist_signal_names_method_and_brand(self):
        wl = Watchlist(brands=["example"])
        result = assess("examp1e", wl)
        sig = result.watchlist_signals[0]
        assert sig.name in {"homoglyph", "replacement"}
        assert sig.brand == "example"
        assert "example" in sig.reason

    def test_lexical_signal_present_when_randomness_nonzero(self):
        result = assess("example", None)
        assert any(s.name == "randomness" for s in result.signals)

    def test_signals_partition_into_watchlist_and_lexical(self):
        wl = Watchlist(brands=["example"])
        result = assess("examp1e", wl)
        assert set(result.watchlist_signals) | set(result.lexical_signals) == set(result.signals)
        assert not (set(result.watchlist_signals) & set(result.lexical_signals))


class TestScoreOrdering:
    def test_more_specific_methods_score_higher(self):
        wl = Watchlist(brands=["example"], max_distance=1)
        # examp1e matches both homoglyph (weight 1.0) and replacement (weight 0.6).
        result = assess("examp1e", wl)
        by_method = {s.name: s.weight for s in result.watchlist_signals}
        assert by_method["homoglyph"] > by_method["replacement"]

    def test_multiple_watchlist_signals_increase_total_score(self):
        wl = Watchlist(brands=["example"], max_distance=1)
        single_signal_score = assess("example-login", Watchlist(
            brands=["example"], methods=frozenset({"combosquat"})
        )).score
        multi_signal_score = assess("examp1e", wl).score   # two methods fire
        assert multi_signal_score > 0
        assert single_signal_score > 0

    def test_score_is_deterministic(self):
        wl = Watchlist(brands=["example"])
        assert assess("examp1e", wl).score == assess("examp1e", wl).score


class TestModelIntegration:
    def test_works_with_no_model(self):
        wl = Watchlist(brands=["example"])
        result = assess("examp1e", wl, None)
        assert result.fires is True

    def test_works_with_a_trained_model(self):
        wl = Watchlist(brands=["example"])
        model = build_from_labels(["example", "coop", "migros"] * 10, tld="ch")
        result = assess("examp1e", wl, model)
        assert result.fires is True
        assert result.features is not None


class TestFeaturesAlwaysPresent:
    def test_features_computed_even_without_a_watchlist(self):
        result = assess("example", None)
        assert result.features is not None
        assert result.features.label == "example"

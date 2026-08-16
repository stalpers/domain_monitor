"""Typosquat detection.

``TestFalsePositiveCorpus`` is the most important class in this file. The project's
design is built on a base-rate argument: a lexical classifier that is 96% accurate on a
balanced benchmark degrades to roughly 20% precision against a real zone's ~1% malicious
rate. Watchlist detection exists because it sidesteps that by asking a specific question
with a small false-positive surface -- but "small" has to be demonstrated, not assumed,
which is what this corpus is for.
"""

import pytest

from domain_monitor.typosquat import (
    Watchlist,
    bitsquat_variants,
    bounded_edit_distance,
    classify_edit,
)


def methods_for(watchlist: Watchlist, label: str) -> set[str]:
    return {m.method for m in watchlist.check(label)}


class TestBoundedEditDistance:
    def test_identical_strings(self):
        assert bounded_edit_distance("example", "example", 2) == 0

    def test_single_substitution(self):
        assert bounded_edit_distance("exbmple", "example", 2) == 1

    def test_single_insertion(self):
        assert bounded_edit_distance("examplle", "example", 2) == 1

    def test_single_omission(self):
        assert bounded_edit_distance("exmple", "example", 2) == 1

    def test_adjacent_transposition(self):
        assert bounded_edit_distance("exapmle", "example", 2) == 1

    def test_exceeding_bound_returns_none(self):
        assert bounded_edit_distance("xyz", "example", 1) is None

    def test_length_prefilter_short_circuits(self):
        # length difference alone exceeds max_distance -- must not even compute the DP.
        assert bounded_edit_distance("a", "example", 1) is None

    def test_distance_at_exactly_the_bound(self):
        assert bounded_edit_distance("exemple", "example", 1) == 1
        assert bounded_edit_distance("exemple", "example", 0) is None


class TestClassifyEdit:
    def test_omission(self):
        assert classify_edit("exmple", "example") == "omission"

    def test_insertion(self):
        assert classify_edit("examplle", "example") == "insertion"

    def test_transposition(self):
        assert classify_edit("exapmle", "example") == "transposition"

    def test_replacement(self):
        assert classify_edit("exbmple", "example") == "replacement"


class TestBitsquatVariants:
    def test_produces_only_legal_domain_characters(self):
        variants = bitsquat_variants("example")
        assert all(c.isalnum() or c == "-" for v in variants for c in v)

    def test_excludes_the_original(self):
        assert "example" not in bitsquat_variants("example")

    def test_nonempty_for_a_real_word(self):
        assert len(bitsquat_variants("example")) > 0

    def test_symmetry_membership(self):
        # If X is a bit-flip of "example", "example" should differ from X by one flipped
        # bit somewhere -- exercised indirectly via the Watchlist index, but check the
        # raw set is stable/deterministic here.
        a = bitsquat_variants("coop")
        b = bitsquat_variants("coop")
        assert a == b


class TestHomoglyph:
    def test_digit_leetspeak(self):
        wl = Watchlist(brands=["example"])
        assert "homoglyph" in methods_for(wl, "examp1e")

    def test_cyrillic_homograph(self):
        wl = Watchlist(brands=["example"])
        matches = wl.check("ехаmple")
        assert any(m.method == "homoglyph" and m.is_homograph for m in matches)

    def test_own_domain_does_not_match_itself(self):
        wl = Watchlist(brands=["example"])
        assert wl.check("example") == []

    def test_rn_folds_to_m(self):
        wl = Watchlist(brands=["amazon"])
        assert "homoglyph" in methods_for(wl, "arnazon")


class TestBitsquatMethod:
    def test_watchlist_flags_a_bitflip(self):
        wl = Watchlist(brands=["example"])
        variant = next(iter(bitsquat_variants("example")))
        assert "bitsquat" in methods_for(wl, variant)


class TestTypoAndKeyboard:
    def test_replacement_within_bound(self):
        wl = Watchlist(brands=["postfinance"], max_distance=1)
        matches = wl.check("postfinanse")
        assert any(m.method == "replacement" for m in matches)

    def test_beyond_bound_is_not_a_typo_match(self):
        wl = Watchlist(brands=["postfinance"], max_distance=1)
        matches = [m for m in wl.check("totallydifferentword") if m.method != "combosquat"]
        assert matches == []

    def test_keyboard_adjacent_qwertz(self):
        # 'a' and 's' are adjacent on row 2 of QWERTZ (and QWERTY).
        wl = Watchlist(brands=["example"], keyboard_layouts=("qwertz",))
        assert "keyboard" in methods_for(wl, "exsmple")

    def test_non_adjacent_substitution_is_not_keyboard(self):
        # 'e' and 'x' are not adjacent on any of the three layouts checked.
        wl = Watchlist(brands=["axample"], keyboard_layouts=("qwertz", "qwerty", "azerty"))
        matches = [m for m in wl.check("example") if m.method == "keyboard"]
        assert matches == []

    def test_short_brand_skips_typo_and_keyboard(self):
        """The empirically-found precision fix: 'usb'/'ups'/'pubs' are all edit-distance
        1 from the 3-letter brand 'ubs'. Below min_length_for_distance, only homoglyph,
        bitsquat and keyword-gated combosquat may fire."""
        wl = Watchlist(brands=["ubs"], min_length_for_distance=5)
        for word in ["usb", "ups", "pubs", "tubs"]:
            assert methods_for(wl, word) == set(), f"{word!r} should not match short brand 'ubs'"

    def test_short_brand_still_catches_homoglyph(self):
        wl = Watchlist(brands=["coop"], min_length_for_distance=5)
        assert "homoglyph" in methods_for(wl, "c00p")


class TestCombosquat:
    def test_hyphen_separated(self):
        wl = Watchlist(brands=["postfinance"])
        assert "combosquat" in methods_for(wl, "postfinance-login")

    def test_keyword_touching_without_hyphen(self):
        wl = Watchlist(brands=["postfinance"])
        assert "combosquat" in methods_for(wl, "postfinancelogin")

    def test_bare_substring_without_separator_or_keyword_does_not_match(self):
        wl = Watchlist(brands=["postfinance"])
        assert methods_for(wl, "xpostfinancex") == set()

    def test_short_brand_requires_keyword_not_bare_hyphen(self):
        wl = Watchlist(brands=["coop"], min_length_for_distance=5)
        assert methods_for(wl, "chicken-coop") == set()
        assert "combosquat" in methods_for(wl, "coop-login")

    def test_short_brand_keyword_without_hyphen_still_matches(self):
        wl = Watchlist(brands=["sbb"], min_length_for_distance=5)
        assert "combosquat" in methods_for(wl, "sbbverify")


class TestHyphenation:
    def test_whole_label_dehyphenates_to_brand(self):
        wl = Watchlist(brands=["postfinance"])
        assert "hyphenation" in methods_for(wl, "post-finance")

    def test_partial_hyphenation_is_not_this_method(self):
        # dehyphenating "post-finance-login" gives "postfinancelogin", not the brand
        # itself, so this specific (strict, whole-label) method should not fire, even
        # though combosquat legitimately will.
        wl = Watchlist(brands=["postfinance"])
        assert "hyphenation" not in methods_for(wl, "post-finance-login")


class TestTldVariant:
    def test_fires_when_registered_under_an_unexpected_tld(self):
        wl = Watchlist(
            brands=["postfinance"], methods=frozenset({"tld_variant"}),
            home_tlds={"postfinance": "ch"},
        )
        matches = wl.check("postfinance", tld="li")
        assert any(m.method == "tld_variant" for m in matches)

    def test_silent_under_the_home_tld(self):
        wl = Watchlist(
            brands=["postfinance"], methods=frozenset({"tld_variant"}),
            home_tlds={"postfinance": "ch"},
        )
        assert wl.check("postfinance", tld="ch") == []

    def test_silent_without_a_home_tld_mapping(self):
        wl = Watchlist(brands=["postfinance"], methods=frozenset({"tld_variant"}))
        assert wl.check("postfinance", tld="li") == []


class TestMethodsFilter:
    def test_disabling_a_method_suppresses_it(self):
        wl = Watchlist(brands=["example"], methods=frozenset({"combosquat"}))
        assert methods_for(wl, "examp1e") == set()          # homoglyph disabled
        assert "combosquat" in methods_for(wl, "example-login")

    def test_multiple_methods_can_fire_on_the_same_name(self):
        wl = Watchlist(brands=["example"], max_distance=1)
        matches = wl.check("examp1e")     # digit substitution: both homoglyph and edit-distance
        assert {"homoglyph", "replacement"} <= {m.method for m in matches}


class TestFalsePositiveCorpus:
    """Every watchlisted brand checked against a corpus of plausible, unrelated Swiss
    domain labels. The bar is zero matches -- this is the test that stands in for the
    project's precision requirement."""

    BRANDS = ["coop", "sbb", "ubs", "migros", "postfinance", "raiffeisen", "swisscom"]

    BENIGN = [
        "cooperative", "recoop", "coopers", "schoolcorp", "coopmarkt", "coophandel",
        "chicken-coop", "ubszurich", "clubs", "ups", "usb", "tubs", "pubs",
        "raiffeisenbank", "migroskultur", "sbbcargo", "garage-sbb-service",
        "muellcontainer", "restaurant-alpin", "gemeinde-info", "zuerich-tourismus",
        "swisscomedy", "swisscommunity", "postfach", "postauto", "postbote",
        "apotheke-zentral", "spital-luzern", "verein-musik", "treuhand-basel",
        "anwaltskanzlei", "architekturbuero", "hotel-alpenblick", "restaurant-krone",
        "gemeindeverwaltung", "kantonsschule", "polizei-notfall", "feuerwehr-verein",
        "wanderweg-schweiz", "bergbahn-info", "skiclub-alpin", "fussballverein",
        "musikschule-zuerich", "kinderkrippe", "pflegeheim-sonnenhof",
        "landwirtschaftsbetrieb", "weingut-wallis", "kaesehandlung",
        "backerei-dorf", "metzgerei-huber", "coiffeur-salon", "zahnarztpraxis",
    ]

    @pytest.fixture()
    def watchlist(self):
        return Watchlist(brands=self.BRANDS, max_distance=1)

    def test_zero_false_positives(self, watchlist):
        false_positives = []
        for word in self.BENIGN:
            matches = watchlist.check(word)
            if matches:
                false_positives.append((word, [(m.method, m.brand) for m in matches]))
        assert false_positives == [], f"unexpected matches: {false_positives}"

    def test_brands_do_not_match_themselves(self, watchlist):
        for brand in self.BRANDS:
            assert watchlist.check(brand) == []


class TestFalsePositiveCorpusAcceptedEdgeCase:
    """One documented, accepted exception to the zero-FP bar above: a bare hyphen
    touching a *long, distinctive* brand (>= min_length_for_distance) is kept as a
    signal even without a keyword, because a third party hyphen-attaching a
    multi-syllable brand name to their own domain is itself a pattern worth a human's
    review -- unlike the short-brand case, where "chicken-coop" makes the same check
    useless. This test exists so the trade-off is visible and intentional, not a
    silent gap in the corpus above."""

    def test_hyphen_adjacent_to_a_long_brand_is_an_accepted_match(self):
        wl = Watchlist(brands=["migros"], min_length_for_distance=5)
        matches = wl.check("kundenservice-migros")
        assert any(m.method == "combosquat" for m in matches)

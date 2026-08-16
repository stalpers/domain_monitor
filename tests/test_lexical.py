from domain_monitor.lexical import extract, max_run, randomness_score, shannon_entropy
from domain_monitor.ngram import build_from_labels


class TestShannonEntropy:
    def test_single_repeated_char_is_zero(self):
        assert shannon_entropy("aaaa") == 0.0

    def test_empty_is_zero(self):
        assert shannon_entropy("") == 0.0

    def test_more_distinct_chars_means_more_entropy(self):
        assert shannon_entropy("abcdefgh") > shannon_entropy("aabbccdd")

    def test_random_looking_string_has_high_entropy(self):
        assert shannon_entropy("xk4q9zv1p") > shannon_entropy("banana")


class TestMaxRun:
    def test_no_run(self):
        assert max_run("abcabc", frozenset("xyz")) == 0

    def test_full_run(self):
        assert max_run("bcdfg", frozenset("bcdfghjklmnpqrstvwxyz")) == 5

    def test_run_broken_by_other_chars(self):
        # "bcd" (3) then "a" breaks it, then "fgh" (3) -- longest run is 3, not the
        # combined 6, since "a" is not in the given charset.
        assert max_run("bcdaefgh", frozenset("bcdfghjklmnpqrstvwxyz")) == 3


class TestExtract:
    def test_basic_counts(self):
        f = extract("coop")
        assert f.length == 4
        assert f.digit_ratio == 0.0
        assert f.vowel_ratio == 0.5   # o, o
        assert f.hyphen_count == 0

    def test_empty_label(self):
        f = extract("")
        assert (f.length, f.entropy, f.digit_ratio) == (0, 0.0, 0.0)

    def test_hyphen_count(self):
        assert extract("post-finance-login").hyphen_count == 2

    def test_is_idn_for_punycode_prefix(self):
        assert extract("xn--zrich-kva").is_idn is True

    def test_is_idn_for_unicode(self):
        assert extract("zürich").is_idn is True

    def test_is_idn_false_for_plain_ascii(self):
        assert extract("example").is_idn is False

    def test_lowercases_input(self):
        assert extract("EXAMPLE").label == "example"

    def test_max_consonant_run_field(self):
        assert extract("xk4q9zvp").max_consonant_run >= 3

    def test_unique_char_ratio_low_for_repetition(self):
        assert extract("aaaa1111").unique_char_ratio == 0.25

    def test_as_dict_is_flat_and_json_serialisable(self):
        import json
        row = extract("example").as_dict()
        json.dumps(row)   # must not raise
        assert row["label"] == "example"
        assert isinstance(row["length"], int)


class TestRandomnessScore:
    def test_bounded_zero_to_one(self):
        for label in ["a", "example", "xk4q9zv1p8m3", "aaaaaaaaaaaaa", ""]:
            score = randomness_score(extract(label))
            assert 0.0 <= score <= 1.0

    def test_random_looking_string_scores_higher_than_a_word(self):
        assert randomness_score(extract("xk4q9zv1p8m")) > randomness_score(extract("example"))

    def test_empty_label_is_zero(self):
        assert randomness_score(extract("")) == 0.0

    def test_works_without_a_model(self):
        # No model supplied -- must not raise, and must still discriminate.
        assert randomness_score(extract("xk4q9zv1p")) > randomness_score(extract("banana"))

    def test_untrained_model_is_treated_like_no_model(self):
        from domain_monitor.ngram import NgramModel
        empty_model = NgramModel(order=3, tld="ch")
        assert randomness_score(extract("example"), empty_model) == randomness_score(
            extract("example"), None
        )

    def test_ngram_model_shifts_the_score(self):
        # A diverse, overlapping training corpus so the model actually discriminates
        # (see the design note in ngram.py / the project notes on toy-corpus artifacts).
        corpus = [
            "migros", "migrosbank", "migroskultur", "coop", "coopmarkt", "coopbau",
            "sbb", "sbbcargo", "postfinance", "postauto", "raiffeisen", "raiffeisenbank",
            "zuerich", "zuerichsee", "basel", "baselland", "bern", "bernmobil",
            "luzern", "luzernstadt", "gemeinde", "gemeindeamt", "verein", "vereinshaus",
            "apotheke", "apothekerin", "spital", "spitalzentrum", "schule", "schulhaus",
            "garage", "garagenverein", "restaurant", "restaurantfuehrer", "hotel",
            "hotelplan", "bank", "bankverein", "treuhand", "treuhandbuero",
        ] * 15
        model = build_from_labels(corpus, order=3, tld="ch")
        assert model.trained

        random_score = randomness_score(extract("xk4q9zv1p8m"), model)
        wordlike_score = randomness_score(extract("baselverein"), model)
        assert random_score > wordlike_score

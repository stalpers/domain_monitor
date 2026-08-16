from domain_monitor.confusables import has_non_ascii_confusable, skeleton


class TestSkeleton:
    def test_identity(self):
        assert skeleton("example") == "example"

    def test_leetspeak_digits_fold(self):
        assert skeleton("examp1e") == skeleton("example")
        assert skeleton("g00gle") == skeleton("google")

    def test_rn_folds_to_m(self):
        assert skeleton("arnazon") == skeleton("amazon")

    def test_vv_folds_to_w(self):
        assert skeleton("vvow") == skeleton("wow")

    def test_cl_folds_to_d(self):
        assert skeleton("clone") == skeleton("done")

    def test_cyrillic_homograph(self):
        # е, х, а below are Cyrillic, not Latin -- a classic homograph of "example".
        assert skeleton("ехаmple") == skeleton("example")

    def test_greek_homograph(self):
        # ο (omicron), ρ (rho) are Greek.
        assert skeleton("exαmple".replace("α", "a")) == "example"

    def test_fullwidth_latin(self):
        assert skeleton("ｅｘａｍｐｌｅ") == "example"

    def test_accented_latin_collapses_with_plain(self):
        assert skeleton("café") == skeleton("cafe")

    def test_operates_on_the_label_not_the_tld(self):
        assert skeleton("examp1e.ch") == "example"

    def test_takes_punycode_input(self):
        # zürich.ch's A-label -- must decode before folding, or Cyrillic/accented
        # homographs stored as punycode would never be caught.
        assert skeleton("xn--zrich-kva") == skeleton("zürich")

    def test_case_insensitive(self):
        assert skeleton("EXAMPLE") == skeleton("example")

    def test_longest_sequence_wins_first(self):
        # "rn" must be tried before falling through to single-char rules.
        assert skeleton("rn") == "m"

    def test_empty_string(self):
        assert skeleton("") == ""


class TestHasNonAsciiConfusable:
    def test_ascii_only_is_false(self):
        assert has_non_ascii_confusable("examp1e") is False

    def test_cyrillic_is_true(self):
        assert has_non_ascii_confusable("ехаmple") is True

    def test_punycode_input_decoded_first(self):
        assert has_non_ascii_confusable("xn--zrich-kva") is True

    def test_plain_punycode_tld_ignored(self):
        assert has_non_ascii_confusable("examp1e.ch") is False

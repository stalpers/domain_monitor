"""alerts.py rendering of typosquat-specific fields: method, brand, score, and the
by-brand summary. Complements tests/test_alerts.py, which covers the plain-regex path."""

import datetime as dt

from domain_monitor.alerts import group_by_brand, render_text
from domain_monitor.rules import Match

WHEN = dt.datetime(2026, 8, 11, 10, 0, tzinfo=dt.timezone.utc)


def squat_match(domain="examp1e.ch", method="homoglyph", brand="example", score=1.0):
    return Match(
        domain_name=domain, tld="ch", event_type="ADDED_TO_ZONE", detected_at=WHEN,
        rule_name="Brand watchlist", rule_description="Typosquats of protected brands",
        rule_pattern="typosquat: 1 brand(s), max_distance=1, methods=['homoglyph']",
        matched_value=domain.rsplit(".", 1)[0],
        method=method, brand=brand, score=score,
        signals='{"method": "homoglyph"}',
    )


class TestMethodAndBrandRendering:
    def test_method_and_brand_appear_in_the_body(self):
        body = render_text([squat_match()], 1, "UTC")
        assert "homoglyph" in body
        assert "example" in body

    def test_score_appears_in_the_body(self):
        body = render_text([squat_match(score=0.87)], 1, "UTC")
        assert "0.87" in body

    def test_plain_regex_match_renders_without_method_line(self):
        """A regex Match has method=None; its line must not claim a technique that
        was never determined."""
        plain = Match(
            domain_name="a.ch", tld="ch", event_type="ADDED_TO_ZONE", detected_at=WHEN,
            rule_name="Auth keywords", rule_description="d", rule_pattern="(?i)login",
            matched_value="login",
        )
        body = render_text([plain], 1, "UTC")
        assert "via" not in body.split("Auth keywords")[1].split("=" * 68)[0]


class TestScoreOrdering:
    def test_higher_score_listed_first_within_a_rule(self):
        low = squat_match(domain="low.ch", score=0.5)
        high = squat_match(domain="high.ch", score=1.5)
        body = render_text([low, high], 1, "UTC")
        assert body.index("high.ch") < body.index("low.ch")

    def test_missing_score_sorts_last(self):
        scored = squat_match(domain="scored.ch", score=0.5)
        unscored = Match(
            domain_name="unscored.ch", tld="ch", event_type="ADDED_TO_ZONE",
            detected_at=WHEN, rule_name="Brand watchlist", rule_description="d",
            rule_pattern="p", matched_value="unscored",
        )
        body = render_text([unscored, scored], 1, "UTC")
        assert body.index("scored.ch") < body.index("unscored.ch")


class TestGroupByBrand:
    def test_groups_matches_sharing_a_brand(self):
        m1 = squat_match(domain="a.ch", method="homoglyph")
        m2 = squat_match(domain="a.ch", method="replacement")
        m3 = squat_match(domain="b.ch", brand="other")
        grouped = group_by_brand([m1, m2, m3])
        assert len(grouped["example"]) == 2
        assert len(grouped["other"]) == 1

    def test_matches_without_a_brand_are_excluded(self):
        plain = Match(
            domain_name="a.ch", tld="ch", event_type="ADDED_TO_ZONE", detected_at=WHEN,
            rule_name="R", rule_description="d", rule_pattern="p", matched_value="a",
        )
        assert group_by_brand([plain]) == {}

    def test_brand_summary_appears_in_the_email_body(self):
        matches = [squat_match(domain="a.ch"), squat_match(domain="b.ch")]
        body = render_text(matches, 1, "UTC")
        assert "Summary by impersonated brand" in body
        assert "'example': 2 domain(s)" in body

    def test_no_brand_summary_section_when_nothing_is_branded(self):
        plain = Match(
            domain_name="a.ch", tld="ch", event_type="ADDED_TO_ZONE", detected_at=WHEN,
            rule_name="R", rule_description="d", rule_pattern="p", matched_value="a",
        )
        body = render_text([plain], 1, "UTC")
        assert "Summary by impersonated brand" not in body

"""Integration: typosquat rules through config loading, the rule engine, and a full
``run_once`` pipeline -- including the punycode/IDN path and the alerting posture."""

import tempfile
from pathlib import Path

import pytest
from sqlalchemy import select

from domain_monitor.config import ConfigError, TypoRule, load_rules
from domain_monitor.models import RuleMatch
from domain_monitor.service import run_once, run_backfill

TYPO_YAML = """
rules:
  - name: "Brand watchlist"
    description: "Typosquats of protected brands"
    type: typosquat
    brands: [example, postfinance, coop]
    max_distance: 1
    events: [ADDED_TO_ZONE, RETURNED_TO_ZONE]
"""


def write(tmp_path, text, name="rules.yaml"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


class TestConfigParsing:
    def test_loads_a_typosquat_rule(self, tmp_path):
        rules = load_rules(write(tmp_path, TYPO_YAML))
        assert isinstance(rules[0], TypoRule)
        assert rules[0].watchlist.brands == ["example", "postfinance", "coop"]

    def test_no_brands_is_rejected(self, tmp_path):
        text = (
            "rules:\n  - name: R\n    description: d\n    type: typosquat\n"
            "    events: [ADDED_TO_ZONE]\n"
        )
        with pytest.raises(ConfigError, match="no 'brands'"):
            load_rules(write(tmp_path, text))

    def test_unknown_type_is_rejected(self, tmp_path):
        text = (
            "rules:\n  - name: R\n    description: d\n    type: nonsense\n"
            "    events: [ADDED_TO_ZONE]\n"
        )
        with pytest.raises(ConfigError, match="unknown type"):
            load_rules(write(tmp_path, text))

    def test_unknown_method_is_rejected(self, tmp_path):
        text = (
            "rules:\n  - name: R\n    description: d\n    type: typosquat\n"
            "    brands: [example]\n    methods: [not_a_real_method]\n"
            "    events: [ADDED_TO_ZONE]\n"
        )
        with pytest.raises(ConfigError, match="unknown method"):
            load_rules(write(tmp_path, text))

    def test_zero_max_distance_is_rejected(self, tmp_path):
        text = (
            "rules:\n  - name: R\n    description: d\n    type: typosquat\n"
            "    brands: [example]\n    max_distance: 0\n    events: [ADDED_TO_ZONE]\n"
        )
        with pytest.raises(ConfigError, match="max_distance"):
            load_rules(write(tmp_path, text))

    def test_default_type_is_still_regex(self, tmp_path):
        text = "rules:\n  - name: R\n    description: d\n    regex: 'x'\n    events: [ADDED_TO_ZONE]\n"
        rules = load_rules(write(tmp_path, text))
        assert type(rules[0]).__name__ == "RegexRule"

    def test_shipped_example_rules_still_load(self):
        from pathlib import Path

        path = Path(__file__).resolve().parent.parent / "rules.example.yaml"
        rules = load_rules(path)
        assert any(isinstance(r, TypoRule) for r in rules)


class TestRuleEngineIntegration:
    def test_evaluate_events_persists_method_brand_score(self, config, session_factory):
        config.rules = load_rules(_watchlist_yaml())

        report = run_once(config, session_factory, zone_names={"ch": ["example.ch"]})
        assert report.counts.baseline

        report = run_once(
            config, session_factory, zone_names={"ch": ["example.ch", "examp1e.ch"]}
        )
        assert len(report.matches) >= 1
        match = report.matches[0]
        assert match.method in {"homoglyph", "replacement"}
        assert match.brand == "example"
        assert match.score is not None
        assert match.signals is not None

        with session_factory() as s:
            rows = s.execute(select(RuleMatch)).scalars().all()
        assert all(r.method is not None for r in rows)
        assert all(r.brand == "example" for r in rows)

    def test_one_domain_two_methods_two_rows(self, session_factory, config):
        config.rules = load_rules(_watchlist_yaml())
        run_once(config, session_factory, zone_names={"ch": ["seed.ch"]})
        report = run_once(
            config, session_factory, zone_names={"ch": ["seed.ch", "examp1e.ch"]}
        )
        methods = {m.method for m in report.matches if m.domain_name == "examp1e.ch"}
        assert {"homoglyph", "replacement"} <= methods

    def test_backfill_finds_a_pre_existing_squat(self, session_factory, config):
        config.rules = []
        run_once(config, session_factory, zone_names={"ch": ["examp1e.ch", "other.ch"]})

        config.rules = load_rules(_watchlist_yaml())
        report = run_backfill(config, session_factory)
        assert any(m.domain_name == "examp1e.ch" for m in report.matches)
        assert all(m.event_type is None for m in report.matches)   # backfill marker


class TestPostureEndToEnd:
    """The design's central alerting rule, proven through the real pipeline rather than
    just scoring.py in isolation: a random-looking but unwatchlisted name must produce
    no match at all, anywhere in the persisted state."""

    def test_random_name_with_no_watchlist_hit_produces_no_match(self, session_factory, config):
        config.rules = load_rules(_watchlist_yaml())
        run_once(config, session_factory, zone_names={"ch": ["seed.ch"]})
        report = run_once(
            config, session_factory,
            zone_names={"ch": ["seed.ch", "xk4q9zv1p8m3q7wtnb.ch"]},
        )
        assert report.matches == []

        with session_factory() as s:
            assert s.execute(select(RuleMatch)).scalars().all() == []


class TestPunycodeEndToEnd:
    def test_cyrillic_homograph_stored_as_punycode_is_still_caught(self, session_factory, config):
        """The pipeline normalises and stores names as punycode A-labels. A homograph
        squat must still be detected after that round-trip, which means the detector
        has to decode back to Unicode before folding -- exactly the subtlety flagged
        in the design as the easiest thing to get wrong."""
        config.rules = load_rules(_watchlist_yaml())
        run_once(config, session_factory, zone_names={"ch": ["seed.ch"]})

        # "ехаmple" with Cyrillic е, х, а -- what actually gets stored is its punycode form.
        report = run_once(
            config, session_factory, zone_names={"ch": ["seed.ch", "ехаmple.ch"]}
        )

        assert len(report.matches) >= 1
        assert report.matches[0].method == "homoglyph"
        assert report.matches[0].domain_name.startswith("xn--")   # confirms punycode storage


def _watchlist_yaml() -> Path:
    text = (
        "rules:\n"
        "  - name: \"Brand watchlist\"\n"
        "    description: \"Typosquats of protected brands\"\n"
        "    type: typosquat\n"
        "    brands: [example, postfinance, coop]\n"
        "    max_distance: 1\n"
        "    events: [ADDED_TO_ZONE]\n"
    )
    fd = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
    fd.write(text)
    fd.close()
    return Path(fd.name)

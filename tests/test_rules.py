import pytest
from sqlalchemy import select

from domain_monitor.config import (
    ADDED_TO_ZONE,
    REMOVED_FROM_ZONE,
    ConfigError,
    load_rules,
)
from domain_monitor.models import RuleMatch
from domain_monitor.service import run_backfill, run_once
from tests.conftest import rule

RULES_YAML = """
rules:
  - name: "Brand"
    description: "Domain resembling the Example brand"
    regex: '(?i)examp[l1]e'
    events: [ADDED_TO_ZONE]
  - name: "Short released"
    description: "Three-letter .ch domain that left the zone"
    regex: '^[a-z]{3}\\.ch$'
    events: [REMOVED_FROM_ZONE]
"""


def write(tmp_path, text, name="rules.yaml"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


class TestRuleLoading:
    def test_loads_valid_rules(self, tmp_path):
        rules = load_rules(write(tmp_path, RULES_YAML))
        assert [r.name for r in rules] == ["Brand", "Short released"]
        assert rules[0].event_types == frozenset({ADDED_TO_ZONE})

    def test_regex_survives_yaml_quoting(self, tmp_path):
        """The reason rules live in YAML: $, \\ and quotes pass through intact."""
        rules = load_rules(write(tmp_path, RULES_YAML))
        assert rules[1].regex.pattern == r"^[a-z]{3}\.ch$"
        assert rules[1].matches("abc.ch") == "abc.ch"
        assert rules[1].matches("abcd.ch") is None

    def test_missing_file(self, tmp_path):
        with pytest.raises(ConfigError, match="not found"):
            load_rules(tmp_path / "nope.yaml")

    def test_invalid_regex_fails_at_load_naming_the_rule(self, tmp_path):
        """Must fail before the zone transfer, not hours later mid-evaluation."""
        bad = "rules:\n  - name: Bad\n    description: d\n    regex: '[unclosed'\n    events: [ADDED_TO_ZONE]\n"
        with pytest.raises(ConfigError, match="Bad.*invalid regex"):
            load_rules(write(tmp_path, bad))

    def test_missing_description_rejected(self, tmp_path):
        text = "rules:\n  - name: N\n    regex: 'x'\n    events: [ADDED_TO_ZONE]\n"
        with pytest.raises(ConfigError, match="no 'description'"):
            load_rules(write(tmp_path, text))

    def test_missing_events_rejected(self, tmp_path):
        text = "rules:\n  - name: N\n    description: d\n    regex: 'x'\n    events: []\n"
        with pytest.raises(ConfigError, match="no 'events'"):
            load_rules(write(tmp_path, text))

    def test_unknown_event_type_rejected(self, tmp_path):
        text = "rules:\n  - name: N\n    description: d\n    regex: 'x'\n    events: [SOLD]\n"
        with pytest.raises(ConfigError, match="unknown event type"):
            load_rules(write(tmp_path, text))

    def test_duplicate_names_rejected(self, tmp_path):
        text = RULES_YAML + "\n  - name: \"Brand\"\n    description: d\n    regex: 'y'\n    events: [ADDED_TO_ZONE]\n"
        with pytest.raises(ConfigError, match="duplicate rule name"):
            load_rules(write(tmp_path, text))

    def test_empty_rules_rejected(self, tmp_path):
        with pytest.raises(ConfigError, match="defines no rules"):
            load_rules(write(tmp_path, "rules: []\n"))


class TestEvaluation:
    def test_matching_event_produces_a_match(self, config, session_factory):
        config.rules = [rule(name="Brand", pattern="example", events=(ADDED_TO_ZONE,))]
        run_once(config, session_factory, zone_names={"ch": ["a.ch"]})
        report = run_once(config, session_factory, zone_names={"ch": ["a.ch", "example.ch"]})
        assert [m.domain_name for m in report.matches] == ["example.ch"]

    def test_non_matching_event_is_ignored(self, config, session_factory):
        config.rules = [rule(name="Brand", pattern="example", events=(ADDED_TO_ZONE,))]
        run_once(config, session_factory, zone_names={"ch": ["a.ch"]})
        report = run_once(config, session_factory, zone_names={"ch": ["a.ch", "other.ch"]})
        assert report.matches == []

    def test_rule_only_fires_for_its_event_types(self, config, session_factory):
        config.rules = [rule(name="OnRemoval", pattern="b", events=(REMOVED_FROM_ZONE,))]
        run_once(config, session_factory, zone_names={"ch": ["a.ch"]})
        added = run_once(config, session_factory, zone_names={"ch": ["a.ch", "b.ch"]})
        assert added.matches == []
        removed = run_once(config, session_factory, zone_names={"ch": ["a.ch"]})
        assert [m.domain_name for m in removed.matches] == ["b.ch"]

    def test_one_event_can_match_several_rules(self, config, session_factory):
        config.rules = [
            rule(name="Contains ex", pattern="ex", events=(ADDED_TO_ZONE,)),
            rule(name="Ends in ch", pattern=r"\.ch$", events=(ADDED_TO_ZONE,)),
        ]
        run_once(config, session_factory, zone_names={"ch": ["a.ch"]})
        report = run_once(config, session_factory, zone_names={"ch": ["a.ch", "example.ch"]})
        assert {m.rule_name for m in report.matches} == {"Contains ex", "Ends in ch"}

    def test_disabled_rule_never_fires(self, config, session_factory):
        config.rules = [rule(name="Off", pattern=".", events=(ADDED_TO_ZONE,), enabled=False)]
        run_once(config, session_factory, zone_names={"ch": ["a.ch"]})
        report = run_once(config, session_factory, zone_names={"ch": ["a.ch", "b.ch"]})
        assert report.matches == []

    def test_match_records_full_attribution(self, config, session_factory):
        config.rules = [rule(
            name="Brand", pattern="example", events=(ADDED_TO_ZONE,),
            description="Domain resembling the Example brand",
        )]
        run_once(config, session_factory, zone_names={"ch": ["a.ch"]})
        run_once(config, session_factory, zone_names={"ch": ["a.ch", "example.ch"]})
        with session_factory() as s:
            row = s.execute(select(RuleMatch)).scalar_one()
        assert row.rule_name == "Brand"
        assert row.rule_description == "Domain resembling the Example brand"
        assert row.rule_pattern == "example"
        assert row.matched_value == "example"
        assert row.domain_event_id is not None       # event-driven match

    def test_rules_evaluate_only_events_not_the_whole_zone(self, config, session_factory):
        """1000 in-zone names, one change: exactly one name is considered."""
        config.rules = [rule(name="All", pattern=".", events=(ADDED_TO_ZONE,))]
        base = [f"d{i}.ch" for i in range(1000)]
        run_once(config, session_factory, zone_names={"ch": base})
        report = run_once(config, session_factory, zone_names={"ch": base + ["new.ch"]})
        assert len(report.matches) == 1


class TestBackfill:
    def test_evaluates_against_current_state(self, config, session_factory):
        """A rule added after the fact must still find what is already in the zone."""
        config.rules = []
        run_once(config, session_factory, zone_names={"ch": ["example.ch", "other.ch"]})

        config.rules = [rule(name="Brand", pattern="example", events=(ADDED_TO_ZONE,))]
        report = run_backfill(config, session_factory)
        assert [m.domain_name for m in report.matches] == ["example.ch"]

    def test_backfill_matches_have_no_event(self, config, session_factory):
        """A backfill match is about present state, not an observed change."""
        config.rules = [rule(name="Brand", pattern="example", events=(ADDED_TO_ZONE,))]
        run_once(config, session_factory, zone_names={"ch": ["example.ch"]})
        run_backfill(config, session_factory)
        with session_factory() as s:
            row = s.execute(select(RuleMatch)).scalar_one()
        assert row.domain_event_id is None
        assert row.domain_id is not None

    def test_backfill_ignores_out_of_zone_domains(self, config, session_factory):
        config.rules = [rule(name="Brand", pattern="example", events=(ADDED_TO_ZONE,))]
        run_once(config, session_factory, zone_names={"ch": ["example.ch", "a.ch"]})
        run_once(config, session_factory, zone_names={"ch": ["a.ch"]})
        report = run_backfill(config, session_factory)
        assert report.matches == []

    def test_backfill_can_target_one_rule(self, config, session_factory):
        config.rules = [
            rule(name="A", pattern="example", events=(ADDED_TO_ZONE,)),
            rule(name="B", pattern="other", events=(ADDED_TO_ZONE,)),
        ]
        run_once(config, session_factory, zone_names={"ch": ["example.ch", "other.ch"]})
        report = run_backfill(config, session_factory, only="B")
        assert [m.rule_name for m in report.matches] == ["B"]

    def test_backfill_ignores_event_type_scoping(self, config, session_factory):
        """There is no event to scope against; the rule applies to current state."""
        config.rules = [rule(name="R", pattern="example", events=(REMOVED_FROM_ZONE,))]
        run_once(config, session_factory, zone_names={"ch": ["example.ch"]})
        report = run_backfill(config, session_factory)
        assert len(report.matches) == 1

    def test_backfill_dry_run_writes_nothing(self, config, session_factory):
        config.rules = [rule(name="R", pattern="example", events=(ADDED_TO_ZONE,))]
        run_once(config, session_factory, zone_names={"ch": ["example.ch"]})
        report = run_backfill(config, session_factory, dry_run=True)
        assert len(report.matches) == 1
        with session_factory() as s:
            assert s.execute(select(RuleMatch)).scalars().all() == []

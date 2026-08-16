"""Locking, the transfer interval guard, config loading and name normalisation."""

import datetime as dt
import multiprocessing
import time

import pytest
from sqlalchemy import select

from domain_monitor.config import ConfigError, load_config
from domain_monitor.locking import AlreadyRunning, process_lock
from domain_monitor.models import Domain, Run, ZoneSnapshotStat
from domain_monitor.names import normalise_name, tld_of, to_display
from domain_monitor.service import run_once
from domain_monitor.zones import hours_since_last_transfer


class TestNormalisation:
    def test_lowercases_and_strips_trailing_dot(self):
        assert normalise_name("Example.CH.") == "example.ch"

    def test_idn_to_punycode(self):
        assert normalise_name("zürich.ch") == "xn--zrich-kva.ch"

    def test_round_trip(self):
        assert to_display(normalise_name("zürich.ch")) == "zürich.ch"

    def test_unicode_and_punycode_collapse(self):
        assert normalise_name("Zürich.CH") == normalise_name("xn--zrich-kva.ch")

    def test_www_is_preserved(self):
        """www.ch is registrable; treating www as a prefix corrupts it into 'ch'."""
        assert normalise_name("www.ch") == "www.ch"
        assert normalise_name("www.example.ch") == "www.example.ch"

    def test_empty_and_whitespace(self):
        assert normalise_name("   ") == ""

    def test_undecodable_label_does_not_raise(self):
        assert normalise_name("xn--.ch")

    def test_tld_of(self):
        assert tld_of("a.b.ch") == "ch"
        assert tld_of("nodots") == ""


class TestLocking:
    def test_lock_is_released_after_the_block(self, tmp_path):
        path = tmp_path / "lock"
        with process_lock(path):
            pass
        with process_lock(path):
            pass

    def test_reentrant_acquisition_in_the_same_process_is_refused(self, tmp_path):
        path = tmp_path / "lock"
        with process_lock(path), pytest.raises(AlreadyRunning):
            with process_lock(path):
                pass

    def test_second_process_is_refused(self, tmp_path):
        """The real case: cron fires again while the previous run is still going."""
        path = str(tmp_path / "lock")
        started = multiprocessing.Event()
        result = multiprocessing.Queue()

        def hold():
            with process_lock(path):
                started.set()
                time.sleep(2.0)

        def attempt():
            started.wait(5.0)
            try:
                with process_lock(path):
                    result.put("acquired")
            except AlreadyRunning:
                result.put("refused")

        holder = multiprocessing.Process(target=hold)
        other = multiprocessing.Process(target=attempt)
        holder.start()
        other.start()
        other.join(10)
        holder.join(10)
        assert result.get(timeout=5) == "refused"

    def test_lock_directory_is_created(self, tmp_path):
        with process_lock(tmp_path / "nested" / "dir" / "lock"):
            pass
        assert (tmp_path / "nested" / "dir").exists()


class TestTransferInterval:
    def test_no_previous_transfer(self, session):
        assert hours_since_last_transfer(session, "ch") is None

    def test_age_of_a_fresh_transfer(self, session):
        session.add(ZoneSnapshotStat(tld="ch", name_count=10))
        session.commit()
        assert hours_since_last_transfer(session, "ch") < 0.1

    def test_run_inside_the_interval_is_skipped(self, config, session_factory):
        """Switch asks for at most one transfer per 24h; the code enforces it."""
        run_once(config, session_factory, zone_names={"ch": ["a.ch"]})
        report = run_once(config, session_factory)          # no injected names -> real path
        assert report.status == Run.STATUS_SKIPPED
        assert "minimum interval" in report.skipped_reason

    def test_skipped_run_changes_nothing(self, config, session_factory):
        run_once(config, session_factory, zone_names={"ch": ["a.ch", "b.ch"]})
        run_once(config, session_factory)
        with session_factory() as s:
            assert len(s.execute(select(Domain)).scalars().all()) == 2

    def test_stale_transfer_is_allowed_to_proceed(self, config, session_factory):
        run_once(config, session_factory, zone_names={"ch": ["a.ch"]})
        with session_factory() as s:
            stat = s.get(ZoneSnapshotStat, "ch")
            stat.transferred_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=30)
            s.commit()
        report = run_once(config, session_factory, zone_names={"ch": ["a.ch", "b.ch"]})
        assert report.status == Run.STATUS_SUCCESS
        assert report.counts.added == 1

    def test_injected_names_bypass_the_guard(self, config, session_factory):
        """Tests and file sources must not be blocked by the interval."""
        run_once(config, session_factory, zone_names={"ch": ["a.ch"]})
        report = run_once(config, session_factory, zone_names={"ch": ["a.ch", "b.ch"]})
        assert report.status == Run.STATUS_SUCCESS


class TestConfigLoading:
    BASE = {
        "MONITOR_TLDS": "ch,li",
        "DATABASE_URL": "sqlite:///x.db",
    }

    def test_loads_with_a_rules_file(self, tmp_path):
        rules = tmp_path / "rules.yaml"
        rules.write_text(
            "rules:\n  - name: N\n    description: d\n    regex: 'x'\n    events: [ADDED_TO_ZONE]\n",
            encoding="utf-8",
        )
        cfg = load_config(env={**self.BASE, "DOMAIN_RULES_PATH": str(rules)})
        assert cfg.tlds == ["ch", "li"]
        assert len(cfg.rules) == 1
        assert set(cfg.zones) == {"ch", "li"}

    def test_smtp_enabled_without_settings_is_rejected(self, tmp_path):
        rules = tmp_path / "rules.yaml"
        rules.write_text(
            "rules:\n  - name: N\n    description: d\n    regex: 'x'\n    events: [ADDED_TO_ZONE]\n",
            encoding="utf-8",
        )
        with pytest.raises(ConfigError, match="SMTP_HOST"):
            load_config(env={
                **self.BASE, "DOMAIN_RULES_PATH": str(rules), "SMTP_ENABLED": "true",
            })

    def test_bad_ratio_rejected(self, tmp_path):
        rules = tmp_path / "rules.yaml"
        rules.write_text(
            "rules:\n  - name: N\n    description: d\n    regex: 'x'\n    events: [ADDED_TO_ZONE]\n",
            encoding="utf-8",
        )
        with pytest.raises(ConfigError, match="ZONE_MIN_RATIO"):
            load_config(env={
                **self.BASE, "DOMAIN_RULES_PATH": str(rules), "ZONE_MIN_RATIO": "1.5",
            })

    def test_shipped_example_rules_are_valid(self):
        """rules.example.yaml is what users copy; it must load."""
        from pathlib import Path

        from domain_monitor.config import load_rules

        path = Path(__file__).resolve().parent.parent / "rules.example.yaml"
        rules = load_rules(path)
        assert len(rules) >= 3
        assert any(r.name == "Short .ch domains released" for r in rules)

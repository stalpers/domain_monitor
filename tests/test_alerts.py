import datetime as dt
import smtplib

import pytest
from sqlalchemy import select

from domain_monitor.alerts import (
    AlertError,
    build_email,
    group_by_rule,
    render_text,
    send_email,
    subject_for,
)
from domain_monitor.config import ADDED_TO_ZONE, REMOVED_FROM_ZONE, SmtpConfig
from domain_monitor.models import Alert
from domain_monitor.rules import Match
from domain_monitor.service import run_once
from tests.conftest import rule

WHEN = dt.datetime(2026, 8, 11, 10, 0, tzinfo=dt.timezone.utc)


def match(domain="example.ch", rule_name="Brand", event=ADDED_TO_ZONE,
          description="Domain resembling the Example brand", pattern="example",
          matched="example"):
    return Match(
        domain_name=domain, tld="ch", event_type=event, detected_at=WHEN,
        rule_name=rule_name, rule_description=description,
        rule_pattern=pattern, matched_value=matched,
    )


def smtp_cfg(**kw):
    defaults = dict(
        enabled=True, host="smtp.test", port=587, username="u", password="p",
        sender="from@test", recipients=["sec@test"],
    )
    defaults.update(kw)
    return SmtpConfig(**defaults)


class TestSubject:
    def test_single_match_names_the_domain(self):
        assert subject_for([match()]) == "[DOMAIN ALERT] ADDED_TO_ZONE example.ch"

    def test_many_matches_one_rule(self):
        subject = subject_for([match(), match(domain="example2.ch")])
        assert "2 matches" in subject and "Brand" in subject

    def test_many_rules_are_counted(self):
        subject = subject_for([match(), match(rule_name="Phishing")])
        assert "2 rule matches across 2 rules" in subject


class TestRendering:
    def test_states_rule_name_description_and_pattern(self):
        body = render_text([match()], 42, "Europe/Zurich")
        assert "Brand" in body
        assert "Domain resembling the Example brand" in body
        assert "example" in body
        assert "Run ID: 42" in body

    def test_groups_by_rule(self):
        body = render_text(
            [match(), match(domain="b.ch", rule_name="Phishing", description="phish")],
            1, "Europe/Zurich",
        )
        assert body.index("Brand") < body.index("Phishing")

    def test_renders_local_time(self):
        body = render_text([match()], 1, "Europe/Zurich")
        assert "2026-08-11 12:00 CEST" in body      # 10:00 UTC in summer

    def test_unknown_timezone_falls_back_without_raising(self):
        assert render_text([match()], 1, "Mars/Olympus")

    def test_punycode_rendered_for_humans(self):
        body = render_text([match(domain="xn--zrich-kva.ch")], 1, "UTC")
        assert "zürich.ch" in body

    def test_backfill_match_is_labelled(self):
        body = render_text([match(event=None)], 1, "UTC")
        assert "backfill" in body.lower()

    def test_warns_that_removal_is_not_availability(self):
        body = render_text([match(event=REMOVED_FROM_ZONE)], 1, "UTC")
        assert "not proof that it is available" in body

    def test_grouping_helper(self):
        grouped = group_by_rule([match(), match(domain="b.ch"), match(rule_name="Other")])
        assert len(grouped["Brand"]) == 2
        assert len(grouped["Other"]) == 1


class TestEmailAssembly:
    def test_headers_and_body(self):
        message = build_email([match()], 7, smtp_cfg(recipients=["a@t", "b@t"]), "UTC")
        assert message["From"] == "from@test"
        assert message["To"] == "a@t, b@t"
        assert "Brand" in message.get_content()

    def test_one_message_for_many_matches(self):
        """~100 .ch removals a day; one email per match would be a mail-flood."""
        matches = [match(domain=f"d{i}.ch") for i in range(50)]
        message = build_email(matches, 1, smtp_cfg(), "UTC")
        assert "50 rule match(es)" in message.get_content()

    def test_disabled_smtp_raises(self):
        with pytest.raises(AlertError, match="not enabled"):
            send_email([match()], 1, smtp_cfg(enabled=False), "UTC")

    def test_smtp_failure_raises_alert_error(self, monkeypatch):
        def boom(*a, **kw):
            raise smtplib.SMTPConnectError(421, "nope")

        monkeypatch.setattr(smtplib, "SMTP", boom)
        with pytest.raises(AlertError, match="SMTP delivery"):
            send_email([match()], 1, smtp_cfg(), "UTC")


class TestDeliveryIsolation:
    """An SMTP outage must never cost a detected change."""

    def test_smtp_failure_leaves_state_committed(self, config, session_factory, monkeypatch):
        config.rules = [rule(name="All", pattern=".", events=(ADDED_TO_ZONE,))]
        config.smtp = smtp_cfg()
        run_once(config, session_factory, zone_names={"ch": ["a.ch"]})

        def boom(*a, **kw):
            raise smtplib.SMTPConnectError(421, "relay down")

        monkeypatch.setattr(smtplib, "SMTP", boom)
        report = run_once(config, session_factory, zone_names={"ch": ["a.ch", "new.ch"]})

        assert report.counts.added == 1
        with session_factory() as s:
            from domain_monitor.models import Domain, DomainEvent
            assert s.execute(select(Domain).where(Domain.name == "new.ch")).scalar_one()
            assert len(s.execute(select(DomainEvent)).scalars().all()) == 1

    def test_smtp_failure_is_recorded_as_a_failed_alert(self, config, session_factory, monkeypatch):
        config.rules = [rule(name="All", pattern=".", events=(ADDED_TO_ZONE,))]
        config.smtp = smtp_cfg()
        run_once(config, session_factory, zone_names={"ch": ["a.ch"]})

        monkeypatch.setattr(
            smtplib, "SMTP", lambda *a, **kw: (_ for _ in ()).throw(OSError("down"))
        )
        run_once(config, session_factory, zone_names={"ch": ["a.ch", "new.ch"]})

        with session_factory() as s:
            alert = s.execute(select(Alert).where(Alert.channel == "smtp")).scalar_one()
        assert alert.status == Alert.STATUS_FAILED
        assert alert.error_message

    def test_successful_delivery_is_recorded(self, config, session_factory, monkeypatch):
        config.rules = [rule(name="All", pattern=".", events=(ADDED_TO_ZONE,))]
        config.smtp = smtp_cfg()
        sent = []

        class FakeSMTP:
            def __init__(self, *a, **kw):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def ehlo(self):
                pass

            def starttls(self):
                pass

            def login(self, *a):
                pass

            def send_message(self, message):
                sent.append(message)

        monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
        run_once(config, session_factory, zone_names={"ch": ["a.ch"]})
        run_once(config, session_factory, zone_names={"ch": ["a.ch", "new.ch"]})

        assert len(sent) == 1
        with session_factory() as s:
            alert = s.execute(select(Alert).where(Alert.channel == "smtp")).scalar_one()
        assert alert.status == Alert.STATUS_SENT
        assert alert.match_count == 1

    def test_no_email_flag_suppresses_delivery(self, config, session_factory, monkeypatch):
        config.rules = [rule(name="All", pattern=".", events=(ADDED_TO_ZONE,))]
        config.smtp = smtp_cfg()
        monkeypatch.setattr(
            smtplib, "SMTP", lambda *a, **kw: pytest.fail("must not send")
        )
        run_once(config, session_factory, zone_names={"ch": ["a.ch"]})
        run_once(
            config, session_factory,
            zone_names={"ch": ["a.ch", "new.ch"]}, send_mail=False,
        )

"""Configuration.

Two sources, deliberately separated:

* ``.env`` -- secrets (TSIG keys, SMTP password) and operational settings.
* ``rules.yaml`` -- the rules themselves.

Rules are *configuration*, not secrets, and they are the thing most likely to change and
most in need of review. Keeping them in a tracked YAML file means a rule change is a
readable diff. Packing them into an env var as JSON also breaks on the characters regexes
are made of -- ``$``, ``#``, quotes, backslashes -- which dotenv parsing and ``set -a``
sourcing both mangle.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

DEFAULT_RULES_PATH = Path("rules.yaml")


class ConfigError(Exception):
    """The environment or rules file is invalid."""


# --- events ---------------------------------------------------------------------

#: Event names are zone-scoped on purpose. "NEW" would read as "newly registered", which
#: is exactly the conflation this system exists to avoid: leaving the zone is not the
#: same as becoming available, and joining it is not the same as being registered.
ADDED_TO_ZONE = "ADDED_TO_ZONE"
REMOVED_FROM_ZONE = "REMOVED_FROM_ZONE"
RETURNED_TO_ZONE = "RETURNED_TO_ZONE"

EVENT_TYPES = frozenset({ADDED_TO_ZONE, REMOVED_FROM_ZONE, RETURNED_TO_ZONE})

#: Reserved for the availability stage; never produced by the zone diff.
FUTURE_EVENT_TYPES = frozenset({"AVAILABLE", "REGISTERED_NOT_DELEGATED", "UNKNOWN"})


@dataclass(frozen=True, slots=True)
class DomainRule:
    name: str
    description: str
    regex: re.Pattern[str]
    event_types: frozenset[str]
    enabled: bool = True

    def matches(self, name: str) -> str | None:
        """Return the matched text, or ``None``. Empty-string matches count as a match."""
        found = self.regex.search(name)
        return found.group(0) if found is not None else None

    def applies_to(self, event_type: str) -> bool:
        return event_type in self.event_types


@dataclass(slots=True)
class ZoneSource:
    tld: str
    server: str = "zonedata.switch.ch"
    tsig_name: str = ""
    tsig_secret: str = ""
    tsig_algorithm: str = "hmac-sha512"
    file_path: Path | None = None      # test/offline source; bypasses AXFR

    @property
    def uses_file(self) -> bool:
        return self.file_path is not None


@dataclass(slots=True)
class SmtpConfig:
    enabled: bool = False
    host: str = ""
    port: int = 587
    username: str = ""
    password: str = ""
    starttls: bool = True
    use_ssl: bool = False
    sender: str = ""
    recipients: list[str] = field(default_factory=list)
    timeout: float = 30.0


@dataclass(slots=True)
class Config:
    database_url: str
    tlds: list[str]
    timezone: str
    zones: dict[str, ZoneSource]
    rules: list[DomainRule]
    smtp: SmtpConfig
    console_alerts: bool
    log_level: str
    lock_path: Path
    min_transfer_interval_hours: int
    min_zone_ratio: float

    def enabled_rules(self) -> list[DomainRule]:
        return [r for r in self.rules if r.enabled]


def _env_bool(name: str, default: bool, env: dict[str, str]) -> bool:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def load_rules(path: Path | str) -> list[DomainRule]:
    """Load and compile rules. Every regex is validated here, not at match time.

    A bad pattern must fail the run immediately with the offending rule named, rather
    than raising mid-sweep after the zone has already been transferred.
    """
    path = Path(path)
    if not path.exists():
        raise ConfigError(
            f"rules file {path} not found -- copy rules.example.yaml to {path}"
        )
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path} is not valid YAML: {exc}") from None

    if not isinstance(raw, dict) or "rules" not in raw:
        raise ConfigError(f"{path} must contain a top-level 'rules:' list")
    entries = raw["rules"]
    if not isinstance(entries, list) or not entries:
        raise ConfigError(f"{path} defines no rules")

    rules: list[DomainRule] = []
    seen: set[str] = set()
    for entry in entries:
        rules.append(_build_rule(entry, path))
        if rules[-1].name in seen:
            raise ConfigError(
                f"duplicate rule name {rules[-1].name!r} in {path}; names must be unique "
                "because every alert is attributed by them"
            )
        seen.add(rules[-1].name)
    return rules


def _build_rule(entry: Any, path: Path) -> DomainRule:
    if not isinstance(entry, dict):
        raise ConfigError(f"each entry under 'rules' in {path} must be a mapping")

    name = str(entry.get("name", "")).strip()
    if not name:
        raise ConfigError(f"a rule in {path} has no 'name'; alerts are attributed by it")

    description = str(entry.get("description", "")).strip()
    if not description:
        raise ConfigError(
            f"rule {name!r} has no 'description'; every alert must explain why it fired"
        )

    pattern = entry.get("regex")
    if not pattern:
        raise ConfigError(f"rule {name!r} has no 'regex'")
    try:
        compiled = re.compile(str(pattern))
    except re.error as exc:
        raise ConfigError(f"rule {name!r} has an invalid regex {pattern!r}: {exc}") from None

    events = entry.get("events", [])
    if isinstance(events, str):
        events = [events]
    events = {str(e).upper() for e in events}
    if not events:
        raise ConfigError(
            f"rule {name!r} lists no 'events'; a rule that matches nothing never fires"
        )
    unknown = events - EVENT_TYPES - FUTURE_EVENT_TYPES
    if unknown:
        raise ConfigError(
            f"rule {name!r} references unknown event type(s) {sorted(unknown)}; "
            f"expected some of {sorted(EVENT_TYPES)}"
        )

    return DomainRule(
        name=name,
        description=description,
        regex=compiled,
        event_types=frozenset(events),
        enabled=bool(entry.get("enabled", True)),
    )


def load_config(env_file: Path | str | None = ".env", env: dict[str, str] | None = None) -> Config:
    """Assemble configuration from the environment plus the rules file."""
    if env is None:
        if env_file and Path(env_file).exists():
            load_dotenv(env_file, override=False)
        env = dict(os.environ)

    tlds = [t.strip().lower().lstrip(".") for t in env.get("MONITOR_TLDS", "ch,li").split(",")]
    tlds = [t for t in tlds if t]
    if not tlds:
        raise ConfigError("MONITOR_TLDS is empty")

    zones: dict[str, ZoneSource] = {}
    for tld in tlds:
        upper = tld.upper()
        file_path = env.get(f"{upper}_ZONE_FILE", "").strip()
        zones[tld] = ZoneSource(
            tld=tld,
            server=env.get(f"{upper}_ZONE_SERVER", "zonedata.switch.ch"),
            tsig_name=env.get(f"{upper}_TSIG_KEY_NAME", "").strip(),
            tsig_secret=env.get(f"{upper}_TSIG_SECRET", "").strip(),
            tsig_algorithm=env.get(f"{upper}_TSIG_ALGORITHM", "hmac-sha512").strip(),
            file_path=Path(file_path) if file_path else None,
        )

    smtp = SmtpConfig(
        enabled=_env_bool("SMTP_ENABLED", False, env),
        host=env.get("SMTP_HOST", ""),
        port=int(env.get("SMTP_PORT") or 587),
        username=env.get("SMTP_USERNAME", ""),
        password=env.get("SMTP_PASSWORD", ""),
        starttls=_env_bool("SMTP_STARTTLS", True, env),
        use_ssl=_env_bool("SMTP_SSL", False, env),
        sender=env.get("SMTP_FROM", ""),
        recipients=[r.strip() for r in env.get("SMTP_TO", "").split(",") if r.strip()],
        timeout=float(env.get("SMTP_TIMEOUT") or 30.0),
    )
    if smtp.enabled and not (smtp.host and smtp.sender and smtp.recipients):
        raise ConfigError(
            "SMTP_ENABLED is true but SMTP_HOST / SMTP_FROM / SMTP_TO are not all set"
        )

    ratio = float(env.get("ZONE_MIN_RATIO") or 0.5)
    if not 0.0 <= ratio < 1.0:
        raise ConfigError("ZONE_MIN_RATIO must be between 0.0 and 1.0")

    return Config(
        database_url=env.get("DATABASE_URL", "sqlite:///data/domain_monitor.db"),
        tlds=tlds,
        timezone=env.get("TIMEZONE", "Europe/Zurich"),
        zones=zones,
        rules=load_rules(env.get("DOMAIN_RULES_PATH") or DEFAULT_RULES_PATH),
        smtp=smtp,
        console_alerts=_env_bool("CONSOLE_ALERTS", True, env),
        log_level=env.get("LOG_LEVEL", "INFO"),
        lock_path=Path(env.get("LOCK_PATH", "/tmp/domain-monitor.lock")),
        min_transfer_interval_hours=int(env.get("ZONE_MIN_TRANSFER_INTERVAL_HOURS") or 24),
        min_zone_ratio=ratio,
    )

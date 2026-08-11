# domain-monitor

Detect changes in the `.ch` and `.li` domain namespace, evaluate them against rules, and
alert — as a cron batch job, not a daemon.

```
cron -> AXFR .ch/.li -> validate -> diff -> events -> rules -> matches -> alerts
```

## The distinction the whole design protects

**A domain leaving the DNS zone does not mean it is available to register.**

A registered domain can lose its delegation and stay registered indefinitely. So this tool
reports what it can actually observe — zone membership — and never claims more:

| Event | Means |
|---|---|
| `ADDED_TO_ZONE` | The name is now delegated. *Not* necessarily newly registered. |
| `REMOVED_FROM_ZONE` | The name is no longer delegated. A **candidate** for release, nothing stronger. |
| `RETURNED_TO_ZONE` | A previously absent name is back. |

Reserved for a later availability stage and never produced by the zone diff: `AVAILABLE`,
`REGISTERED_NOT_DELEGATED`, `UNKNOWN`. See [Availability](#availability).

## Install

Requires **Python 3.11+**.

```bash
pip install -e .
cp .env.example .env          # secrets and operational settings
cp rules.example.yaml rules.yaml
domain-monitor init           # create the database, validate config
```

## Configure

Two files, split on a deliberate line:

- **`.env`** — secrets (TSIG keys, SMTP password) and operational settings. Never committed.
- **`rules.yaml`** — the rules. Tracked in git, because a rule change should be a readable diff.

Rules do not live in `.env`. Regexes are made of exactly the characters dotenv parsing and
`set -a` sourcing mangle — `$`, `#`, quotes, backslashes — and a rule is configuration, not
a secret.

```yaml
rules:
  - name: "Brand impersonation"
    description: "Domain resembling the Example corporate brand, including digit substitutions"
    regex: '(?i)examp[l1]e'
    events: [ADDED_TO_ZONE]
```

Every rule needs a name, a description and a regex, because every alert quotes all three.
An alert that cannot explain why it fired is noise. Patterns are matched against the
**normalised** name: lowercase, punycode — an umlaut domain reaches your regex as `xn--…`.

```bash
domain-monitor rules          # list rules and validate every regex
```

## Use

```bash
domain-monitor run                    # the cron entry point
domain-monitor run --dry-run          # change nothing, send nothing, print what would fire
domain-monitor run --tld ch           # one TLD
domain-monitor run --no-email
domain-monitor run --force-transfer   # ignore the 24h interval

domain-monitor rules --backfill       # evaluate rules against every in-zone domain
domain-monitor status                 # counts, last transfers, recent runs
domain-monitor test-email
```

### Cron

```cron
17 3 * * *  cd /opt/domain-monitor && /opt/domain-monitor/.venv/bin/domain-monitor run \
            >> /var/log/domain-monitor.log 2>&1
```

Daily, because Switch asks that the zone be downloaded **no more than once every 24 hours**.
That limit is enforced in code, not just documented: a run inside the window reuses stored
state and exits `SKIPPED` rather than re-transferring. Running cron more often is therefore
harmless, just pointless. A non-round minute avoids contention with jobs scheduled on the hour.

Concurrent runs are prevented by a file lock (`LOCK_PATH`). A second invocation exits
quietly rather than queueing — a queued run would just re-transfer a zone the running
instance is already transferring.

## Safety: a failed transfer is not a mass deletion

This is the property the system exists to guarantee. `.ch` is ~2.6M names; reading a broken
transfer as "every domain was removed" would produce millions of bogus events, a corrupted
event log and a mail-flood — and it would look like a real incident rather than a bug.

Nothing reaches the diff stage until the transfer passes three gates:

1. **completed** — the transfer finished, not merely "did not raise";
2. **non-empty** — at least one name;
3. **plausible** — within `ZONE_MIN_RATIO` (default 0.5) of the previous successful transfer.

The third gate is the one that matters most. An empty transfer is obvious; a transfer that
returns 40% of the zone looks like a real answer. On any failure the run is recorded
`FAILED` with its reason, **no** domain state changes, and a failure email goes out — a
monitor that goes quiet because it is broken looks exactly like one with nothing to report.

The `--tld` flag is scoped the same way: running only `.ch` does not treat every `.li`
domain as having vanished.

## Data model

```
Domain -> DomainEvent -> RuleMatch -> Alert
   observation      interpretation     notification
```

Events are immutable facts. `Domain.currently_in_zone` is a convenience projection of the
latest event, not the source of truth.

That asymmetry is why this project carries Alembic migrations rather than just recreating
the schema: **the `domains` table is disposable** — one zone transfer rebuilds it — but the
**event log cannot be reconstructed from anything**. It is the historical record.

Timestamps are stored UTC and rendered in `TIMEZONE` only at display time.

SQLite by default; `DATABASE_URL` switches to PostgreSQL with no code changes.

## Performance

- One bulk zone transfer, never per-domain queries.
- The transfer is **streamed** into a staging table (`dns.query.xfr` message by message,
  not `dns.zone.from_xfr`, which materialises the whole zone). Peak memory is the insert
  batch, not the zone.
- The **diff is computed in SQL**. Two 2.6M-name Python sets cost ~600 MB; SQL keeps the
  working set bounded and behaves the same on SQLite and PostgreSQL.
- **Rules evaluate against events, not the namespace.** A run that sees 120 changes tests
  120 names, whatever the zone size. Rule processing is irrelevant to runtime.
- One aggregated email per run. `.ch` sees on the order of a hundred removals a day.

## Backfill

Rules normally see only events, which means a rule added today never notices the
impersonating domain registered last month. `domain-monitor rules --backfill` evaluates
rules against every domain **currently in the zone**.

Backfill matches are stored with `domain_event_id = NULL`: a match against present state is
not an observed change, and minting synthetic events for it would put things in the event
log that never happened.

Two consequences worth knowing:

- Backfill **ignores event-type scoping**, because there is no event to scope against. A
  rule written for `REMOVED_FROM_ZONE` will match in-zone domains during a backfill.
- Run it after adding a rule, not on a schedule. It scans the whole zone.

## Availability

Not implemented, on purpose. `availability.py` defines the `AvailabilityChecker` interface
and nothing else.

Shipping a checker before the monitoring core is solid would invite exactly the conflation
the event names exist to prevent. When one is added it should run only on domains that
already matter — a `REMOVED_FROM_ZONE` event that matched a rule — rather than on every
disappearance, and be rate limited against the registry.

A working RDAP checker for `.ch`/`.li` exists elsewhere in this repository
(`src/wiederfrei/rdap.py`), verified against the live registry: `HEAD` on
`rdap.nic.ch/domain/<name>` returns `200` for registered and `404` for available, and the
response **body is redacted** for anonymous callers — `events` and `nameservers` come back
empty even for a delegated domain — so only the status code carries information.

## Zone data terms

Switch publishes the `.ch`/`.li` zones as open data, restricted to *"combating cybercrime,
scientific and social research or for other purposes in the public interest"*, and asks for
at most one transfer per 24h. Request a TSIG key at <https://www.switch.ch/open-data/>.

Brand-protection and phishing detection sit comfortably inside those purposes. Domain
speculation does not. Whether your use qualifies is your call.

## Development

```bash
pip install -e '.[dev]'
pytest
```

The suite is fully offline. A real AXFR cannot be exercised in CI — it needs a TSIG key and
unrestricted egress — so the pipeline is tested through injected zone contents and the
file source (`CH_ZONE_FILE`), and the AXFR path is unit-tested separately. **The first real
transfer should be run manually with `--dry-run` first.**

`tests/test_safety.py` is the file to read first: it is the mass-removal regression suite,
covering transfer failure, empty zone and plausible-but-partial zone, each asserting zero
state change.

Migrations:

```bash
alembic upgrade head
alembic revision --autogenerate -m "description"
```

## Licence

Apache 2.0.

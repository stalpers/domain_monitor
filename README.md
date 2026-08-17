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

## Malicious-name detection

A second rule type, `type: typosquat`, checks each name against a curated brand watchlist
for homoglyphs, typos, keyboard-adjacent substitutions, bit-flips, combosquats and
hyphenation:

```yaml
rules:
  - name: "Brand watchlist"
    description: "Typosquat, homoglyph or combosquat of a protected brand"
    type: typosquat
    brands: [example, postfinance, migros]
    max_distance: 1
    events: [ADDED_TO_ZONE, RETURNED_TO_ZONE]
```

### Why this is a watchlist, not a classifier

Every method-level model in the literature this was built against — n-gram/entropy
features, a Transformer+CNN reporting 95.8% accuracy — is evaluated on a **balanced**
benchmark. A real zone is not balanced. At roughly 1,000 new `.ch` delegations a day and a
generous ~1% actually malicious, a 95.8%-accurate classifier (~4% false-positive rate)
produces about 40 false alerts for every 10 true ones — **~20% precision**, worse at a
more realistic 0.1% base rate. A classifier that looks excellent in a paper produces an
unreadable alert stream against a real namespace.

So precision, not accuracy, is what this is built around, in order of how specific (and
therefore how precise) each technique is:

1. **Homoglyph skeleton matching** — confusable characters (`0→o`, `rn→m`, Cyrillic
   `а→a`, …) are folded to a canonical form, so a squat becomes an exact-match lookup
   instead of a distance computation. Catches `examp1e`, `exarnple`, and Cyrillic
   homographs (`ехаmple`) in one mechanism, including when the pipeline has already
   normalised the name to punycode — the check decodes back to Unicode first.
2. **Bit-flip matching** — a single-bit error in one character, precomputed per brand
   into a lookup set. Exploits memory/transmission errors rather than perception, so
   unlike the other methods the variant can look nothing like the brand.
3. **Combosquat** — the brand touching a hyphen or a credential/payment-specific keyword
   (`login`, `verify`, `account`, …). Deliberately **not** a bare substring match: a
   watchlist entry for `coop` must not fire on `cooperative.ch`. Generic business
   vocabulary (`service`, `support`, `portal`) was tried in testing and dropped — it
   collides with ordinary Swiss company naming often enough to defeat the point of the
   gate.
4. **Bounded edit-distance and keyboard-adjacency** — omission, insertion, transposition,
   repetition, replacement, and (checked against **QWERTZ** — the Swiss layout — as well
   as QWERTY and AZERTY) single-key slips.

**Short brands need a different bar.** `ubs`, `sbb`, `coop`, `ptt` — common for Swiss
institutions — sit at edit-distance 1 from ordinary words (`ubs`/`usb`/`ups`/`pubs`), and
a bare hyphen next to them is nearly meaningless (`chicken-coop.ch`). Brands shorter than
`min_length_for_distance` (default 5) skip edit-distance, keyboard and bare-hyphen
matching entirely; they still get homoglyph, bit-flip, and keyword-gated combosquat,
which stay precise regardless of length. This was found empirically, not designed in
advance — `tests/test_typosquat.py::TestFalsePositiveCorpus` is the regression test for
it, checked against ~50 plausible Swiss business names with a **zero-match** bar.

**Lexical/randomness scoring never fires an alert on its own.** Every match is enriched
with a 0–1 "how DGA-like is this" score (entropy, consonant runs, vowel ratio, and — once
trained — likelihood against an n-gram model of the zone itself), shown in every alert for
triage, and used to order results by score. But `Assessment.fires` in `scoring.py` is
defined purely in terms of watchlist signals: a maximally random-looking name with no
watchlist hit produces no alert, ever. This is the enforcement point for the whole
precision argument above, and it's covered end-to-end in
`tests/test_security_rules.py::TestPostureEndToEnd`, not just unit-tested in isolation.

### The n-gram baseline is trained on your own zone

`domain-monitor model build` trains a character-trigram model from the domains **already
in your zone**, rather than a generic "benign domains" list. It needs no download, it
matches the actual population being scored (Swiss naming conventions, the DE/FR/IT mix),
and at millions of names it dwarfs any public benign-domain dataset — malicious names are
far too rare to meaningfully bias what "normal" looks like.

```bash
domain-monitor model build           # train from the current zone, all monitored TLDs
domain-monitor model show            # inspect what's trained
```

Run this once you have a real zone; scoring degrades gracefully with no model (a 0.5,
"neutral", likelihood) rather than blocking on it.

### Tools

```bash
domain-monitor analyse examp1e.ch                    # full signal breakdown for one name
domain-monitor analyse suspicious --brands acme,corp  # against an ad-hoc list, no config needed
domain-monitor run --export-features out.csv          # feature CSV for every event this run saw
```

`analyse` is the "why did/didn't this fire" tool — use it to tune a watchlist before
deploying it, and to see exactly what a rule would have done to a name without waiting
for it to actually appear in the zone.

`--export-features` writes a lexical-feature row (length, entropy, digit/vowel ratios,
consonant runs, IDN flag) plus a weak `watchlist_fired` label for **every** event a run
evaluates, not only the ones that matched. This is deliberately the seam for a future
classifier: rather than build one now against data nobody has, this grows a labelled
dataset from your own traffic that a model could later be trained on — see the module
docstring in `scoring.py` for why a classifier isn't in scope yet.

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

domain-monitor analyse <name>         # score one name; see "Malicious-name detection"
domain-monitor model build            # train the n-gram baseline from the zone
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

Concurrent runs are prevented by a file lock (`LOCK_PATH`, defaulting to the system temp
directory). A second invocation exits quietly rather than queueing — a queued run would
just re-transfer a zone the running instance is already transferring.

Runs on Windows as well as POSIX — the lock uses `msvcrt.locking` there instead of
`fcntl.flock`, same non-blocking-acquire contract either way (`domain_monitor/locking.py`).

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

`RuleMatch` rows carry `method` and `brand` (null for a plain regex match) plus `score`
and a JSON `signals` breakdown for typosquat hits — one row per **method** that fired, so
a name matching both `homoglyph` and `combosquat` against the same brand produces two
attributed rows, not one row that has to explain two things at once.

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

A working RDAP checker for `.ch`/`.li` already exists in a sibling project,
[stalpers/check_wiederfrei](https://github.com/stalpers/check_wiederfrei)
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

Three files to read first, for the properties this project is actually built around:

- `tests/test_safety.py` — the mass-removal regression suite. Transfer failure, empty
  zone, plausible-but-partial zone, each asserting zero state change.
- `tests/test_zones.py` — the zone-file parsing regression suite. `*_ZONE_FILE` accepts
  either a plain one-name-per-line list or a real BIND zone dump (auto-detected per
  line); only `NS` owners are ever staged as names, and a last-line-of-defence check
  rejects anything that doesn't look like a domain name before it reaches the database,
  regardless of backend.
- `tests/test_typosquat.py::TestFalsePositiveCorpus` — the precision regression suite.
  A curated brand list checked against ~50 plausible benign Swiss domain names, zero
  matches required.

Migrations:

```bash
alembic upgrade head
alembic revision --autogenerate -m "description"
```

## Licence

Apache 2.0.

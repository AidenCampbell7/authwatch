# authwatch

![tests](https://github.com/AidenCampbell7/authwatch/actions/workflows/tests.yml/badge.svg)

Parses SSH authentication logs, detects suspicious login activity, stores findings
in SQLite, and serves them over a REST API and a small dashboard.

Built to answer a practical question: given a raw `auth.log`, what in it is worth
a human's attention?

```
$ python -m authwatch ingest data/auth.log
Parsed  83 events from data/auth.log
Stored  83 new events, 5 new alerts

[HIGH  ] 2026-03-10T02:15:45  brute_force         10 failed logins for 'root' from 203.0.113.42 within 10 minutes
[HIGH  ] 2026-03-10T04:38:42  password_spray      198.51.100.7 attempted 5 distinct accounts within 30 minutes
[MEDIUM] 2026-03-10T03:12:00  off_hours_success   Successful password login for 'deploy' from 192.168.1.50 at 03:12
[MEDIUM] 2026-03-10T21:06:00  off_hours_success   Successful publickey login for 'aiden' from 45.77.201.9 at 21:06
[MEDIUM] 2026-03-10T21:06:00  new_ip_success      First successful login for 'aiden' from previously unseen IP 45.77.201.9
```

## Quick start

```bash
git clone <your-repo-url> && cd authwatch
pip install -r requirements.txt

python -m authwatch.generate_sample_log > data/auth.log   # synthetic log with known attacks
python -m authwatch ingest data/auth.log                  # parse, detect, store
python -m authwatch alerts --severity high                # query what was found
python -m authwatch serve                                 # dashboard at http://127.0.0.1:8000
```

Point it at a real log instead:

```bash
sudo python -m authwatch ingest /var/log/auth.log --year 2026
```

## Architecture

```
auth.log ──▶ parser.py ──▶ [AuthEvent] ──▶ detections.py ──▶ [Alert] ──▶ store.py ──▶ SQLite
                                                                             │
                                                              api.py ────────┤
                                                              cli.py ────────┘
```

Four modules, one job each:

| Module | Responsibility |
|---|---|
| `parser.py` | The only code that knows log line formats. Emits normalized `AuthEvent` records. |
| `detections.py` | Pure functions: events in, alerts out. No I/O, no printing, no database. |
| `store.py` | SQLite persistence and queries. |
| `api.py` / `cli.py` | Two thin interfaces over the same store. |

The separation is deliberate. Detection rules being pure functions means each one
is unit-testable without a database or a log file — which is why there are 36 tests
that run in a tenth of a second. Supporting a new log source (Windows Event Log,
Cloud​Trail) means writing a new parser, not touching the rules.

## Detection rules

**`brute_force`** (high) — one IP, one account, N failures inside a sliding window.
Implemented with a deque per `(ip, user)` pair: push each failure, pop from the left
while the oldest entry falls outside the window. Each event is pushed and popped at
most once, so the pass is O(n) rather than the O(n²) of rescanning a window per event.
Fires once per pair, not once per attempt past the threshold.

**`password_spray`** (high) — one IP, many *distinct* accounts, few attempts each.
This is the inverse shape of brute force and it is why a raw failure-count threshold
is not enough: an attacker who tries two passwords against eighty accounts never
trips a per-account counter. Tracked by counting distinct usernames in the window.

**`off_hours_success`** (medium) — a *successful* login outside business hours.
Deliberately medium. On its own this is weak signal; engineers deploy at night.
It earns its place by correlating with other alerts — in the sample output above,
the 21:06 login trips both this and `new_ip_success`, and that pair is the finding.

**`new_ip_success`** (medium) — first successful auth from an IP with no prior
success history. Two details make this rule usable rather than noisy:

1. The baseline is built in timestamp order, so an IP is "known" only from *earlier*
   events. Building it from the whole file first means every IP looks known and the
   rule silently never fires.
2. Events inside a warm-up period (default 12h) build the baseline without alerting.
   Without this, every IP in the file is new on the first run and the rule buries
   the real finding in false positives. This was a real bug during development —
   the sample log produced three false positives on office IPs before the warm-up
   window was added.

Thresholds are in `detections.Config` and overridable per run:

```bash
python -m authwatch ingest data/auth.log --brute-force-threshold 20 --window-minutes 5
```

## API

| Endpoint | Description |
|---|---|
| `GET /api/alerts?severity=high&limit=50` | Stored alerts, newest first |
| `GET /api/stats` | Event counts, alerts by severity, top failure sources |
| `GET /api/health` | Liveness check |
| `GET /` | Dashboard |

Interactive API docs at `/docs` (FastAPI generates them from the type hints).

## Design decisions

**SQLite over Postgres.** The tool should run anywhere with no setup — clone and go.
Queries are plain SQL with no SQLite-specific syntax, so moving to Postgres is a
connection string and a driver rather than a rewrite.

**Idempotent ingestion.** A `UNIQUE` constraint plus `INSERT OR IGNORE` means
re-running against the same file inserts nothing the second time. Logs get rotated
and re-read; double-counting events would corrupt every threshold in the system.

**Alerts stored, not just printed.** Storing findings makes them queryable after the
fact and lets the API and CLI share one source of truth.

## Testing

```bash
python -m pytest tests/ -v
```

36 tests. The interesting ones are the negative cases — verifying that rules stay
*quiet* when they should:

- failures spread beyond the window do not trip brute force
- failures split across two accounts or two IPs do not combine into one alert
- 50 attempts against a single account do not register as a spray
- a failed 3am login does not trip the off-hours rule (that is brute force's job)
- every IP in the warm-up window is suppressed

A detection rule that fires on everything is as useless as one that never fires,
and false-positive behavior is where these rules actually break.

## Known limitations

- The IP baseline lives in one file rather than persisting across runs. `store.py`
  is positioned to hold it; that is the next change.
- Single log source (OpenSSH syslog format). The parser boundary is where a second
  source would plug in.
- Rules are independent. A correlation layer — brute force followed by success from
  the same IP — would be higher-signal than any single rule.
- No alert suppression or tuning workflow, so a noisy rule stays noisy.

## Layout

```
authwatch/
├── authwatch/
│   ├── parser.py              # log lines -> AuthEvent
│   ├── detections.py          # rules: events -> alerts
│   ├── store.py               # SQLite persistence
│   ├── api.py                 # FastAPI service
│   ├── cli.py                 # command line interface
│   └── generate_sample_log.py # synthetic log with known attacks
├── dashboard/index.html
├── tests/
└── data/
```

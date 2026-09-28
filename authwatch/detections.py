"""
Detection rules.

Each rule is a function that takes the full event list plus a config and
returns zero or more Alerts. Rules are pure - they read events and return
findings, they never write to storage or print. That keeps them trivial
to unit test and means adding a rule is a self-contained change.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Sequence

from .parser import AuthEvent

Severity = str  # "low" | "medium" | "high"


@dataclass(frozen=True)
class Alert:
    rule: str
    severity: Severity
    timestamp: datetime          # when the behaviour concluded
    source_ip: str
    summary: str
    detail: dict = field(default_factory=dict)

    def as_row(self) -> tuple:
        import json
        return (self.rule, self.severity, self.timestamp.isoformat(),
                self.source_ip, self.summary, json.dumps(self.detail, default=str))


@dataclass
class Config:
    # brute force: this many failures against one account from one IP inside the window
    brute_force_threshold: int = 10
    brute_force_window: timedelta = timedelta(minutes=10)

    # password spray: one IP touching this many distinct accounts inside the window
    spray_distinct_users: int = 5
    spray_window: timedelta = timedelta(minutes=30)

    # off hours: successful logins outside [start, end) local time are suspicious
    business_start_hour: int = 7
    business_end_hour: int = 20

    # new IP: an IP is "known" once it has this many successes before the one being judged
    baseline_min_successes: int = 1

    # new IP: events in the first `baseline_period` of the log only BUILD the
    # baseline, they never raise alerts. Without this every IP looks new on the
    # first run and the rule drowns in false positives.
    baseline_period: timedelta = timedelta(hours=12)


# --------------------------------------------------------------------------
# Rule 1 - brute force
# --------------------------------------------------------------------------
def detect_brute_force(events: Sequence[AuthEvent], cfg: Config) -> list[Alert]:
    """
    Fire when a single (source_ip, user) pair accumulates `threshold` failed
    attempts inside a sliding time window.

    Sliding window via deque: push each failure, pop from the left while the
    oldest entry is older than `window`. Window length is then len(deque).
    O(n) overall - each event is pushed and popped at most once.
    """
    alerts: list[Alert] = []
    windows: dict[tuple[str, str], deque[datetime]] = defaultdict(deque)
    already_fired: set[tuple[str, str]] = set()

    for ev in events:
        if not ev.failed:
            continue
        key = (ev.source_ip, ev.user)
        window = windows[key]
        window.append(ev.timestamp)

        while window and ev.timestamp - window[0] > cfg.brute_force_window:
            window.popleft()

        if len(window) >= cfg.brute_force_threshold and key not in already_fired:
            already_fired.add(key)      # one alert per pair, not one per attempt
            alerts.append(Alert(
                rule="brute_force",
                severity="high",
                timestamp=ev.timestamp,
                source_ip=ev.source_ip,
                summary=(f"{len(window)} failed logins for '{ev.user}' from {ev.source_ip} "
                         f"within {int(cfg.brute_force_window.total_seconds() // 60)} minutes"),
                detail={"user": ev.user,
                        "failures_in_window": len(window),
                        "first_seen": window[0],
                        "last_seen": ev.timestamp},
            ))
    return alerts


# --------------------------------------------------------------------------
# Rule 2 - password spray
# --------------------------------------------------------------------------
def detect_password_spray(events: Sequence[AuthEvent], cfg: Config) -> list[Alert]:
    """
    Fire when one IP fails against many DISTINCT accounts in a window.

    This is the inverse shape of brute force: few attempts per account, many
    accounts. A threshold on raw failure count would miss it, which is exactly
    why attackers use it.
    """
    alerts: list[Alert] = []
    per_ip: dict[str, deque[tuple[datetime, str]]] = defaultdict(deque)
    already_fired: set[str] = set()

    for ev in events:
        if not ev.failed:
            continue
        window = per_ip[ev.source_ip]
        window.append((ev.timestamp, ev.user))

        while window and ev.timestamp - window[0][0] > cfg.spray_window:
            window.popleft()

        distinct = {user for _, user in window}
        if len(distinct) >= cfg.spray_distinct_users and ev.source_ip not in already_fired:
            already_fired.add(ev.source_ip)
            alerts.append(Alert(
                rule="password_spray",
                severity="high",
                timestamp=ev.timestamp,
                source_ip=ev.source_ip,
                summary=(f"{ev.source_ip} attempted {len(distinct)} distinct accounts "
                         f"within {int(cfg.spray_window.total_seconds() // 60)} minutes"),
                detail={"accounts": sorted(distinct), "attempts_in_window": len(window)},
            ))
    return alerts


# --------------------------------------------------------------------------
# Rule 3 - off-hours success
# --------------------------------------------------------------------------
def detect_off_hours_success(events: Sequence[AuthEvent], cfg: Config) -> list[Alert]:
    """
    Fire on a SUCCESSFUL login outside business hours.

    Deliberately medium severity, not high. On its own this is weak signal -
    engineers deploy at night. It earns its place by correlating with other
    alerts, not by standing alone.
    """
    alerts: list[Alert] = []
    for ev in events:
        if not ev.success:
            continue
        hour = ev.timestamp.hour
        if cfg.business_start_hour <= hour < cfg.business_end_hour:
            continue
        alerts.append(Alert(
            rule="off_hours_success",
            severity="medium",
            timestamp=ev.timestamp,
            source_ip=ev.source_ip,
            summary=(f"Successful {ev.method} login for '{ev.user}' from {ev.source_ip} "
                     f"at {ev.timestamp.strftime('%H:%M')}"),
            detail={"user": ev.user, "hour": hour, "method": ev.method},
        ))
    return alerts


# --------------------------------------------------------------------------
# Rule 4 - first success from a new IP
# --------------------------------------------------------------------------
def detect_new_ip_success(events: Sequence[AuthEvent], cfg: Config) -> list[Alert]:
    """
    Fire the first time an account authenticates successfully from an IP that
    has no prior successful history.

    Two things make this rule behave:

    1. Baseline is built in timestamp order, so an IP counts as known only from
       PRIOR events, never from later ones. Getting that backwards is the classic
       way this rule silently stops working.

    2. Events inside `baseline_period` (measured from the first event) only build
       the baseline - they cannot raise alerts. Otherwise every IP in the file
       looks new on the first run and the rule is useless.

    The honest limitation: the baseline lives in this one file. A production
    version would persist known IPs across runs, which is what `store.py` is
    positioned to do next.
    """
    alerts: list[Alert] = []
    successes_per_ip: dict[str, int] = defaultdict(int)

    if not events:
        return alerts
    baseline_ends = events[0].timestamp + cfg.baseline_period

    for ev in events:
        if not ev.success:
            continue
        seen_before = successes_per_ip[ev.source_ip]
        successes_per_ip[ev.source_ip] += 1

        if ev.timestamp < baseline_ends:
            continue                      # warm-up: learn, do not alert
        if seen_before >= cfg.baseline_min_successes:
            continue
        alerts.append(Alert(
            rule="new_ip_success",
            severity="medium",
            timestamp=ev.timestamp,
            source_ip=ev.source_ip,
            summary=f"First successful login for '{ev.user}' from previously unseen IP {ev.source_ip}",
            detail={"user": ev.user, "method": ev.method},
        ))
    return alerts


RULES: list[Callable[[Sequence[AuthEvent], Config], list[Alert]]] = [
    detect_brute_force,
    detect_password_spray,
    detect_off_hours_success,
    detect_new_ip_success,
]


def run_all(events: Sequence[AuthEvent], cfg: Config | None = None) -> list[Alert]:
    """Run every rule and return alerts sorted by time."""
    cfg = cfg or Config()
    alerts: list[Alert] = []
    for rule in RULES:
        alerts.extend(rule(events, cfg))
    alerts.sort(key=lambda a: a.timestamp)
    return alerts

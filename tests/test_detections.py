from datetime import datetime, timedelta

from authwatch.detections import (
    Config,
    detect_brute_force,
    detect_new_ip_success,
    detect_off_hours_success,
    detect_password_spray,
    run_all,
)
from authwatch.parser import AuthEvent

BASE = datetime(2026, 3, 10, 12, 0, 0)


def ev(offset_sec=0, user="root", ip="203.0.113.42", success=False, method="password"):
    """Build an AuthEvent with sensible defaults; offset is seconds from BASE."""
    return AuthEvent(
        timestamp=BASE + timedelta(seconds=offset_sec),
        host="h", pid=1, user=user, source_ip=ip, port=22,
        method=method, success=success, invalid_user=False,
    )


# ----------------------------- brute force -----------------------------

def test_brute_force_fires_at_threshold():
    cfg = Config(brute_force_threshold=5, brute_force_window=timedelta(minutes=10))
    events = [ev(i * 10) for i in range(5)]
    alerts = detect_brute_force(events, cfg)
    assert len(alerts) == 1
    assert alerts[0].rule == "brute_force"
    assert alerts[0].severity == "high"
    assert alerts[0].detail["failures_in_window"] == 5


def test_brute_force_silent_below_threshold():
    cfg = Config(brute_force_threshold=5)
    assert detect_brute_force([ev(i * 10) for i in range(4)], cfg) == []


def test_brute_force_respects_window():
    """5 failures spread over 50 minutes must NOT fire a 10-minute rule."""
    cfg = Config(brute_force_threshold=5, brute_force_window=timedelta(minutes=10))
    events = [ev(i * 600) for i in range(5)]     # one every 10 min
    assert detect_brute_force(events, cfg) == []


def test_brute_force_separates_users():
    """Failures split across two accounts should not combine into one alert."""
    cfg = Config(brute_force_threshold=5)
    events = [ev(i * 10, user="root") for i in range(4)] + \
             [ev(i * 10 + 5, user="admin") for i in range(4)]
    assert detect_brute_force(events, cfg) == []


def test_brute_force_separates_ips():
    cfg = Config(brute_force_threshold=5)
    events = [ev(i * 10, ip="1.1.1.1") for i in range(4)] + \
             [ev(i * 10 + 5, ip="2.2.2.2") for i in range(4)]
    assert detect_brute_force(events, cfg) == []


def test_brute_force_alerts_once_per_pair():
    """20 failures should produce one alert, not eleven."""
    cfg = Config(brute_force_threshold=5)
    alerts = detect_brute_force([ev(i * 10) for i in range(20)], cfg)
    assert len(alerts) == 1


def test_brute_force_ignores_successes():
    cfg = Config(brute_force_threshold=3)
    assert detect_brute_force([ev(i * 10, success=True) for i in range(10)], cfg) == []


# ---------------------------- password spray ----------------------------

def test_password_spray_fires_on_distinct_users():
    cfg = Config(spray_distinct_users=5, spray_window=timedelta(minutes=30))
    events = [ev(i * 60, user=f"user{i}") for i in range(5)]
    alerts = detect_password_spray(events, cfg)
    assert len(alerts) == 1
    assert len(alerts[0].detail["accounts"]) == 5


def test_password_spray_ignores_repeat_same_user():
    """50 hits on ONE account is brute force, not spray - spray must stay quiet."""
    cfg = Config(spray_distinct_users=5)
    assert detect_password_spray([ev(i * 10, user="root") for i in range(50)], cfg) == []


def test_password_spray_respects_window():
    cfg = Config(spray_distinct_users=5, spray_window=timedelta(minutes=30))
    events = [ev(i * 3600, user=f"user{i}") for i in range(5)]   # one per hour
    assert detect_password_spray(events, cfg) == []


# ---------------------------- off hours ----------------------------

def test_off_hours_fires_on_night_success():
    cfg = Config(business_start_hour=7, business_end_hour=20)
    e = AuthEvent(timestamp=datetime(2026, 3, 10, 3, 12), host="h", pid=1, user="deploy",
                  source_ip="10.0.0.1", port=22, method="password",
                  success=True, invalid_user=False)
    alerts = detect_off_hours_success([e], cfg)
    assert len(alerts) == 1
    assert alerts[0].severity == "medium"


def test_off_hours_quiet_during_business_hours():
    cfg = Config(business_start_hour=7, business_end_hour=20)
    e = AuthEvent(timestamp=datetime(2026, 3, 10, 14, 0), host="h", pid=1, user="deploy",
                  source_ip="10.0.0.1", port=22, method="password",
                  success=True, invalid_user=False)
    assert detect_off_hours_success([e], cfg) == []


def test_off_hours_ignores_failures():
    """A failed 3am login is the brute force rule's business, not this one."""
    cfg = Config()
    e = AuthEvent(timestamp=datetime(2026, 3, 10, 3, 0), host="h", pid=1, user="root",
                  source_ip="1.1.1.1", port=22, method="password",
                  success=False, invalid_user=False)
    assert detect_off_hours_success([e], cfg) == []


# ---------------------------- new IP ----------------------------

def make(ts, ip, user="aiden"):
    return AuthEvent(timestamp=ts, host="h", pid=1, user=user, source_ip=ip,
                     port=22, method="password", success=True, invalid_user=False)


def test_new_ip_fires_after_baseline_period():
    cfg = Config(baseline_period=timedelta(hours=1))
    start = datetime(2026, 3, 10, 0, 0)
    events = [
        make(start, "10.0.0.1"),                          # baseline window
        make(start + timedelta(hours=2), "45.77.201.9"),  # new IP, after baseline
    ]
    alerts = detect_new_ip_success(events, cfg)
    assert len(alerts) == 1
    assert alerts[0].source_ip == "45.77.201.9"


def test_new_ip_silent_during_baseline_period():
    """Everything looks new on first run - the warm-up window must suppress it."""
    cfg = Config(baseline_period=timedelta(hours=12))
    start = datetime(2026, 3, 10, 0, 0)
    events = [make(start + timedelta(minutes=i * 10), f"10.0.0.{i}") for i in range(5)]
    assert detect_new_ip_success(events, cfg) == []


def test_known_ip_does_not_alert():
    cfg = Config(baseline_period=timedelta(hours=1))
    start = datetime(2026, 3, 10, 0, 0)
    events = [
        make(start, "10.0.0.1"),                        # learned in baseline
        make(start + timedelta(hours=3), "10.0.0.1"),   # same IP later - known
    ]
    assert detect_new_ip_success(events, cfg) == []


def test_new_ip_handles_empty_input():
    assert detect_new_ip_success([], Config()) == []


# ---------------------------- integration ----------------------------

def test_run_all_returns_time_sorted_alerts():
    cfg = Config(brute_force_threshold=3, spray_distinct_users=3)
    events = [ev(i * 10, user="root") for i in range(5)]
    alerts = run_all(events, cfg)
    assert alerts == sorted(alerts, key=lambda a: a.timestamp)

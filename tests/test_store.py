from datetime import datetime

from authwatch.detections import Alert
from authwatch.parser import AuthEvent
from authwatch.store import Store


def sample_event(pid=1, ip="1.1.1.1"):
    return AuthEvent(timestamp=datetime(2026, 3, 10, 12, 0), host="h", pid=pid,
                     user="root", source_ip=ip, port=22, method="password",
                     success=False, invalid_user=False)


def sample_alert(ip="1.1.1.1"):
    return Alert(rule="brute_force", severity="high",
                 timestamp=datetime(2026, 3, 10, 12, 0), source_ip=ip,
                 summary="test alert", detail={"user": "root"})


def test_insert_and_read_back(tmp_path):
    store = Store(tmp_path / "t.db")
    assert store.insert_events([sample_event()]) == 1
    assert store.insert_alerts([sample_alert()]) == 1

    alerts = store.alerts()
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "brute_force"
    assert alerts[0]["detail"] == {"user": "root"}      # JSON round-trips to a dict


def test_ingest_is_idempotent(tmp_path):
    """Re-reading the same log must not double-count. Log rotation makes this real."""
    store = Store(tmp_path / "t.db")
    events = [sample_event()]
    assert store.insert_events(events) == 1
    assert store.insert_events(events) == 0
    assert store.stats()["total_events"] == 1


def test_alert_dedupe(tmp_path):
    store = Store(tmp_path / "t.db")
    assert store.insert_alerts([sample_alert()]) == 1
    assert store.insert_alerts([sample_alert()]) == 0


def test_severity_filter(tmp_path):
    store = Store(tmp_path / "t.db")
    store.insert_alerts([
        sample_alert(ip="1.1.1.1"),
        Alert(rule="off_hours_success", severity="medium",
              timestamp=datetime(2026, 3, 10, 3, 0), source_ip="2.2.2.2",
              summary="medium alert", detail={}),
    ])
    assert len(store.alerts(severity="high")) == 1
    assert len(store.alerts(severity="medium")) == 1
    assert len(store.alerts()) == 2


def test_stats_shape(tmp_path):
    store = Store(tmp_path / "t.db")
    store.insert_events([sample_event(pid=1), sample_event(pid=2, ip="9.9.9.9")])
    store.insert_alerts([sample_alert()])
    stats = store.stats()
    assert stats["total_events"] == 2
    assert stats["failed_events"] == 2
    assert stats["total_alerts"] == 1
    assert stats["alerts_by_severity"]["high"] == 1
    assert len(stats["top_failure_sources"]) == 2


def test_fresh_db_is_empty(tmp_path):
    store = Store(tmp_path / "new.db")
    assert store.alerts() == []
    assert store.stats()["total_events"] == 0

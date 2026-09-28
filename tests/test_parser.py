from datetime import datetime

import pytest

from authwatch.parser import parse_line, parse_lines


def test_parses_failed_password():
    ev = parse_line("Mar 10 06:52:12 webserver sshd[12345]: "
                    "Failed password for root from 203.0.113.42 port 54321 ssh2")
    assert ev is not None
    assert ev.timestamp == datetime(2026, 3, 10, 6, 52, 12)
    assert ev.host == "webserver"
    assert ev.pid == 12345
    assert ev.user == "root"
    assert ev.source_ip == "203.0.113.42"
    assert ev.port == 54321
    assert ev.method == "password"
    assert ev.success is False
    assert ev.failed is True
    assert ev.invalid_user is False


def test_parses_accepted_publickey():
    ev = parse_line("Mar 10 21:06:00 webserver sshd[999]: "
                    "Accepted publickey for aiden from 45.77.201.9 port 52210 ssh2")
    assert ev.success is True
    assert ev.method == "publickey"
    assert ev.user == "aiden"


def test_flags_invalid_user():
    ev = parse_line("Mar 10 04:30:00 host sshd[1]: "
                    "Failed password for invalid user oracle from 198.51.100.7 port 40000 ssh2")
    assert ev.invalid_user is True
    assert ev.user == "oracle"          # the word "invalid user" must not leak into the username


def test_single_digit_day_is_padded_in_syslog():
    ev = parse_line("Mar  3 01:02:03 host sshd[7]: "
                    "Failed password for root from 10.0.0.1 port 22 ssh2")
    assert ev.timestamp == datetime(2026, 3, 3, 1, 2, 3)


def test_year_is_supplied_by_caller():
    ev = parse_line("Jan  1 00:00:01 host sshd[7]: "
                    "Failed password for root from 10.0.0.1 port 22 ssh2", year=2024)
    assert ev.timestamp.year == 2024


@pytest.mark.parametrize("line", [
    "",
    "   ",
    "Mar 10 12:00:00 webserver sshd[1]: Received disconnect from 192.168.1.50: 11: disconnected",
    "Mar 10 12:01:00 webserver sshd[2]: pam_unix(sshd:session): session opened for user aiden",
    "Mar 10 12:02:00 webserver CRON[3]: (root) CMD (/usr/bin/backup)",
    "this is not a log line at all",
])
def test_non_auth_lines_return_none(line):
    assert parse_line(line) is None


def test_parse_lines_skips_noise_and_keeps_order():
    raw = [
        "Mar 10 01:00:00 h sshd[1]: Failed password for a from 1.1.1.1 port 1 ssh2",
        "garbage",
        "Mar 10 02:00:00 h sshd[2]: Accepted password for b from 2.2.2.2 port 2 ssh2",
    ]
    events = list(parse_lines(raw))
    assert len(events) == 2
    assert [e.user for e in events] == ["a", "b"]

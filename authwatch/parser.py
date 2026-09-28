"""
Parse SSH auth.log lines into structured AuthEvent records.

This is the only module that knows about log formatting. Everything
downstream works on AuthEvent objects, so supporting a new log source
means writing a new parser, not touching the detection rules.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Iterator, Optional

# "Mar 10 06:52:12 webserver sshd[12345]: <message>"
_SYSLOG = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"sshd\[(?P<pid>\d+)\]:\s+"
    r"(?P<message>.*)$"
)

# "Failed password for root from 1.2.3.4 port 5555 ssh2"
# "Failed password for invalid user admin from 1.2.3.4 port 5555 ssh2"
# "Accepted publickey for aiden from 1.2.3.4 port 5555 ssh2"
_AUTH = re.compile(
    r"^(?P<outcome>Failed|Accepted)\s+"
    r"(?P<method>password|publickey|keyboard-interactive(?:/pam)?)\s+for\s+"
    r"(?P<invalid>invalid user\s+)?"
    r"(?P<user>\S+)\s+from\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)"
)


@dataclass(frozen=True)
class AuthEvent:
    """One authentication attempt, normalized."""
    timestamp: datetime
    host: str
    pid: int
    user: str
    source_ip: str
    port: int
    method: str
    success: bool
    invalid_user: bool          # account does not exist on the host

    @property
    def failed(self) -> bool:
        return not self.success


class ParseError(ValueError):
    """Raised when a line looks like sshd output but cannot be parsed."""


def parse_line(raw: str, year: int = 2026) -> Optional[AuthEvent]:
    """
    Parse one log line.

    Returns None for lines that are not authentication attempts
    (session opens, disconnects, and anything that is not sshd).
    Syslog timestamps carry no year, so the caller supplies one.
    """
    raw = raw.rstrip("\n")
    if not raw.strip():
        return None

    head = _SYSLOG.match(raw)
    if head is None:
        return None                       # not an sshd line - ignore

    body = _AUTH.match(head.group("message"))
    if body is None:
        return None                       # sshd, but not an auth attempt

    stamp = datetime.strptime(
        f"{year} {head.group('month')} {head.group('day')} {head.group('time')}",
        "%Y %b %d %H:%M:%S",
    )

    return AuthEvent(
        timestamp=stamp,
        host=head.group("host"),
        pid=int(head.group("pid")),
        user=body.group("user"),
        source_ip=body.group("ip"),
        port=int(body.group("port")),
        method=body.group("method"),
        success=body.group("outcome") == "Accepted",
        invalid_user=body.group("invalid") is not None,
    )


def parse_lines(lines: Iterable[str], year: int = 2026) -> Iterator[AuthEvent]:
    """Parse an iterable of lines, skipping anything that is not an auth event."""
    for raw in lines:
        event = parse_line(raw, year=year)
        if event is not None:
            yield event


def parse_file(path: str, year: int = 2026) -> list[AuthEvent]:
    """Parse a log file into a list of events, ordered by timestamp."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        events = list(parse_lines(fh, year=year))
    events.sort(key=lambda e: e.timestamp)
    return events

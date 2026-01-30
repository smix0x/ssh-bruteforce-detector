"""
Brute force detection logic.

We track failed SSH login attempts per source IP within a time window.
If an IP exceeds the threshold (e.g. 5 failed attempts in 10 minutes),
we consider it malicious and trigger response (alert, then optionally block).

WHY this works:
- Legitimate users rarely fail 5+ times in 10 minutes.
- Attackers often try many passwords or usernames quickly.
- We avoid false positives by:
  - Using a reasonable threshold and window
  - Whitelisting trusted IPs
  - Only counting FAILED / INVALID_USER (not success)
"""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List

from . import config
from .log_parser import SSHEvent


@dataclass
class IPAttempts:
    """
    Tracks attempts for one IP: first seen, last seen, count.

    Used to decide if an IP has exceeded the threshold within the window.
    """

    first_seen: str   # timestamp string from log
    last_seen: str
    attempt_count: int
    usernames: List[str] = field(default_factory=list)  # for alert context


def _parse_timestamp(ts: str) -> datetime:
    """
    Parse log timestamp (e.g. "Jan 30 10:15:23") to datetime for comparison.

    We assume current year for simplicity. For production, use full log timestamp.
    """
    try:
        # Format: "Jan 30 10:15:23"
        return datetime.strptime(ts.strip(), "%b %d %H:%M:%S").replace(
            year=datetime.utcnow().year
        )
    except ValueError:
        return datetime.min


def _is_failed_result(result: str) -> bool:
    """Only failed and invalid_user count toward brute force; success does not."""
    return result in ("failed", "invalid_user")


def _is_in_window(first_ts: str, last_ts: str, window_seconds: int) -> bool:
    """True if (last_ts - first_ts) <= window_seconds."""
    first_dt = _parse_timestamp(first_ts)
    last_dt = _parse_timestamp(last_ts)
    delta = (last_dt - first_dt).total_seconds()
    return 0 <= delta <= window_seconds


def build_attempts_by_ip(events: List[SSHEvent]) -> Dict[str, IPAttempts]:
    """
    Group events by source IP and count only failed attempts.

    For each IP we store: first_seen, last_seen, attempt_count, usernames tried.
    """
    by_ip: Dict[str, IPAttempts] = {}
    for event in events:
        if not _is_failed_result(event.result):
            continue
        ip = event.source_ip
        if ip not in by_ip:
            by_ip[ip] = IPAttempts(
                first_seen=event.timestamp,
                last_seen=event.timestamp,
                attempt_count=0,
                usernames=[],
            )
        rec = by_ip[ip]
        rec.last_seen = event.timestamp
        rec.attempt_count += 1
        if event.username not in rec.usernames:
            rec.usernames.append(event.username)
    return by_ip


def find_malicious_ips(
    events: List[SSHEvent],
    threshold: int = None,
    window_seconds: int = None,
) -> List[tuple[str, IPAttempts]]:
    """
    Identify IPs that exceed the failed-attempt threshold within the time window.

    WHY an IP is considered malicious:
    - It has at least `threshold` failed SSH attempts (wrong password or invalid user).
    - All those attempts occurred within `window_seconds` (e.g. 10 minutes).
    - This pattern is typical of automated brute force, not a human typo.

    Returns list of (ip, IPAttempts) for IPs that exceeded the threshold.
    """
    threshold = threshold or config.FAILED_ATTEMPTS_THRESHOLD
    window_seconds = window_seconds or config.DETECTION_WINDOW_SECONDS

    by_ip = build_attempts_by_ip(events)
    malicious = []
    for ip, rec in by_ip.items():
        if rec.attempt_count < threshold:
            continue
        if not _is_in_window(rec.first_seen, rec.last_seen, window_seconds):
            # Attempts spread over more than window: might be different sessions.
            continue
        malicious.append((ip, rec))
    return malicious

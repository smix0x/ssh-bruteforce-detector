"""
SSH log parser for auth.log (Debian/Ubuntu) and secure (RHEL/CentOS).

We use REGEX to extract:
- Timestamp
- Source IP
- Username
- Authentication result (failed / invalid user / success)

We handle different log formats and avoid duplicate processing by
tracking the last byte offset read from each file.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

from . import config
from . import logger


@dataclass
class SSHEvent:
    """
    One parsed SSH-related log entry.

    Used by the detector to count failed attempts per IP.
    """

    timestamp: str
    source_ip: str
    username: str
    result: str  # "failed", "invalid_user", "success"
    raw_line: str


# ---------------------------------------------------------------------------
# REGEX PATTERNS
# ---------------------------------------------------------------------------
# Debian/Ubuntu auth.log examples:
#   Jan 30 10:15:23 hostname sshd[1234]: Failed password for invalid user root from 192.168.1.100 port 22 ssh2
#   Jan 30 10:15:24 hostname sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
#   Jan 30 10:15:25 hostname sshd[1234]: Accepted password for admin from 192.168.1.50 port 22 ssh2

# RHEL/CentOS secure examples:
#   Jan 30 10:15:23 hostname sshd[1234]: Failed password for invalid user root from 192.168.1.100 port 22 ssh2
#   Jan 30 10:15:24 hostname sshd[1234]: Accepted password for admin from 192.168.1.50 port 22 ssh2

# Common prefix: "Month Day HH:MM:SS hostname sshd[pid]: "
# We capture: timestamp (full), username (after "for" or "invalid user"), IP, and message type.

# Pattern for "Failed password for invalid user <username> from <ip>"
FAILED_INVALID_USER = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed password for invalid user (?P<username>\S+) from (?P<ip>\S+)",
    re.IGNORECASE,
)

# Pattern for "Failed password for <username> from <ip>" (valid user, wrong password)
FAILED_PASSWORD = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed password for (?P<username>\S+) from (?P<ip>\S+)",
    re.IGNORECASE,
)

# Pattern for successful login (we count these for context; detector may use to avoid FP)
ACCEPTED_PASSWORD = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Accepted password for (?P<username>\S+) from (?P<ip>\S+)",
    re.IGNORECASE,
)

# All patterns in order: we try invalid user first, then failed, then accepted.
PATTERNS = [
    (FAILED_INVALID_USER, "invalid_user"),
    (FAILED_PASSWORD, "failed"),
    (ACCEPTED_PASSWORD, "success"),
]


def _parse_line(line: str) -> Optional[SSHEvent]:
    """
    Parse one log line into an SSHEvent if it matches an SSH auth pattern.

    Returns None if the line is not an SSH auth event we care about.
    """
    line = line.strip()
    if not line or not line.lower().startswith(("jan ", "feb ", "mar ", "apr ", "may ", "jun ",
                                                 "jul ", "aug ", "sep ", "oct ", "nov ", "dec ")):
        return None

    for pattern, result in PATTERNS:
        match = pattern.search(line)
        if match:
            # Normalize timestamp: we keep the log format; for ordering we could parse to datetime.
            timestamp = match.group("timestamp").strip()
            username = match.group("username").strip()
            ip = match.group("ip").strip()
            # Remove port suffix if present (e.g. "192.168.1.1" from "192.168.1.1 port 22")
            if " port " in ip:
                ip = ip.split(" port ")[0].strip()
            return SSHEvent(
                timestamp=timestamp,
                source_ip=ip,
                username=username,
                result=result,
                raw_line=line,
            )
    return None


def _find_log_path() -> Optional[Path]:
    """
    Find the first existing log file: auth.log, secure, or sample_auth.log.

    On Linux we prefer real system logs; otherwise we use the project sample.
    """
    for path_str in config.LOG_PATHS:
        p = Path(path_str)
        if p.exists():
            return p
    if config.SAMPLE_LOG_PATH.exists():
        return config.SAMPLE_LOG_PATH
    return None


def _read_from_offset(path: Path, last_offset: int) -> tuple[list[str], int]:
    """
    Read new lines from path starting at last_offset.

    Returns (list of lines, new byte offset at end of file).
    Avoids re-processing: we only read bytes after last_offset.
    """
    new_lines = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(last_offset)
            new_lines = f.readlines()
            new_offset = f.tell()
        return new_lines, new_offset
    except (OSError, IOError) as e:
        logger.log_warn("Could not read log file", path=str(path), error=str(e))
        return [], last_offset


def parse_log(path: Optional[Path] = None, last_offset: int = 0) -> tuple[list[SSHEvent], int]:
    """
    Parse SSH events from the given log path (or auto-detected path).

    Args:
        path: Log file path. If None, we auto-detect (auth.log, secure, or sample).
        last_offset: Byte offset to start reading from (for deduplication).

    Returns:
        (list of SSHEvent, new_offset). new_offset should be saved for next run.
    """
    if path is None:
        path = _find_log_path()
    if path is None:
        logger.log_warn("No log file found", tried=config.LOG_PATHS + [str(config.SAMPLE_LOG_PATH)])
        return [], 0

    lines, new_offset = _read_from_offset(path, last_offset)
    events = []
    for line in lines:
        event = _parse_line(line)
        if event:
            events.append(event)
    return events, new_offset


def get_log_path_and_offset() -> tuple[Optional[Path], int]:
    """
    Get the log path to use and the last saved byte offset (for deduplication).

    We keep state in state/last_position.json: { "path": "...", "offset": N }.
    """
    path = _find_log_path()
    offset = 0
    if config.STATE_FILE.exists():
        try:
            import json
            with open(config.STATE_FILE, "r", encoding="utf-8") as f:
                state = json.load(f)
            saved_path = state.get("path")
            if saved_path and Path(saved_path) == path:
                offset = int(state.get("offset", 0))
        except (ValueError, OSError):
            pass
    return path, offset


def save_offset(path: Path, offset: int) -> None:
    """Save the last read offset for path so we avoid duplicate processing."""
    config.STATE_DIR.mkdir(parents=True, exist_ok=True)
    import json
    with open(config.STATE_FILE, "w", encoding="utf-8") as f:
        json.dump({"path": str(path), "offset": offset}, f, indent=2)

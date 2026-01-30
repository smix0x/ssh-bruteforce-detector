"""
Structured JSON logging for the SSH Brute Force Detector.

Why JSON? SOC/SIEM tools (Splunk, ELK, etc.) ingest JSON logs easily.
Each log line is a single JSON object for simple parsing and correlation.
"""

import json
import sys
from datetime import datetime
from pathlib import Path

# We write to stdout by default so the process can be piped or redirected.
# Alerts are also written to output/alerts.json separately (see main.py).
LOG_STREAM = sys.stdout


def _timestamp_iso() -> str:
    """Current time in ISO format for log entries."""
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def log_event(level: str, message: str, **kwargs) -> None:
    """
    Write a single log event as one line of JSON.

    Args:
        level: INFO, WARN, ERROR, etc.
        message: Human-readable description.
        **kwargs: Additional key-value pairs (e.g. ip, username, action).
    """
    event = {
        "timestamp": _timestamp_iso(),
        "level": level,
        "message": message,
        **kwargs,
    }
    line = json.dumps(event, default=str) + "\n"
    LOG_STREAM.write(line)
    LOG_STREAM.flush()


def log_info(message: str, **kwargs) -> None:
    """Convenience: log at INFO level."""
    log_event("INFO", message, **kwargs)


def log_warn(message: str, **kwargs) -> None:
    """Convenience: log at WARN level."""
    log_event("WARN", message, **kwargs)


def log_error(message: str, **kwargs) -> None:
    """Convenience: log at ERROR level."""
    log_event("ERROR", message, **kwargs)


def append_alert(alert: dict, alerts_file: Path) -> None:
    """
    Append one alert to the alerts file (SIEM-friendly).

    The file contains one JSON object per line (JSON Lines format).
    We open in append mode so multiple runs don't overwrite previous alerts.
    """
    alerts_file.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(alert, default=str) + "\n"
    with open(alerts_file, "a", encoding="utf-8") as f:
        f.write(line)

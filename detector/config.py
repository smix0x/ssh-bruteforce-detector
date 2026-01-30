"""
Central configuration for the SSH Brute Force Detector.

All tunable parameters live here so students can easily adjust
thresholds, paths, and response behavior without touching core logic.
"""

import os
from pathlib import Path

# ---------------------------------------------------------------------------
# DETECTION THRESHOLDS
# ---------------------------------------------------------------------------
# How many failed SSH attempts before we consider it a brute force attack?
FAILED_ATTEMPTS_THRESHOLD = 5

# Within what time window (seconds)? 10 minutes = 600 seconds.
# An IP that exceeds the threshold within this window is flagged.
DETECTION_WINDOW_SECONDS = 600

# ---------------------------------------------------------------------------
# LOG PATHS
# ---------------------------------------------------------------------------
# Where to read SSH logs from. We support both Debian/Ubuntu and RHEL/CentOS.
# On Windows / non-Linux, we use sample logs from the project.
LOG_PATHS = [
    "/var/log/auth.log",   # Debian, Ubuntu
    "/var/log/secure",     # RHEL, CentOS, Fedora
]

# Fallback: use project's sample log when running on non-Linux or for testing.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_LOG_PATH = PROJECT_ROOT / "logs" / "sample_auth.log"

# ---------------------------------------------------------------------------
# OUTPUT
# ---------------------------------------------------------------------------
OUTPUT_DIR = PROJECT_ROOT / "output"
ALERTS_FILE = OUTPUT_DIR / "alerts.json"

# ---------------------------------------------------------------------------
# RESPONSE STAGES
# ---------------------------------------------------------------------------
# Stage 1: Detection only (log + alert)  - always done
# Stage 2: Rate-limit (simulation)      - optional
# Stage 3: Firewall block               - optional, requires root on Linux

# If True, we NEVER run real firewall commands. Only log what we would do.
# Set to False only when you explicitly want to block IPs (e.g. production).
DRY_RUN = True

# How long to block an IP (seconds). 24 hours = 86400.
# After this, we would unblock (if auto-unblock is implemented).
BLOCK_DURATION_SECONDS = 86400

# ---------------------------------------------------------------------------
# WHITELIST / BLACKLIST
# ---------------------------------------------------------------------------
# File paths for trusted IPs (whitelist) and known bad IPs (blacklist).
# Whitelisted IPs are NEVER blocked, even if they exceed the threshold.
CONFIG_DIR = PROJECT_ROOT / "config"
WHITELIST_FILE = CONFIG_DIR / "whitelist.txt"
BLACKLIST_FILE = CONFIG_DIR / "blacklist.txt"

# Default whitelist entries if no file exists (localhost, common internal).
DEFAULT_WHITELIST_IPS = [
    "127.0.0.1",
    "::1",
    "192.168.0.0/16",   # Common internal range (we treat as prefix match)
    "10.0.0.0/8",
]

# ---------------------------------------------------------------------------
# LOG ROTATION / DEDUPLICATION
# ---------------------------------------------------------------------------
# We track the last byte offset we read from each log file to avoid
# re-processing the same lines after log rotation or restart.
STATE_DIR = PROJECT_ROOT / "state"
STATE_FILE = STATE_DIR / "last_position.json"

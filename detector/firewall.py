"""
Firewall response: block malicious IPs via iptables or ufw.

This module is ISOLATED so that:
- We can run in DRY-RUN mode (default) and never touch the firewall.
- Blocking logic is in one place for security review.
- Auto-unblock after a configurable time can be added here.

We support:
- Stage 2: Rate-limit (simulation only: log that we would rate-limit).
- Stage 3: Actual block (iptables or ufw) when DRY_RUN is False.
"""

import subprocess
import sys
from pathlib import Path

from . import config
from . import logger


def _is_linux() -> bool:
    """True if we are on Linux (where iptables/ufw exist)."""
    return sys.platform.startswith("linux")


def block_ip_iptables(ip: str) -> bool:
    """
    Block IP using iptables (insert rule to DROP input from ip).

    Returns True if the command succeeded. Requires root.
    """
    if not _is_linux():
        logger.log_warn("iptables not available (not Linux)", ip=ip)
        return False
    try:
        # Insert at head: -I INPUT 1 -s <ip> -j DROP
        subprocess.run(
            ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"],
            check=True,
            capture_output=True,
            timeout=10,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.log_error("iptables block failed", ip=ip, error=str(e))
        return False


def block_ip_ufw(ip: str) -> bool:
    """
    Block IP using ufw: ufw deny from <ip>.

    Returns True if the command succeeded. Requires root.
    """
    if not _is_linux():
        logger.log_warn("ufw not available (not Linux)", ip=ip)
        return False
    try:
        subprocess.run(
            ["ufw", "deny", "from", ip],
            check=True,
            capture_output=True,
            timeout=10,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.log_error("ufw block failed", ip=ip, error=str(e))
        return False


def block_ip(ip: str, dry_run: bool = None) -> bool:
    """
    Block an IP: use iptables if available, else ufw.

    If dry_run is True (default from config), we only LOG what we would do
    and do not run any firewall command.
    """
    dry_run = dry_run if dry_run is not None else config.DRY_RUN
    if dry_run:
        logger.log_info(
            "[DRY-RUN] Would block IP (firewall not modified)",
            ip=ip,
            action="block_simulated",
        )
        return True

    # Prefer iptables; fallback to ufw
    if _is_linux():
        try:
            subprocess.run(["which", "iptables"], capture_output=True, check=True, timeout=2)
            return block_ip_iptables(ip)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        try:
            subprocess.run(["which", "ufw"], capture_output=True, check=True, timeout=2)
            return block_ip_ufw(ip)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
    logger.log_warn("No firewall tool available; block not applied", ip=ip)
    return False


def rate_limit_simulate(ip: str) -> None:
    """
    Stage 2: Rate-limit simulation.

    We do not implement actual rate-limiting here (e.g. iptables rate limit);
    we only log that we would rate-limit. Real rate-limiting could use
    iptables -m limit or a dedicated daemon.
    """
    logger.log_info(
        "[SIMULATION] Would rate-limit IP",
        ip=ip,
        action="rate_limit_simulated",
    )

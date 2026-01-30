"""
Whitelist: trusted IPs that must NEVER be blocked.

SOC best practice: always whitelist localhost, internal networks,
and admin IPs to avoid locking yourself out or blocking legitimate traffic.
"""

from pathlib import Path
from typing import Set

from . import config


def _ip_in_cidr(ip: str, cidr: str) -> bool:
    """
    Check if IP is in CIDR (e.g. 192.168.1.5 in 192.168.0.0/16).

    Simplified: we support /8, /16, /24 and single IPs.
    For production you might use ipaddress module.
    """
    if "/" not in cidr:
        return ip == cidr.strip()
    try:
        network_part, prefix = cidr.strip().split("/")
        prefix = int(prefix)
        # Convert to 32-bit for IPv4
        def to_bits(addr):
            parts = addr.split(".")
            if len(parts) != 4:
                return None
            return sum(int(p) << (24 - i * 8) for i, p in enumerate(parts))
        ip_bits = to_bits(ip)
        net_bits = to_bits(network_part)
        if ip_bits is None or net_bits is None:
            return False
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        return (ip_bits & mask) == (net_bits & mask)
    except (ValueError, TypeError):
        return False


def load_whitelist(path: Path) -> Set[str]:
    """
    Load whitelist from file: one IP or CIDR per line.

    Returns set of entries (IPs and CIDRs). Empty lines and # comments ignored.
    """
    entries = set()
    if not path.exists():
        return set(config.DEFAULT_WHITELIST_IPS)
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    entries.add(line)
    except OSError:
        pass
    return entries or set(config.DEFAULT_WHITELIST_IPS)


def is_whitelisted(ip: str, whitelist: Set[str]) -> bool:
    """
    Return True if IP is whitelisted (exact match or in CIDR).

    Never block whitelisted IPs.
    """
    for entry in whitelist:
        if "/" in entry:
            if _ip_in_cidr(ip, entry):
                return True
        else:
            if ip == entry.strip():
                return True
    return False


def get_whitelist() -> Set[str]:
    """Load and return the configured whitelist."""
    config.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if config.WHITELIST_FILE.exists():
        return load_whitelist(config.WHITELIST_FILE)
    return set(config.DEFAULT_WHITELIST_IPS)

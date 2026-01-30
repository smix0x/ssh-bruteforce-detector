"""
SSH Brute Force Detector - Blue Team / SOC Educational Project

This package provides:
- log_parser: Parse SSH auth logs (auth.log / secure)
- detector: Detect brute force attempts by IP
- firewall: Block malicious IPs (iptables/ufw)
- whitelist: Trusted IPs (never block)
- logger: JSON logging for SIEM
- config: Central configuration
"""

__version__ = "1.0.0"

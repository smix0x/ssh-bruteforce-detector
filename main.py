"""
SSH Brute Force Detector - Entry point.

Orchestrates:
1. Parse SSH logs (auth.log / secure / sample_auth.log)
2. Detect brute force: IPs that exceed failed-attempt threshold in time window
3. Multi-stage response:
   - Stage 1: Log + alert (always)
   - Stage 2: Rate-limit (simulation)
   - Stage 3: Firewall block (when not in DRY-RUN)

Whitelisted IPs are never blocked. Alerts are written to output/alerts.json.
"""

import sys
from pathlib import Path

# Add project root so we can run: python main.py
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from detector import config
from detector import logger
from detector import detector
from detector import firewall
from detector import whitelist
from detector import log_parser


def append_to_blacklist(ip: str) -> None:
    """Append a detected attacker IP to the blacklist file."""
    config.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(config.BLACKLIST_FILE, "a", encoding="utf-8") as f:
        f.write(ip.strip() + "\n")


def run_detection() -> None:
    """
    Main flow: parse logs -> detect malicious IPs -> respond (alert + optional block).
    """
    logger.log_info("SSH Brute Force Detector started")

    # ---------------------------------------------------------------------------
    # 1. Parse logs (with deduplication via last offset)
    # ---------------------------------------------------------------------------
    log_path, last_offset = log_parser.get_log_path_and_offset()
    if log_path is None:
        logger.log_error("No log file available. Add logs/sample_auth.log or run on Linux with auth.log/secure.")
        return

    events, new_offset = log_parser.parse_log(path=log_path, last_offset=last_offset)
    log_parser.save_offset(log_path, new_offset)

    logger.log_info("Parsed log file", path=str(log_path), events=len(events))

    if not events:
        logger.log_info("No new SSH events to analyze")
        return

    # ---------------------------------------------------------------------------
    # 2. Detect malicious IPs (threshold + window)
    # ---------------------------------------------------------------------------
    malicious = detector.find_malicious_ips(events)
    whitelist_ips = whitelist.get_whitelist()

    for ip, rec in malicious:
        if whitelist.is_whitelisted(ip, whitelist_ips):
            logger.log_info("Skipping whitelisted IP (no action)", ip=ip)
            continue

        # -----------------------------------------------------------------------
        # Stage 1: Detection only - log and write alert
        # -----------------------------------------------------------------------
        alert = {
            "ip": ip,
            "timestamp": rec.last_seen,
            "first_seen": rec.first_seen,
            "last_seen": rec.last_seen,
            "attempt_count": rec.attempt_count,
            "usernames_tried": rec.usernames,
            "reason": (
                f"IP exceeded threshold: {rec.attempt_count} failed SSH attempts "
                f"within configured window (threshold={config.FAILED_ATTEMPTS_THRESHOLD}, "
                f"window={config.DETECTION_WINDOW_SECONDS}s)"
            ),
            "action_stage1": "alert",
            "action_stage2": "rate_limit_simulated",
            "action_stage3": "block_simulated" if config.DRY_RUN else "block_applied",
        }
        logger.log_warn("Brute force detected", **alert)
        logger.append_alert(alert, config.ALERTS_FILE)

        # -----------------------------------------------------------------------
        # Stage 2: Rate-limit (simulation)
        # -----------------------------------------------------------------------
        firewall.rate_limit_simulate(ip)

        # -----------------------------------------------------------------------
        # Stage 3: Firewall block (or dry-run log)
        # -----------------------------------------------------------------------
        firewall.block_ip(ip)

        # Record in blacklist for future reference
        append_to_blacklist(ip)

    if not malicious:
        logger.log_info("No brute force activity detected in this run")
    else:
        logger.log_info(
            "Detection run complete",
            malicious_count=len(malicious),
            dry_run=config.DRY_RUN,
        )


if __name__ == "__main__":
    run_detection()

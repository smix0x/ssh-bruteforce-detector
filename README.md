# SSH Brute Force Detector

**Blue Team / SOC educational project** — Detect SSH brute force attacks via log analysis, with multi-stage response (alert → rate-limit simulation → firewall block). Production-inspired structure, beginner-friendly implementation, and interview-ready explanations s

---

## Project Overview

This project analyzes SSH authentication logs (e.g. `auth.log`, `secure`) to detect **brute force attacks**: many failed login attempts from the same IP in a short time. It then applies a **multi-stage response**: log and alert first, optionally simulate rate-limiting, and optionally block the IP at the firewall — with **DRY-RUN mode on by default** so you can learn and test safely.

**Target audience:** Network & Security students, SOC analyst candidates, and anyone learning Blue Team fundamentals (log analysis, detection thresholds, incident response, automation).

---

## Skills Demonstrated

- Linux log analysis (auth.log / secure)
- SSH attack pattern recognition
- Brute force detection logic (threshold + time window)
- Python scripting for security automation
- Incident response workflow (detect → alert → respond)
- Safe defensive automation (dry-run, whitelist)

---

## What Problem This Solves

- **SSH is a common target:** Attackers scan the internet for port 22 and try default or weak credentials.
- **Manual log review doesn’t scale:** You need automated detection and clear, SIEM-friendly alerts.
- **Response must be safe:** Blocking the wrong IP (e.g. your admin) can lock you out. This project uses a **whitelist** and **dry-run** to reduce risk.

This detector gives you a clear, readable pipeline: **parse logs → detect threshold violations → alert → (optionally) block**, with explanations in code and docs.

---

## How SSH Brute Force Works

1. Attacker finds an open SSH port (e.g. 22).
2. They try many username/password pairs (e.g. `root`/`admin`, `ubuntu`/`ubuntu`).
3. Each failed attempt is logged (e.g. “Failed password for … from \<IP\>”).
4. **Detection idea:** If one IP has **too many failures in a short window** (e.g. 5 in 10 minutes), it’s likely brute force, not a user who forgot a password.

This project implements that idea with configurable threshold and window, plus whitelist and dry-run.

---

## Detection Logic

- **Input:** SSH auth log lines (parsed from `auth.log` or `secure`).
- **Count:** For each **source IP**, we count only **failed** attempts (wrong password or “invalid user”).
- **Threshold:** Default **5 failed attempts** within **10 minutes** (configurable in `detector/config.py`).
- **Malicious IP:** Any IP that meets or exceeds the threshold within that window.
- **Why this works:** Legitimate users rarely fail authentication repeatedly from the same source IP in a short window.
- **False positive reduction:**  
  - Only failed/invalid attempts count (successes are ignored).  
  - Time window keeps one bad day from looking like one “burst.”  
  - Whitelist ensures trusted IPs (localhost, internal, admin) are never blocked.

Details are in `detector/detector.py` (e.g. `find_malicious_ips`, `build_attempts_by_ip`).

---

## Example Log Entries

Typical lines we parse (Debian/Ubuntu `auth.log` style):

```text
Jan 30 10:14:00 server sshd[1234]: Failed password for invalid user root from 203.0.113.50 port 22 ssh2
Jan 30 10:14:02 server sshd[1234]: Failed password for invalid user admin from 203.0.113.50 port 22 ssh2
Jan 30 10:14:15 server sshd[1234]: Failed password for ubuntu from 203.0.113.50 port 22 ssh2
Jan 30 10:15:00 server sshd[1234]: Accepted password for admin from 192.168.1.50 port 22 ssh2
```

We extract: **timestamp**, **source IP**, **username**, and **result** (failed / invalid user / success). Same idea applies to RHEL/CentOS `secure` logs; regex patterns are in `detector/log_parser.py`.

---

## How Alerts Are Generated

1. **Parse** new log lines (from last saved offset to avoid duplicate processing).
2. **Detect** IPs that exceed the threshold in the time window.
3. For each such IP (unless whitelisted):  
   - **Stage 1:** Log a structured event and **append one JSON alert** to `output/alerts.json`.
4. Each alert is **one JSON object per line** (JSON Lines), e.g.:

   - `ip`, `timestamp`, `first_seen`, `last_seen`, `attempt_count`, `usernames_tried`, `reason`, `action_stage1`, `action_stage2`, `action_stage3`.

This format is **SIEM-friendly** (easy to ingest and correlate).

---

## How Firewall Blocking Works

- **Stage 2:** Rate-limit is **simulated** (we only log that we would rate-limit).
- **Stage 3:** Actual block is implemented in `detector/firewall.py`:
  - **DRY_RUN = True (default):** No firewall changes; we only log “would block \<IP\>”.
  - **DRY_RUN = False:** On Linux, we try **iptables** first (e.g. `iptables -I INPUT 1 -s \<IP\> -j DROP`), then **ufw** if iptables isn’t used.
- **Whitelist:** Whitelisted IPs are never blocked (handled before firewall logic).
- **Auto-unblock:** Config has `BLOCK_DURATION_SECONDS` (e.g. 24h); the current code focuses on block logic; a cron or timer could later call an unblock function.
  
  ⚠️ Blocking is intentionally disabled by default to prevent accidental lockout during learning or testing.


---

## How This Compares to Fail2Ban

| Aspect            | This project              | Fail2Ban                    |
|------------------|---------------------------|-----------------------------|
| Purpose          | Educational, clear flow   | Production service          |
| Complexity       | Minimal, no daemon        | Filters, jails, many options  |
| Log sources      | auth.log / secure / sample| Configurable per service    |
| Response         | Alert + optional block    | Ban, recidive, etc.         |
| Learning         | Line-by-line readable     | More opaque for beginners   |

Use this project to **understand** detection and response; use Fail2Ban (or similar) when you need a **battle-tested** solution in production.

---

## Ethical & Educational Disclaimer

This tool is for **defensive use and learning only**:

- Use only on systems you own or are authorized to test.
- Do not use it to attack or abuse others’ systems.
- Understanding brute force detection helps you defend networks and pass SOC/security interviews; do not misuse the knowledge.

---

## How to Run the Project

### Prerequisites

- Python 3.10+ (or 3.8+ with minor adjustments).
- No mandatory external packages (see `requirements.txt`).

### Steps

1. **Clone or copy** the project (e.g. `ssh-bruteforce-detector/`).

2. **Use the sample log (no Linux required):**

   - Logs are read from `logs/sample_auth.log` if `auth.log` / `secure` are not present (e.g. on Windows or when not root).
   - The sample includes one IP with enough failures to trigger detection.

3. **Run the detector:**

   ```bash
   cd "c:\Users\LEGION\Desktop\SSH BRUTE"
   python main.py
   ```

4. **Check output:**

   - **stdout:** JSON log lines (e.g. “Brute force detected”, “Would block IP” when DRY_RUN is True).
   - **output/alerts.json:** One JSON object per line for each detected brute force IP.

5. **Optional — use real logs on Linux:**

   - Run with read access to `/var/log/auth.log` or `/var/log/secure` (e.g. `sudo python main.py` if needed).
   - The script remembers the last read position to avoid reprocessing the same lines.

6. **Optional — actually block IPs:**

   - In `detector/config.py`, set `DRY_RUN = False`.
   - Run with sufficient privileges (e.g. root for iptables/ufw). Use with care and a correct whitelist.

---

## Project Structure

```text
ssh-bruteforce-detector/
├── detector/
│   ├── __init__.py
│   ├── config.py      # Thresholds, paths, DRY_RUN, whitelist/blacklist paths
│   ├── log_parser.py  # Parse auth.log / secure; regex; offset tracking
│   ├── detector.py    # Threshold + window; malicious IP list
│   ├── firewall.py    # Block (iptables/ufw); rate-limit simulation
│   ├── whitelist.py   # Trusted IPs/CIDRs; never block
│   └── logger.py      # JSON logging; append to alerts.json
├── logs/
│   └── sample_auth.log
├── output/
│   └── alerts.json
├── config/            # Created at run; whitelist.txt, blacklist.txt
├── state/             # Created at run; last_position.json
├── main.py            # Entry: parse → detect → respond
├── README.md
├── requirements.txt
└── LICENSE (MIT)
```
---

## Interview Talking Points

- Why threshold-based detection works for brute force attacks
- How false positives are reduced using time windows and whitelisting
- Difference between detection logic and response automation
- Why dry-run mode is critical in security tooling
- When to use a custom script vs Fail2Ban in real environments

---

## Future Improvements

- **Auto-unblock:** After `BLOCK_DURATION_SECONDS`, remove the block (e.g. iptables/ufw delete rule).
- **Full timestamp parsing:** Use full syslog timestamp (with year) for window calculation across log rotation.
- **More log formats:** Support additional syslog or SSH log formats.
- **Whitelist from file:** Already supported; add a sample `config/whitelist.txt` with internal ranges.
- **Metrics:** Count alerts per day, per IP, and export for dashboards.
- **Tests:** Unit tests for parser, detector, and whitelist logic.

---

## Author & License

- **License:** MIT  
- **Intent:** Educational and Blue Team / SOC training.  
- **GitHub:** [smix0x](https://github.com/smix0x)

Use it to learn, adapt it for labs, and explain detection and response in interviews.

# 🛡️ Blue Team Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-3776AB.svg?logo=python&logoColor=white)](https://python.org)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/stevenartzt/blue-team-toolkit/pulls)
[![Maintenance](https://img.shields.io/badge/Maintained-yes-green.svg)](https://github.com/stevenartzt/blue-team-toolkit)

A collection of practical blue team security tools for log analysis, SSL/TLS auditing, threat intelligence aggregation, and file integrity monitoring. Built for defenders who need real tools, not toy scripts.

**Minimal dependencies. Maximum utility. All Python 3 stdlib where possible.**

---

## 🔧 Tools

| Tool | Description | Key Features |
|------|-------------|--------------|
| [`log_analyzer.py`](#-log-analyzer) | Parse auth/syslog for attacks | Brute force detection, password spray, privilege escalation |
| [`ssl_auditor.py`](#-ssltls-auditor) | Audit domain TLS configuration | Cert validation, protocol probing, cipher analysis, HSTS |
| [`threat_intel.py`](#-threat-intel-aggregator) | Aggregate IOCs from public feeds | CISA KEV, abuse.ch, AlienVault OTX, cross-referencing |
| [`fim.py`](#-file-integrity-monitor) | Monitor critical file changes | Hash baselines, permission tracking, cron-friendly |

---

## ⚡ Quick Start

```bash
# Clone
git clone https://github.com/stevenartzt/blue-team-toolkit.git
cd blue-team-toolkit

# Install minimal dependencies (only needed for threat_intel.py feeds)
pip install -r requirements.txt  # Actually empty — it's all stdlib!

# Run any tool
python3 log_analyzer.py --help
python3 ssl_auditor.py --help
python3 threat_intel.py --help
python3 fim.py --help
```

No virtual environments needed. No pip install drama. Just Python 3.8+ and you're good.

---

## 📋 Log Analyzer

Parse `auth.log`, `syslog`, and similar system logs for security events. Detects brute force attempts, password spraying, failed SSH logins, suspicious sudo activity, and pre-auth scanner behavior.

### Usage

```bash
# Basic analysis
python3 log_analyzer.py /var/log/auth.log

# Multiple log files with JSON output
python3 log_analyzer.py /var/log/auth.log /var/log/auth.log.1 --format json

# CSV export for spreadsheet/SIEM
python3 log_analyzer.py /var/log/auth.log --format csv > findings.csv

# Save report to file
python3 log_analyzer.py /var/log/auth.log -o report.txt --verbose
```

### Example Output

```
========================================================================
  LOG ANALYZER — SECURITY EVENT REPORT
  Generated: 2026-02-23 22:15:00
========================================================================

─── SUMMARY ───────────────────────────────────────────────────────
  Total events parsed:      4,271
  Unique source IPs:        89
    ├─ Private:             3
    └─ Public:              86
  Accepted SSH logins:      12

  Severity Breakdown:
    CRITICAL      2  ██
    HIGH         15  ███████████████
    WARNING   1,847  ██████████████████████████████████████████████████
    LOW       2,304  ██████████████████████████████████████████████████

─── BRUTE FORCE / PASSWORD SPRAY DETECTIONS ────────────────────────
  3 source IP(s) flagged:

  [1] 🔴 CRITICAL — 203.0.113.42
      Attack type:        Rapid password spray
      Total failures:     1,204
      Unique users tried: 47
      Users:              admin, root, ubuntu, test, user (+42 more)
      Rapid fire:         Yes ⚡
      First seen:         Feb 23 01:12:33
      Last seen:          Feb 23 04:58:11
      ⚠️  POSSIBLE COMPROMISE — successful login detected after failures!

─── RECOMMENDATIONS ────────────────────────────────────────────────
  1. 🚨 URGENT: Investigate possible compromise from 203.0.113.42.
  2. Block the following IPs at the firewall: 203.0.113.42, 198.51.100.7
  3. Password spray detected. Enforce strong password policies.
```

### What It Detects

- **Brute force attacks** — High-volume failed logins from single IPs
- **Password spraying** — Multiple usernames targeted from one source
- **Rapid-fire attempts** — Burst patterns within 5-minute windows
- **Post-compromise indicators** — Successful login after failed attempts (critical!)
- **Suspicious sudo** — Failed sudo auth, dangerous command execution
- **Scanner behavior** — Pre-auth disconnects from bots/scanners

---

## 🔒 SSL/TLS Auditor

Scan domains for weak ciphers, expired/expiring certificates, deprecated protocol versions, certificate chain issues, and missing security headers. Produces a letter grade (A+ through F).

### Usage

```bash
# Audit a single domain
python3 ssl_auditor.py example.com

# Multiple domains
python3 ssl_auditor.py example.com github.com cloudflare.com

# Custom port
python3 ssl_auditor.py internal.corp:8443

# From a target list
python3 ssl_auditor.py --targets domains.txt

# JSON output
python3 ssl_auditor.py example.com --format json -o audit.json
```

### Example Output

```
========================================================================
  SSL/TLS AUDIT — example.com:443
  2026-02-23 22:15:00
  Overall Grade: A
========================================================================

─── CONNECTION ─────────────────────────────────────────────────────
  ✓ PASS  TLS Handshake
         Connected successfully, negotiated TLSv1.3

─── CERTIFICATE ────────────────────────────────────────────────────
  ✓ PASS  Chain Validation
         Certificate chain is trusted
  ✓ PASS  Expiration
         Valid for 245 days (expires Mar 15 12:00:00 2027 GMT)
  ✓ PASS  Hostname Match
         Certificate matches example.com
  ✓ PASS  Subject Alt Names
         3 DNS name(s): example.com, www.example.com, *.example.com

─── PROTOCOL ───────────────────────────────────────────────────────
  ✓ PASS  SSLv3
         Not supported (good — Broken — POODLE vulnerability)
  ✓ PASS  TLSv1
         Not supported (good — Deprecated)
  ✓ PASS  TLSv1.2
         Supported — Acceptable
  ✓ PASS  TLSv1.3
         Supported — Current, recommended

─── CIPHER ─────────────────────────────────────────────────────────
  ✓ PASS  Weak Ciphers
         No weak ciphers detected
  ✓ PASS  Strong Ciphers
         AEAD ciphers available: TLS_AES_256_GCM_SHA384 (256b)

─── HEADERS ────────────────────────────────────────────────────────
  ✓ PASS  HSTS
         Present: max-age=31536000; includeSubDomains; preload

────────────────────────────────────────────────────────────────────
  14 passed  │  0 warnings  │  0 failed  │  3 info
========================================================================
```

### What It Checks

- **Certificate validity** — Chain trust, expiration, hostname match, SANs
- **Key strength** — RSA ≥ 2048-bit, EC ≥ 256-bit
- **Protocol versions** — SSLv3, TLS 1.0, 1.1 (should be disabled), TLS 1.2, 1.3
- **Cipher suites** — Detects RC4, DES, 3DES, NULL, EXPORT, anonymous ciphers
- **CA/B Forum compliance** — Certificate validity period ≤ 398 days
- **HSTS** — Strict-Transport-Security header, includeSubDomains, preload
- **Self-signed detection** — Flags self-signed certificates

---

## 🕵️ Threat Intel Aggregator

Pull Indicators of Compromise (IOCs) from public threat intelligence feeds and cross-reference them with your local logs or IP lists.

### Supported Feeds

| Feed | Type | Description |
|------|------|-------------|
| CISA KEV | CVEs | Known exploited vulnerabilities (with ransomware flags) |
| URLhaus | URLs | Recently reported malicious URLs |
| ThreatFox | Mixed | IPs, domains, hashes from malware campaigns |
| Feodo Tracker | IPs | Botnet C2 server blocklist |
| SSL Blacklist | IPs | SSL certs tied to botnet C2 |
| AlienVault OTX | Mixed | Community threat intel (free API key) |

### Usage

```bash
# Collect IOCs from all feeds
python3 threat_intel.py --collect

# Specific feeds only
python3 threat_intel.py --collect --feeds cisa_kev feodo_blocklist

# Cross-reference with your logs
python3 threat_intel.py --collect --crossref /var/log/auth.log

# Cross-reference with an IP list
python3 threat_intel.py --collect --crossref /var/log/syslog --ip-list suspicious.txt

# Use AlienVault OTX (free API key)
export OTX_API_KEY="your_key_here"
python3 threat_intel.py --collect --otx-key $OTX_API_KEY

# JSON output for SIEM ingestion
python3 threat_intel.py --collect --format json > iocs.json

# List available feeds
python3 threat_intel.py --list-feeds
```

### Example Cross-Reference Output

```
========================================================================
  THREAT INTEL — CROSS-REFERENCE RESULTS
  Generated: 2026-02-23 22:15:00
========================================================================

  ⚠️  3 MATCH(ES) FOUND!

  [1] 🔴 CRITICAL — IP: 185.220.101.42
      Source:      Feodo Tracker
      Description: Botnet C2 server
      Tags:        botnet, c2

  [2] 🟠 HIGH — IP: 45.155.205.233
      Source:      ThreatFox
      Description: botnet_cc: Emotet
      Tags:        emotet, epoch4

  [3] 🟡 MEDIUM — Domain: malware-download.example.com
      Source:      URLhaus
      Description: Threat: malware_download

─── RECOMMENDED ACTIONS ────────────────────────────────────────────
  1. IMMEDIATE: Block 2 high-severity indicator(s)
  2. Investigate affected systems for signs of compromise
  3. Check network logs for communication with flagged IPs/domains
  4. Rotate credentials on any affected services
```

---

## 📁 File Integrity Monitor

Hash critical system files, maintain a baseline, and detect unauthorized changes. Designed for cron deployment with quiet mode — only alerts when something changes.

### Usage

```bash
# Create initial baseline
sudo python3 fim.py --init

# Create baseline with custom paths
sudo python3 fim.py --init --watch /etc/ /usr/local/bin/ --exclude '*.log'

# Check for changes
sudo python3 fim.py --check

# Check with JSON output (for SIEM)
sudo python3 fim.py --check --format json

# View baseline info
python3 fim.py --info

# Cron-friendly (silent when clean)
sudo python3 fim.py --check --quiet

# Use SHA-512 instead of SHA-256
sudo python3 fim.py --init --algorithm sha512
```

### Cron Setup

```bash
# Check every hour, email on changes
0 * * * * /usr/bin/python3 /opt/blue-team-toolkit/fim.py --check --quiet 2>&1 | mail -E -s "FIM Alert: $(hostname)" security@yourorg.com

# Check every 15 minutes, log to file
*/15 * * * * /usr/bin/python3 /opt/blue-team-toolkit/fim.py --check --quiet -o /var/log/fim-alerts.txt
```

### Example Output

```
========================================================================
  FILE INTEGRITY MONITOR — CHECK RESULTS
  Checked: 2026-02-23 22:15:00
  Baseline: 2026-02-20T10:00:00
  Host: web-prod-01
  Algorithm: sha256
  Files in baseline: 247
========================================================================

  ⚠️  4 CHANGE(S) DETECTED!

─── SUMMARY ────────────────────────────────────────────────────────
  📝 MODIFIED                       2
  ➕ ADDED                          1
  🔒 PERMISSIONS_CHANGED            1

  Severity:
    CRITICAL       1
    HIGH           2
    MEDIUM         1

─── CHANGES ────────────────────────────────────────────────────────
  🔴 [M] /etc/passwd
       Hash changed: a1b2c3d4e5f6... → 9f8e7d6c5b4a...
  🟠 [M] /etc/crontab
       Hash changed: 1234abcd5678... → efgh9012ijkl...
  🟠 [A] /etc/cron.d/suspicious-job
       New file not in baseline
  🟡 [P] /usr/local/bin/backup.sh
       Permissions: -rwxr-xr-x → -rwxrwxrwx

─── RECOMMENDATIONS ────────────────────────────────────────────────
  🚨 CRITICAL changes to core system files detected!
     - Verify changes were authorized
     - Check for signs of compromise
     - Review recent login activity
```

### What It Monitors

- **Default paths:** `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`, cron directories, PAM config, systemd units, `/usr/local/bin/`
- **Change types:** Content modification, new files, deleted files, permission changes, ownership changes
- **Smart severity:** `/etc/passwd` modified = CRITICAL, new cron job = HIGH, etc.
- **Hash algorithms:** SHA-256 (default), SHA-512, SHA-1, MD5, BLAKE2b

---

## 📦 Installation

```bash
git clone https://github.com/stevenartzt/blue-team-toolkit.git
cd blue-team-toolkit

# That's it. No dependencies to install.
# All tools use Python 3 standard library only.
```

### Requirements

- Python 3.8+
- Linux/macOS (some paths are Unix-specific)
- Root access recommended for `fim.py` and `log_analyzer.py` (reading system files)

---

## 🏗️ Project Structure

```
blue-team-toolkit/
├── README.md              # This file
├── LICENSE                # MIT License
├── requirements.txt       # Python dependencies (minimal)
├── log_analyzer.py        # Log analysis tool
├── ssl_auditor.py         # SSL/TLS auditing tool
├── threat_intel.py        # Threat intel aggregator
└── fim.py                 # File integrity monitor
```

---

## 🤝 Contributing

PRs welcome. If you've got a detection pattern, feed source, or check that should be here — open a PR or issue.

---

## 📄 License

MIT — see [LICENSE](LICENSE).

---

## 👤 Author

**Steven Artzt** — [@stevenartzt](https://github.com/stevenartzt)

Security researcher. Builder of [thebreach.news](https://thebreach.news).

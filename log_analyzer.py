#!/usr/bin/env python3
"""
Log Analyzer — Blue Team Toolkit
=================================
Parse syslog, auth.log, and similar system logs for security-relevant events:
brute force attempts, failed SSH logins, privilege escalation, anomalous patterns.

Outputs a summary report with top offending IPs, timestamps, severity ratings,
and recommended actions.

Author: Steven Artzt (@stevenartzt)
License: MIT
"""

import argparse
import collections
import csv
import datetime
import ipaddress
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants & patterns
# ---------------------------------------------------------------------------

VERSION = "1.0.0"

# Regex patterns for common log formats
PATTERNS = {
    "sshd_failed": re.compile(
        r"(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+"
        r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+)\s+"
        r"from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)"
    ),
    "sshd_accepted": re.compile(
        r"(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+"
        r"Accepted (?:password|publickey) for (?P<user>\S+)\s+"
        r"from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)"
    ),
    "sshd_invalid_user": re.compile(
        r"(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+"
        r"Invalid user (?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)"
    ),
    "sudo_auth_failure": re.compile(
        r"(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sudo(?:\[\d+\])?:\s+"
        r"(?P<user>\S+)\s+:.*authentication failure"
    ),
    "sudo_command": re.compile(
        r"(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sudo(?:\[\d+\])?:\s+"
        r"(?P<user>\S+)\s+:\s+.*COMMAND=(?P<command>.+)"
    ),
    "pam_failure": re.compile(
        r"(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+\S+\[\d+\]:\s+"
        r"pam_unix\(\S+\):.*authentication failure.*rhost=(?P<ip>\d+\.\d+\.\d+\.\d+)"
    ),
    "systemd_login_failed": re.compile(
        r"(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+"
        r"systemd-logind\[\d+\]:\s+Failed"
    ),
    "connection_closed_preauth": re.compile(
        r"(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+"
        r"Connection closed by (?P<ip>\d+\.\d+\.\d+\.\d+)\s+port\s+\d+\s+\[preauth\]"
    ),
    "sshd_disconnect_preauth": re.compile(
        r"(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+"
        r"Disconnected from (?:authenticating user \S+ )?(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
        r"port\s+\d+\s+\[preauth\]"
    ),
}

# Severity thresholds for brute force detection
BRUTE_FORCE_THRESHOLD = 5      # failures from same IP
SPRAY_THRESHOLD = 3            # unique usernames targeted by same IP
RAPID_WINDOW_SECONDS = 300     # 5-minute window for rapid-fire detection
RAPID_COUNT_THRESHOLD = 10     # attempts in rapid window

# Well-known dangerous sudo commands
SUSPICIOUS_COMMANDS = [
    "/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh",
    "visudo", "passwd", "useradd", "usermod", "groupadd",
    "chmod 777", "chmod 666", "iptables -F", "ufw disable",
    "systemctl stop", "rm -rf",
]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class LogEvent:
    """Represents a single parsed log event."""
    __slots__ = ("timestamp_raw", "timestamp", "event_type", "ip", "user",
                 "detail", "severity", "line_number")

    def __init__(self, timestamp_raw: str, event_type: str,
                 ip: Optional[str] = None, user: Optional[str] = None,
                 detail: str = "", severity: str = "INFO",
                 line_number: int = 0):
        self.timestamp_raw = timestamp_raw
        self.timestamp = self._parse_timestamp(timestamp_raw)
        self.event_type = event_type
        self.ip = ip
        self.user = user
        self.detail = detail
        self.severity = severity
        self.line_number = line_number

    @staticmethod
    def _parse_timestamp(raw: str) -> Optional[datetime.datetime]:
        """Parse syslog-style timestamp (assumes current year)."""
        try:
            year = datetime.datetime.now().year
            return datetime.datetime.strptime(f"{year} {raw}", "%Y %b %d %H:%M:%S")
        except (ValueError, TypeError):
            return None

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp_raw,
            "event_type": self.event_type,
            "ip": self.ip or "",
            "user": self.user or "",
            "detail": self.detail,
            "severity": self.severity,
            "line": self.line_number,
        }


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class LogAnalyzer:
    """
    Core log analysis engine.

    Parses log files, classifies events, detects attack patterns,
    and generates reports.
    """

    def __init__(self, verbose: bool = False):
        self.events: List[LogEvent] = []
        self.verbose = verbose
        self._failed_by_ip: Dict[str, List[LogEvent]] = collections.defaultdict(list)
        self._failed_by_user: Dict[str, List[LogEvent]] = collections.defaultdict(list)
        self._users_by_ip: Dict[str, set] = collections.defaultdict(set)
        self._accepted_by_ip: Dict[str, List[LogEvent]] = collections.defaultdict(list)
        self._sudo_events: List[LogEvent] = []
        self._preauth_by_ip: Dict[str, int] = collections.defaultdict(int)

    def parse_file(self, filepath: str) -> int:
        """
        Parse a single log file and extract security events.

        Returns the number of events extracted.
        """
        path = Path(filepath)
        if not path.exists():
            print(f"[!] File not found: {filepath}", file=sys.stderr)
            return 0
        if not path.is_file():
            print(f"[!] Not a regular file: {filepath}", file=sys.stderr)
            return 0

        count_before = len(self.events)
        line_num = 0

        try:
            with open(path, "r", errors="replace") as fh:
                for line in fh:
                    line_num += 1
                    self._parse_line(line.rstrip("\n"), line_num)
        except PermissionError:
            print(f"[!] Permission denied: {filepath}", file=sys.stderr)
            return 0

        added = len(self.events) - count_before
        if self.verbose:
            print(f"[*] Parsed {line_num} lines from {filepath}, "
                  f"extracted {added} events")
        return added

    def _parse_line(self, line: str, line_num: int) -> None:
        """Attempt to match a log line against known patterns."""

        # SSH failed authentication
        m = PATTERNS["sshd_failed"].search(line)
        if m:
            ev = LogEvent(
                timestamp_raw=m.group("timestamp"),
                event_type="ssh_failed_auth",
                ip=m.group("ip"),
                user=m.group("user"),
                detail=line,
                severity="WARNING",
                line_number=line_num,
            )
            self.events.append(ev)
            self._failed_by_ip[ev.ip].append(ev)
            self._failed_by_user[ev.user].append(ev)
            self._users_by_ip[ev.ip].add(ev.user)
            return

        # SSH accepted authentication
        m = PATTERNS["sshd_accepted"].search(line)
        if m:
            ev = LogEvent(
                timestamp_raw=m.group("timestamp"),
                event_type="ssh_accepted",
                ip=m.group("ip"),
                user=m.group("user"),
                detail=line,
                severity="INFO",
                line_number=line_num,
            )
            self.events.append(ev)
            self._accepted_by_ip[ev.ip].append(ev)
            return

        # Invalid SSH user
        m = PATTERNS["sshd_invalid_user"].search(line)
        if m:
            ev = LogEvent(
                timestamp_raw=m.group("timestamp"),
                event_type="ssh_invalid_user",
                ip=m.group("ip"),
                user=m.group("user"),
                detail=line,
                severity="WARNING",
                line_number=line_num,
            )
            self.events.append(ev)
            self._failed_by_ip[ev.ip].append(ev)
            self._users_by_ip[ev.ip].add(ev.user)
            return

        # Pre-auth disconnects (scanner/bot behavior)
        m = PATTERNS["connection_closed_preauth"].search(line)
        if not m:
            m = PATTERNS["sshd_disconnect_preauth"].search(line)
        if m:
            ip = m.group("ip")
            self._preauth_by_ip[ip] += 1
            ev = LogEvent(
                timestamp_raw=m.group("timestamp"),
                event_type="preauth_disconnect",
                ip=ip,
                detail=line,
                severity="LOW",
                line_number=line_num,
            )
            self.events.append(ev)
            return

        # PAM authentication failure
        m = PATTERNS["pam_failure"].search(line)
        if m:
            ev = LogEvent(
                timestamp_raw=m.group("timestamp"),
                event_type="pam_auth_failure",
                ip=m.group("ip"),
                detail=line,
                severity="WARNING",
                line_number=line_num,
            )
            self.events.append(ev)
            self._failed_by_ip[ev.ip].append(ev)
            return

        # Sudo authentication failure
        m = PATTERNS["sudo_auth_failure"].search(line)
        if m:
            ev = LogEvent(
                timestamp_raw=m.group("timestamp"),
                event_type="sudo_auth_failure",
                user=m.group("user"),
                detail=line,
                severity="HIGH",
                line_number=line_num,
            )
            self.events.append(ev)
            self._sudo_events.append(ev)
            return

        # Sudo command execution
        m = PATTERNS["sudo_command"].search(line)
        if m:
            cmd = m.group("command")
            severity = "INFO"
            for sus in SUSPICIOUS_COMMANDS:
                if sus in cmd:
                    severity = "HIGH"
                    break
            ev = LogEvent(
                timestamp_raw=m.group("timestamp"),
                event_type="sudo_command",
                user=m.group("user"),
                detail=cmd,
                severity=severity,
                line_number=line_num,
            )
            self.events.append(ev)
            self._sudo_events.append(ev)
            return

    # -------------------------------------------------------------------
    # Analysis
    # -------------------------------------------------------------------

    def detect_brute_force(self) -> List[dict]:
        """
        Detect brute force patterns:
        - High volume of failures from a single IP
        - Rapid-fire attempts within a short window
        - Password spraying (many usernames from one IP)
        """
        findings = []

        for ip, events in self._failed_by_ip.items():
            count = len(events)
            if count < BRUTE_FORCE_THRESHOLD:
                continue

            # Check for rapid-fire bursts
            rapid = False
            if len(events) >= RAPID_COUNT_THRESHOLD:
                timestamps = sorted(e.timestamp for e in events if e.timestamp)
                for i in range(len(timestamps) - RAPID_COUNT_THRESHOLD + 1):
                    window = (timestamps[i + RAPID_COUNT_THRESHOLD - 1] -
                              timestamps[i]).total_seconds()
                    if window <= RAPID_WINDOW_SECONDS:
                        rapid = True
                        break

            # Check for password spraying
            unique_users = self._users_by_ip.get(ip, set())
            spray = len(unique_users) >= SPRAY_THRESHOLD

            # Determine severity
            if rapid and spray:
                severity = "CRITICAL"
                attack_type = "Rapid password spray"
            elif rapid:
                severity = "CRITICAL"
                attack_type = "Rapid brute force"
            elif spray:
                severity = "HIGH"
                attack_type = "Password spray"
            else:
                severity = "MEDIUM"
                attack_type = "Brute force"

            # Check if any successful login followed failures (compromise indicator)
            compromised = False
            if ip in self._accepted_by_ip:
                last_fail = max((e.timestamp for e in events if e.timestamp),
                                default=None)
                for acc in self._accepted_by_ip[ip]:
                    if acc.timestamp and last_fail and acc.timestamp >= last_fail:
                        compromised = True
                        severity = "CRITICAL"
                        break

            first_seen = min((e.timestamp_raw for e in events), default="unknown")
            last_seen = max((e.timestamp_raw for e in events), default="unknown")

            findings.append({
                "ip": ip,
                "attack_type": attack_type,
                "total_failures": count,
                "unique_users": sorted(unique_users),
                "severity": severity,
                "rapid_fire": rapid,
                "password_spray": spray,
                "possible_compromise": compromised,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "preauth_disconnects": self._preauth_by_ip.get(ip, 0),
            })

        # Sort by severity, then count
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings.sort(key=lambda f: (sev_order.get(f["severity"], 5),
                                     -f["total_failures"]))
        return findings

    def detect_suspicious_sudo(self) -> List[dict]:
        """Detect suspicious sudo activity."""
        findings = []
        for ev in self._sudo_events:
            if ev.severity == "HIGH":
                findings.append({
                    "user": ev.user,
                    "event": ev.event_type,
                    "detail": ev.detail,
                    "timestamp": ev.timestamp_raw,
                    "severity": ev.severity,
                })
        return findings

    def get_statistics(self) -> dict:
        """Compute summary statistics."""
        event_counts = collections.Counter(e.event_type for e in self.events)
        severity_counts = collections.Counter(e.severity for e in self.events)

        top_ips = collections.Counter()
        for ip, evts in self._failed_by_ip.items():
            top_ips[ip] = len(evts)

        top_users = collections.Counter()
        for user, evts in self._failed_by_user.items():
            top_users[user] = len(evts)

        # Classify IPs as private vs public
        private_ips = 0
        public_ips = 0
        for ip in self._failed_by_ip:
            try:
                if ipaddress.ip_address(ip).is_private:
                    private_ips += 1
                else:
                    public_ips += 1
            except ValueError:
                pass

        return {
            "total_events": len(self.events),
            "event_types": dict(event_counts),
            "severity_breakdown": dict(severity_counts),
            "unique_source_ips": len(self._failed_by_ip),
            "private_source_ips": private_ips,
            "public_source_ips": public_ips,
            "top_offending_ips": top_ips.most_common(20),
            "top_targeted_users": top_users.most_common(20),
            "total_accepted_logins": sum(
                len(v) for v in self._accepted_by_ip.values()
            ),
        }

    # -------------------------------------------------------------------
    # Reporting
    # -------------------------------------------------------------------

    def generate_report(self, format_type: str = "text") -> str:
        """Generate a complete analysis report."""
        stats = self.get_statistics()
        brute_force = self.detect_brute_force()
        suspicious_sudo = self.detect_suspicious_sudo()

        if format_type == "json":
            return json.dumps({
                "statistics": stats,
                "brute_force_detections": brute_force,
                "suspicious_sudo": suspicious_sudo,
                "generated_at": datetime.datetime.now().isoformat(),
            }, indent=2, default=str)

        if format_type == "csv":
            return self._generate_csv(brute_force)

        return self._generate_text_report(stats, brute_force, suspicious_sudo)

    def _generate_csv(self, brute_force: List[dict]) -> str:
        """Generate CSV output of brute force findings."""
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "IP", "Attack Type", "Severity", "Total Failures",
            "Unique Users", "Rapid Fire", "Password Spray",
            "Possible Compromise", "First Seen", "Last Seen"
        ])
        for f in brute_force:
            writer.writerow([
                f["ip"], f["attack_type"], f["severity"],
                f["total_failures"], len(f["unique_users"]),
                f["rapid_fire"], f["password_spray"],
                f["possible_compromise"], f["first_seen"], f["last_seen"],
            ])
        return output.getvalue()

    def _generate_text_report(self, stats: dict, brute_force: List[dict],
                              suspicious_sudo: List[dict]) -> str:
        """Generate human-readable text report."""
        lines = []
        w = 72

        lines.append("=" * w)
        lines.append("  LOG ANALYZER — SECURITY EVENT REPORT")
        lines.append(f"  Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * w)

        # Summary
        lines.append("")
        lines.append("─── SUMMARY ───────────────────────────────────────────────────────")
        lines.append(f"  Total events parsed:      {stats['total_events']}")
        lines.append(f"  Unique source IPs:        {stats['unique_source_ips']}")
        lines.append(f"    ├─ Private:             {stats['private_source_ips']}")
        lines.append(f"    └─ Public:              {stats['public_source_ips']}")
        lines.append(f"  Accepted SSH logins:      {stats['total_accepted_logins']}")
        lines.append("")

        # Severity breakdown
        lines.append("  Severity Breakdown:")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "WARNING", "LOW", "INFO"]:
            count = stats["severity_breakdown"].get(sev, 0)
            if count > 0:
                bar = "█" * min(count, 50)
                lines.append(f"    {sev:<10} {count:>6}  {bar}")
        lines.append("")

        # Event types
        lines.append("  Event Types:")
        for etype, count in sorted(stats["event_types"].items(),
                                   key=lambda x: -x[1]):
            lines.append(f"    {etype:<25} {count:>6}")
        lines.append("")

        # Brute force findings
        lines.append("─── BRUTE FORCE / PASSWORD SPRAY DETECTIONS ────────────────────────")
        if not brute_force:
            lines.append("  No brute force patterns detected.")
        else:
            lines.append(f"  {len(brute_force)} source IP(s) flagged:\n")
            for i, f in enumerate(brute_force, 1):
                sev_icon = {
                    "CRITICAL": "🔴", "HIGH": "🟠",
                    "MEDIUM": "🟡", "LOW": "🔵"
                }.get(f["severity"], "⚪")

                lines.append(f"  [{i}] {sev_icon} {f['severity']} — {f['ip']}")
                lines.append(f"      Attack type:        {f['attack_type']}")
                lines.append(f"      Total failures:     {f['total_failures']}")
                lines.append(f"      Unique users tried: {len(f['unique_users'])}")
                if f["unique_users"][:5]:
                    users_sample = ", ".join(f["unique_users"][:5])
                    if len(f["unique_users"]) > 5:
                        users_sample += f" (+{len(f['unique_users'])-5} more)"
                    lines.append(f"      Users:              {users_sample}")
                lines.append(f"      Rapid fire:         {'Yes ⚡' if f['rapid_fire'] else 'No'}")
                lines.append(f"      Pre-auth disconns:  {f['preauth_disconnects']}")
                lines.append(f"      First seen:         {f['first_seen']}")
                lines.append(f"      Last seen:          {f['last_seen']}")
                if f["possible_compromise"]:
                    lines.append(f"      ⚠️  POSSIBLE COMPROMISE — successful login detected after failures!")
                lines.append("")
        lines.append("")

        # Top offending IPs
        lines.append("─── TOP OFFENDING IPs ──────────────────────────────────────────────")
        if stats["top_offending_ips"]:
            max_count = stats["top_offending_ips"][0][1] if stats["top_offending_ips"] else 1
            for ip, count in stats["top_offending_ips"][:15]:
                bar_len = int((count / max_count) * 30)
                bar = "█" * bar_len
                lines.append(f"  {ip:<18} {count:>5}  {bar}")
        else:
            lines.append("  No failed authentication attempts found.")
        lines.append("")

        # Top targeted users
        lines.append("─── TOP TARGETED USERS ─────────────────────────────────────────────")
        if stats["top_targeted_users"]:
            max_count = stats["top_targeted_users"][0][1] if stats["top_targeted_users"] else 1
            for user, count in stats["top_targeted_users"][:15]:
                bar_len = int((count / max_count) * 30)
                bar = "█" * bar_len
                lines.append(f"  {user:<18} {count:>5}  {bar}")
        else:
            lines.append("  No targeted users found.")
        lines.append("")

        # Suspicious sudo
        lines.append("─── SUSPICIOUS SUDO ACTIVITY ───────────────────────────────────────")
        if not suspicious_sudo:
            lines.append("  No suspicious sudo activity detected.")
        else:
            for s in suspicious_sudo[:20]:
                lines.append(f"  [{s['severity']}] {s['timestamp']} — "
                             f"user={s['user']} — {s['event']}")
                lines.append(f"    Detail: {s['detail'][:100]}")
        lines.append("")

        # Recommendations
        lines.append("─── RECOMMENDATIONS ────────────────────────────────────────────────")
        recs = self._generate_recommendations(stats, brute_force, suspicious_sudo)
        for i, rec in enumerate(recs, 1):
            lines.append(f"  {i}. {rec}")
        lines.append("")
        lines.append("=" * w)

        return "\n".join(lines)

    def _generate_recommendations(self, stats: dict, brute_force: List[dict],
                                  suspicious_sudo: List[dict]) -> List[str]:
        """Generate actionable security recommendations based on findings."""
        recs = []

        compromised = [f for f in brute_force if f.get("possible_compromise")]
        if compromised:
            ips = ", ".join(f["ip"] for f in compromised)
            recs.append(
                f"🚨 URGENT: Investigate possible compromise from {ips}. "
                f"Check for unauthorized access, review session logs, "
                f"rotate credentials immediately."
            )

        critical = [f for f in brute_force if f["severity"] == "CRITICAL"]
        if critical:
            ips = ", ".join(f["ip"] for f in critical[:5])
            recs.append(
                f"Block the following IPs at the firewall: {ips}"
            )

        if stats["public_source_ips"] > 10:
            recs.append(
                "High volume of external attackers. Consider implementing "
                "fail2ban, rate limiting, or geo-blocking if applicable."
            )

        if any(f["password_spray"] for f in brute_force):
            recs.append(
                "Password spray detected. Enforce strong password policies "
                "and consider multi-factor authentication for SSH."
            )

        if stats["total_accepted_logins"] > 0 and stats["unique_source_ips"] > 20:
            recs.append(
                "Consider restricting SSH access to known IPs via "
                "AllowUsers/AllowGroups in sshd_config or firewall rules."
            )

        if suspicious_sudo:
            recs.append(
                "Review sudo policies. Suspicious privilege escalation "
                "attempts detected — verify all sudoers entries."
            )

        if not recs:
            recs.append("No critical issues found. Continue monitoring.")

        recs.append(
            "Ensure logs are forwarded to a central SIEM for real-time "
            "alerting and long-term retention."
        )

        return recs


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="log_analyzer",
        description=(
            "Blue Team Log Analyzer — Parse system logs for brute force "
            "attempts, failed logins, anomalous patterns, and suspicious "
            "privilege escalation."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s /var/log/auth.log
  %(prog)s /var/log/auth.log /var/log/auth.log.1 --format json
  %(prog)s /var/log/auth.log --format csv > findings.csv
  %(prog)s /var/log/syslog --verbose --output report.txt
        """,
    )

    parser.add_argument(
        "logfiles", nargs="+", metavar="LOGFILE",
        help="One or more log files to analyze (auth.log, syslog, etc.)"
    )
    parser.add_argument(
        "-f", "--format", choices=["text", "json", "csv"],
        default="text", help="Output format (default: text)"
    )
    parser.add_argument(
        "-o", "--output", metavar="FILE",
        help="Write report to file instead of stdout"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Verbose output during parsing"
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {VERSION}"
    )

    args = parser.parse_args()

    analyzer = LogAnalyzer(verbose=args.verbose)

    total = 0
    for logfile in args.logfiles:
        total += analyzer.parse_file(logfile)

    if total == 0:
        print("[!] No events extracted from the provided log files.",
              file=sys.stderr)
        sys.exit(1)

    report = analyzer.generate_report(format_type=args.format)

    if args.output:
        Path(args.output).write_text(report)
        print(f"[+] Report written to {args.output}")
    else:
        print(report)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Threat Intel Aggregator — Blue Team Toolkit
=============================================
Pull Indicators of Compromise (IOCs) from public threat intelligence feeds:
- CISA Known Exploited Vulnerabilities (KEV) catalog
- abuse.ch URLhaus and ThreatFox
- AlienVault OTX (free tier, optional API key)

Cross-reference IOCs with local logs or IP lists to surface actionable alerts.

Author: Steven Artzt (@stevenartzt)
License: MIT
"""

import argparse
import csv
import datetime
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Feed URLs
# ---------------------------------------------------------------------------

FEEDS = {
    "cisa_kev": {
        "name": "CISA Known Exploited Vulnerabilities",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "type": "json",
        "description": "CISA catalog of actively exploited vulnerabilities",
    },
    "urlhaus_recent": {
        "name": "abuse.ch URLhaus (Recent URLs)",
        "url": "https://urlhaus.abuse.ch/downloads/json_recent/",
        "type": "json_urlhaus",
        "description": "Recently reported malicious URLs",
    },
    "threatfox_iocs": {
        "name": "abuse.ch ThreatFox (Recent IOCs)",
        "url": "https://threatfox.abuse.ch/export/json/recent/",
        "type": "json_threatfox",
        "description": "Recent IOCs from ThreatFox (IPs, domains, hashes)",
    },
    "feodo_blocklist": {
        "name": "abuse.ch Feodo Tracker (Botnet C2)",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        "type": "text_ip_list",
        "description": "Recommended Feodo botnet C2 IP blocklist",
    },
    "sslbl_botnet": {
        "name": "abuse.ch SSL Blacklist (Botnet C2 IPs)",
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
        "type": "csv",
        "description": "SSL certificates associated with botnet C2 servers",
    },
}

# OTX (optional, requires free API key)
OTX_BASE = "https://otx.alienvault.com/api/v1"

# User-Agent for requests
USER_AGENT = f"BlueTeamToolkit-ThreatIntel/{VERSION}"

# Cache directory
CACHE_DIR = Path.home() / ".cache" / "blue-team-toolkit" / "threat-intel"
CACHE_MAX_AGE = 3600  # 1 hour default


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _fetch_url(url: str, method: str = "GET", data: Optional[bytes] = None,
               headers: Optional[dict] = None,
               timeout: float = 30.0) -> Optional[bytes]:
    """Fetch a URL with error handling and User-Agent."""
    req_headers = {"User-Agent": USER_AGENT}
    if headers:
        req_headers.update(headers)

    req = urllib.request.Request(url, data=data, headers=req_headers,
                                method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.HTTPError as e:
        print(f"  [!] HTTP {e.code} from {url}", file=sys.stderr)
        return None
    except (urllib.error.URLError, OSError) as e:
        print(f"  [!] Connection error for {url}: {e}", file=sys.stderr)
        return None


def _fetch_cached(url: str, feed_name: str, max_age: int = CACHE_MAX_AGE,
                  method: str = "GET", data: Optional[bytes] = None,
                  headers: Optional[dict] = None) -> Optional[bytes]:
    """Fetch with local filesystem cache."""
    cache_file = CACHE_DIR / f"{feed_name}.cache"
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    # Check cache
    if cache_file.exists():
        age = time.time() - cache_file.stat().st_mtime
        if age < max_age:
            return cache_file.read_bytes()

    # Fetch fresh
    raw = _fetch_url(url, method=method, data=data, headers=headers)
    if raw:
        cache_file.write_bytes(raw)
    return raw


# ---------------------------------------------------------------------------
# Feed parsers
# ---------------------------------------------------------------------------

class IOC:
    """Represents a single Indicator of Compromise."""
    __slots__ = ("ioc_type", "value", "source", "description",
                 "severity", "tags", "timestamp", "reference")

    def __init__(self, ioc_type: str, value: str, source: str,
                 description: str = "", severity: str = "MEDIUM",
                 tags: Optional[List[str]] = None,
                 timestamp: str = "", reference: str = ""):
        self.ioc_type = ioc_type       # ip, domain, url, hash, cve
        self.value = value
        self.source = source
        self.description = description
        self.severity = severity
        self.tags = tags or []
        self.timestamp = timestamp
        self.reference = reference

    def to_dict(self) -> dict:
        return {
            "ioc_type": self.ioc_type,
            "value": self.value,
            "source": self.source,
            "description": self.description,
            "severity": self.severity,
            "tags": self.tags,
            "timestamp": self.timestamp,
            "reference": self.reference,
        }


def parse_cisa_kev(raw: bytes) -> List[IOC]:
    """Parse CISA Known Exploited Vulnerabilities catalog."""
    iocs = []
    try:
        data = json.loads(raw)
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cveID", "")
            vendor = vuln.get("vendorProject", "")
            product = vuln.get("product", "")
            name = vuln.get("vulnerabilityName", "")
            action = vuln.get("requiredAction", "")
            due = vuln.get("dueDate", "")
            added = vuln.get("dateAdded", "")
            known_ransomware = vuln.get("knownRansomwareCampaignUse", "Unknown")

            severity = "CRITICAL" if known_ransomware == "Known" else "HIGH"

            iocs.append(IOC(
                ioc_type="cve",
                value=cve,
                source="CISA KEV",
                description=f"{vendor} {product}: {name}",
                severity=severity,
                tags=[vendor, product] + (["ransomware"] if known_ransomware == "Known" else []),
                timestamp=added,
                reference=f"Required action: {action} (due: {due})",
            ))
    except (json.JSONDecodeError, KeyError) as e:
        print(f"  [!] Failed to parse CISA KEV: {e}", file=sys.stderr)

    return iocs


def parse_urlhaus_recent(raw: bytes) -> List[IOC]:
    """Parse abuse.ch URLhaus recent URLs (json_recent download format)."""
    iocs = []
    try:
        data = json.loads(raw)
        # New format: dict of id -> [entry] (from /downloads/json_recent/)
        if isinstance(data, dict):
            for entry_id, entries in data.items():
                if not isinstance(entries, list):
                    continue
                for entry in entries:
                    url = entry.get("url", "")
                    threat = entry.get("threat", "")
                    status = entry.get("url_status", "")
                    tags = entry.get("tags") or []
                    date_added = entry.get("dateadded", "")

                    if status == "offline":
                        continue  # Skip offline URLs

                    iocs.append(IOC(
                        ioc_type="url",
                        value=url,
                        source="URLhaus",
                        description=f"Threat: {threat}" if threat else "Malicious URL",
                        severity="HIGH",
                        tags=tags if isinstance(tags, list) else [],
                        timestamp=date_added,
                    ))
        # Legacy format: list of entries
        elif isinstance(data, list):
            for entry in data:
                url = entry.get("url", "")
                threat = entry.get("threat", "")
                status = entry.get("url_status", "")
                tags = entry.get("tags") or []
                date_added = entry.get("date_added", entry.get("dateadded", ""))

                if status == "offline":
                    continue

                iocs.append(IOC(
                    ioc_type="url",
                    value=url,
                    source="URLhaus",
                    description=f"Threat: {threat}" if threat else "Malicious URL",
                    severity="HIGH",
                    tags=tags if isinstance(tags, list) else [],
                    timestamp=date_added,
                ))
    except (json.JSONDecodeError, KeyError) as e:
        print(f"  [!] Failed to parse URLhaus: {e}", file=sys.stderr)

    return iocs


def parse_threatfox_iocs(raw: bytes) -> List[IOC]:
    """Parse abuse.ch ThreatFox IOCs (export/json/recent format)."""
    iocs = []
    try:
        data = json.loads(raw)
        
        # New format: dict of id -> [entry] (from /export/json/recent/)
        if isinstance(data, dict) and "query_status" not in data:
            for entry_id, entries in data.items():
                if not isinstance(entries, list):
                    continue
                for entry in entries:
                    ioc_value = entry.get("ioc_value", entry.get("ioc", ""))
                    ioc_type_raw = entry.get("ioc_type", "")
                    threat = entry.get("threat_type", "")
                    malware = entry.get("malware_printable", "")
                    confidence = entry.get("confidence_level", 0)
                    tags_raw = entry.get("tags") or ""
                    tags = tags_raw.split(",") if isinstance(tags_raw, str) else (tags_raw or [])
                    first_seen = entry.get("first_seen_utc", "")
                    reference = entry.get("reference", "")

                    # Map ThreatFox types to our types
                    type_map = {
                        "ip:port": "ip",
                        "domain": "domain",
                        "url": "url",
                        "md5_hash": "hash",
                        "sha256_hash": "hash",
                    }
                    ioc_type = type_map.get(ioc_type_raw, "other")

                    # Strip port from ip:port
                    if ioc_type == "ip" and ":" in ioc_value:
                        ioc_value = ioc_value.split(":")[0]

                    severity = "HIGH" if confidence >= 75 else "MEDIUM"

                    iocs.append(IOC(
                        ioc_type=ioc_type,
                        value=ioc_value,
                        source="ThreatFox",
                        description=f"{threat}: {malware}" if malware else threat,
                        severity=severity,
                        tags=[t.strip() for t in tags if t.strip()],
                        timestamp=first_seen,
                        reference=reference or "",
                    ))
        # Legacy API format
        elif isinstance(data, dict) and data.get("query_status") == "ok":
            for entry in data.get("data", []):
                ioc_value = entry.get("ioc", "")
                ioc_type_raw = entry.get("ioc_type", "")
                threat = entry.get("threat_type", "")
                malware = entry.get("malware_printable", "")
                confidence = entry.get("confidence_level", 0)
                tags = entry.get("tags") or []
                first_seen = entry.get("first_seen_utc", "")
                reference = entry.get("reference", "")

                type_map = {
                    "ip:port": "ip",
                    "domain": "domain",
                    "url": "url",
                    "md5_hash": "hash",
                    "sha256_hash": "hash",
                }
                ioc_type = type_map.get(ioc_type_raw, "other")

                if ioc_type == "ip" and ":" in ioc_value:
                    ioc_value = ioc_value.split(":")[0]

                severity = "HIGH" if confidence >= 75 else "MEDIUM"

                iocs.append(IOC(
                    ioc_type=ioc_type,
                    value=ioc_value,
                    source="ThreatFox",
                    description=f"{threat}: {malware}" if malware else threat,
                    severity=severity,
                    tags=tags if isinstance(tags, list) else [],
                    timestamp=first_seen,
                    reference=reference or "",
                ))
    except (json.JSONDecodeError, KeyError) as e:
        print(f"  [!] Failed to parse ThreatFox: {e}", file=sys.stderr)

    return iocs


def parse_feodo_blocklist(raw: bytes) -> List[IOC]:
    """Parse Feodo Tracker IP blocklist."""
    iocs = []
    for line in raw.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Validate IP
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", line):
            iocs.append(IOC(
                ioc_type="ip",
                value=line,
                source="Feodo Tracker",
                description="Botnet C2 server",
                severity="HIGH",
                tags=["botnet", "c2"],
            ))
    return iocs


def parse_sslbl_csv(raw: bytes) -> List[IOC]:
    """Parse SSL Blacklist CSV."""
    iocs = []
    text = raw.decode("utf-8", errors="replace")
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) >= 3:
            timestamp = parts[0].strip()
            ip = parts[1].strip()
            port = parts[2].strip() if len(parts) > 2 else ""

            if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                iocs.append(IOC(
                    ioc_type="ip",
                    value=ip,
                    source="SSL Blacklist",
                    description=f"Botnet C2 (port {port})" if port else "Botnet C2",
                    severity="HIGH",
                    tags=["botnet", "c2", "ssl"],
                    timestamp=timestamp,
                ))
    return iocs


# Feed parser dispatch
FEED_PARSERS = {
    "cisa_kev": parse_cisa_kev,
    "urlhaus_recent": parse_urlhaus_recent,
    "threatfox_iocs": parse_threatfox_iocs,
    "feodo_blocklist": parse_feodo_blocklist,
    "sslbl_botnet": parse_sslbl_csv,
}


# ---------------------------------------------------------------------------
# AlienVault OTX
# ---------------------------------------------------------------------------

def fetch_otx_pulses(api_key: str, days: int = 7,
                     limit: int = 50) -> List[IOC]:
    """Fetch recent pulses from AlienVault OTX."""
    iocs = []
    since = (datetime.datetime.utcnow() -
             datetime.timedelta(days=days)).strftime("%Y-%m-%dT00:00:00")

    url = (f"{OTX_BASE}/pulses/subscribed"
           f"?modified_since={since}&limit={limit}")

    raw = _fetch_url(url, headers={"X-OTX-API-KEY": api_key})
    if not raw:
        return iocs

    try:
        data = json.loads(raw)
        for pulse in data.get("results", []):
            pulse_name = pulse.get("name", "Unknown Pulse")
            pulse_tags = pulse.get("tags", [])
            created = pulse.get("created", "")

            for indicator in pulse.get("indicators", []):
                ind_type = indicator.get("type", "")
                ind_value = indicator.get("indicator", "")

                # Map OTX types
                type_map = {
                    "IPv4": "ip", "IPv6": "ip",
                    "domain": "domain", "hostname": "domain",
                    "URL": "url",
                    "FileHash-MD5": "hash", "FileHash-SHA1": "hash",
                    "FileHash-SHA256": "hash",
                    "CVE": "cve",
                    "email": "email",
                }
                ioc_type = type_map.get(ind_type, "other")

                iocs.append(IOC(
                    ioc_type=ioc_type,
                    value=ind_value,
                    source="AlienVault OTX",
                    description=pulse_name,
                    severity="MEDIUM",
                    tags=pulse_tags[:5],
                    timestamp=created,
                ))
    except (json.JSONDecodeError, KeyError) as e:
        print(f"  [!] Failed to parse OTX: {e}", file=sys.stderr)

    return iocs


# ---------------------------------------------------------------------------
# Cross-referencing
# ---------------------------------------------------------------------------

def extract_ips_from_log(filepath: str) -> Set[str]:
    """Extract all IP addresses from a log file."""
    ips = set()
    ip_pattern = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

    try:
        with open(filepath, "r", errors="replace") as fh:
            for line in fh:
                for match in ip_pattern.finditer(line):
                    ip = match.group(1)
                    # Basic validation
                    octets = ip.split(".")
                    if all(0 <= int(o) <= 255 for o in octets):
                        ips.add(ip)
    except (FileNotFoundError, PermissionError) as e:
        print(f"  [!] Could not read {filepath}: {e}", file=sys.stderr)

    return ips


def extract_domains_from_log(filepath: str) -> Set[str]:
    """Extract domain-like strings from a log file."""
    domains = set()
    domain_pattern = re.compile(
        r"\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
        r"(?:\.[a-zA-Z]{2,})+)\b"
    )

    try:
        with open(filepath, "r", errors="replace") as fh:
            for line in fh:
                for match in domain_pattern.finditer(line):
                    domains.add(match.group(1).lower())
    except (FileNotFoundError, PermissionError) as e:
        print(f"  [!] Could not read {filepath}: {e}", file=sys.stderr)

    return domains


def load_ip_list(filepath: str) -> Set[str]:
    """Load IPs from a plain text file (one per line)."""
    ips = set()
    try:
        with open(filepath) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", line):
                        ips.add(line)
    except (FileNotFoundError, PermissionError) as e:
        print(f"  [!] Could not read {filepath}: {e}", file=sys.stderr)
    return ips


def cross_reference(iocs: List[IOC], local_ips: Set[str],
                    local_domains: Set[str]) -> List[dict]:
    """
    Cross-reference IOCs with local data.

    Returns list of matches with context.
    """
    matches = []

    # Build lookup sets
    ioc_ips = {}
    ioc_domains = {}
    for ioc in iocs:
        if ioc.ioc_type == "ip":
            ioc_ips.setdefault(ioc.value, []).append(ioc)
        elif ioc.ioc_type == "domain":
            ioc_domains.setdefault(ioc.value.lower(), []).append(ioc)

    # Check IPs
    for ip in local_ips:
        if ip in ioc_ips:
            for ioc in ioc_ips[ip]:
                matches.append({
                    "match_type": "IP",
                    "value": ip,
                    "source": ioc.source,
                    "description": ioc.description,
                    "severity": ioc.severity,
                    "tags": ioc.tags,
                    "reference": ioc.reference,
                })

    # Check domains
    for domain in local_domains:
        if domain in ioc_domains:
            for ioc in ioc_domains[domain]:
                matches.append({
                    "match_type": "Domain",
                    "value": domain,
                    "source": ioc.source,
                    "description": ioc.description,
                    "severity": ioc.severity,
                    "tags": ioc.tags,
                    "reference": ioc.reference,
                })

    # Sort by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    matches.sort(key=lambda m: sev_order.get(m["severity"], 4))

    return matches


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def format_ioc_summary(iocs: List[IOC], format_type: str = "text") -> str:
    """Format IOC collection summary."""
    if format_type == "json":
        return json.dumps({
            "total_iocs": len(iocs),
            "by_type": _count_by(iocs, "ioc_type"),
            "by_source": _count_by(iocs, "source"),
            "by_severity": _count_by(iocs, "severity"),
            "iocs": [i.to_dict() for i in iocs[:500]],  # Limit output
            "fetched_at": datetime.datetime.now().isoformat(),
        }, indent=2)

    return _format_text_summary(iocs)


def _count_by(iocs: List[IOC], attr: str) -> dict:
    from collections import Counter
    return dict(Counter(getattr(i, attr) for i in iocs).most_common())


def _format_text_summary(iocs: List[IOC]) -> str:
    """Generate human-readable IOC summary."""
    from collections import Counter
    lines = []
    w = 72

    lines.append("=" * w)
    lines.append("  THREAT INTELLIGENCE — IOC SUMMARY")
    lines.append(f"  Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * w)

    # Totals
    lines.append("")
    lines.append(f"  Total IOCs collected: {len(iocs)}")
    lines.append("")

    # By source
    source_counts = Counter(i.source for i in iocs)
    lines.append("─── BY SOURCE ──────────────────────────────────────────────────────")
    for source, count in source_counts.most_common():
        lines.append(f"  {source:<35} {count:>6}")
    lines.append("")

    # By type
    type_counts = Counter(i.ioc_type for i in iocs)
    lines.append("─── BY TYPE ────────────────────────────────────────────────────────")
    for itype, count in type_counts.most_common():
        lines.append(f"  {itype:<35} {count:>6}")
    lines.append("")

    # By severity
    sev_counts = Counter(i.severity for i in iocs)
    lines.append("─── BY SEVERITY ────────────────────────────────────────────────────")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = sev_counts.get(sev, 0)
        if count:
            lines.append(f"  {sev:<35} {count:>6}")
    lines.append("")

    # Recent CISA KEV highlights (last 10 added)
    cisa = [i for i in iocs if i.source == "CISA KEV"]
    if cisa:
        cisa.sort(key=lambda x: x.timestamp, reverse=True)
        lines.append("─── CISA KEV — RECENT ADDITIONS ────────────────────────────────────")
        for kev in cisa[:10]:
            ransomware = "🔴 RANSOMWARE" if "ransomware" in kev.tags else ""
            lines.append(f"  {kev.value:<20} {kev.description[:45]}")
            if ransomware:
                lines.append(f"  {'':>20} {ransomware}")
        lines.append("")

    # Recent C2 IPs
    c2_ips = [i for i in iocs if i.ioc_type == "ip" and "c2" in i.tags]
    if c2_ips:
        lines.append("─── ACTIVE BOTNET C2 IPs (SAMPLE) ──────────────────────────────────")
        for ip_ioc in c2_ips[:15]:
            lines.append(f"  {ip_ioc.value:<18} {ip_ioc.source:<20} {ip_ioc.description[:30]}")
        if len(c2_ips) > 15:
            lines.append(f"  ... and {len(c2_ips) - 15} more")
        lines.append("")

    lines.append("=" * w)
    return "\n".join(lines)


def format_crossref_report(matches: List[dict], format_type: str = "text") -> str:
    """Format cross-reference results."""
    if format_type == "json":
        return json.dumps({
            "total_matches": len(matches),
            "matches": matches,
            "checked_at": datetime.datetime.now().isoformat(),
        }, indent=2)

    lines = []
    w = 72

    lines.append("=" * w)
    lines.append("  THREAT INTEL — CROSS-REFERENCE RESULTS")
    lines.append(f"  Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * w)
    lines.append("")

    if not matches:
        lines.append("  ✓ No matches found — your local indicators are clean.")
        lines.append("")
        lines.append("=" * w)
        return "\n".join(lines)

    lines.append(f"  ⚠️  {len(matches)} MATCH(ES) FOUND!\n")

    for i, m in enumerate(matches, 1):
        sev_icon = {
            "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"
        }.get(m["severity"], "⚪")

        lines.append(f"  [{i}] {sev_icon} {m['severity']} — {m['match_type']}: {m['value']}")
        lines.append(f"      Source:      {m['source']}")
        lines.append(f"      Description: {m['description'][:60]}")
        if m.get("tags"):
            lines.append(f"      Tags:        {', '.join(m['tags'][:5])}")
        if m.get("reference"):
            lines.append(f"      Reference:   {m['reference'][:60]}")
        lines.append("")

    lines.append("─── RECOMMENDED ACTIONS ────────────────────────────────────────────")
    critical = [m for m in matches if m["severity"] in ("CRITICAL", "HIGH")]
    if critical:
        lines.append(f"  1. IMMEDIATE: Block {len(critical)} high-severity indicator(s)")
        lines.append("  2. Investigate affected systems for signs of compromise")
        lines.append("  3. Check network logs for communication with flagged IPs/domains")
        lines.append("  4. Rotate credentials on any affected services")
    else:
        lines.append("  1. Monitor flagged indicators for repeated occurrences")
        lines.append("  2. Add to local blocklists as a precaution")

    lines.append("")
    lines.append("=" * w)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main aggregation
# ---------------------------------------------------------------------------

class ThreatIntelAggregator:
    """
    Aggregates IOCs from multiple threat intelligence feeds.
    """

    def __init__(self, feeds: Optional[List[str]] = None,
                 otx_key: Optional[str] = None,
                 cache_age: int = CACHE_MAX_AGE,
                 verbose: bool = False):
        self.feed_names = feeds or list(FEEDS.keys())
        self.otx_key = otx_key
        self.cache_age = cache_age
        self.verbose = verbose
        self.iocs: List[IOC] = []

    def collect(self) -> List[IOC]:
        """Fetch and parse all configured feeds."""
        self.iocs = []

        for feed_name in self.feed_names:
            if feed_name not in FEEDS:
                print(f"  [!] Unknown feed: {feed_name}", file=sys.stderr)
                continue

            feed = FEEDS[feed_name]
            if self.verbose:
                print(f"[*] Fetching {feed['name']}...")

            # Determine fetch method
            method = "GET"
            data = None
            headers = None

            if feed["type"] == "json_post":
                method = "POST"
                post_data = feed.get("post_data", "")
                if post_data:
                    data = post_data.encode("utf-8")
                headers = {"Content-Type": "application/json"}

            raw = _fetch_cached(
                feed["url"], feed_name, self.cache_age,
                method=method, data=data, headers=headers
            )

            if raw is None:
                print(f"  [!] Failed to fetch {feed['name']}", file=sys.stderr)
                continue

            parser = FEED_PARSERS.get(feed_name)
            if parser:
                parsed = parser(raw)
                self.iocs.extend(parsed)
                if self.verbose:
                    print(f"  [+] {feed['name']}: {len(parsed)} IOCs")

        # OTX (optional)
        if self.otx_key:
            if self.verbose:
                print("[*] Fetching AlienVault OTX pulses...")
            otx_iocs = fetch_otx_pulses(self.otx_key)
            self.iocs.extend(otx_iocs)
            if self.verbose:
                print(f"  [+] OTX: {len(otx_iocs)} IOCs")

        if self.verbose:
            print(f"\n[+] Total: {len(self.iocs)} IOCs collected")

        return self.iocs

    def cross_reference_logs(self, log_files: List[str],
                             ip_files: Optional[List[str]] = None) -> List[dict]:
        """Cross-reference collected IOCs with local log files."""
        local_ips = set()
        local_domains = set()

        for lf in log_files:
            if self.verbose:
                print(f"[*] Extracting indicators from {lf}...")
            local_ips.update(extract_ips_from_log(lf))
            local_domains.update(extract_domains_from_log(lf))

        if ip_files:
            for ipf in ip_files:
                if self.verbose:
                    print(f"[*] Loading IPs from {ipf}...")
                local_ips.update(load_ip_list(ipf))

        if self.verbose:
            print(f"[*] Cross-referencing {len(local_ips)} IPs and "
                  f"{len(local_domains)} domains against {len(self.iocs)} IOCs...")

        return cross_reference(self.iocs, local_ips, local_domains)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="threat_intel",
        description=(
            "Blue Team Threat Intel Aggregator — Pull IOCs from public feeds "
            "(CISA KEV, abuse.ch, AlienVault OTX) and cross-reference with "
            "local logs."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s --collect
  %(prog)s --collect --feeds cisa_kev feodo_blocklist
  %(prog)s --collect --crossref /var/log/auth.log
  %(prog)s --collect --crossref /var/log/auth.log --ip-list suspicious_ips.txt
  %(prog)s --collect --otx-key YOUR_KEY --format json > iocs.json

available feeds:
  cisa_kev        CISA Known Exploited Vulnerabilities catalog
  urlhaus_recent  abuse.ch URLhaus (recent malicious URLs)
  threatfox_iocs  abuse.ch ThreatFox (recent IOCs)
  feodo_blocklist abuse.ch Feodo Tracker (botnet C2 IPs)
  sslbl_botnet    abuse.ch SSL Blacklist (C2 IPs)
        """,
    )

    parser.add_argument(
        "--collect", action="store_true",
        help="Collect IOCs from configured feeds"
    )
    parser.add_argument(
        "--feeds", nargs="+", metavar="FEED",
        help="Specific feeds to query (default: all)"
    )
    parser.add_argument(
        "--crossref", nargs="+", metavar="LOGFILE",
        help="Cross-reference IOCs with local log file(s)"
    )
    parser.add_argument(
        "--ip-list", nargs="+", metavar="FILE",
        help="Additional IP list file(s) to cross-reference"
    )
    parser.add_argument(
        "--otx-key", metavar="KEY",
        default=os.environ.get("OTX_API_KEY"),
        help="AlienVault OTX API key (or set OTX_API_KEY env var)"
    )
    parser.add_argument(
        "--cache-age", type=int, default=CACHE_MAX_AGE,
        help=f"Cache max age in seconds (default: {CACHE_MAX_AGE})"
    )
    parser.add_argument(
        "--no-cache", action="store_true",
        help="Bypass cache, always fetch fresh"
    )
    parser.add_argument(
        "-f", "--format", choices=["text", "json"], default="text",
        help="Output format (default: text)"
    )
    parser.add_argument(
        "-o", "--output", metavar="FILE",
        help="Write output to file"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Verbose output"
    )
    parser.add_argument(
        "--list-feeds", action="store_true",
        help="List available feeds and exit"
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {VERSION}"
    )

    args = parser.parse_args()

    # List feeds
    if args.list_feeds:
        print("Available threat intelligence feeds:\n")
        for name, info in FEEDS.items():
            print(f"  {name:<20} {info['description']}")
        print(f"\n  {'otx':<20} AlienVault OTX (requires free API key)")
        sys.exit(0)

    if not args.collect and not args.crossref:
        parser.error("Specify --collect, --crossref, or both.")

    cache_age = 0 if args.no_cache else args.cache_age

    aggregator = ThreatIntelAggregator(
        feeds=args.feeds,
        otx_key=args.otx_key,
        cache_age=cache_age,
        verbose=args.verbose,
    )

    output_parts = []

    if args.collect:
        iocs = aggregator.collect()
        output_parts.append(format_ioc_summary(iocs, args.format))

    if args.crossref:
        if not aggregator.iocs:
            aggregator.collect()
        matches = aggregator.cross_reference_logs(
            args.crossref, args.ip_list
        )
        output_parts.append(format_crossref_report(matches, args.format))

    result = "\n\n".join(output_parts)

    if args.output:
        Path(args.output).write_text(result)
        print(f"[+] Output written to {args.output}")
    else:
        print(result)


if __name__ == "__main__":
    main()

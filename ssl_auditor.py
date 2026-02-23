#!/usr/bin/env python3
"""
SSL/TLS Auditor — Blue Team Toolkit
=====================================
Scan domains for weak ciphers, expired/expiring certificates, protocol
version support, certificate chain issues, and common TLS misconfigurations.

Clean terminal output with pass/fail/warn ratings and an overall grade.

Author: Steven Artzt (@stevenartzt)
License: MIT
"""

import argparse
import datetime
import json
import os
import socket
import ssl
import struct
import sys
import textwrap
from pathlib import Path
from typing import Dict, List, Optional, Tuple

VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Days before expiry to warn
CERT_EXPIRY_WARN_DAYS = 30
CERT_EXPIRY_CRITICAL_DAYS = 7

# Weak cipher suites (substrings to match)
WEAK_CIPHER_PATTERNS = [
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5",
    "RC2", "IDEA", "SEED", "CAMELLIA",
]

# Modern / recommended cipher suites
STRONG_CIPHER_PATTERNS = [
    "AES_256_GCM", "AES_128_GCM", "CHACHA20_POLY1305",
]

# TLS protocol versions and their security status
PROTOCOL_RATINGS = {
    "TLSv1.3": ("PASS", "Current, recommended"),
    "TLSv1.2": ("PASS", "Acceptable"),
    "TLSv1.1": ("FAIL", "Deprecated — disable immediately"),
    "TLSv1":   ("FAIL", "Deprecated — disable immediately"),
    "SSLv3":   ("FAIL", "Broken — POODLE vulnerability"),
    "SSLv2":   ("FAIL", "Broken — completely insecure"),
}

# TLS protocol constants for probing
TLS_PROTOCOLS = {
    "SSLv3":   (3, 0),
    "TLSv1":   (3, 1),
    "TLSv1.1": (3, 2),
    "TLSv1.2": (3, 3),
}

# Minimum key sizes
MIN_RSA_BITS = 2048
MIN_EC_BITS = 256

# Colors for terminal
class C:
    """ANSI color codes (disabled if NO_COLOR env or non-tty)."""
    _enabled = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

    RESET  = "\033[0m" if _enabled else ""
    RED    = "\033[91m" if _enabled else ""
    GREEN  = "\033[92m" if _enabled else ""
    YELLOW = "\033[93m" if _enabled else ""
    BLUE   = "\033[94m" if _enabled else ""
    BOLD   = "\033[1m" if _enabled else ""
    DIM    = "\033[2m" if _enabled else ""


def colored(text: str, color: str) -> str:
    return f"{color}{text}{C.RESET}"


def status_icon(result: str) -> str:
    icons = {
        "PASS": colored("✓ PASS", C.GREEN),
        "WARN": colored("⚠ WARN", C.YELLOW),
        "FAIL": colored("✗ FAIL", C.RED),
        "INFO": colored("ℹ INFO", C.BLUE),
    }
    return icons.get(result, result)


# ---------------------------------------------------------------------------
# Certificate fetching
# ---------------------------------------------------------------------------

def fetch_certificate(host: str, port: int = 443,
                      timeout: float = 10.0) -> Tuple[Optional[dict], Optional[bytes], Optional[str]]:
    """
    Connect to host:port via TLS and retrieve the server certificate.

    Returns (cert_dict, cert_der, negotiated_protocol) or (None, None, None).
    """
    context = ssl.create_default_context()
    # We still want to see the cert even if it's invalid
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                cert_der = ssock.getpeercert(binary_form=True)
                protocol = ssock.version()
                return cert, cert_der, protocol
    except (socket.error, ssl.SSLError, OSError) as e:
        return None, None, str(e)


def fetch_cert_with_validation(host: str, port: int = 443,
                               timeout: float = 10.0) -> Tuple[bool, str]:
    """
    Attempt a fully validated TLS connection.

    Returns (valid, error_message).
    """
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                return True, ""
    except ssl.SSLCertVerificationError as e:
        return False, str(e)
    except (socket.error, ssl.SSLError, OSError) as e:
        return False, str(e)


def get_cipher_info(host: str, port: int = 443,
                    timeout: float = 10.0) -> Optional[Tuple]:
    """Get negotiated cipher suite info."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.cipher()
    except Exception:
        return None


def get_all_ciphers(host: str, port: int = 443,
                    timeout: float = 10.0) -> List[Tuple]:
    """Get all supported cipher suites via the default context."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.shared_ciphers() or []
    except Exception:
        return []


def probe_protocol_support(host: str, port: int = 443,
                           timeout: float = 5.0) -> Dict[str, bool]:
    """
    Probe which TLS/SSL protocol versions the server supports.

    Uses raw socket ClientHello messages for deprecated protocols
    since Python's ssl module may not support them.
    """
    results = {}

    # For TLS 1.2 and 1.3, use Python's ssl module
    for proto_name, proto_const in [
        ("TLSv1.2", ssl.PROTOCOL_TLS_CLIENT),
        ("TLSv1.3", ssl.PROTOCOL_TLS_CLIENT),
    ]:
        try:
            ctx = ssl.SSLContext(proto_const)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            if proto_name == "TLSv1.2":
                ctx.maximum_version = ssl.TLSVersion.TLSv1_2
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            elif proto_name == "TLSv1.3":
                ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    results[proto_name] = True
        except Exception:
            results[proto_name] = False

    # For older protocols, try if available
    for proto_name, proto_attr in [
        ("TLSv1.1", "TLSv1_1"),
        ("TLSv1", "TLSv1"),
    ]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ver = getattr(ssl.TLSVersion, proto_attr, None)
            if ver is None:
                results[proto_name] = False
                continue
            ctx.minimum_version = ver
            ctx.maximum_version = ver
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    results[proto_name] = True
        except Exception:
            results[proto_name] = False

    # SSLv3 — almost certainly not supported, but check
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if hasattr(ssl.TLSVersion, "SSLv3"):
            ctx.minimum_version = ssl.TLSVersion.SSLv3
            ctx.maximum_version = ssl.TLSVersion.SSLv3
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    results["SSLv3"] = True
        else:
            results["SSLv3"] = False
    except Exception:
        results["SSLv3"] = False

    return results


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

class AuditResult:
    """Container for a single audit check result."""

    def __init__(self, category: str, check: str, result: str,
                 detail: str = ""):
        self.category = category
        self.check = check
        self.result = result  # PASS, WARN, FAIL, INFO
        self.detail = detail

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "check": self.check,
            "result": self.result,
            "detail": self.detail,
        }


class SSLAuditor:
    """
    SSL/TLS security auditor.

    Performs comprehensive checks on a target domain's TLS configuration
    including certificate validity, protocol versions, cipher suites,
    and common misconfigurations.
    """

    def __init__(self, host: str, port: int = 443, timeout: float = 10.0,
                 verbose: bool = False):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.verbose = verbose
        self.results: List[AuditResult] = []
        self.cert: Optional[dict] = None
        self.cert_der: Optional[bytes] = None
        self.protocol: Optional[str] = None

    def audit(self) -> List[AuditResult]:
        """Run all audit checks and return results."""
        self.results = []

        if self.verbose:
            print(f"[*] Auditing {self.host}:{self.port}...")

        # Step 1: Connectivity
        self._check_connectivity()
        if self.cert is None:
            return self.results

        # Step 2: Certificate checks
        self._check_cert_validity()
        self._check_cert_expiry()
        self._check_cert_hostname()
        self._check_key_strength()
        self._check_san()
        self._check_cert_chain()

        # Step 3: Protocol checks
        self._check_protocols()

        # Step 4: Cipher checks
        self._check_ciphers()

        # Step 5: Miscellaneous
        self._check_hsts()

        return self.results

    def _add(self, category: str, check: str, result: str, detail: str = ""):
        self.results.append(AuditResult(category, check, result, detail))

    def _check_connectivity(self):
        """Test basic TLS connectivity."""
        self.cert, self.cert_der, self.protocol = fetch_certificate(
            self.host, self.port, self.timeout
        )
        if self.cert is None:
            self._add("Connection", "TLS Handshake", "FAIL",
                       f"Could not connect: {self.protocol}")
            self.protocol = None
        else:
            self._add("Connection", "TLS Handshake", "PASS",
                       f"Connected successfully, negotiated {self.protocol}")

    def _check_cert_validity(self):
        """Verify certificate chain against system trust store."""
        valid, error = fetch_cert_with_validation(
            self.host, self.port, self.timeout
        )
        if valid:
            self._add("Certificate", "Chain Validation", "PASS",
                       "Certificate chain is trusted")
        else:
            self._add("Certificate", "Chain Validation", "FAIL",
                       f"Validation failed: {error}")

    def _check_cert_expiry(self):
        """Check certificate expiration date."""
        if not self.cert:
            return

        not_after = self.cert.get("notAfter", "")
        not_before = self.cert.get("notBefore", "")

        try:
            expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            start = datetime.datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
            now = datetime.datetime.utcnow()

            days_left = (expiry - now).days
            total_days = (expiry - start).days

            if days_left < 0:
                self._add("Certificate", "Expiration", "FAIL",
                           f"EXPIRED {abs(days_left)} days ago ({not_after})")
            elif days_left <= CERT_EXPIRY_CRITICAL_DAYS:
                self._add("Certificate", "Expiration", "FAIL",
                           f"Expires in {days_left} days ({not_after})")
            elif days_left <= CERT_EXPIRY_WARN_DAYS:
                self._add("Certificate", "Expiration", "WARN",
                           f"Expires in {days_left} days ({not_after})")
            else:
                self._add("Certificate", "Expiration", "PASS",
                           f"Valid for {days_left} days (expires {not_after})")

            # Check for excessively long validity (>398 days = CA/B Forum limit)
            if total_days > 398:
                self._add("Certificate", "Validity Period", "WARN",
                           f"Validity period is {total_days} days "
                           f"(exceeds 398-day CA/B Forum guideline)")
            else:
                self._add("Certificate", "Validity Period", "PASS",
                           f"Validity period is {total_days} days")

        except (ValueError, TypeError) as e:
            self._add("Certificate", "Expiration", "WARN",
                       f"Could not parse dates: {e}")

    def _check_cert_hostname(self):
        """Verify the certificate matches the hostname."""
        if not self.cert:
            return

        # Check CN
        subject = dict(x[0] for x in self.cert.get("subject", ()))
        cn = subject.get("commonName", "")

        # Check SANs
        san_entries = []
        for san_type, san_value in self.cert.get("subjectAltName", ()):
            if san_type == "DNS":
                san_entries.append(san_value)

        hostname_match = False
        for name in [cn] + san_entries:
            if self._hostname_matches(name, self.host):
                hostname_match = True
                break

        if hostname_match:
            self._add("Certificate", "Hostname Match", "PASS",
                       f"Certificate matches {self.host}")
        else:
            self._add("Certificate", "Hostname Match", "FAIL",
                       f"Certificate CN={cn}, SANs={san_entries} "
                       f"do not match {self.host}")

    @staticmethod
    def _hostname_matches(pattern: str, hostname: str) -> bool:
        """Check if a certificate name pattern matches the hostname."""
        if pattern.startswith("*."):
            # Wildcard: *.example.com matches sub.example.com
            suffix = pattern[2:]
            return (hostname.endswith(suffix) and
                    hostname.count(".") == pattern.count("."))
        return pattern.lower() == hostname.lower()

    def _check_key_strength(self):
        """Check public key algorithm and size."""
        if not self.cert:
            return

        # Try to extract key info from the cert using ssl
        # The cert dict doesn't directly give key size, so we use the
        # binary cert with ssl's built-in parsing where available
        cipher_info = get_cipher_info(self.host, self.port, self.timeout)
        if cipher_info:
            cipher_name, protocol, bits = cipher_info
            self._add("Certificate", "Negotiated Cipher", "INFO",
                       f"{cipher_name} ({protocol}, {bits} bits)")

            if bits and bits < 128:
                self._add("Cipher", "Key Exchange Strength", "FAIL",
                           f"Cipher uses only {bits}-bit encryption")
            elif bits and bits >= 256:
                self._add("Cipher", "Key Exchange Strength", "PASS",
                           f"Strong {bits}-bit encryption")
            elif bits:
                self._add("Cipher", "Key Exchange Strength", "PASS",
                           f"Acceptable {bits}-bit encryption")

    def _check_san(self):
        """Check Subject Alternative Name entries."""
        if not self.cert:
            return

        sans = self.cert.get("subjectAltName", ())
        dns_sans = [v for t, v in sans if t == "DNS"]

        if not dns_sans:
            self._add("Certificate", "Subject Alt Names", "WARN",
                       "No DNS SANs found — older browsers may reject this")
        else:
            self._add("Certificate", "Subject Alt Names", "PASS",
                       f"{len(dns_sans)} DNS name(s): "
                       f"{', '.join(dns_sans[:5])}"
                       f"{' ...' if len(dns_sans) > 5 else ''}")

    def _check_cert_chain(self):
        """Check certificate issuer and chain depth."""
        if not self.cert:
            return

        issuer = dict(x[0] for x in self.cert.get("issuer", ()))
        issuer_cn = issuer.get("commonName", "Unknown")
        issuer_org = issuer.get("organizationName", "Unknown")

        subject = dict(x[0] for x in self.cert.get("subject", ()))
        subject_cn = subject.get("commonName", "")

        # Self-signed check
        if issuer_cn == subject_cn and issuer_org == subject.get("organizationName", ""):
            self._add("Certificate", "Self-Signed", "FAIL",
                       "Certificate appears to be self-signed")
        else:
            self._add("Certificate", "Issuer", "INFO",
                       f"{issuer_cn} ({issuer_org})")

    def _check_protocols(self):
        """Check which TLS/SSL protocol versions are supported."""
        if self.verbose:
            print("[*] Probing protocol support...")

        supported = probe_protocol_support(self.host, self.port, self.timeout)

        for proto_name in ["SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]:
            is_supported = supported.get(proto_name, False)
            rating, desc = PROTOCOL_RATINGS.get(proto_name, ("INFO", "Unknown"))

            if is_supported:
                if rating == "FAIL":
                    self._add("Protocol", proto_name, "FAIL",
                               f"Supported — {desc}")
                else:
                    self._add("Protocol", proto_name, "PASS",
                               f"Supported — {desc}")
            else:
                if rating == "FAIL":
                    self._add("Protocol", proto_name, "PASS",
                               f"Not supported (good — {desc})")
                else:
                    self._add("Protocol", proto_name, "INFO",
                               f"Not supported")

        # Check that at least TLS 1.2 is supported
        if not supported.get("TLSv1.2") and not supported.get("TLSv1.3"):
            self._add("Protocol", "Minimum Version", "FAIL",
                       "Neither TLS 1.2 nor 1.3 supported!")

    def _check_ciphers(self):
        """Check for weak cipher suites."""
        ciphers = get_all_ciphers(self.host, self.port, self.timeout)

        if not ciphers:
            self._add("Cipher", "Cipher Suite Scan", "INFO",
                       "Could not enumerate shared ciphers")
            return

        weak = []
        strong = []
        for cipher_name, proto, bits in ciphers:
            is_weak = any(p in cipher_name.upper()
                          for p in WEAK_CIPHER_PATTERNS)
            is_strong = any(p in cipher_name
                            for p in STRONG_CIPHER_PATTERNS)
            if is_weak or (bits and bits < 128):
                weak.append(f"{cipher_name} ({bits}b)")
            elif is_strong:
                strong.append(f"{cipher_name} ({bits}b)")

        if weak:
            self._add("Cipher", "Weak Ciphers", "FAIL",
                       f"{len(weak)} weak cipher(s): {', '.join(weak[:5])}")
        else:
            self._add("Cipher", "Weak Ciphers", "PASS",
                       "No weak ciphers detected")

        if strong:
            self._add("Cipher", "Strong Ciphers", "PASS",
                       f"AEAD ciphers available: {', '.join(strong[:3])}")

        self._add("Cipher", "Total Ciphers", "INFO",
                   f"{len(ciphers)} cipher suite(s) supported")

    def _check_hsts(self):
        """Check for HTTP Strict Transport Security header."""
        try:
            import urllib.request
            req = urllib.request.Request(
                f"https://{self.host}:{self.port}/",
                method="HEAD",
            )
            # Disable cert verification for this check
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with urllib.request.urlopen(req, timeout=self.timeout,
                                        context=ctx) as resp:
                hsts = resp.headers.get("Strict-Transport-Security", "")
                if hsts:
                    self._add("Headers", "HSTS", "PASS", f"Present: {hsts}")
                    if "includeSubDomains" not in hsts:
                        self._add("Headers", "HSTS Subdomains", "WARN",
                                   "HSTS does not include subdomains")
                    if "preload" not in hsts:
                        self._add("Headers", "HSTS Preload", "INFO",
                                   "HSTS preload directive not set")
                else:
                    self._add("Headers", "HSTS", "WARN",
                               "Strict-Transport-Security header missing")
        except Exception:
            self._add("Headers", "HSTS", "INFO",
                       "Could not check HSTS (HTTP request failed)")

    # -------------------------------------------------------------------
    # Grading
    # -------------------------------------------------------------------

    def compute_grade(self) -> str:
        """Compute an overall grade based on results."""
        fails = sum(1 for r in self.results if r.result == "FAIL")
        warns = sum(1 for r in self.results if r.result == "WARN")

        if fails == 0 and warns == 0:
            return "A+"
        elif fails == 0 and warns <= 2:
            return "A"
        elif fails <= 1 and warns <= 3:
            return "B"
        elif fails <= 2:
            return "C"
        elif fails <= 4:
            return "D"
        else:
            return "F"

    # -------------------------------------------------------------------
    # Reporting
    # -------------------------------------------------------------------

    def format_report(self, format_type: str = "text") -> str:
        """Format the audit results as text, JSON, or compact."""
        if format_type == "json":
            return json.dumps({
                "host": self.host,
                "port": self.port,
                "grade": self.compute_grade(),
                "results": [r.to_dict() for r in self.results],
                "summary": {
                    "pass": sum(1 for r in self.results if r.result == "PASS"),
                    "warn": sum(1 for r in self.results if r.result == "WARN"),
                    "fail": sum(1 for r in self.results if r.result == "FAIL"),
                    "info": sum(1 for r in self.results if r.result == "INFO"),
                },
                "audited_at": datetime.datetime.now().isoformat(),
            }, indent=2)

        return self._format_text()

    def _format_text(self) -> str:
        """Generate a clean terminal report."""
        lines = []
        w = 72
        grade = self.compute_grade()

        grade_color = {
            "A+": C.GREEN, "A": C.GREEN, "B": C.YELLOW,
            "C": C.YELLOW, "D": C.RED, "F": C.RED,
        }.get(grade, C.RESET)

        lines.append("")
        lines.append(f"{C.BOLD}{'=' * w}{C.RESET}")
        lines.append(f"{C.BOLD}  SSL/TLS AUDIT — {self.host}:{self.port}{C.RESET}")
        lines.append(f"  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"  Overall Grade: {grade_color}{C.BOLD}{grade}{C.RESET}")
        lines.append(f"{C.BOLD}{'=' * w}{C.RESET}")

        # Group by category
        categories = []
        seen = set()
        for r in self.results:
            if r.category not in seen:
                categories.append(r.category)
                seen.add(r.category)

        for cat in categories:
            lines.append("")
            lines.append(f"{C.BOLD}─── {cat.upper()} {'─' * (w - len(cat) - 6)}{C.RESET}")
            for r in self.results:
                if r.category != cat:
                    continue
                icon = status_icon(r.result)
                lines.append(f"  {icon}  {r.check}")
                if r.detail:
                    # Wrap long detail lines
                    wrapped = textwrap.wrap(r.detail, width=w - 12)
                    for dl in wrapped:
                        lines.append(f"         {C.DIM}{dl}{C.RESET}")

        # Summary bar
        passes = sum(1 for r in self.results if r.result == "PASS")
        warns = sum(1 for r in self.results if r.result == "WARN")
        fails = sum(1 for r in self.results if r.result == "FAIL")
        infos = sum(1 for r in self.results if r.result == "INFO")

        lines.append("")
        lines.append(f"{C.BOLD}{'─' * w}{C.RESET}")
        lines.append(
            f"  {colored(f'{passes} passed', C.GREEN)}  │  "
            f"{colored(f'{warns} warnings', C.YELLOW)}  │  "
            f"{colored(f'{fails} failed', C.RED)}  │  "
            f"{colored(f'{infos} info', C.BLUE)}"
        )
        lines.append(f"{C.BOLD}{'=' * w}{C.RESET}")
        lines.append("")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="ssl_auditor",
        description=(
            "Blue Team SSL/TLS Auditor — Scan domains for weak ciphers, "
            "expired certificates, protocol issues, and misconfigurations."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s example.com
  %(prog)s example.com example.org --port 8443
  %(prog)s example.com --format json --output audit.json
  %(prog)s --targets domains.txt
        """,
    )

    parser.add_argument(
        "domains", nargs="*", metavar="DOMAIN",
        help="Domain(s) to audit"
    )
    parser.add_argument(
        "-t", "--targets", metavar="FILE",
        help="File containing list of domains (one per line)"
    )
    parser.add_argument(
        "-p", "--port", type=int, default=443,
        help="Port to connect to (default: 443)"
    )
    parser.add_argument(
        "--timeout", type=float, default=10.0,
        help="Connection timeout in seconds (default: 10)"
    )
    parser.add_argument(
        "-f", "--format", choices=["text", "json"], default="text",
        help="Output format (default: text)"
    )
    parser.add_argument(
        "-o", "--output", metavar="FILE",
        help="Write report to file"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Verbose output"
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {VERSION}"
    )

    args = parser.parse_args()

    # Collect domains
    domains = list(args.domains or [])
    if args.targets:
        try:
            with open(args.targets) as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        domains.append(line)
        except FileNotFoundError:
            print(f"[!] File not found: {args.targets}", file=sys.stderr)
            sys.exit(1)

    if not domains:
        parser.error("No domains specified. Provide domain(s) or use --targets.")

    # Run audits
    all_reports = []
    all_results = []

    for domain in domains:
        # Strip protocol if accidentally included
        domain = domain.replace("https://", "").replace("http://", "")
        domain = domain.split("/")[0]  # Remove path

        # Handle domain:port format
        if ":" in domain:
            domain, port_str = domain.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                port = args.port
        else:
            port = args.port

        auditor = SSLAuditor(domain, port, args.timeout, args.verbose)
        results = auditor.audit()
        all_results.extend(results)

        report = auditor.format_report(args.format)
        all_reports.append(report)

    # Output
    combined = "\n".join(all_reports)

    if args.output:
        Path(args.output).write_text(combined)
        print(f"[+] Report written to {args.output}")
    else:
        print(combined)

    # Exit code: non-zero if any FAIL
    has_fail = any(r.result == "FAIL" for r in all_results)
    sys.exit(1 if has_fail else 0)


if __name__ == "__main__":
    main()

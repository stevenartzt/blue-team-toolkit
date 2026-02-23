#!/usr/bin/env python3
"""
File Integrity Monitor (FIM) — Blue Team Toolkit
==================================================
Hash critical system files, store a baseline, and detect changes.
Designed to be cron-friendly with clean alert output.

Supports multiple hash algorithms, custom watch paths, exclusion patterns,
and configurable alerting thresholds.

Author: Steven Artzt (@stevenartzt)
License: MIT
"""

import argparse
import datetime
import fnmatch
import hashlib
import json
import os
import stat
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Default paths to monitor
# ---------------------------------------------------------------------------

DEFAULT_WATCH_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/ssh/ssh_config",
    "/etc/hosts",
    "/etc/hosts.allow",
    "/etc/hosts.deny",
    "/etc/crontab",
    "/etc/resolv.conf",
    "/etc/nsswitch.conf",
    "/etc/pam.d/",
    "/etc/security/",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d/",
    "/etc/systemd/system/",
    "/usr/local/bin/",
    "/usr/local/sbin/",
]

DEFAULT_WATCH_DIRS = [
    "/etc/cron.d/",
    "/etc/cron.daily/",
    "/etc/cron.hourly/",
    "/etc/cron.weekly/",
    "/etc/cron.monthly/",
    "/etc/init.d/",
]

# File extensions to skip inside watched directories
SKIP_EXTENSIONS = {
    ".swp", ".swo", ".tmp", ".bak~", ".pyc", ".pyo",
    ".log", ".gz", ".journal",
}

# Default baseline storage location
DEFAULT_BASELINE = Path.home() / ".config" / "blue-team-toolkit" / "fim_baseline.json"

# Hash algorithms available
HASH_ALGORITHMS = ["sha256", "sha512", "sha1", "md5", "blake2b"]
DEFAULT_ALGORITHM = "sha256"


# ---------------------------------------------------------------------------
# File hashing
# ---------------------------------------------------------------------------

def hash_file(filepath: str, algorithm: str = DEFAULT_ALGORITHM,
              block_size: int = 65536) -> Optional[str]:
    """
    Compute the cryptographic hash of a file.

    Returns hex digest string or None if file cannot be read.
    """
    try:
        h = hashlib.new(algorithm)
        with open(filepath, "rb") as f:
            while True:
                block = f.read(block_size)
                if not block:
                    break
                h.update(block)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return None


def get_file_metadata(filepath: str) -> Optional[dict]:
    """
    Collect file metadata: permissions, owner, size, timestamps.
    """
    try:
        st = os.stat(filepath)
        return {
            "size": st.st_size,
            "mode": oct(st.st_mode),
            "uid": st.st_uid,
            "gid": st.st_gid,
            "mtime": st.st_mtime,
            "ctime": st.st_ctime,
            "permissions": stat.filemode(st.st_mode),
        }
    except (FileNotFoundError, PermissionError, OSError):
        return None


# ---------------------------------------------------------------------------
# Path collection
# ---------------------------------------------------------------------------

def collect_paths(watch_paths: List[str],
                  exclude_patterns: Optional[List[str]] = None,
                  max_depth: int = 3) -> List[str]:
    """
    Expand watch paths into individual files.

    Handles both individual files and directories (recursively).
    """
    exclude = exclude_patterns or []
    files = []

    for wp in watch_paths:
        wp = wp.rstrip("/")
        path = Path(wp)

        if not path.exists():
            continue

        if path.is_file():
            if not _is_excluded(str(path), exclude):
                files.append(str(path))
        elif path.is_dir():
            _collect_dir(str(path), files, exclude, max_depth, 0)

    return sorted(set(files))


def _collect_dir(dirpath: str, files: List[str],
                 exclude: List[str], max_depth: int, depth: int) -> None:
    """Recursively collect files from a directory."""
    if depth > max_depth:
        return

    try:
        entries = sorted(os.listdir(dirpath))
    except (PermissionError, OSError):
        return

    for entry in entries:
        full = os.path.join(dirpath, entry)

        if _is_excluded(full, exclude):
            continue

        if os.path.isfile(full):
            ext = os.path.splitext(entry)[1]
            if ext not in SKIP_EXTENSIONS:
                files.append(full)
        elif os.path.isdir(full) and not os.path.islink(full):
            _collect_dir(full, files, exclude, max_depth, depth + 1)


def _is_excluded(filepath: str, patterns: List[str]) -> bool:
    """Check if a path matches any exclusion pattern."""
    for pattern in patterns:
        if fnmatch.fnmatch(filepath, pattern):
            return True
        if fnmatch.fnmatch(os.path.basename(filepath), pattern):
            return True
    return False


# ---------------------------------------------------------------------------
# Baseline management
# ---------------------------------------------------------------------------

class Baseline:
    """
    Manages the file integrity baseline.

    Stores file hashes and metadata for comparison.
    """

    def __init__(self, path: Optional[str] = None,
                 algorithm: str = DEFAULT_ALGORITHM):
        self.path = Path(path) if path else DEFAULT_BASELINE
        self.algorithm = algorithm
        self.data: Dict[str, dict] = {}
        self.metadata: dict = {}

    def create(self, watch_paths: List[str],
               exclude: Optional[List[str]] = None,
               verbose: bool = False) -> int:
        """
        Create a new baseline from the specified paths.

        Returns the number of files baselined.
        """
        files = collect_paths(watch_paths, exclude)
        self.data = {}
        count = 0

        for filepath in files:
            file_hash = hash_file(filepath, self.algorithm)
            if file_hash is None:
                if verbose:
                    print(f"  [!] Skipping (unreadable): {filepath}")
                continue

            meta = get_file_metadata(filepath)
            self.data[filepath] = {
                "hash": file_hash,
                "algorithm": self.algorithm,
                "metadata": meta,
            }
            count += 1

            if verbose:
                print(f"  [+] {filepath}")

        self.metadata = {
            "created": datetime.datetime.now().isoformat(),
            "algorithm": self.algorithm,
            "file_count": count,
            "hostname": os.uname().nodename,
            "watch_paths": watch_paths,
            "exclude_patterns": exclude or [],
        }

        return count

    def save(self) -> None:
        """Save baseline to disk."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "metadata": self.metadata,
            "files": self.data,
        }
        self.path.write_text(json.dumps(payload, indent=2))

    def load(self) -> bool:
        """Load baseline from disk. Returns True if successful."""
        if not self.path.exists():
            return False
        try:
            payload = json.loads(self.path.read_text())
            self.metadata = payload.get("metadata", {})
            self.data = payload.get("files", {})
            self.algorithm = self.metadata.get("algorithm", DEFAULT_ALGORITHM)
            return True
        except (json.JSONDecodeError, KeyError) as e:
            print(f"[!] Failed to load baseline: {e}", file=sys.stderr)
            return False


# ---------------------------------------------------------------------------
# Change detection
# ---------------------------------------------------------------------------

class ChangeType:
    MODIFIED = "MODIFIED"
    ADDED = "ADDED"
    DELETED = "DELETED"
    PERMISSIONS = "PERMISSIONS_CHANGED"
    OWNER = "OWNER_CHANGED"


class Change:
    """Represents a detected file change."""

    def __init__(self, filepath: str, change_type: str,
                 severity: str = "MEDIUM", detail: str = ""):
        self.filepath = filepath
        self.change_type = change_type
        self.severity = severity
        self.detail = detail
        self.timestamp = datetime.datetime.now().isoformat()

    def to_dict(self) -> dict:
        return {
            "filepath": self.filepath,
            "change_type": self.change_type,
            "severity": self.severity,
            "detail": self.detail,
            "detected_at": self.timestamp,
        }


def classify_severity(filepath: str, change_type: str) -> str:
    """
    Classify the severity of a file change based on the file and change type.
    """
    # Critical system files
    critical_files = {
        "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers",
        "/etc/ssh/sshd_config", "/etc/hosts",
    }
    critical_dirs = ["/etc/pam.d/", "/etc/security/", "/etc/sudoers.d/"]

    if filepath in critical_files:
        return "CRITICAL"

    for d in critical_dirs:
        if filepath.startswith(d):
            return "HIGH"

    if "/cron" in filepath:
        return "HIGH"

    if filepath.startswith("/usr/local/bin/") or filepath.startswith("/usr/local/sbin/"):
        if change_type in (ChangeType.ADDED, ChangeType.MODIFIED):
            return "HIGH"

    if change_type == ChangeType.PERMISSIONS:
        return "HIGH"
    if change_type == ChangeType.OWNER:
        return "HIGH"

    return "MEDIUM"


def check_integrity(baseline: Baseline,
                    verbose: bool = False) -> List[Change]:
    """
    Compare current file state against the baseline.

    Returns a list of detected changes.
    """
    changes = []

    # Get current watch paths from baseline metadata
    watch_paths = baseline.metadata.get("watch_paths", [])
    exclude = baseline.metadata.get("exclude_patterns", [])

    if not watch_paths:
        # Fall back to checking only baselined files
        watch_paths = list(baseline.data.keys())

    # Collect current files
    current_files = set(collect_paths(watch_paths, exclude))
    baselined_files = set(baseline.data.keys())

    # Check for modified and deleted files
    for filepath, entry in baseline.data.items():
        if not os.path.exists(filepath):
            severity = classify_severity(filepath, ChangeType.DELETED)
            changes.append(Change(
                filepath, ChangeType.DELETED, severity,
                "File no longer exists"
            ))
            continue

        # Check hash
        current_hash = hash_file(filepath, baseline.algorithm)
        if current_hash is None:
            if verbose:
                print(f"  [!] Cannot read: {filepath}")
            continue

        old_hash = entry.get("hash", "")
        if current_hash != old_hash:
            severity = classify_severity(filepath, ChangeType.MODIFIED)
            changes.append(Change(
                filepath, ChangeType.MODIFIED, severity,
                f"Hash changed: {old_hash[:16]}... → {current_hash[:16]}..."
            ))

        # Check metadata changes
        old_meta = entry.get("metadata", {})
        current_meta = get_file_metadata(filepath)

        if old_meta and current_meta:
            # Permissions change
            if old_meta.get("mode") != current_meta.get("mode"):
                severity = classify_severity(filepath, ChangeType.PERMISSIONS)
                changes.append(Change(
                    filepath, ChangeType.PERMISSIONS, severity,
                    f"Permissions: {old_meta.get('permissions', '?')} → "
                    f"{current_meta.get('permissions', '?')}"
                ))

            # Owner change
            if (old_meta.get("uid") != current_meta.get("uid") or
                    old_meta.get("gid") != current_meta.get("gid")):
                severity = classify_severity(filepath, ChangeType.OWNER)
                changes.append(Change(
                    filepath, ChangeType.OWNER, severity,
                    f"Owner: {old_meta.get('uid')}:{old_meta.get('gid')} → "
                    f"{current_meta.get('uid')}:{current_meta.get('gid')}"
                ))

    # Check for new files
    new_files = current_files - baselined_files
    for filepath in sorted(new_files):
        severity = classify_severity(filepath, ChangeType.ADDED)
        changes.append(Change(
            filepath, ChangeType.ADDED, severity,
            "New file not in baseline"
        ))

    # Sort by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    changes.sort(key=lambda c: (sev_order.get(c.severity, 4), c.filepath))

    return changes


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def format_changes(changes: List[Change], baseline: Baseline,
                   format_type: str = "text") -> str:
    """Format change detection results."""

    if format_type == "json":
        return json.dumps({
            "baseline": {
                "created": baseline.metadata.get("created", ""),
                "file_count": baseline.metadata.get("file_count", 0),
                "algorithm": baseline.algorithm,
                "hostname": baseline.metadata.get("hostname", ""),
            },
            "check_time": datetime.datetime.now().isoformat(),
            "total_changes": len(changes),
            "changes": [c.to_dict() for c in changes],
        }, indent=2)

    return _format_text(changes, baseline)


def _format_text(changes: List[Change], baseline: Baseline) -> str:
    """Generate human-readable change report."""
    lines = []
    w = 72

    lines.append("=" * w)
    lines.append("  FILE INTEGRITY MONITOR — CHECK RESULTS")
    lines.append(f"  Checked: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  Baseline: {baseline.metadata.get('created', 'unknown')}")
    lines.append(f"  Host: {baseline.metadata.get('hostname', 'unknown')}")
    lines.append(f"  Algorithm: {baseline.algorithm}")
    lines.append(f"  Files in baseline: {baseline.metadata.get('file_count', 0)}")
    lines.append("=" * w)
    lines.append("")

    if not changes:
        lines.append("  ✓ No changes detected. All files match baseline.")
        lines.append("")
        lines.append("=" * w)
        return "\n".join(lines)

    # Summary counts
    from collections import Counter
    type_counts = Counter(c.change_type for c in changes)
    sev_counts = Counter(c.severity for c in changes)

    lines.append(f"  ⚠️  {len(changes)} CHANGE(S) DETECTED!\n")

    lines.append("─── SUMMARY ────────────────────────────────────────────────────────")
    for ct in [ChangeType.MODIFIED, ChangeType.ADDED, ChangeType.DELETED,
               ChangeType.PERMISSIONS, ChangeType.OWNER]:
        count = type_counts.get(ct, 0)
        if count:
            icon = {
                ChangeType.MODIFIED: "📝",
                ChangeType.ADDED: "➕",
                ChangeType.DELETED: "❌",
                ChangeType.PERMISSIONS: "🔒",
                ChangeType.OWNER: "👤",
            }.get(ct, "•")
            lines.append(f"  {icon} {ct:<25} {count}")
    lines.append("")

    lines.append("  Severity:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = sev_counts.get(sev, 0)
        if count:
            lines.append(f"    {sev:<12} {count}")
    lines.append("")

    # Detailed changes
    lines.append("─── CHANGES ────────────────────────────────────────────────────────")
    for c in changes:
        sev_icon = {
            "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"
        }.get(c.severity, "⚪")
        type_icon = {
            ChangeType.MODIFIED: "M",
            ChangeType.ADDED: "A",
            ChangeType.DELETED: "D",
            ChangeType.PERMISSIONS: "P",
            ChangeType.OWNER: "O",
        }.get(c.change_type, "?")

        lines.append(f"  {sev_icon} [{type_icon}] {c.filepath}")
        lines.append(f"       {c.detail}")
    lines.append("")

    # Recommendations
    lines.append("─── RECOMMENDATIONS ────────────────────────────────────────────────")
    critical = [c for c in changes if c.severity == "CRITICAL"]
    if critical:
        lines.append("  🚨 CRITICAL changes to core system files detected!")
        lines.append("     - Verify changes were authorized")
        lines.append("     - Check for signs of compromise")
        lines.append("     - Review recent login activity")
        lines.append("")

    if type_counts.get(ChangeType.ADDED, 0) > 0:
        lines.append("  New files detected in monitored directories.")
        lines.append("  Verify these additions are legitimate.")
        lines.append("")

    if type_counts.get(ChangeType.PERMISSIONS, 0) > 0:
        lines.append("  File permission changes detected.")
        lines.append("  Check for overly permissive settings (777, world-writable).")
        lines.append("")

    lines.append("  After verifying changes, update baseline with:")
    lines.append(f"    python3 fim.py --init --baseline {baseline.path}")
    lines.append("")
    lines.append("=" * w)

    return "\n".join(lines)


def format_baseline_summary(baseline: Baseline) -> str:
    """Format a summary of the baseline contents."""
    lines = []
    w = 72

    lines.append("=" * w)
    lines.append("  FILE INTEGRITY MONITOR — BASELINE SUMMARY")
    lines.append("=" * w)
    lines.append(f"  Created:    {baseline.metadata.get('created', 'unknown')}")
    lines.append(f"  Host:       {baseline.metadata.get('hostname', 'unknown')}")
    lines.append(f"  Algorithm:  {baseline.algorithm}")
    lines.append(f"  Files:      {baseline.metadata.get('file_count', 0)}")
    lines.append(f"  Stored at:  {baseline.path}")
    lines.append("")

    if baseline.data:
        # Group by directory
        dirs: Dict[str, int] = {}
        for filepath in baseline.data:
            parent = str(Path(filepath).parent)
            dirs[parent] = dirs.get(parent, 0) + 1

        lines.append("─── MONITORED DIRECTORIES ──────────────────────────────────────────")
        for d, count in sorted(dirs.items()):
            lines.append(f"  {d:<50} {count:>4} file(s)")
        lines.append("")

    lines.append("=" * w)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="fim",
        description=(
            "Blue Team File Integrity Monitor — Hash critical system files, "
            "maintain a baseline, and detect unauthorized changes. "
            "Designed for cron deployment."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Create initial baseline
  %(prog)s --init

  # Create baseline with custom paths
  %(prog)s --init --watch /etc/ /usr/local/bin/ --exclude '*.log' '*.tmp'

  # Check for changes
  %(prog)s --check

  # Check and output JSON (for SIEM ingestion)
  %(prog)s --check --format json

  # Show baseline info
  %(prog)s --info

  # Cron job (check every hour, alert on changes)
  # 0 * * * * /usr/bin/python3 /path/to/fim.py --check --quiet

  # Custom baseline location
  %(prog)s --init --baseline /opt/security/baseline.json
        """,
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--init", action="store_true",
        help="Create (or recreate) the file integrity baseline"
    )
    mode.add_argument(
        "--check", action="store_true",
        help="Check current state against the baseline"
    )
    mode.add_argument(
        "--info", action="store_true",
        help="Display baseline information"
    )

    parser.add_argument(
        "--watch", nargs="+", metavar="PATH",
        help="Paths to monitor (files or directories)"
    )
    parser.add_argument(
        "--exclude", nargs="+", metavar="PATTERN",
        help="Glob patterns to exclude (e.g., '*.log', '*.tmp')"
    )
    parser.add_argument(
        "--baseline", metavar="FILE",
        help=f"Baseline file path (default: {DEFAULT_BASELINE})"
    )
    parser.add_argument(
        "--algorithm", choices=HASH_ALGORITHMS,
        default=DEFAULT_ALGORITHM,
        help=f"Hash algorithm (default: {DEFAULT_ALGORITHM})"
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
        "-q", "--quiet", action="store_true",
        help="Only output if changes detected (for cron)"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Verbose output"
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {VERSION}"
    )

    args = parser.parse_args()

    baseline = Baseline(args.baseline, args.algorithm)

    # --init: Create baseline
    if args.init:
        watch_paths = args.watch or (DEFAULT_WATCH_PATHS + DEFAULT_WATCH_DIRS)
        exclude = args.exclude or []

        print(f"[*] Creating baseline ({args.algorithm})...")
        count = baseline.create(watch_paths, exclude, verbose=args.verbose)

        if count == 0:
            print("[!] No files could be baselined. Check paths and permissions.",
                  file=sys.stderr)
            sys.exit(1)

        baseline.save()
        print(f"[+] Baseline created: {count} files")
        print(f"[+] Saved to: {baseline.path}")
        return

    # --info: Show baseline info
    if args.info:
        if not baseline.load():
            print(f"[!] No baseline found at {baseline.path}", file=sys.stderr)
            print("    Run with --init to create one.", file=sys.stderr)
            sys.exit(1)

        print(format_baseline_summary(baseline))
        return

    # --check: Compare against baseline
    if args.check:
        if not baseline.load():
            print(f"[!] No baseline found at {baseline.path}", file=sys.stderr)
            print("    Run with --init to create one.", file=sys.stderr)
            sys.exit(1)

        changes = check_integrity(baseline, verbose=args.verbose)

        # Quiet mode: exit silently if no changes
        if args.quiet and not changes:
            sys.exit(0)

        report = format_changes(changes, baseline, args.format)

        if args.output:
            Path(args.output).write_text(report)
            print(f"[+] Report written to {args.output}")
        else:
            print(report)

        # Exit code: non-zero if changes detected
        sys.exit(1 if changes else 0)


if __name__ == "__main__":
    main()

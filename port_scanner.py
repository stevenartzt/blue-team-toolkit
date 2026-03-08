#!/usr/bin/env python3
"""
port_scanner.py — Fast TCP Port Scanner with Service Detection

Part of Blue Team Toolkit
https://github.com/stevenartzt/blue-team-toolkit

Features:
- Multi-threaded TCP scanning (up to 500 concurrent connections)
- Service version detection via banner grabbing
- Common port presets (top-100, top-1000, web, database, etc.)
- CIDR notation support for network ranges
- JSON/CSV/text output formats
- Rate limiting to avoid detection

Usage:
    python3 port_scanner.py 192.168.1.1
    python3 port_scanner.py 192.168.1.0/24 --ports 22,80,443
    python3 port_scanner.py target.com --preset web --threads 100
    python3 port_scanner.py 10.0.0.1 --ports 1-1000 --format json

License: MIT
"""

import argparse
import concurrent.futures
import ipaddress
import json
import re
import socket
import ssl
import sys
import time
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

# Service signatures for banner matching
SERVICE_SIGNATURES = {
    # SSH
    r'SSH-[\d.]+-': 'ssh',
    r'OpenSSH': 'ssh',
    r'dropbear': 'ssh',
    
    # HTTP
    r'HTTP/[\d.]+': 'http',
    r'Apache': 'http/apache',
    r'nginx': 'http/nginx',
    r'Microsoft-IIS': 'http/iis',
    r'lighttpd': 'http/lighttpd',
    
    # FTP
    r'220.*FTP': 'ftp',
    r'220.*FileZilla': 'ftp/filezilla',
    r'220.*ProFTPD': 'ftp/proftpd',
    r'220.*vsftpd': 'ftp/vsftpd',
    r'220.*Pure-FTPd': 'ftp/pure-ftpd',
    
    # SMTP
    r'220.*SMTP': 'smtp',
    r'220.*ESMTP': 'smtp',
    r'220.*Postfix': 'smtp/postfix',
    r'220.*Exim': 'smtp/exim',
    r'220.*Sendmail': 'smtp/sendmail',
    
    # POP3
    r'\+OK.*POP3': 'pop3',
    r'\+OK.*Dovecot': 'pop3/dovecot',
    
    # IMAP
    r'\* OK.*IMAP': 'imap',
    r'\* OK.*Dovecot': 'imap/dovecot',
    
    # MySQL
    r'mysql': 'mysql',
    r'MariaDB': 'mysql/mariadb',
    
    # PostgreSQL
    r'PostgreSQL': 'postgresql',
    
    # Redis
    r'-ERR.*redis': 'redis',
    r'REDIS': 'redis',
    
    # MongoDB
    r'MongoDB': 'mongodb',
    r'ismaster': 'mongodb',
    
    # Telnet
    r'login:': 'telnet',
    r'telnet': 'telnet',
    
    # DNS
    r'BIND': 'dns/bind',
    
    # SNMP (usually UDP but sometimes TCP)
    r'snmp': 'snmp',
}

# Common ports with default services
COMMON_PORTS = {
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    25: 'smtp',
    53: 'dns',
    80: 'http',
    110: 'pop3',
    111: 'rpc',
    135: 'msrpc',
    139: 'netbios',
    143: 'imap',
    443: 'https',
    445: 'smb',
    465: 'smtps',
    587: 'submission',
    993: 'imaps',
    995: 'pop3s',
    1433: 'mssql',
    1521: 'oracle',
    2049: 'nfs',
    3306: 'mysql',
    3389: 'rdp',
    5432: 'postgresql',
    5900: 'vnc',
    5901: 'vnc',
    6379: 'redis',
    8080: 'http-alt',
    8443: 'https-alt',
    27017: 'mongodb',
}

# Port presets
PORT_PRESETS = {
    'top-20': [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080],
    'top-100': [7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157],
    'web': [80, 443, 8000, 8080, 8443, 8888, 9000, 9090, 9443],
    'database': [1433, 1521, 3306, 5432, 6379, 9042, 27017, 27018, 28017],
    'mail': [25, 110, 143, 465, 587, 993, 995, 2525],
    'file': [20, 21, 22, 69, 115, 139, 445, 873, 2049],
    'remote': [22, 23, 512, 513, 514, 3389, 5900, 5901, 5902],
}


class PortScanner:
    def __init__(self, timeout: float = 2.0, threads: int = 100, 
                 rate_limit: float = 0, verbose: bool = False):
        self.timeout = timeout
        self.threads = min(threads, 500)  # Cap at 500
        self.rate_limit = rate_limit
        self.verbose = verbose
        self.results: Dict[str, List[Dict]] = defaultdict(list)
        self.scan_start = None
        self.scan_end = None
        self.total_scanned = 0
        
    def parse_targets(self, target: str) -> List[str]:
        """Parse target into list of IPs. Supports hostname, IP, CIDR."""
        targets = []
        
        # Check if it's a CIDR range
        if '/' in target:
            try:
                network = ipaddress.ip_network(target, strict=False)
                # Limit to /16 to avoid scanning the entire internet
                if network.num_addresses > 65536:
                    print(f"[!] Network too large ({network.num_addresses} hosts). Max /16 (65536).", file=sys.stderr)
                    sys.exit(1)
                targets = [str(ip) for ip in network.hosts()]
            except ValueError as e:
                print(f"[!] Invalid CIDR: {e}", file=sys.stderr)
                sys.exit(1)
        else:
            # Single IP or hostname
            try:
                # Try to resolve if it's a hostname
                ip = socket.gethostbyname(target)
                targets = [ip]
            except socket.gaierror:
                print(f"[!] Cannot resolve hostname: {target}", file=sys.stderr)
                sys.exit(1)
                
        return targets
    
    def parse_ports(self, port_spec: str) -> List[int]:
        """Parse port specification. Supports: 80, 80-100, 80,443,8080"""
        ports = set()
        
        for part in port_spec.split(','):
            part = part.strip()
            if '-' in part:
                try:
                    start, end = map(int, part.split('-'))
                    if start > end:
                        start, end = end, start
                    if end > 65535:
                        end = 65535
                    if start < 1:
                        start = 1
                    ports.update(range(start, end + 1))
                except ValueError:
                    print(f"[!] Invalid port range: {part}", file=sys.stderr)
            else:
                try:
                    port = int(part)
                    if 1 <= port <= 65535:
                        ports.add(port)
                except ValueError:
                    print(f"[!] Invalid port: {part}", file=sys.stderr)
                    
        return sorted(ports)
    
    def grab_banner(self, ip: str, port: int) -> Optional[str]:
        """Attempt to grab service banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            # For SSL ports, try SSL handshake
            if port in [443, 465, 636, 993, 995, 8443]:
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock, server_hostname=ip)
                except ssl.SSLError:
                    pass  # Not SSL or handshake failed
            
            # Send probe for HTTP
            if port in [80, 8080, 8000, 8888, 443, 8443]:
                sock.send(b'HEAD / HTTP/1.0\r\nHost: ' + ip.encode() + b'\r\n\r\n')
            else:
                # Generic probe - just send newline or wait for banner
                try:
                    sock.send(b'\r\n')
                except:
                    pass
            
            sock.settimeout(2)
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner[:500] if banner else None  # Limit banner size
            
        except Exception:
            return None
    
    def detect_service(self, port: int, banner: Optional[str]) -> Tuple[str, str]:
        """Detect service from banner or port number."""
        service = COMMON_PORTS.get(port, 'unknown')
        version = ''
        
        if banner:
            # Try to match against signatures
            for pattern, svc in SERVICE_SIGNATURES.items():
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    service = svc
                    # Try to extract version info
                    ver_match = re.search(r'[\d]+\.[\d]+(?:\.[\d]+)?', banner)
                    if ver_match:
                        version = ver_match.group(0)
                    break
        
        return service, version
    
    def scan_port(self, ip: str, port: int) -> Optional[Dict]:
        """Scan a single port on an IP."""
        if self.rate_limit > 0:
            time.sleep(self.rate_limit)
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:  # Port is open
                banner = self.grab_banner(ip, port)
                service, version = self.detect_service(port, banner)
                
                return {
                    'port': port,
                    'state': 'open',
                    'service': service,
                    'version': version,
                    'banner': banner,
                }
            return None
            
        except Exception as e:
            if self.verbose:
                print(f"[!] Error scanning {ip}:{port}: {e}", file=sys.stderr)
            return None
    
    def scan_host(self, ip: str, ports: List[int]) -> List[Dict]:
        """Scan multiple ports on a single host."""
        open_ports = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {
                executor.submit(self.scan_port, ip, port): port 
                for port in ports
            }
            
            for future in concurrent.futures.as_completed(future_to_port):
                self.total_scanned += 1
                result = future.result()
                if result:
                    open_ports.append(result)
                    if self.verbose:
                        print(f"[+] {ip}:{result['port']} - {result['service']}", file=sys.stderr)
        
        return sorted(open_ports, key=lambda x: x['port'])
    
    def scan(self, targets: List[str], ports: List[int]) -> Dict:
        """Run the full scan."""
        self.scan_start = datetime.now()
        self.total_scanned = 0
        
        print(f"[*] Starting scan of {len(targets)} host(s), {len(ports)} port(s)", file=sys.stderr)
        print(f"[*] Threads: {self.threads}, Timeout: {self.timeout}s", file=sys.stderr)
        
        for i, ip in enumerate(targets):
            if self.verbose or len(targets) > 1:
                print(f"[*] Scanning {ip} ({i+1}/{len(targets)})", file=sys.stderr)
            
            open_ports = self.scan_host(ip, ports)
            if open_ports:
                self.results[ip] = open_ports
        
        self.scan_end = datetime.now()
        duration = (self.scan_end - self.scan_start).total_seconds()
        
        print(f"[*] Scan complete in {duration:.1f}s ({self.total_scanned} ports scanned)", file=sys.stderr)
        
        return dict(self.results)


def format_text(results: Dict, start_time: datetime, end_time: datetime) -> str:
    """Format results as human-readable text."""
    lines = []
    lines.append("=" * 70)
    lines.append("  PORT SCANNER — RESULTS")
    lines.append(f"  Scan completed: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  Duration: {(end_time - start_time).total_seconds():.1f}s")
    lines.append("=" * 70)
    lines.append("")
    
    if not results:
        lines.append("  No open ports found.")
        return '\n'.join(lines)
    
    total_open = sum(len(ports) for ports in results.values())
    lines.append(f"  Found {total_open} open port(s) on {len(results)} host(s)")
    lines.append("")
    
    for ip, ports in sorted(results.items()):
        lines.append(f"─── {ip} ─────────────────────────────────────────────")
        lines.append("")
        lines.append("  PORT      STATE    SERVICE           VERSION")
        lines.append("  ────      ─────    ───────           ───────")
        
        for p in ports:
            port_str = f"{p['port']}/tcp".ljust(10)
            state = p['state'].ljust(8)
            service = p['service'].ljust(17)
            version = p.get('version', '')
            lines.append(f"  {port_str}{state} {service} {version}")
            
            if p.get('banner'):
                # Show first line of banner
                banner_line = p['banner'].split('\n')[0][:50]
                lines.append(f"           └─ {banner_line}")
        
        lines.append("")
    
    return '\n'.join(lines)


def format_json(results: Dict, start_time: datetime, end_time: datetime) -> str:
    """Format results as JSON."""
    output = {
        'scan_info': {
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration_seconds': (end_time - start_time).total_seconds(),
        },
        'summary': {
            'hosts_scanned': len(results),
            'total_open_ports': sum(len(p) for p in results.values()),
        },
        'results': results,
    }
    return json.dumps(output, indent=2)


def format_csv(results: Dict) -> str:
    """Format results as CSV."""
    lines = ['ip,port,state,service,version,banner']
    for ip, ports in results.items():
        for p in ports:
            banner = (p.get('banner') or '').replace('"', '""').replace('\n', ' ')[:100]
            lines.append(f'{ip},{p["port"]},{p["state"]},{p["service"]},{p.get("version", "")},"{banner}"')
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Fast TCP port scanner with service detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s 192.168.1.1                    # Scan top-20 ports
  %(prog)s 192.168.1.0/24 -p 22,80,443    # Scan specific ports on subnet
  %(prog)s target.com --preset web        # Scan web ports
  %(prog)s 10.0.0.1 -p 1-1000 -t 200      # Fast scan with 200 threads
  %(prog)s 192.168.1.1 --format json      # JSON output
        '''
    )
    
    parser.add_argument('target', help='Target IP, hostname, or CIDR range')
    parser.add_argument('-p', '--ports', help='Ports to scan (e.g., 80, 80-100, 22,80,443)')
    parser.add_argument('--preset', choices=PORT_PRESETS.keys(),
                        help='Use port preset (top-20, top-100, web, database, mail, file, remote)')
    parser.add_argument('-t', '--threads', type=int, default=100,
                        help='Number of concurrent threads (default: 100, max: 500)')
    parser.add_argument('--timeout', type=float, default=2.0,
                        help='Connection timeout in seconds (default: 2.0)')
    parser.add_argument('--rate-limit', type=float, default=0,
                        help='Delay between scans in seconds (default: 0)')
    parser.add_argument('-f', '--format', choices=['text', 'json', 'csv'], default='text',
                        help='Output format (default: text)')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output')
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = PortScanner(
        timeout=args.timeout,
        threads=args.threads,
        rate_limit=args.rate_limit,
        verbose=args.verbose,
    )
    
    # Parse targets
    targets = scanner.parse_targets(args.target)
    
    # Parse ports
    if args.ports:
        ports = scanner.parse_ports(args.ports)
    elif args.preset:
        ports = PORT_PRESETS[args.preset]
    else:
        ports = PORT_PRESETS['top-20']
    
    # Run scan
    results = scanner.scan(targets, ports)
    
    # Format output
    if args.format == 'json':
        output = format_json(results, scanner.scan_start, scanner.scan_end)
    elif args.format == 'csv':
        output = format_csv(results)
    else:
        output = format_text(results, scanner.scan_start, scanner.scan_end)
    
    # Write output
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"[*] Results written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == '__main__':
    main()

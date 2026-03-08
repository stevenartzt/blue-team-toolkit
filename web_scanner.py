#!/usr/bin/env python3
"""
web_scanner.py — Web Vulnerability Scanner

Part of Blue Team Toolkit
https://github.com/stevenartzt/blue-team-toolkit

Features:
- Security header analysis (HSTS, CSP, X-Frame-Options, etc.)
- SSL/TLS configuration check
- Cookie security audit (HttpOnly, Secure, SameSite)
- Common vulnerability detection (directory listing, info disclosure)
- Technology fingerprinting
- Directory/file discovery with wordlist
- JSON/CSV/text output formats

Usage:
    python3 web_scanner.py https://example.com
    python3 web_scanner.py https://target.com --full
    python3 web_scanner.py https://target.com --dirbrute -w wordlist.txt
    python3 web_scanner.py https://target.com --format json -o report.json

License: MIT
"""

import argparse
import concurrent.futures
import json
import re
import socket
import ssl
import sys
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from http.client import HTTPResponse

# Security headers to check
SECURITY_HEADERS = {
    'Strict-Transport-Security': {
        'required': True,
        'description': 'HSTS - Enforce HTTPS',
        'severity': 'HIGH',
    },
    'Content-Security-Policy': {
        'required': True,
        'description': 'CSP - Prevent XSS/injection',
        'severity': 'HIGH',
    },
    'X-Frame-Options': {
        'required': True,
        'description': 'Prevent clickjacking',
        'severity': 'MEDIUM',
    },
    'X-Content-Type-Options': {
        'required': True,
        'description': 'Prevent MIME sniffing',
        'severity': 'MEDIUM',
    },
    'X-XSS-Protection': {
        'required': False,
        'description': 'Legacy XSS filter',
        'severity': 'LOW',
    },
    'Referrer-Policy': {
        'required': True,
        'description': 'Control referrer info',
        'severity': 'LOW',
    },
    'Permissions-Policy': {
        'required': False,
        'description': 'Feature permissions',
        'severity': 'LOW',
    },
    'Cross-Origin-Opener-Policy': {
        'required': False,
        'description': 'Isolate browsing context',
        'severity': 'LOW',
    },
    'Cross-Origin-Resource-Policy': {
        'required': False,
        'description': 'Block cross-origin reads',
        'severity': 'LOW',
    },
}

# Headers that leak information
INFO_LEAK_HEADERS = [
    'Server',
    'X-Powered-By',
    'X-AspNet-Version',
    'X-AspNetMvc-Version',
    'X-Generator',
    'X-Drupal-Cache',
    'X-Pingback',
]

# Common sensitive paths to check
SENSITIVE_PATHS = [
    '/.git/config',
    '/.env',
    '/.htaccess',
    '/.htpasswd',
    '/wp-config.php.bak',
    '/config.php.bak',
    '/phpinfo.php',
    '/server-status',
    '/server-info',
    '/.svn/entries',
    '/backup.sql',
    '/database.sql',
    '/dump.sql',
    '/.DS_Store',
    '/robots.txt',
    '/sitemap.xml',
    '/crossdomain.xml',
    '/clientaccesspolicy.xml',
    '/security.txt',
    '/.well-known/security.txt',
    '/admin/',
    '/administrator/',
    '/wp-admin/',
    '/phpmyadmin/',
    '/pma/',
    '/adminer.php',
]

# Common directory wordlist (small default)
DEFAULT_WORDLIST = [
    'admin', 'administrator', 'login', 'wp-admin', 'wp-login.php',
    'dashboard', 'panel', 'console', 'manage', 'management',
    'api', 'api/v1', 'api/v2', 'graphql', 'swagger', 'swagger-ui',
    'docs', 'documentation', 'help', 'support',
    'backup', 'backups', 'db', 'database', 'sql', 'dump',
    'config', 'configuration', 'settings', 'setup', 'install',
    'test', 'testing', 'debug', 'dev', 'development', 'staging',
    'old', 'new', 'temp', 'tmp', 'cache',
    'upload', 'uploads', 'files', 'assets', 'static', 'media',
    'images', 'img', 'css', 'js', 'scripts',
    'private', 'internal', 'secure', 'secret', 'hidden',
    'user', 'users', 'account', 'accounts', 'profile', 'profiles',
    'data', 'export', 'download', 'downloads',
    '.git', '.svn', '.env', '.htaccess',
]


class WebScanner:
    def __init__(self, timeout: int = 10, threads: int = 10, 
                 user_agent: str = None, verbose: bool = False):
        self.timeout = timeout
        self.threads = threads
        self.user_agent = user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        self.verbose = verbose
        self.findings: List[Dict] = []
        self.scan_start = None
        self.scan_end = None
        
    def make_request(self, url: str, method: str = 'GET', 
                     follow_redirects: bool = True) -> Tuple[Optional[HTTPResponse], Optional[str]]:
        """Make HTTP request and return response."""
        try:
            req = urllib.request.Request(url, method=method)
            req.add_header('User-Agent', self.user_agent)
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            if follow_redirects:
                response = urllib.request.urlopen(req, timeout=self.timeout, context=context)
            else:
                # Don't follow redirects
                class NoRedirect(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self, req, fp, code, msg, headers, newurl):
                        return None
                opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=context))
                response = opener.open(req, timeout=self.timeout)
            
            return response, None
            
        except urllib.error.HTTPError as e:
            return e, None
        except urllib.error.URLError as e:
            return None, str(e.reason)
        except Exception as e:
            return None, str(e)
    
    def add_finding(self, category: str, severity: str, title: str, 
                    description: str, remediation: str = '', evidence: str = ''):
        """Add a finding to the results."""
        self.findings.append({
            'category': category,
            'severity': severity,
            'title': title,
            'description': description,
            'remediation': remediation,
            'evidence': evidence[:500] if evidence else '',
        })
    
    def check_security_headers(self, url: str) -> Dict:
        """Check security headers."""
        response, error = self.make_request(url)
        if error or not response:
            self.add_finding('headers', 'HIGH', 'Connection Failed',
                           f'Could not connect to {url}: {error}')
            return {}
        
        headers = {k.lower(): v for k, v in response.headers.items()}
        results = {'present': [], 'missing': [], 'info_leak': []}
        
        # Check required security headers
        for header, info in SECURITY_HEADERS.items():
            header_lower = header.lower()
            if header_lower in headers:
                results['present'].append({
                    'header': header,
                    'value': headers[header_lower],
                    'description': info['description'],
                })
            elif info['required']:
                results['missing'].append({
                    'header': header,
                    'severity': info['severity'],
                    'description': info['description'],
                })
                self.add_finding('headers', info['severity'], 
                               f'Missing {header}',
                               info['description'],
                               f'Add {header} header to responses')
        
        # Check for info leakage
        for header in INFO_LEAK_HEADERS:
            header_lower = header.lower()
            if header_lower in headers:
                results['info_leak'].append({
                    'header': header,
                    'value': headers[header_lower],
                })
                self.add_finding('headers', 'LOW',
                               f'Information Disclosure: {header}',
                               f'Server reveals: {headers[header_lower]}',
                               f'Remove or obfuscate {header} header')
        
        return results
    
    def check_cookies(self, url: str) -> List[Dict]:
        """Check cookie security."""
        response, _ = self.make_request(url)
        if not response:
            return []
        
        cookies = []
        set_cookie_headers = response.headers.get_all('Set-Cookie') or []
        
        for cookie_str in set_cookie_headers:
            cookie = {'raw': cookie_str, 'issues': []}
            
            # Parse cookie
            parts = cookie_str.split(';')
            name_value = parts[0].strip()
            cookie['name'] = name_value.split('=')[0] if '=' in name_value else name_value
            
            flags = cookie_str.lower()
            
            # Check Secure flag
            if 'secure' not in flags:
                cookie['issues'].append('Missing Secure flag')
                self.add_finding('cookies', 'MEDIUM',
                               f'Cookie missing Secure flag: {cookie["name"]}',
                               'Cookie can be transmitted over unencrypted connections',
                               'Add Secure flag to cookie')
            
            # Check HttpOnly flag (for session cookies)
            if 'httponly' not in flags:
                if any(x in cookie['name'].lower() for x in ['session', 'auth', 'token', 'login', 'sid']):
                    cookie['issues'].append('Missing HttpOnly flag')
                    self.add_finding('cookies', 'MEDIUM',
                                   f'Session cookie missing HttpOnly: {cookie["name"]}',
                                   'Cookie accessible via JavaScript (XSS risk)',
                                   'Add HttpOnly flag to cookie')
            
            # Check SameSite
            if 'samesite' not in flags:
                cookie['issues'].append('Missing SameSite flag')
                self.add_finding('cookies', 'LOW',
                               f'Cookie missing SameSite: {cookie["name"]}',
                               'Cookie vulnerable to CSRF in some browsers',
                               'Add SameSite=Lax or SameSite=Strict')
            
            cookies.append(cookie)
        
        return cookies
    
    def check_ssl(self, url: str) -> Dict:
        """Check SSL/TLS configuration."""
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != 'https':
            self.add_finding('ssl', 'HIGH', 'No HTTPS',
                           'Site not using HTTPS encryption',
                           'Enable HTTPS with valid certificate')
            return {'https': False}
        
        hostname = parsed.hostname
        port = parsed.port or 443
        results = {'https': True, 'issues': []}
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    results['protocol'] = ssock.version()
                    results['cipher'] = ssock.cipher()
                    
                    # Check certificate expiry
                    if cert:
                        not_after = cert.get('notAfter', '')
                        # Parse date like 'Mar  8 00:00:00 2026 GMT'
                        try:
                            from datetime import datetime
                            exp_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                            days_left = (exp_date - datetime.now()).days
                            results['cert_expires'] = not_after
                            results['cert_days_left'] = days_left
                            
                            if days_left < 0:
                                self.add_finding('ssl', 'CRITICAL', 'Certificate Expired',
                                               f'Certificate expired {abs(days_left)} days ago',
                                               'Renew SSL certificate immediately')
                            elif days_left < 30:
                                self.add_finding('ssl', 'HIGH', 'Certificate Expiring Soon',
                                               f'Certificate expires in {days_left} days',
                                               'Renew SSL certificate')
                        except:
                            pass
                    
                    # Check for weak protocols
                    if results['protocol'] in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        self.add_finding('ssl', 'HIGH', f'Weak Protocol: {results["protocol"]}',
                                       'Outdated TLS version with known vulnerabilities',
                                       'Disable TLS 1.0/1.1, use TLS 1.2+')
                        
        except ssl.SSLCertVerificationError as e:
            self.add_finding('ssl', 'HIGH', 'Certificate Verification Failed',
                           str(e), 'Fix certificate chain/validity')
            results['issues'].append(str(e))
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def check_sensitive_paths(self, base_url: str) -> List[Dict]:
        """Check for sensitive files and paths."""
        found = []
        
        def check_path(path):
            url = urllib.parse.urljoin(base_url, path)
            response, _ = self.make_request(url, follow_redirects=False)
            
            if response and hasattr(response, 'status'):
                status = response.status if hasattr(response, 'status') else response.code
                if status == 200:
                    # Read a bit of content to verify it's real
                    try:
                        content = response.read(500).decode('utf-8', errors='ignore')
                        # Filter out generic error pages
                        if 'not found' not in content.lower() and '404' not in content:
                            return {'path': path, 'status': status, 'snippet': content[:100]}
                    except:
                        return {'path': path, 'status': status}
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_path, path): path for path in SENSITIVE_PATHS}
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
                    severity = 'CRITICAL' if any(x in result['path'] for x in ['.git', '.env', 'config', 'backup', '.sql']) else 'HIGH'
                    self.add_finding('exposure', severity,
                                   f'Sensitive path accessible: {result["path"]}',
                                   'File/directory should not be publicly accessible',
                                   'Block access via web server configuration')
                    if self.verbose:
                        print(f"[!] Found: {result['path']}", file=sys.stderr)
        
        return found
    
    def directory_bruteforce(self, base_url: str, wordlist: List[str]) -> List[Dict]:
        """Bruteforce directories."""
        found = []
        
        def check_dir(word):
            url = urllib.parse.urljoin(base_url, '/' + word)
            response, _ = self.make_request(url, follow_redirects=False)
            
            if response:
                status = response.status if hasattr(response, 'status') else response.code
                if status in [200, 301, 302, 403]:
                    return {'path': '/' + word, 'status': status}
            return None
        
        print(f"[*] Bruteforcing {len(wordlist)} paths...", file=sys.stderr)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_dir, word): word for word in wordlist}
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
                    if self.verbose:
                        print(f"[+] {result['status']}: {result['path']}", file=sys.stderr)
        
        return found
    
    def fingerprint(self, url: str) -> Dict:
        """Fingerprint technologies."""
        response, _ = self.make_request(url)
        if not response:
            return {}
        
        tech = {'server': [], 'frameworks': [], 'cms': []}
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        try:
            body = response.read(50000).decode('utf-8', errors='ignore')
        except:
            body = ''
        
        # Server detection
        if 'server' in headers:
            tech['server'].append(headers['server'])
        
        if 'x-powered-by' in headers:
            tech['frameworks'].append(headers['x-powered-by'])
        
        # CMS detection from body
        cms_signatures = {
            'WordPress': ['/wp-content/', '/wp-includes/', 'wp-json'],
            'Drupal': ['drupal.js', '/sites/default/', 'drupal'],
            'Joomla': ['/media/jui/', 'joomla'],
            'Magento': ['/static/frontend/', 'Mage.Cookies'],
            'Shopify': ['cdn.shopify.com', 'shopify'],
        }
        
        for cms, signatures in cms_signatures.items():
            if any(sig.lower() in body.lower() for sig in signatures):
                tech['cms'].append(cms)
        
        # Framework detection
        framework_signatures = {
            'React': ['react', '_reactRoot'],
            'Vue.js': ['vue.js', '__VUE__'],
            'Angular': ['ng-app', 'angular'],
            'jQuery': ['jquery'],
            'Bootstrap': ['bootstrap'],
            'Laravel': ['laravel_session'],
            'Django': ['csrfmiddlewaretoken'],
            'Rails': ['csrf-token', '_rails'],
            'ASP.NET': ['__VIEWSTATE', 'aspnet'],
        }
        
        for fw, signatures in framework_signatures.items():
            if any(sig.lower() in body.lower() for sig in signatures):
                tech['frameworks'].append(fw)
        
        return tech
    
    def scan(self, url: str, full: bool = False, dirbrute: bool = False,
             wordlist: List[str] = None) -> Dict:
        """Run full scan."""
        self.scan_start = datetime.now()
        self.findings = []
        
        print(f"[*] Scanning {url}", file=sys.stderr)
        
        results = {
            'url': url,
            'headers': self.check_security_headers(url),
            'cookies': self.check_cookies(url),
            'ssl': self.check_ssl(url),
        }
        
        if full or True:  # Always do fingerprinting
            results['tech'] = self.fingerprint(url)
        
        if full:
            print("[*] Checking sensitive paths...", file=sys.stderr)
            results['sensitive_paths'] = self.check_sensitive_paths(url)
        
        if dirbrute:
            wl = wordlist or DEFAULT_WORDLIST
            results['directories'] = self.directory_bruteforce(url, wl)
        
        results['findings'] = self.findings
        self.scan_end = datetime.now()
        results['scan_duration'] = (self.scan_end - self.scan_start).total_seconds()
        
        return results


def format_text(results: Dict) -> str:
    """Format results as text."""
    lines = []
    lines.append("=" * 70)
    lines.append("  WEB VULNERABILITY SCANNER — RESULTS")
    lines.append(f"  Target: {results['url']}")
    lines.append(f"  Scan time: {results.get('scan_duration', 0):.1f}s")
    lines.append("=" * 70)
    lines.append("")
    
    # Summary
    findings = results.get('findings', [])
    by_severity = {}
    for f in findings:
        sev = f['severity']
        by_severity[sev] = by_severity.get(sev, 0) + 1
    
    lines.append("─── SUMMARY ────────────────────────────────────────────────────────")
    lines.append(f"  Total findings: {len(findings)}")
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        if sev in by_severity:
            emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}[sev]
            lines.append(f"    {emoji} {sev}: {by_severity[sev]}")
    lines.append("")
    
    # SSL
    ssl_info = results.get('ssl', {})
    if ssl_info:
        lines.append("─── SSL/TLS ────────────────────────────────────────────────────────")
        if ssl_info.get('https'):
            lines.append(f"  ✓ HTTPS enabled")
            if ssl_info.get('protocol'):
                lines.append(f"    Protocol: {ssl_info['protocol']}")
            if ssl_info.get('cert_days_left'):
                lines.append(f"    Certificate expires in: {ssl_info['cert_days_left']} days")
        else:
            lines.append("  ✗ No HTTPS")
        lines.append("")
    
    # Security Headers
    headers = results.get('headers', {})
    if headers:
        lines.append("─── SECURITY HEADERS ───────────────────────────────────────────────")
        for h in headers.get('present', []):
            lines.append(f"  ✓ {h['header']}")
        for h in headers.get('missing', []):
            lines.append(f"  ✗ {h['header']} — {h['description']}")
        if headers.get('info_leak'):
            lines.append("  Information Leakage:")
            for h in headers['info_leak']:
                lines.append(f"    ⚠ {h['header']}: {h['value']}")
        lines.append("")
    
    # Technologies
    tech = results.get('tech', {})
    if tech and any(tech.values()):
        lines.append("─── TECHNOLOGIES ───────────────────────────────────────────────────")
        if tech.get('server'):
            lines.append(f"  Server: {', '.join(tech['server'])}")
        if tech.get('cms'):
            lines.append(f"  CMS: {', '.join(tech['cms'])}")
        if tech.get('frameworks'):
            lines.append(f"  Frameworks: {', '.join(set(tech['frameworks']))}")
        lines.append("")
    
    # Sensitive Paths
    sensitive = results.get('sensitive_paths', [])
    if sensitive:
        lines.append("─── SENSITIVE PATHS FOUND ──────────────────────────────────────────")
        for p in sensitive:
            lines.append(f"  🚨 {p['path']} (HTTP {p['status']})")
        lines.append("")
    
    # Directories
    dirs = results.get('directories', [])
    if dirs:
        lines.append("─── DISCOVERED DIRECTORIES ─────────────────────────────────────────")
        for d in sorted(dirs, key=lambda x: x['status']):
            lines.append(f"  [{d['status']}] {d['path']}")
        lines.append("")
    
    # Detailed Findings
    if findings:
        lines.append("─── DETAILED FINDINGS ──────────────────────────────────────────────")
        for i, f in enumerate(sorted(findings, key=lambda x: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].index(x['severity'])), 1):
            emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}[f['severity']]
            lines.append(f"\n  [{i}] {emoji} {f['severity']} — {f['title']}")
            lines.append(f"      {f['description']}")
            if f.get('remediation'):
                lines.append(f"      → {f['remediation']}")
    
    lines.append("")
    lines.append("=" * 70)
    
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Web vulnerability scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument('url', help='Target URL')
    parser.add_argument('--full', action='store_true',
                        help='Full scan including sensitive path check')
    parser.add_argument('--dirbrute', action='store_true',
                        help='Bruteforce directories')
    parser.add_argument('-w', '--wordlist', help='Wordlist file for directory bruteforce')
    parser.add_argument('-t', '--threads', type=int, default=10,
                        help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=10,
                        help='Request timeout (default: 10s)')
    parser.add_argument('-f', '--format', choices=['text', 'json'], default='text')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('-v', '--verbose', action='store_true')
    
    args = parser.parse_args()
    
    # Normalize URL
    url = args.url
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Load wordlist
    wordlist = None
    if args.wordlist:
        try:
            with open(args.wordlist) as f:
                wordlist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            print(f"[!] Error loading wordlist: {e}", file=sys.stderr)
            sys.exit(1)
    
    scanner = WebScanner(
        timeout=args.timeout,
        threads=args.threads,
        verbose=args.verbose,
    )
    
    results = scanner.scan(url, full=args.full, dirbrute=args.dirbrute, wordlist=wordlist)
    
    if args.format == 'json':
        output = json.dumps(results, indent=2)
    else:
        output = format_text(results)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"[*] Results written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == '__main__':
    main()

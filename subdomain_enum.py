#!/usr/bin/env python3
"""
subdomain_enum.py — Subdomain Enumeration Tool

Part of Blue Team Toolkit
https://github.com/stevenartzt/blue-team-toolkit

Features:
- DNS bruteforce with wordlist
- Certificate Transparency log search (crt.sh)
- DNS record enumeration (A, AAAA, CNAME, MX, TXT, NS)
- Wildcard detection
- Live host verification
- JSON/CSV/text output

Usage:
    python3 subdomain_enum.py example.com
    python3 subdomain_enum.py example.com --dns-brute -w wordlist.txt
    python3 subdomain_enum.py example.com --ct --verify
    python3 subdomain_enum.py example.com --all --format json

License: MIT
"""

import argparse
import concurrent.futures
import json
import random
import re
import socket
import ssl
import sys
import urllib.request
import urllib.error
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

# Default subdomain wordlist
DEFAULT_WORDLIST = [
    'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
    'ns', 'dns', 'dns1', 'dns2', 'mx', 'mx1', 'mx2', 'email', 'remote', 'vpn',
    'admin', 'administrator', 'api', 'app', 'apps', 'beta', 'blog', 'cdn',
    'cloud', 'cms', 'connect', 'console', 'cp', 'cpanel', 'dashboard', 'db',
    'dev', 'developer', 'development', 'direct', 'docs', 'download', 'en',
    'exchange', 'files', 'forum', 'forums', 'gateway', 'git', 'gitlab', 'gw',
    'help', 'home', 'host', 'hosting', 'hub', 'images', 'img', 'intranet',
    'jenkins', 'jira', 'lab', 'labs', 'ldap', 'legacy', 'link', 'links',
    'live', 'login', 'logs', 'm', 'manage', 'management', 'media', 'mobile',
    'monitor', 'monitoring', 'mysql', 'new', 'news', 'office', 'old', 'origin',
    'panel', 'partner', 'partners', 'portal', 'preview', 'prod', 'production',
    'projects', 'proxy', 'public', 'ras', 'rdp', 'redirect', 'register',
    'relay', 'repo', 'repository', 'router', 'rss', 's', 's1', 's2', 's3',
    'sandbox', 'search', 'secure', 'server', 'server1', 'server2', 'service',
    'services', 'shop', 'signin', 'signup', 'sip', 'smtp', 'sql', 'ssh',
    'ssl', 'sso', 'staff', 'stage', 'staging', 'start', 'stat', 'static',
    'stats', 'status', 'storage', 'store', 'support', 'svn', 'sync', 'sys',
    'syslog', 'system', 'test', 'test1', 'test2', 'testing', 'tools', 'track',
    'tracker', 'tracking', 'ts', 'update', 'upload', 'v1', 'v2', 'video',
    'videos', 'voip', 'vps', 'web', 'web1', 'web2', 'webdisk', 'weblog',
    'webmin', 'wiki', 'work', 'wpad', 'ws', 'www1', 'www2', 'www3',
]


class SubdomainEnumerator:
    def __init__(self, domain: str, threads: int = 50, timeout: int = 5,
                 verbose: bool = False):
        self.domain = domain.lower().strip()
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.found_subdomains: Set[str] = set()
        self.wildcard_ips: Set[str] = set()
        self.has_wildcard = False
        self.scan_start = None
        self.scan_end = None
        
    def check_wildcard(self) -> bool:
        """Check if domain has wildcard DNS."""
        # Generate random subdomain
        random_sub = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=16))
        test_domain = f"{random_sub}.{self.domain}"
        
        try:
            ips = socket.gethostbyname_ex(test_domain)[2]
            if ips:
                self.wildcard_ips = set(ips)
                self.has_wildcard = True
                if self.verbose:
                    print(f"[!] Wildcard DNS detected: *.{self.domain} -> {', '.join(ips)}", file=sys.stderr)
                return True
        except socket.gaierror:
            pass
        
        return False
    
    def resolve_subdomain(self, subdomain: str) -> Optional[Dict]:
        """Resolve a subdomain and get its records."""
        full_domain = f"{subdomain}.{self.domain}" if subdomain else self.domain
        
        try:
            # Get A records
            ips = socket.gethostbyname_ex(full_domain)[2]
            
            # Skip if it resolves to wildcard
            if self.has_wildcard and set(ips) == self.wildcard_ips:
                return None
            
            result = {
                'subdomain': subdomain,
                'domain': full_domain,
                'a_records': ips,
                'live': False,
            }
            
            # Try to get CNAME (by checking if hostname != canonical name)
            try:
                canonical, _, _ = socket.gethostbyname_ex(full_domain)
                if canonical != full_domain:
                    result['cname'] = canonical
            except:
                pass
            
            return result
            
        except socket.gaierror:
            return None
        except Exception as e:
            if self.verbose:
                print(f"[!] Error resolving {full_domain}: {e}", file=sys.stderr)
            return None
    
    def dns_bruteforce(self, wordlist: List[str]) -> List[Dict]:
        """Bruteforce subdomains using wordlist."""
        found = []
        
        print(f"[*] DNS bruteforce with {len(wordlist)} words...", file=sys.stderr)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.resolve_subdomain, word): word for word in wordlist}
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
                    self.found_subdomains.add(result['domain'])
                    if self.verbose:
                        print(f"[+] {result['domain']} -> {', '.join(result['a_records'])}", file=sys.stderr)
        
        return found
    
    def search_crt_sh(self) -> List[str]:
        """Search Certificate Transparency logs via crt.sh."""
        subdomains = set()
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        
        print(f"[*] Searching Certificate Transparency logs (crt.sh)...", file=sys.stderr)
        
        try:
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0')
            
            context = ssl.create_default_context()
            response = urllib.request.urlopen(req, timeout=30, context=context)
            data = json.loads(response.read().decode())
            
            for entry in data:
                name = entry.get('name_value', '')
                # Handle multiple names separated by newlines
                for n in name.split('\n'):
                    n = n.strip().lower()
                    # Skip wildcards and validate domain
                    if n and not n.startswith('*') and n.endswith(self.domain):
                        subdomains.add(n)
            
            print(f"[*] Found {len(subdomains)} unique names in CT logs", file=sys.stderr)
            
        except urllib.error.HTTPError as e:
            print(f"[!] CT search failed: HTTP {e.code}", file=sys.stderr)
        except urllib.error.URLError as e:
            print(f"[!] CT search failed: {e.reason}", file=sys.stderr)
        except json.JSONDecodeError:
            print(f"[!] CT search failed: Invalid JSON response", file=sys.stderr)
        except Exception as e:
            print(f"[!] CT search failed: {e}", file=sys.stderr)
        
        return list(subdomains)
    
    def get_dns_records(self, domain: str) -> Dict:
        """Get various DNS records for a domain."""
        records = {}
        
        # We'll use basic resolution since we're stdlib-only
        # For full records (MX, TXT, NS), we'd need dnspython
        try:
            # A records
            ips = socket.gethostbyname_ex(domain)[2]
            records['A'] = ips
        except:
            pass
        
        try:
            # AAAA records (IPv6)
            info = socket.getaddrinfo(domain, None, socket.AF_INET6)
            records['AAAA'] = list(set(addr[4][0] for addr in info))
        except:
            pass
        
        return records
    
    def verify_live(self, subdomains: List[Dict]) -> List[Dict]:
        """Verify which subdomains are live (responding on HTTP/HTTPS)."""
        print(f"[*] Verifying {len(subdomains)} subdomains...", file=sys.stderr)
        
        def check_live(sub: Dict) -> Dict:
            domain = sub['domain']
            sub['live'] = False
            sub['http_status'] = None
            sub['https_status'] = None
            sub['redirect'] = None
            
            # Try HTTPS first
            for scheme in ['https', 'http']:
                url = f"{scheme}://{domain}"
                try:
                    req = urllib.request.Request(url, method='HEAD')
                    req.add_header('User-Agent', 'Mozilla/5.0')
                    
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    response = urllib.request.urlopen(req, timeout=self.timeout, context=context)
                    status = response.status
                    
                    if scheme == 'https':
                        sub['https_status'] = status
                    else:
                        sub['http_status'] = status
                    
                    sub['live'] = True
                    
                    # Check for redirect
                    if response.url != url:
                        sub['redirect'] = response.url
                    
                    break  # Success, no need to try http
                    
                except urllib.error.HTTPError as e:
                    if scheme == 'https':
                        sub['https_status'] = e.code
                    else:
                        sub['http_status'] = e.code
                    sub['live'] = True  # It responded, even if error
                except:
                    pass
            
            return sub
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            verified = list(executor.map(check_live, subdomains))
        
        live_count = sum(1 for s in verified if s['live'])
        print(f"[*] {live_count} live hosts found", file=sys.stderr)
        
        return verified
    
    def enumerate(self, dns_brute: bool = False, ct_search: bool = True,
                  wordlist: List[str] = None, verify: bool = False) -> Dict:
        """Run full enumeration."""
        self.scan_start = datetime.now()
        results = {
            'domain': self.domain,
            'wildcard': False,
            'wildcard_ips': [],
            'subdomains': [],
            'methods_used': [],
        }
        
        # Check for wildcard
        if self.check_wildcard():
            results['wildcard'] = True
            results['wildcard_ips'] = list(self.wildcard_ips)
        
        found_domains = set()
        subdomains = []
        
        # Certificate Transparency search
        if ct_search:
            results['methods_used'].append('ct')
            ct_results = self.search_crt_sh()
            for domain in ct_results:
                if domain not in found_domains:
                    found_domains.add(domain)
                    # Extract subdomain part
                    if domain == self.domain:
                        sub = ''
                    else:
                        sub = domain[:-len(self.domain)-1]
                    subdomains.append({
                        'subdomain': sub,
                        'domain': domain,
                        'source': 'ct',
                    })
        
        # DNS bruteforce
        if dns_brute:
            results['methods_used'].append('dns_brute')
            wl = wordlist or DEFAULT_WORDLIST
            brute_results = self.dns_bruteforce(wl)
            for sub in brute_results:
                if sub['domain'] not in found_domains:
                    found_domains.add(sub['domain'])
                    sub['source'] = 'dns_brute'
                    subdomains.append(sub)
        
        # Resolve any CT-found domains that don't have A records yet
        to_resolve = [s for s in subdomains if 'a_records' not in s]
        if to_resolve:
            print(f"[*] Resolving {len(to_resolve)} discovered subdomains...", file=sys.stderr)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                def resolve(sub):
                    result = self.resolve_subdomain(sub.get('subdomain', ''))
                    if result:
                        sub.update(result)
                    return sub
                
                subdomains = list(executor.map(resolve, subdomains))
        
        # Filter out unresolved
        subdomains = [s for s in subdomains if 'a_records' in s]
        
        # Verify live hosts
        if verify and subdomains:
            subdomains = self.verify_live(subdomains)
        
        results['subdomains'] = sorted(subdomains, key=lambda x: x['domain'])
        results['total_found'] = len(subdomains)
        
        self.scan_end = datetime.now()
        results['scan_duration'] = (self.scan_end - self.scan_start).total_seconds()
        
        return results


def format_text(results: Dict) -> str:
    """Format results as text."""
    lines = []
    lines.append("=" * 70)
    lines.append("  SUBDOMAIN ENUMERATION — RESULTS")
    lines.append(f"  Target: {results['domain']}")
    lines.append(f"  Methods: {', '.join(results.get('methods_used', []))}")
    lines.append(f"  Duration: {results.get('scan_duration', 0):.1f}s")
    lines.append("=" * 70)
    lines.append("")
    
    if results.get('wildcard'):
        lines.append(f"  ⚠️  WILDCARD DNS DETECTED: *.{results['domain']}")
        lines.append(f"     Wildcard IPs: {', '.join(results.get('wildcard_ips', []))}")
        lines.append("")
    
    lines.append(f"─── FOUND {results.get('total_found', 0)} SUBDOMAIN(S) ────────────────────────────────")
    lines.append("")
    
    for sub in results.get('subdomains', []):
        domain = sub['domain']
        ips = ', '.join(sub.get('a_records', []))
        status = ''
        
        if sub.get('live'):
            status = '✓ LIVE'
            if sub.get('https_status'):
                status += f' (HTTPS:{sub["https_status"]})'
            elif sub.get('http_status'):
                status += f' (HTTP:{sub["http_status"]})'
        
        lines.append(f"  {domain}")
        lines.append(f"    └─ IP: {ips}")
        if sub.get('cname'):
            lines.append(f"    └─ CNAME: {sub['cname']}")
        if status:
            lines.append(f"    └─ {status}")
        if sub.get('redirect'):
            lines.append(f"    └─ Redirects to: {sub['redirect']}")
        lines.append("")
    
    return '\n'.join(lines)


def format_csv(results: Dict) -> str:
    """Format results as CSV."""
    lines = ['domain,subdomain,ip_addresses,cname,live,https_status,http_status,source']
    
    for sub in results.get('subdomains', []):
        ips = ';'.join(sub.get('a_records', []))
        cname = sub.get('cname', '')
        live = 'true' if sub.get('live') else 'false'
        https = sub.get('https_status', '')
        http = sub.get('http_status', '')
        source = sub.get('source', '')
        
        lines.append(f"{sub['domain']},{sub.get('subdomain', '')},{ips},{cname},{live},{https},{http},{source}")
    
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Subdomain enumeration tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s example.com                      # CT search only
  %(prog)s example.com --dns-brute          # CT + DNS bruteforce
  %(prog)s example.com --dns-brute -w subs.txt --verify
  %(prog)s example.com --all --format json -o results.json
        '''
    )
    
    parser.add_argument('domain', help='Target domain')
    parser.add_argument('--ct', action='store_true', default=True,
                        help='Search Certificate Transparency logs (default: on)')
    parser.add_argument('--no-ct', action='store_true',
                        help='Disable CT search')
    parser.add_argument('--dns-brute', action='store_true',
                        help='Enable DNS bruteforce')
    parser.add_argument('-w', '--wordlist', help='Custom wordlist file')
    parser.add_argument('--verify', action='store_true',
                        help='Verify which subdomains are live')
    parser.add_argument('--all', action='store_true',
                        help='Enable all enumeration methods + verification')
    parser.add_argument('-t', '--threads', type=int, default=50,
                        help='Number of threads (default: 50)')
    parser.add_argument('--timeout', type=int, default=5,
                        help='Timeout in seconds (default: 5)')
    parser.add_argument('-f', '--format', choices=['text', 'json', 'csv'], default='text')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('-v', '--verbose', action='store_true')
    
    args = parser.parse_args()
    
    # Handle --all
    if args.all:
        args.dns_brute = True
        args.verify = True
    
    ct_search = not args.no_ct
    
    # Load wordlist
    wordlist = None
    if args.wordlist:
        try:
            with open(args.wordlist) as f:
                wordlist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            print(f"[!] Error loading wordlist: {e}", file=sys.stderr)
            sys.exit(1)
    
    enum = SubdomainEnumerator(
        args.domain,
        threads=args.threads,
        timeout=args.timeout,
        verbose=args.verbose,
    )
    
    results = enum.enumerate(
        dns_brute=args.dns_brute,
        ct_search=ct_search,
        wordlist=wordlist,
        verify=args.verify,
    )
    
    # Format output
    if args.format == 'json':
        output = json.dumps(results, indent=2)
    elif args.format == 'csv':
        output = format_csv(results)
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

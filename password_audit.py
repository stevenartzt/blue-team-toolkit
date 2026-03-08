#!/usr/bin/env python3
"""
password_audit.py — Password Strength Analyzer & Auditor

Part of Blue Team Toolkit
https://github.com/stevenartzt/blue-team-toolkit

Features:
- Analyze /etc/shadow for weak password hashes (with wordlist)
- Check password policy compliance
- Detect accounts with no password, disabled, or locked
- Identify password reuse (same hashes)
- Password strength scoring for arbitrary strings
- Entropy calculation
- Common pattern detection

Usage:
    python3 password_audit.py --analyze "MyPassword123!"
    sudo python3 password_audit.py --shadow /etc/shadow
    sudo python3 password_audit.py --shadow /etc/shadow -w rockyou.txt
    python3 password_audit.py --policy-check "password123"

License: MIT
"""

import argparse
import crypt
import hashlib
import math
import os
import re
import sys
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

# Common weak passwords (mini wordlist)
COMMON_PASSWORDS = [
    'password', 'password1', 'password123', '123456', '123456789', 'qwerty',
    'abc123', 'monkey', 'master', 'dragon', 'letmein', 'login', 'admin',
    'welcome', 'shadow', 'sunshine', 'princess', 'football', 'baseball',
    'iloveyou', 'trustno1', 'batman', 'superman', 'access', 'hello',
    'charlie', 'donald', 'password!', 'qwerty123', 'qwertyuiop', 'passw0rd',
    'pass123', 'pass1234', 'changeme', 'root', 'toor', 'administrator',
    '12345678', '1234567890', '1234567', '12345', '1234', 'password1!',
    '000000', '111111', '121212', '654321', 'lovely', 'michael', 'ashley',
    'nicole', 'jessica', 'daniel', 'jennifer', 'jordan', 'hunter', 'pepper',
    'maggie', 'cookie', 'summer', 'winter', 'autumn', 'spring', 'secret',
    'computer', 'internet', 'starwars', 'matrix', 'qweasd', 'zxcvbn',
]

# Keyboard patterns
KEYBOARD_PATTERNS = [
    'qwerty', 'qwertyuiop', 'asdfgh', 'asdfghjkl', 'zxcvbn', 'zxcvbnm',
    '123456', '1234567', '12345678', '123456789', '1234567890',
    'qazwsx', 'qweasd', 'poiuyt', 'lkjhgf', 'mnbvcx',
    '!@#$%^', '!@#$%^&*', 'qwerty123', 'asdf1234',
]

# Leet speak substitutions
LEET_MAP = {
    'a': ['4', '@'], 'e': ['3'], 'i': ['1', '!'], 'o': ['0'],
    's': ['5', '$'], 't': ['7'], 'l': ['1'], 'b': ['8'],
}


class PasswordAnalyzer:
    def __init__(self, min_length: int = 8, require_upper: bool = True,
                 require_lower: bool = True, require_digit: bool = True,
                 require_special: bool = True, min_entropy: float = 50.0):
        self.min_length = min_length
        self.require_upper = require_upper
        self.require_lower = require_lower
        self.require_digit = require_digit
        self.require_special = require_special
        self.min_entropy = min_entropy
        
    def calculate_entropy(self, password: str) -> float:
        """Calculate password entropy in bits."""
        charset_size = 0
        
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'[0-9]', password):
            charset_size += 10
        if re.search(r'[!@#$%^&*()_+=\-\[\]{}|;:,.<>?/~`]', password):
            charset_size += 32
        if re.search(r'\s', password):
            charset_size += 1
        
        if charset_size == 0:
            return 0
        
        # Entropy = length * log2(charset_size)
        entropy = len(password) * math.log2(charset_size)
        
        # Reduce entropy for patterns
        penalty = 0
        
        # Sequential characters
        for i in range(len(password) - 2):
            if ord(password[i+1]) == ord(password[i]) + 1 and \
               ord(password[i+2]) == ord(password[i]) + 2:
                penalty += 5
        
        # Repeated characters
        for i in range(len(password) - 2):
            if password[i] == password[i+1] == password[i+2]:
                penalty += 5
        
        return max(0, entropy - penalty)
    
    def check_common_patterns(self, password: str) -> List[str]:
        """Check for common weak patterns."""
        patterns = []
        lower = password.lower()
        
        # Keyboard patterns
        for pattern in KEYBOARD_PATTERNS:
            if pattern in lower:
                patterns.append(f"Keyboard pattern: {pattern}")
        
        # Common words
        for word in COMMON_PASSWORDS[:50]:  # Check top 50
            if word in lower:
                patterns.append(f"Contains common word: {word}")
        
        # Simple leet substitutions
        deleet = lower
        for char, subs in LEET_MAP.items():
            for sub in subs:
                deleet = deleet.replace(sub, char)
        
        for word in COMMON_PASSWORDS[:50]:
            if word in deleet and word not in lower:
                patterns.append(f"Leet-speak variant of: {word}")
        
        # Date patterns
        if re.search(r'(19|20)\d{2}', password):
            patterns.append("Contains year (possible birth year)")
        if re.search(r'\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}', password):
            patterns.append("Contains date pattern")
        
        # Simple increments
        if re.search(r'(.)\1{3,}', password):
            patterns.append("Contains repeated characters (4+)")
        
        return patterns
    
    def analyze(self, password: str) -> Dict:
        """Analyze password strength."""
        result = {
            'password': password,
            'length': len(password),
            'entropy': self.calculate_entropy(password),
            'score': 0,  # 0-100
            'strength': '',  # Weak/Medium/Strong/Very Strong
            'issues': [],
            'patterns': [],
            'policy_compliant': True,
        }
        
        # Check policy requirements
        if len(password) < self.min_length:
            result['issues'].append(f"Too short (min {self.min_length} chars)")
            result['policy_compliant'] = False
        
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'[0-9]', password))
        has_special = bool(re.search(r'[!@#$%^&*()_+=\-\[\]{}|;:,.<>?/~`]', password))
        
        if self.require_upper and not has_upper:
            result['issues'].append("Missing uppercase letter")
            result['policy_compliant'] = False
        if self.require_lower and not has_lower:
            result['issues'].append("Missing lowercase letter")
            result['policy_compliant'] = False
        if self.require_digit and not has_digit:
            result['issues'].append("Missing digit")
            result['policy_compliant'] = False
        if self.require_special and not has_special:
            result['issues'].append("Missing special character")
            result['policy_compliant'] = False
        
        if result['entropy'] < self.min_entropy:
            result['issues'].append(f"Low entropy ({result['entropy']:.1f} < {self.min_entropy} bits)")
            result['policy_compliant'] = False
        
        # Check patterns
        result['patterns'] = self.check_common_patterns(password)
        if result['patterns']:
            result['issues'].extend(result['patterns'][:3])  # Top 3
        
        # Check against common passwords
        if password.lower() in COMMON_PASSWORDS:
            result['issues'].insert(0, "⚠️ FOUND IN COMMON PASSWORD LIST")
            result['policy_compliant'] = False
        
        # Calculate score
        score = 0
        
        # Length score (up to 30 points)
        score += min(30, len(password) * 2)
        
        # Character variety (up to 30 points)
        score += 8 if has_upper else 0
        score += 8 if has_lower else 0
        score += 8 if has_digit else 0
        score += 6 if has_special else 0
        
        # Entropy bonus (up to 30 points)
        score += min(30, result['entropy'] / 3)
        
        # Penalties
        score -= len(result['patterns']) * 10
        score -= 30 if password.lower() in COMMON_PASSWORDS else 0
        
        result['score'] = max(0, min(100, int(score)))
        
        # Strength label
        if result['score'] >= 80:
            result['strength'] = 'Very Strong'
        elif result['score'] >= 60:
            result['strength'] = 'Strong'
        elif result['score'] >= 40:
            result['strength'] = 'Medium'
        else:
            result['strength'] = 'Weak'
        
        return result


class ShadowAuditor:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.accounts: List[Dict] = []
        
    def parse_shadow(self, shadow_path: str = '/etc/shadow') -> List[Dict]:
        """Parse shadow file."""
        accounts = []
        
        try:
            with open(shadow_path, 'r') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) >= 2:
                        username = parts[0]
                        password_hash = parts[1]
                        
                        account = {
                            'username': username,
                            'hash': password_hash,
                            'status': 'active',
                            'hash_type': '',
                            'cracked': False,
                            'cracked_password': None,
                        }
                        
                        # Determine status
                        if password_hash == '' or password_hash == '!!':
                            account['status'] = 'no_password'
                        elif password_hash == '*' or password_hash == '!*':
                            account['status'] = 'disabled'
                        elif password_hash.startswith('!'):
                            account['status'] = 'locked'
                        elif password_hash.startswith('$'):
                            # Determine hash type
                            if password_hash.startswith('$1$'):
                                account['hash_type'] = 'MD5'
                            elif password_hash.startswith('$5$'):
                                account['hash_type'] = 'SHA-256'
                            elif password_hash.startswith('$6$'):
                                account['hash_type'] = 'SHA-512'
                            elif password_hash.startswith('$y$') or password_hash.startswith('$gy$'):
                                account['hash_type'] = 'yescrypt'
                            elif password_hash.startswith('$2'):
                                account['hash_type'] = 'bcrypt'
                        
                        # Get additional fields if present
                        if len(parts) >= 3:
                            try:
                                last_change = int(parts[2]) if parts[2] else None
                                if last_change:
                                    # Days since Jan 1, 1970
                                    from datetime import datetime, timedelta
                                    account['last_change'] = (datetime(1970, 1, 1) + timedelta(days=last_change)).isoformat()
                            except:
                                pass
                        
                        if len(parts) >= 5:
                            try:
                                max_days = int(parts[4]) if parts[4] else None
                                if max_days and max_days < 99999:
                                    account['max_age_days'] = max_days
                            except:
                                pass
                        
                        accounts.append(account)
                        
        except PermissionError:
            print("[!] Permission denied. Run with sudo.", file=sys.stderr)
            sys.exit(1)
        except FileNotFoundError:
            print(f"[!] File not found: {shadow_path}", file=sys.stderr)
            sys.exit(1)
        
        self.accounts = accounts
        return accounts
    
    def crack_with_wordlist(self, wordlist_path: str = None, 
                           wordlist: List[str] = None) -> Dict[str, str]:
        """Attempt to crack hashes with wordlist."""
        if wordlist_path:
            try:
                with open(wordlist_path, 'r', errors='ignore') as f:
                    words = [line.strip() for line in f if line.strip()]
            except Exception as e:
                print(f"[!] Error loading wordlist: {e}", file=sys.stderr)
                words = COMMON_PASSWORDS
        else:
            words = wordlist or COMMON_PASSWORDS
        
        cracked = {}
        hashable_accounts = [a for a in self.accounts 
                           if a['status'] == 'active' and a['hash'].startswith('$')]
        
        print(f"[*] Testing {len(words)} passwords against {len(hashable_accounts)} accounts...", 
              file=sys.stderr)
        
        for account in hashable_accounts:
            username = account['username']
            target_hash = account['hash']
            
            # Extract salt (everything up to and including the last $)
            # Format: $type$salt$hash
            parts = target_hash.split('$')
            if len(parts) >= 4:
                salt = '$'.join(parts[:3]) + '$'
            else:
                continue
            
            for password in words:
                try:
                    computed = crypt.crypt(password, salt)
                    if computed == target_hash:
                        cracked[username] = password
                        account['cracked'] = True
                        account['cracked_password'] = password
                        if self.verbose:
                            print(f"[+] Cracked: {username}:{password}", file=sys.stderr)
                        break
                except Exception:
                    continue
        
        return cracked
    
    def find_reused_hashes(self) -> Dict[str, List[str]]:
        """Find accounts with identical password hashes."""
        hash_to_users = defaultdict(list)
        
        for account in self.accounts:
            if account['status'] == 'active' and account['hash'].startswith('$'):
                hash_to_users[account['hash']].append(account['username'])
        
        # Filter to only reused hashes
        return {h: users for h, users in hash_to_users.items() if len(users) > 1}
    
    def audit(self, wordlist_path: str = None) -> Dict:
        """Run full audit."""
        results = {
            'total_accounts': len(self.accounts),
            'active_accounts': 0,
            'disabled_accounts': 0,
            'locked_accounts': 0,
            'no_password': 0,
            'weak_hash_algorithm': [],
            'reused_passwords': {},
            'cracked': {},
            'findings': [],
        }
        
        for account in self.accounts:
            if account['status'] == 'active':
                results['active_accounts'] += 1
            elif account['status'] == 'disabled':
                results['disabled_accounts'] += 1
            elif account['status'] == 'locked':
                results['locked_accounts'] += 1
            elif account['status'] == 'no_password':
                results['no_password'] += 1
                results['findings'].append({
                    'severity': 'CRITICAL',
                    'username': account['username'],
                    'issue': 'No password set',
                })
        
        # Check for weak algorithms
        for account in self.accounts:
            if account['hash_type'] == 'MD5':
                results['weak_hash_algorithm'].append(account['username'])
                results['findings'].append({
                    'severity': 'HIGH',
                    'username': account['username'],
                    'issue': 'Using weak MD5 hash algorithm',
                })
        
        # Check for reused passwords
        results['reused_passwords'] = self.find_reused_hashes()
        for hash_val, users in results['reused_passwords'].items():
            results['findings'].append({
                'severity': 'MEDIUM',
                'username': ', '.join(users),
                'issue': f'Password reuse detected ({len(users)} accounts)',
            })
        
        # Attempt to crack with wordlist
        if wordlist_path or True:  # Always try common passwords
            results['cracked'] = self.crack_with_wordlist(wordlist_path)
            for username, password in results['cracked'].items():
                results['findings'].append({
                    'severity': 'CRITICAL',
                    'username': username,
                    'issue': f'Password cracked: {password}',
                })
        
        return results


def format_analysis(result: Dict) -> str:
    """Format password analysis result."""
    lines = []
    lines.append("=" * 60)
    lines.append("  PASSWORD STRENGTH ANALYSIS")
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"  Password:  {'*' * len(result['password'])}")
    lines.append(f"  Length:    {result['length']} characters")
    lines.append(f"  Entropy:   {result['entropy']:.1f} bits")
    lines.append(f"  Score:     {result['score']}/100")
    lines.append(f"  Strength:  {result['strength']}")
    lines.append("")
    
    # Visual score bar
    filled = int(result['score'] / 5)
    bar = '█' * filled + '░' * (20 - filled)
    lines.append(f"  [{bar}] {result['score']}%")
    lines.append("")
    
    if result['policy_compliant']:
        lines.append("  ✓ Meets password policy requirements")
    else:
        lines.append("  ✗ Does NOT meet password policy requirements")
    
    if result['issues']:
        lines.append("")
        lines.append("─── ISSUES ───────────────────────────────────────────────")
        for issue in result['issues']:
            lines.append(f"  • {issue}")
    
    lines.append("")
    return '\n'.join(lines)


def format_audit(results: Dict) -> str:
    """Format shadow audit results."""
    lines = []
    lines.append("=" * 70)
    lines.append("  PASSWORD AUDIT — SHADOW FILE ANALYSIS")
    lines.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 70)
    lines.append("")
    
    lines.append("─── SUMMARY ────────────────────────────────────────────────────────")
    lines.append(f"  Total accounts:     {results['total_accounts']}")
    lines.append(f"  Active:             {results['active_accounts']}")
    lines.append(f"  Disabled:           {results['disabled_accounts']}")
    lines.append(f"  Locked:             {results['locked_accounts']}")
    lines.append(f"  No password:        {results['no_password']}")
    lines.append("")
    
    # Findings by severity
    findings = results.get('findings', [])
    critical = [f for f in findings if f['severity'] == 'CRITICAL']
    high = [f for f in findings if f['severity'] == 'HIGH']
    medium = [f for f in findings if f['severity'] == 'MEDIUM']
    
    if critical or high or medium:
        lines.append("─── FINDINGS ───────────────────────────────────────────────────────")
        lines.append("")
        
        for f in critical:
            lines.append(f"  🔴 CRITICAL — {f['username']}")
            lines.append(f"      {f['issue']}")
            lines.append("")
        
        for f in high:
            lines.append(f"  🟠 HIGH — {f['username']}")
            lines.append(f"      {f['issue']}")
            lines.append("")
        
        for f in medium:
            lines.append(f"  🟡 MEDIUM — {f['username']}")
            lines.append(f"      {f['issue']}")
            lines.append("")
    else:
        lines.append("  ✓ No significant issues found")
        lines.append("")
    
    # Recommendations
    lines.append("─── RECOMMENDATIONS ────────────────────────────────────────────────")
    
    if results['no_password'] > 0:
        lines.append("  1. 🚨 Set passwords for accounts with no password")
    if results['weak_hash_algorithm']:
        lines.append("  2. Upgrade MD5 hashes to SHA-512 or yescrypt")
    if results['cracked']:
        lines.append("  3. 🚨 IMMEDIATELY change cracked passwords")
    if results['reused_passwords']:
        lines.append("  4. Enforce unique passwords per account")
    if not findings:
        lines.append("  • Continue regular password audits")
        lines.append("  • Consider implementing password rotation policy")
    
    lines.append("")
    lines.append("=" * 70)
    
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Password strength analyzer and shadow file auditor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s --analyze "MyP@ssw0rd!"        # Analyze single password
  %(prog)s --policy-check "password123"    # Check against policy
  sudo %(prog)s --shadow /etc/shadow       # Audit shadow file
  sudo %(prog)s --shadow /etc/shadow -w rockyou.txt  # With wordlist
        '''
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--analyze', '-a', metavar='PASSWORD',
                       help='Analyze password strength')
    group.add_argument('--policy-check', '-p', metavar='PASSWORD',
                       help='Check password against policy')
    group.add_argument('--shadow', '-s', metavar='FILE',
                       help='Audit shadow file')
    
    parser.add_argument('-w', '--wordlist', help='Wordlist for cracking')
    parser.add_argument('--min-length', type=int, default=8,
                        help='Minimum password length (default: 8)')
    parser.add_argument('--min-entropy', type=float, default=50,
                        help='Minimum entropy bits (default: 50)')
    parser.add_argument('-f', '--format', choices=['text', 'json'], default='text')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('-v', '--verbose', action='store_true')
    
    args = parser.parse_args()
    
    if args.analyze or args.policy_check:
        password = args.analyze or args.policy_check
        analyzer = PasswordAnalyzer(
            min_length=args.min_length,
            min_entropy=args.min_entropy,
        )
        result = analyzer.analyze(password)
        
        if args.format == 'json':
            output = json.dumps(result, indent=2)
        else:
            output = format_analysis(result)
    
    elif args.shadow:
        auditor = ShadowAuditor(verbose=args.verbose)
        auditor.parse_shadow(args.shadow)
        results = auditor.audit(args.wordlist)
        
        if args.format == 'json':
            # Remove raw hashes from JSON output for security
            import json
            output = json.dumps(results, indent=2)
        else:
            output = format_audit(results)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"[*] Results written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == '__main__':
    import json  # Needed for JSON output
    main()

#!/usr/bin/env python3
"""
ZORT - Advanced URL Analysis Tool
Bug Bounty & Pentesting Edition

A powerful URL analysis and vulnerability detection tool for security researchers.
"""

import asyncio
import aiohttp
import argparse
import re
import sys
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from collections import defaultdict
import json

# Color codes for terminal output
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    MAGENTA = '\033[0;35m'
    CYAN = '\033[0;36m'
    NC = '\033[0m'  # No Color
    BOLD = '\033[1m'

# Configuration
class Config:
    BUILTIN_KEYWORDS = [
        # Authentication & Authorization
        "admin", "administrator", "auth", "authentication", "login", "signin", "signup",
        "register", "password", "passwd", "credential", "oauth", "saml", "sso",
        "session", "cookie", "jwt", "bearer", "token", "refresh", "access_token",
        
        # API & Endpoints
        "api", "rest", "graphql", "soap", "grpc", "endpoint", "webhook", "callback",
        "v1", "v2", "v3", "v4", "version", "swagger", "openapi", "wsdl",
        
        # Sensitive Data
        "key", "secret", "private", "credential", "certificate", "cert", "pem",
        "config", "configuration", "settings", "env", "environment",
        
        # Database & Storage
        "database", "db", "sql", "mysql", "postgres", "mongo", "redis", "elastic",
        "backup", "dump", "export", "archive", "s3", "bucket", "storage", "blob",
        
        # Development & Testing
        "dev", "development", "test", "testing", "debug", "staging", "uat",
        "sandbox", "demo", "preview", "beta", "alpha", "internal",
        
        # Infrastructure
        "server", "console", "dashboard", "panel", "monitor", "metrics",
        "docker", "kubernetes", "k8s", "jenkins", "gitlab", "github",
        "aws", "azure", "gcp", "cloud", "firebase", "heroku",
        
        # Security Critical
        "upload", "download", "file", "document", "image", "avatar",
        "user", "users", "account", "profile", "member", "customer",
        "payment", "billing", "invoice", "transaction", "checkout",
        "email", "mail", "smtp", "imap", "webmail", "mailbox",
        
        # Sensitive Files
        ".env", ".git", ".svn", ".config", ".sql", ".db", ".log", ".bak", ".backup",
        ".old", ".tmp", ".temp", ".swp", "phpinfo", "info.php",
        
        # Admin Panels
        "wp-admin", "wp-config", "administrator", "manager", "adminer",
        "phpmyadmin", "cpanel", "plesk", "webmin", "control",
        
        # Common Vulnerabilities
        "redirect", "url", "file", "path", "dir", "page", "include",
        "exec", "cmd", "command", "shell", "eval", "system",
    ]
    
    TOKEN_PATTERNS = [
        r'api[_-]?key', r'access[_-]?token', r'auth[_-]?token',
        r'session[_-]?id', r'session[_-]?token', r'jwt[_-]?token',
        r'bearer[_-]?token', r'refresh[_-]?token', r'client[_-]?secret',
        r'client[_-]?id', r'api[_-]?secret', r'private[_-]?key',
        r'secret[_-]?key', r'access[_-]?key', r'aws[_-]?key',
        r's3[_-]?key', r'oauth[_-]?token', r'slack[_-]?token',
        r'github[_-]?token', r'gitlab[_-]?token',
    ]
    
    VULN_PATTERNS = {
        'sqli': ['id=', 'user=', 'username=', 'email=', 'search=', 'q=', 'query=', 'keyword=', 'category=', 'item=', 'product='],
        'xss': ['search=', 'q=', 'query=', 'keyword=', 'name=', 'comment=', 'message=', 'title=', 'description='],
        'lfi': ['file=', 'path=', 'page=', 'include=', 'dir=', 'folder=', 'document=', 'template=', 'layout='],
        'rfi': ['url=', 'uri=', 'link=', 'src=', 'source=', 'redirect=', 'return=', 'goto=', 'next='],
        'ssrf': ['url=', 'uri=', 'link=', 'host=', 'proxy=', 'api=', 'endpoint=', 'callback=', 'webhook='],
        'idor': ['id=', 'uid=', 'user_id=', 'account=', 'profile=', 'order=', 'invoice=', 'document='],
        'openredirect': ['redirect=', 'return=', 'url=', 'next=', 'goto=', 'continue=', 'target=', 'dest='],
    }
    
    INTERESTING_EXTENSIONS = [
        '.sql', '.db', '.sqlite', '.bak', '.backup', '.old', '.orig', '.save',
        '.conf', '.config', '.ini', '.env', '.properties', '.yaml', '.yml',
        '.json', '.xml', '.log', '.txt', '.csv', '.xls', '.xlsx',
        '.zip', '.tar', '.gz', '.rar', '.7z', '.dump', '.dmp',
        '.key', '.pem', '.crt', '.cer', '.p12', '.pfx',
        '.git', '.svn', '.DS_Store', '.htaccess', '.htpasswd',
        '.php~', '.php.bak', '.asp.bak', '.jsp.bak', '.swp',
    ]
    
    API_PATTERNS = ['/v1', '/v2', '/v3', '/v4', '/api/', '/rest/', '/graphql', '/ws/', '/service/']
    
    INTERESTING_STATUS_CODES = [401, 403, 405, 429, 500, 501, 502, 503]
    
    # JavaScript file patterns
    JS_EXTENSIONS = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.json']
    
    # Sensitive data patterns to search in JS files
    JS_SENSITIVE_PATTERNS = {
        'api_keys': [
            r'["\']?api[_-]?key["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
            r'["\']?apikey["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
            r'["\']?api[_-]?secret["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
        ],
        'access_tokens': [
            r'["\']?access[_-]?token["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-\.]{20,}["\']',
            r'["\']?auth[_-]?token["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-\.]{20,}["\']',
            r'bearer\s+[a-zA-Z0-9_\-\.]{20,}',
        ],
        'aws_keys': [
            r'AKIA[0-9A-Z]{16}',
            r'["\']?aws[_-]?access[_-]?key[_-]?id["\']?\s*[:=]\s*["\'][A-Z0-9]{20}["\']',
            r'["\']?aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\'][A-Za-z0-9/+=]{40}["\']',
        ],
        'google_api': [
            r'AIza[0-9A-Za-z_\-]{35}',
            r'["\']?google[_-]?api[_-]?key["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-]{35,}["\']',
        ],
        'github_tokens': [
            r'gh[pousr]_[0-9a-zA-Z]{36}',
            r'github_pat_[0-9a-zA-Z_]{82}',
            r'["\']?github[_-]?token["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-]{40}["\']',
        ],
        'slack_tokens': [
            r'xox[baprs]-[0-9a-zA-Z\-]{10,72}',
            r'["\']?slack[_-]?token["\']?\s*[:=]\s*["\']xox[baprs]-[0-9a-zA-Z\-]{10,}["\']',
        ],
        'private_keys': [
            r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
            r'-----BEGIN OPENSSH PRIVATE KEY-----',
            r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
        ],
        'jwt_tokens': [
            r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}',
        ],
        'database_urls': [
            r'mongodb(\+srv)?://[^\s\'"]{10,}',
            r'postgres(ql)?://[^\s\'"]{10,}',
            r'mysql://[^\s\'"]{10,}',
            r'redis://[^\s\'"]{10,}',
        ],
        'internal_urls': [
            r'https?://(?:localhost|127\.0\.0\.1|192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3})[^\s\'"]*',
            r'https?://[a-z0-9\-]+\.(?:local|internal|corp|dev|staging)[^\s\'"]*',
        ],
        'passwords': [
            r'["\']?password["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
            r'["\']?passwd["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
            r'["\']?pwd["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
        ],
        'client_secrets': [
            r'["\']?client[_-]?secret["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
            r'["\']?client[_-]?id["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
        ],
        'encryption_keys': [
            r'["\']?encryption[_-]?key["\']?\s*[:=]\s*["\'][a-zA-Z0-9+/=]{20,}["\']',
            r'["\']?secret[_-]?key["\']?\s*[:=]\s*["\'][a-zA-Z0-9+/=]{20,}["\']',
        ],
        'endpoints': [
            r'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}/[^\s\'"<>]*',
        ],
    }

class URLAnalyzer:
    """Main URL analysis class"""
    
    def __init__(self, args):
        self.args = args
        self.output_base = Path(args.output)
        self.log_file = self.output_base / "zort.log"
        self.results = {
            'alive_200': set(),
            'interesting_codes': [],
            'parameters': set(),
            'tokens_secrets': set(),
            'api_endpoints': set(),
            'vulnerabilities': defaultdict(set),
            'keywords': defaultdict(set),
            'js_files': set(),
            'js_secrets': defaultdict(list),
            'js_analyzed': set(),  # Track all analyzed JS files
            'js_download_failed': set(),  # Track failed downloads
        }
        self.stats = {
            'total_urls': 0,
            'checked': 0,
            'alive': 0,
            'interesting': 0,
            'js_files': 0,
            'js_secrets_found': 0,
        }
        
        # Compile regex patterns
        self.token_regex = re.compile('|'.join(Config.TOKEN_PATTERNS), re.IGNORECASE)
        
        # Setup
        self.setup_output_directories()
        self.load_keywords()
        
    def setup_output_directories(self):
        """Create output directory structure"""
        self.output_base.mkdir(exist_ok=True)
        (self.output_base / "potential_vulnerabilities").mkdir(exist_ok=True)
        (self.output_base / "keywords").mkdir(exist_ok=True)
        (self.output_base / "js_analysis").mkdir(exist_ok=True)
        
    def load_keywords(self):
        """Load keywords from config and optional wordlist"""
        self.keywords = Config.BUILTIN_KEYWORDS.copy()
        
        if self.args.wordlist and Path(self.args.wordlist).exists():
            with open(self.args.wordlist, 'r') as f:
                custom_keywords = [line.strip() for line in f if line.strip()]
                self.keywords.extend(custom_keywords)
                self.log(f"Loaded {len(custom_keywords)} custom keywords from {self.args.wordlist}")
        
        self.log(f"Total keywords: {len(self.keywords)}")
    
    def log(self, message, level="INFO"):
        """Log message to file and optionally console"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] [{level}] {message}\n"
        
        with open(self.log_file, 'a') as f:
            f.write(log_entry)
    
    def print_colored(self, message, color=Colors.NC, prefix=""):
        """Print colored message to console"""
        if prefix:
            print(f"{color}{prefix}{Colors.NC} {message}")
        else:
            print(f"{color}{message}{Colors.NC}")
    
    def normalize_url(self, url):
        """Normalize URL by removing fragments and trailing slashes"""
        url = url.strip()
        if '#' in url:
            url = url.split('#')[0]
        url = url.rstrip('/')
        return url
    
    def has_parameters(self, url):
        """Check if URL has query parameters"""
        return '?' in url
    
    def extract_parameters(self, url):
        """Extract parameter names from URL"""
        if not self.has_parameters(url):
            return []
        
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            return list(params.keys())
        except:
            return []
    
    def matches_token_pattern(self, url):
        """Check if URL matches token/secret patterns"""
        return bool(self.token_regex.search(url))
    
    def has_interesting_extension(self, url):
        """Check if URL has interesting file extension"""
        url_lower = url.lower()
        return any(ext in url_lower for ext in Config.INTERESTING_EXTENSIONS)
    
    def is_api_endpoint(self, url):
        """Check if URL matches API patterns"""
        return any(pattern in url for pattern in Config.API_PATTERNS)
    
    def is_js_file(self, url):
        """Check if URL is a JavaScript file"""
        url_lower = url.lower()
        return any(url_lower.endswith(ext) for ext in Config.JS_EXTENSIONS)
    
    def analyze_vulnerability_patterns(self, url):
        """Analyze URL for vulnerability patterns"""
        vulnerabilities = []
        
        for vuln_type, patterns in Config.VULN_PATTERNS.items():
            if any(pattern in url for pattern in patterns):
                vulnerabilities.append(vuln_type)
        
        return vulnerabilities
    
    def analyze_url_static(self, url):
        """Perform static analysis on URL without HTTP request"""
        # Check for JavaScript files
        if self.is_js_file(url):
            self.results['js_files'].add(url)
        
        # Check for parameters
        if self.has_parameters(url):
            self.results['parameters'].add(url)
            
            # Check vulnerability patterns
            vulns = self.analyze_vulnerability_patterns(url)
            for vuln in vulns:
                self.results['vulnerabilities'][vuln].add(url)
        
        # Check for tokens/secrets
        if self.matches_token_pattern(url):
            self.results['tokens_secrets'].add(url)
        
        # Check for API endpoints
        if self.is_api_endpoint(url):
            self.results['api_endpoints'].add(url)
        
        # Check for interesting files
        if self.has_interesting_extension(url):
            self.results['vulnerabilities']['interesting_files'].add(url)
        
        # Check keywords
        url_lower = url.lower()
        for keyword in self.keywords:
            if keyword.lower() in url_lower:
                self.results['keywords'][keyword].add(url)
    
    async def check_url(self, session, url):
        """Check URL HTTP status code"""
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=self.args.timeout),
                allow_redirects=False,
                ssl=False
            ) as response:
                return url, response.status
        except asyncio.TimeoutError:
            return url, 0
        except:
            return url, 0
    
    async def fetch_js_content(self, session, url):
        """Fetch JavaScript file content"""
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=self.args.timeout * 3),
                allow_redirects=True,
                ssl=False
            ) as response:
                if response.status == 200:
                    # Check content type
                    content_type = response.headers.get('content-type', '').lower()
                    
                    # Only process if it's actually JavaScript/JSON
                    if any(t in content_type for t in ['javascript', 'json', 'text/plain', 'application/octet-stream']):
                        try:
                            content = await response.text(errors='ignore')
                            return url, content
                        except:
                            return url, None
                    else:
                        self.log(f"Skipping {url} - wrong content type: {content_type}", level="WARN")
                        return url, None
                else:
                    self.log(f"Failed to fetch {url} - Status: {response.status}", level="WARN")
                    return url, None
        except asyncio.TimeoutError:
            self.log(f"Timeout fetching JS: {url}", level="WARN")
            return url, None
        except Exception as e:
            self.log(f"Error fetching JS {url}: {str(e)}", level="ERROR")
            return url, None
    
    def analyze_js_content(self, url, content):
        """Analyze JavaScript content for sensitive data"""
        if not content:
            return
        
        findings = []
        
        # Search for each pattern category
        for category, patterns in Config.JS_SENSITIVE_PATTERNS.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    # Get context (surrounding lines)
                    start = max(0, match.start() - 100)
                    end = min(len(content), match.end() + 100)
                    context = content[start:end].replace('\n', ' ').strip()
                    
                    finding = {
                        'category': category,
                        'match': match.group(0),
                        'context': context[:200],  # Limit context length
                        'pattern': pattern[:50],  # Show which pattern matched
                    }
                    findings.append(finding)
                    self.stats['js_secrets_found'] += 1
        
        if findings:
            self.results['js_secrets'][url] = findings
            self.log(f"Found {len(findings)} secrets in {url}", level="FOUND")
    
    async def http_check_urls(self, urls):
        """Perform HTTP checks on URLs with concurrency control"""
        self.print_colored("Phase 2: HTTP Status Code Analysis", Colors.MAGENTA, "[!]")
        self.print_colored(f"Checking URLs with HTTP requests (concurrency: {self.args.threads}, timeout: {self.args.timeout}s)", Colors.BLUE, "[INFO]")
        print()
        
        connector = aiohttp.TCPConnector(limit=self.args.threads, ssl=False)
        timeout = aiohttp.ClientTimeout(total=self.args.timeout)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            tasks = [self.check_url(session, url) for url in urls]
            
            # Process results as they complete
            for i, task in enumerate(asyncio.as_completed(tasks), 1):
                url, status = await task
                
                self.stats['checked'] = i
                
                # Log result
                self.log(f"{status}: {url}", level="CHECK")
                
                # Categorize by status
                if status == 200:
                    self.results['alive_200'].add(url)
                    self.stats['alive'] += 1
                elif status in Config.INTERESTING_STATUS_CODES:
                    self.results['interesting_codes'].append(f"[{status}] {url}")
                    self.stats['interesting'] += 1
                
                # Progress update
                if i % 100 == 0 or i == len(urls):
                    progress = int((i / len(urls)) * 100)
                    print(f"\r{Colors.BLUE}[{progress:3d}%]{Colors.NC} Checked: {i}/{len(urls)} | "
                          f"{Colors.GREEN}200: {self.stats['alive']}{Colors.NC} | "
                          f"{Colors.YELLOW}Interesting: {self.stats['interesting']}{Colors.NC}", end='', flush=True)
        
        print("\n")
    
    async def analyze_js_files(self):
        """Download and analyze JavaScript files"""
        if not self.results['js_files']:
            self.print_colored("No JavaScript files found to analyze", Colors.YELLOW, "[WARN]")
            return
        
        self.print_colored("Phase 3: JavaScript File Analysis", Colors.MAGENTA, "[!]")
        
        js_count = len(self.results['js_files'])
        self.print_colored(f"Found {js_count} JavaScript files", Colors.BLUE, "[INFO]")
        
        if not self.args.analyze_js:
            self.print_colored("JavaScript content analysis disabled. Use --analyze-js to enable.", Colors.YELLOW, "[WARN]")
            self.print_colored(f"JS files list saved to: {self.output_base}/js_files.txt", Colors.BLUE, "[INFO]")
            print()
            return
        
        # Ask for confirmation if many files
        if js_count > 50:
            print()
            self.print_colored(f"⚠️  Warning: {js_count} JavaScript files found!", Colors.YELLOW, "[!]")
            print(f"   This will download and analyze {js_count} files.")
            print(f"   Estimated time: ~{js_count * 2} seconds")
            print()
            
            try:
                response = input(f"{Colors.CYAN}Continue with JS analysis? [y/N]: {Colors.NC}").strip().lower()
                if response not in ['y', 'yes']:
                    self.print_colored("Skipping JS analysis. Files list saved to js_files.txt", Colors.YELLOW, "[INFO]")
                    print()
                    return
            except KeyboardInterrupt:
                print()
                self.print_colored("Skipping JS analysis", Colors.YELLOW, "[INFO]")
                print()
                return
        
        print()
        self.print_colored(f"Downloading and analyzing {js_count} JavaScript files...", Colors.BLUE, "[INFO]")
        self.print_colored("This may take a while depending on file sizes...", Colors.BLUE, "[INFO]")
        print()
        
        connector = aiohttp.TCPConnector(limit=min(self.args.threads // 2, 10), ssl=False)
        timeout = aiohttp.ClientTimeout(total=self.args.timeout * 3)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            tasks = [self.fetch_js_content(session, url) for url in self.results['js_files']]
            
            # Process results as they complete
            downloaded = 0
            failed = 0
            
            for i, task in enumerate(asyncio.as_completed(tasks), 1):
                url, content = await task
                
                self.results['js_analyzed'].add(url)
                
                if content:
                    downloaded += 1
                    self.analyze_js_content(url, content)
                else:
                    failed += 1
                    self.results['js_download_failed'].add(url)
                
                # Progress update
                if i % 5 == 0 or i == len(self.results['js_files']):
                    progress = int((i / len(self.results['js_files'])) * 100)
                    print(f"\r{Colors.BLUE}[{progress:3d}%]{Colors.NC} Analyzed: {i}/{len(self.results['js_files'])} | "
                          f"{Colors.GREEN}Downloaded: {downloaded}{Colors.NC} | "
                          f"{Colors.RED}Failed: {failed}{Colors.NC} | "
                          f"{Colors.YELLOW}Secrets: {self.stats['js_secrets_found']}{Colors.NC}", end='', flush=True)
        
        print("\n")
        
        # Summary
        files_with_secrets = len(self.results['js_secrets'])
        clean_files = downloaded - files_with_secrets
        
        if self.stats['js_secrets_found'] > 0:
            self.print_colored(f"🔥 Found {self.stats['js_secrets_found']} potential secrets in {files_with_secrets} JS files!", 
                             Colors.GREEN, "[✓]")
            self.print_colored(f"   Clean files (no secrets): {clean_files}", Colors.BLUE, "[INFO]")
        else:
            self.print_colored(f"No secrets found in {downloaded} JavaScript files", Colors.BLUE, "[INFO]")
        
        if failed > 0:
            self.print_colored(f"Failed to download {failed} JS files (timeout/error)", Colors.YELLOW, "[WARN]")
        
        # Ask about cleanup
        if clean_files > 0 and files_with_secrets > 0:
            print()
            try:
                response = input(f"{Colors.CYAN}Remove clean JS files from downloaded list? [y/N]: {Colors.NC}").strip().lower()
                if response in ['y', 'yes']:
                    # This is just informational - we keep all in output but mark them
                    self.print_colored("Clean files will be marked in output (check clean_files.txt)", Colors.GREEN, "[✓]")
            except KeyboardInterrupt:
                print()
        
        print()
    
    def save_results(self):
        """Save all results to files"""
        self.print_colored("Saving results...", Colors.BLUE, "[INFO]")
        
        # Save alive URLs
        if self.results['alive_200']:
            alive_file = self.output_base / "alive_200.txt"
            with open(alive_file, 'w') as f:
                for url in sorted(self.results['alive_200']):
                    f.write(f"{url}\n")
        
        # Save interesting status codes
        if self.results['interesting_codes']:
            interesting_file = self.output_base / "interesting_codes.txt"
            with open(interesting_file, 'w') as f:
                for entry in sorted(self.results['interesting_codes']):
                    f.write(f"{entry}\n")
        
        # Save parameters
        if self.results['parameters']:
            params_file = self.output_base / "parameters.txt"
            with open(params_file, 'w') as f:
                for url in sorted(self.results['parameters']):
                    f.write(f"{url}\n")
        
        # Save tokens/secrets
        if self.results['tokens_secrets']:
            tokens_file = self.output_base / "tokens_secrets.txt"
            with open(tokens_file, 'w') as f:
                for url in sorted(self.results['tokens_secrets']):
                    f.write(f"{url}\n")
        
        # Save API endpoints
        if self.results['api_endpoints']:
            api_file = self.output_base / "api_endpoints.txt"
            with open(api_file, 'w') as f:
                for url in sorted(self.results['api_endpoints']):
                    f.write(f"{url}\n")
        
        # ALWAYS save JS files list (even if no secrets found)
        if self.results['js_files']:
            js_file = self.output_base / "js_files.txt"
            with open(js_file, 'w') as f:
                f.write(f"# JavaScript Files Found: {len(self.results['js_files'])}\n")
                f.write(f"# Use --analyze-js flag to scan these files for secrets\n\n")
                for url in sorted(self.results['js_files']):
                    f.write(f"{url}\n")
        
        # Save JS analysis results (only if analysis was performed)
        if self.results['js_secrets']:
            js_dir = self.output_base / "js_analysis"
            
            # Save all analyzed JS files (with and without secrets)
            js_analyzed_file = js_dir / "all_analyzed_files.txt"
            with open(js_analyzed_file, 'w') as f:
                f.write(f"# All JavaScript Files Analyzed: {len(self.results.get('js_analyzed', set()))}\n\n")
                for url in sorted(self.results.get('js_analyzed', set())):
                    has_secrets = url in self.results['js_secrets']
                    marker = "[SECRETS FOUND]" if has_secrets else "[CLEAN]"
                    f.write(f"{marker} {url}\n")
            
            # Save files with secrets
            js_with_secrets = js_dir / "files_with_secrets.txt"
            with open(js_with_secrets, 'w') as f:
                f.write(f"# JavaScript Files Containing Secrets: {len(self.results['js_secrets'])}\n\n")
                for url in sorted(self.results['js_secrets'].keys()):
                    secret_count = len(self.results['js_secrets'][url])
                    f.write(f"{url} ({secret_count} secrets)\n")
            
            # Save clean files (no secrets)
            clean_files = self.results.get('js_analyzed', set()) - set(self.results['js_secrets'].keys())
            if clean_files:
                js_clean_file = js_dir / "clean_files.txt"
                with open(js_clean_file, 'w') as f:
                    f.write(f"# JavaScript Files Without Secrets: {len(clean_files)}\n\n")
                    for url in sorted(clean_files):
                        f.write(f"{url}\n")
            
            # Save detailed findings
            js_secrets_file = js_dir / "js_secrets_detailed.txt"
            with open(js_secrets_file, 'w') as f:
                f.write("=" * 80 + "\n")
                f.write("JavaScript Secrets Analysis - Detailed Report\n")
                f.write("=" * 80 + "\n\n")
                
                for url, findings in sorted(self.results['js_secrets'].items()):
                    f.write(f"\n{'=' * 80}\n")
                    f.write(f"File: {url}\n")
                    f.write(f"Findings: {len(findings)}\n")
                    f.write(f"{'=' * 80}\n\n")
                    
                    for idx, finding in enumerate(findings, 1):
                        f.write(f"[{idx}] Category: {finding['category'].upper()}\n")
                        f.write(f"    Match: {finding['match']}\n")
                        f.write(f"    Context: ...{finding['context']}...\n")
                        f.write(f"    Pattern: {finding['pattern']}\n\n")
            
            # Save categorized findings
            categorized = defaultdict(list)
            for url, findings in self.results['js_secrets'].items():
                for finding in findings:
                    categorized[finding['category']].append({
                        'url': url,
                        'match': finding['match']
                    })
            
            for category, items in categorized.items():
                category_file = js_dir / f"{category}.txt"
                with open(category_file, 'w') as f:
                    f.write(f"# {category.upper()} - Found in JavaScript Files\n")
                    f.write(f"# Total: {len(items)} findings\n\n")
                    for item in items:
                        f.write(f"{item['url']}\n")
                        f.write(f"  └─> {item['match']}\n\n")
            
            # Save summary
            js_summary = js_dir / "summary.json"
            summary_data = {
                'total_js_files_found': len(self.results['js_files']),
                'total_js_files_analyzed': len(self.results.get('js_analyzed', set())),
                'files_with_secrets': len(self.results['js_secrets']),
                'clean_files': len(clean_files),
                'total_secrets': self.stats['js_secrets_found'],
                'by_category': {cat: len(items) for cat, items in categorized.items()},
                'files_with_secrets_list': list(self.results['js_secrets'].keys())
            }
            with open(js_summary, 'w') as f:
                json.dump(summary_data, f, indent=2)
        
        # Save vulnerabilities
        vuln_dir = self.output_base / "potential_vulnerabilities"
        for vuln_type, urls in self.results['vulnerabilities'].items():
            if urls:
                vuln_file = vuln_dir / f"{vuln_type}.txt"
                with open(vuln_file, 'w') as f:
                    for url in sorted(urls):
                        f.write(f"{url}\n")
        
        # Save keywords
        keyword_dir = self.output_base / "keywords"
        for keyword, urls in self.results['keywords'].items():
            if urls:
                keyword_file = keyword_dir / f"{keyword}.txt"
                with open(keyword_file, 'w') as f:
                    for url in sorted(urls):
                        f.write(f"{url}\n")
    
    def generate_summary(self):
        """Generate and display summary report"""
        summary_file = self.output_base / "summary_report.txt"
        
        vuln_count = sum(len(urls) for urls in self.results['vulnerabilities'].values())
        keyword_matches = len([k for k, v in self.results['keywords'].items() if v])
        
        summary = f"""
═══════════════════════════════════════════════════════════════
           ZORT - URL Analysis Summary Report
═══════════════════════════════════════════════════════════════
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

OVERVIEW
───────────────────────────────────────────────────────────────
Total URLs analyzed: {self.stats['total_urls']}

"""
        
        if not self.args.skip_check:
            summary += f"""HTTP STATUS RESULTS
───────────────────────────────────────────────────────────────
✓ Alive (200): {len(self.results['alive_200'])}
⚠ Interesting codes (401/403/405/500...): {len(self.results['interesting_codes'])}

"""
        
        summary += f"""PATTERN ANALYSIS
───────────────────────────────────────────────────────────────
🔑 URLs with tokens/secrets: {len(self.results['tokens_secrets'])}
📊 API endpoints: {len(self.results['api_endpoints'])}
🔍 URLs with parameters: {len(self.results['parameters'])}

POTENTIAL VULNERABILITY VECTORS
───────────────────────────────────────────────────────────────
"""
        
        for vuln_type, urls in sorted(self.results['vulnerabilities'].items()):
            summary += f"{vuln_type:<20} : {len(urls)} URLs\n"
        
        summary += f"""
KEYWORD CATEGORIES
───────────────────────────────────────────────────────────────
Total keyword categories matched: {keyword_matches}

TOP FINDINGS
───────────────────────────────────────────────────────────────
"""
        
        # Sample tokens/secrets
        if self.results['tokens_secrets']:
            summary += "Sample URLs with tokens/secrets:\n"
            for url in list(self.results['tokens_secrets'])[:5]:
                summary += f"  • {url}\n"
            summary += "\n"
        
        # Sample API endpoints
        if self.results['api_endpoints']:
            summary += "Sample API endpoints:\n"
            for url in list(self.results['api_endpoints'])[:5]:
                summary += f"  • {url}\n"
            summary += "\n"
        
        # Sample interesting codes
        if self.results['interesting_codes']:
            summary += "Sample interesting status codes:\n"
            for entry in self.results['interesting_codes'][:5]:
                summary += f"  • {entry}\n"
            summary += "\n"
        
        # Sample JS secrets
        if self.results['js_secrets']:
            summary += "Sample JavaScript secrets found:\n"
            count = 0
            for url, findings in list(self.results['js_secrets'].items())[:3]:
                summary += f"  • {url}\n"
                for finding in findings[:2]:  # Show first 2 findings per file
                    summary += f"    └─> [{finding['category']}] {finding['match'][:60]}...\n"
                count += 1
                if count >= 3:
                    break
            summary += "\n"
        
        summary += f"""OUTPUT FILES
───────────────────────────────────────────────────────────────
📁 Main results directory: {self.output_base}/
"""
        
        if self.results['alive_200']:
            summary += "  ✓ alive_200.txt\n"
        if self.results['interesting_codes']:
            summary += "  ⚠ interesting_codes.txt\n"
        if self.results['parameters']:
            summary += "  🔍 parameters.txt\n"
        if self.results['tokens_secrets']:
            summary += "  🔑 tokens_secrets.txt\n"
        if self.results['api_endpoints']:
            summary += "  📊 api_endpoints.txt\n"
        
        summary += """  📂 potential_vulnerabilities/
  📂 keywords/

═══════════════════════════════════════════════════════════════
💡 TIP: Start with tokens_secrets.txt and interesting_codes.txt
    for quick wins in bug bounty hunting!
═══════════════════════════════════════════════════════════════
"""
        
        # Save to file
        with open(summary_file, 'w') as f:
            f.write(summary)
        
        # Print to console
        print(summary)
        self.print_colored(f"Summary report saved: {summary_file}", Colors.GREEN, "[✓]")
    
    async def run(self):
        """Main execution flow"""
        start_time = datetime.now()
        
        # Header
        print()
        print("╔═══════════════════════════════════════════════════════════════╗")
        print("║              ZORT - URL Analysis Tool                         ║")
        print("║          Bug Bounty & Pentesting Edition                      ║")
        print("╚═══════════════════════════════════════════════════════════════╝")
        print()
        
        # Load and deduplicate URLs
        self.print_colored("Loading and deduplicating URLs...", Colors.BLUE, "[INFO]")
        
        try:
            with open(self.args.url_file, 'r') as f:
                urls = [self.normalize_url(line.strip()) for line in f if line.strip()]
        except Exception as e:
            self.print_colored(f"Error reading file: {e}", Colors.RED, "[ERROR]")
            sys.exit(1)
        
        # Deduplicate
        original_count = len(urls)
        urls = list(set(urls))
        self.stats['total_urls'] = len(urls)
        
        self.print_colored(f"Original URLs: {original_count}, Unique URLs: {len(urls)}", Colors.BLUE, "[INFO]")
        self.log(f"Deduplication: {original_count} -> {len(urls)} URLs")
        
        if not urls:
            self.print_colored("No URLs to process", Colors.RED, "[ERROR]")
            sys.exit(1)
        
        print()
        
        # Phase 1: Static Analysis
        self.print_colored("Phase 1: Static Pattern Analysis", Colors.MAGENTA, "[!]")
        self.print_colored("Performing static URL analysis...", Colors.BLUE, "[INFO]")
        
        for url in urls:
            self.analyze_url_static(url)
        
        self.print_colored("Static analysis complete:", Colors.GREEN, "[✓]")
        print(f"  • URLs with parameters: {len(self.results['parameters'])}")
        print(f"  • URLs with tokens/secrets: {len(self.results['tokens_secrets'])}")
        print(f"  • API endpoints: {len(self.results['api_endpoints'])}")
        print(f"  • JavaScript files: {len(self.results['js_files'])}")
        
        if self.results['js_files'] and not self.args.analyze_js:
            print()
            self.print_colored(f"💡 Tip: Use --analyze-js to scan {len(self.results['js_files'])} JS files for secrets!", 
                             Colors.CYAN, "[TIP]")
        
        print()
        
        # Phase 2: HTTP Checks
        if not self.args.skip_check:
            await self.http_check_urls(urls)
        else:
            self.print_colored("Skipping HTTP checks (--skip-check enabled)", Colors.BLUE, "[INFO]")
            print()
        
        # Phase 3: JavaScript Analysis
        if self.results['js_files'] and not self.args.skip_check:
            await self.analyze_js_files()
        
        # Phase 4: Save Results
        self.print_colored("Phase 4: Saving Results", Colors.MAGENTA, "[!]")
        self.save_results()
        print()
        
        # Generate Summary
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        self.generate_summary()
        
        print()
        self.print_colored(f"Analysis completed in {duration:.1f}s", Colors.GREEN, "[✓]")
        self.log(f"Analysis completed in {duration:.1f}s")
        
        print()
        self.print_colored("Quick Start Guide:", Colors.MAGENTA, "[!]")
        print("  1. Check tokens_secrets.txt for exposed credentials")
        print("  2. Review interesting_codes.txt for 401/403 (potential bypasses)")
        print("  3. 🔥 Check js_analysis/ for hardcoded secrets in JavaScript files")
        print("  4. Test parameters.txt for injection vulnerabilities")
        print("  5. Explore api_endpoints.txt for API testing")
        print("  6. Review potential_vulnerabilities/ by attack type")
        print()

def main():
    parser = argparse.ArgumentParser(
        description='ZORT - Advanced URL Analysis Tool for Bug Bounty & Pentesting',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s urls.txt
  %(prog)s urls.txt -w keywords.txt -t 100 -T 5
  %(prog)s urls.txt --skip-check
  %(prog)s urls.txt -o custom_output -t 50
        """
    )
    
    parser.add_argument('url_file', help='Text file containing URLs (one per line)')
    parser.add_argument('-w', '--wordlist', help='Optional external wordlist file')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of concurrent requests (default: 50)')
    parser.add_argument('-T', '--timeout', type=int, default=10, help='Timeout per URL in seconds (default: 10)')
    parser.add_argument('-s', '--skip-check', action='store_true', help='Skip HTTP checks (static analysis only)')
    parser.add_argument('-j', '--analyze-js', action='store_true', help='Download and analyze JavaScript files for secrets (slower)')
    parser.add_argument('-o', '--output', default='results', help='Output directory (default: results)')
    parser.add_argument('-v', '--version', action='version', version='ZORT 2.0')
    
    args = parser.parse_args()
    
    # Validate input file
    if not Path(args.url_file).exists():
        print(f"{Colors.RED}[ERROR]{Colors.NC} File not found: {args.url_file}")
        sys.exit(1)
    
    # Run analyzer
    analyzer = URLAnalyzer(args)
    
    try:
        asyncio.run(analyzer.run())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[WARN]{Colors.NC} Interrupted by user")
        analyzer.log("Interrupted by user", level="WARN")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.NC} {str(e)}")
        analyzer.log(f"Fatal error: {str(e)}", level="ERROR")
        sys.exit(1)

if __name__ == '__main__':
    main()

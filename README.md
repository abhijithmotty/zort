# ZORT
<p align="center"> &nbsp; <img src="https://img.shields.io/badge/version-2.0-blue.svg" alt="Version">&nbsp; <img src="https://img.shields.io/badge/python-3.7+-brightgreen.svg" alt="Python">&nbsp; <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">&nbsp; <img src="https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg" alt="Platform">
</p>
  
**URL Analysis Tool for Bug Bounty & Pentesting**




## Quick Start

```bash
# Install
git clone https://github.com/abhijithmotty/zort.git
cd zort
pip install -r requirements.txt

# Run
python zort.py urls.txt
```



## Usage

### Basic Commands

```bash
# Standard scan
python zort.py urls.txt

# With JavaScript analysis (downloads & scans JS files)
python zort.py urls.txt --analyze-js

# Fast scan (skip HTTP checks)
python zort.py urls.txt --skip-check

# Custom threads and timeout
python zort.py urls.txt -t 100 -T 5

# With custom wordlist
python zort.py urls.txt -w keywords.txt
```

### Typical Workflow

```bash
# 1. Collect URLs
echo "target.com" | waybackurls > urls.txt

# 2. Analyze
python zort.py urls.txt --analyze-js

# 3. Check results (priority order)
cat results/tokens_secrets.txt          # Exposed credentials
cat results/js_analysis/api_keys.txt    # Secrets in JS files
cat results/interesting_codes.txt       # 401/403 bypasses
cat results/potential_vulnerabilities/sqli.txt
```



## 📂 Output

```
results/
├── alive_200.txt              # Working URLs
├── interesting_codes.txt      # 401, 403, 405, 500+ status codes
├── tokens_secrets.txt         # URLs with sensitive tokens
├── js_files.txt              # All JavaScript files found
├── parameters.txt            # URLs with parameters (injection points)
├── api_endpoints.txt         # API endpoints
├── js_analysis/              # JavaScript secrets (with --analyze-js)
|    ├── js_secrets_detailed.txt      # Full report with code context
|    ├── secrets_by_line.txt          # Quick grep-friendly format
|    ├── secrets_per_file.txt         # Organized by file
|    ├── all_analyzed_files.txt       # All files (with/without secrets)
|    ├── files_with_secrets.txt       # Only files with secrets
|    ├── clean_files.txt              # Files without secrets
|    └── summary.json                 # JSON summary
├── potential_vulnerabilities/
│   ├── sqli.txt
│   ├── xss.txt
│   ├── lfi.txt
│   └── ssrf.txt
└── keywords/                 # Categorized by keyword
```




## Options

```
python zort.py <url_file> [options]

Required:
  url_file              File with URLs (one per line)

Options:
  -w, --wordlist        Custom keywords file
  -t, --threads         Concurrent requests (default: 50)
  -T, --timeout         Timeout per request (default: 10s)
  -s, --skip-check      Skip HTTP checks (static analysis only)
  -j, --analyze-js      Download & analyze JS files for secrets
  -o, --output          Output directory (default: results)
  -h, --help            Show help
```




## Integration

```bash
# With Nuclei
python zort.py urls.txt
nuclei -l results/alive_200.txt

# With SQLMap
cat results/potential_vulnerabilities/sqli.txt | while read url; do
    sqlmap -u "$url" --batch
done

# With httpx
cat results/tokens_secrets.txt | httpx -mc 200
```



## Requirements

- Python 3.7+
- aiohttp (`pip install aiohttp`)



## 📝 License

MIT License - See [LICENSE](LICENSE)



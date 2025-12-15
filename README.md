# 🎯 ZORT - Advanced URL Analysis Tool



<p align="center">

&nbsp; <img src="https://img.shields.io/badge/version-2.0-blue.svg" alt="Version">&nbsp; <img src="https://img.shields.io/badge/python-3.7+-brightgreen.svg" alt="Python">&nbsp; <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">&nbsp; <img src="https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg" alt="Platform">



</p>



**ZORT** is a powerful URL analysis and vulnerability detection tool designed for bug bounty hunters and penetration testers. It intelligently analyzes URLs from tools like `waybackurls`, identifying critical security patterns, sensitive endpoints, and potential vulnerabilities.



## 📦 Installation



### Python Version (Recommended) 🐍



```bash

# Clone the repository

git clone https://github.com/abhijithmotty/zort.git

cd zort
```

## 🧩 Recommended Setup (Kali / Linux)

If you're using **Kali Linux** or any Linux distribution, it's strongly recommended to use a **Python virtual environment (venv)** to prevent conflicts with system packages.

### 🔹 Steps

```bash
# Install venv module (if not already installed)
sudo apt install python3-venv -y

# Create a new virtual environment
python3 -m venv venv

# Activate the environment
source venv/bin/activate


# Install Python dependencies

pip install -r requirements.txt



# Make executable

chmod +x zort.py

# copy to /usr/local/bin (requires sudo)

sudo cp zort.py /usr/local/bin/zort

# Run

zort urls.txt

```



### Requirements



**Python version:**

- Python 3.7 or higher

- `aiohttp` library





## 🚀 Quick Start



### Python



```bash

# Basic usage

zort urls.txt



# With custom threads and timeout

zort urls.txt -t 100 -T 5



# Fast mode (no HTTP checks)

zort urls.txt --skip-check



# With external wordlist

zort urls.txt -w custom\_keywords.txt



# Custom output directory

zort urls.txt -o my\_results

```





### Typical Bug Bounty Workflow



```bash

# 1. Collect URLs using waybackurls

echo "target.com" | waybackurls > urls.txt



# 2. Run ZORT analysis

zort urls.txt -t 100



# 3. Start testing!

# - Check results/tokens\_secrets.txt for quick wins

# - Review results/interesting\_codes.txt for bypasses

# - Test results/potential\_vulnerabilities/ for vulns

```



## 📖 Usage






```

# Basic scan (just identifies JS files, no analysis)
python zort.py urls.txt

# With JS analysis (downloads and scans content)
python zort.py urls.txt --analyze-js

# Full power scan
python zort.py urls.txt -t 100 --analyze-js

# JS analysis only (skip other HTTP checks)
python zort.py urls.txt --analyze-js --skip-check
```

## 💡 Example Output:
```
[!] Phase 3: JavaScript File Analysis
[INFO] Analyzing 45 JavaScript files for secrets...

[100%] Analyzed: 45/45 | Secrets Found: 127

[✓] Found 127 potential secrets in 12 JS files!

Results:
  • api_keys          : 23
  • endpoints         : 45
  • jwt_tokens        : 8
  • aws_keys          : 2
  • github_tokens     : 1
  • database_urls     : 3
  • internal_urls     : 45
```




## 📂 Output Structure



```

results/

├── alive\_200.txt                    # URLs returning HTTP 200

├── interesting\_codes.txt            # URLs with 401, 403, 405, 500, etc.

├── parameters.txt                   # URLs with query parameters

├── tokens\_secrets.txt               # URLs containing tokens/keys/secrets

├── api\_endpoints.txt                # API endpoints and versions

├── potential\_vulnerabilities/       # Categorized by vulnerability type

│   ├── sqli.txt                    # SQL injection candidates

│   ├── xss.txt                     # XSS candidates

│   ├── lfi.txt                     # Local file inclusion

│   ├── rfi.txt                     # Remote file inclusion

│   ├── ssrf.txt                    # SSRF candidates

│   ├── idor.txt                    # IDOR candidates

│   ├── openredirect.txt            # Open redirect candidates

│   └── interesting\_files.txt       # Backups, configs, etc.

├── keywords/                        # Per-keyword URL matches

│   ├── admin.txt

│   ├── api.txt

│   ├── backup.txt

│   └── ...

├── summary\_report.txt               # Comprehensive analysis report

├── zort.log                         # Detailed execution log

├── js_files.txt                       # All JS files found

└── js_analysis/                       # JS analysis results
    ├── js_secrets_detailed.txt        # Full detailed report
    ├── summary.json                   # JSON summary
    ├── api_keys.txt                   # API keys found
    ├── aws_keys.txt                   # AWS credentials
    ├── github_tokens.txt              # GitHub tokens
    ├── jwt_tokens.txt                 # JWT tokens
    ├── private_keys.txt               # Private keys
    ├── database_urls.txt              # DB connection strings
    ├── passwords.txt                  # Passwords
    └── endpoints.txt                  # Hardcoded endpoints

```







### Pro Tips



- **Start Fast**: Use `--skip-check` for initial pattern analysis on large datasets

- **Focus on High-Value Targets**: Prioritize tokens\_secrets.txt and interesting\_codes.txt

- **Combine Results**: Cross-reference multiple output files for better context

- **Custom Wordlists**: Create domain-specific wordlists for better coverage

- **Automate Follow-up**: Pipe results to other tools like nuclei, sqlmap, etc.



## 🔧 Advanced Usage



### Custom Wordlist Example

```bash

# Create custom wordlist

cat > custom\_keywords.txt << EOF

internal

employee

staging

v3

v4

graphql

EOF



# Run with custom wordlist (Python)

zort urls.txt -w custom\_keywords.txt



# Run with custom wordlist (Bash)

./zort.sh urls.txt -w custom\_keywords.txt

```



### Integration with Other Tools



```bash

# Waybackurls → ZORT → Nuclei

echo "target.com" | waybackurls | tee urls.txt

zort urls.txt -t 100

nuclei -l results/alive\_200.txt -t ~/nuclei-templates/



# ZORT → SQLMap

zort urls.txt

cat results/potential\_vulnerabilities/sqli.txt | while read url; do

sqlmap -u "$url" --batch --level 2

done



# ZORT → FFUF for parameter fuzzing

cat results/parameters.txt | ffuf -w wordlist.txt -u FUZZ



# ZORT → httpx for detailed analysis

zort urls.txt --skip-check  # Fast pattern analysis

cat results/tokens\_secrets.txt | httpx -mc 200 -follow-redirects

```



### Performance Tuning



**Python:**

```bash

# Maximum speed (use with caution)

zort urls.txt -t 200 -T 3



# Conservative (avoid rate limiting)

zort urls.txt -t 25 -T 15



# Static analysis only (fastest)

zort urls.txt --skip-check

```





## 🎨 Sample Output



```

╔═══════════════════════════════════════════════════════════════╗

║          ZORT - Advanced URL Analysis Tool                    ║

║          Bug Bounty \& Pentesting Edition                      ║

╚═══════════════════════════════════════════════════════════════╝



[INFO] Loading and deduplicating URLs...

[INFO] Original URLs: 47140, Unique URLs: 47079



[!] Phase 1: Static Pattern Analysis

[INFO] Performing static URL analysis...

[✓] Static analysis complete:

 • URLs with parameters: 12,453

 • URLs with tokens/secrets: 234

 • API endpoints: 567



[!] Phase 2: HTTP Status Code Analysis

[INFO] Checking URLs with HTTP requests (concurrency: 50, timeout: 10s)

[100%] Checked: 47079/47079 | 200: 8,432 | Interesting: 1,245



[✓] Analysis completed in 125.4s



[!] Quick Start Guide:

 1. Check tokens\_secrets.txt for exposed credentials

 2. Review interesting\_codes.txt for 401/403 (potential bypasses)

 3. Test parameters.txt for injection vulnerabilities

 4. Explore api\_endpoints.txt for API testing

 5. Review potential\_vulnerabilities/ by attack type

```



## 🔍 Detection Patterns



### Built-in Token Patterns

- API keys: `api\_key`, `apikey`, `api-key`

- Access tokens: `access\_token`, `accessToken`

- Session identifiers: `session\_id`, `sessionid`, `PHPSESSID`

- JWT tokens: `jwt`, `jwt\_token`, `bearer`

- OAuth tokens: `oauth\_token`, `oauth\_secret`

- Cloud credentials: `aws\_key`, `s3\_key`, `azure\_key`

- GitHub/GitLab tokens

- Slack tokens



### Vulnerability Parameters

- **SQLi**: `id`, `user`, `username`, `email`, `search`, `q`, `query`

- **XSS**: `search`, `q`, `query`, `name`, `comment`, `message`

- **LFI**: `file`, `path`, `page`, `include`, `dir`, `template`

- **RFI**: `url`, `uri`, `link`, `src`, `source`, `redirect`

- **SSRF**: `url`, `uri`, `host`, `proxy`, `api`, `callback`, `webhook`

- **IDOR**: `id`, `uid`, `user\_id`, `account`, `order`, `invoice`



### Interesting File Extensions

- Backups: `.bak`, `.backup`, `.old`, `.orig`, `.save`

- Configs: `.conf`, `.config`, `.ini`, `.env`, `.yaml`

- Databases: `.sql`, `.db`, `.sqlite`, `.dump`

- Archives: `.zip`, `.tar`, `.gz`, `.rar`, `.7z`

- Certificates: `.key`, `.pem`, `.crt`, `.cer`, `.p12`

- Source control: `.git`, `.svn`, `.DS\_Store`

- Temporary: `.swp`, `.tmp`, `.temp`, `~`



## 🤝 Contributing



Contributions are welcome! Please feel free to submit a Pull Request.



### Development Setup



**Python:**

```bash

git clone https://github.com/abhijithmotty/zort.git

cd zort

pip install -r requirements.txt

python -m pytest tests/  # Run tests (if available)

```






### Adding New Patterns



**Python (`zort.py`):**

Edit the `Config` class to add patterns:

```python

class Config:

   BUILTIN\_KEYWORDS = \[...]  # Add keywords

   TOKEN\_PATTERNS = \[...]     # Add regex patterns

   VULN\_PATTERNS = {...}      # Add vulnerability patterns

```



## 📝 Version History



## 📝 License



This project is licensed under the MIT License - see the \[LICENSE](LICENSE) file for details.



## ⚠️ Disclaimer



This tool is for educational and ethical testing purposes only. Always obtain proper authorization before testing any systems you do not own. The authors are not responsible for any misuse or damage caused by this tool.





## 📧 Contact



- GitHub Issues: \[Report bugs or request features](https://github.com/abhijithmotty/zort/issues)

- Twitter: \[@primeaetheron](https://x.com/primeaetheron)



## 🌟 Star History



If you find ZORT useful, please consider giving it a star! ⭐



---



**Happy Hunting! 🎯**



Made with ❤️ for the Bug Bounty Community


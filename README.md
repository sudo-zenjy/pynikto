# PyNikto - Python Web Server Scanner

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-GPL-blue.svg)](LICENSE)

PyNikto is a Python-based web server scanner inspired by Nikto, designed for security testing and vulnerability assessment of web servers.

## Features

- 🔍 **Comprehensive Web Scanning**: Tests for thousands of potentially dangerous files, outdated servers, and misconfigurations
- 🕷️ **Website Crawling**: Automatic discovery of new paths through link following
- 🤖 **Robots.txt Support**: Respects robots.txt when crawling
- 📊 **Multiple Output Formats**: JSON, XML, CSV, SARIF, JUnit XML, HTML
- 🔗 **Tool Integration**: Easy integration with Nmap, CI/CD pipelines, and other security tools
- 🐍 **Python API**: Programmatic interface for automation and integration
- ⚡ **Concurrent Scanning**: Multi-threaded for fast scanning
- 🎯 **Tuning Options**: Filter tests by category (XSS, SQL injection, etc.)


### Windows

```powershell
# Install Python 3.7+ from python.org
# Then install dependencies
pip install -r requirements.txt
```

## Quick Start

### Basic Usage

```bash
# Scan a web server
python nikto.py -host example.com

# Scan HTTPS
python nikto.py -host example.com -port 443 -ssl

# Custom port
python nikto.py -host example.com -port 8080
```

### Output Formats

```bash
# JSON output
python nikto.py -host example.com -Format json -output results.json

# SARIF for GitHub Security
python nikto.py -host example.com -Format sarif -output results.sarif

# HTML report
python nikto.py -host example.com -Format html -output report.html
```

### Enable Crawling

```bash
# Crawl website and scan discovered paths
python nikto.py -host example.com -crawl -crawl-depth 3
```

## Nmap Integration

PyNikto can automatically discover and scan web services using Nmap:

```bash
# Discover web services with Nmap and scan with PyNikto
python nmap_integration.py example.com

# Custom Nmap scan
python nmap_integration.py example.com --nmap-args "-p 80,443,8080,8443"

# Using shell script (Linux/Mac)
./scripts/utils/nmap_pynikto.sh example.com

# Using batch script (Windows)
scripts\utils\nmap_pynikto.bat example.com
```

See [docs/NMAP_INTEGRATION_README.md](docs/NMAP_INTEGRATION_README.md) for detailed documentation.

## Python API

```python
from api import PyNiktoScanner

# Initialize scanner
scanner = PyNiktoScanner()

# Run scan
results = scanner.scan("https://example.com", threads=10)

# Access findings
for finding in results.findings:
    print(f"{finding.risk}: {finding.message}")

# Export results
results.export_json("results.json")
results.export_sarif("results.sarif")
```

See [docs/INTEGRATION_EXAMPLES.md](docs/INTEGRATION_EXAMPLES.md) for more examples.

## Command-Line Options

### Basic Options

- `-host <target>`: Target hostname or IP (required)
- `-port <port>`: Port number (default: 80)
- `-ssl`: Use SSL/TLS
- `-t <threads>`: Number of concurrent threads (default: 10)
- `-timeout <seconds>`: Request timeout (default: 30)

### Output Options

- `-Format <format>`: Output format (json, xml, csv, sarif, junit, html, text)
- `-output <file>`: Output file path

### Advanced Options

- `-crawl`: Enable website crawling
- `-crawl-depth <N>`: Maximum crawl depth (default: 3)
- `-Tuning <filters>`: Filter tests by category (e.g., "1,2,3")
- `-no-robots`: Ignore robots.txt when crawling
- `-useragent <string>`: Custom user agent
- `-useproxy <url>`: Use HTTP proxy

### Help

```bash
python nikto.py -Help
```

## Output Formats

PyNikto supports multiple output formats for integration with various tools:

| Format | Use Case | Example |
|-------|----------|---------|
| **JSON** | Programmatic parsing, automation | `-Format json` |
| **XML** | Burp Suite, OWASP ZAP, Metasploit | `-Format xml` |
| **CSV** | Excel, databases, SIEM systems | `-Format csv` |
| **SARIF** | GitHub Security, CodeQL, VS Code | `-Format sarif` |
| **JUnit XML** | Jenkins, GitLab CI, GitHub Actions | `-Format junit` |
| **HTML** | Human-readable reports | `-Format html` |
| **Text** | Console output (default) | (default) |

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run PyNikto
        run: |
          pip install -r requirements.txt
          python nikto.py -host ${{ secrets.TARGET_URL }} \
            -Format sarif -output results.sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
security_scan:
  script:
    - pip install -r requirements.txt
    - python nikto.py -host $TARGET_URL -Format junit -output results.xml
  artifacts:
    reports:
      junit: results.xml
```

## Project Structure

```
pynikto/
├── nikto.py                 # Main scanner script
├── api.py                   # Python API
├── nmap_integration.py      # Nmap integration script
├── plugins/                 # Scanning plugins
│   ├── files_from_db.py     # Database-driven tests
│   ├── crawler.py           # Website crawler
│   ├── security_headers.py  # Security headers check
│   └── ...
├── databases/               # Test databases
│   ├── db_tests.json        # Main test database
│   ├── nuclei/              # Nuclei templates
│   ├── seclists/            # SecLists wordlists
│   ├── cve/                 # CVE tests
│   └── wappalyzer/          # Wappalyzer patterns
├── scripts/                  # Utility scripts
│   ├── github/              # GitHub tools
│   ├── install/             # Installation scripts
│   └── utils/                # Utility scripts
├── docs/                     # Additional documentation
├── output_formatters.py     # Output format handlers
└── requirements.txt        # Python dependencies
```

See [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md) for detailed structure information.

## Tuning Options

Filter tests by category:

- `1` - Interesting File / Seen in logs
- `2` - Misconfiguration / Default File
- `3` - Information Disclosure
- `4` - Injection (XSS/Script/HTML)
- `5` - Remote File Retrieval - Inside Web Root
- `6` - Denial of Service
- `7` - Remote File Retrieval - Server Wide
- `8` - Command Execution / Remote Shell
- `9` - SQL Injection
- `0` - File Upload
- `a` - Authentication Bypass
- `b` - Software Identification
- `c` - Remote Source Inclusion
- `d` - WebService
- `e` - Administrative Console

Example:
```bash
python nikto.py -host example.com -Tuning "1,2,3"  # Only test categories 1, 2, 3
```

## Requirements

- Python 3.7 or higher
- requests library (install via `pip install -r requirements.txt`)
- Nmap (optional, for integration features)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the GPL License - see the LICENSE file for details.

## Disclaimer

This tool is for authorized security testing only. Unauthorized use against systems you don't own or have permission to test is illegal. The authors are not responsible for any misuse or damage caused by this program.

## Acknowledgments

- Inspired by [Nikto](https://github.com/sullo/nikto)
- Built with Python for flexibility and extensibility

## Support

For issues, questions, or contributions, please open an issue on GitHub.

## Changelog

### Version 0.1.0
- Initial release
- Basic web server scanning
- Multiple output formats (JSON, XML, CSV, SARIF, JUnit, HTML)
- Website crawling support
- Nmap integration
- Python API
- CI/CD integration support

---

**Made with ❤️ for the security community**

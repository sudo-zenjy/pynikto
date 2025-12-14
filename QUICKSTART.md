# PyNikto Quick Start Guide

Get up and running with PyNikto in 5 minutes!

## Installation (Kali Linux)

```bash
# Clone repository
git clone https://github.com/sudo-zenjy/pynikto.git
cd pynikto

# Run installation script
chmod +x install.sh
./install.sh

# Or install manually (Kali Linux - use virtual environment)
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
chmod +x *.py *.sh
```

## First Scan

**Important**: Make sure you're in the `pynikto` directory and virtual environment is activated:

```bash
# Navigate to the directory (if not already there)
cd ~/pynikto

# Activate virtual environment (IMPORTANT!)
source venv/bin/activate

# You should see (venv) in your prompt

# Basic scan
python3 nikto.py -host scanme.nmap.org -port 80

# With output
python3 nikto.py -host scanme.nmap.org -port 80 -Format json -output results.json
```

## Common Commands

**Remember**: Always activate virtual environment first: `source venv/bin/activate`

```bash
# Scan HTTPS
python3 nikto.py -host example.com -port 443 -ssl

# Enable crawling
python3 nikto.py -host example.com -crawl

# Nmap integration
python3 nmap_integration.py example.com

# Python API
python3 -c "from api import quick_scan; r = quick_scan('example.com'); print(f'Found {len(r.findings)} issues')"
```

## Output Formats

```bash
# JSON
python3 nikto.py -host example.com -Format json -output results.json

# SARIF (GitHub Security)
python3 nikto.py -host example.com -Format sarif -output results.sarif

# HTML Report
python3 nikto.py -host example.com -Format html -output report.html
```

## Help

```bash
# Show all options
python3 nikto.py -Help

# Version
python3 nikto.py -Version
```

## Next Steps

- Read [README.md](README.md) for full documentation
- Check [INTEGRATION_EXAMPLES.md](INTEGRATION_EXAMPLES.md) for integration examples
- See [NMAP_INTEGRATION_README.md](NMAP_INTEGRATION_README.md) for Nmap integration

---

**Remember**: Always get permission before scanning targets!

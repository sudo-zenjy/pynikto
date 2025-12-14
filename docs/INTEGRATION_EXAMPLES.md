# PyNikto Integration Guide

PyNikto now supports extensive integration with other security tools and platforms.

## Output Formats

### 1. JSON Format
**Use case:** Programmatic parsing, custom tools, data analysis

```bash
python nikto.py -host example.com -Format json -output results.json
```

**Python usage:**
```python
import json
with open("results.json") as f:
    data = json.load(f)
    for finding in data["findings"]:
        print(f"{finding['risk']}: {finding['message']}")
```

### 2. XML Format
**Use case:** Burp Suite, OWASP ZAP, Metasploit, custom XML parsers

```bash
python nikto.py -host example.com -Format xml -output results.xml
```

### 3. CSV Format
**Use case:** Excel, databases, SIEM systems, data analysis tools

```bash
python nikto.py -host example.com -Format csv -output results.csv
```

### 4. SARIF Format (NEW)
**Use case:** GitHub Security, CodeQL, VS Code, Azure DevOps, SonarQube

```bash
python nikto.py -host example.com -Format sarif -output results.sarif
```

**GitHub Actions integration:**
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
          python nikto.py -host ${{ secrets.TARGET_URL }} -Format sarif -output results.sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### 5. JUnit XML Format (NEW)
**Use case:** Jenkins, GitLab CI, GitHub Actions, CircleCI, TeamCity

```bash
python nikto.py -host example.com -Format junit -output results.xml
```

**Jenkins integration:**
```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'python nikto.py -host example.com -Format junit -output results.xml'
                junit 'results.xml'
            }
        }
    }
}
```

**GitLab CI integration:**
```yaml
security_scan:
  script:
    - python nikto.py -host $TARGET_URL -Format junit -output results.xml
  artifacts:
    reports:
      junit: results.xml
```

### 6. HTML Format (NEW)
**Use case:** Human-readable reports, email notifications, documentation

```bash
python nikto.py -host example.com -Format html -output report.html
```

## Python API Integration

### Basic Usage

```python
from api import PyNiktoScanner

# Initialize scanner
scanner = PyNiktoScanner(
    timeout=30.0,
    verify_ssl=True,
    user_agent="MySecurityTool/1.0"
)

# Run scan
results = scanner.scan(
    target="https://example.com",
    threads=10,
    crawl_enabled=True,
    crawl_depth=3
)

# Access findings
print(f"Found {len(results.findings)} issues")
for finding in results.findings:
    print(f"{finding.risk}: {finding.message} at {finding.url}")

# Filter findings
high_risk = results.get_findings_by_risk("high")
print(f"High risk issues: {len(high_risk)}")

# Export to different formats
results.export_json("results.json")
results.export_sarif("results.sarif")
results.export_junit("results.xml")
results.export_html("report.html")
```

### Quick Scan

```python
from api import quick_scan

results = quick_scan("https://example.com", threads=5)
print(f"Scan completed: {len(results.findings)} findings")
```

### Integration with Other Tools

#### Example: Integrate with Nmap

```python
import nmap
from api import PyNiktoScanner

# Scan ports with Nmap
nm = nmap.PortScanner()
nm.scan('example.com', '80,443,8080')

# Run PyNikto on discovered web services
scanner = PyNiktoScanner()
for host in nm.all_hosts():
    for proto in nm[host].all_protocols():
        ports = nm[host][proto].keys()
        for port in ports:
            if port in [80, 443, 8080]:
                ssl = port == 443
                results = scanner.scan(host, port=str(port), ssl=ssl)
                results.export_json(f"scan_{host}_{port}.json")
```

#### Example: Batch Scanning

```python
from api import PyNiktoScanner

targets = [
    "https://example.com",
    "https://test.example.com",
    "http://dev.example.com:8080"
]

scanner = PyNiktoScanner()
all_results = []

for target in targets:
    print(f"Scanning {target}...")
    results = scanner.scan(target)
    all_results.append(results)
    results.export_json(f"scan_{target.replace('://', '_').replace('/', '_')}.json")

# Aggregate results
total_findings = sum(len(r.findings) for r in all_results)
print(f"Total findings across all targets: {total_findings}")
```

#### Example: CI/CD Integration

```python
from api import PyNiktoScanner
import sys

def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    
    scanner = PyNiktoScanner()
    results = scanner.scan(target, threads=10)
    
    # Export for CI/CD
    results.export_sarif("results.sarif")
    results.export_junit("results.xml")
    
    # Fail build if high-risk issues found
    high_risk = results.get_findings_by_risk("high")
    if high_risk:
        print(f"ERROR: {len(high_risk)} high-risk issues found!")
        sys.exit(1)
    
    print("Scan completed successfully")

if __name__ == "__main__":
    main()
```

## Command-Line Integration

### Shell Scripts

```bash
#!/bin/bash
TARGET="https://example.com"

# Run scan
python nikto.py -host "$TARGET" -Format json -output scan.json

# Parse results with jq
HIGH_RISK=$(jq '.findings[] | select(.risk == "high")' scan.json | wc -l)
echo "High risk issues: $HIGH_RISK"

# Exit with error if high-risk issues found
if [ "$HIGH_RISK" -gt 0 ]; then
    exit 1
fi
```

### PowerShell Integration

```powershell
$target = "https://example.com"
python nikto.py -host $target -Format json -output scan.json

$results = Get-Content scan.json | ConvertFrom-Json
$highRisk = $results.findings | Where-Object { $_.risk -eq "high" }

if ($highRisk.Count -gt 0) {
    Write-Error "Found $($highRisk.Count) high-risk issues"
    exit 1
}
```

## Integration Checklist

- ✅ JSON output (programmatic parsing)
- ✅ XML output (Burp, ZAP, Metasploit)
- ✅ CSV output (Excel, databases, SIEM)
- ✅ SARIF output (GitHub Security, CodeQL, VS Code)
- ✅ JUnit XML output (Jenkins, GitLab CI, GitHub Actions)
- ✅ HTML reports (human-readable)
- ✅ Python API (programmatic use)
- ✅ Command-line interface (shell scripts, automation)

## Supported Tools & Platforms

| Tool/Platform | Format | Status |
|--------------|--------|--------|
| GitHub Security | SARIF | ✅ Supported |
| CodeQL | SARIF | ✅ Supported |
| VS Code | SARIF | ✅ Supported |
| Jenkins | JUnit XML | ✅ Supported |
| GitLab CI | JUnit XML | ✅ Supported |
| GitHub Actions | JUnit XML, SARIF | ✅ Supported |
| Burp Suite | XML | ✅ Supported |
| OWASP ZAP | XML | ✅ Supported |
| Excel | CSV | ✅ Supported |
| Splunk | CSV, JSON | ✅ Supported |
| ELK Stack | JSON | ✅ Supported |
| Custom Tools | JSON, XML, CSV | ✅ Supported |
| Nmap | XML (via integration script) | ✅ Supported |

## Nmap Integration

PyNikto can be integrated with Nmap to automatically discover and scan web services.

### Method 1: Using the Integration Script (Recommended)

The `nmap_integration.py` script automatically runs Nmap, parses results, and scans discovered web services with PyNikto.

#### Basic Usage

```bash
# Scan a host - Nmap discovers web services, then PyNikto scans them
python nmap_integration.py example.com

# Custom Nmap port scan
python nmap_integration.py example.com --nmap-args "-p 80,443,8080,8443,8000,8888"

# Full port scan then web scan
python nmap_integration.py example.com --nmap-args "-p-"

# Service detection + web scan
python nmap_integration.py example.com --nmap-args "-sV -p 80,443"
```

#### Advanced Usage

```bash
# Custom PyNikto options
python nmap_integration.py example.com \
    --nmap-args "-p 80,443,8080" \
    --pynikto-threads 20 \
    --pynikto-format json \
    --pynikto-crawl \
    --output results.json

# Use existing Nmap XML file
python nmap_integration.py example.com --nmap-xml scan.xml --skip-nmap

# Output to SARIF for GitHub Security
python nmap_integration.py example.com \
    --nmap-args "-p 80,443" \
    --pynikto-format sarif \
    --output results.sarif
```

#### Using Shell Scripts

**Linux/Mac:**
```bash
# Make executable
chmod +x nmap_pynikto.sh

# Run
./nmap_pynikto.sh example.com
./nmap_pynikto.sh example.com "-p 80,443,8080" "--pynikto-threads 20"
```

**Windows:**
```batch
nmap_pynikto.bat example.com
nmap_pynikto.bat example.com "-p 80,443,8080" "--pynikto-threads 20"
```

### Method 2: Manual Integration (Command Line)

#### Step 1: Run Nmap

```bash
# Scan for web services
nmap -p 80,443,8080,8443,8000,8888 -oX nmap_results.xml example.com

# Or with service detection
nmap -sV -p 80,443,8080,8443 -oX nmap_results.xml example.com

# Full port scan
nmap -p- -oX nmap_results.xml example.com
```

#### Step 2: Parse Nmap XML and Run PyNikto

```bash
# Extract web services from Nmap XML (using grep/xmlstarlet)
# Then run PyNikto on each discovered service

# Example: HTTP service on port 80
python nikto.py -host example.com -port 80 -Format json -output scan_80.json

# Example: HTTPS service on port 443
python nikto.py -host example.com -port 443 -ssl -Format json -output scan_443.json

# Example: Custom port
python nikto.py -host example.com -port 8080 -Format json -output scan_8080.json
```

#### Automated Script Example

```bash
#!/bin/bash
TARGET="example.com"
NMAP_XML="nmap_scan.xml"

# Run Nmap
nmap -p 80,443,8080,8443,8000,8888 -oX "$NMAP_XML" "$TARGET"

# Extract web services and scan
for port in $(xmlstarlet sel -t -v "//port[@protocol='tcp' and state/@state='open']/@portid" "$NMAP_XML" | grep -E '^(80|443|8080|8443|8000|8888)$'); do
    if [ "$port" = "443" ] || [ "$port" = "8443" ]; then
        SSL_FLAG="-ssl"
    else
        SSL_FLAG=""
    fi
    
    echo "[*] Scanning $TARGET:$port"
    python nikto.py -host "$TARGET" -port "$port" $SSL_FLAG -Format json -output "scan_${TARGET}_${port}.json"
done
```

### Method 3: Python API Integration

```python
import subprocess
import xml.etree.ElementTree as ET
from api import PyNiktoScanner

# Step 1: Run Nmap
target = "example.com"
nmap_xml = "nmap_scan.xml"

subprocess.run([
    "nmap", "-p", "80,443,8080,8443", "-oX", nmap_xml, target
])

# Step 2: Parse Nmap XML
tree = ET.parse(nmap_xml)
root = tree.getroot()

web_services = []
for host in root.findall('host'):
    for port in host.findall('ports/port'):
        if port.find('state').get('state') == 'open':
            port_num = int(port.get('portid'))
            if port_num in [80, 443, 8080, 8443, 8000, 8888]:
                hostname = host.find('hostnames/hostname')
                host_ip = host.find('address[@addrtype="ipv4"]')
                target_host = hostname.get('name') if hostname is not None else host_ip.get('addr')
                is_ssl = port_num in [443, 8443]
                web_services.append((target_host, port_num, is_ssl))

# Step 3: Scan with PyNikto
scanner = PyNiktoScanner()
all_results = []

for host, port, is_ssl in web_services:
    print(f"Scanning {host}:{port}...")
    results = scanner.scan(host, port=str(port), ssl=is_ssl, threads=10)
    all_results.append(results)
    
    # Export results
    results.export_json(f"scan_{host}_{port}.json")

# Aggregate results
total_findings = sum(len(r.findings) for r in all_results)
print(f"Total findings: {total_findings}")
```

### Method 4: Using python-nmap Library

```python
import nmap
from api import PyNiktoScanner

# Initialize Nmap scanner
nm = nmap.PortScanner()

# Scan for web services
target = "example.com"
nm.scan(target, '80,443,8080,8443,8000,8888', arguments='-sV')

# Initialize PyNikto scanner
pynikto = PyNiktoScanner()

# Scan discovered web services
for host in nm.all_hosts():
    for proto in nm[host].all_protocols():
        ports = nm[host][proto].keys()
        for port in ports:
            if port in [80, 443, 8080, 8443, 8000, 8888]:
                is_ssl = port in [443, 8443]
                print(f"Scanning {host}:{port}...")
                
                results = pynikto.scan(host, port=str(port), ssl=is_ssl)
                results.export_json(f"scan_{host}_{port}.json")
                
                # Print summary
                print(f"  Found {len(results.findings)} issues")
                high_risk = results.get_findings_by_risk("high")
                if high_risk:
                    print(f"  ⚠️  {len(high_risk)} high-risk issues!")
```

### Integration Workflow Examples

#### Example 1: Quick Web Service Discovery and Scan

```bash
# One-liner: Discover and scan
python nmap_integration.py example.com --nmap-args "-p 80,443,8080" --pynikto-format json
```

#### Example 2: Comprehensive Security Assessment

```bash
# Step 1: Full Nmap scan with service detection
nmap -sV -p- -oX full_scan.xml example.com

# Step 2: Use integration script with existing Nmap results
python nmap_integration.py example.com \
    --nmap-xml full_scan.xml \
    --skip-nmap \
    --pynikto-crawl \
    --pynikto-format sarif \
    --output security_report.sarif
```

#### Example 3: CI/CD Integration

```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on: [push, pull_request]
jobs:
  nmap-pynikto:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install Nmap
        run: sudo apt-get update && sudo apt-get install -y nmap
      - name: Run Nmap + PyNikto
        run: |
          python nmap_integration.py ${{ secrets.TARGET_URL }} \
            --nmap-args "-p 80,443,8080" \
            --pynikto-format sarif \
            --output results.sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### Tips for Nmap Integration

1. **Port Selection**: Focus on common web ports (80, 443, 8080, 8443, 8000, 8888) for faster scans
2. **Service Detection**: Use `-sV` flag to identify HTTP/HTTPS services more accurately
3. **Output Formats**: Use JSON or SARIF for automated processing
4. **Performance**: Use `--pynikto-threads` to control scan speed
5. **Crawling**: Enable `--pynikto-crawl` for comprehensive website discovery

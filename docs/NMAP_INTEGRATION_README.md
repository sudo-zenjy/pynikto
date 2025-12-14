# Nmap + PyNikto Integration Guide

This guide shows you how to integrate Nmap with PyNikto to automatically discover and scan web services.

## Quick Start

### Basic Usage

```bash
# Discover web services with Nmap and scan with PyNikto
python nmap_integration.py example.com
```

This will:
1. Run Nmap to discover web services on common ports (80, 443, 8080, 8443, 8000, 8888)
2. Automatically scan each discovered service with PyNikto
3. Display results and optionally save to file

## Installation Requirements

- **Nmap**: Must be installed and in your PATH
  - Windows: Download from https://nmap.org/download.html
  - Linux: `sudo apt-get install nmap` or `sudo yum install nmap`
  - Mac: `brew install nmap`

- **Python**: Python 3.7+ with PyNikto dependencies

## Usage Examples

### Example 1: Basic Scan

```bash
python nmap_integration.py example.com
```

Scans common web ports (80, 443, 8080, 8443, 8000, 8888) and runs PyNikto on discovered services.

### Example 2: Custom Port Range

```bash
python nmap_integration.py example.com --nmap-args "-p 80,443,8080,8443"
```

Only scans specified ports.

### Example 3: Full Port Scan

```bash
python nmap_integration.py example.com --nmap-args "-p-"
```

Scans all ports (takes longer).

### Example 4: Service Detection

```bash
python nmap_integration.py example.com --nmap-args "-sV -p 80,443"
```

Uses Nmap service detection to better identify web services.

### Example 5: Custom PyNikto Options

```bash
python nmap_integration.py example.com \
    --pynikto-threads 20 \
    --pynikto-format json \
    --pynikto-crawl \
    --output results.json
```

- Uses 20 threads for faster scanning
- Outputs JSON format
- Enables website crawling
- Saves to results.json

### Example 6: Use Existing Nmap Results

```bash
# First, run Nmap separately
nmap -p 80,443,8080 -oX nmap_scan.xml example.com

# Then use the XML file
python nmap_integration.py example.com \
    --nmap-xml nmap_scan.xml \
    --skip-nmap
```

### Example 7: Output to SARIF (GitHub Security)

```bash
python nmap_integration.py example.com \
    --nmap-args "-p 80,443" \
    --pynikto-format sarif \
    --output results.sarif
```

## Command-Line Options

### Nmap Options

- `--nmap-args "<args>"`: Additional Nmap arguments
  - Example: `--nmap-args "-p 80,443,8080 -sV"`
  
- `--nmap-xml <file>`: Use existing Nmap XML file instead of running new scan

- `--skip-nmap`: Skip Nmap scan (use with --nmap-xml)

- `--keep-nmap-xml`: Keep Nmap XML file after scanning (default: deleted)

### PyNikto Options

- `--pynikto-threads <N>`: Number of threads (default: 10)

- `--pynikto-timeout <seconds>`: Request timeout (default: 30.0)

- `--pynikto-format <format>`: Output format
  - Options: json, xml, csv, sarif, junit, html, text
  - Default: text

- `--pynikto-tuning <filters>`: Tuning filter (e.g., "1,2,3")

- `--pynikto-crawl`: Enable website crawling

- `--pynikto-crawl-depth <N>`: Maximum crawl depth (default: 3)

### Output Options

- `--output <file>`: Output file path
  - Format determined by file extension or --pynikto-format

## Using Shell Scripts

### Linux/Mac

```bash
# Make executable
chmod +x nmap_pynikto.sh

# Run
./nmap_pynikto.sh example.com
./nmap_pynikto.sh example.com "-p 80,443,8080" "--pynikto-threads 20"
```

### Windows

```batch
nmap_pynikto.bat example.com
nmap_pynikto.bat example.com "-p 80,443,8080" "--pynikto-threads 20"
```

## Manual Integration (Step-by-Step)

If you prefer to run Nmap and PyNikto separately:

### Step 1: Run Nmap

```bash
nmap -p 80,443,8080,8443 -oX nmap_results.xml example.com
```

### Step 2: Parse Results and Run PyNikto

```bash
# HTTP service on port 80
python nikto.py -host example.com -port 80 -Format json -output scan_80.json

# HTTPS service on port 443
python nikto.py -host example.com -port 443 -ssl -Format json -output scan_443.json

# Custom port
python nikto.py -host example.com -port 8080 -Format json -output scan_8080.json
```

## Python API Integration

```python
import subprocess
from api import PyNiktoScanner

# Run Nmap
subprocess.run(["nmap", "-p", "80,443,8080", "-oX", "scan.xml", "example.com"])

# Parse Nmap XML and scan with PyNikto
# (See INTEGRATION_EXAMPLES.md for full example)
```

## Output Formats

The integration script supports all PyNikto output formats:

- **JSON**: For programmatic parsing
- **XML**: For Burp Suite, OWASP ZAP
- **CSV**: For Excel, databases
- **SARIF**: For GitHub Security, CodeQL
- **JUnit XML**: For CI/CD pipelines
- **HTML**: For human-readable reports
- **Text**: Default console output

## Troubleshooting

### Nmap Not Found

**Error**: `Error: Nmap not found`

**Solution**: Install Nmap and ensure it's in your PATH
- Windows: Add Nmap installation directory to PATH
- Linux/Mac: Install via package manager

### No Web Services Found

**Issue**: Nmap scan completes but no web services are discovered

**Solutions**:
- Try broader port range: `--nmap-args "-p-"`
- Use service detection: `--nmap-args "-sV -p 80,443"`
- Check if target is actually running web services

### PyNikto Scan Fails

**Issue**: Nmap finds services but PyNikto fails to scan

**Solutions**:
- Check if service is actually HTTP/HTTPS
- Try increasing timeout: `--pynikto-timeout 60`
- Check network connectivity
- Verify SSL/TLS settings

## Best Practices

1. **Start with common ports**: Use `-p 80,443,8080,8443` for faster initial scans
2. **Use service detection**: Add `-sV` to Nmap args for better identification
3. **Enable crawling**: Use `--pynikto-crawl` for comprehensive discovery
4. **Save results**: Always use `--output` to save results for later analysis
5. **Use appropriate format**: JSON/SARIF for automation, HTML for reports

## Examples for Common Scenarios

### Quick Security Check

```bash
python nmap_integration.py example.com \
    --nmap-args "-p 80,443" \
    --pynikto-format json \
    --output quick_scan.json
```

### Comprehensive Assessment

```bash
python nmap_integration.py example.com \
    --nmap-args "-sV -p-" \
    --pynikto-crawl \
    --pynikto-crawl-depth 5 \
    --pynikto-format html \
    --output full_report.html
```

### CI/CD Integration

```bash
python nmap_integration.py $TARGET_URL \
    --nmap-args "-p 80,443,8080" \
    --pynikto-format sarif \
    --output results.sarif
```

## See Also

- `INTEGRATION_EXAMPLES.md` - More integration examples
- `api.py` - Python API documentation
- PyNikto main documentation

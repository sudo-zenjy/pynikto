# PyNikto Usage Examples

## Basic Scanning

```bash
# Basic scan
python nikto.py -host example.com

# HTTPS scan
python nikto.py -host example.com -port 443 -ssl

# Custom port
python nikto.py -host example.com -port 8080
```

## Legacy Mode and CGI Scanning

### Force All CGI Directories (`-C all`)

Use this to force scanning all CGI directories, even if none are detected:

```bash
# Force check all CGI directories
python nikto.py -host example.com -C all

# Short form (same as -C all)
python nikto.py -host example.com -C
```

**What it does:**
- Forces scanning of all CGI paths in the database
- Bypasses CGI directory detection
- Useful when CGI directories exist but aren't detected initially

### Full Legacy Mode (`--legacy-mode`)

Use this for comprehensive scanning like original Nikto:

```bash
# Enable full legacy mode
python nikto.py -host example.com --legacy-mode
```

**What it does:**
- Scans ALL paths (no tech-specific filtering)
- Forces all CGI directory scanning
- Always checks common test paths (phpinfo.php, /test/, /admin/)
- Similar to original Nikto's behavior

## When to Use Each Option

### Use `-C all` when:
- You know CGI directories exist but weren't detected
- You want to test all CGI paths without full legacy mode
- You're testing legacy applications

### Use `--legacy-mode` when:
- You want maximum coverage (like original Nikto)
- Testing old/vulnerable applications
- You want to find everything, including legacy paths
- You're doing a comprehensive security assessment

## Examples

```bash
# Quick scan (default - smart filtering)
python nikto.py -host testphp.vulnweb.com

# Force CGI scanning
python nikto.py -host testphp.vulnweb.com -C all

# Full legacy mode (most comprehensive)
python nikto.py -host testphp.vulnweb.com --legacy-mode

# Combine with other options
python nikto.py -host example.com --legacy-mode -t 100 -timeout 60
```

## Output Differences

**Default mode:**
- Skips tech-specific paths if tech not detected
- Skips CGI paths if no CGI directories found
- Faster, more focused scanning

**Legacy mode (`--legacy-mode`):**
- Tests ALL paths regardless of tech detection
- Tests ALL CGI paths
- Slower but more comprehensive
- Matches original Nikto behavior

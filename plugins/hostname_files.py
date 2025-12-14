# plugins/hostname_files.py
from typing import List, Dict
import hashlib

from findings import Finding
from http_client import HttpClient
from targets import Target

PLUGIN_NAME = "hostname_files"


def run(target: Target, http: HttpClient, notfound_sigs: Dict = None) -> List[Finding]:
    """
    Check for hostname-based backup files (like original Nikto).
    Examples: juice-shop.cer, juice-shop.jks, juice-shop.tgz, etc.
    """
    findings: List[Finding] = []
    
    # Extract hostname without domain extension for variations
    hostname = target.host
    hostname_parts = hostname.split(".")
    
    # Generate variations
    variations = [
        hostname,  # full hostname
        hostname.replace(".", "_"),  # underscores
        hostname.replace(".", "-"),  # dashes
        hostname.replace(".", ""),   # no separators
    ]
    
    # If hostname has multiple parts, also try the first part (subdomain/main name)
    if len(hostname_parts) > 1:
        variations.append(hostname_parts[0])
    
    # Common backup/cert file extensions
    extensions = [
        ".cer", ".crt", ".pem", ".key", ".p12", ".pfx",  # Certificates
        ".jks", ".keystore",  # Java keystores
        ".tar", ".tar.gz", ".tgz", ".zip", ".bak",  # Backups
        ".sql", ".sql.gz", ".dump",  # Database dumps
        ".egg", ".jar", ".war",  # Application packages
        ".old", ".orig", ".save", ".backup",  # Backup suffixes
    ]
    
    # Check each variation with each extension
    paths_to_check = []
    for variation in variations:
        for ext in extensions:
            paths_to_check.append(f"/{variation}{ext}")
    
    # Check paths
    for path in paths_to_check:
        url = f"{target.base_url}{path}"
        resp = http.get(url, allow_redirects=False)  # Use GET to get content for validation
        
        # Check for successful response
        if resp and resp.status_code == 200:
            # Validate against 404 signatures (filter false positives)
            is_false_positive = False
            if notfound_sigs and notfound_sigs.get('enabled'):
                for sig in notfound_sigs.get('signatures', []):
                    # Check if response matches 404 signature
                    if resp.status_code == sig.get('status'):
                        # Compare content length (within 100 bytes tolerance)
                        if abs(len(resp.text) - sig.get('length', 0)) < 100:
                            # Compare MD5 hash
                            resp_hash = hashlib.md5(resp.text.encode()).hexdigest()
                            if resp_hash == sig.get('hash'):
                                is_false_positive = True
                                break
            
            # Skip if it's a false positive
            if is_false_positive:
                continue
            
            # Additional validation: check content type and size
            content_type = resp.headers.get('Content-Type', '').lower()
            content_length = len(resp.content)
            
            # Skip if content looks like HTML (likely a catch-all page)
            if 'text/html' in content_type and content_length > 10000:
                # Large HTML response is likely a catch-all page, not a backup file
                continue
            
            # Determine risk and message based on extension
            risk = "medium"
            file_type = "backup/cert"
            
            if any(ext in path for ext in [".cer", ".crt", ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"]):
                file_type = "backup/cert"
                message = f"Potentially interesting backup/cert file found. ."
            elif any(ext in path for ext in [".sql", ".sql.gz", ".dump"]):
                file_type = "database backup"
                message = f"Potentially interesting database backup file found. ."
                risk = "high"
            elif any(ext in path for ext in [".tar", ".tar.gz", ".tgz", ".zip", ".bak"]):
                file_type = "backup"
                message = f"Potentially interesting backup file found. ."
            else:
                file_type = "backup"
                message = f"Potentially interesting backup file found. ."
            
            findings.append(Finding(
                plugin=PLUGIN_NAME,
                url=url,
                message=message,
                risk=risk,
                status=resp.status_code,
                nikto_id="000520",
                references="https://cwe.mitre.org/data/definitions/530.html",
                uri=path,
            ))
    
    return findings


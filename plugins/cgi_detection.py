# plugins/cgi_detection.py
from typing import List
import hashlib

from findings import Finding
from http_client import HttpClient
from targets import Target

PLUGIN_NAME = "cgi_detection"


def run(target: Target, http: HttpClient) -> List[Finding]:
    """
    Detect CGI directories (like original Nikto).
    Reports if no CGI directories are found.
    Uses baseline comparison to filter false positives.
    """
    findings: List[Finding] = []
    
    # Get baseline response from root
    baseline_resp = http.get(f"{target.base_url}/", allow_redirects=False)
    baseline_hash = None
    if baseline_resp and baseline_resp.text:
        # Calculate hash of baseline response body
        baseline_hash = hashlib.md5(baseline_resp.text.encode('utf-8', errors='ignore')).hexdigest()
    
    # Common CGI directories to check
    cgi_dirs = [
        "/cgi-bin/",
        "/cgi/",
        "/cgi-mod/",
        "/cgi-sys/",
        "/scripts/",
        "/cgi-local/",
        "/htbin/",
        "/cgibin/",
        "/cgis/",
        "/cgi-win/",
        "/fcgi-bin/",
    ]
    
    found_cgi = []
    
    for cgi_dir in cgi_dirs:
        url = f"{target.base_url}{cgi_dir}"
        resp = http.get(url, allow_redirects=False)
        
        # Check for successful response or redirect (indicates directory exists)
        if resp and resp.status_code in [200, 301, 302, 403]:
            # Compare with baseline to filter false positives
            is_false_positive = False
            if baseline_hash and resp.text:
                cgi_hash = hashlib.md5(resp.text.encode('utf-8', errors='ignore')).hexdigest()
                # If hash is identical to baseline, it's likely a false positive
                # (server returning same content for all paths or redirecting to root)
                if cgi_hash == baseline_hash:
                    is_false_positive = True
            
            # Only add if not a false positive
            if not is_false_positive:
                found_cgi.append(cgi_dir)
    
    # Report findings like Nikto
    if not found_cgi:
        # No CGI directories found (like Nikto reports)
        findings.append(Finding(
            plugin=PLUGIN_NAME,
            url=f"{target.base_url}/",
            message="No CGI Directories found (use '-C all' or '--legacy-mode' to force check all possible dirs).",
            risk="info",
            status=200,
            nikto_id="000600",
            uri="/",
        ))
    else:
        # CGI directories found
        for cgi_dir in found_cgi:
            findings.append(Finding(
                plugin=PLUGIN_NAME,
                url=f"{target.base_url}{cgi_dir}",
                message=f"CGI directory found: {cgi_dir}.",
                risk="info",
                status=200,
                nikto_id="000601",
                uri=cgi_dir,
            ))
    
    return findings


# plugins/http_methods.py
from typing import List

from findings import Finding
from http_client import HttpClient
from targets import Target

PLUGIN_NAME = "http_methods"

def run(target: Target, http: HttpClient) -> List[Finding]:
    findings: List[Finding] = []
    url = f"{target.base_url}/"
    
    # Test OPTIONS
    resp = http.request("OPTIONS", url)
    if resp and "Allow" in resp.headers:
        allowed = resp.headers["Allow"]
        findings.append(Finding(
            plugin=PLUGIN_NAME,
            url=url,
            message=f"Allowed HTTP Methods: {allowed} .",
            risk="info",
            status=resp.status_code,
            nikto_id="000200",
            method="OPTIONS",
            uri="/",
        ))
        
        # Check for dangerous methods (like original Nikto)
        if "PUT" in allowed:
            findings.append(Finding(
                plugin=PLUGIN_NAME,
                url=url,
                message="'PUT' method could allow clients to save files on the web server.",
                risk="medium",
                status=resp.status_code,
                nikto_id="000201",
                method="HTTP method ('Allow' Header)",
                uri="/",
            ))
        
        if "DELETE" in allowed:
            findings.append(Finding(
                plugin=PLUGIN_NAME,
                url=url,
                message="'DELETE' may allow clients to remove files on the web server.",
                risk="medium",
                status=resp.status_code,
                nikto_id="000202",
                method="HTTP method ('Allow' Header)",
                uri="/",
            ))
        
        # Test junk methods (like original Nikto)
        junk_methods = ["TEST", "JUNK", "FAKE"]
        for method in junk_methods:
            junk_resp = http.request(method, url)
            if junk_resp and junk_resp.status_code in [200, 400, 405]:
                findings.append(Finding(
                    plugin=PLUGIN_NAME,
                    url=url,
                    message="Web Server returns a valid response with junk HTTP methods which may cause false positives.",
                    risk="info",
                    status=junk_resp.status_code,
                    nikto_id="000203",
                    method="",
                    uri="/",
                ))
                break  # Only report once
    
    return findings

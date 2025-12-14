from typing import List
from targets import Target
from http_client import HttpClient
from findings import Finding

PLUGIN_NAME = "cookies"

def run(target: Target, http: HttpClient) -> List[Finding]:
    findings: List[Finding] = []
    url = f"{target.base_url}/"
    
    resp = http.get(url)
    if not resp:
        return findings
    
    cookies = resp.headers.get("Set-Cookie", "")
    if not cookies:
        return findings
    
    # Check for HttpOnly flag
    if "HttpOnly" not in cookies:
        findings.append(Finding(
            plugin=PLUGIN_NAME,
            url=url,
            message="Cookie without HttpOnly flag",
            risk="medium",
            status=resp.status_code,
            nikto_id="000300",
            references="OWASP-002",
        ))
    
    # Check for Secure flag on HTTP
    if not target.ssl and "Secure" not in cookies:
        findings.append(Finding(
            plugin=PLUGIN_NAME,
            url=url,
            message="Cookie without Secure flag on HTTP connection",
            risk="high",
            status=resp.status_code,
            nikto_id="000301",
            references="OWASP-003",
        ))
    
    return findings

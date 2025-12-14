from typing import List
from targets import Target
from http_client import HttpClient
from findings import Finding

PLUGIN_NAME = "robots"

def run(target: Target, http: HttpClient) -> List[Finding]:
    findings: List[Finding] = []
    url = f"{target.base_url}/robots.txt"
    
    resp = http.get(url, allow_redirects=True)
    if not resp or resp.status_code != 200:
        return findings
    
    # Parse robots.txt and check disallowed paths
    content = resp.text
    findings.append(Finding(
        plugin=PLUGIN_NAME,
        url=url,
        message="robots.txt found.",
        risk="info",
        status=resp.status_code,
        nikto_id="000500",
        uri="/robots.txt",
    ))
    
    # Check for interesting disallowed paths
    disallowed_paths = []
    for line in content.split('\n'):
        line = line.strip()
        if line.lower().startswith('disallow:'):
            path = line.split(':', 1)[1].strip()
            if path and path not in ['/', '']:
                disallowed_paths.append(path)
    
    if disallowed_paths:
        findings.append(Finding(
            plugin=PLUGIN_NAME,
            url=url,
            message=f"robots.txt contains {len(disallowed_paths)} disallowed path(s).",
            risk="info",
            status=resp.status_code,
            nikto_id="000501",
            uri="/robots.txt",
        ))
    
    return findings

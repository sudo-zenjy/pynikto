from typing import List
from targets import Target
from http_client import HttpClient
from findings import Finding

PLUGIN_NAME = "headers_fingerprint"


def run(target: Target, http: HttpClient) -> List[Finding]:
    findings: List[Finding] = []

    url = f"{target.base_url}/"
    resp = http.get(url, allow_redirects=True)
    if not resp:
        return findings

    server = resp.headers.get("Server", "")
    powered = resp.headers.get("X-Powered-By", "")

    # Basic examples; extend this list over time
    if server:
        findings.append(Finding(
            plugin=PLUGIN_NAME,
            url=url,
            message=f"Server header present: {server}",
            risk="info",
            status=resp.status_code,
            nikto_id="000400",
        ))

        if "Apache/2.2" in server:
            findings.append(Finding(
                plugin=PLUGIN_NAME,
                url=url,
                message="Apache 2.2.x is very old and likely unsupported",
                risk="medium",
                status=resp.status_code,
                nikto_id="000401",
            ))

    if powered:
        findings.append(Finding(
            plugin=PLUGIN_NAME,
            url=url,
            message=f"X-Powered-By reveals tech stack: {powered}",
            risk="low",
            status=resp.status_code,
            nikto_id="000402",
        ))

        if "PHP/5." in powered:
            findings.append(Finding(
                plugin=PLUGIN_NAME,
                url=url,
                message="Old PHP 5.x detected (end of life)",
                risk="high",
                status=resp.status_code,
                nikto_id="000403",
                references="CVE-2018-19518",
            ))

    return findings
# plugins/security_headers.py
from typing import List

from findings import Finding
from http_client import HttpClient
from targets import Target

PLUGIN_NAME = "security_headers"


def run(target: Target, http: HttpClient) -> tuple[List[Finding], int]:
    """
    Check for missing security headers (industry-standard security checks).
    """
    findings: List[Finding] = []
    tests_run = 0
    
    url = f"{target.base_url}/"
    
    # Try to get root page (with multiple fallbacks)
    resp = http.get(url, allow_redirects=True)
    if not resp:
        # Try without redirects
        resp = http.get(url, allow_redirects=False)
    if not resp:
        # Try HEAD request as last resort
        resp = http.head(url, allow_redirects=True)
    if not resp:
        # Give up - can't connect to server
        return findings, 0
    
    tests_run += 1
    
    # Check for redirect (like real Nikto reports)
    if resp.status_code in [301, 302, 303, 307, 308]:
        location = resp.headers.get("Location", "")
        if location:
            findings.append(Finding(
                plugin=PLUGIN_NAME,
                url=url,
                message=f"Root page / redirects to: {location}",
                risk="info",
                status=resp.status_code,
                nikto_id="000006",
                uri="/",
            ))
            
            # Follow the redirect to check headers on final destination
            # This is critical for sites that redirect HTTP → HTTPS
            if location.startswith("http"):
                redirect_resp = http.get(location, allow_redirects=True)
                if redirect_resp and redirect_resp.status_code == 200:
                    # Use the redirected response for header checks
                    resp = redirect_resp
                    tests_run += 1
    
    # Check X-Frame-Options (Clickjacking protection)
    tests_run += 1
    if not resp.headers.get("X-Frame-Options"):
        findings.append(Finding(
            plugin=PLUGIN_NAME,
            url=url,
            message="The anti-clickjacking X-Frame-Options header is not present.",
            risk="low",
            status=resp.status_code,
            nikto_id="999103",
            references="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
            uri="/",
        ))
    else:
        xfo_value = resp.headers.get("X-Frame-Options", "").upper()
        if xfo_value not in ["DENY", "SAMEORIGIN"]:
            findings.append(Finding(
                plugin=PLUGIN_NAME,
                url=url,
                message=f"X-Frame-Options header has non-standard value: '{resp.headers.get('X-Frame-Options')}'. Should be 'DENY' or 'SAMEORIGIN'.",
                risk="low",
                status=resp.status_code,
                nikto_id="999103a",
            ))
    
    # Check X-Content-Type-Options
    tests_run += 1
    if not resp.headers.get("X-Content-Type-Options"):
        findings.append(Finding(
            plugin=PLUGIN_NAME,
            url=url,
            message="The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type.",
            risk="low",
            status=resp.status_code,
            nikto_id="999104",
            references="https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/",
            uri="/",
        ))
    else:
        xcto_value = resp.headers.get("X-Content-Type-Options", "").upper()
        if xcto_value != "NOSNIFF":
            findings.append(Finding(
                plugin=PLUGIN_NAME,
                url=url,
                message=f"X-Content-Type-Options header has non-standard value: '{resp.headers.get('X-Content-Type-Options')}'. Should be 'nosniff'.",
                risk="low",
                status=resp.status_code,
                nikto_id="999104a",
            ))
    
    # Check X-XSS-Protection
    tests_run += 1
    if not resp.headers.get("X-XSS-Protection"):
        findings.append(Finding(
            plugin=PLUGIN_NAME,
            url=url,
            message="X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS. While deprecated in modern browsers, its absence may indicate lack of security awareness.",
            risk="low",
            status=resp.status_code,
            nikto_id="999107",
            references="OWASP-A7",
        ))
    
    # Check Strict-Transport-Security (HSTS) for HTTPS sites
    tests_run += 1
    if target.ssl:
        if not resp.headers.get("Strict-Transport-Security"):
            findings.append(Finding(
                plugin=PLUGIN_NAME,
                url=url,
                message="Strict-Transport-Security (HSTS) header is not defined. This site may be vulnerable to SSL stripping attacks. HTTPS sites should include 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
                risk="medium",
                status=resp.status_code,
                nikto_id="999108",
                references="OWASP-A6, RFC 6797",
            ))
        else:
            hsts_value = resp.headers.get("Strict-Transport-Security", "")
            if "max-age" not in hsts_value.lower():
                findings.append(Finding(
                    plugin=PLUGIN_NAME,
                    url=url,
                    message=f"HSTS header present but missing max-age directive: '{hsts_value}'. Should include 'max-age=31536000' for proper protection.",
                    risk="low",
                    status=resp.status_code,
                    nikto_id="999108a",
                ))
    
    # Check Content-Security-Policy
    tests_run += 1
    if not resp.headers.get("Content-Security-Policy"):
        findings.append(Finding(
            plugin=PLUGIN_NAME,
            url=url,
            message="Content-Security-Policy header is not set. This could allow XSS attacks and unauthorized resource loading. CSP helps prevent XSS, clickjacking, and other code injection attacks.",
            risk="low",
            status=resp.status_code,
            nikto_id="999109",
            references="OWASP-A7, https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
        ))
    
    # Check Referrer-Policy
    tests_run += 1
    if not resp.headers.get("Referrer-Policy"):
        findings.append(Finding(
            plugin=PLUGIN_NAME,
            url=url,
            message="Referrer-Policy header is not set. This may leak sensitive information in the Referer header when users navigate away from the site.",
            risk="low",
            status=resp.status_code,
            nikto_id="999110",
            references="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
        ))
    
    # Check Permissions-Policy (formerly Feature-Policy)
    tests_run += 1
    if not resp.headers.get("Permissions-Policy") and not resp.headers.get("Feature-Policy"):
        findings.append(Finding(
            plugin=PLUGIN_NAME,
            url=url,
            message="Permissions-Policy (or Feature-Policy) header is not set. This allows all browser features by default, which may pose security risks.",
            risk="low",
            status=resp.status_code,
            nikto_id="999111",
            references="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
        ))
    
    # Check for information disclosure in headers
    tests_run += 1
    server_header = resp.headers.get("Server", "")
    if server_header:
        findings.append(Finding(
            plugin=PLUGIN_NAME,
            url=url,
            message=f"Server header present: {server_header}.",
            risk="info",
            status=resp.status_code,
            nikto_id="999112",
            uri="/",
        ))
        
        # Check for outdated versions
        if any(x in server_header for x in ["Apache/2.2", "Apache/2.0", "IIS/6.0", "nginx/1.0"]):
            findings.append(Finding(
                plugin=PLUGIN_NAME,
                url=url,
                message=f"Server header reveals outdated software version: '{server_header}'. This may indicate unpatched vulnerabilities.",
                risk="medium",
                status=resp.status_code,
                nikto_id="999112a",
                references="OWASP-A6",
            ))
    
    # Check for BREACH attack vulnerability (Content-Encoding: deflate/gzip)
    tests_run += 1
    content_encoding = resp.headers.get("Content-Encoding", "").lower()
    if content_encoding and any(enc in content_encoding for enc in ["deflate", "gzip", "compress"]):
        findings.append(Finding(
            plugin=PLUGIN_NAME,
            url=url,
            message=f"The Content-Encoding header is set to \"{content_encoding}\" which may mean that the server is vulnerable to the BREACH attack.",
            risk="info",
            status=resp.status_code,
            nikto_id="999113",
            references="http://breachattack.com/",
            uri="/",
        ))
    
    # Don't print here - let nikto.py handle printing to avoid duplicates
    return findings, tests_run

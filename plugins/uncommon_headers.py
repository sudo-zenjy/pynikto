# plugins/uncommon_headers.py
from typing import List

from findings import Finding
from http_client import HttpClient
from targets import Target

PLUGIN_NAME = "uncommon_headers"


def run(target: Target, http: HttpClient) -> List[Finding]:
    """
    Detect uncommon or unusual HTTP headers (like original Nikto).
    Reports headers that are not standard but may be interesting.
    """
    findings: List[Finding] = []
    
    url = f"{target.base_url}/"
    
    # Get root page (follow redirects to final destination)
    resp = http.get(url, allow_redirects=True)
    if not resp:
        # Try without redirects as fallback
        resp = http.get(url, allow_redirects=False)
    if not resp:
        return findings
    
    # If we got a redirect, also check the final destination
    if resp.status_code in [301, 302, 303, 307, 308]:
        location = resp.headers.get("Location", "")
        if location and location.startswith("http"):
            # Fetch the redirect target
            redirect_resp = http.get(location, allow_redirects=True)
            if redirect_resp and redirect_resp.status_code == 200:
                # Check headers on both the redirect and final page
                # (some headers may only appear on one or the other)
                pass  # We'll check both below
    
    # Standard headers that should NOT be reported as uncommon
    standard_headers = {
        "date", "server", "content-type", "content-length", "connection",
        "cache-control", "expires", "pragma", "transfer-encoding",
        "content-encoding", "vary", "accept-ranges", "etag", "last-modified",
        "location", "set-cookie", "cookie", "host", "user-agent", "accept",
        "accept-encoding", "accept-language", "referer", "authorization",
        "www-authenticate", "proxy-authenticate", "proxy-authorization",
        "age", "retry-after", "warning", "via", "upgrade", "trailer",
        "te", "allow", "content-range", "if-match", "if-none-match",
        "if-modified-since", "if-unmodified-since", "if-range", "range",
        "max-forwards", "expect", "from", "content-location", "content-md5",
        "content-disposition", "mime-version", "link", "p3p", "refresh",
        # Common security headers
        "strict-transport-security", "x-frame-options", "x-content-type-options",
        "x-xss-protection", "content-security-policy", "referrer-policy",
        "permissions-policy", "feature-policy", "x-permitted-cross-domain-policies",
        "cross-origin-embedder-policy", "cross-origin-opener-policy",
        "cross-origin-resource-policy", "expect-ct", "nel", "report-to",
        # Common CDN/proxy headers
        "x-cache", "x-cache-hits", "x-served-by", "x-timer", "x-cdn",
        "x-amz-cf-id", "x-amz-cf-pop", "x-amz-request-id", "x-azure-ref",
        "cf-ray", "cf-cache-status", "x-fastly-request-id", "x-varnish",
        # Common application headers
        "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
        "x-runtime", "x-request-id", "x-correlation-id", "x-trace-id",
        # CORS headers
        "access-control-allow-origin", "access-control-allow-methods",
        "access-control-allow-headers", "access-control-expose-headers",
        "access-control-max-age", "access-control-allow-credentials",
        # Other common headers
        "alt-svc", "timing-allow-origin", "x-robots-tag", "x-ua-compatible",
    }
    
    # Check for uncommon headers
    for header_name, header_value in resp.headers.items():
        header_lower = header_name.lower()
        
        # Skip standard headers
        if header_lower in standard_headers:
            continue
        
        # Skip empty headers
        if not header_value or not header_value.strip():
            continue
        
        # Report uncommon header
        findings.append(Finding(
            plugin=PLUGIN_NAME,
            url=url,
            message=f"Uncommon header '{header_name}' found, with contents: {header_value}.",
            risk="info",
            status=resp.status_code,
            nikto_id="000530",
            uri="/",
        ))
    
    # Also check for retrieved via header (like Nikto reports)
    via_header = resp.headers.get("Via")
    if via_header:
        findings.append(Finding(
            plugin=PLUGIN_NAME,
            url=url,
            message=f"Retrieved via header: {via_header}.",
            risk="info",
            status=resp.status_code,
            nikto_id="000531",
            uri="/",
        ))
    
    # Check for alt-svc header (HTTP/3 advertising)
    alt_svc = resp.headers.get("Alt-Svc") or resp.headers.get("alt-svc")
    if alt_svc:
        # Parse endpoint from alt-svc header
        endpoint = "unknown"
        if "h3=" in alt_svc or "h2=" in alt_svc:
            try:
                # Extract endpoint (e.g., ':443')
                parts = alt_svc.split(";")
                for part in parts:
                    if ":" in part and not "=" in part:
                        endpoint = part.strip()
                        break
            except:
                pass
        
        protocol = "HTTP/3" if "h3" in alt_svc else "HTTP/2"
        findings.append(Finding(
            plugin=PLUGIN_NAME,
            url=url,
            message=f"An alt-svc header was found which is advertising {protocol}. The endpoint is: '{endpoint}'. Nikto cannot test {protocol} over QUIC.",
            risk="info",
            status=resp.status_code,
            nikto_id="000533",
            references="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/alt-svc",
            uri="/",
        ))
    
    # Check for access-control-allow-origin: * (overly permissive CORS)
    acao = resp.headers.get("Access-Control-Allow-Origin")
    if acao and acao.strip() == "*":
        findings.append(Finding(
            plugin=PLUGIN_NAME,
            url=url,
            message="Retrieved access-control-allow-origin header: *.",
            risk="info",
            status=resp.status_code,
            nikto_id="000532",
            uri="/",
        ))
    
    # Check common paths for CORS misconfigurations
    cors_paths = ["/api/", "/cart/", "/checkout/", "/admin/"]
    for path in cors_paths:
        test_url = f"{target.base_url}{path}"
        cors_resp = http.get(test_url, allow_redirects=False)
        if cors_resp and cors_resp.status_code in [200, 301, 302]:
            cors_acao = cors_resp.headers.get("Access-Control-Allow-Origin")
            if cors_acao and cors_acao.strip() == "*":
                findings.append(Finding(
                    plugin=PLUGIN_NAME,
                    url=test_url,
                    message="Retrieved access-control-allow-origin header: *.",
                    risk="info",
                    status=cors_resp.status_code,
                    nikto_id="000534",
                    uri=path,
                ))
    
    return findings


# plugins/anomaly_detection.py
"""
Anomaly detection plugin
Detects unusual patterns in server behavior
"""
from typing import List, Dict
import re
import hashlib

from findings import Finding
from http_client import HttpClient
from targets import Target

PLUGIN_NAME = "anomaly_detection"


def run(target: Target, http: HttpClient) -> List[Finding]:
    """
    Detect anomalies in server behavior using pattern analysis.
    """
    findings: List[Finding] = []
    
    # Test multiple paths to establish baseline
    test_paths = ["/", "/index.html", "/robots.txt", "/favicon.ico", "/sitemap.xml"]
    responses = {}
    
    for path in test_paths:
        url = f"{target.base_url}{path}"
        resp = http.get(url, allow_redirects=False)
        if resp:
            responses[path] = {
                'status': resp.status_code,
                'length': len(resp.content),
                'headers': dict(resp.headers),
                'hash': hashlib.md5(resp.content).hexdigest(),
                'response_time': resp.elapsed.total_seconds() if hasattr(resp, 'elapsed') else 0,
            }
    
    if len(responses) < 2:
        return findings  # Not enough data
    
    # Detect response time anomalies
    response_times = [r['response_time'] for r in responses.values() if r['response_time'] > 0]
    if response_times:
        avg_time = sum(response_times) / len(response_times)
        for path, data in responses.items():
            if data['response_time'] > avg_time * 3:  # 3x slower than average
                findings.append(Finding(
                    plugin=PLUGIN_NAME,
                    url=f"{target.base_url}{path}",
                    message=f"Unusually slow response time detected ({data['response_time']:.2f}s vs avg {avg_time:.2f}s). May indicate server-side processing or WAF inspection.",
                    risk="info",
                    status=data['status'],
                    nikto_id="900001",
                    uri=path,
                ))
    
    # Detect header inconsistencies
    all_headers = set()
    for data in responses.values():
        all_headers.update(data['headers'].keys())
    
    # Check for headers that appear inconsistently
    for header in all_headers:
        header_lower = header.lower()
        if header_lower in ['date', 'content-length', 'etag', 'last-modified']:
            continue  # Skip dynamic headers
        
        present_count = sum(1 for data in responses.values() if header in data['headers'])
        if 0 < present_count < len(responses):
            # Header appears on some paths but not others - anomaly
            findings.append(Finding(
                plugin=PLUGIN_NAME,
                url=f"{target.base_url}/",
                message=f"Inconsistent header '{header}' detected (present on {present_count}/{len(responses)} paths). May indicate load balancer or caching inconsistency.",
                risk="info",
                status=200,
                nikto_id="900002",
                uri="/",
            ))
    
    # Detect length-based anomalies (catch-all detection)
    lengths = [r['length'] for r in responses.values()]
    if len(set(lengths)) == 1 and len(lengths) >= 3:
        # All responses same length - likely catch-all
        findings.append(Finding(
            plugin=PLUGIN_NAME,
            url=f"{target.base_url}/",
            message=f"All tested paths return identical content length ({lengths[0]} bytes). Server may be using catch-all routing (SPA or custom 404).",
            risk="info",
            status=200,
            nikto_id="900003",
            uri="/",
        ))
    
    # Detect server fingerprint changes
    servers = [r['headers'].get('Server', '') for r in responses.values() if r['headers'].get('Server')]
    if len(set(servers)) > 1:
        findings.append(Finding(
            plugin=PLUGIN_NAME,
            url=f"{target.base_url}/",
            message=f"Server header changes across requests: {', '.join(set(servers))}. May indicate load balancer or proxy inconsistency.",
            risk="info",
            status=200,
            nikto_id="900004",
            uri="/",
        ))
    
    # Detect potential honeypot behavior
    status_codes = [r['status'] for r in responses.values()]
    if all(s == 200 for s in status_codes) and len(status_codes) >= 4:
        # Everything returns 200 - suspicious
        hashes = [r['hash'] for r in responses.values()]
        if len(set(hashes)) == 1:
            findings.append(Finding(
                plugin=PLUGIN_NAME,
                url=f"{target.base_url}/",
                message="ALERT: All paths return 200 OK with identical content. This may indicate a honeypot or monitoring system.",
                risk="medium",
                status=200,
                nikto_id="900005",
                uri="/",
            ))
    
    return findings


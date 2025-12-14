from typing import List, Set, Dict, Optional
import re
import urllib.parse
from urllib.parse import urljoin, urlparse
import threading
from collections import deque

from targets import Target
from http_client import HttpClient
from findings import Finding

PLUGIN_NAME = "crawler"

# Thread-safe URL tracking
_discovered_urls: Set[str] = set()
_discovered_lock = threading.Lock()
_crawled_urls: Set[str] = set()
_crawled_lock = threading.Lock()
_robots_disallowed: Set[str] = set()
_robots_lock = threading.Lock()


def _parse_robots_txt(target: Target, http: HttpClient) -> Set[str]:
    """
    Parse robots.txt and return set of disallowed paths.
    Respects robots.txt rules for crawling.
    """
    disallowed = set()
    
    try:
        robots_url = f"{target.base_url}/robots.txt"
        resp = http.get(robots_url, allow_redirects=True)
        
        if not resp or resp.status_code != 200:
            return disallowed
        
        content = resp.text
        user_agent = "*"  # Default: match all user agents
        
        for line in content.split('\n'):
            line = line.strip()
            
            # Skip comments
            if line.startswith('#'):
                continue
            
            # Parse User-agent
            if line.lower().startswith('user-agent:'):
                user_agent = line.split(':', 1)[1].strip()
                continue
            
            # Parse Disallow (only for * or our user agent)
            if line.lower().startswith('disallow:') and (user_agent == "*" or "nikto" in user_agent.lower() or "pynikto" in user_agent.lower()):
                path = line.split(':', 1)[1].strip()
                if path:
                    # Normalize path
                    if not path.startswith('/'):
                        path = '/' + path
                    disallowed.add(path)
                    # Also add parent directories
                    parts = path.rstrip('/').split('/')
                    for i in range(1, len(parts)):
                        parent = '/'.join(parts[:i+1])
                        if parent:
                            disallowed.add(parent + '/')
        
        with _robots_lock:
            _robots_disallowed.update(disallowed)
        
    except Exception:
        pass
    
    return disallowed


def _is_allowed_by_robots(url: str, target: Target) -> bool:
    """
    Check if URL is allowed by robots.txt rules.
    """
    parsed = urlparse(url)
    path = parsed.path
    
    with _robots_lock:
        for disallowed in _robots_disallowed:
            # Check if path starts with disallowed path
            if path.startswith(disallowed):
                return False
    
    return True


def _extract_links(html_content: str, base_url: str, target: Target) -> Set[str]:
    """
    Extract all links from HTML content.
    Returns set of absolute URLs within the target domain.
    """
    links = set()
    target_domain = urlparse(target.base_url).netloc
    
    # Improved regex patterns - handle more cases
    
    # 1. Extract href from <a> tags (handle both quoted and unquoted)
    # Pattern 1: href="..." or href='...'
    href_quoted = r'<a[^>]+href\s*=\s*["\']([^"\']+)["\']'
    for match in re.finditer(href_quoted, html_content, re.IGNORECASE):
        href = match.group(1).strip()
        if href:
            links.update(_process_link(href, base_url, target_domain))
    
    # Pattern 2: href=... (unquoted, but be careful)
    href_unquoted = r'<a[^>]+href\s*=\s*([^\s>]+)'
    for match in re.finditer(href_unquoted, html_content, re.IGNORECASE):
        href = match.group(1).strip()
        # Skip if it looks like it has quotes (already handled)
        if href and not (href.startswith('"') or href.startswith("'")):
            links.update(_process_link(href, base_url, target_domain))
    
    # 2. Extract from src attributes (img, script, link, iframe, source, embed)
    src_tags = r'<(?:img|script|link|iframe|source|embed|video|audio)[^>]+(?:src|href)\s*=\s*["\']([^"\']+)["\']'
    for match in re.finditer(src_tags, html_content, re.IGNORECASE):
        src = match.group(1).strip()
        if src:
            links.update(_process_link(src, base_url, target_domain))
    
    # 3. Extract form actions
    form_actions = r'<form[^>]+action\s*=\s*["\']([^"\']+)["\']'
    for match in re.finditer(form_actions, html_content, re.IGNORECASE):
        action = match.group(1).strip()
        if action:
            links.update(_process_link(action, base_url, target_domain))
    
    # 4. Extract from data attributes (data-url, data-href, etc.)
    data_attrs = r'data-(?:url|href|link|src)\s*=\s*["\']([^"\']+)["\']'
    for match in re.finditer(data_attrs, html_content, re.IGNORECASE):
        data_url = match.group(1).strip()
        if data_url:
            links.update(_process_link(data_url, base_url, target_domain))
    
    # 5. Extract from JavaScript (basic - looks for URLs in strings)
    # This is a simple approach - could be improved
    js_urls = r'(?:url|href|src|action)\s*[:=]\s*["\']([^"\']+\.(?:html?|php|asp|jsp|aspx))["\']'
    for match in re.finditer(js_urls, html_content, re.IGNORECASE):
        js_url = match.group(1).strip()
        if js_url and not js_url.startswith('javascript:'):
            links.update(_process_link(js_url, base_url, target_domain))
    
    return links


def _process_link(href: str, base_url: str, target_domain: str) -> Set[str]:
    """
    Process a single link and return set of valid absolute URLs.
    """
    links = set()
    
    # Skip javascript:, mailto:, tel:, etc.
    if ':' in href and not href.startswith('http') and not href.startswith('/') and not href.startswith('./'):
        return links
    
    # Skip anchors only (#section)
    if href.startswith('#'):
        return links
    
    # Skip data URIs
    if href.startswith('data:'):
        return links
    
    try:
        # Convert to absolute URL
        absolute_url = urljoin(base_url, href)
        parsed = urlparse(absolute_url)
        
        # Only include links from same domain
        if parsed.netloc == target_domain or not parsed.netloc:
            # Remove fragment
            clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                clean_url += f"?{parsed.query}"
            
            # Normalize - but keep trailing slash for directories
            # Don't strip trailing slash as it might be significant
            
            # Ensure we have a valid URL
            if clean_url and clean_url.startswith('http'):
                links.add(clean_url)
    except Exception:
        pass
    
    return links


def _normalize_url(url: str) -> str:
    """
    Normalize URL for duplicate detection.
    """
    parsed = urlparse(url)
    
    # Remove default ports
    netloc = parsed.netloc
    if ':80' in netloc and parsed.scheme == 'http':
        netloc = netloc.replace(':80', '')
    if ':443' in netloc and parsed.scheme == 'https':
        netloc = netloc.replace(':443', '')
    
    # Normalize path
    path = parsed.path.rstrip('/') or '/'
    
    # Sort query parameters for consistency
    query = parsed.query
    if query:
        params = sorted(query.split('&'))
        query = '&'.join(params)
    
    normalized = f"{parsed.scheme}://{netloc}{path}"
    if query:
        normalized += f"?{query}"
    
    return normalized


def _crawl_recursive(
    target: Target,
    http: HttpClient,
    start_url: str,
    max_depth: int = 3,
    max_urls: int = 500,
    current_depth: int = 0,
    findings: List[Finding] = None
) -> List[Finding]:
    """
    Recursively crawl website starting from start_url.
    Respects depth limits, robots.txt, and handles duplicates.
    """
    if findings is None:
        findings = []
    
    # Check depth limit
    if current_depth >= max_depth:
        return findings
    
    # Check URL limit
    with _crawled_lock:
        if len(_crawled_urls) >= max_urls:
            return findings
    
    # Normalize and check if already crawled
    normalized = _normalize_url(start_url)
    with _crawled_lock:
        if normalized in _crawled_urls:
            return findings
        _crawled_urls.add(normalized)
    
    # Check robots.txt
    if not _is_allowed_by_robots(start_url, target):
        return findings
    
    # Fetch page
    try:
        resp = http.get(start_url, allow_redirects=True)
        if not resp or resp.status_code != 200:
            return findings
        
        # Check content type
        content_type = resp.headers.get('Content-Type', '').lower()
        if 'text/html' not in content_type:
            return findings
        
        # Extract links
        links = _extract_links(resp.text, start_url, target)
        
        # Add ALL discovered URLs (before verification)
        with _discovered_lock:
            for link in links:
                normalized_link = _normalize_url(link)
                if normalized_link not in _discovered_urls:
                    _discovered_urls.add(normalized_link)
        
        # Verify links exist (but don't filter - we want to show all)
        verified_links = set()
        for link in links:
            # Quick HEAD check to verify link exists
            try:
                check_resp = http.head(link, allow_redirects=True)
                if check_resp and check_resp.status_code in [200, 301, 302, 303, 307, 308]:
                    verified_links.add(link)
            except Exception:
                # If HEAD fails, try GET
                try:
                    check_resp = http.get(link, allow_redirects=False)
                    if check_resp and check_resp.status_code in [200, 301, 302, 303, 307, 308]:
                        verified_links.add(link)
                except Exception:
                    pass  # Keep link in discovered list even if verification fails
        
        # Recursively crawl verified links only (but all discovered links are shown)
        for link in verified_links:
            normalized_link = _normalize_url(link)
            
            # Skip if already crawled
            with _crawled_lock:
                if normalized_link in _crawled_urls:
                    continue
            
            # Recursively crawl
            _crawl_recursive(
                target,
                http,
                link,
                max_depth,
                max_urls,
                current_depth + 1,
                findings
            )
            
            # Check URL limit again
            with _crawled_lock:
                if len(_crawled_urls) >= max_urls:
                    return findings
        
    except Exception:
        pass
    
    return findings


def _test_discovered_urls(target: Target, http: HttpClient) -> List[Finding]:
    """
    Test discovered URLs for vulnerabilities.
    Integrates with existing vulnerability testing.
    """
    findings = []
    
    with _discovered_lock:
        urls_to_test = list(_discovered_urls)
    
    # Test each discovered URL
    for url in urls_to_test:
        try:
            resp = http.get(url, allow_redirects=True)
            if not resp:
                continue
            
            # Check for interesting findings
            parsed = urlparse(url)
            path = parsed.path
            
            # Check for sensitive file patterns
            sensitive_patterns = [
                (r'\.(bak|backup|old|orig|tmp|log|sql|db)$', 'Backup or sensitive file extension detected'),
                (r'/(admin|administrator|manage|control|config)', 'Administrative interface detected'),
                (r'/(\.git|\.svn|\.env|\.htaccess)', 'Version control or configuration file exposed'),
                (r'/(api|rest|graphql)', 'API endpoint detected'),
            ]
            
            for pattern, message in sensitive_patterns:
                if re.search(pattern, path, re.IGNORECASE):
                    findings.append(Finding(
                        plugin=PLUGIN_NAME,
                        url=url,
                        message=f"Crawled URL '{path}' - {message}. This path was discovered through link following and may not be intended for public access.",
                        risk="medium",
                        status=resp.status_code,
                        nikto_id="000900",
                        references="",
                    ))
                    break
            
            # Check for directory listing
            if resp.status_code == 200 and '<title>Index of' in resp.text or '<title>Directory Listing' in resp.text:
                findings.append(Finding(
                    plugin=PLUGIN_NAME,
                    url=url,
                    message=f"Crawled URL '{path}' - Directory listing enabled. This exposes file structure and may reveal sensitive files.",
                    risk="medium",
                    status=resp.status_code,
                    nikto_id="000901",
                    references="",
                ))
        
        except Exception:
            continue
    
    return findings


def run(
    target: Target,
    http: HttpClient,
    max_depth: int = 3,
    max_urls: int = 500,
    respect_robots: bool = True,
) -> tuple[List[Finding], int]:
    """
    Main crawling function.
    
    Args:
        target: Target to crawl
        http: HTTP client
        max_depth: Maximum crawl depth (default: 3)
        max_urls: Maximum URLs to crawl (default: 500)
        respect_robots: Whether to respect robots.txt (default: True)
    
    Returns:
        Tuple of (findings, urls_crawled)
    """
    findings: List[Finding] = []
    
    # Reset globals
    global _discovered_urls, _crawled_urls, _robots_disallowed
    with _discovered_lock:
        _discovered_urls.clear()
    with _crawled_lock:
        _crawled_urls.clear()
    with _robots_lock:
        _robots_disallowed.clear()
    
    # Parse robots.txt if enabled
    if respect_robots:
        print(f"[i] Parsing robots.txt...")
        disallowed = _parse_robots_txt(target, http)
        if disallowed:
            print(f"[i] robots.txt: {len(disallowed)} disallowed path(s) found")
            # Print each disallowed path
            for path in sorted(disallowed):
                print(f"    - {path}")
        else:
            print(f"[i] robots.txt: No restrictions found or file not accessible")
    
    # Start crawling from root
    start_url = f"{target.base_url}/"
    print(f"[i] Starting crawl from {start_url} (max depth: {max_depth}, max URLs: {max_urls})")
    
    # Recursive crawl
    _crawl_recursive(target, http, start_url, max_depth, max_urls, 0, findings)
    
    # Get count of crawled URLs
    with _crawled_lock:
        urls_crawled = len(_crawled_urls)
    
    # Get discovered URLs list
    with _discovered_lock:
        discovered_list = sorted(list(_discovered_urls))
    
    print(f"[i] Crawl completed: {urls_crawled} URL(s) crawled, {len(discovered_list)} URL(s) discovered")
    
    # Print ALL discovered URLs with status (industry-level output)
    if discovered_list:
        print(f"\n[i] Discovered URLs ({len(discovered_list)} total):")
        
        # Collect URL data for table
        url_data = []
        for url in discovered_list:
            # Check status for each URL
            try:
                check_resp = http.head(url, allow_redirects=True)
                if check_resp:
                    status = check_resp.status_code
                    if status == 200:
                        status_msg = "OK"
                        indicator = "+"
                    elif status in [301, 302, 303, 307, 308]:
                        location = check_resp.headers.get('Location', '')
                        status_msg = f"Redirect → {location}"
                        indicator = "→"
                    elif status == 404:
                        status_msg = "Not Found"
                        indicator = "-"
                    elif status == 403:
                        status_msg = "Forbidden"
                        indicator = "×"
                    else:
                        status_msg = f"HTTP {status}"
                        indicator = "?"
                    url_data.append((indicator, url, status, status_msg))
                else:
                    url_data.append(("-", url, "N/A", "No response"))
            except Exception as e:
                url_data.append(("-", url, "Error", str(e)[:50]))
        
        # Print table
        if url_data:
            # Calculate column widths
            max_url_len = max(len(url) for _, url, _, _ in url_data)
            max_status_len = max(len(str(status)) for _, _, status, _ in url_data)
            max_msg_len = max(len(msg) for _, _, _, msg in url_data)
            
            # Set minimum widths
            url_width = max(max_url_len, 50)
            status_width = max(max_status_len, 8)
            msg_width = max(max_msg_len, 20)
            
            # Print header
            header = f"  {'Status':<8} {'URL':<{url_width}} {'Code':<{status_width}} {'Message':<{msg_width}}"
            print(header)
            print("  " + "-" * (8 + url_width + status_width + msg_width + 6))
            
            # Print rows
            for indicator, url, status, msg in url_data:
                status_col = f"[{indicator}]"
                print(f"  {status_col:<8} {url:<{url_width}} {str(status):<{status_width}} {msg:<{msg_width}}")
    
    # Test discovered URLs for vulnerabilities
    if _discovered_urls:
        print(f"\n[i] Testing {len(_discovered_urls)} discovered URLs for vulnerabilities...")
        test_findings = _test_discovered_urls(target, http)
        findings.extend(test_findings)
    
    return findings, urls_crawled

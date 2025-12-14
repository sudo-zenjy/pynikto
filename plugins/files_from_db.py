from typing import List, Dict
import json
import os
import concurrent.futures
import threading
import re
import hashlib

from targets import Target
from http_client import HttpClient
from config import load_config
from variables import expand_variables
from findings import Finding

PLUGIN_NAME = "files_from_db"

# Thread-safe tracking
_printed_findings = set()
_printed_lock = threading.Lock()
_progress_counter = {"checked": 0, "total": 0}
_progress_lock = threading.Lock()
_error_count = {"consecutive": 0, "total": 0}  # Track consecutive errors (for logging only)
_error_lock = threading.Lock()
_success_count = {"total": 0}  # Track successful requests (got a response)
_success_lock = threading.Lock()


def _load_db() -> List[Dict]:
    """Load the main Nikto database (db_tests.json)"""
    cfg = load_config()
    db_path = os.path.join(cfg["dbdir"], "db_tests.json")
    try:
        with open(db_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[-] {PLUGIN_NAME}: failed to load DB {db_path}: {exc}")
        return []


DB_ENTRIES = _load_db()


def _detect_tech(target: Target, http: HttpClient) -> set[str]:
    """
    Very simple tech fingerprinting.
    Returns tags like {"wordpress", "joomla"} based on root page and a couple of probes.
    """
    tags: set[str] = set()
    base = target.base_url

    # 1) Root GET once
    resp = http.get(f"{base}/", allow_redirects=True)
    if resp and resp.text:
        body = resp.text.lower()
        if "wp-content" in body or "wordpress" in body:
            tags.add("wordpress")
        if "joomla!" in body or "content=\"joomla" in body:
            tags.add("joomla")

    # 2) Light extra probes if not already detected
    if "wordpress" not in tags:
        r = http.head(f"{base}/wp-login.php", allow_redirects=False)
        # Only add if we get a definitive response (not 404)
        if r and r.status_code in (200, 302, 403):
            tags.add("wordpress")

    if "joomla" not in tags:
        r = http.head(f"{base}/administrator/", allow_redirects=False)
        # Only add if we get a definitive response (not 404)
        if r and r.status_code in (200, 302, 403):
            tags.add("joomla")

    return tags


def _filter_by_tuning(entry: Dict, tuning_set: set[str]) -> bool:
    """
    Returns True if entry should be included based on tuning filter.
    If tuning_set is empty, include everything.
    If tuning_set contains 'x', exclude entries matching other codes in set.
    """
    if not tuning_set:
        return True

    entry_tuning = entry.get("tuning", "")
    if not entry_tuning:
        # If entry has no tuning, include it by default
        return True

    if "x" in tuning_set:
        # Reverse mode: exclude if entry tuning matches any in set (except 'x')
        exclude_set = tuning_set - {"x"}
        return not any(t in entry_tuning for t in exclude_set)
    else:
        # Normal mode: include if entry tuning matches any in set
        return any(t in entry_tuning for t in tuning_set)


def _check_content_match(resp_text: str, entry: Dict) -> bool:
    """Check if response content matches the entry's match criteria"""
    match_1 = entry.get("match_1", "")
    match_1_or = entry.get("match_1_or", "")
    match_1_and = entry.get("match_1_and", "")
    fail_1 = entry.get("fail_1", "")
    fail_2 = entry.get("fail_2", "")
    
    # Check negative matches first (fail conditions)
    if fail_1 and fail_1 in resp_text:
        return False
    if fail_2 and fail_2 in resp_text:
        return False
    
    # Check positive matches
    if match_1:
        # Try regex first, fallback to simple string search
        try:
            if re.search(match_1, resp_text, re.IGNORECASE):
                match_found = True
            else:
                match_found = False
        except re.error:
            # Invalid regex, use simple string search
            match_found = match_1.lower() in resp_text.lower()
        
        if not match_found:
            return False
    
    # match_1_or: at least one must match
    if match_1_or:
        or_patterns = [p.strip() for p in match_1_or.split("|")]
        or_match = False
        for pattern in or_patterns:
            try:
                if re.search(pattern, resp_text, re.IGNORECASE):
                    or_match = True
                    break
            except re.error:
                if pattern.lower() in resp_text.lower():
                    or_match = True
                    break
        if not or_match:
            return False
    
    # match_1_and: all must match
    if match_1_and:
        and_patterns = [p.strip() for p in match_1_and.split("&")]
        for pattern in and_patterns:
            try:
                if not re.search(pattern, resp_text, re.IGNORECASE):
                    return False
            except re.error:
                if pattern.lower() not in resp_text.lower():
                    return False
    
    return True


def _check_404_match(resp, notfound_sigs: Dict) -> bool:
    """Check if response matches 404 signature (false positive filter)"""
    if not notfound_sigs or not notfound_sigs.get('enabled'):
        return False
    
    content_hash = hashlib.md5(resp.text.encode()).hexdigest()
    content_len = len(resp.text)
    
    for sig in notfound_sigs.get('signatures', []):
        # Match by hash (exact) or similar length + same status
        if sig.get('hash') == content_hash:
            return True
        
        # Also check if length is very similar (within 100 bytes) and same status
        if sig.get('status') == resp.status_code and abs(sig.get('length', 0) - content_len) < 100:
            return True
    
    return False


def _enhance_message(entry: Dict, expanded_path: str, resp) -> str:
    """
    Enhance database messages with technical details and context.
    Replaces casual wording with professional, detailed descriptions.
    """
    original_message = entry.get("message", "File found")
    path_lower = expanded_path.lower()
    
    # If message already has good technical details, use it
    if any(keyword in original_message.lower() for keyword in [
        "vulnerability", "allows", "may allow", "contains", "exposes", 
        "reveals", "detected", "running", "enabled", "configured"
    ]):
        return original_message
    
    # Generate detailed messages based on path patterns and context
    detailed_message = original_message
    
    # CGI scripts
    if "/cgi" in path_lower or path_lower.endswith(".cgi"):
        if "webmap" in path_lower:
            detailed_message = f"CGI script '{expanded_path}' found: nmap front-end interface detected. This tool may allow network scanning capabilities and could expose internal network information if misconfigured."
        elif "cart32" in path_lower:
            detailed_message = f"CGI script '{expanded_path}' found: Cart32 e-commerce application detected. This may expose customer data or allow unauthorized access if not properly secured."
        elif "download" in path_lower:
            detailed_message = f"CGI script '{expanded_path}' found: File download interface detected. This may allow unauthorized file access if access controls are not properly configured."
        elif "classified" in path_lower:
            detailed_message = f"CGI script '{expanded_path}' found: Classified ads system detected. Known vulnerabilities exist (see Phrack 55). This may allow remote code execution or unauthorized access."
        elif "could be fun" in original_message.lower():
            detailed_message = f"CGI script '{expanded_path}' found: Interactive tool detected. This may provide functionality that could be exploited if not properly secured."
        else:
            detailed_message = f"CGI script '{expanded_path}' found: {original_message}. CGI scripts may contain vulnerabilities and should be reviewed for proper input validation and access controls."
    
    # Directory listings
    elif path_lower.endswith("/") or path_lower in ["/c/", "/home/", "/homepage/", "/job/", "/login/"]:
        if "might be interesting" in original_message.lower():
            detailed_message = f"Directory '{expanded_path}' accessible: Directory listing or directory traversal may be possible. This could expose file structure and sensitive files if directory browsing is enabled."
        else:
            detailed_message = f"Directory '{expanded_path}' accessible: {original_message}. Verify that directory listing is disabled and proper access controls are in place."
    
    # Configuration files
    elif any(ext in path_lower for ext in [".conf", ".config", ".ini", ".cfg"]):
        detailed_message = f"Configuration file '{expanded_path}' accessible: Configuration files may contain sensitive information such as database credentials, API keys, or system settings. These should not be publicly accessible."
    
    # Backup files
    elif any(ext in path_lower for ext in [".bak", ".backup", ".old", ".orig", ".tmp"]):
        detailed_message = f"Backup file '{expanded_path}' found: Backup files may contain source code, configuration data, or sensitive information. These should be removed from production environments."
    
    # Database files
    elif any(ext in path_lower for ext in [".db", ".sql", ".sqlite", ".mdb"]):
        detailed_message = f"Database file '{expanded_path}' accessible: Database files should never be publicly accessible as they may contain sensitive user data, credentials, or application information."
    
    # Log files
    elif any(ext in path_lower for ext in [".log", ".txt"]):
        if "import" in path_lower or "order" in path_lower:
            detailed_message = f"Log/Data file '{expanded_path}' accessible: This file may contain sensitive transaction data, customer information, or system logs. Public access should be restricted."
        else:
            detailed_message = f"Log file '{expanded_path}' accessible: Log files may contain sensitive information about system activity, user actions, or errors. These should not be publicly accessible."
    
    # Admin/management interfaces
    elif any(term in path_lower for term in ["admin", "administrator", "manage", "control"]):
        detailed_message = f"Administrative interface '{expanded_path}' accessible: Administrative interfaces should be protected with strong authentication and access controls. Verify that proper security measures are in place."
    
    # Default/example files
    elif any(term in path_lower for term in ["example", "sample", "test", "demo", "default"]):
        detailed_message = f"Default/Example file '{expanded_path}' found: Default or example files should be removed from production environments as they may reveal system information or contain vulnerabilities."
    
    # PHP files
    elif path_lower.endswith(".php"):
        detailed_message = f"PHP script '{expanded_path}' accessible: {original_message}. Verify that this script is intended for public access and does not expose sensitive functionality."
    
    # Generic enhancement for "might be interesting"
    elif "might be interesting" in original_message.lower():
        detailed_message = f"Path '{expanded_path}' accessible: This path has been observed in web server logs and may indicate exposed functionality, misconfiguration, or potential information disclosure. Review access controls and intended functionality."
    
    # Generic enhancement for "could be fun"
    elif "could be fun" in original_message.lower():
        detailed_message = f"Tool/Interface '{expanded_path}' detected: Interactive tool or interface found. Verify that this functionality is intended for public access and is properly secured against unauthorized use."
    
    # Add risk context if available
    risk = entry.get("risk", "info")
    if risk == "high" and "vulnerability" not in detailed_message.lower():
        detailed_message += " HIGH RISK: This finding indicates a potential security vulnerability that should be addressed immediately."
    elif risk == "medium":
        detailed_message += " MEDIUM RISK: This finding should be reviewed and secured if not intended for public access."
    
    # Add references if available
    references = entry.get("references", "")
    if references and "http" in references.lower():
        detailed_message += f" Reference: {references}"
    
    return detailed_message


def _check_single_path(entry: Dict, expanded_path: str, target: Target, http: HttpClient, detected: set[str], notfound_sigs: Dict = None) -> Finding | None:
    """Check a single path and return finding if match, None otherwise."""
    # No stop flag - continue scanning everything
    
    # Tech-based filtering (basic - can be enhanced)
    if expanded_path.startswith("/wp-") or expanded_path.startswith("/wp-admin") or expanded_path.startswith("/wp-content"):
        if "wordpress" not in detected:
            with _progress_lock:
                _progress_counter["checked"] += 1
            return None

    if expanded_path.startswith("/administrator"):
        if "joomla" not in detected:
            with _progress_lock:
                _progress_counter["checked"] += 1
            return None

    statuses = entry.get("match_status", [200])
    method = entry.get("method", "GET")
    
    url = f"{target.base_url}{expanded_path}"
    
    # Make request with appropriate method
    if method == "POST":
        data = entry.get("data", "")
        headers = {}
        if entry.get("headers"):
            # Parse headers if provided
            for h in entry["headers"].split("\r\n"):
                if ":" in h:
                    k, v = h.split(":", 1)
                    headers[k.strip()] = v.strip()
        resp = http.request("POST", url, allow_redirects=True)
    else:
        resp = http.request(method, url, allow_redirects=True)
    
    # Continue scanning - no stop conditions
    
    if not resp:
        # Track consecutive errors (like real Nikto)
        with _error_lock:
            _error_count["consecutive"] += 1
            _error_count["total"] += 1
        # Update progress even on failure
        with _progress_lock:
            _progress_counter["checked"] += 1
        return None
    
    # Success! We got a response (even if it doesn't match)
    with _success_lock:
        _success_count["total"] += 1
    with _error_lock:
        if _error_count["consecutive"] > 0:
            _error_count["consecutive"] = 0  # Reset on success

    # *** Check if this matches 404 signature (false positive filter) ***
    if _check_404_match(resp, notfound_sigs):
        with _progress_lock:
            _progress_counter["checked"] += 1
        return None

    if resp.status_code not in statuses:
        with _progress_lock:
            _progress_counter["checked"] += 1
        return None

    # Check content matching
    if not _check_content_match(resp.text, entry):
        with _progress_lock:
            _progress_counter["checked"] += 1
        return None

    # Check server header matching if specified
    server_match = entry.get("server", "")
    if server_match:
        server_header = resp.headers.get("Server", "")
        if server_header:
            try:
                if not re.search(server_match, server_header, re.IGNORECASE):
                    with _progress_lock:
                        _progress_counter["checked"] += 1
                    return None
            except re.error:
                if server_match.lower() not in server_header.lower():
                    with _progress_lock:
                        _progress_counter["checked"] += 1
                    return None

    # Ensure risk defaults to "info" if missing or empty
    risk = entry.get("risk", "info")
    if not risk or risk.strip() == "":
        risk = "info"

    # Enhance message with technical details
    enhanced_message = _enhance_message(entry, expanded_path, resp)

    finding = Finding(
        plugin=PLUGIN_NAME,
        url=url,
        message=enhanced_message,  # Use enhanced message
        risk=risk,
        status=resp.status_code,
        nikto_id=entry.get("test_id"),
        references=entry.get("references", ""),
        method=method,
        uri=expanded_path,
    )

    # Update progress
    with _progress_lock:
        _progress_counter["checked"] += 1
        checked = _progress_counter["checked"]
        total = _progress_counter["total"]
        if checked % 50 == 0 or checked == total:  # Print every 50 or on completion
            print(f"[i] Progress: {checked}/{total} paths checked", end="\r")

    # Normalize URL for deduplication (remove trailing slashes, lowercase, etc.)
    normalized_url = url.rstrip('/').lower()
    if not normalized_url.endswith(target.base_url.lower().rstrip('/')):
        # Ensure we have the full URL
        if not normalized_url.startswith('http'):
            normalized_url = url.lower()
    
    # Deduplicate and print (thread-safe)
    finding_key = normalized_url  # Use normalized URL
    
    with _printed_lock:
        # Skip if we've already printed this exact URL
        if finding_key in _printed_findings:
            return finding  # Still return it for the findings list, just don't print again
        
        _printed_findings.add(finding_key)
        # Use Nikto-style output
        print(finding.to_nikto_format(target.host))

    return finding


def run(target: Target, http: HttpClient, tuning_set: set[str] = None, max_workers: int = 50, notfound_sigs: Dict = None, legacy_mode: bool = False, cgi_all: bool = False) -> tuple[List[Finding], int]:
    if tuning_set is None:
        tuning_set = set()

    # Reset globals for each new target
    global _printed_findings, _progress_counter, _error_count, _success_count
    with _printed_lock:
        _printed_findings.clear()
    with _progress_lock:
        _progress_counter = {"checked": 0, "total": 0}
    with _error_lock:
        _error_count = {"consecutive": 0, "total": 0}
    with _success_lock:
        _success_count = {"total": 0}  # Reset success counter

    findings: List[Finding] = []
    detected = _detect_tech(target, http)
    if detected:
        print(f"[i] Detected technologies: {', '.join(detected)}")

    # Collect and filter paths to check (with intelligent filtering like real Nikto)
    paths_to_check = []
    skipped_tech = 0
    skipped_cgi = 0
    
    # Detect if server has CGI directories (quick check)
    # Force CGI scanning if -C all or --legacy-mode is enabled
    has_cgi = cgi_all or legacy_mode
    if not has_cgi:
        cgi_dirs = ["/cgi-bin/", "/scripts/", "/cgi-mod/", "/cgi-sys/"]
        for cgi_dir in cgi_dirs:
            resp = http.head(f"{target.base_url}{cgi_dir}", allow_redirects=False)
            if resp and resp.status_code in [200, 301, 302, 403]:
                has_cgi = True
                break
    
    for entry in DB_ENTRIES:
        if not _filter_by_tuning(entry, tuning_set):
            continue

        rel_path = entry.get("path")
        if not rel_path:
            continue

        # Skip tech-specific paths if tech not detected (aggressive filtering)
        # But always check common paths in legacy mode
        uri = entry.get("uri", rel_path)
        
        # Always check common test paths (phpinfo.php, /test/, /admin/, etc.)
        # These are critical security paths that should always be tested
        common_paths = [
            "/phpinfo.php", "/test.php", "/test/", "/admin/", "/administrator/",
            "/cgi-bin/phpinfo.php", "/info.php", "/phpinfo", "/testphp.php"
        ]
        is_common_path = any(
            uri.endswith(cp) or uri == cp or cp in uri or 
            uri.endswith(cp.rstrip('/')) or uri == cp.rstrip('/')
            for cp in common_paths
        )
        
        # In legacy mode, skip filtering for common paths
        if not legacy_mode:
            # WordPress paths
            if any(x in uri for x in ["/wp-", "/wordpress", "/wp-content", "/wp-admin", "/wp-includes"]) and "wordpress" not in detected:
                skipped_tech += 1
                continue
            
            # Joomla paths
            if any(x in uri for x in ["/administrator", "/joomla", "/components/com_"]) and "joomla" not in detected:
                skipped_tech += 1
                continue
            
            # Drupal paths
            if any(x in uri for x in ["/drupal", "/sites/default", "/modules/"]) and "drupal" not in detected:
                skipped_tech += 1
                continue
            
            # CGI paths (skip if no CGI detected, unless common path)
            if not has_cgi and not is_common_path and any(x in uri for x in ["/cgi-bin/", "/cgi-mod/", "/cgi-sys/", "/scripts/"]):
                skipped_cgi += 1
                continue
            
            # Skip very specific tech paths (but not common paths)
            if not is_common_path and any(x in uri for x in ["/phpmyadmin", "/phpMyAdmin"]) and "php" not in detected:
                skipped_tech += 1
                continue
        else:
            # Legacy mode: only skip CGI if explicitly disabled
            if not has_cgi and not is_common_path and any(x in uri for x in ["/cgi-bin/", "/cgi-mod/", "/cgi-sys/", "/scripts/"]):
                skipped_cgi += 1
                continue

        expanded_paths = expand_variables(rel_path, target.host, target.host)
        for expanded_path in expanded_paths:
            paths_to_check.append((entry, expanded_path))
    
    # Add explicit common paths if not already in database
    # These are critical test paths that should always be checked
    explicit_common_paths = [
        {"test_id": "COMMON001", "path": "/phpinfo.php", "uri": "/phpinfo.php", "message": "phpinfo.php may reveal system information", "risk": "high", "match_status": [200], "tuning": "3", "method": "GET"},
        {"test_id": "COMMON002", "path": "/test/", "uri": "/test/", "message": "Test directory may be accessible", "risk": "medium", "match_status": [200, 301, 302, 403], "tuning": "2", "method": "GET"},
        {"test_id": "COMMON003", "path": "/admin/", "uri": "/admin/", "message": "Admin directory may be accessible", "risk": "medium", "match_status": [200, 301, 302, 403], "tuning": "2", "method": "GET"},
        {"test_id": "COMMON004", "path": "/test.php", "uri": "/test.php", "message": "Test file may be accessible", "risk": "medium", "match_status": [200], "tuning": "2", "method": "GET"},
    ]
    
    # Check if these paths are already in paths_to_check
    existing_paths = {expanded_path for _, expanded_path in paths_to_check}
    for common_entry in explicit_common_paths:
        common_path = common_entry["path"]
        # Check both with and without trailing slash
        if common_path not in existing_paths and f"{common_path}/" not in existing_paths:
            # Add it to paths_to_check (use path as expanded_path since no variables)
            paths_to_check.append((common_entry, common_path))
    
    # Report filtering stats
    if skipped_tech > 0 or skipped_cgi > 0:
        print(f"[i] Skipped {skipped_tech} tech-specific and {skipped_cgi} CGI paths (not detected)")
    
    # Extract common paths to ensure they're always tested
    common_paths_list = [
        "/phpinfo.php", "/test.php", "/test/", "/admin/", "/administrator/",
        "/cgi-bin/phpinfo.php", "/info.php", "/phpinfo", "/testphp.php"
    ]
    common_paths_to_check = []
    regular_paths = []
    
    for entry, expanded_path in paths_to_check:
        uri = entry.get("uri", entry.get("path", ""))
        is_common = any(
            uri.endswith(cp) or uri == cp or cp in uri or 
            uri.endswith(cp.rstrip('/')) or uri == cp.rstrip('/') or
            expanded_path.endswith(cp) or expanded_path == cp or cp in expanded_path
            for cp in common_paths_list
        )
        if is_common:
            common_paths_to_check.append((entry, expanded_path))
        else:
            regular_paths.append((entry, expanded_path))
    
    # Smart limiting: prioritize high-value checks (like real Nikto)
    # Only scan everything if explicitly requested via tuning
    original_count = len(regular_paths)
    if original_count > 5000 and not tuning_set:
        # Prioritize by risk and tuning code
        priority_order = ["1", "2", "3", "8", "9", "a", "b", "c", "4", "5", "6", "7", "0"]
        def get_priority(item):
            entry = item[0]
            risk = entry.get("risk", "info")
            tuning = entry.get("tuning", "")
            
            # High risk = priority 0-10
            if risk == "high":
                priority = 0
            elif risk == "medium":
                priority = 100
            else:
                priority = 200
            
            # Add tuning code priority
            for i, code in enumerate(priority_order):
                if code in tuning:
                    priority += i
                    break
            else:
                priority += 99
            
            return priority
        
        # Sort by priority and limit to 5000 most important
        regular_paths.sort(key=get_priority)
        regular_paths = regular_paths[:5000]
        print(f"[i] Prioritized {len(regular_paths)} most important paths (from {original_count})")
    
    # Always include common paths (add them at the beginning for priority)
    paths_to_check = common_paths_to_check + regular_paths
    if common_paths_to_check:
        print(f"[i] Always checking {len(common_paths_to_check)} common test paths (phpinfo.php, /test/, /admin/, etc.)")

    # Set total for progress tracking
    with _progress_lock:
        _progress_counter["total"] = len(paths_to_check)

    if len(paths_to_check) > 0:
        print(f"[i] Checking {len(paths_to_check)} paths from Nikto database...")
    else:
        return [], 0

    # Check paths concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(_check_single_path, entry, expanded_path, target, http, detected, notfound_sigs)
            for entry, expanded_path in paths_to_check
        ]

        completed = 0
        for fut in concurrent.futures.as_completed(futures):
            completed += 1
            try:
                finding = fut.result()
                if finding:
                    findings.append(finding)
                
                # Never give up - continue scanning everything
                # Findings are displayed immediately when found
                # No stop conditions - scan all paths regardless of errors
            except Exception as exc:
                with _error_lock:
                    _error_count["consecutive"] += 1
                    _error_count["total"] += 1

    # Clear progress line
    if _progress_counter["total"] > 0:
        print()  # Newline after progress

    # Deduplicate findings list (use normalized URL to avoid duplicates)
    seen = set()
    unique_findings = []
    for f in findings:
        # Normalize URL for comparison
        normalized = f.url.rstrip('/').lower()
        if normalized not in seen:
            seen.add(normalized)
            unique_findings.append(f)
    
    # Return findings and total tests attempted
    total_tested = _progress_counter["checked"]
    return unique_findings, total_tested
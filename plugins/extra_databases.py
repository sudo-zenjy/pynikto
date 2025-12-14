# plugins/extra_databases.py
"""
Plugin to load and test from extra databases:
- Nuclei templates
- SecLists wordlists
- CVE-specific tests
- Wappalyzer technology detection
"""
from typing import List, Dict
import concurrent.futures
from targets import Target
from http_client import HttpClient
from database_loader import (
    get_nuclei_databases,
    get_seclists_databases,
    get_cve_databases,
    get_wappalyzer_databases,
    convert_nuclei_template_to_entry,
    convert_seclists_to_entry,
    convert_cve_to_entry,
    convert_wappalyzer_to_entry,
)
from findings import Finding
from variables import expand_variables

PLUGIN_NAME = "extra_databases"


def _normalize_entry(entry: Dict, source: str) -> Dict:
    """Normalize database entry to standard format"""
    if not isinstance(entry, dict):
        return {}
    
    # If already in PyNikto format, return as-is
    if "test_id" in entry or "path" in entry:
        entry["source"] = source
        return entry
    
    # Convert based on source
    if source == "nuclei":
        return convert_nuclei_template_to_entry(entry) or {}
    elif source == "seclists":
        return convert_seclists_to_entry(entry.get("path", "")) or {}
    elif source == "cve":
        return convert_cve_to_entry(entry) or {}
    elif source == "wappalyzer":
        return convert_wappalyzer_to_entry(entry) or {}
    
    return {}


def _check_entry(
    target: Target,
    http: HttpClient,
    entry: Dict,
    notfound_sigs: Dict = None,
    ignore_404_codes: List[int] = None,
    ignore_404_string: str = "",
) -> Finding:
    """Check a single database entry and return finding if match"""
    path = entry.get("path") or entry.get("uri", "")
    if not path:
        return None
    
    # Expand variables in path
    expanded_path = expand_variables(path, target)
    url = f"{target.base_url}{expanded_path}"
    
    method = entry.get("method", "GET")
    match_status = entry.get("match_status", [200, 301, 302, 403])
    
    # Make request
    resp = http.request(method, url, allow_redirects=False)
    if not resp:
        return None
    
    # Check if status matches
    if resp.status_code not in match_status:
        return None
    
    # Check 404 filtering
    if notfound_sigs and notfound_sigs.get("enabled"):
        for sig in notfound_sigs.get("signatures", []):
            if (sig.get("status") == resp.status_code and
                abs(sig.get("length", 0) - len(resp.text)) < 100):
                # Likely a 404, skip
                return None
    
    # Check ignore codes
    if ignore_404_codes and resp.status_code in ignore_404_codes:
        return None
    
    # Check ignore string
    if ignore_404_string and ignore_404_string in resp.text:
        return None
    
    # Check content matches
    match_1 = entry.get("match_1", "")
    match_1_and = entry.get("match_1_and", "")
    match_1_or = entry.get("match_1_or", "")
    
    if match_1:
        if match_1.lower() not in resp.text.lower():
            return None
        if match_1_and and match_1_and.lower() not in resp.text.lower():
            return None
    elif match_1_or:
        if match_1_or.lower() not in resp.text.lower():
            return None
    
    # Create finding
    message = entry.get("message", f"Found: {expanded_path}")
    risk = entry.get("risk", "info")
    nikto_id = entry.get("nikto_id") or entry.get("test_id", "EXTRA-000000")
    references = entry.get("references", "")
    source = entry.get("source", "extra")
    
    # Add source to message
    if source != "extra":
        message = f"[{source.upper()}] {message}"
    
    return Finding(
        plugin=PLUGIN_NAME,
        url=url,
        message=message,
        risk=risk,
        status=resp.status_code,
        nikto_id=nikto_id,
        references=references,
        method=method,
        uri=expanded_path,
    )


def run(
    target: Target,
    http: HttpClient,
    tuning_set: set[str] = None,
    max_workers: int = 50,
    notfound_sigs: Dict = None,
    ignore_404_codes: List[int] = None,
    ignore_404_string: str = "",
) -> tuple[List[Finding], int]:
    """
    Load and test from extra databases (Nuclei, SecLists, CVE, Wappalyzer).
    """
    findings: List[Finding] = []
    
    # Load all extra databases
    print(f"[i] Loading extra databases (Nuclei, SecLists, CVE, Wappalyzer)...")
    
    nuclei_entries = get_nuclei_databases()
    seclists_entries = get_seclists_databases()
    cve_entries = get_cve_databases()
    wappalyzer_entries = get_wappalyzer_databases()
    
    # Normalize and combine all entries
    all_entries = []
    
    for entry in nuclei_entries:
        normalized = _normalize_entry(entry, "nuclei")
        if normalized:
            all_entries.append(normalized)
    
    for entry in seclists_entries:
        normalized = _normalize_entry(entry, "seclists")
        if normalized:
            all_entries.append(normalized)
    
    for entry in cve_entries:
        normalized = _normalize_entry(entry, "cve")
        if normalized:
            all_entries.append(normalized)
    
    for entry in wappalyzer_entries:
        normalized = _normalize_entry(entry, "wappalyzer")
        if normalized:
            all_entries.append(normalized)
    
    if not all_entries:
        print(f"[i] No extra database entries found. Add JSON files to databases/nuclei/, databases/seclists/, databases/cve/, or databases/wappalyzer/")
        return findings, 0
    
    print(f"[i] Testing {len(all_entries)} entries from extra databases...")
    
    # Filter by tuning if specified
    if tuning_set:
        filtered_entries = []
        for entry in all_entries:
            entry_tuning = entry.get("tuning", "")
            if not entry_tuning or any(t in entry_tuning for t in tuning_set):
                filtered_entries.append(entry)
        all_entries = filtered_entries
        print(f"[i] After tuning filter: {len(all_entries)} entries")
    
    # Test entries concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(
                _check_entry,
                target,
                http,
                entry,
                notfound_sigs,
                ignore_404_codes,
                ignore_404_string,
            )
            for entry in all_entries
        ]
        
        for future in concurrent.futures.as_completed(futures):
            try:
                finding = future.result()
                if finding:
                    findings.append(finding)
            except Exception as exc:
                pass  # Silently skip errors
    
    print(f"[i] Extra databases: {len(findings)} finding(s) from {len(all_entries)} test(s)")
    return findings, len(all_entries)

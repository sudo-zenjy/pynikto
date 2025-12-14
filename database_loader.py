# database_loader.py
"""
Database loader utility for loading databases from multiple directories.
Supports:
- /databases/ (main Nikto databases)
- /databases/nuclei/ (Nuclei templates)
- /databases/seclists/ (SecLists wordlists)
- /databases/cve/ (CVE-specific tests)
- /databases/wappalyzer/ (Wappalyzer technology detection)
"""
import os
import json
from typing import List, Dict, Optional
from pathlib import Path
from config import load_config


def load_database_from_file(file_path: str) -> List[Dict]:
    """Load a single database file (JSON format)"""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            # Handle both list and dict formats
            if isinstance(data, dict):
                # If it's a dict, try to extract entries
                if "entries" in data:
                    return data["entries"]
                elif "tests" in data:
                    return data["tests"]
                else:
                    # Return as single-item list
                    return [data]
            return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[-] Failed to load database {file_path}: {exc}")
        return []


def load_databases_from_directory(directory: str, pattern: str = "*.json") -> List[Dict]:
    """
    Load all database files from a directory matching the pattern.
    Returns a combined list of all entries.
    """
    if not os.path.exists(directory):
        return []
    
    entries = []
    db_path = Path(directory)
    
    # Load all JSON files matching the pattern
    for db_file in db_path.glob(pattern):
        file_entries = load_database_from_file(str(db_file))
        entries.extend(file_entries)
    
    return entries


def get_nuclei_databases() -> List[Dict]:
    """Load all databases from /databases/nuclei/ directory"""
    cfg = load_config()
    nuclei_dir = os.path.join(cfg["dbdir"], "nuclei")
    return load_databases_from_directory(nuclei_dir)


def get_seclists_databases() -> List[Dict]:
    """Load all databases from /databases/seclists/ directory"""
    cfg = load_config()
    seclists_dir = os.path.join(cfg["dbdir"], "seclists")
    return load_databases_from_directory(seclists_dir)


def get_cve_databases() -> List[Dict]:
    """Load all databases from /databases/cve/ directory"""
    cfg = load_config()
    cve_dir = os.path.join(cfg["dbdir"], "cve")
    return load_databases_from_directory(cve_dir)


def get_wappalyzer_databases() -> List[Dict]:
    """Load all databases from /databases/wappalyzer/ directory"""
    cfg = load_config()
    wappalyzer_dir = os.path.join(cfg["dbdir"], "wappalyzer")
    return load_databases_from_directory(wappalyzer_dir)


def get_all_extra_databases() -> Dict[str, List[Dict]]:
    """
    Load all extra databases from subdirectories.
    Returns a dictionary mapping database type to entries.
    """
    return {
        "nuclei": get_nuclei_databases(),
        "seclists": get_seclists_databases(),
        "cve": get_cve_databases(),
        "wappalyzer": get_wappalyzer_databases(),
    }


def convert_nuclei_template_to_entry(template: Dict) -> Optional[Dict]:
    """
    Convert a Nuclei template to PyNikto database entry format.
    Nuclei templates have structure like:
    {
        "id": "CVE-2023-XXXX",
        "info": {"name": "...", "severity": "...", ...},
        "requests": [{"path": ["/path"], "method": "GET", ...}]
    }
    """
    if not isinstance(template, dict):
        return None
    
    template_id = template.get("id", "")
    info = template.get("info", {})
    requests = template.get("requests", [])
    
    if not requests:
        return None
    
    # Extract first request path
    first_request = requests[0]
    paths = first_request.get("path", [])
    if not paths:
        return None
    
    path = paths[0] if isinstance(paths, list) else paths
    method = first_request.get("method", "GET")
    
    # Convert severity to risk level
    severity = info.get("severity", "info").lower()
    risk_map = {
        "critical": "high",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
    }
    risk = risk_map.get(severity, "info")
    
    return {
        "test_id": template_id or "NUCLEI-000000",
        "path": path,
        "match_status": [200, 301, 302, 403],
        "message": info.get("name", "") or info.get("description", ""),
        "risk": risk,
        "tuning": "",
        "method": method,
        "references": info.get("reference", ""),
        "nikto_id": template_id,
        "source": "nuclei",
    }


def convert_seclists_to_entry(wordlist_path: str, base_path: str = "") -> Optional[Dict]:
    """
    Convert a SecLists wordlist entry to PyNikto format.
    SecLists are typically text files with one path per line.
    """
    if not wordlist_path:
        return None
    
    # Clean up the path
    path = wordlist_path.strip()
    if not path.startswith("/"):
        path = "/" + path
    
    return {
        "test_id": "SECLISTS-000000",
        "path": path,
        "match_status": [200, 301, 302, 403],
        "message": f"Potential file or directory: {path}",
        "risk": "info",
        "tuning": "",
        "method": "GET",
        "references": "SecLists",
        "source": "seclists",
    }


def convert_cve_to_entry(cve_entry: Dict) -> Optional[Dict]:
    """
    Convert a CVE database entry to PyNikto format.
    Expected format:
    {
        "cve_id": "CVE-2023-XXXX",
        "path": "/vulnerable/path",
        "description": "...",
        "severity": "high",
        ...
    }
    """
    if not isinstance(cve_entry, dict):
        return None
    
    cve_id = cve_entry.get("cve_id", "") or cve_entry.get("id", "")
    path = cve_entry.get("path", "")
    description = cve_entry.get("description", "") or cve_entry.get("message", "")
    
    if not path:
        return None
    
    severity = cve_entry.get("severity", "info").lower()
    risk_map = {
        "critical": "high",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
    }
    risk = risk_map.get(severity, "info")
    
    return {
        "test_id": cve_id or "CVE-000000",
        "path": path,
        "match_status": [200, 301, 302, 403],
        "message": description or f"Potential CVE: {cve_id}",
        "risk": risk,
        "tuning": "",
        "method": cve_entry.get("method", "GET"),
        "references": cve_id,
        "nikto_id": cve_id,
        "source": "cve",
    }


def convert_wappalyzer_to_entry(wapp_entry: Dict) -> Optional[Dict]:
    """
    Convert a Wappalyzer technology detection entry to PyNikto format.
    Wappalyzer format:
    {
        "name": "WordPress",
        "url": "/wp-content/...",
        "headers": {...},
        "html": ["..."]
    }
    """
    if not isinstance(wapp_entry, dict):
        return None
    
    name = wapp_entry.get("name", "")
    url = wapp_entry.get("url", "")
    html_patterns = wapp_entry.get("html", [])
    
    if not url and not html_patterns:
        return None
    
    # Use URL if available, otherwise use first HTML pattern
    path = url if url else "/"
    
    return {
        "test_id": f"WAPP-{name.upper().replace(' ', '-')}",
        "path": path,
        "match_status": [200],
        "message": f"Wappalyzer detection pattern for {name}",
        "risk": "info",
        "tuning": "b",  # Software identification
        "method": "GET",
        "references": f"Wappalyzer: {name}",
        "source": "wappalyzer",
        "match_1": html_patterns[0] if html_patterns else "",
    }

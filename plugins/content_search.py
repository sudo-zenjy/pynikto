from typing import List, Dict
import json
import os
from targets import Target
from http_client import HttpClient
from config import load_config
from findings import Finding

PLUGIN_NAME = "content_search"

def _load_content_db() -> List[Dict]:
    cfg = load_config()
    db_path = os.path.join(cfg["dbdir"], "db_content_search.json")
    try:
        with open(db_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return []

CONTENT_DB = _load_content_db()

def run(target: Target, http: HttpClient) -> List[Finding]:
    findings: List[Finding] = []
    
    if not CONTENT_DB:
        return findings
    
    # Get root page
    resp = http.get(f"{target.base_url}/", allow_redirects=True)
    if not resp or resp.status_code != 200:
        return findings
    
    content = resp.text.lower()
    
    for entry in CONTENT_DB:
        search_term = entry.get("search", "").lower()
        if not search_term:
            continue
        
        if search_term in content:
            findings.append(Finding(
                plugin=PLUGIN_NAME,
                url=f"{target.base_url}/",
                message=entry.get("message", f"Content found: {search_term}"),
                risk=entry.get("risk", "info"),
                status=resp.status_code,
                nikto_id=entry.get("test_id", "000600"),
                references=entry.get("references", ""),
            ))
    
    return findings

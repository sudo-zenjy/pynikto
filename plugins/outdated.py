from typing import List, Dict
import json
import os
from targets import Target
from http_client import HttpClient
from config import load_config
from findings import Finding

PLUGIN_NAME = "outdated"

def _load_outdated_db() -> List[Dict]:
    cfg = load_config()
    db_path = os.path.join(cfg["dbdir"], "db_outdated.json")
    try:
        with open(db_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return []

OUTDATED_DB = _load_outdated_db()

def run(target: Target, http: HttpClient) -> List[Finding]:
    findings: List[Finding] = []
    
    if not OUTDATED_DB:
        return findings
    
    resp = http.get(f"{target.base_url}/", allow_redirects=True)
    if not resp:
        return findings
    
    server = resp.headers.get("Server", "").lower()
    powered = resp.headers.get("X-Powered-By", "").lower()
    content = resp.text.lower()
    
    for entry in OUTDATED_DB:
        pattern = entry.get("pattern", "").lower()
        if not pattern:
            continue
        
        # Check in headers or content
        if pattern in server or pattern in powered or pattern in content:
            findings.append(Finding(
                plugin=PLUGIN_NAME,
                url=f"{target.base_url}/",
                message=entry.get("message", f"Outdated software detected: {pattern}"),
                risk="high",
                status=resp.status_code,
                nikto_id=entry.get("test_id", "000700"),
                references=entry.get("references", ""),
            ))
    
    return findings

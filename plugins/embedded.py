from typing import List, Dict
import json
import os
from targets import Target
from http_client import HttpClient
from config import load_config
from findings import Finding

PLUGIN_NAME = "embedded"

def _load_embedded_db() -> List[Dict]:
    cfg = load_config()
    db_path = os.path.join(cfg["dbdir"], "db_embedded.json")
    try:
        with open(db_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return []

EMBEDDED_DB = _load_embedded_db()

def run(target: Target, http: HttpClient) -> List[Finding]:
    findings: List[Finding] = []
    
    if not EMBEDDED_DB:
        return findings
    
    for entry in EMBEDDED_DB:
        path = entry.get("path", "")
        if not path:
            continue
        
        url = f"{target.base_url}{path}"
        resp = http.get(url, allow_redirects=True)
        if not resp:
            continue
        
        if resp.status_code == 200:
            # Check for embedded server signature
            content = resp.text
            signature = entry.get("signature", "")
            
            if signature and signature.lower() in content.lower():
                findings.append(Finding(
                    plugin=PLUGIN_NAME,
                    url=url,
                    message=entry.get("message", "Embedded server detected"),
                    risk=entry.get("risk", "medium"),
                    status=resp.status_code,
                    nikto_id=entry.get("test_id", "000800"),
                    references=entry.get("references", ""),
                ))
    
    return findings

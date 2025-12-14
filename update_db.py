#!/usr/bin/env python3
"""Update Nikto database from cirt.net"""
import urllib.request
import json
import os
from config import load_config

def update_database():
    """Download latest database from cirt.net"""
    cfg = load_config()
    db_dir = cfg["dbdir"]
    
    print("[+] Updating database from cirt.net...")
    
    # Main database URL (example - actual URL may differ)
    db_url = "https://cirt.net/nikto/2.1.5/db_tests"
    
    try:
        print(f"[+] Downloading {db_url}...")
        with urllib.request.urlopen(db_url, timeout=30) as response:
            data = response.read().decode('utf-8')
        
        # Convert to JSON (would need conversion logic)
        # For now, save raw
        output_path = os.path.join(db_dir, "db_tests_updated")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(data)
        
        print(f"[+] Database updated: {output_path}")
        print("[!] Run convert_nikto_db.py to convert to JSON format")
        
    except Exception as e:
        print(f"[-] Update failed: {e}")

if __name__ == "__main__":
    update_database()

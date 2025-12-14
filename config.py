# config.py
import os
from typing import Dict


def load_config() -> Dict[str, str]:
    """
    Very small stand-in for Nikto's config/environment step.
    Later we can:
      - Read nikto.conf-style files
      - Respect env vars
      - Support user overrides
    """
    execdir = os.path.dirname(os.path.abspath(__file__))

    cfg: Dict[str, str] = {
        "execdir": execdir,
        "plugindir": os.path.join(execdir, "plugins"),
        "dbdir": os.path.join(execdir, "databases"),
        "nuclei_dir": os.path.join(execdir, "databases", "nuclei"),
        "seclists_dir": os.path.join(execdir, "databases", "seclists"),
        "cve_dir": os.path.join(execdir, "databases", "cve"),
        "wappalyzer_dir": os.path.join(execdir, "databases", "wappalyzer"),
        "proxy": "",  # later: from config file or CLI
    }

    return cfg
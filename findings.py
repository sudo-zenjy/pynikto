# findings.py
from dataclasses import dataclass
from typing import Optional


@dataclass
class Finding:
    """Enhanced finding structure matching Nikto's format"""
    plugin: str
    url: str
    message: str
    risk: str
    status: int
    nikto_id: Optional[str] = None
    references: Optional[str] = None
    method: str = "GET"
    uri: Optional[str] = None
    
    def to_nikto_format(self, hostname: str = "") -> str:
        """Format finding like original Nikto: + [uri or method]: [message] See: [refs]"""
        from urllib.parse import urlparse
        
        # Extract URI from URL
        uri = self.uri
        if not uri:
            try:
                parsed = urlparse(self.url)
                uri = parsed.path or "/"
                if parsed.query:
                    uri += f"?{parsed.query}"
            except:
                uri = "/"
        
        # Format like Nikto: + [uri]: [message] See: [refs]
        # Or: + [method]: [message] See: [refs] for method-based findings
        prefix = ""
        if self.method and self.method != "GET":
            # For method-based findings, show method first
            if uri == "/" or not uri:
                prefix = f"{self.method}: "
            else:
                prefix = f"{self.method} {uri}: "
        else:
            prefix = f"{uri}: " if uri else ""
        
        msg = self.message
        # Don't add period if message already ends with one
        if msg and not msg.endswith("."):
            msg += "."
        
        if self.references:
            msg += f" See: {self.references}"
        
        line = f"+ {prefix}{msg}" if prefix else f"+ {msg}"
        return line
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON/XML export"""
        return {
            "plugin": self.plugin,
            "url": self.url,
            "message": self.message,
            "risk": self.risk,
            "status": self.status,
            "nikto_id": self.nikto_id or "000000",
            "references": self.references or "",
            "method": self.method,
            "uri": self.uri or "",
        }

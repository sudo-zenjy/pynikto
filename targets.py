# targets.py
from dataclasses import dataclass
from typing import List
from urllib.parse import urlparse


@dataclass
class Target:
    host: str
    port: int
    ssl: bool

    @property
    def scheme(self) -> str:
        return "https" if self.ssl or self.port == 443 else "http"

    @property
    def base_url(self) -> str:
        # Don't add port if it's the default port
        if (self.port == 80 and not self.ssl) or (self.port == 443 and self.ssl):
            return f"{self.scheme}://{self.host}"
        return f"{self.scheme}://{self.host}:{self.port}"


def _parse_ports(port_input: str) -> List[int]:
    # Similar to Nikto: accept "80", "80,443", "80-90"
    ports: List[int] = []
    for part in port_input.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start > end:
                start, end = end, start
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def build_targets_from_cli(host_input: str, port_input: str, ssl_flag: bool) -> List[Target]:
    """
    Mirrors Nikto's 'build host list' step, but only for a single host for now.
    Later: host files, CIDR, etc.
    
    Handles URLs like http://example.com or https://example.com:8080
    """
    host = host_input.strip()
    if not host:
        return []

    # Parse URL if it starts with http:// or https://
    if host.startswith("http://") or host.startswith("https://"):
        try:
            parsed_url = urlparse(host)
            
            # Extract hostname from URL (remove any path/query/fragment)
            if parsed_url.hostname:
                host = parsed_url.hostname
            elif parsed_url.netloc:
                # Fallback: extract from netloc (handles cases where hostname might be None)
                netloc_parts = parsed_url.netloc.split(":")
                host = netloc_parts[0]
            else:
                # If we can't parse, strip scheme and try to extract hostname
                host = (
                    host.replace("http://", "")
                    .replace("https://", "")
                    .split("/")[0]
                    .split("?")[0]
                    .split("#")[0]
                )
            
            # Check scheme first (regardless of port presence)
            if parsed_url.scheme == "https":
                ssl_flag = True
                # Default to 443 if no port specified
                if not parsed_url.port and (not port_input or port_input == "80"):
                    port_input = "443"
            
            # Extract port from URL if present
            if parsed_url.port:
                port_input = str(parsed_url.port)
            elif ":" in parsed_url.netloc and not parsed_url.port:
                # Port might be in netloc but not parsed (e.g., http://host:port/path)
                netloc_parts = parsed_url.netloc.split(":")
                if len(netloc_parts) == 2:
                    try:
                        # Try to parse port from netloc
                        potential_port = netloc_parts[1].split("/")[0]
                        int(potential_port)  # Validate it's a number
                        port_input = potential_port
                    except (ValueError, IndexError):
                        pass
        except Exception:
            # If parsing fails, try to extract hostname manually
            try:
                # Strip scheme and extract hostname
                host_clean = host.replace("http://", "").replace("https://", "")
                host = host_clean.split("/")[0].split("?")[0].split("#")[0]
                # Try to extract port if present
                if ":" in host:
                    host, port_part = host.split(":", 1)
                    try:
                        port_input = port_part.split("/")[0]
                    except Exception:
                        pass
            except Exception:
                # If all else fails, treat as regular hostname
                pass

    ports = _parse_ports(port_input)
    if not ports:
        return []

    return [Target(host=host, port=p, ssl=ssl_flag) for p in ports]
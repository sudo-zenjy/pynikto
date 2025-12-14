import random
import string
from typing import Dict

def expand_variables(path: str, target_host: str, target_ip: str = None) -> list[str]:
    """
    Expand Nikto-style variables in paths.
    @IP -> target IP
    @HOSTNAME -> target hostname
    @CGIDIRS -> common CGI directories
    JUNK(n) -> random string of length n
    """
    if target_ip is None:
        target_ip = target_host

    # Replace simple variables
    path = path.replace("@IP", target_ip)
    path = path.replace("@HOSTNAME", target_host)

    # Expand @CGIDIRS
    if "@CGIDIRS" in path:
        cgi_dirs = ["/cgi-bin/", "/cgi/", "/cgi-local/", "/cgi-win/", "/cgi-sys/"]
        return [path.replace("@CGIDIRS", d) for d in cgi_dirs]

    # Expand JUNK(n)
    import re
    def replace_junk(match):
        n = int(match.group(1))
        return ''.join(random.choices(string.ascii_letters + string.digits, k=n))
    
    path = re.sub(r'JUNK\((\d+)\)', replace_junk, path)

    return [path]

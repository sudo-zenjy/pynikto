# plugins/ssl_checks.py
from typing import List
import ssl
import socket
import datetime

from findings import Finding
from http_client import HttpClient
from targets import Target

PLUGIN_NAME = "ssl_checks"


def run(target: Target, http: HttpClient) -> List[Finding]:
    """
    Check SSL/TLS configuration and certificate details (like original Nikto).
    Reports certificate subject, issuer, cipher, and potential issues.
    """
    findings: List[Finding] = []
    
    # Only run for HTTPS targets
    if not target.ssl and target.port != 443:
        return findings
    
    try:
        # Create SSL context
        context = ssl.create_default_context()
        
        # Connect and get SSL info
        with socket.create_connection((target.host, target.port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=target.host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol = ssock.version()
                
                # Extract certificate subject (CN)
                subject = dict(x[0] for x in cert.get('subject', []))
                subject_cn = subject.get('commonName', 'Unknown')
                
                # Extract issuer
                issuer = dict(x[0] for x in cert.get('issuer', []))
                issuer_cn = issuer.get('commonName', 'Unknown')
                issuer_o = issuer.get('organizationName', '')
                issuer_c = issuer.get('countryName', '')
                
                # Format issuer string (like Nikto)
                issuer_parts = []
                if issuer_c:
                    issuer_parts.append(f"C={issuer_c}")
                if issuer_o:
                    issuer_parts.append(f"O={issuer_o}")
                if issuer_cn:
                    issuer_parts.append(f"CN={issuer_cn}")
                issuer_str = "/".join(issuer_parts) if issuer_parts else "Unknown"
                
                # Get cipher info
                cipher_name = cipher[0] if cipher else "Unknown"
                
                # Print SSL info (like original Nikto)
                print(f"+ SSL Info:        Subject:  /CN={subject_cn}")
                print(f"                   Ciphers:  {cipher_name}")
                print(f"                   Issuer:   /{issuer_str}")
                
                # Check for wildcard certificate
                if subject_cn.startswith("*."):
                    findings.append(Finding(
                        plugin=PLUGIN_NAME,
                        url=f"{target.base_url}/",
                        message=f"Server is using a wildcard certificate: {subject_cn}.",
                        risk="info",
                        status=200,
                        nikto_id="000100",
                        references="https://en.wikipedia.org/wiki/Wildcard_certificate",
                        uri="/",
                    ))
                
                # Check certificate expiration
                not_after_str = cert.get('notAfter')
                if not_after_str:
                    try:
                        not_after = datetime.datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                        days_left = (not_after - datetime.datetime.now()).days
                        
                        if days_left < 0:
                            findings.append(Finding(
                                plugin=PLUGIN_NAME,
                                url=f"{target.base_url}/",
                                message=f"SSL certificate has EXPIRED ({abs(days_left)} days ago).",
                                risk="high",
                                status=200,
                                nikto_id="000101",
                                uri="/",
                            ))
                        elif days_left < 30:
                            findings.append(Finding(
                                plugin=PLUGIN_NAME,
                                url=f"{target.base_url}/",
                                message=f"SSL certificate expires soon (in {days_left} days).",
                                risk="medium",
                                status=200,
                                nikto_id="000102",
                                uri="/",
                            ))
                    except Exception:
                        pass
                
                # Check protocol version (warn about old protocols)
                if protocol in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                    findings.append(Finding(
                        plugin=PLUGIN_NAME,
                        url=f"{target.base_url}/",
                        message=f"Outdated SSL/TLS protocol in use: {protocol}. This protocol has known vulnerabilities.",
                        risk="high",
                        status=200,
                        nikto_id="000103",
                        references="CVE-2014-3566, CVE-2011-3389",
                        uri="/",
                    ))
                
                # Check for weak ciphers
                weak_ciphers = ["DES", "RC4", "MD5", "NULL", "EXPORT", "anon"]
                if cipher_name and any(weak in cipher_name.upper() for weak in weak_ciphers):
                    findings.append(Finding(
                        plugin=PLUGIN_NAME,
                        url=f"{target.base_url}/",
                        message=f"Weak cipher suite detected: {cipher_name}. This may allow attackers to decrypt traffic.",
                        risk="high",
                        status=200,
                        nikto_id="000104",
                        references="https://www.openssl.org/docs/man1.1.1/man1/ciphers.html",
                        uri="/",
                    ))
                
    except ssl.SSLError as e:
        # SSL-specific errors
        findings.append(Finding(
            plugin=PLUGIN_NAME,
            url=f"{target.base_url}/",
            message=f"SSL/TLS error: {str(e)}.",
            risk="medium",
            status=0,
            nikto_id="000105",
            uri="/",
        ))
    except socket.timeout:
        # Timeout connecting
        pass
    except Exception:
        # Other errors - silently skip
        pass
    
    return findings

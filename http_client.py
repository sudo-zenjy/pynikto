# http_client.py
import requests
from typing import Optional, List, Dict
import random
import string
import re

from evasion import IDSEvasion


class HttpClient:
    """
    Modern equivalent of Nikto's LibWhisker-based HTTP layer (simplified).
    """

    def __init__(
        self,
        timeout: float = 10.0,
        verify_ssl: bool = True,
        user_agent: str = "Mozilla/5.0 (compatible; Nikto/2.5.0)",  # Match Nikto's default UA
        proxy: Optional[str] = None,
        use_evasion: bool = False,
    ) -> None:
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.default_user_agent = user_agent

        # Use HTTPAdapter with connection pooling
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        self.session = requests.Session()
        
        # Connection pooling
        adapter = HTTPAdapter(
            pool_connections=100,  # Nikto uses ~10, we use 100
            pool_maxsize=100,      # Massive connection pool
            max_retries=Retry(
                total=3,
                backoff_factor=0.3,
                status_forcelist=[500, 502, 503, 504],
                allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
            )
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set default headers like Nikto
        self.session.headers.update({
            "User-Agent": user_agent,
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
        })

        if proxy:
            self.session.proxies.update({
                "http": proxy,
                "https": proxy,
            })

        self.use_evasion = use_evasion
        self.evasion = IDSEvasion() if use_evasion else None
        
        # Track performance metrics
        self.failed_hosts = set()
        self.retry_count = 0
        self.request_times = []  # Track response times for adaptive throttling
        self.success_rate = {"total": 0, "success": 0}  # Track success rate

    def request(self, method: str, url: str, allow_redirects: bool = True, retries: int = 2):
        """
        HTTP request with WAF bypass and adaptive throttling.
        """
        import time
        from urllib.parse import urlparse
        
        start_time = time.time()
        host = urlparse(url).netloc
        
        for attempt in range(retries + 1):
            try:
                headers = {}
                
                # Adaptive User-Agent rotation
                if host in self.failed_hosts or attempt > 0:
                    headers['User-Agent'] = self.get_random_user_agent()
                    # Add realistic browser headers to bypass WAF
                    headers['Accept-Language'] = random.choice([
                        'en-US,en;q=0.9',
                        'en-GB,en;q=0.9',
                        'en-CA,en;q=0.9',
                    ])
                    headers['DNT'] = '1'
                    headers['Upgrade-Insecure-Requests'] = '1'
                
                if self.use_evasion and self.evasion:
                    headers['User-Agent'] = self.evasion.get_random_user_agent()
                    if random.random() < 0.3:
                        url = self.evasion.add_junk_params(url)
                
                # Adaptive timeout based on host performance
                adaptive_timeout = self.timeout
                if self.request_times:
                    avg_time = sum(self.request_times[-50:]) / len(self.request_times[-50:])
                    adaptive_timeout = max(self.timeout, avg_time * 2)
                
                resp = self.session.request(
                    method=method.upper(),
                    url=url,
                    timeout=adaptive_timeout,
                    allow_redirects=allow_redirects,
                    verify=self.verify_ssl,
                    headers=headers if headers else None,
                )
                
                # Track performance metrics
                elapsed = time.time() - start_time
                self.request_times.append(elapsed)
                if len(self.request_times) > 100:
                    self.request_times.pop(0)  # Keep last 100
                
                # Track success rate
                self.success_rate["total"] += 1
                if resp.status_code < 400:
                    self.success_rate["success"] += 1
                
                # Cloudflare/WAF detection and bypass
                if resp.status_code in [403, 503, 429]:
                    cf_ray = resp.headers.get('CF-RAY') or resp.headers.get('cf-ray')
                    waf_detected = (
                        cf_ray or 
                        'cloudflare' in resp.text.lower()[:500] or
                        'access denied' in resp.text.lower()[:500] or
                        resp.status_code == 429  # Rate limit
                    )
                    
                    if waf_detected and attempt < retries:
                        self.failed_hosts.add(host)
                        # Exponential backoff with jitter
                        wait_time = (0.5 * (2 ** attempt)) + random.uniform(0, 0.5)
                        time.sleep(wait_time)
                        continue
                
                # Success - update metrics
                if host in self.failed_hosts and resp.status_code < 400:
                    self.failed_hosts.discard(host)
                
                return resp
                
            except requests.Timeout:
                if attempt < retries:
                    # Adaptive backoff
                    time.sleep(0.3 * (attempt + 1) + random.uniform(0, 0.2))
                    continue
                return None
            except requests.ConnectionError as e:
                if attempt < retries:
                    # Exponential backoff for connection errors
                    time.sleep(0.5 * (2 ** attempt) + random.uniform(0, 0.3))
                    continue
                return None
            except requests.RequestException as e:
                if hasattr(e, 'response') and e.response is not None:
                    return e.response
                return None
        return None

    def head(self, url: str, allow_redirects: bool = True):
        return self.request("HEAD", url, allow_redirects=allow_redirects)

    def get(self, url: str, allow_redirects: bool = True):
        return self.request("GET", url, allow_redirects=allow_redirects)

    @staticmethod
    def obfuscate_path(path: str) -> List[str]:
        """Generate obfuscated versions of a path"""
        obfuscated = [path]  # Original
        
        # URL encoding variations
        if '/' in path:
            parts = path.split('/')
            # Double encoding
            encoded = '/'.join([f'%2F' if p == '' else p for p in parts])
            obfuscated.append(encoded)
            
            # Unicode encoding
            unicode_path = path.replace('/', '\u002f')
            obfuscated.append(unicode_path)
        
        # Case variations
        obfuscated.append(path.upper())
        obfuscated.append(path.lower())
        
        return list(set(obfuscated))  # Remove duplicates
    
    @staticmethod
    def get_random_user_agent() -> str:
        """Get random user agent for rotation"""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101",
        ]
        return random.choice(user_agents)
    
    @staticmethod
    def add_junk_params(url: str) -> str:
        """Add random parameters to evade IDS"""
        junk = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        separator = '&' if '?' in url else '?'
        return f"{url}{separator}{junk}={junk}"
import random
import string
from typing import List

class IDSEvasion:
    """IDS evasion techniques similar to Nikto"""
    
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

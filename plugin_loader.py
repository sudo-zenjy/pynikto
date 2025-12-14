# plugin_loader.py
import importlib
import inspect
import pkgutil
from typing import Any, Dict, List

from targets import Target
from http_client import HttpClient
from findings import Finding


def load_plugins(cfg: Dict[str, str]) -> List[Any]:
    """
    Dynamically imports all plugins from the 'plugins' package.
    Each plugin must expose a `run(target, http)` function.
    
    Plugins are sorted to run quick ones first (like original Nikto):
    - Quick plugins: security_headers, http_methods, robots, ssl_checks
    - Medium plugins: embedded, headers_fingerprint, cookies, outdated
    - Heavy plugins: files_from_db, crawler, content_search
    """
    plugins: List[Any] = []
    quick_plugins: List[Any] = []
    medium_plugins: List[Any] = []
    heavy_plugins: List[Any] = []
    post_plugins: List[Any] = []  # Run after all others

    package_name = "plugins"
    package = importlib.import_module(package_name)

    # Define plugin priority
    QUICK_PLUGINS = ["security_headers", "http_methods", "robots", "ssl_checks", "uncommon_headers", "cgi_detection"]
    MEDIUM_PLUGINS = ["hostname_files", "embedded", "headers_fingerprint", "cookies", "outdated", "anomaly_detection"]
    HEAVY_PLUGINS = ["files_from_db", "crawler", "content_search", "extra_databases"]
    # Post-processing plugins (run last to correlate all findings)
    POST_PLUGINS = ["vulnerability_correlation", "exploit_verification"]

    for module_info in pkgutil.iter_modules(package.__path__):
        module = importlib.import_module(f"{package_name}.{module_info.name}")
        if hasattr(module, "run"):
            plugin_name = module_info.name
            if plugin_name in QUICK_PLUGINS:
                quick_plugins.append(module)
            elif plugin_name in MEDIUM_PLUGINS:
                medium_plugins.append(module)
            elif plugin_name in HEAVY_PLUGINS:
                heavy_plugins.append(module)
            elif plugin_name in POST_PLUGINS:
                post_plugins.append(module)
            else:
                # Default to medium if not explicitly categorized
                medium_plugins.append(module)

    # Sort within each category alphabetically for consistency
    def get_module_sort_key(module):
        """Extract plugin name from module for sorting."""
        name = getattr(module, '__name__', '')
        # Extract just the plugin name (e.g., 'plugins.security_headers' -> 'security_headers')
        if '.' in name:
            return name.split('.')[-1]
        return name

    quick_plugins.sort(key=get_module_sort_key)
    medium_plugins.sort(key=get_module_sort_key)
    heavy_plugins.sort(key=get_module_sort_key)
    post_plugins.sort(key=get_module_sort_key)
    
    # Combine: quick first, then medium, then heavy
    # Post-plugins are returned separately for special handling
    plugins = quick_plugins + medium_plugins + heavy_plugins
    
    # Store post-plugins separately for later execution
    for plugin in post_plugins:
        plugin._is_post_plugin = True
    plugins.extend(post_plugins)

    print(f"[i] Loaded {len(plugins)} plugin(s).")
    return plugins


def run_plugins_for_target(
    target: Target, 
    http: HttpClient, 
    plugins: List[Any], 
    tuning_set: set[str] = None, 
    max_workers: int = 50, 
    notfound_sigs: Dict = None,
    ignore_404_codes: List[int] = None,
    ignore_404_string: str = "",
    follow_redirects: bool = True,
    root: str = "",
    crawl_enabled: bool = False,
    crawl_depth: int = 3,
    crawl_max: int = 500,
    respect_robots: bool = True,
    legacy_mode: bool = False,
    cgi_all: bool = False,
) -> tuple[List[Finding], int]:
    findings = []
    total_tests = 0
    for plugin in plugins:
        try:
            sig = inspect.signature(plugin.run)
            params = sig.parameters
            
            # Build arguments based on what plugin accepts
            kwargs = {}
            if 'tuning_set' in params:
                kwargs['tuning_set'] = tuning_set
            if 'max_workers' in params:
                kwargs['max_workers'] = max_workers
            if 'notfound_sigs' in params and notfound_sigs:
                kwargs['notfound_sigs'] = notfound_sigs
            if 'ignore_404_codes' in params and ignore_404_codes:
                kwargs['ignore_404_codes'] = ignore_404_codes
            if 'ignore_404_string' in params and ignore_404_string:
                kwargs['ignore_404_string'] = ignore_404_string
            if 'follow_redirects' in params:
                kwargs['follow_redirects'] = follow_redirects
            if 'root' in params and root:
                kwargs['root'] = root
            # Add crawl parameters
            if 'max_depth' in params and crawl_enabled:
                kwargs['max_depth'] = crawl_depth
            if 'max_urls' in params and crawl_enabled:
                kwargs['max_urls'] = crawl_max
            if 'respect_robots' in params and crawl_enabled:
                kwargs['respect_robots'] = respect_robots
            if 'legacy_mode' in params:
                kwargs['legacy_mode'] = legacy_mode
            if 'cgi_all' in params:
                kwargs['cgi_all'] = cgi_all
            
            result = plugin.run(target, http, **kwargs)
            
            # Handle both tuple (findings, count) and list returns
            if isinstance(result, tuple) and len(result) == 2:
                plugin_findings, plugin_test_count = result
                total_tests += plugin_test_count
                if plugin_findings:
                    findings.extend(plugin_findings)
            else:
                # Single list return (other plugins)
                plugin_findings = result
                if plugin_findings:
                    findings.extend(plugin_findings)
                    total_tests += len(plugin_findings)
        except Exception as exc:
            print(f"[-] Plugin {getattr(plugin, '__name__', plugin)} error: {exc}")
    return findings, total_tests
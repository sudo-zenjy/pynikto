"""
PyNikto Python API
==================

This module provides a programmatic interface to PyNikto for integration
with other Python tools and automation scripts.

Example usage:
    from pynikto import PyNiktoScanner
    
    scanner = PyNiktoScanner()
    results = scanner.scan("https://example.com")
    
    # Access findings
    for finding in results.findings:
        print(f"{finding.risk}: {finding.message}")
    
    # Export to different formats
    results.export_json("results.json")
    results.export_sarif("results.sarif")
"""

from typing import List, Optional, Dict, Any
import time
from dataclasses import dataclass

from targets import Target, build_targets_from_cli
from http_client import HttpClient
from plugin_loader import load_plugins, run_plugins_for_target
from statistics import ScanStatistics
from findings import Finding
from config import load_config
from nikto import scan_target, detect_404_signatures
from output_formatters import (
    format_json, format_xml, format_csv, format_sarif,
    format_junit_xml, format_html
)


@dataclass
class ScanResults:
    """Container for scan results"""
    findings: List[Finding]
    statistics: ScanStatistics
    target: str
    start_time: str
    end_time: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert results to dictionary"""
        return {
            "target": self.target,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "statistics": {
                "items_tested": self.statistics.items_tested,
                "items_found": self.statistics.items_found,
                "errors": self.statistics.errors,
                "high_risk": self.statistics.high_risk,
                "medium_risk": self.statistics.medium_risk,
                "info": self.statistics.info,
            },
            "findings": [f.to_dict() for f in self.findings]
        }
    
    def export_json(self, filename: str) -> None:
        """Export results to JSON file"""
        content = format_json(self.findings, self.statistics, self.target)
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
    
    def export_xml(self, filename: str) -> None:
        """Export results to XML file"""
        content = format_xml(self.findings, self.statistics, self.target, self.start_time, self.end_time)
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
    
    def export_csv(self, filename: str) -> None:
        """Export results to CSV file"""
        content = format_csv(self.findings, self.statistics, self.target)
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
    
    def export_sarif(self, filename: str) -> None:
        """Export results to SARIF file (for GitHub Security, CodeQL, etc.)"""
        content = format_sarif(self.findings, self.statistics, self.target, self.start_time, self.end_time)
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
    
    def export_junit(self, filename: str) -> None:
        """Export results to JUnit XML file (for CI/CD pipelines)"""
        content = format_junit_xml(self.findings, self.statistics, self.target, self.start_time, self.end_time)
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
    
    def export_html(self, filename: str) -> None:
        """Export results to HTML report"""
        content = format_html(self.findings, self.statistics, self.target, self.start_time, self.end_time)
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
    
    def get_findings_by_risk(self, risk: str) -> List[Finding]:
        """Get findings filtered by risk level"""
        return [f for f in self.findings if f.risk.lower() == risk.lower()]
    
    def get_findings_by_plugin(self, plugin: str) -> List[Finding]:
        """Get findings filtered by plugin name"""
        return [f for f in self.findings if f.plugin == plugin]


class PyNiktoScanner:
    """
    Main scanner class for programmatic use.
    
    Example:
        scanner = PyNiktoScanner()
        results = scanner.scan("https://example.com", threads=10)
        print(f"Found {len(results.findings)} issues")
    """
    
    def __init__(
        self,
        timeout: float = 30.0,
        proxy: Optional[str] = None,
        verify_ssl: bool = True,
        user_agent: Optional[str] = None,
        follow_redirects: bool = True,
    ):
        """
        Initialize PyNikto scanner.
        
        Args:
            timeout: Request timeout in seconds
            proxy: Proxy URL (e.g., "http://proxy:8080")
            verify_ssl: Whether to verify SSL certificates
            user_agent: Custom user agent string
            follow_redirects: Whether to follow HTTP redirects
        """
        self.timeout = timeout
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self.user_agent = user_agent or "PyNikto/0.1"
        self.follow_redirects = follow_redirects
        self.config = load_config()
    
    def scan(
        self,
        target: str,
        port: str = "80",
        ssl: bool = False,
        threads: int = 10,
        max_workers: int = 50,
        tuning: Optional[str] = None,
        disable_404: bool = False,
        ignore_404_codes: Optional[List[int]] = None,
        ignore_404_string: str = "",
        root: str = "",
        pause: float = 0.0,
        crawl_enabled: bool = False,
        crawl_depth: int = 3,
        crawl_max: int = 500,
        respect_robots: bool = True,
        output_format: str = "text",
        verbose: bool = False,
    ) -> ScanResults:
        """
        Perform a scan on the target.
        
        Args:
            target: Target hostname or URL
            port: Port number (default: "80")
            ssl: Use SSL/TLS (default: False)
            threads: Number of concurrent threads (default: 10)
            max_workers: Max workers for plugin execution (default: 50)
            tuning: Tuning filter (e.g., "1,2,3" for specific test categories)
            disable_404: Disable 404 detection (default: False)
            ignore_404_codes: List of HTTP codes to ignore as 404s
            ignore_404_string: String in response body to ignore as 404
            root: Prepend root directory to all requests
            pause: Pause between tests in seconds
            crawl_enabled: Enable website crawling (default: False)
            crawl_depth: Maximum crawl depth (default: 3)
            crawl_max: Maximum URLs to crawl (default: 500)
            respect_robots: Respect robots.txt (default: True)
            output_format: Output format (not used in API, use export methods)
            verbose: Print verbose output (default: False)
        
        Returns:
            ScanResults object containing findings and statistics
        """
        start_time = time.ctime()
        
        # Build targets
        targets = build_targets_from_cli(target, port, ssl)
        if not targets:
            raise ValueError(f"Invalid target: {target}")
        
        target_obj = targets[0]
        
        # Initialize HTTP client
        http = HttpClient(
            timeout=self.timeout,
            proxy=self.proxy or self.config.get("proxy"),
            use_evasion=False,
            verify_ssl=self.verify_ssl,
            user_agent=self.user_agent,
        )
        
        # Load plugins
        plugins = load_plugins(self.config)
        
        # Parse tuning
        tuning_set = set(tuning.replace(",", "").replace(" ", "")) if tuning else set()
        
        # Parse ignore_404_codes
        if ignore_404_codes is None:
            ignore_404_codes = []
        
        # Detect 404 signatures
        notfound_sigs = detect_404_signatures(target_obj, http, disable_404)
        
        # Run scan
        all_findings: List[Finding] = []
        stats = ScanStatistics()
        
        for plugin in plugins:
            try:
                if pause > 0:
                    time.sleep(pause)
                
                plugin_findings, plugin_test_count = run_plugins_for_target(
                    target_obj,
                    http,
                    [plugin],
                    tuning_set,
                    max_workers,
                    notfound_sigs,
                    ignore_404_codes,
                    ignore_404_string,
                    self.follow_redirects,
                    root,
                    crawl_enabled,
                    crawl_depth,
                    crawl_max,
                    respect_robots,
                )
                
                if plugin_findings:
                    all_findings.extend(plugin_findings)
                    for f in plugin_findings:
                        stats.add_finding(f.risk)
                
                stats.increment_tested(plugin_test_count)
            except Exception as exc:
                stats.increment_error()
                if verbose:
                    print(f"[-] Plugin error: {exc}")
        
        end_time = time.ctime()
        
        return ScanResults(
            findings=all_findings,
            statistics=stats,
            target=target_obj.base_url,
            start_time=start_time,
            end_time=end_time,
        )


# Convenience function for quick scans
def quick_scan(target: str, **kwargs) -> ScanResults:
    """
    Quick scan function for simple use cases.
    
    Example:
        results = quick_scan("https://example.com")
        print(f"Found {len(results.findings)} issues")
    """
    scanner = PyNiktoScanner(**{k: v for k, v in kwargs.items() if k in [
        "timeout", "proxy", "verify_ssl", "user_agent", "follow_redirects"
    ]})
    return scanner.scan(target, **{k: v for k, v in kwargs.items() if k not in [
        "timeout", "proxy", "verify_ssl", "user_agent", "follow_redirects"
    ]})

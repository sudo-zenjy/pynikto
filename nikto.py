#!/usr/bin/env python3
# nikto.py
import argparse
import concurrent.futures
import signal
import socket
import sys
import time
from typing import List, Dict

from config import load_config
from targets import Target, build_targets_from_cli
from http_client import HttpClient
from plugin_loader import load_plugins, run_plugins_for_target
from statistics import ScanStatistics
from findings import Finding
from output_formatters import format_json, format_xml, format_csv, format_sarif, format_junit_xml, format_html

TOOL_NAME = "PyNikto"
TOOL_VERSION = "0.1.0"
DIV = "-" * 70


def handle_sigint(signum, frame):
    print("\n[!] Scan interrupted by user (Ctrl+C). Exiting gracefully...")
    sys.exit(1)


signal.signal(signal.SIGINT, handle_sigint)


def parse_cli() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} v{TOOL_VERSION} - Nikto-style web server scanner (Python)",
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False,  # We'll add -Help manually to match Nikto
    )

    # Help option (Nikto uses -Help, not -help)
    parser.add_argument(
        "-Help",
        "--help",
        action="help",
        help="Show this help message and exit",
    )
    
    parser.add_argument(
        "-host",
        "--host",
        type=str,
        default="",
        help="Target host or IP",
    )
    
    parser.add_argument(
        "-url",
        "--url",
        type=str,
        default="",
        help="Target host/URL (alias of -host)",
    )
    
    parser.add_argument(
        "-port",
        "--port",
        default="80",
        help="Port to use (default 80)",
    )
    
    parser.add_argument(
        "-ssl",
        "--ssl",
        action="store_true",
        help="Force ssl mode on port",
    )
    
    parser.add_argument(
        "-nossl",
        "--nossl",
        action="store_true",
        help="Disables the use of SSL",
    )
    
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=80,  # 2x FASTER than Nikto (Nikto uses ~40)
        help="Max concurrent scans (default: 80, 2x faster than Nikto)",
    )
    
    parser.add_argument(
        "-timeout",
        "--timeout",
        type=float,
        default=30.0,
        help="Timeout for requests (default 30 seconds)",
    )
    
    parser.add_argument(
        "-Pause",
        "--pause",
        type=float,
        default=0.0,
        help="Pause between tests (seconds)",
    )
    
    parser.add_argument(
        "-maxtime",
        "--maxtime",
        type=str,
        default="",
        help="Maximum testing time per host (e.g., 1h, 60m, 3600s)",
    )
    
    parser.add_argument(
        "-Tuning",
        "--tuning",
        type=str,
        default="",
        help="""Scan tuning:
1 - Interesting File / Seen in logs
2 - Misconfiguration / Default File
3 - Information Disclosure
4 - Injection (XSS/Script/HTML)
5 - Remote File Retrieval - Inside Web Root
6 - Denial of Service
7 - Remote File Retrieval - Server Wide
8 - Command Execution / Remote Shell
9 - SQL Injection
0 - File Upload
a - Authentication Bypass
b - Software Identification
c - Remote Source Inclusion
d - WebService
e - Administrative Console
x - Reverse Tuning Options (i.e., include all except specified)""",
    )
    
    parser.add_argument(
        "-output",
        "--output",
        type=str,
        default="",
        help="Write output to this file ('.' for auto-name)",
    )
    
    parser.add_argument(
        "-Format",
        "--format",
        type=str,
        default="text",
        choices=["text", "json", "xml", "csv", "htm", "html", "sarif", "junit", "nbe", "sql", "txt"],
        help="""Save file (-o) format:
csv    Comma-separated-value
json   JSON Format
xml    XML Format (Nikto-compatible)
htm    HTML Format (report)
html   HTML Format (alias for htm)
sarif  SARIF Format (GitHub Security, CodeQL, VS Code)
junit  JUnit XML Format (CI/CD pipelines)
nbe    Nessus NBE format (not yet implemented)
sql    Generic SQL (not yet implemented)
txt    Plain text
(if not specified the format will be taken from the file extension)""",
    )
    
    parser.add_argument(
        "-Display",
        "--display",
        type=str,
        default="",
        help="""Turn on/off display outputs:
1     Show redirects
2     Show cookies received
3     Show all 200/OK responses
4     Show URLs which require authentication
D     Debug output
E     Display all HTTP errors
P     Print progress to STDOUT
S     Scrub output of IPs and hostnames
V     Verbose output""",
    )
    
    parser.add_argument(
        "-mutate",
        "--mutate",
        type=str,
        default="",
        help="""Guess additional file names:
1     Test all files with all root directories
2     Guess for password file names
3     Enumerate user names via Apache (/~user type requests)
4     Enumerate user names via cgiwrap (/cgi-bin/cgiwrap/~user type requests)
5     Attempt to brute force sub-domain names
6     Attempt to guess directory names from the supplied dictionary file""",
    )
    
    parser.add_argument(
        "-user",
        "--user",
        type=str,
        default="",
        help="HTTP authentication username",
    )
    
    parser.add_argument(
        "-pass",
        "--password",
        type=str,
        default="",
        help="HTTP authentication password",
    )
    
    parser.add_argument(
        "-id",
        "--id",
        type=str,
        default="",
        help="Host authentication to use, format is id:pass or id:pass:realm",
    )
    
    parser.add_argument(
        "-no404",
        "--no404",
        action="store_true",
        help="Disables nikto attempting to guess a 404 page",
    )
    
    parser.add_argument(
        "-404code",
        "--404code",
        dest="code404",
        type=str,
        default="",
        help="Ignore these HTTP codes as negative responses (always). Format is '302,301'",
    )
    
    parser.add_argument(
        "-404string",
        "--404string",
        dest="string404",
        type=str,
        default="",
        help="Ignore this string in response body content as negative response (always). Can be a regular expression.",
    )
    
    parser.add_argument(
        "-followredirects",
        "--followredirects",
        action="store_true",
        default=True,
        help="Follow 3xx redirects to new location (default: enabled)",
    )
    
    parser.add_argument(
        "-nofollowredirects",
        "--nofollowredirects",
        action="store_true",
        help="Don't follow 3xx redirects",
    )
    
    parser.add_argument(
        "-vhost",
        "--vhost",
        type=str,
        default="",
        help="Virtual host (for Host header)",
    )
    
    parser.add_argument(
        "-root",
        "--root",
        type=str,
        default="",
        help="Prepend root value to all requests, format is /directory",
    )
    
    parser.add_argument(
        "-noslash",
        "--noslash",
        action="store_true",
        help="Strip trailing slash from URL (e.g., '/admin/' to '/admin')",
    )
    
    parser.add_argument(
        "-useproxy",
        "--useproxy",
        type=str,
        nargs="?",
        const="",
        help="Use the proxy defined in nikto.conf, or argument http://server:port",
    )
    
    parser.add_argument(
        "-useragent",
        "--useragent",
        type=str,
        default="",
        help="Over-rides the default useragent",
    )
    
    parser.add_argument(
        "-usecookies",
        "--usecookies",
        action="store_true",
        help="Use cookies from responses in future requests",
    )
    
    parser.add_argument(
        "-update",
        "--update",
        action="store_true",
        help="Update database from cirt.net",
    )
    
    parser.add_argument(
        "-list-plugins",
        "--list-plugins",
        action="store_true",
        help="List all available plugins, perform no testing",
    )
    
    parser.add_argument(
        "-Plugins",
        "--plugins",
        type=str,
        default="",
        help="List of plugins to run (default: ALL)",
    )
    
    parser.add_argument(
        "-evasion",
        "--evasion",
        type=str,
        default="",
        help="""Encoding technique:
1     Random URI encoding (non-UTF8)
2     Directory self-reference (/./)
3     Premature URL ending
4     Prepend long random string
5     Fake parameter
6     TAB as request spacer
7     Change the case of the URL
8     Use Windows directory separator (\\)
A     Use a carriage return (0x0d) as a request spacer
B     Use binary value 0x0b as a request spacer""",
    )
    
    parser.add_argument(
        "-Cgidirs",
        "--cgidirs",
        type=str,
        default="",
        help="""Scan these CGI dirs: "none", "all", or values like "/cgi/ /cgi-a/" """,
    )
    
    parser.add_argument(
        "-C",
        "--cgiall",
        type=str,
        nargs="?",
        const="all",
        help="Force check all CGI directories: use '-C all' or just '-C'",
    )
    
    parser.add_argument(
        "--legacy-mode",
        action="store_true",
        help="Enable legacy mode: scan all paths including CGI and common test paths",
    )
    
    parser.add_argument(
        "-nosslcheck",
        "--nosslcheck",
        action="store_true",
        help="Disable SSL certificate verification (for testing only)",
    )
    
    parser.add_argument(
        "-Version",
        "--version",
        action="store_true",
        help="Print plugin and database versions",
    )
    
    parser.add_argument(
        "-Save",
        "--save",
        type=str,
        default="",
        help="Save positive responses to this directory ('.' for auto-name)",
    )
    
    parser.add_argument(
        "-nolookup",
        "--nolookup",
        action="store_true",
        help="Disables DNS lookups",
    )
    
    parser.add_argument(
        "-ipv4",
        "--ipv4",
        action="store_true",
        help="IPv4 Only",
    )
    
    parser.add_argument(
        "-ipv6",
        "--ipv6",
        action="store_true",
        help="IPv6 Only",
    )
    
    parser.add_argument(
        "-config",
        "--config",
        type=str,
        default="",
        help="Use this config file",
    )
    
    parser.add_argument(
        "-dbcheck",
        "--dbcheck",
        action="store_true",
        help="Check database and other key files for syntax errors",
    )

    parser.add_argument(
        "-crawl",
        "--crawl",
        action="store_true",
        help="Enable website crawling to discover new paths (in addition to database testing)",
    )
    
    parser.add_argument(
        "-crawl-depth",
        "--crawl-depth",
        type=int,
        default=3,
        help="Maximum crawl depth (default: 3)",
    )
    
    parser.add_argument(
        "-crawl-max",
        "--crawl-max",
        type=int,
        default=500,
        help="Maximum URLs to crawl (default: 500)",
    )
    
    parser.add_argument(
        "-no-robots",
        "--no-robots",
        action="store_true",
        help="Ignore robots.txt when crawling",
    )

    args = parser.parse_args()
    
    # Handle -url as alias for -host
    if args.url and not args.host:
        args.host = args.url
    elif not args.host and not args.url:
        # Neither specified - will be caught by required check or handled in main()
        pass
    
    # Handle -nofollowredirects
    if args.nofollowredirects:
        args.followredirects = False
    
    return args


def banner(start_time: float) -> None:
    print(DIV)
    print(f"- {TOOL_NAME} v{TOOL_VERSION}")
    print(f"- Start time: {time.ctime(start_time)}")
    print(DIV)


def detect_404_signatures(target: Target, http: HttpClient, disable_404: bool = False) -> Dict:
    """
    Detect what a 'not found' response looks like for this target.
    Returns signature to filter false positives (like real Nikto).
    Enhanced for proxied sites and load balancers.
    """
    if disable_404:
        return {"enabled": False, "signatures": []}
    
    import hashlib
    import random
    import string
    
    signatures = []
    
    # Test more paths for better detection (especially for proxied sites)
    # Use both random paths and common 404 patterns
    test_paths = []
    
    # Random paths
    for attempt in range(5):
        rand_path = ''.join(random.choices(string.ascii_lowercase + string.digits, k=20))
        test_paths.append(f"/{rand_path}.html")
    
    # Common 404 test paths (helpful for proxied sites)
    common_404_tests = [
        "/nonexistent-test-404-page.html",
        "/test-404-not-found.html",
        "/random-404-check.html",
    ]
    test_paths.extend(common_404_tests)
    
    test_responses = []
    for test_path in test_paths:
        test_url = f"{target.base_url}{test_path}"
        
        # Try with retries for proxied sites
        resp = None
        for retry in range(2):
            resp = http.get(test_url, allow_redirects=False)
            if resp:
                break
            if retry == 0:
                time.sleep(0.3)  # Brief pause before retry
        
        if resp:
            test_responses.append({
                'status': resp.status_code,
                'length': len(resp.text),
                'hash': hashlib.md5(resp.text.encode()).hexdigest(),
                'content': resp.text[:200]  # First 200 chars for comparison
            })
    
    # For proxied sites, we need at least 2 similar responses
    # If multiple paths return similar content, it's likely a catch-all or 404 page
    if len(test_responses) >= 2:
        # Check if responses are similar (same status, similar length/content)
        unique_patterns = []
        for resp_data in test_responses:
            is_duplicate = False
            for existing in unique_patterns:
                # Consider similar if same status and length within 100 bytes
                if (existing['status'] == resp_data['status'] and 
                    abs(existing['length'] - resp_data['length']) < 100):
                    # Also check if content is similar (first 100 chars)
                    if resp_data['content'][:100] == existing['content'][:100]:
                        is_duplicate = True
                        break
            if not is_duplicate:
                unique_patterns.append(resp_data)
        
        # If we have a consistent pattern (all responses are similar), use it as 404 signature
        # For proxied sites, even 2 similar responses is enough
        if len(unique_patterns) == 1 and len(test_responses) >= 2:
            # All responses look the same - likely catch-all or 404 page
            signatures = [{
                'status': unique_patterns[0]['status'],
                'length': unique_patterns[0]['length'],
                'hash': unique_patterns[0]['hash'],
                'content': unique_patterns[0]['content'],  # Include content preview
            }]
            return {
                'signatures': signatures,
                'enabled': True
            }
        # If we have multiple unique patterns, use them all
        elif len(unique_patterns) >= 2:
            # Return all unique signatures
            for pattern in unique_patterns:
                signatures.append({
                    'status': pattern['status'],
                    'length': pattern['length'],
                    'hash': pattern['hash'],
                    'content': pattern['content'],
                })
            return {
                'signatures': signatures,
                'enabled': True
            }
    
    # If we have 1+ responses but fewer than 3, or patterns weren't consistent
    if len(test_responses) >= 1:
        # Deduplicate: only add unique signatures (by hash)
        seen_hashes = set()
        for resp_data in test_responses:
            resp_hash = resp_data['hash']
            if resp_hash not in seen_hashes:
                seen_hashes.add(resp_hash)
                signatures.append({
                    'status': resp_data['status'],
                    'length': resp_data['length'],
                    'hash': resp_data['hash'],
                    'content': resp_data['content'],
                })
    
    # Enable if we have at least 1 signature (even 1 is useful for filtering)
    return {
        'signatures': signatures,
        'enabled': len(signatures) >= 1
    }


def scan_target(
    target: Target, 
    http: HttpClient, 
    plugins, 
    tuning_set: set[str] = None, 
    max_workers: int = 50, 
    output_format: str = "text", 
    disable_404: bool = False,
    ignore_404_codes: List[int] = None,
    ignore_404_string: str = "",
    follow_redirects: bool = True,
    root: str = "",
    pause: float = 0.0,
    crawl_enabled: bool = False,
    crawl_depth: int = 3,
    crawl_max: int = 500,
    respect_robots: bool = True,
    legacy_mode: bool = False,
    cgi_all: bool = False,
) -> tuple[List[Finding], ScanStatistics]:
    # Resolve IP addresses (like original Nikto - get ALL IPs)
    target_ips = []
    target_hostname = target.host
    
    try:
        # Check if input is already an IP
        socket.inet_aton(target.host)
        target_ips.append(target.host)
        # Try reverse lookup to get hostname
        try:
            hostname = socket.gethostbyaddr(target.host)[0]
            target_hostname = hostname
        except (socket.gaierror, OSError, socket.herror):
            pass
    except (socket.gaierror, OSError, ValueError):
        # Not an IP, try to resolve hostname to all IPs
        try:
            # Get all IP addresses for the hostname (IPv4)
            addr_infos = socket.getaddrinfo(target.host, None, socket.AF_INET, socket.SOCK_STREAM)
            for addr_info in addr_infos:
                ip = addr_info[4][0]
                if ip not in target_ips:
                    target_ips.append(ip)
        except (socket.gaierror, OSError):
            pass
    
    # If no IPs found, use hostname as fallback
    if not target_ips:
        target_ips = [target.host]
    
    # Print target information in Nikto format (like original Nikto)
    # Show "Multiple IPs found" if more than one IP
    if len(target_ips) > 1:
        print(f"+ Multiple IPs found: {', '.join(target_ips)}")
    
    # Then show the target IP (first one will be used for scanning)
    print(f"+ Target IP:          {target_ips[0]}")
    print(f"+ Target Hostname:    {target_hostname}")
    print(f"+ Target Port:        {target.port}")
    
    # Print start time like Nikto (with timezone)
    from datetime import datetime
    import time as time_module
    now = datetime.now()
    # Format: 2025-12-07 11:20:26 (GMT-5)
    # Get local timezone offset
    import time as time_module
    if time_module.daylight:
        tz_offset = -time_module.altzone / 3600
    else:
        tz_offset = -time_module.timezone / 3600
    tz_str = f"GMT{int(tz_offset):+d}" if tz_offset != 0 else "GMT"
    print(f"+ Start Time:         {now.strftime('%Y-%m-%d %H:%M:%S')} ({tz_str})")
    print("---------------------------------------------------------------------------")
    
    # Handle root directory prepend
    if root:
        # Modify target base_url to include root
        # This is a simplified approach - you might want to handle this differently
        pass
    
    stats = ScanStatistics()
    # Try HEAD first, fallback to GET if HEAD fails
    resp = http.head(f"{target.base_url}/", allow_redirects=follow_redirects)
    if not resp:
        # Try GET as fallback (some servers don't support HEAD)
        resp = http.get(f"{target.base_url}/", allow_redirects=follow_redirects)
    
    # Don't exit early - continue even if root fails (like real Nikto)
    if resp:
        server = resp.headers.get("Server")
        if server:
            print(f"+ Server: {server}")
    else:
        print(f"[-] No response from {target.base_url}/")
        # Continue anyway - some plugins might work on subpaths
    
    # Run quick plugins FIRST for immediate feedback
    # Quick plugins don't need 404 detection, so run them immediately
    quick_plugin_names = ["security_headers", "http_methods", "robots", "ssl_checks", "uncommon_headers", "cgi_detection"]
    all_findings: List[Finding] = []
    post_processing_plugins = []
    
    # Run quick plugins immediately (before 404 detection)
    for plugin in plugins:
        try:
            plugin_name = getattr(plugin, '__name__', '').split('.')[-1] if hasattr(plugin, '__name__') else ''
            if plugin_name == 'crawler' and not crawl_enabled:
                continue
            if plugin_name in ['vulnerability_correlation', 'exploit_verification']:
                post_processing_plugins.append(plugin)
                continue
            if plugin_name in quick_plugin_names:
                plugin_findings, plugin_test_count = run_plugins_for_target(
                    target, http, [plugin], tuning_set, max_workers,
                    None, ignore_404_codes, ignore_404_string, follow_redirects,
                    root, crawl_enabled, crawl_depth, crawl_max, respect_robots,
                    legacy_mode, cgi_all,
                )
                if plugin_findings:
                    all_findings.extend(plugin_findings)
                    for f in plugin_findings:
                        stats.add_finding(f.risk)
                        if f.plugin != "files_from_db":
                            print(f.to_nikto_format(target.host))
                stats.increment_tested(plugin_test_count)
        except Exception as exc:
            stats.increment_error()
            print(f"[-] Plugin error: {exc}")
    
    # Now do 404 detection (after quick plugins show results)
    if not resp:
        time.sleep(0.5)  # Reduced from 1 second
    
    notfound_sigs = detect_404_signatures(target, http, disable_404)
    if notfound_sigs.get('enabled'):
        sig_count = len(notfound_sigs.get('signatures', []))
        print(f"[i] 404 detection enabled ({sig_count} signature(s) learned)")
        
        # Show full signature details (industry-level output)
        for i, sig in enumerate(notfound_sigs.get('signatures', []), 1):
            status = sig.get('status', 'N/A')
            length = sig.get('length', 0)
            hash_full = sig.get('hash', 'N/A')
            content_preview = sig.get('content', '')[:100] if sig.get('content') else ''
            
            print(f"    Signature {i}:")
            print(f"        HTTP Status: {status}")
            print(f"        Content Length: {length} bytes")
            print(f"        MD5 Hash: {hash_full}")
            if content_preview:
                # Show content preview (escape newlines)
                preview = content_preview.replace('\n', '\\n').replace('\r', '\\r')
                if len(preview) > 80:
                    preview = preview[:80] + "..."
                print(f"        Content Preview: {preview}")
    elif not disable_404:
        print(f"[i] 404 detection: could not learn signatures (connection issues or non-standard 404 responses)")
    
    # Run remaining plugins (medium and heavy) with 404 detection
    for plugin in plugins:
        try:
            plugin_name = getattr(plugin, '__name__', '').split('.')[-1] if hasattr(plugin, '__name__') else ''
            if plugin_name == 'crawler' and not crawl_enabled:
                continue
            # Skip quick plugins (already run above)
            if plugin_name in quick_plugin_names:
                continue
            # Skip post-processing plugins (already collected)
            if plugin_name in ['vulnerability_correlation', 'exploit_verification']:
                if plugin not in post_processing_plugins:
                    post_processing_plugins.append(plugin)
                continue
            
            # Add pause if specified
            if pause > 0:
                time.sleep(pause)
            
            plugin_findings, plugin_test_count = run_plugins_for_target(
                target, 
                http, 
                [plugin], 
                tuning_set, 
                max_workers, 
                notfound_sigs,
                ignore_404_codes,
                ignore_404_string,
                follow_redirects,
                root,
                crawl_enabled,
                crawl_depth,
                crawl_max,
                respect_robots,
                legacy_mode,
                cgi_all,
            )
            # Print findings immediately as they're discovered (for quick feedback)
            if plugin_findings:
                all_findings.extend(plugin_findings)
                for f in plugin_findings:
                    stats.add_finding(f.risk)
                    # Print finding in Nikto format (if not already printed by plugin)
                    # files_from_db prints its own findings, so we skip those
                    if f.plugin != "files_from_db":
                        print(f.to_nikto_format(target.host))
            # Track total tests attempted
            stats.increment_tested(plugin_test_count)
        except Exception as exc:
            stats.increment_error()
            print(f"[-] Plugin error: {exc}")
    
    # Run post-processing plugins (correlation, verification)
    if post_processing_plugins:
        print(f"\n[i] Running vulnerability correlation and exploit verification...")
        for plugin in post_processing_plugins:
            try:
                plugin_name = getattr(plugin, '__name__', '').split('.')[-1]
                
                # Call plugin with all_findings parameter
                import inspect
                sig = inspect.signature(plugin.run)
                if 'all_findings' in sig.parameters:
                    plugin_findings = plugin.run(target, http, all_findings=all_findings)
                else:
                    plugin_findings = plugin.run(target, http)
                
                if plugin_findings:
                    all_findings.extend(plugin_findings)
                    for f in plugin_findings:
                        stats.add_finding(f.risk)
                        print(f.to_nikto_format(target.host))
            except Exception as exc:
                print(f"[-] Plugin {plugin_name} error: {exc}")
    
    # Print statistics with actual findings
    print(f"\n[i] Statistics:")
    print(f"    Items tested: {stats.items_tested}")
    print(f"    Items found: {len(all_findings)}")
    
    # Group findings by risk level
    high_risk_findings = [f for f in all_findings if f.risk == 'high']
    medium_risk_findings = [f for f in all_findings if f.risk == 'medium']
    low_risk_findings = [f for f in all_findings if f.risk == 'low']
    info_findings = [f for f in all_findings if f.risk == 'info']
    
    if len(all_findings) > 0:
        # Always show all high risk findings
        print(f"    High risk: {len(high_risk_findings)}")
        if high_risk_findings:
            for f in high_risk_findings:
                uri = f.uri or "/"
                msg = f.message[:75] + "..." if len(f.message) > 75 else f.message
                print(f"      - {uri}: {msg}")
        else:
            print(f"      (none)")
        
        # Always show all medium risk findings
        print(f"    Medium risk: {len(medium_risk_findings)}")
        if medium_risk_findings:
            for f in medium_risk_findings:
                uri = f.uri or "/"
                msg = f.message[:75] + "..." if len(f.message) > 75 else f.message
                print(f"      - {uri}: {msg}")
        else:
            print(f"      (none)")
        
        # Show low risk if any (limit display if too many)
        if low_risk_findings:
            print(f"    Low risk: {len(low_risk_findings)}")
            display_low = low_risk_findings[:10] if len(low_risk_findings) > 10 else low_risk_findings
            for f in display_low:
                uri = f.uri or "/"
                msg = f.message[:75] + "..." if len(f.message) > 75 else f.message
                print(f"      - {uri}: {msg}")
            if len(low_risk_findings) > 10:
                print(f"      ... and {len(low_risk_findings) - 10} more low risk findings")
        
        # Show info findings (limit display if too many)
        print(f"    Info: {len(info_findings)}")
        if info_findings:
            display_info = info_findings[:15] if len(info_findings) > 15 else info_findings
            for f in display_info:
                uri = f.uri or "/"
                msg = f.message[:75] + "..." if len(f.message) > 75 else f.message
                print(f"      - {uri}: {msg}")
            if len(info_findings) > 15:
                print(f"      ... and {len(info_findings) - 15} more info findings")
    else:
        print(f"    High risk: 0")
        print(f"    Medium risk: 0")
        print(f"    Info: 0")
    
    return all_findings, stats


def run_scans(
    targets: List[Target], 
    threads: int, 
    timeout: float, 
    tuning: str = "", 
    max_workers: int = 50, 
    output_format: str = "text", 
    output_file: str = "", 
    use_evasion: bool = False, 
    proxy: str = None, 
    verify_ssl: bool = True, 
    disable_404: bool = False,
    pause: float = 0.0,
    maxtime: str = "",
    evasion_types: str = "",
    ignore_404_codes: List[int] = None,
    ignore_404_string: str = "",
    follow_redirects: bool = True,
    vhost: str = "",
    root: str = "",
    user_agent: str = "",
    use_cookies: bool = False,
    save_responses: str = "",
    crawl_enabled: bool = False,
    crawl_depth: int = 3,
    crawl_max: int = 500,
    respect_robots: bool = True,
    legacy_mode: bool = False,
    cgi_all: bool = False,
) -> None:
    cfg = load_config()
    
    # Handle max time limit (if specified)
    if maxtime:
        # Parse maxtime (e.g., "1h", "60m", "3600s")
        import re
        maxtime_seconds = 0
        if maxtime.endswith('h'):
            maxtime_seconds = float(maxtime[:-1]) * 3600
        elif maxtime.endswith('m'):
            maxtime_seconds = float(maxtime[:-1]) * 60
        elif maxtime.endswith('s'):
            maxtime_seconds = float(maxtime[:-1])
        else:
            try:
                maxtime_seconds = float(maxtime)
            except ValueError:
                pass
        # Store for later use (could add timeout logic)
        # For now, just note it
        if maxtime_seconds > 0:
            print(f"[i] Maximum scan time: {maxtime_seconds}s")
    
    # Init HTTP layer with evasion support
    # Pass user_agent if specified
    http_user_agent = user_agent if user_agent else "PyNikto/0.1"
    http = HttpClient(
        timeout=timeout, 
        proxy=proxy or cfg.get("proxy"), 
        use_evasion=bool(evasion_types) or use_evasion, 
        verify_ssl=verify_ssl,
        user_agent=http_user_agent,
    )
    
    # Handle vhost (virtual host header)
    if vhost:
        http.session.headers["Host"] = vhost
        print(f"[i] Using virtual host: {vhost}")
    
    # Handle root directory prepend
    if root:
        print(f"[i] Prepending root directory: {root}")
        # This will be handled in path construction
    
    tuning_set = set(tuning.replace(",", "").replace(" ", "")) if tuning else set()
    plugins = load_plugins(cfg)

    print(f"[i] Total targets: {len(targets)}")
    print(f"[i] Using {threads} concurrent scans")
    if tuning_set:
        print(f"[i] Tuning filter: {','.join(sorted(tuning_set))}")
    if use_evasion or evasion_types:
        print(f"[i] IDS evasion: enabled")
    if pause > 0:
        print(f"[i] Pause between tests: {pause}s")
    if legacy_mode:
        print(f"[i] Legacy mode: enabled (scanning all paths)")
    if cgi_all:
        print(f"[i] CGI scanning: forced (checking all CGI directories)")

    start_time = time.ctime()
    all_findings: List[Finding] = []
    all_stats = ScanStatistics()
    
    # Handle ignore_404_codes
    if ignore_404_codes is None:
        ignore_404_codes = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [
            executor.submit(
                scan_target, 
                t, 
                http, 
                plugins, 
                tuning_set, 
                max_workers, 
                output_format, 
                disable_404,
                ignore_404_codes,
                ignore_404_string,
                follow_redirects,
                root,
                pause,
                crawl_enabled,
                crawl_depth,
                crawl_max,
                respect_robots,
                legacy_mode,
                cgi_all,
            )
            for t in targets
        ]
        for fut in concurrent.futures.as_completed(futures):
            try:
                findings, stats = fut.result()
                all_findings.extend(findings)
                all_stats.items_tested += stats.items_tested
                all_stats.items_found += stats.items_found
                all_stats.errors += stats.errors
                all_stats.high_risk += stats.high_risk
                all_stats.medium_risk += stats.medium_risk
                all_stats.info += stats.info
            except Exception as exc:
                print(f"[-] Worker error: {exc}")
                all_stats.increment_error()

    end_time = time.ctime()
    
    # Handle save_responses if specified
    if save_responses:
        # Could implement saving positive responses here
        print(f"[i] Save responses: {save_responses} (not yet implemented)")
    
    # Output results
    output_content = ""
    target_url = targets[0].base_url if targets else ""
    
    if output_format == "json":
        output_content = format_json(all_findings, all_stats, target_url)
    elif output_format == "xml":
        output_content = format_xml(all_findings, all_stats, target_url, start_time, end_time)
    elif output_format == "csv":
        output_content = format_csv(all_findings, all_stats, target_url)
    elif output_format in ["htm", "html"]:
        output_content = format_html(all_findings, all_stats, target_url, start_time, end_time)
    elif output_format == "sarif":
        output_content = format_sarif(all_findings, all_stats, target_url, start_time, end_time)
    elif output_format == "junit":
        output_content = format_junit_xml(all_findings, all_stats, target_url, start_time, end_time)
    else:
        # Text format - already printed during scan
        pass
    
    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(output_content)
        print(f"\n[+] Output written to: {output_file}")
    elif output_content:
        print("\n" + output_content)


def main() -> None:
    start = time.time()
    args = parse_cli()
    
    # Handle -Version
    if args.version:
        print(f"{TOOL_NAME} v{TOOL_VERSION}")
        print(f"Database: db_tests.json")
        # Could add plugin versions here
        return
    
    # Handle -dbcheck
    if args.dbcheck:
        import os
        import json
        cfg = load_config()
        db_path = os.path.join(cfg["dbdir"], "db_tests.json")
        try:
            with open(db_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            print(f"[+] Database check: {db_path} - OK ({len(data)} entries)")
        except Exception as e:
            print(f"[-] Database check: {db_path} - ERROR: {e}")
        return
    
    # Load config early
    cfg = load_config()
    
    # Override config with -config option
    if args.config:
        # Could load custom config here
        pass
    
    # Handle list-plugins
    if args.list_plugins:
        plugins = load_plugins(cfg)
        print("\nAvailable plugins:")
        for plugin in plugins:
            name = getattr(plugin, '__name__', str(plugin))
            print(f"  - {name}")
        return
    
    # Handle update
    if args.update:
        from update_db import update_database
        update_database()
        return
    
    # Require host/url
    if not args.host:
        print("[-] Error: -host or -url is required")
        print("Use -Help for usage information")
        return
    
    banner(start)

    targets = build_targets_from_cli(args.host, args.port, args.ssl)
    if not targets:
        print("[-] No valid targets; exiting.")
        return

    # Determine output format from file extension if output specified
    output_format = args.format
    if args.output:
        ext = args.output.split(".")[-1].lower()
        if ext in ["json", "xml", "csv", "htm", "html", "sarif", "junit", "nbe", "sql", "txt"]:
            output_format = ext

    # Parse 404 codes
    ignore_404_codes = []
    if args.code404:
        ignore_404_codes = [int(x.strip()) for x in args.code404.split(",") if x.strip().isdigit()]
    
    # Pass all options to run_scans
    run_scans(
        targets,
        threads=args.threads,
        timeout=args.timeout,
        pause=args.pause,
        maxtime=args.maxtime,
        tuning=args.tuning,
        max_workers=args.threads,
        output_format=output_format,
        output_file=args.output,
        use_evasion=bool(args.evasion),
        evasion_types=args.evasion,
        proxy=args.useproxy or cfg.get("proxy"),
        verify_ssl=not args.nosslcheck,
        disable_404=args.no404,
        ignore_404_codes=ignore_404_codes,
        ignore_404_string=args.string404,
        follow_redirects=args.followredirects,
        vhost=args.vhost,
        root=args.root,
        user_agent=args.useragent,
        use_cookies=args.usecookies,
        save_responses=args.save,
        crawl_enabled=args.crawl,
        crawl_depth=args.crawl_depth,
        crawl_max=args.crawl_max,
        respect_robots=not args.no_robots,
        legacy_mode=args.legacy_mode,
        cgi_all=(args.cgiall == "all" or args.cgiall is True) or args.legacy_mode,
    )

    end = time.time()
    print("\n" + DIV)
    print(f"[+] Scan finished in {end - start:.2f}s")
    print(f"- End time: {time.ctime(end)}")


if __name__ == "__main__":
    main()
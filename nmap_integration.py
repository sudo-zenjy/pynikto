#!/usr/bin/env python3
"""
Nmap + PyNikto Integration Script
=================================

This script integrates Nmap port scanning with PyNikto web scanning.
It uses Nmap to discover web services and then automatically scans them with PyNikto.

Usage:
    # Basic usage - scan a host with Nmap, then PyNikto
    python nmap_integration.py example.com
    
    # Custom Nmap scan
    python nmap_integration.py example.com --nmap-args "-p 80,443,8080,8443"
    
    # Custom PyNikto options
    python nmap_integration.py example.com --pynikto-threads 20 --pynikto-format json
    
    # Output to file
    python nmap_integration.py example.com --output results.json

Examples:
    # Scan common web ports
    python nmap_integration.py example.com --nmap-args "-p 80,443,8080,8443,8000,8888"
    
    # Full port scan then web scan
    python nmap_integration.py example.com --nmap-args "-p-"
    
    # Scan with service detection
    python nmap_integration.py example.com --nmap-args "-sV -p 80,443"
"""

import argparse
import subprocess
import sys
import xml.etree.ElementTree as ET
import json
import os
from typing import List, Dict, Tuple, Optional
from pathlib import Path

# Import PyNikto components
from targets import Target, build_targets_from_cli
from http_client import HttpClient
from plugin_loader import load_plugins, run_plugins_for_target
from statistics import ScanStatistics
from findings import Finding
from config import load_config
from nikto import scan_target, detect_404_signatures
from output_formatters import format_json, format_xml, format_csv, format_sarif, format_junit_xml, format_html


def parse_nmap_xml(xml_file: str) -> List[Tuple[str, int, bool]]:
    """
    Parse Nmap XML output and extract web services.
    
    Returns:
        List of tuples: (host, port, is_ssl)
    """
    web_services = []
    common_web_ports = {80, 443, 8080, 8443, 8000, 8888, 9000, 3000, 5000, 7001, 7002}
    
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        for host in root.findall('host'):
            host_state = host.find('status')
            if host_state is None or host_state.get('state') != 'up':
                continue
            
            # Get hostname or IP
            hostnames = host.findall('hostnames/hostname')
            hostname = hostnames[0].get('name') if hostnames else None
            
            addresses = host.findall('address')
            ip = None
            for addr in addresses:
                if addr.get('addrtype') == 'ipv4':
                    ip = addr.get('addr')
                    break
            
            target_host = hostname or ip
            if not target_host:
                continue
            
            # Check ports
            ports = host.findall('ports/port')
            for port_elem in ports:
                port_state = port_elem.find('state')
                if port_state is None or port_state.get('state') != 'open':
                    continue
                
                port_num = int(port_elem.get('portid'))
                protocol = port_elem.get('protocol')
                
                if protocol != 'tcp':
                    continue
                
                # Check if it's a web service
                service = port_elem.find('service')
                service_name = service.get('name', '').lower() if service is not None else ''
                
                # Check if port is common web port or service indicates HTTP
                is_web = (
                    port_num in common_web_ports or
                    service_name in ['http', 'https', 'http-proxy', 'ssl/http', 'ssl/https'] or
                    'http' in service_name
                )
                
                if is_web:
                    is_ssl = port_num == 443 or port_num in [8443, 8444] or 'ssl' in service_name or 'https' in service_name
                    web_services.append((target_host, port_num, is_ssl))
                    print(f"[+] Found web service: {target_host}:{port_num} ({'HTTPS' if is_ssl else 'HTTP'})")
        
    except Exception as e:
        print(f"[-] Error parsing Nmap XML: {e}")
        return []
    
    return web_services


def run_nmap_scan(target: str, nmap_args: str = "", output_file: str = "nmap_scan.xml") -> str:
    """
    Run Nmap scan and return path to XML output file.
    
    Args:
        target: Target hostname or IP
        nmap_args: Additional Nmap arguments
        output_file: Output XML file path
    
    Returns:
        Path to Nmap XML output file
    """
    print(f"[*] Running Nmap scan on {target}...")
    
    # Build Nmap command
    cmd = ["nmap", "-oX", output_file]
    
    # Add custom arguments
    if nmap_args:
        # Split arguments safely
        import shlex
        cmd.extend(shlex.split(nmap_args))
    else:
        # Default: scan common web ports
        cmd.extend(["-p", "80,443,8080,8443,8000,8888"])
    
    # Add target
    cmd.append(target)
    
    print(f"[*] Nmap command: {' '.join(cmd)}")
    
    try:
        # Run Nmap
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3600  # 1 hour timeout
        )
        
        if result.returncode != 0:
            print(f"[-] Nmap scan failed:")
            print(result.stderr)
            return ""
        
        print(f"[+] Nmap scan completed. Results saved to {output_file}")
        return output_file
        
    except subprocess.TimeoutExpired:
        print(f"[-] Nmap scan timed out")
        return ""
    except FileNotFoundError:
        print(f"[-] Error: Nmap not found. Please install Nmap first.")
        print(f"    Install: https://nmap.org/download.html")
        return ""
    except Exception as e:
        print(f"[-] Error running Nmap: {e}")
        return ""


def scan_web_service(host: str, port: int, is_ssl: bool, pynikto_args: Dict) -> Tuple[List[Finding], ScanStatistics]:
    """
    Scan a web service with PyNikto.
    
    Args:
        host: Target hostname or IP
        port: Port number
        is_ssl: Whether to use SSL
        pynikto_args: Dictionary of PyNikto arguments
    
    Returns:
        Tuple of (findings, statistics)
    """
    print(f"\n{'='*70}")
    print(f"[*] Scanning {host}:{port} ({'HTTPS' if is_ssl else 'HTTP'})")
    print(f"{'='*70}")
    
    # Build target
    targets = build_targets_from_cli(host, str(port), is_ssl)
    if not targets:
        print(f"[-] Invalid target: {host}:{port}")
        return [], ScanStatistics()
    
    target = targets[0]
    
    # Initialize HTTP client
    cfg = load_config()
    http = HttpClient(
        timeout=pynikto_args.get('timeout', 30.0),
        proxy=pynikto_args.get('proxy') or cfg.get("proxy"),
        use_evasion=False,
        verify_ssl=pynikto_args.get('verify_ssl', True),
        user_agent=pynikto_args.get('user_agent', 'PyNikto/0.1'),
    )
    
    # Load plugins
    plugins = load_plugins(cfg)
    
    # Parse tuning
    tuning = pynikto_args.get('tuning', '')
    tuning_set = set(tuning.replace(",", "").replace(" ", "")) if tuning else set()
    
    # Detect 404 signatures
    disable_404 = pynikto_args.get('disable_404', False)
    notfound_sigs = detect_404_signatures(target, http, disable_404)
    
    # Run scan
    all_findings: List[Finding] = []
    stats = ScanStatistics()
    
    ignore_404_codes = pynikto_args.get('ignore_404_codes', [])
    ignore_404_string = pynikto_args.get('ignore_404_string', '')
    
    for plugin in plugins:
        try:
            plugin_findings, plugin_test_count = run_plugins_for_target(
                target,
                http,
                [plugin],
                tuning_set,
                pynikto_args.get('max_workers', 50),
                notfound_sigs,
                ignore_404_codes,
                ignore_404_string,
                pynikto_args.get('follow_redirects', True),
                pynikto_args.get('root', ''),
                pynikto_args.get('crawl_enabled', False),
                pynikto_args.get('crawl_depth', 3),
                pynikto_args.get('crawl_max', 500),
                pynikto_args.get('respect_robots', True),
            )
            
            if plugin_findings:
                all_findings.extend(plugin_findings)
                for f in plugin_findings:
                    stats.add_finding(f.risk)
            
            stats.increment_tested(plugin_test_count)
        except Exception as exc:
            stats.increment_error()
            print(f"[-] Plugin error: {exc}")
    
    return all_findings, stats


def main():
    parser = argparse.ArgumentParser(
        description="Nmap + PyNikto Integration - Discover web services with Nmap and scan with PyNikto",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument(
        "target",
        help="Target hostname or IP address"
    )
    
    parser.add_argument(
        "--nmap-args",
        default="",
        help="Additional Nmap arguments (e.g., '-p 80,443,8080' or '-sV -p-')"
    )
    
    parser.add_argument(
        "--nmap-xml",
        default="",
        help="Use existing Nmap XML file instead of running new scan"
    )
    
    parser.add_argument(
        "--pynikto-threads",
        type=int,
        default=10,
        help="PyNikto threads (default: 10)"
    )
    
    parser.add_argument(
        "--pynikto-timeout",
        type=float,
        default=30.0,
        help="PyNikto timeout (default: 30.0)"
    )
    
    parser.add_argument(
        "--pynikto-format",
        choices=["json", "xml", "csv", "sarif", "junit", "html", "text"],
        default="text",
        help="Output format (default: text)"
    )
    
    parser.add_argument(
        "--pynikto-tuning",
        default="",
        help="PyNikto tuning filter (e.g., '1,2,3')"
    )
    
    parser.add_argument(
        "--pynikto-crawl",
        action="store_true",
        help="Enable PyNikto crawling"
    )
    
    parser.add_argument(
        "--pynikto-crawl-depth",
        type=int,
        default=3,
        help="PyNikto crawl depth (default: 3)"
    )
    
    parser.add_argument(
        "--output",
        default="",
        help="Output file for results (format determined by extension or --pynikto-format)"
    )
    
    parser.add_argument(
        "--keep-nmap-xml",
        action="store_true",
        help="Keep Nmap XML file after scanning"
    )
    
    parser.add_argument(
        "--skip-nmap",
        action="store_true",
        help="Skip Nmap scan (use with --nmap-xml)"
    )
    
    args = parser.parse_args()
    
    # Determine output format
    output_format = args.pynikto_format
    if args.output:
        ext = args.output.split(".")[-1].lower()
        if ext in ["json", "xml", "csv", "sarif", "junit", "html", "htm"]:
            output_format = ext
    
    # Step 1: Run Nmap or use existing XML
    nmap_xml_file = args.nmap_xml
    if not args.skip_nmap and not nmap_xml_file:
        nmap_xml_file = run_nmap_scan(args.target, args.nmap_args)
        if not nmap_xml_file:
            print("[-] Failed to run Nmap scan. Exiting.")
            sys.exit(1)
    elif not nmap_xml_file:
        print("[-] Error: Must provide --nmap-xml or run Nmap scan")
        sys.exit(1)
    
    # Step 2: Parse Nmap XML
    print(f"\n[*] Parsing Nmap results from {nmap_xml_file}...")
    web_services = parse_nmap_xml(nmap_xml_file)
    
    if not web_services:
        print("[-] No web services found in Nmap scan results.")
        if not args.keep_nmap_xml and os.path.exists(nmap_xml_file):
            os.remove(nmap_xml_file)
        sys.exit(0)
    
    print(f"\n[+] Found {len(web_services)} web service(s) to scan")
    
    # Step 3: Scan each web service with PyNikto
    all_findings: List[Finding] = []
    all_stats = ScanStatistics()
    service_results: Dict[str, List[Finding]] = {}
    
    pynikto_args = {
        'timeout': args.pynikto_timeout,
        'max_workers': args.pynikto_threads,
        'tuning': args.pynikto_tuning,
        'crawl_enabled': args.pynikto_crawl,
        'crawl_depth': args.pynikto_crawl_depth,
        'crawl_max': 500,
        'respect_robots': True,
        'follow_redirects': True,
        'disable_404': False,
        'ignore_404_codes': [],
        'ignore_404_string': '',
        'root': '',
        'verify_ssl': True,
        'user_agent': 'PyNikto/0.1',
        'proxy': None,
    }
    
    for host, port, is_ssl in web_services:
        findings, stats = scan_web_service(host, port, is_ssl, pynikto_args)
        
        # Add service identifier to findings
        for finding in findings:
            finding.url = finding.url.replace(finding.url.split('/')[2], f"{host}:{port}")
        
        all_findings.extend(findings)
        all_stats.items_tested += stats.items_tested
        all_stats.items_found += stats.items_found
        all_stats.errors += stats.errors
        all_stats.high_risk += stats.high_risk
        all_stats.medium_risk += stats.medium_risk
        all_stats.info += stats.info
        
        service_key = f"{host}:{port}"
        service_results[service_key] = findings
    
    # Step 4: Output results
    print(f"\n{'='*70}")
    print(f"[+] Scan Summary")
    print(f"{'='*70}")
    print(f"Services scanned: {len(web_services)}")
    print(f"Total findings: {len(all_findings)}")
    print(f"High risk: {all_stats.high_risk}")
    print(f"Medium risk: {all_stats.medium_risk}")
    print(f"Info: {all_stats.info}")
    
    if args.output or output_format != "text":
        # Generate output content
        output_content = ""
        target_str = args.target
        
        if output_format == "json":
            output_content = format_json(all_findings, all_stats, target_str)
        elif output_format == "xml":
            output_content = format_xml(all_findings, all_stats, target_str, "", "")
        elif output_format == "csv":
            output_content = format_csv(all_findings, all_stats, target_str)
        elif output_format == "sarif":
            output_content = format_sarif(all_findings, all_stats, target_str, "", "")
        elif output_format == "junit":
            output_content = format_junit_xml(all_findings, all_stats, target_str, "", "")
        elif output_format in ["html", "htm"]:
            output_content = format_html(all_findings, all_stats, target_str, "", "")
        
        # Write to file
        output_file = args.output or f"nmap_pynikto_results.{output_format}"
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(output_content)
        print(f"\n[+] Results written to: {output_file}")
    
    # Cleanup
    if not args.keep_nmap_xml and os.path.exists(nmap_xml_file):
        os.remove(nmap_xml_file)
        print(f"[+] Cleaned up temporary Nmap XML file")


if __name__ == "__main__":
    main()

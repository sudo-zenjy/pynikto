import json
import xml.etree.ElementTree as ET
from typing import List
from datetime import datetime
from findings import Finding
from statistics import ScanStatistics

def format_json(findings: List[Finding], stats: ScanStatistics, target: str) -> str:
    """Format output as JSON like Nikto"""
    output = {
        "host": target,
        "items_found": stats.items_found,
        "items_tested": stats.items_tested,
        "errors": stats.errors,
        "high_risk": stats.high_risk,
        "medium_risk": stats.medium_risk,
        "info": stats.info,
        "findings": [f.to_dict() for f in findings]
    }
    return json.dumps(output, indent=2)


def format_xml(findings: List[Finding], stats: ScanStatistics, target: str, start_time: str = "", end_time: str = "") -> str:
    """Format output as XML like Nikto"""
    root = ET.Element("niktoscan")
    root.set("version", "0.1.0")
    root.set("scanstart", start_time)
    root.set("scanend", end_time)
    
    scandetails = ET.SubElement(root, "scandetails")
    scandetails.set("target", target)
    scandetails.set("itemsfound", str(stats.items_found))
    scandetails.set("itemstested", str(stats.items_tested))
    scandetails.set("errors", str(stats.errors))
    
    for f in findings:
        item = ET.SubElement(scandetails, "item")
        item.set("id", f.nikto_id or "000000")
        item.set("method", f.method)
        
        ET.SubElement(item, "uri").text = f.uri or f.url
        ET.SubElement(item, "description").text = f.message
        if f.references:
            ET.SubElement(item, "references").text = f.references
    
    statistics = ET.SubElement(scandetails, "statistics")
    statistics.set("itemsfound", str(stats.items_found))
    statistics.set("itemstested", str(stats.items_tested))
    statistics.set("errors", str(stats.errors))
    
    return ET.tostring(root, encoding="unicode")


def format_csv(findings: List[Finding], stats: ScanStatistics, target: str) -> str:
    """Format output as CSV"""
    import csv
    import io
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow(["Test ID", "Method", "URI", "Message", "Risk", "References", "Status"])
    
    # Data
    for f in findings:
        writer.writerow([
            f.nikto_id or "000000",
            f.method,
            f.uri or f.url,
            f.message,
            f.risk,
            f.references or "",
            f.status
        ])
    
    return output.getvalue()


def format_sarif(findings: List[Finding], stats: ScanStatistics, target: str, start_time: str = "", end_time: str = "") -> str:
    """
    Format output as SARIF (Static Analysis Results Interchange Format).
    Compatible with GitHub Security, CodeQL, VS Code, and many security tools.
    """
    # Map risk levels to SARIF severity
    risk_to_severity = {
        "high": "error",
        "medium": "warning",
        "info": "note",
        "low": "note"
    }
    
    # Map risk levels to SARIF level
    risk_to_level = {
        "high": "error",
        "medium": "warning",
        "info": "note",
        "low": "note"
    }
    
    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "PyNikto",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/yourusername/pynikto"
                }
            },
            "results": []
        }]
    }
    
    for f in findings:
        severity = risk_to_severity.get(f.risk.lower(), "note")
        level = risk_to_level.get(f.risk.lower(), "note")
        
        result = {
            "ruleId": f.nikto_id or "000000",
            "level": level,
            "message": {
                "text": f.message
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f.url
                    },
                    "region": {
                        "startLine": 1
                    }
                }
            }],
            "properties": {
                "risk": f.risk,
                "status": f.status,
                "method": f.method,
                "plugin": f.plugin
            }
        }
        
        if f.references:
            result["message"]["text"] += f" See: {f.references}"
        
        sarif["runs"][0]["results"].append(result)
    
    return json.dumps(sarif, indent=2)


def format_junit_xml(findings: List[Finding], stats: ScanStatistics, target: str, start_time: str = "", end_time: str = "") -> str:
    """
    Format output as JUnit XML format.
    Compatible with Jenkins, GitLab CI, GitHub Actions, and other CI/CD tools.
    """
    root = ET.Element("testsuites")
    root.set("name", "PyNikto Scan")
    root.set("tests", str(stats.items_tested))
    root.set("failures", str(stats.high_risk + stats.medium_risk))
    root.set("errors", str(stats.errors))
    root.set("time", "0")
    
    testsuite = ET.SubElement(root, "testsuite")
    testsuite.set("name", target)
    testsuite.set("tests", str(stats.items_tested))
    testsuite.set("failures", str(stats.high_risk + stats.medium_risk))
    testsuite.set("errors", str(stats.errors))
    testsuite.set("time", "0")
    
    # Add test cases for findings
    for f in findings:
        testcase = ET.SubElement(testsuite, "testcase")
        testcase.set("name", f"{f.method} {f.uri or f.url}")
        testcase.set("classname", f.plugin)
        
        # High and medium risk findings are failures
        if f.risk.lower() in ["high", "medium"]:
            failure = ET.SubElement(testcase, "failure")
            failure.set("message", f.message)
            failure.set("type", f.risk)
            failure.text = f"Risk: {f.risk}\nStatus: {f.status}\nURL: {f.url}\n{f.message}"
            if f.references:
                failure.text += f"\nReferences: {f.references}"
        else:
            # Info findings are skipped (not failures)
            pass
    
    return ET.tostring(root, encoding="unicode")


def format_html(findings: List[Finding], stats: ScanStatistics, target: str, start_time: str = "", end_time: str = "") -> str:
    """
    Format output as HTML report.
    """
    risk_colors = {
        "high": "#dc3545",      # Red
        "medium": "#ffc107",    # Yellow
        "info": "#17a2b8",      # Blue
        "low": "#6c757d"        # Gray
    }
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>PyNikto Scan Report - {target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat-box {{ background: white; padding: 15px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .stat-box h3 {{ margin: 0 0 10px 0; }}
        .stat-value {{ font-size: 24px; font-weight: bold; }}
        .findings {{ background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .finding {{ margin: 15px 0; padding: 15px; border-left: 4px solid; border-radius: 3px; background: #f8f9fa; }}
        .finding.high {{ border-color: {risk_colors['high']}; }}
        .finding.medium {{ border-color: {risk_colors['medium']}; }}
        .finding.info {{ border-color: {risk_colors['info']}; }}
        .finding.low {{ border-color: {risk_colors['low']}; }}
        .finding-header {{ font-weight: bold; margin-bottom: 5px; }}
        .finding-url {{ color: #0066cc; word-break: break-all; }}
        .finding-message {{ margin: 5px 0; }}
        .finding-meta {{ font-size: 12px; color: #666; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #2c3e50; color: white; }}
        tr:hover {{ background: #f5f5f5; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>PyNikto Scan Report</h1>
        <p><strong>Target:</strong> {target}</p>
        <p><strong>Scan Start:</strong> {start_time or 'N/A'}</p>
        <p><strong>Scan End:</strong> {end_time or 'N/A'}</p>
    </div>
    
    <div class="stats">
        <div class="stat-box">
            <h3>Items Tested</h3>
            <div class="stat-value">{stats.items_tested}</div>
        </div>
        <div class="stat-box">
            <h3>Items Found</h3>
            <div class="stat-value">{stats.items_found}</div>
        </div>
        <div class="stat-box">
            <h3>High Risk</h3>
            <div class="stat-value" style="color: {risk_colors['high']}">{stats.high_risk}</div>
        </div>
        <div class="stat-box">
            <h3>Medium Risk</h3>
            <div class="stat-value" style="color: {risk_colors['medium']}">{stats.medium_risk}</div>
        </div>
        <div class="stat-box">
            <h3>Info</h3>
            <div class="stat-value" style="color: {risk_colors['info']}">{stats.info}</div>
        </div>
    </div>
    
    <div class="findings">
        <h2>Findings ({len(findings)} total)</h2>
        <table>
            <thead>
                <tr>
                    <th>Risk</th>
                    <th>Method</th>
                    <th>URL</th>
                    <th>Message</th>
                    <th>Status</th>
                    <th>Test ID</th>
                </tr>
            </thead>
            <tbody>
"""
    
    for f in findings:
        risk_class = f.risk.lower()
        html += f"""                <tr>
                    <td><span style="color: {risk_colors.get(risk_class, '#000')}; font-weight: bold;">{f.risk.upper()}</span></td>
                    <td>{f.method}</td>
                    <td class="finding-url">{f.url}</td>
                    <td>{f.message}</td>
                    <td>{f.status}</td>
                    <td>{f.nikto_id or '000000'}</td>
                </tr>
"""
    
    html += """            </tbody>
        </table>
    </div>
</body>
</html>"""
    
    return html

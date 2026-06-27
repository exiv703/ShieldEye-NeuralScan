"""Report exporters: pure transformations from a scan result to an output format."""
import json
from typing import Dict, Any, Optional


def export_report(scan_result: Dict[str, Any], format: str = 'json', output_path: Optional[str] = None) -> str:
    if format == 'json':
        report = _export_json(scan_result)
    elif format == 'markdown':
        report = _export_markdown(scan_result)
    elif format == 'html':
        report = _export_html(scan_result)
    else:
        raise ValueError(f"Unsupported format: {format}. Use 'json', 'markdown', or 'html'.")

    if output_path:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report)

    return report


def _export_json(scan_result: Dict[str, Any]) -> str:
    return json.dumps(scan_result, indent=2, ensure_ascii=False)


def _export_markdown(scan_result: Dict[str, Any]) -> str:
    lines = []
    lines.append("# Security Scan Report\n")
    lines.append(f"**File:** `{scan_result.get('file_path', 'Unknown')}`\n")
    lines.append(f"**Security Score:** {scan_result.get('security_score', 0)}/100\n")
    lines.append(f"**Total Findings:** {len(scan_result.get('findings', []))}\n")

    risk_cats = scan_result.get('risk_categories', [])
    if risk_cats:
        lines.append("\n## Risk Categories\n")
        for cat in risk_cats:
            lines.append(f"- **{cat['category']}**: {cat['count']} issues (Max Severity: {cat['max_severity']})")

    findings = scan_result.get('findings', [])
    if findings:
        lines.append("\n## Findings\n")
        for i, finding in enumerate(findings, 1):
            lines.append(f"\n### {i}. {finding.get('description', 'Unknown Issue')}\n")
            lines.append(f"- **Line:** {finding.get('line', 'N/A')}")
            lines.append(f"- **Severity:** {finding.get('severity', 'Unknown')}")
            if 'confidence' in finding:
                lines.append(f"- **Confidence:** {finding['confidence']}")
            if 'category' in finding:
                lines.append(f"- **Category:** {finding['category']}")
            if 'cwe' in finding:
                lines.append(f"- **CWE:** {finding['cwe']}")
            if 'owasp' in finding:
                lines.append(f"- **OWASP:** {finding['owasp']}")
            if 'pci_dss' in finding:
                lines.append(f"- **PCI-DSS:** {finding['pci_dss']}")
            if 'nist' in finding:
                lines.append(f"- **NIST:** {finding['nist']}")

            lines.append(f"\n**Code:**\n```python\n{finding.get('code_snippet', '')}\n```\n")
            lines.append(f"**Explanation:** {finding.get('explanation', '')}\n")

            if 'remediation' in finding:
                lines.append(f"**Remediation:** {finding['remediation']}\n")

    return "\n".join(lines)


def _export_html(scan_result: Dict[str, Any]) -> str:
    import html
    findings = scan_result.get('findings', [])
    score = scan_result.get('security_score', 0)

    if score >= 80:
        score_color = "#28a745"
    elif score >= 60:
        score_color = "#ffc107"
    else:
        score_color = "#dc3545"

    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Scan Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        .score {{ font-size: 48px; font-weight: bold; color: {score_color}; }}
        .finding {{ border-left: 4px solid #007bff; padding: 15px; margin: 20px 0; background: #f8f9fa; }}
        .critical {{ border-left-color: #dc3545; }}
        .high {{ border-left-color: #fd7e14; }}
        .medium {{ border-left-color: #ffc107; }}
        .low {{ border-left-color: #28a745; }}
        .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; margin: 2px; }}
        .badge-critical {{ background: #dc3545; color: white; }}
        .badge-high {{ background: #fd7e14; color: white; }}
        .badge-medium {{ background: #ffc107; color: black; }}
        .badge-low {{ background: #28a745; color: white; }}
        code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; }}
        pre {{ background: #282c34; color: #abb2bf; padding: 15px; border-radius: 5px; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Security Scan Report</h1>
        <p><strong>File:</strong> <code>{html.escape(scan_result.get('file_path', 'Unknown'))}</code></p>
        <p><strong>Security Score:</strong> <span class="score">{score}/100</span></p>
        <p><strong>Total Findings:</strong> {len(findings)}</p>

        <h2>Findings</h2>
"""

    for i, finding in enumerate(findings, 1):
        severity = finding.get('severity', 'Medium').lower()
        severity_badge = f"badge-{severity}"

        html_content += f"""
        <div class="finding {severity}">
            <h3>{i}. {html.escape(finding.get('description', 'Unknown Issue'))}</h3>
            <p>
                <span class="badge {severity_badge}">{html.escape(finding.get('severity', 'Unknown'))}</span>
"""
        if 'confidence' in finding:
            html_content += f"""                <span class="badge" style="background: #6c757d; color: white;">Confidence: {html.escape(str(finding['confidence']))}</span>\n"""
        if 'cwe' in finding:
            html_content += f"""                <span class="badge" style="background: #17a2b8; color: white;">{html.escape(str(finding['cwe']))}</span>\n"""
        if 'owasp' in finding:
            html_content += f"""                <span class="badge" style="background: #6610f2; color: white;">{html.escape(str(finding['owasp']))}</span>\n"""

        html_content += f"""            </p>
            <p><strong>Line:</strong> {html.escape(str(finding.get('line', 'N/A')))}</p>
            <pre><code>{html.escape(finding.get('code_snippet', ''))}</code></pre>
            <p>{html.escape(finding.get('explanation', ''))}</p>
"""
        if 'remediation' in finding:
            html_content += f"""            <p><strong>🔧 Remediation:</strong> {html.escape(finding['remediation'])}</p>\n"""

        html_content += """        </div>\n"""

    html_content += """    </div>
</body>
</html>"""

    return html_content

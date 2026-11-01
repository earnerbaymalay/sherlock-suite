"""
Report Generator for Sherlock OSINT Suite.
Supports JSON, Markdown, and HTML report exports.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Union
from .models import InvestigationResult, Severity


class ReportGenerator:
    def __init__(self, result: InvestigationResult):
        self.result = result

    def to_json(self, indent: int = 2) -> str:
        return self.result.model_dump_json(indent=indent)

    def to_markdown(self) -> str:
        res = self.result
        s = res.summary

        lines = [
            f"# Sherlock OSINT Investigation Report: {res.target.domain}",
            "",
            "## Executive Summary",
            f"- **Target Domain:** `{res.target.domain}`",
            f"- **Investigation Depth:** `{s.depth.value.upper()}`",
            f"- **Execution Date:** {s.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"- **Duration:** {s.duration_seconds} seconds",
            f"- **Overall Risk Score:** **{s.risk_score} / 100**",
            f"- **Total Discovered Hostnames / Subdomains:** {s.subdomains_count}",
            f"- **Total Findings:** {s.total_findings}",
            "",
            "### Finding Breakdown by Severity",
            "| Severity | Count |",
            "| :--- | :--- |",
        ]

        for sev in Severity:
            cnt = s.severity_counts.get(sev.value, 0)
            lines.append(f"| **{sev.value}** | {cnt} |")

        lines.extend([
            "",
            "## Discovered Attack Surface Hostnames",
        ])
        if s.subdomains:
            for sub in s.subdomains[:50]:
                lines.append(f"- `{sub}`")
            if len(s.subdomains) > 50:
                lines.append(f"- *...and {len(s.subdomains) - 50} more*")
        else:
            lines.append("_No additional hostnames discovered._")

        lines.extend([
            "",
            "## Detailed Findings",
        ])

        if not res.findings:
            lines.append("_No findings identified._")
        else:
            for i, f in enumerate(res.findings, 1):
                lines.extend([
                    f"### {i}. [{f.severity.value}] {f.title}",
                    f"- **Category:** {f.category.value}",
                    f"- **Target Asset:** `{f.target}`",
                    f"- **Discovered By:** {f.source_module}",
                    f"- **Timestamp:** {f.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                    "",
                    f"**Details:**",
                    f"> {f.description}",
                    "",
                ])
                if f.remediation:
                    lines.extend([
                        f"**Remediation Recommendation:**",
                        f"> {f.remediation}",
                        "",
                    ])

        return "\n".join(lines)

    def to_html(self) -> str:
        res = self.result
        s = res.summary
        score_color = "#10b981" if s.risk_score < 30 else ("#f59e0b" if s.risk_score < 60 else "#ef4444")

        sev_colors = {
            "INFO": "#06b6d4",
            "LOW": "#10b981",
            "MEDIUM": "#f59e0b",
            "HIGH": "#ec4899",
            "CRITICAL": "#ef4444",
        }

        sev_rows = ""
        for sev in Severity:
            cnt = s.severity_counts.get(sev.value, 0)
            col = sev_colors.get(sev.value, "#64748b")
            sev_rows += f"""
            <tr>
                <td><span style="display:inline-block;padding:2px 8px;border-radius:4px;font-weight:600;font-size:12px;background:{col}20;color:{col};border:1px solid {col}40;">{sev.value}</span></td>
                <td style="font-weight:bold;text-align:right;">{cnt}</td>
            </tr>
            """

        subdomains_html = ""
        if s.subdomains:
            for sub in s.subdomains[:100]:
                subdomains_html += f"<li style='margin-bottom:4px;font-family:monospace;font-size:13px;'><code>{sub}</code></li>\n"
            if len(s.subdomains) > 100:
                subdomains_html += f"<li><em>...and {len(s.subdomains) - 100} more hostnames</em></li>\n"
        else:
            subdomains_html = "<li><em>No subdomains discovered.</em></li>"

        findings_html = ""
        if not res.findings:
            findings_html = "<p style='color:#64748b;font-style:italic;'>No findings recorded.</p>"
        else:
            for i, f in enumerate(res.findings, 1):
                col = sev_colors.get(f.severity.value, "#64748b")
                rem_block = ""
                if f.remediation:
                    rem_block = f"""
                    <div style="margin-top:10px;padding:10px 14px;background:#fef3c7;border-left:4px solid #f59e0b;border-radius:4px;color:#92400e;font-size:13px;">
                        <strong>Remediation Recommendation:</strong> {f.remediation}
                    </div>
                    """
                findings_html += f"""
                <div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:8px;padding:16px;margin-bottom:14px;box-shadow:0 1px 3px rgba(0,0,0,0.05);">
                    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">
                        <span style="font-weight:700;font-size:15px;color:#0f172a;">{i}. {f.title}</span>
                        <span style="display:inline-block;padding:3px 10px;border-radius:9999px;font-size:12px;font-weight:700;background:{col}20;color:{col};border:1px solid {col}50;">{f.severity.value}</span>
                    </div>
                    <div style="font-size:12px;color:#64748b;margin-bottom:8px;">
                        <span><strong>Asset:</strong> <code>{f.target}</code></span> &bull; 
                        <span><strong>Category:</strong> {f.category.value}</span> &bull; 
                        <span><strong>Module:</strong> {f.source_module}</span>
                    </div>
                    <div style="color:#334155;font-size:13.5px;line-height:1.5;">
                        {f.description}
                    </div>
                    {rem_block}
                </div>
                """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sherlock OSINT Report - {res.target.domain}</title>
<style>
    body {{
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        background: #f8fafc;
        color: #1e293b;
        margin: 0;
        padding: 30px 20px;
        line-height: 1.6;
    }}
    .container {{
        max-width: 960px;
        margin: 0 auto;
    }}
    .header {{
        background: #0f172a;
        color: #ffffff;
        padding: 24px;
        border-radius: 12px;
        margin-bottom: 24px;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }}
    .stats-grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 16px;
        margin-bottom: 24px;
    }}
    .stat-card {{
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 16px;
        text-align: center;
    }}
    .stat-val {{
        font-size: 26px;
        font-weight: 800;
        margin-top: 4px;
    }}
    .card {{
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 10px;
        padding: 20px;
        margin-bottom: 24px;
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
    }}
    th, td {{
        padding: 8px 12px;
        border-bottom: 1px solid #e2e8f0;
        font-size: 13.5px;
    }}
    code {{
        background: #f1f5f9;
        padding: 2px 6px;
        border-radius: 4px;
        font-size: 12.5px;
        color: #0f172a;
    }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <h1 style="margin:0;font-size:22px;letter-spacing:-0.5px;">Sherlock Attack Surface & OSINT Report</h1>
            <p style="margin:4px 0 0;font-size:14px;color:#94a3b8;">Target Domain: <strong style="color:#ffffff;">{res.target.domain}</strong> &bull; Depth: {s.depth.value.upper()}</p>
        </div>
        <div style="text-align:right;">
            <div style="font-size:12px;color:#94a3b8;">Overall Risk Score</div>
            <div style="font-size:28px;font-weight:800;color:{score_color};">{s.risk_score} <span style="font-size:16px;color:#94a3b8;">/ 100</span></div>
        </div>
    </div>

    <div class="stats-grid">
        <div class="stat-card">
            <div style="font-size:12px;color:#64748b;font-weight:600;text-transform:uppercase;">Total Findings</div>
            <div class="stat-val" style="color:#0f172a;">{s.total_findings}</div>
        </div>
        <div class="stat-card">
            <div style="font-size:12px;color:#64748b;font-weight:600;text-transform:uppercase;">Hostnames Mapped</div>
            <div class="stat-val" style="color:#0284c7;">{s.subdomains_count}</div>
        </div>
        <div class="stat-card">
            <div style="font-size:12px;color:#64748b;font-weight:600;text-transform:uppercase;">Audit Duration</div>
            <div class="stat-val" style="color:#0f172a;">{s.duration_seconds}s</div>
        </div>
        <div class="stat-card">
            <div style="font-size:12px;color:#64748b;font-weight:600;text-transform:uppercase;">Generated Date</div>
            <div class="stat-val" style="font-size:15px;margin-top:10px;color:#475569;">{s.start_time.strftime('%Y-%m-%d %H:%M UTC')}</div>
        </div>
    </div>

    <div style="display:grid;grid-template-columns:1fr 2fr;gap:20px;margin-bottom:24px;">
        <div class="card" style="margin-bottom:0;">
            <h3 style="margin-top:0;font-size:16px;">Severity Breakdown</h3>
            <table>
                <thead>
                    <tr><th style="text-align:left;">Severity</th><th style="text-align:right;">Count</th></tr>
                </thead>
                <tbody>
                    {sev_rows}
                </tbody>
            </table>
        </div>
        <div class="card" style="margin-bottom:0;max-height:280px;overflow-y:auto;">
            <h3 style="margin-top:0;font-size:16px;">Discovered Hostnames ({len(s.subdomains)})</h3>
            <ul style="padding-left:18px;margin:0;">
                {subdomains_html}
            </ul>
        </div>
    </div>

    <div class="card">
        <h3 style="margin-top:0;font-size:18px;">Detailed Findings & Remediations</h3>
        {findings_html}
    </div>
</div>
</body>
</html>
"""

    def save_report(self, filepath: Union[str, Path]) -> Path:
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.suffix.lower() == ".json":
            content = self.to_json()
        elif path.suffix.lower() == ".html":
            content = self.to_html()
        else:
            content = self.to_markdown()
        path.write_text(content, encoding="utf-8")
        return path

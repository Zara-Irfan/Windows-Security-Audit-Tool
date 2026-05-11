"""Report exporters — JSON, CSV, HTML."""

import html as _html
import json
import csv
import io
from datetime import datetime
from typing import Any


def export_json(findings: list[dict[str, Any]], score: int, system_info: dict | None = None) -> str:
    payload = {
        "generated_at": datetime.now().isoformat(),
        "tool": "SentinelScan",
        "security_score": score,
        "system_info": system_info or {},
        "findings_count": len(findings),
        "findings": findings,
    }
    return json.dumps(payload, indent=2, default=str)


def export_csv(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return ""
    buf = io.StringIO()
    fieldnames = ["id", "title", "severity", "category", "description", "evidence", "recommendation", "fix"]
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for f in findings:
        writer.writerow({k: f.get(k, "") for k in fieldnames})
    return buf.getvalue()


def export_html(findings: list[dict[str, Any]], score: int, system_info: dict | None = None) -> str:
    si = system_info or {}
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    sev_colors = {
        "Critical": "#b71c1c",
        "High": "#e53935",
        "Medium": "#f57c00",
        "Low": "#f9a825",
        "Info": "#1565c0",
    }

    score_color = "#00c853" if score >= 80 else "#ffd600" if score >= 60 else "#d50000"

    rows_html = ""
    for f in findings:
        sev = f.get("severity", "Info")
        color = sev_colors.get(sev, "#555")
        rows_html += f"""
        <tr>
          <td><code>{_html.escape(f.get('id',''))}</code></td>
          <td>{_html.escape(f.get('title',''))}</td>
          <td><span class="badge" style="background:{color}">{_html.escape(sev)}</span></td>
          <td>{_html.escape(f.get('category',''))}</td>
          <td>{_html.escape(f.get('description',''))}</td>
          <td><em>{_html.escape(f.get('evidence',''))}</em></td>
          <td>{_html.escape(f.get('recommendation',''))}</td>
          <td><code>{_html.escape(f.get('fix',''))}</code></td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SentinelScan Security Report — {timestamp}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #c9d1d9; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
  h1 {{ color: #58a6ff; font-size: 2rem; margin-bottom: 0.25rem; }}
  h2 {{ color: #8b949e; font-size: 1.1rem; font-weight: normal; margin-bottom: 2rem; }}
  h3 {{ color: #c9d1d9; margin: 1.5rem 0 0.75rem; }}
  .score-box {{ display: inline-block; background: #161b22; border: 2px solid {score_color};
               border-radius: 12px; padding: 1.5rem 3rem; text-align: center; margin-bottom: 2rem; }}
  .score-val {{ font-size: 4rem; font-weight: bold; color: {score_color}; }}
  .score-label {{ color: #8b949e; }}
  .info-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .info-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem; }}
  .info-card .label {{ color: #8b949e; font-size: 0.8rem; text-transform: uppercase; }}
  .info-card .value {{ color: #c9d1d9; font-size: 1rem; font-weight: 600; margin-top: 0.25rem; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: 0.85rem; }}
  th {{ background: #161b22; color: #8b949e; text-align: left; padding: 0.6rem 0.8rem;
        border-bottom: 2px solid #30363d; text-transform: uppercase; font-size: 0.75rem; }}
  td {{ padding: 0.6rem 0.8rem; border-bottom: 1px solid #21262d; vertical-align: top; }}
  tr:hover td {{ background: #161b22; }}
  .badge {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px;
            color: #fff; font-weight: 600; font-size: 0.75rem; }}
  code {{ background: #161b22; padding: 0.1rem 0.4rem; border-radius: 3px; font-size: 0.8rem;
          font-family: 'Courier New', monospace; color: #79c0ff; }}
  .footer {{ margin-top: 3rem; color: #484f58; text-align: center; font-size: 0.8rem; }}
</style>
</head>
<body>
<div class="container">
  <h1>SentinelScan Security Report</h1>
  <h2>Generated: {timestamp}</h2>

  <div class="score-box">
    <div class="score-val">{score}/100</div>
    <div class="score-label">Security Score</div>
  </div>

  <div class="info-grid">
    <div class="info-card"><div class="label">Hostname</div><div class="value">{_html.escape(str(si.get('hostname','N/A')))}</div></div>
    <div class="info-card"><div class="label">OS</div><div class="value">{_html.escape(str(si.get('os','N/A')))} {_html.escape(str(si.get('os_release','')))}</div></div>
    <div class="info-card"><div class="label">Total Findings</div><div class="value">{len(findings)}</div></div>
    <div class="info-card"><div class="label">RAM</div><div class="value">{_html.escape(str(si.get('ram_total_gb','N/A')))} GB</div></div>
  </div>

  <h3>Findings Detail</h3>
  <table>
    <thead>
      <tr><th>ID</th><th>Issue</th><th>Severity</th><th>Category</th><th>Description</th>
          <th>Evidence</th><th>Recommendation</th><th>Fix</th></tr>
    </thead>
    <tbody>{rows_html}</tbody>
  </table>

  <div class="footer">
    SentinelScan — Local Security Auditing Platform &nbsp;|&nbsp; No data leaves this machine
  </div>
</div>
</body>
</html>"""

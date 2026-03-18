"""Security report rendering in Markdown and HTML."""

import dataclasses
from datetime import date
from typing import List

from jinja2 import Template


SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

SEVERITY_COLORS = {
    "Critical": "#d32f2f",
    "High": "#e65100",
    "Medium": "#f9a825",
    "Low": "#1565c0",
    "Info": "#757575",
}


@dataclasses.dataclass
class Finding:
    title: str
    description: str
    impact: str
    mitigation: str
    severity: str
    cvss_score: float
    cvss_vector: str
    evidence_files: str
    host: str


def findings_from_dicts(dicts):
    """Convert list of dicts from LLM to Finding objects."""
    findings = []
    for d in dicts:
        try:
            findings.append(Finding(
                title=d.get("title", "Untitled Finding"),
                description=d.get("description", "No description provided."),
                impact=d.get("impact", "Not specified."),
                mitigation=d.get("mitigation", "Not specified."),
                severity=d.get("severity", "Info"),
                cvss_score=float(d.get("cvss_score", 0.0)),
                cvss_vector=d.get("cvss_vector", "N/A"),
                evidence_files=d.get("evidence_file", "N/A"),
                host=d.get("host", "Unknown"),
            ))
        except (ValueError, TypeError):
            continue
    return findings


def sort_findings(findings):
    """Sort findings by severity (Critical first) then by CVSS score descending."""
    return sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 5), -f.cvss_score),
    )


def severity_summary(findings):
    """Count findings per severity level."""
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def render_markdown(findings, hosts, skipped_files=None, report_date=None):
    """Render findings as a Markdown report."""
    if report_date is None:
        report_date = date.today().isoformat()

    findings = sort_findings(findings)
    counts = severity_summary(findings)
    total = len(findings)
    hosts_str = ", ".join(hosts)

    lines = []
    lines.append("# Security Assessment Report")
    lines.append("")
    lines.append(f"**Date:** {report_date}  ")
    lines.append(f"**Hosts analyzed:** {hosts_str}  ")

    count_parts = []
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        if counts[sev] > 0:
            count_parts.append(f"{counts[sev]} {sev}")
    lines.append(f"**Total findings:** {total} ({', '.join(count_parts)})")
    lines.append("")

    # Executive summary table
    lines.append("## Executive Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        lines.append(f"| {sev} | {counts[sev]} |")
    lines.append("")

    # Findings
    if findings:
        lines.append("## Findings")
        lines.append("")

        for i, f in enumerate(findings, 1):
            lines.append(f"### [{f.severity.upper()}] {i}. {f.title} (CVSS: {f.cvss_score})")
            lines.append("")
            lines.append(f"**Host:** {f.host}  ")
            lines.append(f"**CVSS Vector:** `{f.cvss_vector}`  ")
            lines.append(f"**Evidence:** `{f.evidence_files}`")
            lines.append("")
            lines.append(f"**Description:**  ")
            lines.append(f"{f.description}")
            lines.append("")
            lines.append(f"**Impact:**  ")
            lines.append(f"{f.impact}")
            lines.append("")
            lines.append(f"**Mitigation:**  ")
            lines.append(f"{f.mitigation}")
            lines.append("")
            lines.append("---")
            lines.append("")
    else:
        lines.append("## Findings")
        lines.append("")
        lines.append("No security findings were identified.")
        lines.append("")

    # Skipped files
    if skipped_files:
        lines.append("## Skipped Files")
        lines.append("")
        for sf in skipped_files:
            lines.append(f"- {sf}")
        lines.append("")

    return "\n".join(lines)


HTML_TEMPLATE = Template("""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Assessment Report</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 960px; margin: 0 auto; padding: 20px; color: #333; line-height: 1.6; }
  h1 { border-bottom: 2px solid #333; padding-bottom: 10px; }
  h2 { color: #555; margin-top: 30px; }
  table { border-collapse: collapse; width: 100%; margin: 15px 0; }
  th, td { border: 1px solid #ddd; padding: 10px 14px; text-align: left; }
  th { background: #f5f5f5; font-weight: 600; }
  .finding { border: 1px solid #ddd; border-radius: 6px; padding: 20px; margin: 20px 0; }
  .severity-badge { display: inline-block; padding: 3px 10px; border-radius: 4px; color: white; font-weight: 600; font-size: 0.85em; }
  .severity-Critical { background: {{ colors.Critical }}; }
  .severity-High { background: {{ colors.High }}; }
  .severity-Medium { background: {{ colors.Medium }}; color: #333; }
  .severity-Low { background: {{ colors.Low }}; }
  .severity-Info { background: {{ colors.Info }}; }
  .meta { color: #666; margin: 8px 0; }
  code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }
  .finding-section { margin: 12px 0; }
  .finding-section strong { display: block; margin-bottom: 4px; }
  hr { border: none; border-top: 1px solid #eee; margin: 20px 0; }
</style>
</head>
<body>
<h1>Security Assessment Report</h1>
<p><strong>Date:</strong> {{ report_date }}<br>
<strong>Hosts analyzed:</strong> {{ hosts_str }}<br>
<strong>Total findings:</strong> {{ total }} ({{ count_summary }})</p>

<h2>Executive Summary</h2>
<table>
<tr><th>Severity</th><th>Count</th></tr>
{% for sev in severity_order %}
<tr><td><span class="severity-badge severity-{{ sev }}">{{ sev }}</span></td><td>{{ counts[sev] }}</td></tr>
{% endfor %}
</table>

<h2>Findings</h2>
{% if findings %}
{% for f in findings %}
<div class="finding">
  <h3><span class="severity-badge severity-{{ f.severity }}">{{ f.severity }}</span> {{ loop.index }}. {{ f.title }} (CVSS: {{ f.cvss_score }})</h3>
  <p class="meta"><strong>Host:</strong> {{ f.host }}<br>
  <strong>CVSS Vector:</strong> <code>{{ f.cvss_vector }}</code><br>
  <strong>Evidence:</strong> <code>{{ f.evidence_files }}</code></p>
  <div class="finding-section"><strong>Description:</strong> {{ f.description }}</div>
  <div class="finding-section"><strong>Impact:</strong> {{ f.impact }}</div>
  <div class="finding-section"><strong>Mitigation:</strong> {{ f.mitigation }}</div>
</div>
{% endfor %}
{% else %}
<p>No security findings were identified.</p>
{% endif %}

{% if skipped_files %}
<h2>Skipped Files</h2>
<ul>
{% for sf in skipped_files %}
<li>{{ sf }}</li>
{% endfor %}
</ul>
{% endif %}

</body>
</html>
""")


def render_html(findings, hosts, skipped_files=None, report_date=None):
    """Render findings as an HTML report."""
    if report_date is None:
        report_date = date.today().isoformat()

    findings = sort_findings(findings)
    counts = severity_summary(findings)
    total = len(findings)
    hosts_str = ", ".join(hosts)

    count_parts = []
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        if counts[sev] > 0:
            count_parts.append(f"{counts[sev]} {sev}")

    return HTML_TEMPLATE.render(
        report_date=report_date,
        hosts_str=hosts_str,
        total=total,
        count_summary=", ".join(count_parts),
        counts=counts,
        severity_order=["Critical", "High", "Medium", "Low", "Info"],
        findings=findings,
        skipped_files=skipped_files or [],
        colors=SEVERITY_COLORS,
    )

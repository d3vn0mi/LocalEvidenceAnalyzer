"""Prompt templates for LLM-based security analysis."""

SYSTEM_PROMPT = """You are a senior security analyst performing a security assessment. \
You analyze system evidence (configuration files, logs, scan outputs, network captures) \
and identify security findings.

You MUST respond with ONLY a valid JSON array. No markdown, no explanation, no commentary. \
Just the JSON array."""

PHASE1_PROMPT_TEMPLATE = """Analyze the following evidence file for security issues.

Host: {host_name}
File: {filepath}
{kb_context}Content:
---
{content}
---

For each security finding, return a JSON array of objects with these exact fields:
- "title": concise finding title
- "description": detailed technical description of the issue
- "impact": technical impact if exploited
- "mitigation": specific remediation steps
- "severity": one of "Critical", "High", "Medium", "Low", "Info"
- "cvss_score": CVSSv3 base score (0.0 - 10.0)
- "cvss_vector": CVSSv3 vector string (e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- "evidence_file": "{filepath}"
- "host": "{host_name}"

If no security issues are found, return an empty array: []
Respond with ONLY the JSON array."""

PHASE2_PROMPT_TEMPLATE = """You are a senior security analyst finalizing a security assessment report.

Below are raw security findings from multiple evidence files across one or more hosts. Your tasks:
1. Deduplicate findings that describe the same underlying issue (merge their evidence_file values into a comma-separated list)
2. Validate and adjust CVSS scores for consistency
3. Rank findings by severity (Critical first, then High, Medium, Low, Info)
4. Ensure descriptions are clear and professional

Raw findings:
{findings_json}

Return a JSON array with the same field structure. For deduplicated findings, combine the evidence_file fields into a comma-separated list.
Respond with ONLY the JSON array."""

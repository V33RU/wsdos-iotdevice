"""Consolidated reporting: JSON, Markdown, or pretty-printed terminal."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from typing import List

from .common import Finding, color, severity_label


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def emit(findings: List[Finding], fmt: str, target: str) -> str:
    if fmt == "json":
        return json.dumps({
            "target": target,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "findings": [f.to_dict() for f in findings],
        }, indent=2)
    if fmt == "markdown":
        return _markdown(findings, target)
    return _pretty(findings, target)


def _pretty(findings: List[Finding], target: str) -> str:
    sorted_f = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    lines = [
        color(f"=== wsdos scan report ===", "bold"),
        f"Target: {target}",
        f"Findings: {len(sorted_f)}",
        "",
    ]
    counts = {}
    for f in sorted_f:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = "  ".join(
        f"{severity_label(s)} {n}"
        for s, n in sorted(counts.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 99))
    )
    lines.append("Summary: " + summary)
    lines.append("")
    for f in sorted_f:
        lines.append(f.pretty())
        if f.references:
            for ref in f.references:
                lines.append(color(f"      → {ref}", "dim"))
        lines.append("")
    return "\n".join(lines)


def _markdown(findings: List[Finding], target: str) -> str:
    sorted_f = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    counts = {}
    for f in sorted_f:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    lines = [
        f"# wsdos scan report",
        f"",
        f"- **Target:** `{target}`",
        f"- **Scanned at:** {datetime.now(timezone.utc).isoformat()}",
        f"- **Total findings:** {len(sorted_f)}",
        f"",
        "## Summary",
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if counts.get(s):
            lines.append(f"| **{s}** | {counts[s]} |")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    for f in sorted_f:
        lines.append(f"### `{f.check}` — {f.title}")
        lines.append("")
        lines.append(f"**Severity:** {f.severity}")
        lines.append("")
        lines.append(f.detail)
        lines.append("")
        if f.references:
            lines.append("**References:**")
            for ref in f.references:
                lines.append(f"- {ref}")
            lines.append("")
        if f.evidence:
            lines.append("<details><summary>Evidence</summary>\n\n```json")
            lines.append(json.dumps(f.evidence, indent=2, default=str))
            lines.append("```\n\n</details>")
            lines.append("")
    return "\n".join(lines)

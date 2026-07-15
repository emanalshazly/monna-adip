"""JSON, text, Markdown, and SARIF renderers for ADIP reports."""

from __future__ import annotations

import json
from typing import Any

RULE_DESCRIPTIONS = {
    "ADIP-01": "Unknown or invalid security-relevant provenance",
    "ADIP-02": "Untrusted value assigned a trusted security role",
    "ADIP-03": "Sensitive action depends on an unverified field",
    "ADIP-04": "Mixed-trust structural ambiguity",
    "ADIP-05": "Same-context confirmation dependency",
    "ADIP-06": "Derived value loses provenance",
    "ADIP-07": "Mitigation lacks verification evidence",
}


def render_json(report: dict[str, Any], compact: bool = False) -> str:
    if compact:
        return json.dumps(report, ensure_ascii=False, separators=(",", ":"))
    return json.dumps(report, ensure_ascii=False, indent=2)


def _counts(report: dict[str, Any]) -> str:
    counts = report.get("finding_counts", {})
    ordered = ["critical", "high", "medium", "low"]
    present = [f"{name}={counts.get(name, 0)}" for name in ordered]
    return ", ".join(present)


def render_text(report: dict[str, Any]) -> str:
    lines = [
        f"MONNA ADIP Lite v{report['version']}",
        f"Status: {report['status']}",
        f"Inventories: {report['inventory_count']}",
        f"Findings: {_counts(report)}",
    ]
    if not report.get("findings"):
        lines.extend(["", "No baseline findings."])
        return "\n".join(lines)

    lines.append("")
    for finding in report["findings"]:
        lines.extend(
            [
                f"[{finding['severity'].upper()}] {finding['id']} — {finding['message']}",
                f"  Source: {finding['source']}",
                f"  Location: {finding['location']}",
                f"  Recommendation: {finding['recommendation']}",
            ]
        )
    return "\n".join(lines)


def _markdown_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# MONNA ADIP Lite Report",
        "",
        f"- Version: `{report['version']}`",
        f"- Status: **{report['status']}**",
        f"- Inventories: {report['inventory_count']}",
        f"- Findings: {_counts(report)}",
        "",
    ]
    if not report.get("findings"):
        lines.append("No baseline findings.")
        return "\n".join(lines)

    lines.extend(
        [
            "| Severity | Rule | Source | Location | Finding | Recommendation |",
            "|---|---|---|---|---|---|",
        ]
    )
    for finding in report["findings"]:
        cells = [
            finding["severity"].upper(),
            finding["id"],
            finding["source"],
            finding["location"],
            finding["message"],
            finding["recommendation"],
        ]
        lines.append("| " + " | ".join(_markdown_cell(cell) for cell in cells) + " |")
    return "\n".join(lines)


def build_sarif(report: dict[str, Any]) -> dict[str, Any]:
    used_ids = sorted({finding["id"] for finding in report.get("findings", [])})
    rules = [
        {
            "id": rule_id,
            "name": rule_id.replace("-", ""),
            "shortDescription": {"text": RULE_DESCRIPTIONS[rule_id]},
            "helpUri": "https://github.com/emanalshazly/monna-adip/blob/main/docs/FRAMEWORK.md",
        }
        for rule_id in used_ids
    ]
    level_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    results = []
    for finding in report.get("findings", []):
        results.append(
            {
                "ruleId": finding["id"],
                "level": level_map.get(finding["severity"], "warning"),
                "message": {"text": finding["message"]},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding["source"]}
                        },
                        "logicalLocations": [{"fullyQualifiedName": finding["location"]}],
                    }
                ],
                "properties": {
                    "severity": finding["severity"],
                    "recommendation": finding["recommendation"],
                },
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MONNA ADIP Lite",
                        "informationUri": "https://github.com/emanalshazly/monna-adip",
                        "version": report["version"],
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def render_report(report: dict[str, Any], output_format: str, compact: bool = False) -> str:
    if output_format == "json":
        return render_json(report, compact)
    if output_format == "text":
        return render_text(report)
    if output_format == "markdown":
        return render_markdown(report)
    if output_format == "sarif":
        return render_json(build_sarif(report), compact)
    raise ValueError(f"Unsupported output format: {output_format}")

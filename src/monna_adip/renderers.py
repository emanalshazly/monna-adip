"""JSON, text, Markdown, and SARIF renderers for ADIP reports."""

from __future__ import annotations

import json
from typing import Any

RULE_DESCRIPTIONS = {
    "ADIP-01": "Unknown or invalid security-relevant provenance",
    "ADIP-02": "Untrusted value assigned a trusted security role",
    "ADIP-03": "Sensitive action depends on an unverified field",
    "ADIP-04": "Mixed-trust structural ambiguity",
    "ADIP-05": "Non-independent verification dependency",
    "ADIP-06": "Derived or downstream value loses provenance",
    "ADIP-07": "Mitigation lacks verification evidence",
}

# Primary OWASP Top 10 for Agentic Applications 2026 vector per control.
# The mapping is [MONNA-Analysis-2026]; see docs/OWASP-MAPPING.md.
# ADIP-07 is cross-cutting and carries no ASI tag.
OWASP_ASI_2026 = {
    "ADIP-01": ["ASI06"],
    "ADIP-02": ["ASI03"],
    "ADIP-03": ["ASI02"],
    "ADIP-04": ["ASI01"],
    "ADIP-05": ["ASI09"],
    "ADIP-06": ["ASI06"],
    "ADIP-07": [],
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


def _threat_context(report: dict[str, Any]) -> tuple[list[str], list[str], list[str]]:
    context = report.get("threat_context", {})
    if not isinstance(context, dict):
        return [], [], []
    impacts = [item for item in context.get("cia_impacts", []) if isinstance(item, str)]
    attack_paths = [
        item for item in context.get("attack_paths", []) if isinstance(item, str)
    ]
    references: list[str] = []
    for reference in context.get("external_references", []):
        if not isinstance(reference, dict) or not isinstance(
            reference.get("namespace"), str
        ):
            continue
        references.extend(
            f"{reference['namespace']}:{item}"
            for item in reference.get("ids", [])
            if isinstance(item, str)
        )
    return impacts, attack_paths, references


def render_text(report: dict[str, Any]) -> str:
    lines = [
        f"MONNA ADIP Lite v{report['version']}",
        f"Status: {report['status']}",
        f"Inventories: {report['inventory_count']}",
        f"Findings: {_counts(report)}",
    ]
    impacts, attack_paths, references = _threat_context(report)
    if impacts:
        lines.append(f"CIA impacts: {', '.join(impacts)}")
    if attack_paths:
        lines.append(f"Attack paths: {', '.join(attack_paths)}")
    if references:
        lines.append(f"External references: {', '.join(references)}")
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
    ]
    impacts, attack_paths, references = _threat_context(report)
    if impacts:
        lines.append(f"- CIA impacts: {', '.join(impacts)}")
    if attack_paths:
        lines.append(f"- Attack paths: {', '.join(attack_paths)}")
    if references:
        lines.append(f"- External references: {', '.join(references)}")
    lines.append("")
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
    impacts, attack_paths, external_references = _threat_context(report)
    external_tags = [
        f"external/taxonomy/{reference.replace(':', '/', 1)}"
        for reference in external_references
    ]
    used_ids = sorted({finding["id"] for finding in report.get("findings", [])})
    rules = []
    for rule_id in used_ids:
        asi_vectors = OWASP_ASI_2026.get(rule_id, [])
        rules.append(
            {
                "id": rule_id,
                "name": rule_id.replace("-", ""),
                "shortDescription": {"text": RULE_DESCRIPTIONS[rule_id]},
                "helpUri": "https://github.com/emanalshazly/monna-adip/blob/main/docs/FRAMEWORK.md",
                "properties": {
                    "tags": ["security"]
                    + [f"external/owasp-asi/{vector}" for vector in asi_vectors],
                    "owaspAsi2026": asi_vectors,
                },
            }
        )
    level_map = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
    }
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
                        "logicalLocations": [
                            {"fullyQualifiedName": finding["location"]}
                        ],
                    }
                ],
                "properties": {
                    "severity": finding["severity"],
                    "recommendation": finding["recommendation"],
                    "basis": finding.get("basis", "declared"),
                    "ciaImpacts": impacts,
                    "attackPaths": attack_paths,
                    "externalTaxonomyReferences": external_references,
                    "tags": external_tags,
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
                "properties": {
                    "ciaImpacts": impacts,
                    "attackPaths": attack_paths,
                    "externalTaxonomyReferences": external_references,
                },
            }
        ],
    }


def render_report(
    report: dict[str, Any], output_format: str, compact: bool = False
) -> str:
    if output_format == "json":
        return render_json(report, compact)
    if output_format == "text":
        return render_text(report)
    if output_format == "markdown":
        return render_markdown(report)
    if output_format == "sarif":
        return render_json(build_sarif(report), compact)
    raise ValueError(f"Unsupported output format: {output_format}")

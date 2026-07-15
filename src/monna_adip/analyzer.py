"""Deterministic baseline checks for a MONNA ADIP inventory.

The Lite analyzer intentionally avoids exploit generation and proprietary
weighted scoring. It reports architecture gaps that require human review.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

TRUST_CLASSES = {"trusted", "untrusted", "derived", "unknown"}
SECURITY_ROLES = {
    "identifier",
    "origin",
    "authorization",
    "tool_history",
    "verification_result",
    "action_argument",
}
HIGH_IMPACT = {"high", "critical"}
STRUCTURED_FORMATS = {"json", "xml", "markdown", "dom", "custom"}


def _finding(
    finding_id: str,
    severity: str,
    location: str,
    message: str,
    recommendation: str,
) -> dict[str, str]:
    return {
        "id": finding_id,
        "severity": severity,
        "location": location,
        "message": message,
        "recommendation": recommendation,
    }


def _index_fields(inventory: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    index: dict[tuple[str, str], dict[str, Any]] = {}
    for obj in inventory.get("data_objects", []):
        object_id = obj.get("id", "<missing-object-id>")
        for field in obj.get("fields", []):
            index[(object_id, field.get("name", "<missing-field-name>"))] = field
    return index


def analyze_inventory(inventory: dict[str, Any]) -> dict[str, Any]:
    """Return deterministic triage findings for an ADIP inventory."""

    findings: list[dict[str, str]] = []
    objects = inventory.get("data_objects")
    actions = inventory.get("actions")

    if not isinstance(objects, list) or not isinstance(actions, list):
        return {
            "status": "INCOMPLETE",
            "finding_counts": {"high": 1},
            "findings": [
                _finding(
                    "ADIP-01",
                    "high",
                    "inventory",
                    "Inventory must contain data_objects and actions arrays.",
                    "Complete the inventory using templates/assessment.json.",
                )
            ],
        }

    field_index = _index_fields(inventory)

    for obj in objects:
        object_id = obj.get("id", "<missing-object-id>")
        fields = obj.get("fields", [])
        trust_values = {field.get("trust", "unknown") for field in fields}

        for field in fields:
            name = field.get("name", "<missing-field-name>")
            trust = field.get("trust", "unknown")
            role = field.get("security_role", "content")
            location = f"data_objects.{object_id}.fields.{name}"

            if trust not in TRUST_CLASSES:
                findings.append(
                    _finding(
                        "ADIP-01",
                        "high",
                        location,
                        f"Unsupported trust class: {trust!r}.",
                        "Use trusted, untrusted, derived, or unknown and document evidence.",
                    )
                )
            elif trust == "unknown" and role in SECURITY_ROLES:
                findings.append(
                    _finding(
                        "ADIP-01",
                        "high",
                        location,
                        "Security-relevant field has unknown provenance.",
                        "Establish origin and integrity evidence or treat the field as untrusted.",
                    )
                )

            if trust == "untrusted" and role in SECURITY_ROLES:
                findings.append(
                    _finding(
                        "ADIP-02",
                        "critical",
                        location,
                        "Untrusted data is assigned a security-relevant role.",
                        "Verify the value outside model interpretation before using it as a security anchor.",
                    )
                )

            if trust == "derived" and not field.get("provenance_preserved", False):
                findings.append(
                    _finding(
                        "ADIP-06",
                        "high",
                        location,
                        "Derived value does not preserve input provenance.",
                        "Propagate the least-trusted relevant provenance through the transformation.",
                    )
                )

        if (
            "trusted" in trust_values
            and ({"untrusted", "unknown"} & trust_values)
            and obj.get("format", "").lower() in STRUCTURED_FORMATS
            and not obj.get("structural_isolation", False)
        ):
            findings.append(
                _finding(
                    "ADIP-04",
                    "high",
                    f"data_objects.{object_id}",
                    "Mixed-trust object is serialized without stated structural isolation.",
                    "Add deterministic isolation, provenance labels, runtime randomization, or independent validation.",
                )
            )

    for action in actions:
        action_id = action.get("id", "<missing-action-id>")
        impact = action.get("impact", "unknown")
        parameters = action.get("parameters", [])

        for parameter in parameters:
            name = parameter.get("name", "<missing-parameter-name>")
            source = parameter.get("source", {})
            key = (source.get("object"), source.get("field"))
            field = field_index.get(key)
            location = f"actions.{action_id}.parameters.{name}"

            if field is None:
                findings.append(
                    _finding(
                        "ADIP-01",
                        "high",
                        location,
                        "Action parameter source cannot be resolved to an inventoried field.",
                        "Map the parameter to an exact object and field.",
                    )
                )
                continue

            if impact in HIGH_IMPACT and not (
                parameter.get("deterministic_validation", False)
                and parameter.get("provenance_check", False)
            ):
                severity = "critical" if impact == "critical" else "high"
                findings.append(
                    _finding(
                        "ADIP-03",
                        severity,
                        location,
                        "High-impact action depends on a field without both deterministic validation and provenance checking.",
                        "Validate structure and independently verify provenance before execution.",
                    )
                )

        if (
            impact in HIGH_IMPACT
            and action.get("user_confirmation", False)
            and not action.get("independent_confirmation_evidence", False)
        ):
            findings.append(
                _finding(
                    "ADIP-05",
                    "high",
                    f"actions.{action_id}",
                    "Confirmation relies on the agent context without independent evidence.",
                    "Show or verify the authoritative source outside the potentially corrupted context.",
                )
            )

    counts = Counter(item["severity"] for item in findings)
    if counts["critical"] or counts["high"]:
        status = "EXPOSED"
    elif any(item["id"] == "ADIP-01" for item in findings):
        status = "INCOMPLETE"
    else:
        status = "REVIEW_READY"

    return {
        "framework": "MONNA ADIP Lite",
        "version": "0.1.0",
        "status": status,
        "finding_counts": dict(sorted(counts.items())),
        "findings": findings,
        "disclaimer": "Triage result only; not a security certification.",
    }


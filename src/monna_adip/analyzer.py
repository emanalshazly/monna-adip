"""Deterministic baseline checks for a MONNA ADIP inventory.

The Lite analyzer intentionally avoids exploit generation and proprietary
weighted scoring. It reports architecture gaps that require human review.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from .version import __version__

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
CIA_IMPACTS = {"confidentiality", "integrity", "availability"}
ATTACK_PATHS = {"direct", "indirect", "retrieval", "multi_model", "mixed"}


def _finding(
    finding_id: str,
    severity: str,
    location: str,
    message: str,
    recommendation: str,
    basis: str = "declared",
) -> dict[str, str]:
    # Calibration honesty: every finding states its epistemic basis.
    # "structural" = observed directly in the inventory document;
    # "declared" = derived from trust/impact labels the author declared.
    # The analyzer never inspects the running system itself.
    return {
        "id": finding_id,
        "severity": severity,
        "location": location,
        "message": message,
        "recommendation": recommendation,
        "basis": basis,
    }


def _has_evidence(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list):
        return any(_has_evidence(item) for item in value)
    if isinstance(value, dict):
        return any(_has_evidence(item) for item in value.values())
    return value is not None and value is not False


def _adip07(location: str, claim: str, evidence_field: str) -> dict[str, str]:
    return _finding(
        "ADIP-07",
        "medium",
        location,
        f"Mitigation claim {claim!r} has no reviewable verification evidence.",
        f"Add {evidence_field} with a test, log, policy reference, or independent review artifact.",
    )


def _index_fields(inventory: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    index: dict[tuple[str, str], dict[str, Any]] = {}
    for obj in inventory.get("data_objects", []):
        if not isinstance(obj, dict):
            continue
        object_id = obj.get("id", "<missing-object-id>")
        fields = obj.get("fields", [])
        if not isinstance(fields, list):
            continue
        for field in fields:
            if isinstance(field, dict):
                index[(object_id, field.get("name", "<missing-field-name>"))] = field
    return index


def _normalize_threat_context(inventory: dict[str, Any]) -> dict[str, Any]:
    """Return safe, reportable threat metadata without importing a taxonomy."""

    context = inventory.get("threat_context", {})
    if not isinstance(context, dict):
        return {"cia_impacts": [], "attack_paths": [], "external_references": []}

    impacts = sorted(
        {
            item
            for item in context.get("cia_impacts", [])
            if isinstance(item, str) and item in CIA_IMPACTS
        }
    )
    attack_paths = sorted(
        {
            item
            for item in context.get("attack_paths", [])
            if isinstance(item, str) and item in ATTACK_PATHS
        }
    )
    references: list[dict[str, Any]] = []
    for reference in context.get("external_references", []):
        if not isinstance(reference, dict):
            continue
        namespace = reference.get("namespace")
        ids = reference.get("ids")
        if (
            not isinstance(namespace, str)
            or not namespace.strip()
            or not isinstance(ids, list)
        ):
            continue
        normalized_ids = sorted(
            {item for item in ids if isinstance(item, str) and item.strip()}
        )
        if not normalized_ids:
            continue
        normalized: dict[str, Any] = {
            "namespace": namespace.strip(),
            "ids": normalized_ids,
        }
        for key in ("version", "source_url"):
            value = reference.get(key)
            if isinstance(value, str) and value.strip():
                normalized[key] = value.strip()
        references.append(normalized)

    references.sort(
        key=lambda item: (
            item["namespace"],
            item.get("version", ""),
            item.get("source_url", ""),
            tuple(item["ids"]),
        )
    )
    return {
        "cia_impacts": impacts,
        "attack_paths": attack_paths,
        "external_references": references,
    }


def analyze_inventory(inventory: dict[str, Any]) -> dict[str, Any]:
    """Return deterministic triage findings for an ADIP inventory."""

    findings: list[dict[str, str]] = []
    threat_context = _normalize_threat_context(inventory)
    objects = inventory.get("data_objects")
    actions = inventory.get("actions")

    if not isinstance(objects, list) or not isinstance(actions, list):
        return {
            "framework": "MONNA ADIP Lite",
            "version": __version__,
            "status": "INCOMPLETE",
            "finding_counts": {"high": 1},
            "threat_context": threat_context,
            "findings": [
                _finding(
                    "ADIP-01",
                    "high",
                    "inventory",
                    "Inventory must contain data_objects and actions arrays.",
                    "Complete the inventory using templates/assessment.json.",
                    basis="structural",
                )
            ],
            "disclaimer": "Triage result only; not a security certification.",
        }

    field_index = _index_fields(inventory)

    for object_position, obj in enumerate(objects):
        if not isinstance(obj, dict):
            findings.append(
                _finding(
                    "ADIP-01",
                    "high",
                    f"data_objects.{object_position}",
                    "Data object must be a JSON object.",
                    "Describe the object using the published inventory schema.",
                    basis="structural",
                )
            )
            continue

        object_id = obj.get("id", "<missing-object-id>")
        fields = obj.get("fields", [])
        if not isinstance(fields, list):
            findings.append(
                _finding(
                    "ADIP-01",
                    "high",
                    f"data_objects.{object_id}.fields",
                    "Fields must be an array.",
                    "Describe each field using the published inventory schema.",
                    basis="structural",
                )
            )
            continue

        trust_values = {
            field.get("trust", "unknown") for field in fields if isinstance(field, dict)
        }

        for field_position, field in enumerate(fields):
            if not isinstance(field, dict):
                findings.append(
                    _finding(
                        "ADIP-01",
                        "high",
                        f"data_objects.{object_id}.fields.{field_position}",
                        "Field must be a JSON object.",
                        "Describe the field using the published inventory schema.",
                        basis="structural",
                    )
                )
                continue

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
                        basis="structural",
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
            elif (
                trust == "derived"
                and field.get("provenance_preserved", False)
                and not _has_evidence(field.get("provenance_evidence"))
            ):
                findings.append(
                    _adip07(location, "provenance_preserved", "provenance_evidence")
                )

        if (
            "trusted" in trust_values
            and ({"untrusted", "unknown"} & trust_values)
            and str(obj.get("format", "")).lower() in STRUCTURED_FORMATS
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
        elif obj.get("structural_isolation", False) and not _has_evidence(
            obj.get("structural_isolation_evidence")
        ):
            findings.append(
                _adip07(
                    f"data_objects.{object_id}",
                    "structural_isolation",
                    "structural_isolation_evidence",
                )
            )

    for action_position, action in enumerate(actions):
        if not isinstance(action, dict):
            findings.append(
                _finding(
                    "ADIP-01",
                    "high",
                    f"actions.{action_position}",
                    "Action must be a JSON object.",
                    "Describe the action using the published inventory schema.",
                    basis="structural",
                )
            )
            continue

        action_id = action.get("id", "<missing-action-id>")
        impact = action.get("impact", "unknown")
        parameters = action.get("parameters", [])
        if not isinstance(parameters, list):
            findings.append(
                _finding(
                    "ADIP-01",
                    "high",
                    f"actions.{action_id}.parameters",
                    "Parameters must be an array.",
                    "Describe each parameter using the published inventory schema.",
                    basis="structural",
                )
            )
            continue

        for parameter_position, parameter in enumerate(parameters):
            if not isinstance(parameter, dict):
                findings.append(
                    _finding(
                        "ADIP-01",
                        "high",
                        f"actions.{action_id}.parameters.{parameter_position}",
                        "Parameter must be a JSON object.",
                        "Describe the parameter using the published inventory schema.",
                        basis="structural",
                    )
                )
                continue

            name = parameter.get("name", "<missing-parameter-name>")
            source = parameter.get("source", {})
            source = source if isinstance(source, dict) else {}
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
                        basis="structural",
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

            if parameter.get("deterministic_validation", False) and not _has_evidence(
                parameter.get("validation_evidence")
            ):
                findings.append(
                    _adip07(location, "deterministic_validation", "validation_evidence")
                )
            if parameter.get("provenance_check", False) and not _has_evidence(
                parameter.get("provenance_evidence")
            ):
                findings.append(
                    _adip07(location, "provenance_check", "provenance_evidence")
                )

        verification = action.get("verification")
        if (
            not isinstance(verification, dict)
            and impact in HIGH_IMPACT
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
        elif action.get(
            "independent_confirmation_evidence", False
        ) and not _has_evidence(action.get("confirmation_evidence")):
            findings.append(
                _adip07(
                    f"actions.{action_id}",
                    "independent_confirmation_evidence",
                    "confirmation_evidence",
                )
            )

        if isinstance(verification, dict):
            if impact in HIGH_IMPACT and not verification.get("independent", False):
                findings.append(
                    _finding(
                        "ADIP-05",
                        "high",
                        f"actions.{action_id}.verification",
                        "High-impact action relies on a non-independent verification step.",
                        "Use an independently sourced deterministic, human, or external verification path.",
                    )
                )
            elif verification.get("independent", False) and not _has_evidence(
                verification.get("evidence")
            ):
                findings.append(
                    _adip07(
                        f"actions.{action_id}.verification",
                        "independent verification",
                        "verification.evidence",
                    )
                )

    outputs = inventory.get("outputs", [])
    if isinstance(outputs, list):
        for output_position, output in enumerate(outputs):
            if not isinstance(output, dict):
                findings.append(
                    _finding(
                        "ADIP-01",
                        "high",
                        f"outputs.{output_position}",
                        "Output sink must be a JSON object.",
                        "Describe the output using the published inventory schema.",
                        basis="structural",
                    )
                )
                continue

            output_id = output.get("id", output_position)
            location = f"outputs.{output_id}"
            sources = output.get("source_fields", [])
            if not isinstance(sources, list) or not sources:
                findings.append(
                    _finding(
                        "ADIP-01",
                        "high",
                        f"{location}.source_fields",
                        "Output sink must identify at least one source field.",
                        "Map the output to every inventoried object and field that influences it.",
                        basis="structural",
                    )
                )
            else:
                for source_position, source in enumerate(sources):
                    source = source if isinstance(source, dict) else {}
                    key = (source.get("object"), source.get("field"))
                    if key not in field_index:
                        findings.append(
                            _finding(
                                "ADIP-01",
                                "high",
                                f"{location}.source_fields.{source_position}",
                                "Output source cannot be resolved to an inventoried field.",
                                "Map the output to an exact object and field.",
                                basis="structural",
                            )
                        )

            consumer = output.get("consumer", {})
            consumer = consumer if isinstance(consumer, dict) else {}
            if consumer.get("type") == "llm" and not output.get(
                "provenance_preserved", False
            ):
                findings.append(
                    _finding(
                        "ADIP-06",
                        "high",
                        location,
                        "Output passed to another model does not preserve source provenance.",
                        "Carry field-level trust and provenance into the downstream model context.",
                    )
                )
            elif output.get("provenance_preserved", False) and not _has_evidence(
                output.get("provenance_evidence")
            ):
                findings.append(
                    _adip07(location, "provenance_preserved", "provenance_evidence")
                )

            if output.get("impact") in HIGH_IMPACT and not (
                output.get("deterministic_validation", False)
                and output.get("independent_verification", False)
            ):
                severity = "critical" if output.get("impact") == "critical" else "high"
                findings.append(
                    _finding(
                        "ADIP-03",
                        severity,
                        location,
                        "High-impact output reaches a sink without deterministic validation and independent verification.",
                        "Validate the output deterministically and verify its authority before the sink consumes it.",
                    )
                )

            if output.get("deterministic_validation", False) and not _has_evidence(
                output.get("validation_evidence")
            ):
                findings.append(
                    _adip07(location, "deterministic_validation", "validation_evidence")
                )
            if output.get("independent_verification", False) and not _has_evidence(
                output.get("verification_evidence")
            ):
                findings.append(
                    _adip07(
                        location, "independent_verification", "verification_evidence"
                    )
                )

    mitigations = inventory.get("mitigations", [])
    if isinstance(mitigations, list):
        for position, mitigation in enumerate(mitigations):
            if not isinstance(mitigation, dict):
                continue
            mitigation_id = mitigation.get("id", position)
            verified = mitigation.get("verification_status") == "verified"
            if not verified or not _has_evidence(
                mitigation.get("verification_evidence")
            ):
                findings.append(
                    _adip07(
                        f"mitigations.{mitigation_id}",
                        str(mitigation.get("control", "declared mitigation")),
                        "verification_status='verified' and verification_evidence",
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
        "version": __version__,
        "status": status,
        "finding_counts": dict(sorted(counts.items())),
        "threat_context": threat_context,
        "findings": findings,
        "disclaimer": "Triage result only; not a security certification.",
    }

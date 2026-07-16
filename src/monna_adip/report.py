"""Inventory discovery and aggregate report construction."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from .version import __version__

STATUS_PRIORITY = {"REVIEW_READY": 0, "INCOMPLETE": 1, "EXPOSED": 2}


def discover_inventory_paths(
    paths: Iterable[Path], recursive: bool = False
) -> list[Path]:
    discovered: dict[str, Path] = {}
    for path in paths:
        if path.is_file():
            if path.suffix.lower() == ".json":
                discovered[str(path.resolve())] = path
            continue
        if path.is_dir():
            iterator = path.rglob("*.json") if recursive else path.glob("*.json")
            for candidate in iterator:
                if candidate.is_file():
                    discovered[str(candidate.resolve())] = candidate
            continue
        raise FileNotFoundError(path)
    return [discovered[key] for key in sorted(discovered)]


def _merge_threat_contexts(contexts: Iterable[dict[str, Any]]) -> dict[str, Any]:
    impacts: set[str] = set()
    attack_paths: set[str] = set()
    references: dict[tuple[Any, ...], dict[str, Any]] = {}

    for context in contexts:
        if not isinstance(context, dict):
            continue
        impacts.update(
            item for item in context.get("cia_impacts", []) if isinstance(item, str)
        )
        attack_paths.update(
            item for item in context.get("attack_paths", []) if isinstance(item, str)
        )
        for reference in context.get("external_references", []):
            if not isinstance(reference, dict):
                continue
            ids = tuple(
                sorted(
                    item for item in reference.get("ids", []) if isinstance(item, str)
                )
            )
            namespace = reference.get("namespace")
            if not isinstance(namespace, str) or not ids:
                continue
            key = (
                namespace,
                reference.get("version", ""),
                reference.get("source_url", ""),
                ids,
            )
            normalized = {"namespace": namespace, "ids": list(ids)}
            for optional in ("version", "source_url"):
                value = reference.get(optional)
                if isinstance(value, str) and value:
                    normalized[optional] = value
            references[key] = normalized

    return {
        "cia_impacts": sorted(impacts),
        "attack_paths": sorted(attack_paths),
        "external_references": [references[key] for key in sorted(references)],
    }


def build_report(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a JSON-compatible aggregate while preserving top-level findings."""

    counts: Counter[str] = Counter()
    findings: list[dict[str, Any]] = []
    inventories: list[dict[str, Any]] = []
    contexts: list[dict[str, Any]] = []
    status = "REVIEW_READY"

    for record in records:
        source = record["source"]
        result = record["result"]
        if STATUS_PRIORITY.get(result["status"], 0) > STATUS_PRIORITY[status]:
            status = result["status"]
        counts.update(result.get("finding_counts", {}))
        context = result.get("threat_context", {})
        contexts.append(context)
        for finding in result.get("findings", []):
            findings.append({"source": source, **finding})
        inventory_summary = {
            "source": source,
            "status": result["status"],
            "finding_counts": result.get("finding_counts", {}),
        }
        if isinstance(context, dict) and any(context.values()):
            inventory_summary["threat_context"] = context
        inventories.append(inventory_summary)

    return {
        "framework": "MONNA ADIP Lite",
        "version": __version__,
        "status": status,
        "inventory_count": len(records),
        "finding_counts": dict(sorted(counts.items())),
        "threat_context": _merge_threat_contexts(contexts),
        "findings": findings,
        "inventories": inventories,
        "disclaimer": "Triage result only; not a security certification.",
    }

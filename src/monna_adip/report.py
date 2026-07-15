"""Inventory discovery and aggregate report construction."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from .version import __version__

STATUS_PRIORITY = {"REVIEW_READY": 0, "INCOMPLETE": 1, "EXPOSED": 2}


def discover_inventory_paths(paths: Iterable[Path], recursive: bool = False) -> list[Path]:
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


def build_report(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a JSON-compatible aggregate while preserving top-level findings."""

    counts: Counter[str] = Counter()
    findings: list[dict[str, Any]] = []
    inventories: list[dict[str, Any]] = []
    status = "REVIEW_READY"

    for record in records:
        source = record["source"]
        result = record["result"]
        if STATUS_PRIORITY.get(result["status"], 0) > STATUS_PRIORITY[status]:
            status = result["status"]
        counts.update(result.get("finding_counts", {}))
        for finding in result.get("findings", []):
            findings.append({"source": source, **finding})
        inventories.append(
            {
                "source": source,
                "status": result["status"],
                "finding_counts": result.get("finding_counts", {}),
            }
        )

    return {
        "framework": "MONNA ADIP Lite",
        "version": __version__,
        "status": status,
        "inventory_count": len(records),
        "finding_counts": dict(sorted(counts.items())),
        "findings": findings,
        "inventories": inventories,
        "disclaimer": "Triage result only; not a security certification.",
    }

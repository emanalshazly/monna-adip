"""Optional JSON Schema validation for ADIP inventories."""

from __future__ import annotations

import json
from importlib import resources
from typing import Any


class ValidationDependencyError(RuntimeError):
    """Raised when optional schema-validation dependencies are unavailable."""


def load_schema() -> dict[str, Any]:
    schema_resource = resources.files("monna_adip").joinpath(
        "schemas", "inventory.schema.json"
    )
    return json.loads(schema_resource.read_text(encoding="utf-8"))


def validate_inventory(inventory: Any) -> list[str]:
    """Return stable, human-readable schema errors for an inventory."""

    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:
        raise ValidationDependencyError(
            "Schema validation requires the optional dependency: "
            "python -m pip install 'monna-adip[validation]'"
        ) from exc

    validator = Draft202012Validator(load_schema())
    errors = sorted(validator.iter_errors(inventory), key=lambda item: list(item.path))
    rendered: list[str] = []
    for error in errors:
        path = "$"
        for part in error.absolute_path:
            path += f"[{part}]" if isinstance(part, int) else f".{part}"
        rendered.append(f"{path}: {error.message}")
    return rendered

"""Draft-inventory generation from public interface descriptions.

Generators draft, never silently approve. Every generated trust label,
origin, and impact is a conservative placeholder that must pass human
review before the inventory is treated as an assessment input.
"""

from __future__ import annotations

from typing import Any

GENERATOR_NOTE = (
    "Draft inventory generated from an MCP tool manifest. Every trust label, "
    "origin, and impact is a placeholder and must pass human review."
)
UNMAPPED_ORIGIN = "unmapped: replace with the true source object during review"


class ManifestError(ValueError):
    """Raised when a tool manifest cannot be interpreted."""


def _extract_tools(manifest: Any) -> list[dict[str, Any]]:
    if isinstance(manifest, list):
        tools = manifest
    elif isinstance(manifest, dict):
        candidate = manifest.get("tools")
        if candidate is None and isinstance(manifest.get("result"), dict):
            candidate = manifest["result"].get("tools")
        tools = candidate
    else:
        tools = None

    if not isinstance(tools, list) or not tools:
        raise ManifestError(
            "Manifest must contain a non-empty tools array "
            "(accepted shapes: {\"tools\": [...]}, a tools/list JSON-RPC "
            "response, or a bare array of tools)."
        )
    for position, tool in enumerate(tools):
        if not isinstance(tool, dict) or not str(tool.get("name", "")).strip():
            raise ManifestError(f"Tool at position {position} has no usable name.")
    return tools


def _schema_properties(schema: Any) -> dict[str, Any]:
    if not isinstance(schema, dict):
        return {}
    properties = schema.get("properties")
    return properties if isinstance(properties, dict) else {}


def _free_text_trust(property_schema: Any) -> str:
    """Free-text values default to untrusted; constrained values to unknown."""

    if not isinstance(property_schema, dict):
        return "untrusted"
    if property_schema.get("enum") is not None or property_schema.get("const") is not None:
        return "unknown"
    property_type = property_schema.get("type")
    if property_type in (None, "string"):
        return "untrusted"
    return "unknown"


def generate_from_mcp(manifest: Any) -> dict[str, Any]:
    """Draft an ADIP inventory from an MCP tool manifest (tools/list shape)."""

    tools = _extract_tools(manifest)

    catalog_fields: list[dict[str, Any]] = []
    context_fields: list[dict[str, Any]] = []
    data_objects: list[dict[str, Any]] = []
    actions: list[dict[str, Any]] = []

    for tool in tools:
        name = str(tool["name"]).strip()

        catalog_fields.append(
            {
                "name": f"{name}.description",
                "trust": "untrusted",
                "origin": "MCP server manifest",
                "security_role": "content",
            }
        )

        response_properties = _schema_properties(tool.get("outputSchema"))
        if response_properties:
            data_objects.append(
                {
                    "id": f"{name}-response",
                    "format": "json",
                    "structural_isolation": False,
                    "fields": [
                        {
                            "name": field_name,
                            "trust": _free_text_trust(field_schema),
                            "origin": f"response from MCP tool '{name}'",
                            "security_role": "content",
                        }
                        for field_name, field_schema in response_properties.items()
                    ],
                }
            )

        parameters: list[dict[str, Any]] = []
        for parameter_name in _schema_properties(tool.get("inputSchema")):
            context_fields.append(
                {
                    "name": f"{name}.{parameter_name}",
                    "trust": "unknown",
                    "origin": UNMAPPED_ORIGIN,
                    "security_role": "action_argument",
                }
            )
            parameters.append(
                {
                    "name": parameter_name,
                    "source": {"object": "agent-context", "field": f"{name}.{parameter_name}"},
                    "deterministic_validation": False,
                    "provenance_check": False,
                }
            )

        actions.append(
            {
                "id": name,
                "impact": "high",
                "draft_note": "Impact defaulted conservatively; set the real impact during review.",
                "user_confirmation": False,
                "parameters": parameters,
            }
        )

    data_objects.insert(
        0,
        {
            "id": "tool-catalog",
            "format": "json",
            "structural_isolation": False,
            "fields": catalog_fields,
        },
    )
    if context_fields:
        data_objects.insert(
            1,
            {
                "id": "agent-context",
                "format": "custom",
                "structural_isolation": False,
                "fields": context_fields,
            },
        )

    return {
        "system": {
            "name": "MCP toolset draft",
            "description": GENERATOR_NOTE,
        },
        "draft": True,
        "generator": {"tool": "monna-adip", "source": "mcp"},
        "data_objects": data_objects,
        "actions": actions,
    }

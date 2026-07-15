# Public Roadmap

## Inventory generators

The largest adoption barrier is the initial field-level inventory. Generators
draft, never silently approve, an inventory from public interface
descriptions.

The MCP tool-manifest generator shipped with `monna-adip generate --from mcp`;
see the [CLI reference](CLI.md). Planned command surface for the rest:

```text
monna-adip generate --from openapi path/to/openapi.json --output draft.json
```

Generator rules:

- Generated trust labels default to `unknown` unless provenance is explicit.
- Descriptions and free-text values default to `untrusted`.
- Tool names and schema keys are not automatically treated as trusted values.
- Every generated inventory is marked `draft` and must pass human review.
- Generators do not infer authorization or mitigation sufficiency.

Remaining order:

1. ~~MCP tool-manifest generator~~ (shipped)
2. OpenAPI operation and parameter generator
3. Framework adapters for common agent tool schemas
4. Diff mode to detect inventory drift across schema versions

This work remains within the public open-core boundary. Weighted scoring,
exploit corpora, and automated mitigation selection remain reserved.

# CLI Reference

## Synopsis

```text
monna-adip INVENTORY [INVENTORY ...] [options]
monna-adip generate --from mcp MANIFEST [--output PATH] [--compact]
```

An input can be a JSON inventory file or a directory. Directories include
top-level `*.json` files by default; add `--recursive` for nested inventories.
Duplicate file paths are de-duplicated.

## Options

| Option | Purpose |
|---|---|
| `--version` | Print the installed MONNA ADIP version. |
| `--format json` | Machine-readable aggregate report; default. |
| `--format text` | Concise reviewer-oriented terminal report. |
| `--format markdown` | Table report suitable for PR comments or artifacts. |
| `--format sarif` | SARIF 2.1.0 for GitHub code scanning. |
| `--output PATH` | Write the report to a file instead of stdout. |
| `--validate` | Validate every inventory against the packaged JSON Schema first. |
| `--recursive` | Recursively scan input directories. |
| `--compact` | Minify JSON or SARIF output. |

`--validate` requires the optional extra:

```bash
python -m pip install "monna-adip[validation]"
```

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Analysis completed and aggregate status is `REVIEW_READY`. |
| `2` | Analysis completed and aggregate status is `EXPOSED` or `INCOMPLETE`. |
| `3` | Input, JSON, schema-validation, read, or write error. |

The exit code describes the aggregate status across all scanned inventories.

## JSON compatibility

The v0.2 aggregate retains `status`, `finding_counts`, and `findings` at the
top level. Every finding now includes `source`, and the report adds
`inventory_count` plus per-inventory summaries.

Every finding also carries a `basis` label stating its epistemic ground:
`structural` means the analyzer observed the problem directly in the
inventory document (missing arrays, malformed entries, invalid trust
classes, unresolvable sources); `declared` means the finding is derived
from trust, impact, or evidence labels the inventory author declared. The
analyzer never inspects the running system, so no finding is ever a
measured runtime fact.

## Generating a draft inventory

`monna-adip generate --from mcp` drafts an inventory from an MCP tool manifest
(the result of a `tools/list` call, a full JSON-RPC response, or a bare tools
array):

```bash
monna-adip generate --from mcp examples/mcp-toolset/manifest.json --output draft.json
```

Generator rules (see the [roadmap](ROADMAP.md)):

- Trust labels default to `unknown`; descriptions and free-text values default
  to `untrusted`.
- Action impact defaults conservatively to `high` and must be reviewed.
- Every tool parameter maps to an `agent-context` field with an unmapped
  origin, so analysis of an unreviewed draft intentionally reports `EXPOSED`
  ADIP-01 findings until a human maps each argument to its true source.
- The draft is marked `"draft": true` and is not an assessment result.

Exit codes: `0` on success, `3` on manifest or write errors.

## SARIF upload

```yaml
- run: monna-adip inventories --recursive --format sarif --output adip.sarif
  continue-on-error: true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: adip.sarif
```

Treat the analyzer as triage, not certification. A SARIF result identifies an
architecture evidence gap; it is not proof of exploitability.

SARIF rule metadata tags each control with its primary OWASP Top 10 for
Agentic Applications 2026 vector (`external/owasp-asi/ASI0X`); see the
[OWASP mapping](OWASP-MAPPING.md).

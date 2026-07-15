# CLI Reference

## Synopsis

```text
monna-adip INVENTORY [INVENTORY ...] [options]
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

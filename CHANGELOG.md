
# Changelog

## 0.3.0.dev0 — Unreleased

- Added optional CIA impacts, attack paths, and generic external taxonomy references.
- Added output/sink inventories with exact source-field dependencies.
- Extended ADIP-03 to high-impact output sinks.
- Extended ADIP-05 to non-independent verification, including LLM judges.
- Extended ADIP-06 to provenance loss across downstream model boundaries.
- Preserved threat context in text, Markdown, JSON, aggregate reports, and SARIF.
- Added independent APE Taxonomy compatibility guidance without redistributing its content.
- Added safe multi-model before/after examples and focused regression tests.

## 0.2.0 — 2026-07-15

- Added `monna-adip generate --from mcp` to draft an inventory from an MCP tool manifest.
- Mapped every control to its primary OWASP Agentic Applications 2026 vector, with ASI tags in SARIF rule metadata.
- Added a `basis` label (`structural` or `declared`) to every finding stating its epistemic ground.
- Implemented ADIP-07 checks for mitigation claims without verification evidence.
- Added optional Draft 2020-12 JSON Schema validation through `jsonschema`.
- Added text, Markdown, and SARIF output alongside JSON.
- Added multiple-file and directory scanning with aggregate findings.
- Added `--version`, `--output`, `--format`, `--recursive`, and `--validate`.
- Expanded the test suite across all finding IDs, CLI paths, and renderers.
- Added Python 3.11, 3.12, and 3.13 CI coverage.
- Added before/after email-agent and code-agent examples.
- Added a PyPI trusted-publishing workflow for tagged GitHub releases.

## 0.1.0 — 2026-07-15

- Published the seven-control open-core framework.
- Added the field-level inventory schema and safe synthetic template.
- Added the dependency-free Lite analyzer.
- Added research attribution and source-to-framework mapping.
- Added the proposed SecurityFortress V23 integration specification.

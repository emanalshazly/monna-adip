
# MONNA ADIP™

**English** | [العربية](README_AR.md)

**Agent Data Integrity Protocol**
Research Extension 01 · Open Core v0.3.0.dev0

MONNA ADIP is a defensive framework and command-line analyzer for finding
trust-boundary failures inside AI-agent data. It audits tool responses,
retrieved objects, metadata, mitigation evidence, and action arguments at field
level so teams can see when attacker-influenced data may be mistaken for
trusted agent state.

The project is research-informed by Choi et al., *Agent Data Injection Attacks
are Realistic Threats to AI Agents* (arXiv:2607.05120v1, 2026). It is an
independent defensive extension by MONNA Consulting™, not an official artifact
of the paper and not endorsed by its authors.

## What v0.3 development adds

- Optional threat context with CIA impacts, attack paths, and external taxonomy references
- Multi-model provenance checks for downstream LLM handoffs
- Output/sink integrity checks for execution, storage, transmission, rendering, and model forwarding
- Independent-verification modeling for LLM judges, humans, deterministic gates, and external services
- External context preserved in JSON, text, Markdown, and SARIF
- Safe multi-model before/after examples

See [APE compatibility guidance](docs/APE-COMPATIBILITY.md). The integration is independent, identifier-only, and does not redistribute the external taxonomy.

## What v0.2 added

- All seven public controls implemented, including ADIP-07 evidence checks
- Optional JSON Schema validation while keeping the core dependency-free
- JSON, text, Markdown, and SARIF output
- Multiple files, directory scanning, and aggregate reports
- `--version`, `--output`, `--recursive`, and `--validate`
- Python 3.11–3.13 CI matrix
- Before/after email-agent and code-agent examples
- Trusted-publishing workflow for PyPI releases
- Arabic README, quick start, framework guide, examples, and terminology glossary

## Why this exists

Conventional prompt-injection defenses focus on separating instructions from
data. Agent Data Injection (ADI) exposes a different boundary: trusted and
untrusted values can coexist inside the same tool response, object, or context
block. An agent may continue following the user's goal while acting on a forged
identifier, origin, metadata field, or tool-history record.

MONNA ADIP operationalizes that problem through seven controls:

1. Trust Origin Mapping
2. Field-Level Trust Classification
3. Boundary Collision Detection
4. Structural Ambiguity Review
5. Decision Dependency Tracing
6. Action Integrity Gates
7. Mitigation and Verification Mapping

See [the framework specification](docs/FRAMEWORK.md) for the full open-core
method, and the [OWASP mapping](docs/OWASP-MAPPING.md) for how each control
relates to the OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10).
The [APE compatibility guide](docs/APE-COMPATIBILITY.md) explains the optional
attack-context reference layer and its attribution boundary.

## Install

Requires Python 3.11 or later.

From a checkout:

```bash
python -m pip install -e .
```

Add optional standards-based schema validation:

```bash
python -m pip install -e ".[validation]"
```

The analyzer core has no runtime dependencies. The `validation` extra installs
`jsonschema` only for `--validate`.

## Quick start

Human-readable triage:

```bash
monna-adip examples/example-inventory.json --format text
```

Validate user input before analysis:

```bash
monna-adip examples/example-inventory.json --validate --format text
```

Scan a directory and write a Markdown report:

```bash
monna-adip examples --recursive --format markdown --output adip-report.md
```

Create SARIF for GitHub code scanning:

```bash
monna-adip inventories/ --format sarif --output adip.sarif
```

Draft an inventory from an MCP tool manifest instead of writing it by hand
(the draft must pass human review before analysis):

```bash
monna-adip generate --from mcp examples/mcp-toolset/manifest.json --output draft.json
```

JSON remains the default for backward-compatible piping. See the
[CLI reference](docs/CLI.md) for formats and exit codes.

## Arabic documentation

- [Arabic README — الواجهة العربية](README_AR.md)
- [Arabic quick start — البداية السريعة](docs/QUICKSTART_AR.md)
- [Arabic framework guide — مرجع الإطار](docs/FRAMEWORK_AR.md)
- [Arabic examples — شرح الأمثلة](docs/EXAMPLES_AR.md)
- [Arabic–English glossary — قاموس المصطلحات](docs/GLOSSARY_AR.md)

Machine-readable identifiers, JSON keys, trust values, CLI flags, and SARIF
rule IDs remain in English to preserve one interoperable schema.

## Example cases

- [Email agent: before and after](examples/email-agent/)
- [Code review agent: before and after](examples/code-agent/)
- [Multi-model review agent: before and after](examples/multi-model-agent/)
- [Examples guide](docs/EXAMPLES.md)

The examples are synthetic and defensive. They do not include exploit payloads.

## Repository map

```text
docs/                         Framework, CLI, examples, and research mapping
schemas/                      Public machine-readable inventory contract
templates/                    Blank assessment template
examples/                     Safe synthetic before/after inventories
src/monna_adip/               Dependency-free analyzer and CLI
tests/                        Analyzer, validation, CLI, and renderer tests
```

## Open-core boundary

This repository includes the public taxonomy, inventory model, deterministic
baseline checks, safe examples, and integration guidance. It does not include
MONNA's commercial scoring formula, exploit corpus, mitigation-selection engine,
client report logic, or protected SecurityFortress implementation.

See [Open Core Boundary](docs/OPEN-CORE-BOUNDARY.md).

## Responsible use

This project is defensive. Do not submit exploit payloads, reproduction steps
against live services, secrets, or vendor-confidential vulnerability details.
See [SECURITY.md](SECURITY.md).

## Research citation

- Woohyuk Choi, Juhee Kim, Taehyun Kang, Jihyeon Jeong, Luyi Xing, and
  Byoungyoung Lee. "Agent Data Injection Attacks are Realistic Threats to AI
  Agents." arXiv:2607.05120v1, 2026.
- Paper: https://arxiv.org/abs/2607.05120
- DOI: https://doi.org/10.48550/arXiv.2607.05120

The paper is licensed CC BY 4.0. This repository does not redistribute its
figures, payloads, benchmark, or source code.

## License and marks

Original repository materials are licensed under Apache License 2.0. MONNA,
MONNA ADIP, SecurityFortress, and related names and marks are not granted under
that license. See [NOTICE](NOTICE).

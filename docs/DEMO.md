# Local demo path

This walkthrough exercises the committed synthetic fixtures from a clean checkout. It does not call an external model, scan a live system, or represent a hosted deployment.

## 1. Create an isolated environment

```bash
python -m venv .venv
python -m pip install -e ".[validation]"
```

Activate the environment using the command appropriate for your shell.

## 2. Run the quality gate

```bash
python -m unittest discover -s tests -v
monna-adip --version
```

The version must remain `0.3.0.dev0` while the project is in the documented Alpha development state.

## 3. Inspect one field-level analysis

```bash
monna-adip examples/example-inventory.json --validate --format markdown
```

Review the reported trust origins, boundary collisions, decision dependencies, and action gates against the input JSON. A generated report is deterministic triage evidence for that fixture only.

## 4. Compare a synthetic before/after pair

```bash
monna-adip examples/email-agent/before.json --validate --format text
monna-adip examples/email-agent/after.json --validate --format text
```

The examples are safe synthetic inventories. They do not prove that a production agent or mitigation is secure.

## Release boundary

A new public release requires the repository's Python 3.11–3.13 CI matrix and release checks to pass for the release commit. This document does not replace those receipts.

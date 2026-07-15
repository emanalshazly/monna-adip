# MONNA ADIP™

**Agent Data Integrity Protocol**  
Research Extension 01 · Open Core v0.1.0

MONNA ADIP is a defensive framework for finding trust-boundary failures inside
AI-agent data. It audits tool responses, retrieved objects, metadata, and action
arguments at field level so teams can see when attacker-influenced data may be
mistaken for trusted agent state.

The project is research-informed by Choi et al., *Agent Data Injection Attacks
are Realistic Threats to AI Agents* (arXiv:2607.05120v1, 2026). It is an
independent defensive extension by MONNA Consulting™, not an official artifact
of the paper and not endorsed by its authors.

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
method.

## Quick start

Requires Python 3.11 or later and has no runtime dependencies.

```bash
python -m pip install -e .
python -m monna_adip examples/example-inventory.json
```

To start an assessment:

1. Copy `templates/assessment.json`.
2. Describe data objects at field level.
3. Map action parameters back to their source fields.
4. Run the Lite analyzer.
5. Review findings and add deterministic controls outside the LLM.

The Lite analyzer is a triage aid. It does not prove that an agent is secure,
execute attack payloads, or replace architecture review.

## Repository map

```text
docs/                         Framework and research mapping
schemas/                      Machine-readable inventory contract
templates/                    Blank assessment template
examples/                     Safe, synthetic example
src/monna_adip/               Dependency-free Lite analyzer
tests/                        Analyzer regression tests
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


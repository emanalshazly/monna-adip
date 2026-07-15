# SecurityFortress Integration Specification

Status: proposal only. No production MONNA file is modified by this release.

## Proposed designation

**SecurityFortress V23 — Intra-Context Trust Boundary Integrity**

Adoption gate: promote only after the v0.1.x inventory model and analyzer pass
synthetic regression tests and at least two documented architecture case
studies.

## Placement

```text
Module B / Harness
  -> tool and context assembly evidence
Module D / SecurityFortress V1-V22
  -> existing prompt, tool, metadata, and agent protections
V23 / ADIP extension
  -> field-level trust + action dependency integrity
GAGE / Governance (when implemented)
  -> control ownership, evidence, and attestation
```

## Inputs from MONNA modules

| Source | Required handoff |
|---|---|
| Harness | Tool list, response format, context assembly, recovery path |
| SecurityFortress | Existing injection, metadata, tool, and permission controls |
| Agent Security Analyst | OWASP ASI applicability and architecture gaps |
| Attack Surface Auditor | Data boundaries, external sources, provenance questions |
| GAGE, future | Control owner, evidence status, review schedule |

## Proposed V23 checks

1. `V23.1 Trust Origin Completeness`
2. `V23.2 Mixed-Trust Object Isolation`
3. `V23.3 Structural Ambiguity Exposure`
4. `V23.4 Security Anchor Verification`
5. `V23.5 Action Argument Provenance`
6. `V23.6 Derived-Data Taint Preservation`
7. `V23.7 Independent Confirmation Integrity`
8. `V23.8 Mitigation Evidence Sufficiency`

## Crosswalk

| ADIP finding | Existing MONNA touchpoint | Proposed treatment |
|---|---|---|
| ADIP-01 | Agent Security Analyst data-classification gap | Expand from system-level classification to field provenance. |
| ADIP-02 | SecurityFortress metadata injection | Distinguish forged trusted data from injected instructions. |
| ADIP-03 | Tool misuse and permission controls | Validate arguments before authorization or execution. |
| ADIP-04 | Attack Surface Auditor data boundary | Add serializer and structural ambiguity evidence. |
| ADIP-05 | Human confirmation / HITL | Require independent evidence channel for high-impact actions. |
| ADIP-06 | Harness state and derived context | Preserve least-trusted relevant provenance. |
| ADIP-07 | Quality Gate and governance evidence | Require control test and evidence owner. |

All mappings and the V23 design are `[MONNA-Analysis-2026]`.

## Non-merge conditions

Do not promote V23 when:

- the field inventory cannot represent real MONNA agent tool responses;
- the public and protected IP boundaries are not documented;
- tests cover only JSON and make universal-format claims;
- the framework implies prompt-only prevention;
- claims are not separated into paper-derived and MONNA analysis.

## Release path

1. `v0.1.0`: public architecture and Lite analyzer.
2. `v0.1.1`: two safe case studies and schema feedback.
3. `v0.2.0`: mitigation evidence model and OWASP crosswalk review.
4. Internal validation: commercial scoring and red-team corpus.
5. `V23 candidate`: formal merge review against current production baseline.


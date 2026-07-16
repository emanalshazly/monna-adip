# OWASP Agentic Applications Mapping

This document maps the seven MONNA ADIP controls to the OWASP Top 10 for
Agentic Applications 2026 (ASI01–ASI10) and, where applicable, to the OWASP
Agentic AI Threats and Mitigations taxonomy (T01–T17).

Sources:

- OWASP Top 10 for Agentic Applications 2026, OWASP GenAI Security Project,
  December 2025.
  https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- OWASP Agentic AI: Threats and Mitigations Guide (T01–T17).
  https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/

The ASI identifiers, vector names, and T-numbers are OWASP content
(`[OWASP-ASI-2026]`). The ADIP-to-ASI mapping itself is an original MONNA
interpretation (`[MONNA-Analysis-2026]`) and is confidence-classed per row:
`[SEMANTIC]` means the two controls address the same failure mode at
different layers, not that OWASP endorses or references ADIP.

## Control mapping

| ADIP control | Finding | Primary ASI vector | T-refs | Confidence |
|---|---|---|---|---|
| ADIP-01 | Unknown or invalid security-relevant provenance | ASI06 Memory & Context Poisoning | T1, T12 | [SEMANTIC] |
| ADIP-02 | Untrusted value assigned a trusted security role | ASI03 Identity & Privilege Abuse | T3, T8, T9 | [SEMANTIC] |
| ADIP-03 | Sensitive action depends on an unverified field | ASI02 Tool Misuse & Exploitation | T2 | [SEMANTIC] |
| ADIP-04 | Mixed-trust structural ambiguity | ASI01 Agent Goal Hijack | T6, T7 | [SEMANTIC] |
| ADIP-05 | Non-independent verification dependency | ASI09 Human-Agent Trust Exploitation | T10, T15 | [SEMANTIC] |
| ADIP-06 | Derived or downstream value loses provenance | ASI06 Memory & Context Poisoning | T1, T12 | [SEMANTIC] |
| ADIP-07 | Mitigation lacks verification evidence | Cross-cutting (no single vector) | — | [SEMANTIC] |

Notes `[MONNA-Analysis-2026]`:

- ADIP-02 aligns with the 2026 framing that identity and delegated trust are
  the primary agentic attack surface: a forged identifier, origin, or
  authorization value inside agent data is an identity-abuse pathway.
- ADIP-04 maps to goal hijack because mixed-trust serialization without
  structural isolation is the architectural precondition that lets untrusted
  content displace trusted context.
- ADIP-07 is an assessment-quality control: unverified mitigation claims can
  mask exposure on any vector, so it is tagged cross-cutting rather than
  forced onto a single ASI ID.
- T16 and T17 exist in the current Threats and Mitigations guide but are not
  cross-referenced here; this mapping only uses T-numbers that OWASP maps to
  the corresponding ASI vectors.

## SARIF tags

`monna-adip --format sarif` emits the primary ASI vector for each rule in the
rule metadata (`properties.tags` as `external/owasp-asi/ASI0X` plus a
machine-readable `properties.owaspAsi2026` array), so GitHub code scanning
and other SARIF consumers can group ADIP findings by OWASP vector. ADIP-07
carries no ASI tag.

## Scope boundary

This mapping is descriptive, not a compliance claim. An ADIP inventory that
analyzes clean does not certify OWASP ASI coverage: ADIP examines field-level
data trust in agent data paths, which is one slice of the agentic attack
surface. Runtime concerns such as sandbox escape, inter-agent transport
security, rate limiting, and rogue-agent detection are out of ADIP's scope
and are not mapped.

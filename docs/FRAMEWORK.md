
# MONNA ADIP Framework Specification

Version: 0.3.0.dev0
Status: Research Extension 01
Claim labels: paper-derived statements are cited; original interpretations are
marked `[MONNA-Analysis-2026]`.

## 1. Scope

MONNA ADIP audits whether an AI agent preserves the integrity and provenance of
data used for decisions and actions. It focuses on the boundary *within agent
data*: trusted and untrusted data may be placed in the same response, object, or
context block.

The framework covers:

- Web, email, coding, RAG, browser, and MCP-enabled agents
- JSON, XML, DOM-like, Markdown, and custom tool-response formats
- Metadata, identifiers, origins, URLs, tool names, execution history, and
  derived variables
- Model-to-model handoffs and LLM judge paths
- Outputs consumed by tools, renderers, storage, external systems, or other models
- Read, write, click, execute, merge, send, purchase, approve, and equivalent
  actions

It does not claim to:

- Prove immunity to ADI or indirect prompt injection
- Replace deterministic parsing, authorization, sandboxing, or data-flow policy
- Generate or execute exploit payloads
- Assess infrastructure vulnerabilities outside the agent data path

## 2. Core model

For each agent data object `D`, record four trust classes:

| Class | Meaning |
|---|---|
| `trusted` | Produced and integrity-protected by an authorized agent, tool, or backend. |
| `untrusted` | Directly or indirectly controllable by an external party. |
| `derived` | Computed from one or more inputs; inherits the least-trusted relevant provenance unless independently verified. |
| `unknown` | Origin or integrity cannot be established. Treat as untrusted for sensitive decisions. |

`[MONNA-Analysis-2026]`: Trust is a property of provenance and verification,
not of a field name. A field named `sender`, `url`, or `tool_result` is not
trusted merely because its label looks authoritative.

## 3. Assessment units

Assess the data path at four nested levels:

1. **Block** — tool call and corresponding response or execution-history unit.
2. **Object** — an email, DOM element, issue, transaction, document, or record.
3. **Field** — a named attribute such as sender, URL, ID, body, or status.
4. **Value** — the content and its provenance, transformation, and validation.

An action is assessed separately and linked back to the exact fields that
provide each argument. An output sink is also assessed separately and linked
to every field that influences the emitted value.

## 4. Seven-control protocol

### C1 — Trust Origin Mapping

For every object and field, capture:

- producing component
- original source
- attacker influence path
- transformations
- integrity mechanism
- trust class and supporting evidence

**Gate C1:** No security-relevant field may remain `unknown` before a
high-impact action is enabled.

### C2 — Field-Level Trust Classification

Classify keys and values independently. Identify security roles:

- `content`
- `identifier`
- `origin`
- `authorization`
- `tool_history`
- `verification_result`
- `action_argument`

**Gate C2:** A security role must not be assigned from untrusted content merely
because the model interprets the content as structured metadata.

### C3 — Boundary Collision Detection

Flag an object when trusted and untrusted values coexist and the LLM receives a
single serialized representation of both. Record the serializer and delimiter
family.

**Gate C3:** Mixed-trust objects require an explicit isolation, labeling,
randomization, or deterministic-validation decision.

### C4 — Structural Ambiguity Review

Review whether untrusted values can contain syntax resembling block, object, or
field boundaries. This is a design review, not a request to create payloads.

Check:

- Is the model shown raw serialized data?
- Does the representation mix structure and free text?
- Are security anchors expressed only as natural-language tokens?
- Can untrusted content imitate tool or provenance labels?
- Does escaping protect the parser but leave model interpretation ambiguous?

**Gate C4:** High-impact flows must not rely solely on the LLM's interpretation
of serialized boundaries.

### C5 — Decision Dependency Tracing

Map every action parameter and output sink to its source fields and record all
transformations. For derived values and model-to-model handoffs, preserve the
provenance and least-trusted relevant label of the inputs.

**Gate C5:** An action cannot be rated controlled unless reviewers can identify
which data caused the action and where that data originated.

### C6 — Action Integrity Gate

For `high` and `critical` actions and output sinks, require controls appropriate
to impact:

- deterministic schema and type validation
- independent provenance verification
- server-side object lookup using a trusted identifier
- fine-grained authorization policy
- data-flow or taint propagation
- sandbox restriction
- out-of-band human verification for exceptional cases

User confirmation based on the same potentially corrupted agent context is not
independent verification. An LLM judge is also not independent merely because
it is a separate call; reviewers must establish independent inputs, policy, and
evidence.

### C7 — Mitigation and Verification Mapping

For each finding, select a control and evidence test. Preserve the difference
between prevention, reduction, detection, and recovery.

| Control | Appropriate use | Important limitation |
|---|---|---|
| Fine-grained sandbox policy | Restrict high-impact actions and arguments | Policy creation and maintenance cost |
| Data-flow tracking | Preserve provenance through transformations | Label propagation and policy completeness |
| Runtime randomization | Make key/identifier imitation harder | Primarily useful for key-value formats |
| Sanitization | Reduce a known delimiter surface | Utility loss; not a complete defense |
| Independent validation | Re-fetch or verify security anchors outside model interpretation | Adds latency and integration work |
| Guardrail detection | Detect suspicious structural patterns | Detection does not establish provenance |

The first four limitations reflect the defense analysis in Choi et al.; the
independent-validation formulation and control taxonomy are
`[MONNA-Analysis-2026]`.

## 5. Finding taxonomy

| ID | Name | Baseline severity |
|---|---|---|
| ADIP-01 | Unknown security-relevant provenance | High |
| ADIP-02 | Untrusted value assigned a trusted security role | Critical |
| ADIP-03 | Sensitive action depends on an unverified field | High/Critical |
| ADIP-04 | Mixed-trust structural ambiguity | Medium/High |
| ADIP-05 | Non-independent verification dependency | High |
| ADIP-06 | Derived or downstream value loses provenance | High |
| ADIP-07 | Mitigation without verification evidence | Medium |

Severity must be adjusted using actual action impact and reachable controls.
The public taxonomy does not include MONNA's commercial weighted score.

## 6. Minimum evidence package

An assessment is incomplete without:

- object and field inventory
- trust-label rationale
- action-to-field and output-to-field dependency mapping
- verifier independence and model-to-model handoff evidence
- format and serializer description
- control ownership
- verification evidence or an explicit evidence gap

## 7. Completion states

- `INCOMPLETE`: required provenance or dependency information is missing.
- `EXPOSED`: at least one critical/high path lacks independent control.
- `REVIEW_READY`: no baseline critical/high finding remains, but specialist
  validation is still required.

These states are triage outcomes, not security certifications.

## 8. Threat-context interoperability

Inventories may declare CIA impacts, attack paths, and identifiers from external
taxonomies. These declarations provide reviewer context only; the Lite analyzer
does not import external datasets, infer attack techniques, or claim runtime
detection. See [APE Compatibility](APE-COMPATIBILITY.md) for the first public
interoperability profile and its license boundary.

## References

Choi, W. et al. *Agent Data Injection Attacks are Realistic Threats to AI
Agents*. arXiv:2607.05120v1 (2026). https://arxiv.org/abs/2607.05120

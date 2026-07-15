# Research-to-Framework Mapping

This file separates source findings from MONNA's operational extension.

| Research finding | MONNA ADIP translation | Status |
|---|---|---|
| ADI makes untrusted data appear trusted rather than instructional. | Separate instruction/data review from trusted/untrusted field review. | Source-derived |
| Trust boundaries exist inside agent data. | Assess block, object, field, and value levels. | Source-derived + operationalized |
| Probabilistic delimiter injection can alter model interpretation of structure. | Add Structural Ambiguity Review without publishing payloads. | Source-derived + safety-bounded |
| Existing instruction-injection guardrails do not reliably address ADI. | Do not accept prompt-only controls as sufficient evidence. | Source-derived |
| Fine-grained sandboxing and data-flow tracking can mitigate ADI but depend on policy quality. | Require policy scope and verification evidence. | Source-derived + operationalized |
| Randomization reduces some attacks but is format-limited. | Treat randomization as reduction, not universal prevention. | Source-derived |
| Sanitization can reduce success with utility cost. | Require explicit utility and data-corruption review. | Source-derived |
| Strict security can reduce useful task completion. | Record security/utility trade-offs per control. | Source-derived |
| Action parameters should be linked to exact source fields. | Add Decision Dependency Tracing. | `[MONNA-Analysis-2026]` |
| Confirmation using the same agent interpretation is not independent. | Add Same-Context Confirmation finding. | Source-informed + `[MONNA-Analysis-2026]` |

## Attribution boundary

MONNA ADIP does not claim to have discovered ADI or probabilistic delimiter
injection. Those contributions belong to Choi et al. MONNA's contribution is the
defensive assessment protocol, field inventory, action-dependency method,
baseline finding taxonomy, safe Lite analyzer, and SecurityFortress integration
design.

## Source

Woohyuk Choi, Juhee Kim, Taehyun Kang, Jihyeon Jeong, Luyi Xing, and
Byoungyoung Lee. "Agent Data Injection Attacks are Realistic Threats to AI
Agents." arXiv:2607.05120v1, submitted July 6, 2026.

- https://arxiv.org/abs/2607.05120
- https://doi.org/10.48550/arXiv.2607.05120


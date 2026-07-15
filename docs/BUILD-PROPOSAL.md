# Build Proposal and Approval Record

Status: approved for v0.1.0 build on 2026-07-15.

## Mechanistic core

### Input

- Agent and tool architecture
- Tool-response formats and schemas
- External data sources
- Field origins and trust classifications
- Agent actions, arguments, and authorization controls

### Process

1. Map the origin of each field.
2. Classify fields as trusted, untrusted, derived, or unknown.
3. Find objects that mix trust classes.
4. review structural ambiguity at block, object, field, and value levels.
5. Trace sensitive action arguments to their source fields.
6. require independent integrity controls for high-impact actions.
7. map gaps to mitigations and verification evidence.

### Output

- Trust map
- Field-level inventory
- Boundary-collision findings
- Action dependency graph
- Mitigation requirements
- Regression-test plan

### Failure modes

- Incorrect trust labels create false assurance.
- Prompt-only controls cannot enforce runtime isolation.
- Unstructured content limits precise field tracking.
- Overly strict controls can reduce legitimate agent utility.
- A clean inventory does not prove model-level robustness.

## Prompt-ability filters

| Filter | Result | Rationale |
|---|---|---|
| Operationalizable | PASS, hybrid | Inventory, reasoning, and reporting are prompt-operationalizable; enforcement needs runtime controls. |
| Differentiated | PASS | Field-level trust and action-dependency analysis is more specific than generic prompt-injection review. |
| Buyer match | PASS | Agent developers, AppSec teams, AI governance teams, and MCP/tool builders have a direct use case. |

All rationales in this section are `[MONNA-Analysis-2026]`.

## Anti-reverse-engineering decision

The public name describes the defensive outcome, not MONNA's protected scoring
or selection logic. The public release exposes an auditable baseline while the
commercial layer retains weighted scoring, attack corpora, automated mitigation
selection, and enterprise reporting.


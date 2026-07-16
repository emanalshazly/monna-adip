
# Example Inventories

All examples are synthetic, defensive, and payload-free.

## Support-ticket baseline

`examples/example-inventory.json` demonstrates an exposed derived decision:
the agent can close a ticket using an LLM-derived status that does not preserve
provenance. The example also demonstrates same-context confirmation risk.

## Email reply agent

### Before

`examples/email-agent/before.json` uses an attacker-influenced display sender as
an origin and action argument, mixes trusted and untrusted values without
isolation, and asks for confirmation using the same agent interpretation.

### After

`examples/email-agent/after.json` obtains the sender from the authenticated
backend envelope, records structural-isolation evidence, verifies the action
argument, and records independent confirmation evidence.

```bash
monna-adip examples/email-agent --format text
```

The aggregate remains `EXPOSED` because the directory intentionally contains
both the before and after inventories. Analyze `after.json` alone to obtain the
remediated result.

## Code review agent

### Before

`examples/code-agent/before.json` treats a commit identifier claimed in
untrusted pull-request content as a verification result and critical merge
argument.

### After

`examples/code-agent/after.json` separates untrusted prose from trusted
repository metadata and re-fetches the current commit identifier from the
backend before merge.

```bash
monna-adip examples/code-agent/after.json --validate --format markdown
```

The evidence identifiers are illustrative references to hypothetical tests;
teams must replace them with artifacts from their own systems.

## Multi-model review agent

### Before

`examples/multi-model-agent/before.json` passes retrieved content to another
model without preserving provenance, sends a high-impact output without both
required gates, and treats a shared-context LLM judge as independent review.

### After

`examples/multi-model-agent/after.json` preserves source labels through the
handoff, validates the output package, and uses an independently evidenced
external policy gate.

```bash
monna-adip examples/multi-model-agent --format text
```

The optional HiddenLayer APE identifiers are reviewer-supplied external
references. The examples do not copy taxonomy descriptions or prompts; see
[APE compatibility](APE-COMPATIBILITY.md).

# HiddenLayer APE Taxonomy Compatibility

Status: independent interoperability guidance for MONNA ADIP v0.3 development.

MONNA ADIP and the HiddenLayer Adversarial Prompt Engineering (APE) Taxonomy
describe different layers of an AI-security assessment:

- APE provides an attack-oriented vocabulary for prompt behavior, adversarial
  objectives, and security impact.
- MONNA ADIP provides a defensive inventory, provenance analysis, action gate,
  and verification-evidence protocol.

MONNA ADIP does not import, redistribute, translate, or modify the APE dataset.
Inventories may carry external identifiers as reviewer-supplied context. The
analyzer preserves those identifiers in JSON, text, Markdown, and SARIF without
claiming that a runtime attack occurred.

## Reference model

Use the optional inventory block:

```json
{
  "threat_context": {
    "cia_impacts": ["confidentiality", "integrity"],
    "attack_paths": ["indirect", "multi_model"],
    "external_references": [
      {
        "namespace": "hiddenlayer-ape",
        "version": "2026-06-18",
        "source_url": "https://github.com/hiddenlayerai/ape-taxonomy",
        "ids": ["HLT07.04", "HLT08.01", "HLT08.02"]
      }
    ]
  }
}
```

External identifiers are declarations by the inventory author. MONNA ADIP does
not validate their meaning, retrieve the external taxonomy, or infer them from
payload content.

## Independent crosswalk

This table records MONNA's compatibility analysis. It does not reproduce APE
descriptions or examples.

| MONNA ADIP finding | Potentially relevant external IDs |
|---|---|
| ADIP-01 — unknown provenance | HLT07.04, HLT08.01 |
| ADIP-02 — untrusted security role | HLT05.03, HLT05.05, HLT05.07 |
| ADIP-03 — unverified sensitive action or sink | HLG02.05, HLG02.06, HLG02.07 |
| ADIP-04 — structural ambiguity | HLT01.02, HLT01.05, HLT05.03 |
| ADIP-05 — non-independent verification | HLT08.02 |
| ADIP-06 — lost downstream provenance | HLT08.01 |
| ADIP-07 — unverified mitigation claim | Cross-cutting; reviewer assigned |

A mapping indicates conceptual relevance only. It is not evidence of
exploitability, detection, taxonomy conformance, or endorsement.

## Multi-model and output-sink extension

The v0.3 inventory can describe:

- an action's `verification` type, verifier, independence claim, and evidence;
- an `outputs` sink, its exact source fields, consumer, sink type, and impact;
- provenance preservation across model-to-model handoffs;
- deterministic validation and independent verification before a high-impact
  output is executed, stored, transmitted, rendered, or passed to another
  model.

The analyzer extends existing public findings instead of adding an eighth core
control:

- ADIP-03 covers unverified high-impact outputs.
- ADIP-05 covers non-independent LLM judges and other verification paths.
- ADIP-06 covers provenance loss across downstream model boundaries.
- ADIP-07 covers unsupported verification and provenance claims.

## Attribution and license boundary

HiddenLayer APE Taxonomy is available at
https://github.com/hiddenlayerai/ape-taxonomy and
https://ape.hiddenlayer.com. The repository states that the taxonomy is
licensed under Creative Commons Attribution-NoDerivatives 4.0 International.

MONNA ADIP's compatibility layer contains original schema fields, analyzer
logic, and mapping analysis. It does not include APE prompt examples,
descriptions, images, website code, or `ape.json`. HiddenLayer and APE names
are used only to identify the external source. No affiliation, sponsorship, or
endorsement is claimed.

For any future redistribution, translation, or modification of APE material,
obtain permission from the rights holder and conduct an appropriate license
review.

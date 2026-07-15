# Contributing

Thank you for improving MONNA ADIP's defensive open core.

## Accepted contributions

- Documentation corrections
- Schema interoperability improvements
- Deterministic defensive checks
- Safe synthetic examples
- Tests for false positives and false negatives
- Accessibility and developer-experience improvements

## Not accepted publicly

- Active exploit payloads
- Instructions targeting live services or named vendors
- Unpublished vulnerability details
- Client or production data
- Changes that disclose MONNA's protected scoring, corpus, or policy logic

## Development

```bash
python -m unittest discover -s tests -v
python -m monna_adip examples/example-inventory.json
```

The example intentionally exits with status 2 because it contains findings.
New checks must be deterministic, include tests, state their limitations, and
avoid claiming security certification.

## Research claims

Use a primary source for paper-derived claims. Label original interpretations
`[MONNA-Analysis-2026]` and do not imply endorsement by cited researchers.


# `cage-conformance`

A standalone verifier for the Cybernetic Agent Governance Engine (CAGE). It lets
a partner, a counterparty or an independent auditor check CAGE's governance
traces and tamper-evident evidence streams without a CAGE checkout and without
trusting any third-party code: the package uses only the Python standard
library.

It applies exactly the checks CAGE's own test suite applies. `model.py`,
`trace_conformance.py` and `stream_invariants.py` are byte-identical copies of
the repository's `proof/` modules, and CAGE's CI fails if they ever differ
(`scripts/check_conformance_sync.py`).

## Install

```bash
pip install ./packages/cage-conformance   # from a CAGE checkout, or the built wheel
```

## Verify a governance trace

`GOVERNANCE_TRACE` events, one JSON object per line in emission order, bare or
wrapped in an evidence record's `event` field:

```bash
cage-conformance verify --trace events.jsonl \
  --provider-id cage-kernel \
  --adapter-author-org "Google LLC" \
  --counterparty-org "Example Bank" \
  --adapter-version 5.0.0 \
  --adapter-commit 5b0055ad \
  --runner-org "Example Bank" \
  --runner-identity "ci@example-bank.test" \
  --output trace_report.json
```

Each event is projected onto the formal model and checked for `schema`, `plan`,
`coverage`, `seal`, `reachable`, `no_direct_bind` and `single_use`.

## Verify an evidence stream

`cage-audit/3.0` records exported from `cage:evidence:stream`, in order:

```bash
cage-conformance verify --stream evidence.jsonl \
  --expected-thresholds-digest <64-hex> --require-thresholds-loaded \
  [provenance options as above] --output stream_report.json
```

This checks the hash chain (RFC 8785 canonical JSON, SHA-256 links, contiguous
sequences) and the five stream invariants: no action binds without a routing
seal, the control barrier is never breached, a seal implies every stage passed,
rollback conserves the balance, and every denial produces an evidence record.

## Check a report

```bash
cage-conformance verify-report trace_report.json
```

This re-derives the verification posture and summary from the report's own
fields and rejects any report whose recorded values disagree. It also prints the
report digest: `sha256:` over the report's RFC 8785 canonical JSON.

A report names each input by its file name and the SHA-256 of its bytes, never
by its path, so anyone holding an input can confirm with `sha256sum` that a
report covers it. `verify-report` does not re-run the checks; to reproduce a
result, run `verify` on the same input.

Exit codes: `verify` returns 0 if conformant, 1 if not, 2 on unreadable input
or bad arguments. `verify-report` returns 0 for a valid report, 2 otherwise.
A run that checked nothing is never conformant.

## Verification posture

Every report carries a provenance block, and its posture is derived from it,
never taken from it:

| Posture | When |
|---|---|
| `AUTHOR_SELF_TEST` | The runner's organization is the adapter author's |
| `UNVERIFIED_LOCAL` | Anyone else, self-declared |
| `COUNTERPARTY_VERIFIED` | The counterparty, with a verified identity bound to the report |
| `INDEPENDENT_PARTY_VERIFIED` | A third party, with a verified identity bound to the report |

The runner's organization is self-declared, so a report on its own proves
nothing about who produced it. This version can therefore produce only the
first two postures, and `verify-report` rejects a report that claims either of
the others. Claiming them needs an attestation: an OIDC token from a pinned
issuer whose audience is the report digest. That arrives with the `attest`
command (`docs/architecture/CONFORMANCE_VERIFIER_SPEC.md` §3).

## License

Apache-2.0.

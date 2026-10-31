# `cage-conformance`

A standalone verifier for the Cybernetic Agent Governance Engine (CAGE). It lets
a partner, a counterparty or an independent auditor check CAGE's governance
traces and tamper-evident evidence streams without a CAGE checkout and without
trusting any third-party code: checking traces, streams and reports uses only
the Python standard library. Checking an attestation's signature is the one
step that needs a third-party package, `cryptography`, from the `attest` extra.

It applies exactly the checks CAGE's own test suite applies. `model.py`,
`trace_conformance.py` and `stream_invariants.py` are byte-identical copies of
the repository's `proof/` modules, and CAGE's CI fails if they ever differ
(`scripts/check_conformance_sync.py`).

## Install

```bash
pip install ./packages/cage-conformance            # from a CAGE checkout, or the built wheel
pip install './packages/cage-conformance[attest]'  # to attest reports or check attested ones
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
or bad arguments. `audience`, `attest` and `verify-report` return 0 on success,
2 otherwise. A run that checked nothing is never conformant.

## Attest a report

A report's runner is self-declared. To prove who ran it, bind an OIDC ID token
whose audience is the report digest, so that it attests exactly that report:

```bash
pip install './packages/cage-conformance[attest]'   # cryptography, for the RSA check
cage-conformance audience report.json               # cage-conformance:sha256:<digest>
# obtain an ID token with that audience (below), then:
cage-conformance attest report.json --token-file token --output attested.json
```

`attest` reads the token from `--token-file` or `$CAGE_CONFORMANCE_OIDC_TOKEN`,
never from the command line, and accepts it only if:

- its issuer is pinned: GitHub Actions, naming `github:<owner>/<repo>`, or
  Google, naming `google:<email>` for verified emails only;
- it is RS256-signed under a key of at least 2048 bits, fetched by `kid` from
  that issuer's published JWKS, never from the token;
- it is current, and its audience is this report's digest.

In GitHub Actions, with `permissions: id-token: write`:

```bash
curl -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=$(cage-conformance audience report.json)" \
  | python3 -c 'import json, sys; print(json.load(sys.stdin)["value"])' > token
```

With a Google service account, call the IAM Credentials `generateIdToken`
method with that audience and `includeEmail: true`.

`verify-report attested.json` re-verifies the token. Expiry no longer matters,
because the audience already binds the token to one report, so it verifies for
as long as the issuer publishes the key. The posture comes from the verified
principal and the party pins you trust, never from the organizations the runner
declared:

| Verified principal | Posture |
|---|---|
| One of the profile's author principals | `AUTHOR_SELF_TEST` |
| One of its counterparty principals | `COUNTERPARTY_VERIFIED` |
| Neither, with both roles pinned or no counterparty role | `INDEPENDENT_PARTY_VERIFIED` |
| Neither, while a role's principals are unpinned | None: it could hold that role |

The package pins the CAGE repository as the author of `trace-v1` and
`stream-v1`, and leaves the counterparty, the deploying operator, unpinned. So
only a verifier who knows the operator can grant `COUNTERPARTY_VERIFIED` or
`INDEPENDENT_PARTY_VERIFIED`, by passing its own pins with `--parties`:

```json
{
  "schema_version": "cage-conformance-parties/1",
  "profiles": {
    "trace-v1": {
      "author": ["github:google/cybernetic-agent-governance-engine"],
      "counterparty": ["github:example-bank/governance-ci"]
    }
  }
}
```

The embedded token's audience is specific to one report, so it authenticates
nowhere that checks its audience, and it expires within the hour. A Google
token carries the account's email, so attest with a service account rather than
a person's account.

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
nothing about who produced it. A report's own provenance therefore carries
only the first two postures, and `verify-report` rejects a report that claims
either of the others. Only an attested report earns them (above;
`docs/architecture/CONFORMANCE_VERIFIER_SPEC.md` §3.1).

## License

Apache-2.0.

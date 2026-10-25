# `cage-conformance` — Standalone Black-Box Conformance & Provenance Runner

`cage-conformance` is a standalone, zero-`src/` verification package for the
Cybernetic Agent Governance Engine (CAGE). It enables partners, counterparties,
and third-party auditors (such as regulatory sandboxes) to independently verify
CAGE trace invariants and partner wire contracts without a CAGE repository
checkout.

Every conformance report produced by `cage-conformance` embeds a mandatory
**`provenance` block** that deterministically derives the verification posture:

| Posture | Condition | Meaning |
|---|---|---|
| `AUTHOR_SELF_TEST` | `runner_org == adapter_author_org` | Executed by the organization that authored the integration adapter |
| `COUNTERPARTY_VERIFIED` | `runner_org == counterparty_org` (with verified OIDC identity) | Executed by the partner counterparty on the other side of the integration boundary |
| `INDEPENDENT_PARTY_VERIFIED` | `runner_org not in {adapter_author_org, counterparty_org}` (with verified OIDC identity) | Executed by an independent third party (e.g., regulator or external auditor) |
| `UNVERIFIED_LOCAL` | `identity_proof == "NONE"` (and `runner_org != adapter_author_org`) | Local or unauthenticated run without cryptographic/OIDC runner identity proof |

## Installation

```bash
pip install cage-conformance
```

## CLI Usage

### 1. Verify an exported `GOVERNANCE_TRACE` stream (`--trace`)

```bash
cage-conformance verify --trace events.jsonl \
  --provider-id kernel \
  --adapter-author-org "Google LLC" \
  --counterparty-org "FlowSignal" \
  --runner-org "FlowSignal" \
  --output trace_report.json
```

### 2. Verify a live partner or gateway endpoint (`--endpoint`)

```bash
cage-conformance verify \
  --endpoint https://flowsignal-cage-phase4-staging.example.run.app \
  --profile flowsignal-v0.2 \
  --provider-id provider_01 \
  --adapter-author-org "Google LLC" \
  --counterparty-org "FlowSignal" \
  --runner-org "FlowSignal" \
  --oidc-token "$OIDC_ID_TOKEN" \
  --output step1_conformance_report.json
```

### 3. Validate a conformance report's provenance & posture (`verify-report`)

```bash
cage-conformance verify-report step1_conformance_report.json
```

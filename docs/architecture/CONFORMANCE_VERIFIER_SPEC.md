# Standalone Conformance Verifier Specification (W4) & `feat/cage-conformance` Disposition

**Status:** Normative Specification (Workpackage `W4` / Track B Step B3)  
**Scope:** Standalone zero-`src/` trace, evidence-stream, and partner wire conformance verification (`proof/` → `packages/cage-conformance/`)

---

## 1. Purpose & Motivation

External partners, counterparties, and independent third-party auditors (such as regulatory sandboxes) need to verify three claims without checking out the full CAGE monorepo or importing `src/`:

1. **Decision Trace Conformance (`GOVERNANCE_TRACE`)**: Every runtime governance decision conforms to the reachable state space of the 7-tier deterministic formal model ([`proof/model.py`](../../proof/model.py)) and satisfies `no_direct_bind` and `single_use` ([`proof/trace_conformance.py`](../../proof/trace_conformance.py)).
2. **Evidence Stream Invariant Conformance (`EvidenceStreamSink` JSONL)**: Every tamper-evident audit stream satisfies RFC 8785 canonical JSON (`jcs_bytes`), SHA-256 hash-chain continuity (`compute_cage_audit_hash`), startup/header/decision `thresholds_digest` pinning (`POAM-2026-151`), zero-drop completeness, and the five stream-wide safety invariants (`I1_no_unsealed_actuation`, `I2_single_use_seal`, `I3_no_unsettled_mutating_allow`, `I4_monotonic_cbf_version`, `I5_quarantine_blocks_commit`) defined in [`proof/stream_invariants.py`](../../proof/stream_invariants.py).
3. **Attributable Wire Conformance**: Over-the-wire partner and gateway endpoint checks emit a signed or OIDC-bound conformance report whose `provenance` block deterministically records *who* ran the verification relative to the adapter author and counterparty.

Prior to this specification, `W4` was referenced in the repository only in the module docstring of [`tests/test_stream_invariants_oracle.py`](../../tests/test_stream_invariants_oracle.py#L18) (`1. proof/ modules have zero src/ imports (AST purity guard for W4 reuse)`), while an earlier unmerged prototype lived on branch `feat/cage-conformance` (`6e46ca00`).

---

## 2. Architectural Invariants (`W4`)

### 2.1 Zero-`src/` AST Purity in `proof/`

All Python modules in [`proof/`](../../proof/) are pure-stdlib verification artifacts that must never import from `src` or `src.*`:

| Module | Responsibility | Guard Test |
|---|---|---|
| [`proof/model.py`](../../proof/model.py) | 7-tier deterministic BFS state-space enumeration (`TIERS = ("ftra", "stpa", "opa", "confidence", "consensus", "cbf", "fiscal")`; `34` gated states, `38` under `EU_ECB`, `17` ungated, `31` skipped-tier) | [`tests/test_no_direct_bind_proof.py`](../../tests/test_no_direct_bind_proof.py), [`tests/test_stream_invariants_oracle.py`](../../tests/test_stream_invariants_oracle.py) |
| [`proof/trace_conformance.py`](../../proof/trace_conformance.py) | `GOVERNANCE_TRACE` projection onto `reachable_over(plan, profile)` plus `no_direct_bind` and `single_use` | [`tests/test_governance_trace_conformance.py`](../../tests/test_governance_trace_conformance.py), [`tests/test_stream_invariants_oracle.py`](../../tests/test_stream_invariants_oracle.py) |
| [`proof/stream_invariants.py`](../../proof/stream_invariants.py) | Pure-stdlib RFC 8785 `jcs_bytes`, `compute_cage_audit_hash`, and `check_stream()` over `I1`–`I5`, chain continuity, `thresholds_digest` pinning, and zero-drop check | [`tests/test_stream_invariants_oracle.py`](../../tests/test_stream_invariants_oracle.py) |
| [`proof/distributed_cbf_model.py`](../../proof/distributed_cbf_model.py) | Multi-process distributed CBF state-space twin of [`proof/DistributedCBF.tla`](../../proof/DistributedCBF.tla) | [`tests/test_distributed_cbf_proof.py`](../../tests/test_distributed_cbf_proof.py), [`tests/test_stream_invariants_oracle.py`](../../tests/test_stream_invariants_oracle.py) |
| [`proof/tla_pins.py`](../../proof/tla_pins.py) | Pinned TLC state counts and expected negative-control invariant violations for TLA+ specifications | [`tests/test_tla_specs_proof.py`](../../tests/test_tla_specs_proof.py), [`tests/test_stream_invariants_oracle.py`](../../tests/test_stream_invariants_oracle.py) |

`test_proof_directory_has_zero_src_imports` in [`tests/test_stream_invariants_oracle.py`](../../tests/test_stream_invariants_oracle.py) parses the AST of every `proof/*.py` file and fails if any `import src...` or `from src...` statement is introduced.

### 2.2 Single Source of Truth Between `proof/` and `packages/cage-conformance/`

`packages/cage-conformance/` must **never fork** the formal model or invariant checkers. When packaged as a standalone wheel:

1. **Authoritative Source**: [`proof/model.py`](../../proof/model.py), [`proof/trace_conformance.py`](../../proof/trace_conformance.py), and [`proof/stream_invariants.py`](../../proof/stream_invariants.py) remain the single authoritative implementations in the repository.
2. **Byte-for-Byte Sync Gate (`SYNC_PAIRS`)**: The CI sync check ([`scripts/check_conformance_sync.py`](../../scripts/check_conformance_sync.py)) must verify SHA-256 byte equality across **all three** modules:
   - [`proof/model.py`](../../proof/model.py)
   - [`proof/trace_conformance.py`](../../proof/trace_conformance.py)
   - [`proof/stream_invariants.py`](../../proof/stream_invariants.py)
3. **AST Isolation Gate**: No module under `packages/cage-conformance/` may import `src`, `src.*`, `proof` or `proof.*`. The `proof/` modules therefore import each other relatively (`from .model import ...`), so the same bytes resolve both in the repository and in the installed package.

### 2.3 CLI Surface (`cage-conformance`)

[`packages/cage-conformance/`](../../packages/cage-conformance/) ships the CLI. Checking traces, streams and reports uses only the Python standard library, so an auditor runs it without trusting third-party code. Checking an attestation's RS256 signature is the one step that needs a third-party package, `cryptography`, from the optional `attest` extra.

| Command | Status | Behavior |
|---|---|---|
| `verify --trace <events.jsonl>` | Shipped | Runs `check_trace()` from [`proof/trace_conformance.py`](../../proof/trace_conformance.py) and emits a provenance-stamped report |
| `verify --stream <evidence.jsonl>` | Shipped | Runs `check_stream()` from [`proof/stream_invariants.py`](../../proof/stream_invariants.py), with the options of [`scripts/check_trace_conformance.py`](../../scripts/check_trace_conformance.py) `--stream` |
| `audience <report.json>` | Shipped | Prints the audience an OIDC token must carry to attest the report (§3.1) |
| `attest <report.json>` | Shipped | Verifies an OIDC token and binds it to the report (§3.1) |
| `verify-report <report.json> [--parties <file>]` | Shipped | Re-derives the posture and summary from the report's own fields and rejects any disagreement; for an attested report, also re-verifies the token and derives the posture from the relying party's party pins (§3.1) |
| `verify --endpoint <url> --profile <profile>` | Planned | Black-box HTTP vectors against a live partner adapter or gateway endpoint; `substrate-v1` asserts `/governance/policy-version`'s `thresholds_digest` contract |

Each report holds one assertion per checker rule. A finding under a rule the package does not list still fails the report under its own name, and a run that checked nothing is not conformant. A report names each input by its file name and the SHA-256 of its bytes, never by its path, so an attestation over the report digest (§3.1) also commits to exactly what was verified.

---

## 3. Attributable Provenance & Verification Posture Schema

Every report emitted by `cage-conformance` embeds a mandatory `provenance` block. The posture is derived from the report's fields, never taken from them. A runner's organization is self-declared until an attestation (§3.1) verifies it:

| Posture | Condition | Evidentiary Meaning |
|---|---|---|
| `AUTHOR_SELF_TEST` | Unattested and the self-declared runner is the adapter author, or attested by a pinned author principal | Run by the organization that authored the adapter; proves author-side execution, not counterparty sign-off |
| `COUNTERPARTY_VERIFIED` | Attested, and the verified principal is one of the counterparty principals the relying party pins | Run by the organization on the other side of the seam, with a verified identity |
| `INDEPENDENT_PARTY_VERIFIED` | Attested, the verified principal is neither an author nor a counterparty principal, and both roles are pinned (or the seam has no counterparty) | Run by a third party (auditor, evaluator, regulatory sandbox), with a verified identity |
| `UNVERIFIED_LOCAL` | Not attested, and the self-declared runner is not the author | Cannot claim counterparty or independent verification |

`feat/cage-conformance` (`6e46ca00`) set its identity flag by parsing a runner's OIDC token without verifying the signature, so anyone could mint a token that claimed `COUNTERPARTY_VERIFIED`. The rebuilt package derives verified postures only from an attestation.

### 3.1 Attestation (`attest`)

Implemented in [`attestation.py`](../../packages/cage-conformance/src/cage_conformance/attestation.py):

1. `verify` emits an unattested report, whose own provenance can derive only `AUTHOR_SELF_TEST` or `UNVERIFIED_LOCAL`. `verify-report` rejects one that claims a verified posture.
2. `attest` binds an OIDC ID token whose audience is `cage-conformance:` plus the report digest (`sha256:` over the report's RFC 8785 canonical JSON), so it attests exactly one report and any edit to the report breaks it. The runner reads the audience with `audience`, and `attest` reads the token from a file or `$CAGE_CONFORMANCE_OIDC_TOKEN`, never from the command line.
3. The token must come from a pinned issuer: GitHub Actions (`https://token.actions.githubusercontent.com`) or Google (`https://accounts.google.com`). Its key is fetched by `kid` from that issuer's pinned JWKS URL, never from the token. An unknown `kid` fails closed, a header carrying its own key (`jwk`, `jku`, `x5c`, `x5u`) or critical extensions is refused, and only RS256 under keys of at least 2048 bits is accepted.
4. At `attest` the token must be current. At both `attest` and `verify-report`, it must not have been issued in the future or before the report's timestamp, allowing 60 seconds of clock skew either way.
5. The attested report embeds the token next to the unchanged report. `verify-report` re-verifies the token except for expiry, because the audience already binds it to one report. It therefore verifies for as long as the issuer publishes the key.
6. The verified principal is `github:<owner>/<repo>` (the `repository` claim) or `google:<email>` (verified emails only). It is compared with the party principals pinned for the report's contract profile, never with organizations the runner supplies, so a runner cannot name itself the counterparty.
7. The pins belong to the relying party, which is whoever runs `verify-report`: the package defaults, or a `cage-conformance-parties/1` file passed with `--parties`. The defaults pin the CAGE repository as the author of `trace-v1` and `stream-v1`. They leave the counterparty, the deploying operator, unpinned, because only the relying party knows who that is.
8. A principal outside the pins earns no verified posture while either role's principals are unpinned, because it might hold that role. `verify-report` then exits 2 and says which pins are missing. This refines the refusal rule agreed for this design. The refusal sits where the posture is derived, not at `attest`, so that a runner can attest a report before the relying party has supplied its pins.

---

## 4. Forensic Audit & Disposition of `feat/cage-conformance` (`6e46ca00`)

Branch `origin/feat/cage-conformance` (`6e46ca00`, authored `2026-10-25` on top of `1d5e4e10`, touching 63 files, `+5,259 / -91`) was inspected against `main` (`7577deda`).

### 4.1 Why `6e46ca00` Must Not Be Merged As-Is

Merging or cherry-picking `6e46ca00` directly onto `main` would introduce **four concrete regressions**:

1. **Forked Pre-Downscope 8-Tier `model.py` (`1,497` lines)**:
   - `6e46ca00` copies an older 8-tier version of `model.py` (`TIERS = ("ftra", "stpa", "opa", "confidence", "causal", "consensus", "cbf", "fiscal")`) into `packages/cage-conformance/` and does not match `main`'s 7-tier deterministic core in [`proof/model.py`](../../proof/model.py) (`34` gated states, `38` under `EU_ECB`, `17` ungated, `31` skipped-tier).
   - Merging it would either fail `check_conformance_sync.py` immediately or, if copied over [`proof/model.py`](../../proof/model.py), regress the formal proof and break [`tests/test_no_direct_bind_proof.py`](../../tests/test_no_direct_bind_proof.py).
2. **Omits [`proof/stream_invariants.py`](../../proof/stream_invariants.py) (`#579`)**:
   - `6e46ca00` predates [`proof/stream_invariants.py`](../../proof/stream_invariants.py) (`2026-10-29`, `#579`). Its `SYNC_PAIRS` in `check_conformance_sync.py` only syncs `model.py` and `trace_conformance.py`, and its CLI lacks `--stream` verification for `EvidenceStreamSink` (`I1`–`I5` + `jcs_bytes` + `thresholds_digest`).
3. **Regresses `GET /governance/policy-version` (`POAM-2026-151`, `#584`)**:
   - In [`src/gateway/server/governance_middleware.py`](../../src/gateway/server/governance_middleware.py), `6e46ca00` overwrites `get_policy_version_endpoint` to return only `{"policy_version_id": active_hash[:16], "active_region": registry.active_region, "active_hash": active_hash}`.
   - On `main`, `get_policy_version_endpoint` was updated in `#584` (`POAM-2026-151`) to return `thresholds_digest`, `thresholds_source`, and `thresholds` so callers and [`proof/stream_invariants.py`](../../proof/stream_invariants.py) can cross-check live runtime thresholds against `GOVERNANCE_THRESHOLDS_LOADED` and `GOVERNANCE_DECISION`. Merging `6e46ca00`'s hunk would break `POAM-2026-151` and [`tests/test_policy_pinning.py`](../../tests/test_policy_pinning.py).
4. **Reintroduces a Deleted Module Import via `POST /governance/ingest-policy`**:
   - `6e46ca00` adds `POST /governance/ingest-policy` to [`src/gateway/server/governance_middleware.py`](../../src/gateway/server/governance_middleware.py), importing `translate_policy` from `e5376b58^:src/gateway/governance/ingress/policy_translator.py` (which was deleted on `main`), and hardcodes `/governance/ingest-policy` into its `substrate_v1.json` endpoint vector.

### 4.2 Component-by-Component Disposition Table

Instead of merging `6e46ca00`, its four bundled workstreams are disposed of as follows:

| Component in `6e46ca00` | Files in `6e46ca00` | Disposition | Rationale & Action |
|---|---|---|---|
| **1. Standalone `packages/cage-conformance/` CLI & Provenance Model (`W4`)** | `packages/cage-conformance/**`, `check_conformance_sync.py`, `test_cage_conformance.py`, `.github/workflows/publish-client-sdk.yml` | **Salvage & Rebuild on `main`'s `proof/`** | Rebuilt on `main`'s [`proof/model.py`](../../proof/model.py) (7-tier), [`proof/trace_conformance.py`](../../proof/trace_conformance.py), and [`proof/stream_invariants.py`](../../proof/stream_invariants.py) (`SYNC_PAIRS` covering all 3 modules); `verify --trace`, `verify --stream` and `verify-report` are shipped (§2.3). `provenance.py` is not retained: its OIDC inspection never verified a signature (§3), so a report's own provenance in the rebuilt [`report.py`](../../packages/cage-conformance/src/cage_conformance/report.py) derives only unattested postures, and verified postures come only from `attest`, which checks the token's signature against the issuer's pinned JWKS (§3.1). The endpoint profiles (with `substrate_v1.json` asserting `main`'s `/governance/policy-version` `thresholds_digest` contract instead of `/governance/ingest-policy`) and the `publish-client-sdk.yml` release step remain planned. |
| **2. Partner Document Provenance Banners & CI Linter** | `check_partner_headers.py`, `docs/partners/**` (25 files) | **Salvage Separately (Optional Docs/CI PR)** | Salvaged apart from the code PRs. [`scripts/check_partner_headers.py`](../../scripts/check_partner_headers.py) keeps one banner directly under each partner document's title, stating only what holds for every one: third-party integration material, not a Google certification or endorsement of the partner, with a link to the Live Verification Status table, which must list every partner directory. Unlike `6e46ca00`'s, the banner claims no partner authorship, CLA coverage or `AUTHOR_SELF_TEST` posture, and no JSON record is edited; files pinned by a `MANIFEST.sha256` are exempt rather than given sibling header files. |
| **3. `importlib.metadata.entry_points` Partner SPI** | `PARTNER_SPI.md`, `contrib/example-normative-provider/**`, [`src/gateway/governance/normative_provider.py`](../../src/gateway/governance/normative_provider.py), [`src/gateway/governance/attestation_aggregator.py`](../../src/gateway/governance/attestation_aggregator.py), [`src/gateway/governance/execution_actuator.py`](../../src/gateway/governance/execution_actuator.py), [`src/gateway/governance/estate_provider.py`](../../src/gateway/governance/estate_provider.py), [`src/gateway/governance/seams/normative.py`](../../src/gateway/governance/seams/normative.py), [`src/gateway/governance/seams/estate.py`](../../src/gateway/governance/seams/estate.py) | **Defer** | In-tree Tier 1 adapters (`provider_01`–`provider_08`, `actuator_01`) already resolve cleanly via allowlisted lazy factories enforced by Gate G3 ([`scripts/check_import_boundaries.py`](../../scripts/check_import_boundaries.py)). Defer `entry_points` discovery until an external partner distributes an out-of-tree wheel. |
| **4. `POST /governance/ingest-policy` Endpoint & `SPACY_MODEL` Dockerfile Churn** | [`src/gateway/server/governance_middleware.py`](../../src/gateway/server/governance_middleware.py), [`tests/test_policy_pinning.py`](../../tests/test_policy_pinning.py), [`Dockerfile`](../../Dockerfile), [`src/gateway/Dockerfile`](../../src/gateway/Dockerfile) | **Drop (Reject)** | `POST /governance/ingest-policy` depends on deleted `e5376b58^:src/gateway/governance/ingress/policy_translator.py` and overwrites `POAM-2026-151`'s `/governance/policy-version` payload. CAGE compiles STPA and OPA artifacts offline and verifies them in CI (`stpa-freshness-check`), never via unauthenticated runtime HTTP ingestion. |

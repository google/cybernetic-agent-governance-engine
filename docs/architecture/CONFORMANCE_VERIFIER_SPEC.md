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
2. **Byte-for-Byte Sync Gate (`SYNC_PAIRS`)**: The CI sync check (`check_conformance_sync.py`) must verify SHA-256 byte equality across **all three** modules:
   - [`proof/model.py`](../../proof/model.py)
   - [`proof/trace_conformance.py`](../../proof/trace_conformance.py)
   - [`proof/stream_invariants.py`](../../proof/stream_invariants.py)
3. **AST Isolation Gate**: No module under `packages/cage-conformance/` may import `src` or `src.*`.

### 2.3 CLI Surface (`cage-conformance`)

The standalone CLI exposes four subcommands backed by [`proof/`](../../proof/) and `provenance.py`:

1. `cage-conformance verify --trace <events.jsonl>`: Runs `check_trace_stream()` from [`proof/trace_conformance.py`](../../proof/trace_conformance.py) and emits a provenance-stamped report.
2. `cage-conformance verify --stream <evidence_stream.jsonl>`: Runs `check_stream()` from [`proof/stream_invariants.py`](../../proof/stream_invariants.py) (matching [`scripts/check_trace_conformance.py`](../../scripts/check_trace_conformance.py) `--stream`) and emits a provenance-stamped report.
3. `cage-conformance verify --endpoint <url> --profile <profile>`: Executes black-box HTTP conformance vectors against a live partner adapter or CAGE gateway endpoint.
4. `cage-conformance verify-report <report.json>`: Re-computes and validates the report's `provenance` posture and digest integrity.

---

## 3. Attributable Provenance & Verification Posture Schema

Every report emitted by `cage-conformance` embeds a mandatory `provenance` block. Verification posture is derived deterministically from four inputs — `adapter_author_org`, `counterparty_org`, `runner_org`, and `identity_proof` (`OIDC` vs. `NONE`):

| Posture | Condition | Evidentiary Meaning |
|---|---|---|
| `AUTHOR_SELF_TEST` | `runner_org == adapter_author_org` | Run by the organization that authored the adapter; proves author-side wire execution, not counterparty sign-off |
| `COUNTERPARTY_VERIFIED` | `runner_org == counterparty_org` and `identity_proof != "NONE"` | Run by the counterparty organization on the other side of the seam with verified OIDC identity |
| `INDEPENDENT_PARTY_VERIFIED` | `runner_org not in {adapter_author_org, counterparty_org}` and `identity_proof != "NONE"` | Run by an independent third party (auditor, evaluator, or regulatory sandbox) with verified OIDC identity |
| `UNVERIFIED_LOCAL` | `identity_proof == "NONE"` and `runner_org != adapter_author_org` | Local or unauthenticated run without cryptographic/OIDC runner identity proof; cannot claim counterparty or independent verification |

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
| **1. Standalone `packages/cage-conformance/` CLI & Provenance Model (`W4`)** | `packages/cage-conformance/**`, `check_conformance_sync.py`, `test_cage_conformance.py`, `.github/workflows/publish-client-sdk.yml` | **Salvage & Rebuild on `main`'s `proof/`** | Build `packages/cage-conformance/` directly from `main`'s [`proof/model.py`](../../proof/model.py) (7-tier), [`proof/trace_conformance.py`](../../proof/trace_conformance.py), and [`proof/stream_invariants.py`](../../proof/stream_invariants.py) (`SYNC_PAIRS` covering all 3 modules), retain `provenance.py` and `cli.py` (adding `--stream`), and update `substrate_v1.json` to assert `main`'s `/governance/policy-version` (`thresholds_digest`) contract instead of `/governance/ingest-policy`. |
| **2. Partner Document Provenance Banners & CI Linter** | `check_partner_headers.py`, `docs/partners/**` (25 files) | **Salvage Separately (Optional Docs/CI PR)** | Self-contained documentation hygiene (adds explicit status headers to partner design docs in `docs/partners/`). Has zero coupling to `src/` or `packages/cage-conformance/` and must not be bundled with code changes. |
| **3. `importlib.metadata.entry_points` Partner SPI** | `PARTNER_SPI.md`, `contrib/example-normative-provider/**`, [`src/gateway/governance/normative_provider.py`](../../src/gateway/governance/normative_provider.py), [`src/gateway/governance/attestation_aggregator.py`](../../src/gateway/governance/attestation_aggregator.py), [`src/gateway/governance/execution_actuator.py`](../../src/gateway/governance/execution_actuator.py), [`src/gateway/governance/estate_provider.py`](../../src/gateway/governance/estate_provider.py), [`src/gateway/governance/seams/normative.py`](../../src/gateway/governance/seams/normative.py), [`src/gateway/governance/seams/estate.py`](../../src/gateway/governance/seams/estate.py) | **Defer** | In-tree Tier 1 adapters (`provider_01`–`provider_08`, `actuator_01`) already resolve cleanly via allowlisted lazy factories enforced by Gate G3 ([`scripts/check_import_boundaries.py`](../../scripts/check_import_boundaries.py)). Defer `entry_points` discovery until an external partner distributes an out-of-tree wheel. |
| **4. `POST /governance/ingest-policy` Endpoint & `SPACY_MODEL` Dockerfile Churn** | [`src/gateway/server/governance_middleware.py`](../../src/gateway/server/governance_middleware.py), [`tests/test_policy_pinning.py`](../../tests/test_policy_pinning.py), [`Dockerfile`](../../Dockerfile), [`src/gateway/Dockerfile`](../../src/gateway/Dockerfile) | **Drop (Reject)** | `POST /governance/ingest-policy` depends on deleted `e5376b58^:src/gateway/governance/ingress/policy_translator.py` and overwrites `POAM-2026-151`'s `/governance/policy-version` payload. CAGE compiles STPA and OPA artifacts offline and verifies them in CI (`stpa-freshness-check`), never via unauthenticated runtime HTTP ingestion. |

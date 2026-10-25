# CAGE Partner Integration SPI (Service Provider Interface)

**Version:** 1.0  
**Scope:** External compliance, attestation, execution-actuation, and estate-context integrations (Layer 3)

---

## 1. Architectural Principle

External partners integrate with CAGE by implementing one of four typed protocol seams in [`src/gateway/governance/seams/`](../src/gateway/governance/seams/) and registering their package via standard Python `importlib.metadata.entry_points`.

Partner packages:
- **Never** modify Layer 1 kernel files (`src/gateway/`).
- **Never** require adding vendor-specific imports to [`scripts/check_import_boundaries.py`](../scripts/check_import_boundaries.py).
- Can be developed, versioned, and certified in the partner's own repository using the standalone [`packages/cage-conformance/`](../packages/cage-conformance/) CLI.

---

## 2. The Four Seam Protocols

| Seam Protocol | Canonical Definition | Entry-Point Group | Environment Selector |
|---|---|---|---|
| `NormativeProvider` | [`src/gateway/governance/seams/normative.py`](../src/gateway/governance/seams/normative.py) | `cage.normative_providers` | `CAGE_NORMATIVE_PROVIDER` |
| `AttestationProvider` | [`src/gateway/governance/attestation_provider.py`](../src/gateway/governance/attestation_provider.py) | `cage.attestation_providers` | `CAGE_ATTESTATION_PROVIDERS` |
| `ExecutionActuator` | [`src/gateway/governance/seams/execution.py`](../src/gateway/governance/seams/execution.py) | `cage.execution_actuators` | `CAGE_ACTIVE_ACTUATORS` |
| `EstateProvider` | [`src/gateway/governance/seams/estate.py`](../src/gateway/governance/seams/estate.py) | `cage.estate_providers` | `CAGE_ESTATE_PROVIDER` |

### 2.1 `NormativeProvider` (`cage.normative_providers`)
Resolved by `get_normative_provider()` in [`src/gateway/governance/normative_provider.py`](../src/gateway/governance/normative_provider.py). Implements three async methods:
- `fetch_baseline(region: str) -> NormativeBaseline`
- `validate_fria(payload: dict[str, Any]) -> ValidationResult`
- `submit_evidence(thread_id: str, evidence_hash: str) -> EvidenceSeal`

### 2.2 `AttestationProvider` (`cage.attestation_providers`)
Resolved by `_load_attestation_provider()` in [`src/gateway/governance/attestation_aggregator.py`](../src/gateway/governance/attestation_aggregator.py). Supplies boot-fetched and periodically polled `ExternalAttestation` records into `GovernanceEnvelopeBuilder`.

### 2.3 `ExecutionActuator` (`cage.execution_actuators`)
Resolved by `_load_actuator()` in [`src/gateway/governance/execution_actuator.py`](../src/gateway/governance/execution_actuator.py). Consumes single-use `ExecutionClearance` envelopes and returns `ActuatorReceipt` records with `VerificationStatus`.

### 2.4 `EstateProvider` (`cage.estate_providers`)
Resolved by `get_estate_provider()` in [`src/gateway/governance/estate_provider.py`](../src/gateway/governance/estate_provider.py). Supplies `CloudOpsResourcePredicate`, `BlastRadiusEstimate`, and `TopologySnapshot` records for FTRA reachability analysis.

---

## 3. Registering an External Adapter via `entry_points`

An external partner package registers its adapter in `pyproject.toml`:

```toml
[project.entry-points."cage.normative_providers"]
example_partner = "example_normative_provider:ExampleNormativeProvider"
```

When `CAGE_NORMATIVE_PROVIDER=example_partner` is set:
1. `get_normative_provider()` checks built-in providers first, then queries `importlib.metadata.entry_points(group="cage.normative_providers")`.
2. If the entry point target defines a `.from_env()` classmethod, CAGE invokes `target.from_env()`; otherwise it invokes `target()`.
3. CAGE validates that the returned object satisfies the `@runtime_checkable` seam protocol (`isinstance(instance, NormativeProvider)`) and fails closed with `TypeError` if any method is missing.

See [`contrib/example-normative-provider/`](../contrib/example-normative-provider/) for a complete minimal reference package.

---

## 4. Mandatory Security Invariants for Partner Adapters

1. **Out-of-Band Trust Anchors (`kid` Resolution):** Never verify a cryptographic signature against a public key embedded inside the signed payload. Resolve keys by `kid` against an out-of-band key manifest and fail closed on unknown `kid`.
2. **Resolution Status != Verification Status:** A successful HTTP `200 OK` response proves only that a receipt was fetched (`UNVERIFIED`), not that its signature is valid (`VERIFIED`).
3. **Refusals Are Primary Evidence:** `DENY` and `DEFER` outcomes must be recorded in the tamper-evident evidence chain with the same completeness as `ALLOW` outcomes.
4. **URL Scheme Validation:** All outbound HTTP requests must validate `http://` or `https://` schemes before opening connections.

---

## 5. Self-Certification & Provenance Posture (`cage-conformance`)

Partners certify their own adapters using [`packages/cage-conformance/`](../packages/cage-conformance/):

```bash
pip install cage-conformance

# Verify governance trace invariants:
cage-conformance verify --trace trace.jsonl \
  --adapter-id partner-adapter-v1 \
  --adapter-author-org github:partner-org \
  --counterparty-org github:google \
  --runner-org github:partner-org \
  --output conformance_report.json

# Verify live wire endpoint conformance:
cage-conformance verify --endpoint https://sandbox.partner.example \
  --profile flowsignal-v0.2 \
  --adapter-id partner-adapter-v1 \
  --adapter-author-org github:partner-org \
  --counterparty-org github:google \
  --runner-org github:partner-org \
  --output wire_report.json

# Validate report integrity and provenance posture:
cage-conformance verify-report wire_report.json
```

The `provenance.verification_posture` field is derived deterministically from `(adapter_author_org, counterparty_org, runner_org, identity_proof)` and cannot be overridden via CLI flags.

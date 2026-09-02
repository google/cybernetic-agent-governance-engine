# FTRA Terminal Registry Signature Verification — Compensating Controls

> **Reference architecture note:** This document describes the signature verification
> control implemented for the FTRA terminal registry (`config/ftra/terminal_registry.json`).
> The posture gate and serial-durability limitations documented below are illustrative
> patterns for adopters to consider when adapting this control to their own environments.

## Overview

The FTRA Terminal Registry Signature Verification control (closes **VEC-005** registry
re-declaration bypass and **VEC-008** signed-registry rollback) verifies cryptographic
signatures and enforces monotonic serial numbers on the terminal registry file.

**Implementation:**
- [`src/gateway/governance/ftra/registry_verifier.py`](../../src/gateway/governance/ftra/registry_verifier.py) — signature and serial verification
- [`src/gateway/governance/ftra/classifier.py`](../../src/gateway/governance/ftra/classifier.py) — load-path integration with fail-closed enforcement

**Closed vulnerabilities:**
- **VEC-005:** Registry re-declaration bypass (attacker writes tampered registry → irreversible actions misclassified as reversible)
- **VEC-008:** Signed-registry rollback (attacker replaces current registry with older but validly signed version)

---

## Control Objectives

1. **Integrity binding:** Any tampering with the terminal registry (changing action classifications) must cause signature verification failure and fail-closed behavior (all actions classified as `IRREVERSIBLE_TERMINAL`).

2. **Rollback prevention:** An attacker who replaces a current registry with an older but validly signed version must be detected via monotonic serial enforcement.

3. **Fail-closed contract:** Verification failure with enforcement ON must never yield an empty registry, partial load, or uncaught exception — it must result in every action being classified as `IRREVERSIBLE_TERMINAL`.

---

## Enforcement Posture

Signature enforcement is controlled by the `FTRA_REGISTRY_REQUIRE_SIGNATURE` environment variable:

| Environment Variable | Behavior |
|---|---|
| `FTRA_REGISTRY_REQUIRE_SIGNATURE=true` | **Enforcement ON** — signature and serial verification required; failures block registry load |
| `FTRA_REGISTRY_REQUIRE_SIGNATURE=false` | **Enforcement OFF** — verification skipped; v1.0 unsigned registries allowed (dev/test/ci) |
| *(unset)* | Derived from `CAGE_ENV`: ON in production, OFF in dev/test/ci |

**Precedent:** Mirrors the `CAGE_ENV`-derived enforcement pattern in [`cbf_engine.py:426`](../../src/gateway/governance/cbf.py:426) for Redis epoch fail-closed behavior.

---

## Known Limitations

### 1. Posture gate is not a defense against environment control

**The limitation, stated plainly:**

A posture gate controlled by an environment variable is **not** a defense against an attacker who controls the pod's environment.

Anyone who can set `FTRA_REGISTRY_REQUIRE_SIGNATURE=false` or `CAGE_ENV=dev` on the gateway pod has already defeated the control. The attacker can then load an unsigned, tampered v1.0 registry with no verification.

**What this control does defend against:**

An attacker who can write the registry file (`config/ftra/terminal_registry.json`) — via tampered ConfigMap, compromised artifact in the image build, or malicious PR to a downstream fork — but **cannot** alter the pod's environment variables.

**Mitigations:**

- **Kubernetes RBAC:** Restrict `ConfigMap` write access to the `governance-stack` namespace. The ConfigMap containing the registry should be immutable or tightly controlled via GitOps (e.g., ArgoCD with signed commits).
- **Immutable container images:** Sign and verify container images with Binary Authorization. A compromised build that embeds a tampered registry can be detected at deploy time.
- **Pod Security Standards:** The gateway Deployment should specify `securityContext` settings that prevent environment variable injection by untrusted workloads.
- **Runtime attestation:** The compliance bridge can verify the `FTRA_REGISTRY_REQUIRE_SIGNATURE` value at startup and log/alert if enforcement is unexpectedly disabled in production.

**Why this trade-off exists:**

An unconditional enforcement model would require every dev and CI environment to hold KMS signing credentials, breaking the `stpa_compiler` workflow and PR #1's `tmp_path` test fixtures. A dedicated signing keypair for dev (materialized in the codebase) would eliminate the posture gate but require key rotation and a larger architectural change (see Alternatives Considered in [`plans/issue_107_pr2_registry_signing_plan.md §2`](../../plans/issue_107_pr2_registry_signing_plan.md)).

---

### 2. In-memory serial high-water mark defeated by rollback + pod restart

**The limitation, stated plainly:**

The monotonic serial check uses two defenses:

1. **`FTRA_REGISTRY_MIN_SERIAL`** — deployment-pinned floor, survives pod restart (set in Deployment manifest)
2. **In-process high-water mark** — `_seen_serial_high_water` module-level variable, tracks the highest serial seen during the pod's lifetime

An attacker who rolls back the registry **and** restarts the gateway pod defeats the in-memory high-water mark, leaving only the deployment-pinned floor. If `FTRA_REGISTRY_MIN_SERIAL` is unset or stale, the rollback succeeds.

**Example attack scenario:**

- Legitimate registry at serial `142` is loaded at pod startup.
- Attacker replaces the registry with a validly signed version at serial `100` (rollback).
- Attacker triggers a pod restart (e.g., via resource exhaustion, ConfigMap update forcing a rollout, or exploiting a separate vulnerability).
- New pod starts with in-memory high-water = `0`. If `FTRA_REGISTRY_MIN_SERIAL` is unset, serial `100` is accepted.

**Mitigations:**

1. **Deployment-pinned serial floor:** Set `FTRA_REGISTRY_MIN_SERIAL` in the gateway Deployment manifest to the serial of the most recently deployed registry. Update this value with every registry rotation.

   ```yaml
   # deployment/k8s/gateway-deployment.yaml
   env:
     - name: FTRA_REGISTRY_MIN_SERIAL
       value: "142"  # Update with each registry rotation
   ```

2. **Redis-backed durable serial:** The in-memory high-water mark could be replaced with a Redis-backed counter (similar to the CBF reconciliation epoch). This would survive pod restarts and provide cluster-wide rollback prevention. **Trade-off:** puts Redis on the FTRA load path (latency impact). Deferred as future work (see [`plans/issue_107_pr2_registry_signing_plan.md §5`](../../plans/issue_107_pr2_registry_signing_plan.md)).

3. **Immutable ConfigMaps:** Use Kubernetes immutable ConfigMaps for the registry. Any registry update requires creating a new ConfigMap with a new name, and the Deployment must reference the new name. This prevents in-place rollback attacks without detection.

4. **Audit logging and alerting:** The compliance bridge should log every registry load with `serial`, `enforcement`, `verified`, and `failure_reason`. A sudden serial regression (even if it passes the floor check) is a detection signal for investigation.

**Why this trade-off exists:**

Making serial enforcement fully durable requires external state (Redis or equivalent). This introduces a new dependency on the FTRA hot path and increases latency. The deployment-pinned floor is a simpler mitigation that covers most rollback scenarios, reserving the Redis-backed solution for environments with higher rollback threat models.

---

## Verification and Observability

### Telemetry (OpenTelemetry span attributes)

Every FTRA analysis span (`cage.ftra_analysis`) includes registry verification attributes (added in [`node_factory.py`](../../src/gateway/governance/ftra/node_factory.py)):

| Attribute | Meaning |
|---|---|
| `cage.ftra.registry.verified` | `true` if signature check passed, `false` otherwise |
| `cage.ftra.registry.enforcement` | `"enforced"` / `"advisory"` / `"none"` (v1.0 registries) |
| `cage.ftra.registry.serial` | Registry serial number (present for v2.0 registries) |
| `cage.ftra.registry.failure_reason` | Failure code if verification failed (e.g., `SIG_INVALID`, `EXPIRED`, `SERIAL_REGRESSED`) |

### Logging

- **Successful verification:** `INFO` log with serial, enforcement posture, and action count.
- **Verification failure (enforcement ON):** `ERROR` log with failure reason; registry load raises `RuntimeError`.
- **Verification failure (enforcement OFF):** `WARNING` log; registry loads unverified.
- **Version downgrade blocked (D1 fix):** `ERROR` log if enforcement ON and `version != "2.0"`.

### Failure Codes

Distinct failure codes (surfaced as `cage.ftra.registry.failure_reason`) enable precise diagnostics:

| Code | Trigger |
|---|---|
| `SIG_MISSING` | `.sig` file absent |
| `SIG_MALFORMED` | `.sig` unparseable or missing required keys |
| `SIG_INVALID` | Signature verification returned `false` |
| `EXPIRED` | `expires_at` in the past |
| `EXPIRY_MISSING` | `expires_at` field absent |
| `EXPIRY_NAIVE` | `expires_at` lacks timezone (never coerced to UTC) |
| `EXPIRY_MALFORMED` | `expires_at` not a valid ISO 8601 timestamp |
| `SERIAL_REGRESSED` | `serial` below high-water mark or `FTRA_REGISTRY_MIN_SERIAL` floor |
| `SERIAL_MISSING` | `serial` absent or not an integer |
| `ENVELOPE_INVALID` | Shape check failed (version, terminals dict, `signed_at` trap) |
| `PUBKEY_UNAVAILABLE` | No public key loaded and enforcement is ON |

---

## References

- **Remediation plan:** [`plans/issue_107_pr2_registry_signing_plan.md`](../../plans/issue_107_pr2_registry_signing_plan.md)
- **Defect fixes (D1–D4):** Plan section 12
- **NIST SP 800-53 controls:** SI-7 (Software, Firmware, and Information Integrity), AU-10 (Non-repudiation)
- **OSCAL component:** Pending update (within 2 business days of merge per [`AGENTS.md`](../../AGENTS.md))

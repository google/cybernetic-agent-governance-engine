# 07 — Security Infrastructure

| Field              | Value                                           |
| ------------------ | ----------------------------------------------- |
| **Version**        | 3.0                                             |
| **Date**           | 2026-08-22                                      |
| **Classification** | INTERNAL                                        |
| **Document**       | CAGE Technical Report — Security Infrastructure |

---

## 1. Security Architecture Overview

CAGE implements a defense-in-depth security model across seven distinct layers. The architecture assumes zero inherent trust between components and enforces explicit allow decisions at every boundary.

| Layer                   | Mechanism                            | Implementation                               |
| ----------------------- | ------------------------------------ | -------------------------------------------- |
| Cryptographic Integrity   | Cloud KMS HSM (primary) + HMAC-SHA256 (fallback) | KMS RSA-4096 governance signing + HMAC routing seal |
| Policy Authorization      | OPA Rego RBAC                        | `trade.governance` package, fail-closed      |
| Network Isolation         | Kubernetes NetworkPolicy             | 9 objects, default-deny ingress/egress       |
| External Normative Gate   | Adaptive FRIA enforcement (v2.1.0)   | `normative_provider.py`: confidence-mapped sync/async external validation (SA-9) |
| PII Protection            | NeMo Guardrails + Microsoft Presidio | Input/output scanning + anonymization        |
| Audit Logging             | OpenTelemetry + Langfuse             | 7-year retention, ISO 42001 control stamping; direct OTLP ingestion (OTel Collector deprecated 2026-05-31) |
| Continuous Monitoring     | AgentSight eBPF DaemonSet            | Kernel-level process audit trail             |

> ⚠️ **Current Security Posture: HIGH Overall Risk — ATO Not Recommended**
>
> One **critical** open finding remains unresolved: unsigned FIPS 199 categorization (FIND-007). Two critical findings have been resolved: HMAC bypass vulnerability FIND-010 / POAM-012 is **CLOSED**, and intra-cluster mTLS FIND-011 / POAM-007 is **CLOSED** (Linkerd mTLS + Cilium L7 egress lockdown deployed).
>
> ✅ **v2.0.0-rc.2 Security Hardening Sprint (2026-06-03):** All four No-Direct-Bind architectural gaps have been closed. The `NoDirectBind` safety invariant is now machine-verified over the entire reachable state space. See §3a below and [Document 10 — Formal Verification](./10-FORMAL-VERIFICATION.md) §Step 7 for full details.
>
> ✅ **commit e959cc3 — Production Environment Hardening (2026-06-15):** Three additional fail-closed hardening measures have been applied: `CAGE_ENV` standardization across all production guards, fail-closed telemetry enforcement in the causal gatekeeper, and `StubNormativeProvider` production guard. See §3b, §3c, and §3d below.

---

## 2. Authorization Boundary

**Kubernetes Namespace**: `governance-stack` on Google Kubernetes Engine (GKE)

Source: [`compliance/boundary/AUTHORIZATION_BOUNDARY.md`](../../compliance/boundary/AUTHORIZATION_BOUNDARY.md)

### Network Policy Objects (9 Total)

All network policy manifests are defined in:

- [`deployment/k8s/network-policy.yaml`](../../deployment/k8s/network-policy.yaml) — baseline default-deny rules
- [`deployment/k8s/network-policy-hardening.yaml`](../../deployment/k8s/network-policy-hardening.yaml) — hardened explicit allow rules
- [`deployment/k8s/pod-security-admission.yaml`](../../deployment/k8s/pod-security-admission.yaml) — restricted pod security profile
- [`deployment/k8s/security-context-patch.yaml`](../../deployment/k8s/security-context-patch.yaml) — runtime security context

Explicit allow rules cover: agent server → gateway, gateway → OPA, gateway → Redis, gateway → vLLM, and compliance bridge → Langfuse.

### External Interconnections

| External System     | Purpose                           | ISA Status                             |
| ------------------- | --------------------------------- | -------------------------------------- |
| GCS Artifact Bucket | OSCAL results; model artifacts    | GCP ToS                                |
| MinIO               | Model weight storage              | Internal cluster service               |
| Langfuse SaaS       | Observability; compliance metrics | ISA — DPA risk (Langfuse DPA required) |
| yfinance            | Market data                       | **Yes** — read-only API; ISA required for data correlation risk |

> **ADR**: GCP Secret Manager was removed as an external interconnection.
> Secrets are now provided exclusively via Kubernetes `Secret` objects mounted
> as environment variables. No runtime dependency on `google-cloud-secret-manager`.

> ⚠️ **Langfuse DPA Risk**: Langfuse SaaS processes compliance metrics and agent traces. A Data Processing Agreement (DPA) is required before production use. This represents a residual ISA risk until the DPA is executed.

---

## 3a. Remediation Update — Closure of Ungated Variant Vulnerabilities (v2.0.0-rc.2)

> **Classification:** Security Hardening — Pre-ATO Package Update
> **Date:** 2026-06-03
> **Sprint:** No-Direct-Bind Formal Verification Lock

The v2.0.0-rc.2 security hardening sprint closed four architectural gaps identified during formal analysis of the `NoDirectBind` safety invariant. The invariant is defined as:

$$\text{NoDirectBind} \equiv (\text{phase} = \texttt{EXECUTED}) \Rightarrow (\text{resolvedAllow} = \texttt{TRUE})$$

All four gaps have been remediated and machine-verified. The system is now hard-gated against fail-open configurations in production environments.

### Gap 2 — Cryptographic Attestation Enforced on All Execution Paths

**Finding:** The `SymbolicGovernor.govern()` method ran the full 8-tier governance pipeline (FTRA + 7 in-pipeline tiers) but returned `None` on approval, providing no cryptographic attestation that authority had been resolved. A caller that caught `GovernanceError` on denial could proceed to execution without a routing seal — a direct-bind shortcut identical to the ungated counterexample in the formal proof.

**Remediation:**

[`symbolic_governor.govern()`](../../src/gateway/governance/symbolic_governor.py) now issues an HMAC-SHA256 routing seal on approval and returns it as a non-empty string. The seal is generated via [`routing_seal.generate_seal()`](../../src/gateway/governance/routing_seal.py) inside a dedicated `cage.routing_seal` OTel span, after all 7 governance tiers have passed. [`governance_middleware.enforce_governance()`](../../src/gateway/server/governance_middleware.py) propagates the seal to callers. [`mcp_tool_server.execute_trade_action()`](../../src/gateway/server/mcp_tool_server.py) calls `verify_seal()` before executing the trade; a missing or invalid seal produces an immediate `BLOCKED` response.

Both `govern()` and `validate_action()` now satisfy the `NoDirectBind` invariant. There is no longer any code path from `CHECKING` to `EXECUTED` that bypasses `SEAL_ISSUED`.

**Verification:** The formal proof in `proof/model.py` confirms that the pre-fix `govern()` path (no seal) produces a direct-bind violation (`EXECUTED` with `resolvedAllow = False`), and that the fixed path does not.

### Gap 3 — `CBF_FAIL_OPEN` Hard-Gated in Production

**Finding:** Setting `CBF_FAIL_OPEN=true` silently removed the Control Barrier Function (Tier 2) from the governance gate. The condition was logged at `CRITICAL` level but did not prevent the service from starting or processing requests. This constituted a documented, operator-accessible direct-bind shortcut that degraded the 8-tier gate to a 7-tier gate without any deployment-time enforcement.

**Remediation:**

A module-level startup assertion in [`symbolic_governor.py`](../../src/gateway/governance/symbolic_governor.py) now raises a `RuntimeError` at import time if `CBF_FAIL_OPEN=true` is detected in any non-development environment (`CAGE_ENV` not in `{development, test, dev, ci}`):

```
CAGE STARTUP FAILURE (No-Direct-Bind Gap 3): CBF_FAIL_OPEN=true is set in a
production environment. This removes the Control Barrier Function tier from the
governance gate, creating a direct-bind shortcut to EXECUTED without resolved
cash-barrier authority.
```

The pod will crash at startup rather than serve requests with a degraded gate. This is consistent with the existing `CAGE_ROUTING_SEAL_SECRET` and `CAGE_ENV` startup validation pattern.

**Operational impact:** `CBF_FAIL_OPEN=true` remains available in `development` and `test` environments for local development without a Redis instance. It is permanently blocked in production.

### Gap 4 — DoWhy Causal Gatekeeper Mandatory in Production

**Finding:** If the `dowhy` Python package was not installed, the causal gatekeeper (Tier 6) was silently skipped via `except ImportError: logger.debug(...)`. This removed a mandatory governance tier without any startup-time signal, allowing the service to start and process requests with a 6-tier gate while appearing to operate normally.

Additionally, runtime exceptions during DoWhy refutation (e.g., numerical instability, telemetry parse errors) were previously swallowed via `except Exception: logger.warning(...)`, causing the tier to silently pass rather than fail closed.

**Remediation:**

1. **Import assertion:** A module-level startup assertion in [`symbolic_governor.py`](../../src/gateway/governance/symbolic_governor.py) attempts `import dowhy` in production environments and raises `RuntimeError` if the import fails:

   ```
   CAGE STARTUP FAILURE (No-Direct-Bind Gap 4): 'dowhy' is not installed.
   The DoWhy causal gatekeeper (Tier 6) is a mandatory component of the
   No-Direct-Bind governance gate in production.
   ```

2. **Fail-closed runtime errors:** Unexpected exceptions during DoWhy refutation are now appended to the `violations` list, causing the governance pipeline to return `DENIED` rather than proceeding as if the tier had passed. The `except ImportError` branch inside `_run_checks()` remains for dev/test environments (where the startup assertion does not fire) and logs at `DEBUG` level with an explicit note that production startup will fail if `dowhy` is absent.

**Verification:** The formal proof confirms that the DoWhy-absent configuration preserves the structural `NoDirectBind` invariant (the seal path is intact), but the production startup assertion prevents this configuration from being reachable in production at all.

> **Jurisdiction note:** The causal gatekeeper's Phase 1 statistical kernel (CTRL_MRM_004) is tagged with SR 26-2 MRM back-testing requirements `[US_FED only]`. Phase 2 placebo refutation (CTRL_TEL_003) is tagged with **ISO/IEC 42001:2023 §A.9.4** (universal). Regional profiles (`EU_ECB_BASELINE.json`, `APAC_MAS_BASELINE.json`) encode jurisdiction-correct citations via the `legacy_citation` / `primary_framework` fields; the `_NO_LEGAL_FORCE_MARKER` sentinel suppresses US-only citations in EU and APAC spans automatically.

### Remediation Status Summary

| Gap | Description | Status | Enforcement Point |
| --- | ----------- | ------ | ----------------- |
| Gap 1 | No exhaustive state-space proof | ✅ **CLOSED** | `proof/model.py` — BFS over 57 reachable states (66 concurrent) |

> **Scope limitation:** The current BFS proof covers the governance state machine (57-state tuple). It does not model the full implementation including the LangGraph harness, Redis state, and the FTRA boundary. A TLA+/Alloy extension to the full implementation is tracked as future work.
| Gap 2 | `govern()` path issued no seal & actuator verification | ✅ **CLOSED** | [`symbolic_governor.govern()`](../../src/gateway/governance/symbolic_governor.py) + [`mcp_tool_server.execute_trade_action()`](../../src/gateway/server/mcp_tool_server.py) |
| Gap 3 | `CBF_FAIL_OPEN=true` silently degraded gate | ✅ **CLOSED** | Module-level `RuntimeError` in [`symbolic_governor.py`](../../src/gateway/governance/symbolic_governor.py) |
| Gap 4 | DoWhy absence silently removed Tier 6 | ✅ **CLOSED** | Module-level `RuntimeError` + fail-closed runtime handler in [`symbolic_governor.py`](../../src/gateway/governance/symbolic_governor.py) |

---

## 3b. Production Environment Hardening — `CAGE_ENV` Standardization (commit e959cc3)

> **Classification:** Security Hardening — Pre-ATO Package Update
> **Date:** 2026-06-15
> **Commit:** `e959cc3`

### Background

Prior to this hardening, production detection logic was inconsistent across the gateway codebase. Some guards consulted `CAGE_ENV`, others fell back to a separate `ENVIRONMENT` variable, and some used neither. This created a **split-brain risk**: a pod could have `CAGE_ENV=production` set while `ENVIRONMENT` was absent or set to a non-production value, causing production guards (KMS activation, salt validation, seal enforcement, stub ledger prohibition) to be silently skipped.

### Standardized Production Detection

All production guards in [`src/gateway/server/hybrid_server.py`](../../src/gateway/server/hybrid_server.py) now use a single, consistent detection expression:

```python
cage_env = os.getenv("CAGE_ENV", "production").lower()
_is_production = cage_env not in ("development", "test", "dev", "ci")
```

**Valid `CAGE_ENV` values and their effect:**

| `CAGE_ENV` value | Treated as | Production guards active? |
| ---------------- | ---------- | ------------------------- |
| *(unset)*        | `production` (default) | ✅ Yes |
| `production`     | Production | ✅ Yes |
| `development`    | Non-production | ❌ No |
| `dev`            | Non-production | ❌ No |
| `test`           | Non-production | ❌ No |
| `ci`             | Non-production | ❌ No |

Any value not in the non-production set is treated as production. This is a **fail-safe default**: an unrecognized or missing value activates all production guards rather than silently disabling them.

### Guards Unified Under `CAGE_ENV`

The following startup guards in [`_gateway_lifespan()`](../../src/gateway/server/hybrid_server.py) now all derive `_is_production` from `CAGE_ENV` exclusively — the `ENVIRONMENT` variable is no longer consulted for any of these checks:

| Guard | Failure Mode | Finding Addressed |
| ----- | ------------ | ----------------- |
| KMS signer activation (`assert_kms_active_in_production`) | `RuntimeError` at startup — pod crashes | H-05 |
| Custom governance salt (`assert_custom_salt_in_production`) | `RuntimeError` at startup — pod crashes | C-04 |
| `CAGE_SEAL_ENFORCEMENT=log` prohibition | `RuntimeError` at startup — pod crashes | BLOCKER-03 |
| Stub ledger provider prohibition (`RECONCILIATION_PROVIDER=stub`) | `RuntimeError` at startup — pod crashes | BLOCKER-06 |

The `/debug/*` endpoint guard in [`_DebugEndpointGuard`](../../src/gateway/server/hybrid_server.py) uses the same `CAGE_ENV` variable (allowing `dev`, `test`, `local`) to gate internal governance state exposure.

### Security Significance

This change eliminates the split-brain attack surface where an operator could set `ENVIRONMENT=development` (or leave it unset) while `CAGE_ENV=production` was active, bypassing all startup guards. The `ENVIRONMENT` variable is now **deprecated** for production detection purposes throughout the gateway. All new guards must use `CAGE_ENV`.

---

## 3c. Fail-Closed Telemetry Enforcement in Causal Gatekeeper (commit e959cc3)

> **Classification:** Security Hardening — Governance Tier Integrity
> **Date:** 2026-06-15
> **Commit:** `e959cc3`
> **Affected Component:** [`src/gateway/governance/causal_gatekeeper.py`](../../src/gateway/governance/causal_gatekeeper.py) — Tier 6 (DoWhy Causal Gate)

### Background

The causal gatekeeper (Tier 6 of the 8-tier governance pipeline) validates that the system's world-model is trustworthy before permitting high-stakes trade execution. It requires live telemetry — sourced from Langfuse governance spans — to run its DoWhy placebo refutation.

Prior to this hardening, if `causal_safety_check()` was called with `current_telemetry=None` (i.e., no live telemetry was provided), the function silently fell back to **synthetic mock data** generated with a fixed `np.random.seed(42)`. This fallback had two critical security properties:

1. **Predictable outputs**: The fixed seed produces identical telemetry on every call. An adversary who knew the seed could craft trade parameters that always pass the causal check against the synthetic data, regardless of actual market conditions.
2. **Silent degradation**: The governance pipeline appeared to run Tier 6 normally while actually evaluating against fabricated data — providing false assurance of causal safety.

### Remediation

[`causal_safety_check()`](../../src/gateway/governance/causal_gatekeeper.py) now applies environment-aware fail-closed logic when `current_telemetry` is `None`:

```python
if current_telemetry is None:
    _cage_env = os.getenv("CAGE_ENV", "production").lower()
    if _cage_env not in ("development", "test", "dev", "ci"):
        logger.error(
            "causal_safety_check: no live telemetry provided in production "
            "(CAGE_ENV=%s) — failing closed. Ensure LangfuseTelemetryProvider "
            "is configured and returning data before calling this function.",
            _cage_env,
        )
        return False   # ← DENY: fail closed
    # dev/test only: fall back to mock data with warning
    current_telemetry = generate_mock_telemetry()
```

**Behaviour by environment:**

| `CAGE_ENV` | Telemetry absent | Result |
| ---------- | ---------------- | ------ |
| `production` (or unset) | No live telemetry | **DENY** — `return False` (fail closed) |
| `development` / `dev` / `test` / `ci` | No live telemetry | **WARN** — falls back to `generate_mock_telemetry()` |

The mock fallback (`generate_mock_telemetry()`) is retained for dev/test environments where a live Langfuse instance is not available. However, it is now **unreachable in production** — any production call without live telemetry returns `False` immediately, causing the governance pipeline to return `DENIED`.

### Telemetry Freshness (Pre-existing Fail-Closed)

In addition to the missing-telemetry guard, the existing `_check_telemetry_freshness()` helper enforces that the most-recent observation in the provided telemetry is not older than `TELEMETRY_MAX_STALENESS_SECONDS` (default: 300 seconds). Stale telemetry also causes a fail-closed `return False`. This freshness check is independent of the missing-telemetry guard and applies in all environments.

### ISO 42001 Alignment

This hardening directly supports **ISO/IEC 42001:2023 §A.9.4** (AI system operational monitoring) by ensuring that the causal validation tier always operates against real, fresh operational data in production — never against predictable synthetic data that could be gamed.

---

## 3d. `StubNormativeProvider` Production Guard (commit e959cc3)

> **Classification:** Security Hardening — Governance Fail-Safe
> **Date:** 2026-06-15
> **Commit:** `e959cc3`
> **Affected Component:** [`src/gateway/governance/normative_provider.py`](../../src/gateway/governance/normative_provider.py)

### Background

The `StubNormativeProvider` is a development-only implementation of the `NormativeProvider` protocol. Its `validate_fria()` method unconditionally returns `admitted=True` — meaning every FRIA boundary check passes without any external validation. This is intentional for dev/CI environments where the external normative provider (e.g. Provider 01) is not reachable.

Prior to this hardening, `StubNormativeProvider` could be instantiated in any environment, including production. If `CAGE_NORMATIVE_PROVIDER=static` (the default) was left unchanged in a production deployment, the adaptive FRIA gating mechanism would silently operate against the stub — admitting all transactions regardless of their compliance posture.

### Remediation

[`StubNormativeProvider.__init__()`](../../src/gateway/governance/normative_provider.py) now raises `RuntimeError` at construction time if instantiated in a production environment:

```python
def __init__(self) -> None:
    _cage_env = os.getenv("CAGE_ENV", "production").lower()
    _is_production = _cage_env not in ("development", "test", "dev", "ci")

    if _is_production:
        raise RuntimeError(
            "StubNormativeProvider cannot be used in production "
            f"(CAGE_ENV={_cage_env!r}). "
            "Set CAGE_NORMATIVE_PROVIDER to a real provider name "
            "(e.g. CAGE_NORMATIVE_PROVIDER=provider_01) and ensure the "
            "provider credentials are configured."
        )
```

Because `StubNormativeProvider` is the implementation behind `CAGE_NORMATIVE_PROVIDER=static` (the default), this guard means that **a production deployment with the default provider configuration will fail at startup** rather than silently running with stub governance.

**Behaviour by environment:**

| `CAGE_ENV` | `CAGE_NORMATIVE_PROVIDER` | Result |
| ---------- | ------------------------- | ------ |
| `production` (or unset) | `static` (default) | `RuntimeError` at construction — pod crashes |
| `production` (or unset) | `provider_01` or `provider_02` | Real provider instantiated — normal operation |
| `development` / `dev` / `test` / `ci` | `static` | Stub instantiated with `WARNING` log |

### Security Significance

This guard closes the silent-stub attack surface: an operator who forgets to configure `CAGE_NORMATIVE_PROVIDER` in production will receive an immediate, unambiguous startup failure rather than a system that appears healthy while providing no real normative validation. The error message explicitly names the required corrective action.

This is consistent with the existing pattern of production startup assertions for KMS signing, governance salt, seal enforcement mode, and stub ledger provider (see §3b).

### ISO 42001 Alignment

This hardening supports **ISO/IEC 42001:2023 §A.6.1** (AI risk management) and **§A.9.2** (AI system controls) by ensuring that the external normative validation gate — a mandatory component of the adaptive FRIA enforcement mechanism — cannot be silently bypassed in production through a default configuration.

---

## 3. Authentication & Authorization

### HMAC-SHA256 Routing Seal

Every `POST /tools/execute` call is protected by the `X-CAGE-Routing-Seal` request header:

- **Algorithm**: HMAC-SHA256 of the full request body bytes
- **Secret**: `CAGE_ROUTING_SEAL_SECRET` environment variable
- **Enforcement**: [`src/gateway/server/governance_middleware.py`](../../src/gateway/server/governance_middleware.py)
- **Behavior**: Fail-closed — returns HTTP 401 on missing or invalid seal

> ✅ **FIND-010 / POAM-012: RESOLVED** — The HMAC bypass vulnerability that allowed unsigned requests to reach governed endpoints has been patched. This critical finding is closed.

### HMAC-SHA256 Governance State Signature

A second HMAC-SHA256 layer protects agent state transitions within the LangGraph pipeline:

- **Scope**: Applied over `execution_plan_output` content in `AgentState`
- **Flow**: Evaluator agent signs → stored as `governance_signature` in state → [`check_safety_signature(state)`](../../src/governed_financial_advisor/graph/nodes/safety_node.py) validates in `safety_node` before `governed_trader` executes
- **Purpose**: Prevents state tampering between evaluator and trader graph nodes

### OPA Rego RBAC (`trade.governance` Package)

Policy files:

- [`src/governed_financial_advisor/governance/policy/trade_governance.rego`](../../src/governed_financial_advisor/governance/policy/trade_governance.rego)
- [`deployment/system_authz.rego`](../../deployment/system_authz.rego)

| Role     | Trade Limit      | Behavior            |
| -------- | ---------------- | ------------------- |
| `junior` | ≤ $5,000         | Allow               |
| `junior` | $5,001 – $10,000 | Escalate for review |
| `senior` | ≤ $500,000       | Allow               |
| Any      | Above role limit | **DENY**            |

- Default policy: **DENY** (fail-closed)
- Confidence gate: `confidence_sufficient ≥ 0.95` enforced via `deployment/system_authz.rego`

### Authentication Gaps (Open Findings)

| Finding                                           | Area                     | Status |
| ------------------------------------------------- | ------------------------ | ------ |
| No MFA implemented                                | IA family (15% coverage) | Open   |
| FIND-001: No formal account management procedures | IA                       | Open   |
| FIND-012: No automated secret rotation schedule   | IA                       | Open   |

---

## 4. Network Security

### Kubernetes NetworkPolicy Enforcement

The `governance-stack` namespace enforces default-deny for all ingress and egress traffic. Explicit allow rules are defined per-service pair. Pod security admission applies the `restricted` profile, enforcing non-root execution, read-only root filesystem, and dropped capabilities.

**Ingress controller**: [`deployment/k8s/ingress.yaml`](../../deployment/k8s/ingress.yaml)

### Kubernetes Inference Gateway (ADR-002)

CAGE migrates from GKE GCE GatewayClass to nginx-based Kubernetes Inference Gateway:

| Manifest                                                                                                               | Purpose                                 |
| ---------------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| [`deployment/k8s/inference-gateway/gateway.yaml`](../../deployment/k8s/inference-gateway/gateway.yaml)                 | Gateway definition (nginx GatewayClass) |
| [`deployment/k8s/inference-gateway/http-route.yaml`](../../deployment/k8s/inference-gateway/http-route.yaml)           | HTTP routing rules                      |
| [`deployment/k8s/inference-gateway/inference-pool.yaml`](../../deployment/k8s/inference-gateway/inference-pool.yaml)   | vLLM backend pool                       |
| [`deployment/k8s/inference-gateway/reference-grant.yaml`](../../deployment/k8s/inference-gateway/reference-grant.yaml) | Cross-namespace reference grant         |

### Zero-Trust Network Hardening (Z3N)

CAGE defines a **Zero-Trust Network (Z3N)** architecture combining two complementary network enforcement layers:

#### Layer 1 — Linkerd mTLS (Intra-Cluster Encryption)

Source: [`deployment/k8s/linkerd-mtls-policy.yaml`](../../deployment/k8s/linkerd-mtls-policy.yaml)

Linkerd proxy injection encrypts all service-to-service traffic within the `governance-stack` namespace using mutual TLS. Certificates are automatically rotated every 24 hours by the Linkerd control plane.

| Resource Type | Purpose | Manifest Section |
| ------------- | ------- | ---------------- |
| `Server` (policy.linkerd.io/v1beta2) | Declares OPA (port 8181), NeMo (port 8000), and vLLM (port 8000) as named server resources | Lines 130–180 |
| `AuthorizationPolicy` | Fine-grained service-to-service allow rules (e.g., gateway → OPA, gateway → NeMo) | Lines 180–250 |
| `MeshTLSAuthentication` | Requires valid Linkerd mesh identity for all inbound connections | Lines 250+ |

Identity format: `<serviceaccount>.<namespace>.serviceaccount.identity.linkerd.cluster.local`

Verification: `linkerd viz authz deployment/opa-service -n governance-stack`

#### Layer 2 — Cilium L7 Egress Lockdown (Outbound FQDN Filtering)

Source: [`deployment/k8s/cilium-egress-lockdown.yaml`](../../deployment/k8s/cilium-egress-lockdown.yaml)

Three `CiliumNetworkPolicy` resources extend the standard L3/L4 NetworkPolicies with L7 DNS-aware filtering:

| Policy | Target | Allowed FQDNs | Purpose |
| ------ | ------ | -------------- | ------- |
| `cage-egress-inference` | `role: inference-node` | `generativelanguage.googleapis.com`, `oauth2.googleapis.com` | LLM API access only |
| `cage-egress-sovereign-agent` | `role: sovereign-agent` | `query1.finance.yahoo.com`, `storage.googleapis.com`, `generativelanguage.googleapis.com` | Market data + cloud storage + LLM |
| `cage-default-deny-egress` | All pods | None | Cilium-layer default-deny for all non-allowlisted external egress |

**Full approved FQDN egress allowlist** (all roles combined):

| FQDN | Purpose |
| ---- | ------- |
| `api.openai.com` | OpenAI-compatible API (external LLM fallback) |
| `api.anthropic.com` | Anthropic Claude API (external LLM fallback) |
| `generativelanguage.googleapis.com` | Google Gemini / Vertex AI |
| `*.googleapis.com` | GCS, Cloud KMS, Cloud Audit Logs, Workload Identity |
| `metadata.google.internal` | GKE Workload Identity metadata server |
| `us.i.posthog.com` | Product analytics (Langfuse telemetry) |
| `cloud.langfuse.com` | Langfuse SaaS OTLP ingestion |
| `api.trade.gov` | OFAC sanctions screening |
| `www.treasury.gov` | OFAC SDN list reference |

Cilium's DNS proxy intercepts all UDP/53 responses and dynamically populates FQDN-based IP sets, ensuring that sovereign agent pods cannot exfiltrate data to arbitrary external endpoints.

Verification: `cilium monitor --type l7 --from-label role=sovereign-agent`

#### ✅ Deployment Status (FIND-011 / POAM-007 — RESOLVED)

> **Z3N manifests are deployed and verified.** Linkerd mTLS proxy injection is active in the `governance-stack` namespace, enforcing SPIFFE/SVID identity for Gateway→OPA and Gateway→NeMo paths. Cilium L7 egress lockdown prevents lateral movement to unauthorized external endpoints. POAM-007 closed 2026-05-17.
>
> Verification: `linkerd viz authz deployment/opa-service -n governance-stack`

- **Residual Risk**: NONE (formerly PR-6 MODERATE)
- **FIPS Impact**: Resolved — all intra-cluster traffic is now mTLS-encrypted

---

## 5. Secret Management

Source: [`docs/SECRET_MANAGEMENT_OPTIONS.md`](../security/SECRET_MANAGEMENT_OPTIONS.md)

### Current Kubernetes Secrets (3 Objects in `governance-stack`)

| Secret Name              | Contents                                       |
| ------------------------ | ---------------------------------------------- |
| `oscal-artifact-secrets` | GCS credentials for OSCAL artifact storage     |
| `advisor-secrets`        | LLM API keys; governance salt; Langfuse tokens |
| `minio-credentials`      | MinIO access key and secret key                |

### Current Approach — Kubernetes-native Secret Injection

> **ADR**: Google Secret Manager was removed in favour of Kubernetes-native
> secret injection (env vars from `Secret` objects). No runtime dependency on
> `google-cloud-secret-manager`.

- Secrets are stored as `kubernetes_secret` resources provisioned by Terraform
  (see [`infra/modules/app_secrets/main.tf`](../../infra/modules/app_secrets/main.tf))
- Pods consume secrets via `envFrom` / `secretRef` — values are standard
  environment variables inside containers
- Rotation: update the Kubernetes `Secret` object and trigger a rolling restart

### Alternative Approaches (for future consideration)

| Option   | Approach                                         | Note                                              |
| -------- | ------------------------------------------------ | ------------------------------------------------- |
| Option A | External Secrets Operator (ESO) with any backend | Cloud-portable; Vault, AWS SM, Azure KV supported |
| Option C | CI pipeline injection at deployment time         | Fallback; manual `kubectl create secret` commands          |

### Terraform IAM Configuration

- [`infra/modules/app_secrets/main.tf`](../../infra/modules/app_secrets/main.tf) — least-privilege service account IAM bindings
- [`infra/targets/gcp-gke/main.tf`](../../infra/targets/gcp-gke/main.tf) — base IAM configuration
- [`infra/modules/gcp_gke_cluster/main.tf`](../../infra/modules/gcp_gke_cluster/main.tf) — GKE Workload Identity and shielded node configuration

> ⚠️ **FIND-012 (Open)**: No automated secret rotation schedule is defined or enforced. Manual rotation is the current practice.

---

## 6. PII & Privacy Protection

### Unified PII Protection Architecture

```
User Input
    │
    ▼
NeMo Guardrails (Input Scan)
    │  Blocks PII before reaching LLM using in-process Presidio
    │
    ▼
LLM Inference
    │
    ▼
NeMo Guardrails (Output Rail)
    │  Masks PII in LLM responses using in-process Presidio
    │
    ▼
Sanitized Output
    │
    ▼
OTel Telemetry Export
    │  Inference Proxy applies `scrub_pii` regex for span redaction
```

### Layer 1 — NeMo Guardrails with In-Process Presidio

- Configuration: [`config/rails/config.yml`](../../config/rails/config.yml) — **10** Presidio PII entity types configured
- Microsoft Presidio is executed **in-process** as a custom action within NeMo Guardrails, scanning for **10** entity types at `score_threshold = 0.3` (NeMo config); the standalone `PIISanitizer` uses `PRESIDIO_SCORE_THRESHOLD=0.5`.
- Input scan (`nemo_input_scan`): blocks PII-containing prompts before LLM inference
- Output rail (`nemo_output_rail`): masks PII in LLM responses
- ISO 42001 mapping: A.9.2 (data minimization) and A.5.2 (privacy by design)
- Implementation: [`src/governed_financial_advisor/utils/privacy.py`](../../src/governed_financial_advisor/utils/privacy.py)

### Layer 2 — Telemetry Redaction

- The Inference Proxy uses a lightweight `scrub_pii` (regex-based) utility strictly to redact telemetry span attributes before export to observability backends.

### Privacy Data Retention Schedule

| Data Type                      | Retention Period | Regulatory Authority            |
| ------------------------------ | ---------------- | ------------------------------- |
| Audit logs                     | 7 years          | FINRA Rule 4511, SEC Rule 17a-4 |
| AI interaction logs (raw)      | 90 days          | Internal policy                 |
| AI interaction logs (redacted) | 7 years          | Internal policy                 |
| PII in session                 | 24 hours         | SEC Reg S-P                     |
| Session tokens                 | ≤ 8 hours        | Internal policy                 |

---

## 7. Audit Logging Architecture

### OpenTelemetry Pipeline

- Auto-instrumentation: `FastAPIInstrumentor` (gateway API) + `LangchainInstrumentor` (agent graph)
- **Collector:** Langfuse integrated OTLP ingestion (standalone `opentelemetry-collector-contrib` deprecated 2026-05-31)
- Sampling strategy: 1% general traffic (RA-001 requirement); 100% governance decision spans
- Export: OTLP/HTTP → Langfuse integrated collector endpoint

### ISO 42001 Control Stamping

Every governance span receives 6 OpenTelemetry attributes applied by [`src/gateway/governance/iso_control.py:stamp_iso_control()`](../../src/gateway/governance/iso_control.py):

| OTel Attribute             | Purpose                                   |
| -------------------------- | ----------------------------------------- |
| `iso42001.control`         | Control identifier (e.g., A.6.1.3)        |
| `iso42001.tier`            | Risk tier classification                  |
| `iso42001.outcome`         | Pass / Fail / Escalate                    |
| `iso42001.timestamp`       | UTC timestamp of control evaluation       |
| `iso42001.gateway_version` | Gateway version that enforced the control |
| `iso42001.evidence_chain`  | Hash chain linking prior evidence spans   |

### Langfuse Dual-Project Setup

| Project                 | Data Captured                                          |
| ----------------------- | ------------------------------------------------------ |
| Project 1 — Application | Agent traces, latency, token usage, quality metrics    |
| Project 2 — Compliance  | Control pass/fail rates, evidence age, OSCAL alignment |

- Cache: `TTLCache(maxsize=32, ttl=300)` — 5-minute cache per compliance metric to reduce Langfuse API load

> ⚠️ **FIND-003 / POAM-003 (High, Open)**: The `EvaluatorAuditor` component partially uses mock trace data instead of real audit events. This means audit evidence for evaluator decisions is not fully trustworthy. Remediation requires replacing mock data sources with genuine telemetry instrumentation.

---

## 8. AgentSight eBPF Monitoring

Source: [`deployment/agentsight/agentsight-config.yaml`](../../deployment/agentsight/agentsight-config.yaml), [`deployment/agentsight/README.md`](../../deployment/agentsight/README.md)

### DaemonSet Deployment

Manifest: [`deployment/k8s/agentsight-daemon.yaml`](../../deployment/k8s/agentsight-daemon.yaml)

- **Scope**: Runs on every GKE node as a DaemonSet (kernel-privileged)
- **Target**: `python3` processes specifically (narrows to CAGE application processes)
- **Intercepts**:
  - OpenSSL uprobes — captures TLS handshake metadata
  - Syscall events — file I/O operations and network calls
- **Output**: Kernel-level audit trail of all process activity within the node

### ✅ Gap G7.1-2 (RESOLVED)

The eBPF exporter has been updated to `remote` output mode:

- Exporter type: `"remote"` (targeting `http://agentsight-dashboard:8080`)
- eBPF findings are now exported to the AgentSight dashboard backend for centralized collection
- **Previous gap**: Console-only output meant no centralized storage or alerting

---

## 8a. Vendor Integration Security (`src/integrations/`)

> **Status:** Implemented in v2.1.0. See [`EXTENSIBILITY_ARCHITECTURE.md §2.6`](../../docs/architecture/EXTENSIBILITY_ARCHITECTURE.md).

All third-party compliance and attestation provider adapters are isolated under `src/integrations/{vendor}/`. This boundary prevents vendor SDK code from leaking into the governance kernel or gateway packages, limiting the blast radius of any vendor-side vulnerability.

| Provider      | Module                                    | Protocol | Role                                                                 | Verdict vocabulary | Security Boundary                                      |
| ------------- | ----------------------------------------- | -------- | -------------------------------------------------------------------- | ------------------ | ------------------------------------------------------ |
| Provider 01   | `src/integrations/provider_01/provider.py` | `NormativeProvider` | Normative legal-baseline provider and synchronous FRIA gate (Tier 6b) | `ALLOW` / `REFUSE` / `ESCALATE` | Isolated package; lazy-loaded only when provider API key is set |
| Provider 02   | `src/integrations/provider_02/`           | Vendor attestation surface | Certified Evidence Receipt creation, JWK-cached verification, and LangGraph bundle assembly | — (no gate verdict) | Isolated package; lazy-loaded only when provider API key is set |
| Provider 03   | `src/integrations/provider_03/`           | `NormativeProvider` | Decision-governance and bind-receipt provider; synchronous FRIA gate | `APPROVED` / `ESCALATE` / `REJECTED` | Isolated package; lazy-loaded |
| Provider 04   | `src/integrations/provider_04/`           | `AttestationProvider` + envelope mapper | Attestation fetch (**stub — returns an empty list**) and bidirectional `GovernanceEnvelope` ↔ vendor wire-format mapping | — (emits `AttestationStatus`) | Isolated package; lazy-loaded |
| Provider 05   | `src/integrations/provider_05/`           | `AttestationProvider` ×3 | Verifiable Execution Evidence Pack — three axioms (Blueprint, Key, Physics); seeded/synthetic data store | — (emits `AttestationStatus`) | Isolated package; lazy-loaded |
| Provider 06   | `src/integrations/provider_06/adapter.py` | `NormativeProvider` | Agent-integrity verifier; synchronous gate. In-repo component is a **SPIKE** with a mock endpoint; upstream vendored at `third_party/agent-integrity/` | `PASS` / `REVIEW` / `BLOCKED` | Isolated package; lazy-loaded |

> **Verdict vocabularies are per-provider and are not interchangeable.** In
> particular, `REVIEW` is valid **only** for Provider 06; Provider 01 rejects it
> as unrecognized and fails closed. `ESCALATE` (Providers 01 and 03) and
> `REVIEW` (Provider 06) produce the same CAGE-side outcome — `admitted=False`
> with `needs_human_review: true`, parking the request in the `DeferQueue` —
> but the accepted wire tokens differ. Each adapter directory carries a
> `README.md` with its full mapping table.
>
> Providers 01, 02, and 03 are `INTERFACE READY` — the HTTP clients are
> complete, but **no live endpoints are configured** in this repository;
> documentation uses placeholders such as `https://api.example.com/normative`.
> Provider 04's fetch path is a stub and Provider 05 serves seeded synthetic
> records, so neither performs live I/O today.

**Key security properties:**
- Vendor SDKs are **not imported at module load time** — `get_normative_provider()` in [`src/gateway/governance/normative_provider.py`](../../src/gateway/governance/normative_provider.py) resolves vendor packages through lazy imports, so a missing or misconfigured vendor credential does not crash the gateway.
- Every adapter is exercised by the hermetic Universal Protocol Conformance Suite ([`tests/test_normative_provider_conformance.py`](../../tests/test_normative_provider_conformance.py)), which asserts protocol conformance and fail-closed semantics across all regions in CI. Some vendor directories additionally carry a package-local suite under `src/integrations/{vendor}/tests/`.
- Cloud KMS (`kms_signer.py`) and Redis (`evidence_stream.py`) are **not** vendor adapters — they are substrate infrastructure invariants and remain in `src/gateway/governance/`.

> ⚠️ **POAM-018 (Open):** External normative provider credentials (`LANGFUSE_COMPLIANCE_*`) fail silently when absent. See [`DUAL_PROJECT_ARCHITECTURE.md §5.2`](../../docs/architecture/DUAL_PROJECT_ARCHITECTURE.md) for remediation details.

---

## 9. Cryptographic Controls

| Mechanism               | Algorithm                  | Usage                            | FIPS Status              | Gaps                             |
| ----------------------- | -------------------------- | -------------------------------- | ------------------------ | -------------------------------- |
| **KMS Governance Signing** | RSA asymmetric HSM (GCP/AWS/Azure; algorithm auto-detected per key) | **Primary** — all governance decisions; non-repudiation; provider selected via `CAGE_KMS_PROVIDER` | ✅ FIPS-approved | 90-day rotation cadence per `KEY_ROTATION.md` |

> **Security hardening (H52):** `KmsSigner.sign()` embeds `"signed_at": int(time.time())` in every signed payload. `KmsSigner.verify()` raises `ValueError` if `now - signed_at > 300 s` (`MAX_KMS_PAYLOAD_AGE_SECONDS`). This closes the replay-attack vector where a compromised agent with Redis write access could reset the 300 s TTL indefinitely by overwriting a stale-but-signed payload.
| Routing Seal            | HMAC-SHA256                | Every `POST /tools/execute` call | ✅ FIPS-approved         | 30-day secret rotation cadence per `KEY_ROTATION.md` |
| Governance Signature    | HMAC-SHA256                | Agent state transitions          | ✅ FIPS-approved         | None — fully implemented         |
| TLS (external)          | TLS 1.2+ (NIST SP 800-52)  | External service connections     | ✅ FIPS-compliant        | Verified via `tests/test_tls_enforcement.py` (POAM-011 CLOSED) |
| Intra-cluster transport | **Linkerd mTLS**           | Service-to-service               | ✅ FIPS-compliant        | **FIND-011 RESOLVED** — Linkerd mTLS with SA annotations |
| Context Evidence Chain  | SHA-256 Hash Chain         | OscalFindings integrity tracking | ✅ FIPS-approved         | None — fully implemented         |
| Provenance Hash Chain   | SHA-256 Hash Chain         | LangGraph governance node audit trail | ✅ FIPS-approved    | None — fully implemented         |
| Key Lifecycle & Rotation| Cloud KMS / HMAC / mTLS    | Key management policies          | ✅ FIPS-compliant        | **POAM-012 CLOSED** — Documented in `KEY_ROTATION.md` |

**FIPS 140-2/3 Assessment**: HMAC-SHA256 is a FIPS-approved algorithm. Intra-cluster mTLS is now enforced via Linkerd (FIND-011 resolved), satisfying FIPS transport requirements for all service-to-service communication within the `governance-stack` namespace.

### 9.0 Cryptographic Integrity — Routing Seal v2 and Provenance Chain

#### HMAC-SHA256 Routing Seal v2 (Evidence Binding)

**Source:** [`src/gateway/governance/routing_seal.py`](../../src/gateway/governance/routing_seal.py)

Every governance approval is sealed with an HMAC-SHA256 routing seal before execution is permitted. The v2 seal format binds the durable evidence record directly into the cryptographic payload:

```
<expire_ts_hex>.<action_slug>.<record_hash_hex>.<hmac_hex>
```

| Field | Description |
| ----- | ----------- |
| `expire_ts_hex` | Hex-encoded Unix timestamp of seal expiry |
| `action_slug` | URL-safe slug identifying the governed action |
| `record_hash_hex` | Hex-encoded SHA-256 hash of the durable evidence record |
| `hmac_hex` | HMAC-SHA256 hex digest over `expire_ts_hex.action_slug.record_hash_hex` |

| Parameter | Value | Security Property |
| --------- | ----- | ----------------- |
| TTL | **30 seconds** | Prevents replay attacks; seal expires 30s after issuance |
| Algorithm | HMAC-SHA256 | FIPS-approved; constant-time `hmac.compare_digest` prevents timing side-channels |
| Secret | `CAGE_ROUTING_SEAL_SECRET` | Kubernetes `Secret` object; custom non-default secret enforced in production |
| Evidence Binding | `record_hash` folded into HMAC | Actuators enforce `CAGE_REQUIRE_EVIDENCE_BINDING=true` in production |
| Enforcement | [`src/gateway/server/governance_middleware.py`](../../src/gateway/server/governance_middleware.py) | Missing, expired, or un-bound seal → HTTP 401 / `SymbolicGovernorViolation` (fail-closed) |

The routing seal satisfies the `NoDirectBind` formal invariant: there is no code path from `CHECKING` to `EXECUTED` that bypasses `SEAL_ISSUED`. This was machine-verified over the full reachable state space in `proof/model.py` (see §3a, Gap 2).

**ISO 42001 mapping:** A.7.5 (Records Integrity). **[US_FED only]** NIST AU-10 (Non-repudiation).

#### SHA-256 Provenance Hash Chain

**Source:** [`src/gateway/governance/provenance_chain.py`](../../src/gateway/governance/provenance_chain.py)

The provenance chain builds a tamper-evident SHA-256 hash chain across all LangGraph governance nodes. Any modification to any node's input, output, or decision invalidates all subsequent chain links.

**Hash computation:** [`compute_hash(data)`](../../src/gateway/governance/provenance_chain.py) canonicalises the dict with **RFC 8785 JCS** (`jcs_canonicalize_plan()`) before SHA-256 hashing — deterministic regardless of insertion order and byte-identical across Python, Go, and JavaScript runtimes. Non-serialisable values are coerced to strings before canonicalization. This replaces the previous `json.dumps(sort_keys=True, separators=(',', ':'))` form; digests are not comparable across the change (see [`docs/BREAKING_CHANGES_v3.md`](../BREAKING_CHANGES_v3.md)).

**Chain construction complexity:** O(n) — each record's `parent_hash` is the SHA-256 of the preceding record's full dict (sorted keys). The first record has `parent_hash=None`.

```
ProvenanceRecord[0]  (parent_hash=None)
      │  chain_hash() = SHA-256(jcs_canonicalize_plan(record_0))
      ▼
ProvenanceRecord[1]  (parent_hash=chain_hash[0])
      │  chain_hash() = SHA-256(jcs_canonicalize_plan(record_1))
      ▼
ProvenanceRecord[n]  (parent_hash=chain_hash[n-1])
```

**Chain integrity verification:** [`verify_chain_integrity(records)`](../../src/gateway/governance/provenance_chain.py) checks that each record's `parent_hash` matches the `chain_hash()` of the preceding record. Returns `False` on any broken link — O(n) verification.

**ISO 42001 mapping:** A.7.5 (Records Integrity — universal). **[US_FED only]** NIST AI 600-1 §2.7 (Information Integrity).

---

### 9.1 Cryptographic Context Accumulator (AARM-V1)

CAGE v2.0.0 introduces a **Cryptographic Context Accumulator** (`src/compliance_bridge/context_accumulator.py`) to seal audit evidence against retroactive tampering or Memory Poisoning attempts. 
*   **SHA-256 Hash-Chaining:** Every emitted `OscalFinding` is chained cryptographically to its predecessor. The `record_hash` for finding $n$ is calculated as `SHA-256(prev_hash || content_json)`.
*   **Seal Sentinel:** Each audit execution is capped by a `CHAIN_SEALED` sentinel payload. The compliance API validates `chain_root`, `chain_length`, and `chain_integrity_valid` on all reads, satisfying **ISO 42001 Annex A.5.3** evidence logging controls.

---

### 9.2 CVE-2025-69872 Remediation (`outlines` Package Removal)

The `outlines` Python package was removed from all CAGE container images following the discovery of **CVE-2025-69872** (critical severity). This remediation satisfies **ISO/IEC 42001:2023 §A.9.3** (AI system vulnerability management) universally, and additionally satisfies **NIST SP 800-53 SI-2 (Flaw Remediation)** `[US_FED only]` as validated by the `compliance/lula/lula-validation-si2.yaml` Lula manifest.

| Attribute | Value |
| --------- | ----- |
| **CVE** | CVE-2025-69872 |
| **Severity** | Critical |
| **Affected Package** | `outlines` (structured output library) |
| **Remediation** | Package removed from all images; vLLM FSM guided decoding used for `ExecutionPlan` schema compliance |
| **Universal Control** | ISO/IEC 42001:2023 §A.9.3 (AI system vulnerability management) — all regions |
| **US_FED Control** | NIST SP 800-53 SI-2 (Flaw Remediation) `[US_FED only]` |
| **Status** | **RESOLVED** |

---

## 9.3 Financial Safety Controls

This section documents the mathematical safety controls that enforce financial integrity at the governance layer. These controls are complementary to the cryptographic controls in §9.0–§9.2 and operate on the financial state of the system.

### Control Barrier Function (CBF)

**Source:** [`src/gateway/governance/cbf.py`](../../src/gateway/governance/cbf.py)

The Control Barrier Function enforces the core financial safety invariant using control theory formalism. The safe set and barrier function are:

```
Safe set:         S = {x ∈ ℝⁿ : h(x) ≥ 0}
Barrier function: h(x) = cash_balance − min_cash_balance
```

The discrete-time CBF condition enforced at every governance step:

```
h(S(t+1)) ≥ (1−γ) · h(S(t))     where γ ∈ (0,1)
```

| Parameter | Value | Region |
| --------- | ----- | ------ |
| `min_cash_balance` | `1000.0` | All regions |
| `γ` (decay rate) | `0.5` | US_FED, APAC_MAS |
| `γ` (decay rate) | `0.6` | EU_ECB (stricter CRD VI buffer) |

**Enforcement mechanism:** Redis `WATCH/MULTI/EXEC` atomic transaction (5 retries on contention). A violation of `h(x) ≥ 0` raises `GovernanceError` immediately (fail-closed). The CBF is re-evaluated at execution time by `post_hitl_revalidate_node` using the fresh live price to prevent price-drift races.

**Security significance:** The CBF is the primary financial safety gate. Setting `CBF_FAIL_OPEN=true` in production raises a `RuntimeError` at startup (Gap 3 remediation — see §3a), preventing any degraded-gate configuration from reaching production.

**ISO 42001 mapping:** A.8.4 (AI System Operation Controls). **[US_FED only]** NIST SP 800-53 SC-4.

### Fiscal Limit Guard

**Source:** [`src/gateway/governance/fiscal_limit_guard.py`](../../src/gateway/governance/fiscal_limit_guard.py)

The `FiscalLimitGuard` prevents race conditions where parallel agent threads collectively exceed the authorized daily spending limit:

| Parameter | Value | Notes |
| --------- | ----- | ----- |
| Daily cap | **$500,000 USD** | Configurable via `FISCAL_DAILY_CAP_USD` env var |
| Cap storage | Integer cents | Prevents floating-point precision errors in financial arithmetic |
| Window | **86,400 seconds** | Rolling 24-hour window |
| Retry strategy | Exponential backoff: `_RETRY_BASE_MS × 2^attempt` | Handles Redis `WATCH/MULTI/EXEC` contention |
| Reservation TTL | 300 seconds | Reclaims limits from crashed nodes automatically |

**Headroom pre-reservation:** Fiscal headroom is reserved in Redis *after* concurrent CBF+OPA validation (Tiers 2+4), closing the saga-atomicity gap (distributed-transaction atomicity failure, not a concurrency race). Unused limits are returned via `release(token)` on Saga LIFO rollback. `FiscalLimitGuard.rollback_state(amount, audit_id)` is a Saga compensation stub that reverses the Redis debit when a downstream tier fails after Tier 3a commitment; it logs `[SAGA-ROLLBACK]` and re-raises on Redis failure. If Redis is unavailable, the trade is blocked (fail-closed).

**ISO 42001 mapping:** A.8.4 (AI System Operation Controls). **[US_FED only]** NIST SP 800-53 SC-4 (Information in Shared Resources).

---

## 10. Red Team & Adversarial Testing

Source: [`tests/red_team/`](../../tests/red_team/), [`src/governed_financial_advisor/agents/evaluator/red_agent.py`](../../src/governed_financial_advisor/agents/evaluator/red_agent.py)

### Adversarial Test Coverage

| Component                                                                                                                            | Description                                              |
| ------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------- |
| [`tests/red_team/adversarial_dataset.json`](../../tests/red_team/adversarial_dataset.json)                                           | 290+ adversarial payloads across attack categories       |
| [`src/governed_financial_advisor/agents/evaluator/red_agent.py`](../../src/governed_financial_advisor/agents/evaluator/red_agent.py) | Adversarial harness running the full governance pipeline |
| [`tests/red_teaming/test_adversarial.py`](../../tests/red_team/test_adversarial.py)                                               | Automated adversarial test suite (CI-integrated)         |
| [`tests/red_team/run_red_team.py`](../../tests/red_team/run_red_team.py)                                                             | Full red team execution script                           |

### Attack Categories Covered

- **Prompt injection** — attempts to override system instructions via user input
- **Policy bypass** — semantic tricks to circumvent OPA authorization decisions
- **PII extraction** — attempts to elicit protected personal information from LLM responses
- **Semantic override** — rephrasing to bypass NeMo Guardrails entity detection
- **HMAC forgery attempts** — invalid seal construction to test routing seal enforcement

### Governance Policy Regression Testing

| Test Artifact                                                                                          | Purpose                                               |
| ------------------------------------------------------------------------------------------------------ | ----------------------------------------------------- |
| [`tests/opa_snapshots/01_no_identity_match.json`](../../tests/opa_snapshots/01_no_identity_match.json) | Validates OPA DENY on unrecognized identity           |
| [`tests/opa_snapshots/02_trade_no_auth.json`](../../tests/opa_snapshots/02_trade_no_auth.json)         | Validates OPA DENY on unauthorized trade request      |
| [`scripts/canary_opa_policy.sh`](../../scripts/canary_opa_policy.sh)                                   | Canary check for policy regression across deployments |

---

## 11. Security Assessment Findings Summary

Sources: [`compliance/sar/SAR_2026Q1.md`](../../compliance/sar/SAR_2026Q1.md), [`docs/POAM.md`](../POAM.md)

> ⚠️ **Overall Assessment: HIGH Risk — ATO Not Recommended**

| Finding ID                                      | Severity     | Security Area     | Status                            |
| ----------------------------------------------- | ------------ | ----------------- | --------------------------------- |
| FIND-010: HMAC routing seal bypass              | **Critical** | Cryptography      | ✅ **RESOLVED (POAM-007 Closed)** |
| FIND-011: No intra-cluster mTLS                 | **Critical** | Network           | ✅ **RESOLVED (POAM-007 Closed)** |
| FIND-007: FIPS 199 unsigned                     | **Critical** | Compliance        | 🔄 In-Progress                    |
| FIND-001: No account management procedures      | High         | Identity & Access | ❌ Open                           |
| FIND-003: Mock audit traces in EvaluatorAuditor | High         | Audit             | ❌ Open                           |
| FIND-008: No vulnerability scanning            | High         | Risk Assessment   | ✅ **RESOLVED (POAM-010 Closed)** |
| FIND-006: No Incident Response Plan             | High         | Incident Response | ❌ Open                           |
| FIND-012: No automated secret rotation          | Medium       | Identity & Access | ❌ Open                           |
| POAM-011: SC-8 Transmission Confidentiality     | Medium       | Network           | ❌ **Open**                       |
| POAM-012: SC-12 Cryptographic Key Management    | Medium       | Cryptography      | ❌ **Open**                       |

### Supporting Security Documents

| Document                                                             | Purpose                            |
| --------------------------------------------------------------------- | ---------------------------------- |
| [`compliance/sar/SAR_2026Q1.md`](../../compliance/sar/SAR_2026Q1.md) | Security Assessment Report Q1 2026 |

> **Note (FIND-006, FIND-007):** Draft Incident Response Plan, Security
> Assessment Plan, and Change Management Process documents previously lived
> under `docs/security/` and `docs/governance/`. They were removed — CAGE
> is a reference architecture, not an operating organization, and fictional
> `[TBD]` role incumbents and AO sign-off blocks provided no engineering
> value. Adopters deploying CAGE in a real regulated environment author
> their own IRP/SAP/change-management process using the control mapping in
> `docs/compliance/` and the engineering standards in
> [`AGENTS.md`](../../AGENTS.md) as the starting point.

---

## 12. Terraform Security Configuration

Source: [`infra/README.md`](../../infra/README.md)

CAGE infrastructure is provisioned via Terraform with security controls encoded as IaC:

| Terraform File                                                                                     | Security Relevance                                                   |
| -------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| [`infra/modules/app_secrets/main.tf`](../../infra/modules/app_secrets/main.tf) | Least-privilege IAM bindings for all service accounts                |
| [`infra/targets/gcp-gke/main.tf`](../../infra/targets/gcp-gke/main.tf)                                 | Base IAM configuration and role assignments                          |
| [`infra/modules/app_secrets/main.tf`](../../infra/modules/app_secrets/main.tf)                         | Kubernetes Secret resource provisioning (GSM removed)                |
| [`infra/modules/gcp_gke_cluster/main.tf`](../../infra/modules/gcp_gke_cluster/main.tf)                                 | GKE cluster: Workload Identity, shielded nodes, binary authorization |
| [`infra/modules/gcp_gke_cluster/networking.tf`](../../infra/modules/gcp_gke_cluster/networking.tf)                   | VPC configuration and firewall rules                                 |
| [`infra/modules/agentsight_ui/main.tf`](../../infra/modules/agentsight_ui/main.tf)                   | AgentSight eBPF monitoring deployment                                |

**Key security principles enforced in Terraform**:

- Workload Identity Federation — eliminates static service account key files
- Shielded GKE nodes — Secure Boot, vTPM, Integrity Monitoring enabled
- VPC-native cluster networking — no legacy routes
- Least-privilege IAM — each service account bound to minimum required roles

---

_End of Document — CAGE Technical Report: Security Infrastructure_

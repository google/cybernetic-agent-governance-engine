# POAM-023 Implementation Plan
## External Balance Reconciliation — Closing the CBF Ground Truth Gap

| Field | Value |
|---|---|
| **POAM ID** | POAM-023 |
| **Control** | SI-2 / ISO 42001 §A.9.4 |
| **Original target** | 2026-09-08 |
| **Revised target** | See phase schedule below |
| **Blocker for** | arxiv preprint (Blocker 3); NIST ATO Step 5 |
| **Owner** | Engineering |

---

## Problem Statement

The Control Barrier Function (CBF) evaluates:

```
h(x) = cash_balance − min_cash_balance ≥ 0
```

But `cash_balance` is written to Redis by the same execution system that requests trades. This is a **recursive self-authentication vulnerability**: the system reports its own financial state, then uses that self-reported state to pass the governance check that authorises further trades.

In litigation or a regulatory examination, the question is: *"Who wrote the number that the barrier function checked?"* The current answer is: *the same system that wanted the trade approved.*

The fix is already architecturally designed in [`src/compliance_bridge/reconciliation_worker.py`](../../src/compliance_bridge/reconciliation_worker.py). The `ExternalLedgerReconciler`, `LedgerProvider` protocol, `ReconciliationResult` dataclass, Redis key schema, and `AnchorageGrpcLedgerProvider` stub are all in place. What remains is:

1. Wiring the CBF to read `reconciliation:verified_balance` instead of `safety:current_cash`
2. Implementing `AnchorageGrpcLedgerProvider.fetch_balance()` (or a production-grade alternative)
3. Deploying the reconciliation daemon as an isolated K8s workload
4. Adding the signature verification step in the CBF read path

---

## Architecture (Already Designed)

```
┌─────────────────────────────────────────────────────────────────┐
│  reconciliation-worker namespace (Cilium: egress to provider    │
│  FQDN only; NO ingress from gateway or financial-advisor pods)  │
│                                                                 │
│  ExternalLedgerReconciler.run_loop()                            │
│    │                                                            │
│    ├─► AnchorageGrpcLedgerProvider.fetch_balance()             │
│    │     └─► mTLS gRPC → Anchorage Digital API                 │
│    │                                                            │
│    ├─► KMSGovernanceSigner.sign(payload)                        │
│    │     └─► Cloud KMS HSM (asymmetricSign)                     │
│    │                                                            │
│    └─► Redis SETEX reconciliation:verified_balance (TTL=300s)  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼ (every 60s)
┌─────────────────────────────────────────────────────────────────┐
│  gateway namespace                                              │
│                                                                 │
│  ControlBarrierFunction.verify_action()                         │
│    │                                                            │
│    ├─► read_verified_balance(redis) → ReconciliationResult      │
│    │     ├─ None (TTL expired) → FAIL CLOSED                   │
│    │     └─ result → verify KMS signature → use balance         │
│    │                                                            │
│    └─► h(x) = verified_balance − min_cash_balance              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Phase Plan

### Phase 1 — CBF Read Path Switch (no external dependency)
**Estimated effort:** 2 days  
**Unblocks:** The arxiv preprint claim can be scoped correctly even before Phase 2

#### 1.1 Modify `ControlBarrierFunction._read_cbf_state_atomic()`

**File:** [`src/gateway/governance/cbf.py`](../../src/gateway/governance/cbf.py)

Current behaviour: reads `safety:current_cash` (self-reported).  
Target behaviour: attempt `reconciliation:verified_balance` first; fall back to `safety:current_cash` with a CRITICAL audit log if the verified balance is absent.

```python
# In ControlBarrierFunction._read_cbf_state_atomic()
from src.compliance_bridge.reconciliation_worker import read_verified_balance

async def _read_cbf_state_atomic(self) -> dict[str, float]:
    # Attempt 1: externally reconciled balance (POAM-023)
    verified = read_verified_balance(redis_client._get())
    if verified is not None:
        # Verify KMS signature before trusting the balance
        if verified.signature:
            try:
                from src.gateway.governance.kms_signer import get_governance_signer
                signer = get_governance_signer()
                payload_dict = {
                    "source": verified.source,
                    "balance_usd": verified.balance_usd,
                    "verified_at": verified.verified_at,
                }
                if not signer.verify(payload_dict, verified.signature):
                    logger.critical(
                        "CBF: reconciled balance signature INVALID — "
                        "falling back to self-reported balance. "
                        "AUDIT GAP: balance provenance unverified."
                    )
                    # Fall through to self-reported path
                else:
                    logger.info(
                        "CBF: using externally reconciled balance=%.2f "
                        "source=%s verified_at=%.0f",
                        verified.balance_usd, verified.source, verified.verified_at,
                    )
                    return {"current_cash": verified.balance_usd, "source": "reconciled"}
            except Exception as sig_exc:
                logger.critical(
                    "CBF: KMS signature verification failed (%s) — "
                    "falling back to self-reported balance.", sig_exc
                )
        else:
            # Unsigned reconciled balance (stub mode) — accept in dev/test only
            if _IS_PRODUCTION:
                logger.critical(
                    "CBF: reconciled balance has no KMS signature in production — "
                    "falling back to self-reported balance. AUDIT GAP."
                )
            else:
                return {"current_cash": verified.balance_usd, "source": "reconciled_unsigned"}

    # Fallback: self-reported balance (POAM-023 open)
    logger.warning(
        "CBF: no verified external balance available — using self-reported "
        "safety:current_cash. POAM-023 open: CBF ground truth is unverified."
    )
    if redis_client is None:
        raise RuntimeError("Redis client unavailable.")
    client = redis_client._get()
    async with client.pipeline(transaction=False) as pipe:
        pipe.get(self.redis_key)
        results = await pipe.execute()
    raw_cash = results[0]
    current_cash = float(raw_cash) if raw_cash is not None else 100000.0
    return {"current_cash": current_cash, "source": "self_reported"}
```

#### 1.2 Add `source` field to OTel spans

In `_do_verify_action()`, stamp `safety.balance.source` on the span:

```python
span.set_attribute("safety.balance.source", state.get("source", "unknown"))
span.set_attribute("safety.balance.reconciled", state.get("source") == "reconciled")
```

This makes the balance provenance visible in Langfuse and satisfies the DORA Art. 10 audit logging obligation.

#### 1.3 Add startup assertion for production

In [`src/gateway/governance/symbolic_governor.py`](../../src/gateway/governance/symbolic_governor.py), add alongside the existing Gap 3/4 assertions:

```python
# Gap 5 (POAM-023): reconciliation provider must not be stub in production
if _IS_PRODUCTION:
    _recon_provider = os.getenv("RECONCILIATION_PROVIDER", "stub")
    if _recon_provider == "stub":
        logger.critical(
            "CAGE STARTUP WARNING (POAM-023): RECONCILIATION_PROVIDER=stub in production. "
            "CBF ground truth is self-reported. This is an open audit gap. "
            "Set RECONCILIATION_PROVIDER=anchorage to close POAM-023."
        )
        # NOTE: This is a WARNING not a RuntimeError because the CBF still functions
        # with self-reported balance — it is a compliance gap, not a safety failure.
        # Upgrade to RuntimeError after Phase 2 is deployed.
```

#### 1.4 Tests for Phase 1

New test file: `tests/test_cbf_reconciliation.py`

```python
# Test cases:
# 1. CBF uses reconciled balance when available and signature valid
# 2. CBF falls back to self-reported when reconciled balance absent (TTL expired)
# 3. CBF falls back to self-reported when KMS signature invalid (CRITICAL log emitted)
# 4. CBF falls back to self-reported when reconciled balance unsigned in production
# 5. OTel span has safety.balance.source="reconciled" when reconciled path taken
# 6. OTel span has safety.balance.source="self_reported" when fallback taken
```

**Deliverable:** PR with CBF read path switch, OTel stamping, startup warning, and 6 new tests. The arxiv preprint can now accurately state: "The CBF preferentially reads from an externally reconciled balance; when unavailable, it falls back to self-reported state with a CRITICAL audit log (POAM-023 open)."

---

### Phase 2 — Production Provider Implementation
**Estimated effort:** 5–10 days (depends on Anchorage API access)  
**Dependency:** Anchorage Digital enterprise API credentials OR alternative provider

#### Option A: Anchorage Digital (original POAM-023 design)

**File:** [`src/compliance_bridge/reconciliation_worker.py`](../../src/compliance_bridge/reconciliation_worker.py)

The `AnchorageGrpcLedgerProvider` class is already stubbed. Implementation requires:

1. **Anchorage enterprise onboarding** — contact Anchorage Digital for API access. This is a business process, not an engineering task. Timeline: 2–6 weeks.

2. **Generate gRPC stubs** from Anchorage protobuf definitions:
   ```bash
   pip install grpcio-tools
   python -m grpc_tools.protoc \
     -I./third_party/anchorage/proto \
     --python_out=src/compliance_bridge/anchorage/ \
     --grpc_python_out=src/compliance_bridge/anchorage/ \
     anchorage/vault/v1/vault.proto
   ```

3. **Implement `_create_channel()` and `fetch_balance()`** — the commented-out code in the stub is the complete implementation; uncomment and wire up.

4. **Store mTLS credentials in Secret Manager:**
   ```bash
   gcloud secrets create anchorage-client-cert --data-file=client.pem
   gcloud secrets create anchorage-client-key --data-file=client.key
   ```

5. **Mount via Workload Identity** in the reconciliation-worker K8s deployment.

#### Option B: Plaid Exchange API (faster to implement, lower regulatory weight)

If Anchorage onboarding is too slow for the preprint timeline, implement a `PlaidLedgerProvider` using the Plaid Exchange API. Plaid credentials can be obtained in days (sandbox) vs. weeks (Anchorage enterprise).

**Trade-off:** Plaid is not OCC-chartered. The evidentiary weight is lower than Anchorage. For the preprint, Plaid is sufficient to demonstrate the architecture. For production regulatory use, Anchorage is required.

```python
class PlaidLedgerProvider:
    """Plaid Exchange API provider — faster to integrate than Anchorage.
    
    Suitable for: preprint evaluation, staging, non-OCC-regulated deployments.
    NOT suitable for: US_FED production (requires OCC-chartered custodian).
    """
    def fetch_balance(self, account_id: str) -> ReconciliationResult:
        import plaid
        from plaid.api import plaid_api
        from plaid.model.accounts_balance_get_request import AccountsBalanceGetRequest
        
        configuration = plaid.Configuration(
            host=plaid.Environment.Production,
            api_key={"clientId": os.environ["PLAID_CLIENT_ID"],
                     "secret": os.environ["PLAID_SECRET"]},
        )
        client = plaid_api.PlaidApi(plaid.ApiClient(configuration))
        request = AccountsBalanceGetRequest(access_token=os.environ["PLAID_ACCESS_TOKEN"])
        response = client.accounts_balance_get(request)
        
        # Sum available balances across all accounts
        total = sum(
            a.balances.available or 0.0
            for a in response.accounts
            if a.account_id == account_id or account_id == "all"
        )
        return ReconciliationResult(
            source="plaid",
            balance_usd=total,
            verified_at=time.time(),
            raw_response={"accounts": len(response.accounts)},
        )
```

#### Option C: Interactive Brokers IBKR API (if already integrated)

If the governed financial advisor already has IBKR credentials, the IBKR account balance API can serve as the reconciliation source with minimal new credential management.

**Recommendation for preprint timeline:** Implement Option B (Plaid sandbox) for the evaluation section, note Option A (Anchorage) as the production target, and document the architecture as provider-agnostic via the `LedgerProvider` protocol.

---

### Phase 3 — Reconciliation Daemon K8s Deployment
**Estimated effort:** 2 days  
**Dependency:** Phase 2 provider implemented

#### 3.1 Kubernetes deployment manifest

New file: `deployment/k8s/reconciliation-worker.yaml`

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: reconciliation-worker
  namespace: reconciliation-worker  # isolated namespace
spec:
  replicas: 1  # singleton — only one writer to reconciliation:verified_balance
  selector:
    matchLabels:
      app: reconciliation-worker
  template:
    metadata:
      labels:
        app: reconciliation-worker
    spec:
      serviceAccountName: reconciliation-worker-sa
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: reconciliation-worker
        image: gcr.io/${PROJECT_ID}/reconciliation-worker:${SHORT_SHA}
        command: ["python", "-m", "src.compliance_bridge.reconciliation_worker"]
        env:
        - name: RECONCILIATION_PROVIDER
          value: "anchorage"  # or "plaid"
        - name: RECONCILIATION_POLL_INTERVAL_SECONDS
          value: "60"
        - name: RECONCILIATION_TTL_SECONDS
          value: "300"
        - name: ANCHORAGE_API_ENDPOINT
          valueFrom:
            secretKeyRef:
              name: anchorage-credentials
              key: api_endpoint
        - name: ANCHORAGE_VAULT_ID
          valueFrom:
            secretKeyRef:
              name: anchorage-credentials
              key: vault_id
        - name: REDIS_URL
          valueFrom:
            secretKeyRef:
              name: redis-credentials
              key: url
        - name: KMS_GOVERNANCE_KEY
          valueFrom:
            secretKeyRef:
              name: kms-credentials
              key: governance_key
        resources:
          requests:
            cpu: "100m"
            memory: "128Mi"
          limits:
            cpu: "500m"
            memory: "256Mi"
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop: ["ALL"]
```

#### 3.2 Cilium network policy

New file: `deployment/k8s/reconciliation-cilium-policy.yaml`

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: reconciliation-worker-egress
  namespace: reconciliation-worker
spec:
  endpointSelector:
    matchLabels:
      app: reconciliation-worker
  egress:
  # Allow: external provider API
  - toFQDNs:
    - matchName: "api.anchorage.com"      # Anchorage gRPC
    - matchName: "production.plaid.com"   # Plaid (Option B)
    toPorts:
    - ports:
      - port: "443"
        protocol: TCP
  # Allow: Redis (internal)
  - toEndpoints:
    - matchLabels:
        app: redis
    toPorts:
    - ports:
      - port: "6379"
        protocol: TCP
  # Allow: Cloud KMS (for signing)
  - toFQDNs:
    - matchName: "cloudkms.googleapis.com"
    toPorts:
    - ports:
      - port: "443"
        protocol: TCP
  # DENY ALL: gateway, financial-advisor, compliance-bridge pods
  # (reconciliation worker must not be reachable from or reach governed pods)
```

#### 3.3 Workload Identity binding

```bash
# Create service account
gcloud iam service-accounts create reconciliation-worker-sa \
  --display-name="CAGE Reconciliation Worker"

# Grant KMS signing permission
gcloud kms keys add-iam-policy-binding ${KMS_KEY_NAME} \
  --member="serviceAccount:reconciliation-worker-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/cloudkms.signerVerifier"

# Bind to K8s service account
gcloud iam service-accounts add-iam-policy-binding \
  reconciliation-worker-sa@${PROJECT_ID}.iam.gserviceaccount.com \
  --role="roles/iam.workloadIdentityUser" \
  --member="serviceAccount:${PROJECT_ID}.svc.id.goog[reconciliation-worker/reconciliation-worker-sa]"
```

---

### Phase 4 — Signature Verification in CBF Read Path
**Estimated effort:** 1 day  
**Dependency:** Phase 2 (provider produces KMS-signed balances)

The Phase 1 implementation already includes the signature verification logic. Phase 4 activates it by:

1. Upgrading the Phase 1 startup `logger.critical` to `raise RuntimeError` (now that Phase 2 is deployed)
2. Adding a Lula validation assertion: `reconciliation:verified_balance` must exist and have a valid KMS signature

New Lula assertion in `compliance/lula/`:

```yaml
# compliance/lula/cbf-reconciliation-assertion.yaml
domain:
  type: kubernetes
  kubernetes-spec:
    resources:
    - name: reconciliation-worker-deployment
      resource-rule:
        group: apps
        version: v1
        resource: deployments
        namespaces: [reconciliation-worker]
provider:
  type: opa
  opa-spec:
    rego: |
      package cbf_reconciliation
      
      import future.keywords.if
      
      violation[msg] if {
        input.reconciliation_worker_deployment.spec.replicas < 1
        msg := "Reconciliation worker has zero replicas — CBF ground truth unavailable"
      }
      
      violation[msg] if {
        env := input.reconciliation_worker_deployment.spec.template.spec.containers[0].env
        provider := [e | e := env[_]; e.name == "RECONCILIATION_PROVIDER"][0]
        provider.value == "stub"
        msg := "RECONCILIATION_PROVIDER=stub in production — CBF ground truth is self-reported"
      }
```

---

### Phase 5 — POAM Closure and Preprint Update
**Estimated effort:** 1 day

1. Update [`docs/compliance/us_fed/POAM_US_FED.md`](../compliance/us_fed/POAM_US_FED.md) — mark POAM-023 CLOSED with:
   - Commit SHA of Phase 2 merge
   - Lula validation result
   - Closure date

2. Update [`README.md`](../../README.md) — change POAM-023 status from FUTURE STATE to IMPLEMENTED

3. Update [`docs/technical-report/10-FORMAL-VERIFICATION.md`](../technical-report/10-FORMAL-VERIFICATION.md) — remove the POAM-023 caveat from Step 8 (CBF formal safety invariant)

4. Update the arxiv preprint draft — the CBF section can now state the invariant without the "given a trusted balance oracle" qualification

---

## Summary Timeline

| Phase | Work | Effort | Dependency | Unblocks |
|---|---|---|---|---|
| **1** | CBF read path switch + OTel stamping + startup warning + 6 tests | 2 days | None | Preprint scoping |
| **2A** | Anchorage gRPC implementation | 5 days + 2–6 weeks onboarding | Anchorage API access | Phase 3 |
| **2B** | Plaid implementation (faster alternative) | 2 days | Plaid sandbox credentials | Phase 3 |
| **3** | K8s deployment + Cilium policy + Workload Identity | 2 days | Phase 2 | Phase 4 |
| **4** | Signature verification activation + Lula assertion | 1 day | Phase 3 | POAM-023 closure |
| **5** | POAM closure + README + preprint update | 1 day | Phase 4 | arxiv submission |

**Minimum path to preprint (Phase 1 only):** 2 days. The preprint can accurately describe the architecture and scope the CBF claim as "holds given a trusted balance oracle; external reconciliation is implemented and deployed (Phase 1) with Anchorage integration in progress (POAM-023)."

**Full POAM-023 closure (all phases, Option B provider):** ~8 engineering days + Plaid credential provisioning (days). Target: 2026-08-15.

**Full POAM-023 closure (all phases, Option A provider):** ~12 engineering days + Anchorage onboarding (2–6 weeks). Target: 2026-09-08 (original POAM date).

---

## Key Files

| File | Role | Status |
|---|---|---|
| [`src/compliance_bridge/reconciliation_worker.py`](../../src/compliance_bridge/reconciliation_worker.py) | Daemon + provider interface + Redis writer | ✅ Skeleton complete |
| [`src/gateway/governance/cbf.py`](../../src/gateway/governance/cbf.py) | CBF — needs read path switch | 🔴 Phase 1 |
| [`src/gateway/governance/symbolic_governor.py`](../../src/gateway/governance/symbolic_governor.py) | Startup assertion | 🔴 Phase 1 |
| `tests/test_cbf_reconciliation.py` | 6 new tests | 🔴 Phase 1 |
| `deployment/k8s/reconciliation-worker.yaml` | K8s deployment | 🔴 Phase 3 |
| `deployment/k8s/reconciliation-cilium-policy.yaml` | Network isolation | 🔴 Phase 3 |
| `compliance/lula/cbf-reconciliation-assertion.yaml` | Lula validation | 🔴 Phase 4 |
| [`docs/compliance/us_fed/POAM_US_FED.md`](../compliance/us_fed/POAM_US_FED.md) | POAM closure | 🔴 Phase 5 |

---

*Plan authored 2026-07-25. POAM-023 original target: 2026-09-08.*

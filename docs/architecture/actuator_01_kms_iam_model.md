# actuator_01 — KMS IAM Model and Dual-Operator Security Boundary

**Status:** Architecture Note
**Scope:** `src/integrations/actuator_01/` — quorum signing for execution authorization envelopes
**Raised by:** Luis Fernando Martinez Chavez (security review, Sep 7 2026)

---

## 1. Current Implementation

[`signatures.py`](../../src/integrations/actuator_01/signatures.py) exposes a single
`sign_for_quorum(signer, raw_body)` function that accepts a `KMSGovernanceSigner` instance.
That signer is constructed by
[`KMSGovernanceSigner.from_env()`](../../src/gateway/governance/kms_signer.py#L574), which reads
a **single** environment variable:

```
KMS_GOVERNANCE_KEY=projects/<project>/locations/<loc>/keyRings/<ring>/cryptoKeyVersions/<ver>
```

**Consequence:** every quorum operator in the current reference implementation shares the same
KMS key material, loaded from the same environment variable on the same pod. A compromised pod
therefore holds the signing credential for *all* quorum participants simultaneously —
forged quorum signatures become possible without any additional compromise step.

Luis Fernando's question was precise:

> *"does the CAGE adapter service account have standing IAM `cloudkms.cryptoKeyVersions.useToSign`
> permission to both KMS projects — which would mean compromising one pod = forged quorum?"*

**The answer, as currently coded: yes.** The standing IAM permission is granted to the pod
service account and covers a single key shared across all operator roles. This is the correct
model for a **reference architecture** but must be hardened by adopters before production use.

---

## 2. The Security Boundary Adopters Must Enforce

True multi-operator quorum requires that **no single pod holds all operator signing credentials
simultaneously**. Two implementation patterns close this gap:

### Option A — Per-Operator Workload Identity with Separate Key Rings

Each logical "operator" maps to a distinct Kubernetes workload identity (`ServiceAccount`) and
a distinct GCP KMS key ring:

```
Operator Alice → KSA alice-signer → GCP SA alice@project.iam → KMS ring/key alice-ring/alice-key
Operator Bob   → KSA bob-signer   → GCP SA bob@project.iam   → KMS ring/key bob-ring/bob-key
```

`sign_for_quorum()` is refactored to accept a `signer_factory(operator_id: str) → KMSGovernanceSigner`
callable. Each call resolves credentials bound to a specific operator's Workload Identity
Federation token — no pod holds all signing keys simultaneously unless it can assume all
workload identities simultaneously (a significantly harder bar).

**Trade-off:** Requires multi-keyring IAM configuration and a per-operator signer registry.

### Option B — Per-Ceremony OIDC Downscoping (Recommended)

The pod holds **no standing KMS IAM**. For each quorum ceremony, it exchanges a short-lived
OIDC token for a ceremony-scoped credential via
`iamcredentials.googleapis.com/generateAccessToken` with a TTL aligned to `MAX_TTL_SECONDS = 30s`
(the existing Micro-TTL constant in
[`constants.py`](../../src/integrations/actuator_01/constants.py)):

```python
# Pseudocode — ceremony-scoped credential exchange
ceremony_token = iam_credentials.generate_access_token(
    service_account=operator_sa_for_ceremony(operator_id),
    lifetime=f"{MAX_TTL_SECONDS}s",
    scope=["https://www.googleapis.com/auth/cloudkms"],
)
# Use ceremony_token for exactly one sign_for_quorum() call
# Token is discarded after ceremony — never stored
```

**Rationale for recommending Option B:**
- Aligns with `MAX_TTL_SECONDS = 30` already codified in the wire contract
- Token lifetime = ceremony window; post-ceremony, the credential is worthless
- No standing service account IAM binding — attacker must compromise the token-exchange flow
- Compatible with GKE Workload Identity without per-operator KSA proliferation

---

## 3. CAGE Reference Architecture Position

CAGE is an illustrative reference architecture. The current single-key model is intentional:
it makes the signing path legible and testable without multi-account IAM complexity. The
design seam for per-operator credentials already exists — `sign_for_quorum()` accepts a
`signer` argument rather than calling `get_governance_signer()` internally, which means
callers can supply different signers for different operators without any changes to the core
signing function.

---

## 4. Draft Response to Luis Fernando

> Hi Luis Fernando,
>
> Great question — you've identified the correct gap in the current reference implementation.
>
> **Short answer:** Yes, as currently coded, the pod service account holds a single standing
> `cloudkms.cryptoKeyVersions.useToSign` permission covering one shared KMS key used by all
> quorum operators. Your concern is valid: a compromised pod = forged quorum in the current
> model.
>
> **Why it's this way:** CAGE is a reference architecture. The single-key model makes the
> quorum signing path legible and testable without multi-account IAM complexity. The design
> seam for per-operator keys already exists (`sign_for_quorum()` takes a `signer` argument,
> so callers can supply distinct signers per operator without changing the core function).
>
> **Recommended hardening for adopters:** Option B — per-ceremony OIDC downscoping. The pod
> holds no standing KMS IAM. For each ceremony, it exchanges a short-lived OIDC token for a
> ceremony-scoped access token with a TTL matching `MAX_TTL_SECONDS = 30s`. Post-ceremony,
> the token expires — an attacker must compromise the token-exchange flow, not just the pod.
> This aligns naturally with the Micro-TTL already in the wire contract.
>
> I've written this up in full at `docs/architecture/actuator_01_kms_iam_model.md` in the
> repo. Happy to walk through the IAM binding changes needed for Option B if that's useful.
>
> — Lars

---

## 5. Related Files

| File | Relevance |
|---|---|
| [`src/integrations/actuator_01/signatures.py`](../../src/integrations/actuator_01/signatures.py) | `sign_for_quorum()` — signer injection point |
| [`src/integrations/actuator_01/constants.py`](../../src/integrations/actuator_01/constants.py) | `MAX_TTL_SECONDS = 30`, `NONCE_HEX_LENGTH = 32` |
| [`src/gateway/governance/kms_signer.py`](../../src/gateway/governance/kms_signer.py) | `KMSGovernanceSigner.from_env()` — reads `KMS_GOVERNANCE_KEY` |

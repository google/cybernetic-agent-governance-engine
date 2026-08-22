# Cryptographic Key Management & Rotation Schedule

> **Reference Architecture Note:** Per [`AGENTS.md`](../../AGENTS.md), CAGE is a
> reference architecture demonstrating governance patterns for AI systems. The
> rotation schedules, emergency procedures, and control mappings below provide an
> **illustrative operational model** for adopting institutions configuring their own
> production key lifecycle policies under NIST SP 800-53 Rev. 5 SC-12 and IA-5.

---

## 1. Cryptographic Key Inventory & Lifecycle Matrix

| Key Identifier | Purpose | Algorithm / Format | Storage / Custody | Rotation Cadence | Zero-Downtime Overlap |
|---|---|---|---|---|---|
| **Cloud KMS HSM Governance Key** (`KMS_GOVERNANCE_KEY`) | Asymmetric signing of compliance evidence records and v3 JWT routing seals (`CTRL_KMS_001`) | ECDSA SHA-256 / NIST P-256 (or RSA-PSS 2048) | Google Cloud KMS (HSM Protection Level) | **90 days** | Supported via JWKS multi-key discovery (`GET /v1/jwks`) |
| **Routing Seal HMAC Secret** (`CAGE_ROUTING_SEAL_SECRET`) | Symmetric HMAC token binding for v2 seals and actuator single-use replay defense | HMAC-SHA256 (32+ bytes cryptographic entropy) | Kubernetes Secret / Secret Manager | **30 days** | Grace-period dual-secret verification window (60s) |
| **Linkerd Workload mTLS Certificates** | Mutual TLS authentication across intra-cluster pod communications (`IA-3 / SC-8`) | ECDSA P-256 TLS 1.3 certificates | Ephemeral in-memory (Linkerd / SPIRE) | **24 hours** (Automated) | Automatic mesh proxy rollover |
| **Linkerd Trust Anchor & Issuer CA** | Root and intermediate CA for cluster-wide mesh identity | RSA 4096 / ECDSA P-384 | Secret Manager / cert-manager | **365 days** | Dual-anchor rollover window |
| **Redis Access Secret** (`REDIS_PASSWORD`) | Authentication for Redis evidence stream and state store | High-entropy alphanumeric token | Kubernetes Secret / Secret Manager | **60 days** | Client re-authentication on reconnect |

---

## 2. Rotation Procedures

### 2.1 Cloud KMS HSM Governance Key Rotation (90-Day Cadence)

CAGE uses asymmetric public-key cryptography for evidence non-repudiation. When rotating KMS keys:
1. **Create New Key Version in Cloud KMS:**
   ```bash
   gcloud kms keys versions create \
     --keyring=governance-keyring \
     --location=us-central1 \
     --key=governance-signer \
     --protection-level=hsm
   ```
2. **Publish New Public Key to JWKS:**
   The gateway automatically exposes all active public keys under its `/v1/jwks` endpoint. The new key version is added to the JWKS set while the previous version remains listed for verification of in-flight evidence.
3. **Promote New Key Version for Signing:**
   Update the `KMS_GOVERNANCE_KEY` environment variable in the Terraform variables (`dev.tfvars` / `prod.tfvars`) and trigger deployment via Cloud Build:
   ```bash
   # Update terraform variable:
   # kms_governance_key = "projects/PROJECT_ID/locations/us-central1/keyRings/governance-keyring/cryptoKeys/governance-signer/cryptoKeyVersions/2"
   terraform plan -out=tfplan
   terraform apply tfplan
   ```
4. **Deprecate Old Key Version (After 30-Day Verification Window):**
   Once all in-flight seals and evidence verification windows have elapsed:
   ```bash
   gcloud kms keys versions disable 1 \
     --keyring=governance-keyring \
     --location=us-central1 \
     --key=governance-signer
   ```

---

### 2.2 Routing Seal Secret Rotation (30-Day Cadence)

1. **Generate Cryptographically Secure Secret:**
   ```bash
   NEW_SECRET=$(openssl rand -hex 32)
   ```
2. **Update Kubernetes Secret:**
   ```bash
   kubectl create secret generic cage-routing-seal-secret \
     --namespace=governance-stack \
     --from-literal=routing-seal-secret="${NEW_SECRET}" \
     --dry-run=client -o yaml | kubectl apply -f -
   ```
3. **Rolling Restart of Gateway Pods:**
   ```bash
   kubectl rollout restart deployment/gateway -n governance-stack
   kubectl rollout status deployment/gateway -n governance-stack
   ```
   *Note:* Because routing seals carry a maximum 30-second TTL and atomic single-use nonce consumption, in-flight seals expire within 30 seconds of issuance.

---

### 2.3 Linkerd mTLS Certificate Maintenance

- Workload certificates rotate automatically every 24 hours without operator intervention.
- For annual Trust Anchor / Issuer certificate rotation, follow the standard cert-manager + Linkerd dual-trust-anchor procedure documented in Linkerd operational runbooks.

---

## 3. Emergency Key Revocation & Compromise Runbook

In the event of suspected key compromise:

1. **Immediate Revocation in Cloud KMS:**
   ```bash
   gcloud kms keys versions destroy <COMPROMISED_VERSION> \
     --keyring=governance-keyring \
     --location=us-central1 \
     --key=governance-signer
   ```
2. **Immediate Routing Seal Secret Invalidation:**
   Overwrite `CAGE_ROUTING_SEAL_SECRET` with a freshly generated secret and force an immediate restart of all gateway replicas. All active forged tokens fail verification immediately.
3. **Audit Trail Verification:**
   Query Langfuse / OpenTelemetry traces for evidence receipts signed during the compromise window:
   ```bash
   python scripts/verify_audit_provenance.py --since="<TIMESTAMP>"
   ```
4. **POAM Logging:**
   Record incident details, revoked key version IDs, and remediation timestamps in [`docs/POAM.md`](../POAM.md) under incident controls (IR-6 / SC-12).


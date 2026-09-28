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
| **Linkerd Workload mTLS Certificates** | Mutual TLS authentication across intra-cluster pod communications (`IA-3 / SC-8`); the gateway authenticates callers by this identity (`src/gateway/server/workload_identity.py`, POAM-2026-080) | ECDSA P-256 TLS 1.3 certificates | Ephemeral in-memory (Linkerd) | **24 hours** (Automated) | Automatic mesh proxy rollover |
| **Linkerd Trust Anchor & Issuer CA** | Root and intermediate CA for cluster-wide mesh identity | Root: EC P-256 in Google CAS (HSM-backed key, 10-year lifetime); Issuer: ECDSA, issued via cert-manager CSR | Root key never leaves Google CAS; issuer key generated in-cluster by cert-manager (`infra/modules/service_mesh/main.tf`) — no CA key in Terraform state | Issuer: **48 hours** (cert-manager renews 25h before expiry); Root: manual | Dual-anchor rollover window |
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

### 2.2 Linkerd mTLS Certificate Maintenance

- Workload certificates rotate automatically every 24 hours without operator intervention.
- The Linkerd identity issuer certificate (48h) is renewed automatically by cert-manager through the Google CAS issuer; its key is generated in-cluster and only the CSR goes to CAS (`infra/modules/service_mesh/main.tf`).
- For Trust Anchor (CAS root CA) rotation, follow the standard Linkerd dual-trust-anchor procedure documented in Linkerd operational runbooks.

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
2. **Revoke a Compromised Caller Identity:**
   Remove the workload identity from `CAGE_TRUSTED_CLIENT_IDENTITIES` and from the gateway's mesh `MeshTLSAuthentication`, then restart the gateway replicas. The gateway then refuses that workload with `403` (`src/gateway/server/workload_identity.py`).
3. **Audit Trail Verification:**
   Query Langfuse / OpenTelemetry traces for evidence receipts signed during the compromise window:
   ```bash
   python scripts/verify_audit_provenance.py --since="<TIMESTAMP>"
   ```
4. **POAM Logging:**
   Record incident details, revoked key version IDs, and remediation timestamps in [`docs/POAM.md`](../POAM.md) under incident controls (IR-6 / SC-12).


# CAGE → Archytan: mTLS Identity Materials for Connectivity Proof Run

**Date:** 2026-09-14  
**Thread:** actuator_01 integration — wire protocol complete, ready for live connectivity  
**Status:** Identity materials generated and ready for registration

---

Hi Luis,

Wire protocol work is complete — both bugs fixed, all tests passing, SignerResolver seam implemented. Ready to move to connectivity proof run.

Attached are the mTLS identity materials needed for Archytan's trust store and ingress allowlist registration.

---

## 1. Root CA Certificate (for Archytan Trust Store)

**File:** `ca.crt` (attached)
**Format:** PEM-encoded X.509
**Key Size:** 4096-bit RSA
**Validity:** 10 years (Sep 14 2026 - Sep 11 2036)

**Certificate Subject:**
```
C=US, ST=California, L=Mountain View,
O=CAGE Reference Architecture,
OU=Governance Integrations,
CN=CAGE actuator_01 Root CA
```

**Action:** Add the attached `ca.crt` file to Archytan's mTLS trust store for client certificate verification.

---

## 2. Client Identity Strings (for Ingress Allowlist)

CAGE will present this identity during TLS handshake:

| Field | Value |
|---|---|
| **Primary DNS SAN** (recommended) | `cage.governance.example.com` |
| **Secondary DNS SAN** | `cage-actuator01.governance.example.com` |
| **Subject CN** (fallback) | `CAGE Governance Engine - actuator_01 Client` |

**Recommendation:** Use the **Primary SAN** (`cage.governance.example.com`) for allowlist registration.

---

## 3. Information Needed from Archytan

Once registration is complete and sandbox is provisioned, please provide:

1. **Sandbox endpoint URL** (for `ACTUATOR_01_ENDPOINT` configuration)
   - Example: `https://sandbox.archytan.example.com`

2. **Tenant ID** (value for `X-Secure-Tenant-ID` header)
   - CAGE will configure as `ACTUATOR_01_TENANT_ID`

3. **Server CA certificate** *(if applicable)*
   - Only needed if Archytan sandbox uses self-signed or private CA
   - If using Let's Encrypt or publicly-trusted CA, not needed

4. **Preferred testing window**
   - Propose 1-2 hour ephemeral sandbox window
   - CAGE can accommodate:
     - **Wednesday Sep 16, 14:00-15:00 UTC**
     - **Thursday Sep 17, 09:00-10:00 UTC**
     - **Friday Sep 18, 15:00-16:00 UTC**
   - Or any alternative that fits your operational constraints

---

## 4. Test Envelope Characteristics

During the proof run, CAGE will submit:

- **Quorum:** 2 distinct operator URNs
- **Envelope size:** ~800 bytes (well under 4KB)
- **Domain tags:** `ARCHYTAN_ASSERTION_V1:`, `ARCHYTAN_QUORUM_V1:`
- **Header:** `X-Archytan-Signatures` with 2 distinct Ed25519 signatures
- **Assertion:** 120-byte execution assertion
- **Expected response:** 200 OK with `ACCEPTED` status

---

## 5. Two-Track Split (recap)

### Track 1: Wire Protocol Connectivity (blocking, ready now)
- ✅ mTLS identity materials generated (this message)
- ⏳ Archytan registers identity + provisions sandbox
- ⏳ CAGE configures endpoint and fires test envelope
- ⏳ Both sides validate handshake + receipt round-trip

### Track 2: IAM Hardening Walkthrough (non-blocking, deferred)
- Per-ceremony OIDC token exchange (Option B from [`CRYPTOGRAPHIC_SIGNER_ENGINE.md`](../architecture/CRYPTOGRAPHIC_SIGNER_ENGINE.md))
- Scheduled after connectivity proof succeeds
- Multi-operator key independence remains **OPEN** until then

---

## 6. Next Steps

1. **CAGE (immediate):** This message + attached `ca.crt` sent to Luis
2. **Archytan (on your timeline):** Register identity → provision sandbox → provide endpoint/tenant-id
3. **Coordination:** Confirm testing window
4. **Execution:** CAGE submits envelope during window → both sides triage results

---

Let me know which testing window works best, or propose an alternative. Ready to proceed once identity registration is complete.

Best,  
Lars

---

**Attachments:**
- **`ca.crt`** — Root CA certificate (PEM format, 2.2KB) — Add to Archytan's trust store
- Reference: Full certificate details in [`deployment/certs/actuator_01/README.md`](../../deployment/certs/actuator_01/README.md)

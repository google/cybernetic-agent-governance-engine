# CAGE mTLS Identity Registration for Archytan Integration

**Date:** 2026-09-14  
**Purpose:** mTLS client authentication materials for actuator_01 connectivity proof run  
**Recipient:** Luis Fernando Martinez Chavez (Archytan)

---

## 1. Root CA Certificate

**File:** `ca.crt` (attached or inline below)  
**Format:** PEM-encoded X.509 certificate  
**Action Required:** Add this certificate to Archytan's trust store for client certificate verification.

### Certificate Details
```
Subject: C=US, ST=California, L=Mountain View, O=CAGE Reference Architecture, 
         OU=Governance Integrations, CN=CAGE actuator_01 Root CA
Validity: 10 years (Sep 14 2026 - Sep 11 2036)
Key Size: 4096-bit RSA
Self-Signed: Yes (root CA)
```

### PEM Content
```
-----BEGIN CERTIFICATE-----
(See attached ca.crt file)
-----END CERTIFICATE-----
```

**Note:** The full PEM content is in the attached `ca.crt` file. Archytan should import this into their mTLS termination layer's trust store.

---

## 2. Client Identity for Allowlist Registration

CAGE will present the following identity during TLS handshake:

### Primary Identifier (Recommended for Allowlist)
**DNS Subject Alternative Name (SAN):**
```
cage.governance.example.com
```

### Alternative Identifiers (if SAN-based matching is unavailable)
**Subject Common Name (CN):**
```
CAGE Governance Engine - actuator_01 Client
```

**Secondary DNS SAN:**
```
cage-actuator01.governance.example.com
```

**Recommendation:** Use the **Primary SAN** (`cage.governance.example.com`) as the canonical client identity for ingress allowlist rules.

---

## 3. Client Certificate Details

For reference (Archytan does **not** need this file, only the CA above):

```
Subject: C=US, ST=California, L=Mountain View, O=CAGE Reference Architecture,
         OU=Governance Engine, CN=CAGE Governance Engine - actuator_01 Client
Issuer: CAGE actuator_01 Root CA
Validity: 2 years (Sep 14 2026 - Sep 13 2028)
Key Size: 4096-bit RSA
Subject Alternative Names:
  - DNS: cage.governance.example.com
  - DNS: cage-actuator01.governance.example.com
```

---

## 4. Information Needed from Archytan

Once identity registration is complete and the sandbox is provisioned, please provide:

1. **Sandbox Endpoint URL**
   - Example: `https://sandbox.archytan.example.com`
   - CAGE will configure this as `ACTUATOR_01_ENDPOINT`

2. **Tenant ID**
   - Value for the `X-Secure-Tenant-ID` header
   - CAGE will configure this as `ACTUATOR_01_TENANT_ID`

3. **Server CA Certificate** *(if applicable)*
   - If Archytan's sandbox uses a self-signed or private CA (not publicly-trusted)
   - CAGE needs this to verify Archytan's server certificate during TLS handshake
   - If using Let's Encrypt or another publicly-trusted CA, this is not needed

4. **Preferred Testing Window**
   - Proposed 1-2 hour window for the connectivity proof run

---

## 5. Wire Protocol Readiness Checklist

All wire protocol elements are implemented and tested:

- ✅ Domain tags: `ARCHYTAN_ASSERTION_V1:`, `ARCHYTAN_QUORUM_V1:`
- ✅ Header name: `X-Archytan-Signatures`
- ✅ Distinct-URN guard: ≥2 unique operator URNs enforced
- ✅ Quorum signing loop: Per-operator signature generation
- ✅ mTLS client configuration: TLS 1.3 only, mutual authentication
- ✅ 4KB envelope ceiling enforcement
- ✅ RFC 8785 (JCS) canonical serialization

---

## 6. Test Envelope Characteristics

During the proof run, CAGE will submit:

- **Action:** Synthetic governance action (non-production)
- **Quorum:** 2 distinct operator URNs
- **Envelope size:** < 1KB (well under 4KB limit)
- **Signatures:** 2 distinct Ed25519 signatures (one per operator)
- **Assertion:** 120-byte execution assertion signed by CAGE issuer key
- **Nonce:** Unique replay-protection nonce
- **Timestamp:** ISO 8601 UTC timestamp

Expected success path:
```
CAGE → mTLS handshake → envelope submission → 200 OK → ACCEPTED receipt
```

---

## 7. Contact Information

**CAGE Technical Contact:** Lars Ahlfors  
**Integration Package:** `src/integrations/actuator_01/`  
**Wire Protocol Documentation:** `src/integrations/actuator_01/README.md`

---

## Files Included

1. `ca.crt` — Root CA certificate (PEM format) — **Send to Archytan**
2. This document — Identity registration details

**Note:** Private keys (`ca.key`, `client.key`) are **not** included and must remain confidential on CAGE's side.

# actuator_01 mTLS Certificate Materials

**Purpose:** Client authentication certificates for Archytan integration.

**Generated:** 2026-09-14  
**Status:** Reference implementation materials

---

## Files

| File | Purpose | Sensitivity | Share with Archytan? |
|---|---|---|---|
| `ca.crt` | Root CA certificate | Public | ✅ **YES** — Send to Archytan for trust store |
| `ca.key` | Root CA private key | **SECRET** | ❌ **NO** — Keep private |
| `client.crt` | Client certificate | Public | Optional (Archytan doesn't need this) |
| `client.key` | Client private key | **SECRET** | ❌ **NO** — Keep private |

---

## Identity Registration Details for Archytan

When registering CAGE's mTLS identity with Archytan, provide:

### 1. Root CA Certificate
**File:** `ca.crt`  
**Format:** PEM-encoded X.509 certificate  
**Purpose:** Archytan adds this to their trust store to verify CAGE's client certificate during TLS handshake.

### 2. Client Identity String
Archytan's mTLS termination layer needs to allowlist one or both of:

- **Subject Common Name (CN):** `CAGE Governance Engine - actuator_01 Client`
- **Primary DNS Subject Alternative Name (SAN):** `cage.governance.example.com`
- **Secondary DNS SAN:** `cage-actuator01.governance.example.com`

**Recommendation:** Provide the **primary SAN** (`cage.governance.example.com`) as the canonical client identity.

---

## CAGE Environment Configuration

Once Archytan provides their sandbox endpoint, configure:

```bash
export ACTUATOR_01_ENDPOINT="https://<archytan-sandbox-url>"
export ACTUATOR_01_TENANT_ID="<provided-tenant-id>"
export ACTUATOR_01_CERT_PATH="$(pwd)/deployment/certs/actuator_01/client.crt"
export ACTUATOR_01_KEY_PATH="$(pwd)/deployment/certs/actuator_01/client.key"
export ACTUATOR_01_CA_PATH="<path-to-archytan-server-ca.crt>"
```

**Note:** `ACTUATOR_01_CA_PATH` points to **Archytan's server CA certificate** (for verifying their server during TLS handshake), not CAGE's `ca.crt`. If Archytan uses a publicly-trusted CA (e.g., Let's Encrypt), you may be able to omit this and rely on system trust stores.

---

## Certificate Details

### Root CA Certificate
```
Subject: C=US, ST=California, L=Mountain View, O=CAGE Reference Architecture, OU=Governance Integrations, CN=CAGE actuator_01 Root CA
Validity: 10 years (2026-09-14 to 2036-09-12)
Key Size: 4096-bit RSA
```

### Client Certificate
```
Subject: C=US, ST=California, L=Mountain View, O=CAGE Reference Architecture, OU=Governance Engine, CN=CAGE Governance Engine - actuator_01 Client
Issuer: CAGE actuator_01 Root CA
Validity: 2 years (2026-09-14 to 2028-09-13)
Key Size: 4096-bit RSA
SAN: DNS:cage.governance.example.com, DNS:cage-actuator01.governance.example.com
```

---

## Regeneration

If certificates expire or rotation is needed:

```bash
cd deployment/certs/actuator_01
./generate_certs.sh
```

This will **overwrite** existing certificates. Back up current materials if needed before regenerating.

---

## Security Notes

1. **Private keys (`*.key`) are gitignored** and must never be committed to version control.
2. This is a **reference implementation**. Production deployments should:
   - Use hardware security modules (HSMs) or cloud KMS for private key storage
   - Implement certificate rotation policies
   - Use organizationally-appropriate Subject DN fields
   - Consider shorter validity periods (e.g., 90 days for client certs)
3. The example domain `cage.governance.example.com` is illustrative. Adopters should use their actual domain.

---

## What to Send to Luis (Archytan)

Create a message with:

1. **Attached file:** `ca.crt` (the Root CA certificate)
2. **Body text:**
   ```
   Archytan mTLS Identity Registration
   
   Root CA Certificate: Attached (ca.crt)
   
   Client Identity for Allowlist:
   - Primary SAN: cage.governance.example.com
   - Subject CN: CAGE Governance Engine - actuator_01 Client
   
   Please register this identity in your sandbox environment and provide:
   1. Sandbox endpoint URL (for ACTUATOR_01_ENDPOINT)
   2. Tenant ID (for X-Secure-Tenant-ID header)
   3. Server CA certificate (if not using a publicly-trusted CA)
   ```

---

## Reference

- Wire protocol spec: [`src/integrations/actuator_01/README.md`](../../../src/integrations/actuator_01/README.md)
- Configuration variables: [`src/integrations/actuator_01/adapter.py`](../../../src/integrations/actuator_01/adapter.py) lines 148-152

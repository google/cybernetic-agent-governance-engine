# Security FAQ: Certificate Distribution

## Is it safe to send certificates in cleartext?

**Yes.** Public certificates (`.crt` files) contain no secret information and are designed to be distributed openly.

---

## What's Safe to Share vs. What Must Stay Private

| File | Contains | Safe to send? | Transmission method |
|---|---|---|---|
| `ca.crt` | Public CA certificate | ✅ **YES** | Email, Slack, GitHub, HTTP, etc. |
| `client.crt` | Public client certificate | ✅ **YES** | Email, Slack, GitHub, HTTP, etc. |
| `ca.key` | Private CA key | ❌ **NO** | NEVER send or share |
| `client.key` | Private client key | ❌ **NO** | NEVER send or share |

---

## Why Certificates Are Public Information

### What's in a certificate (public data):
- Subject Distinguished Name (CN, O, OU, etc.)
- Issuer Distinguished Name
- Public key (the partner needs this to verify signatures)
- Validity period (notBefore, notAfter)
- Subject Alternative Names (DNS SANs)
- Serial number
- Signature algorithm

**None of this is secret.** Certificates are specifically designed to be shared widely.

### What's NOT in a certificate:
- ❌ Private keys
- ❌ Passwords or credentials
- ❌ Any secret information

---

## How Public Key Infrastructure (PKI) Works

1. **You keep the private key secret** (`client.key`, `ca.key`)
   - Never leave the system where it was generated
   - Never sent over email, Slack, or any network
   - Protected with file permissions (600)

2. **You share the certificate freely** (`client.crt`, `ca.crt`)
   - Contains your public key
   - Partner uses it to verify your signatures
   - Anyone can read it without security risk

3. **Authentication proof:**
   - You prove you own the private key by signing challenges during TLS handshake
   - Partner verifies those signatures using your public certificate
   - Private key never leaves your system

---

## Real-World Examples

**Certificates are public by design:**
- Every HTTPS website's certificate is sent in cleartext during TLS handshake
- Certificate Transparency logs publish all issued certificates publicly
- `openssl s_client -connect google.com:443` downloads Google's cert in cleartext
- GitHub commits certificates directly to public repositories

**The security model relies on:**
- Private keys staying private (never transmitted)
- Certificates being authentic (signed by trusted CA)
- TLS handshake proving possession of private key without revealing it

---

## What We're Sending to Luis (Archytan)

### ✅ Safe to send:
- `ca.crt` — Our Root CA public certificate
- Client SAN strings (`cage.governance.example.com`)
- Client CN (`CAGE Governance Engine - actuator_01 Client`)

### ❌ Never sending:
- `ca.key` — Our Root CA private key (stays on CAGE systems)
- `client.key` — Our client private key (stays on CAGE systems)

---

## Summary

**Certificates = Public information. Safe to email, post on GitHub, send via Slack, etc.**

**Private keys = Secret. Never transmit. Never share. Never commit to version control.**

The `.gitignore` file protects private keys from accidental commits. The message to Luis contains only public certificates, which is standard practice and completely secure.

---

## References

- [RFC 5280 - Internet X.509 Public Key Infrastructure](https://datatracker.ietf.org/doc/html/rfc5280)
- [Certificate Transparency](https://certificate.transparency.dev/) — All issued certs are published
- [How TLS Works](https://tls.ulfheim.net/) — Interactive demo showing certificates transmitted in cleartext

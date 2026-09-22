# AGENT_IDENTITY_BINDING_SPEC.md

**Version:** 1.0.0  
**Status:** CANONICAL  
**Last Updated:** 2026-09-22  
**Applies To:** CAGE Gateway v3.0+

---

## Executive Summary

This specification defines the cryptographic binding mechanism between agent identities and governance decisions in the Cybernetic Agentic Governance Engine (CAGE). It establishes SPIFFE Verifiable Identity Documents (SVIDs) extracted from mTLS transport layer certificates as the canonical source of truth for agent authentication, eliminating reliance on spoofable HTTP headers and request bodies.

**Core Principle:** *"Secure the consequence, not the identity."* Authentication happens at the transport layer; authorization happens at the governance gate.

---

## §1 Architectural Role & Security Boundaries

### 1.1 Threat Model & Anti-Patterns

**Vulnerability:** Relying on unauthenticated HTTP request metadata (`X-Agent-ID`, `X-SPIFFE-ID` headers, or JSON body fields) for identity assertion creates a trivial spoofing attack surface. Any client capable of crafting HTTP requests can forge identity claims.

**Deprecated Patterns:**
```python
# ❌ FORBIDDEN: Header-based identity extraction
agent_id = request.headers.get("X-Agent-ID")  # Spoofable
spiffe_id = request.headers.get("X-SPIFFE-ID")  # Unauthenticated

# ❌ FORBIDDEN: Body-based identity assertion
agent_id = request.json.get("agent_id")  # Client-controlled
```

**Canonical Pattern:**
```python
# ✅ REQUIRED: Extract SVID from verified TLS peer certificate
from cryptography.x509 import (
    load_der_x509_certificate,
    SubjectAlternativeName,
    UniformResourceIdentifier,
)
from cryptography.hazmat.backends import default_backend


def extract_spiffe_id_from_mtls(tls_peer_cert_der: bytes) -> str:
    """
    Extract SPIFFE ID from the verified TLS client certificate's Subject Alternative Name.

    Args:
        tls_peer_cert_der: DER-encoded X.509 certificate from the TLS handshake peer

    Returns:
        SPIFFE ID URI (e.g., 'spiffe://cage.altostrat.com/agents/finance/trading-bot-abc123')

    Raises:
        ValueError: If certificate lacks SPIFFE SAN or is malformed
    """
    cert = load_der_x509_certificate(tls_peer_cert_der, default_backend())

    try:
        san_ext = cert.extensions.get_extension_for_oid(SubjectAlternativeName.oid)
        for san in san_ext.value:
            if isinstance(san, UniformResourceIdentifier):
                uri = san.value
                if uri.startswith("spiffe://"):
                    return uri
    except Exception as e:
        raise ValueError(f"Certificate lacks valid SPIFFE SAN: {e}")

    raise ValueError("No SPIFFE URI found in certificate SANs")
```

### 1.2 Layer 1 Integration Point

The extraction occurs at the **outermost gateway middleware** ([`src/gateway/middleware/mtls_extractor.py`](src/gateway/middleware/mtls_extractor.py)), upstream of all governance decision logic:

```python
# Middleware pseudocode (FastAPI/Starlette)
async def mtls_identity_middleware(request: Request, call_next):
    # Extract DER cert from request.scope["transport"]["peercert"]
    peer_cert_der = request.scope.get("transport", {}).get("peercert")
    
    if not peer_cert_der:
        raise Unauthorized("mTLS client certificate required")
    
    spiffe_id = extract_spiffe_id_from_mtls(peer_cert_der)
    
    # Inject into request state for downstream consumption
    request.state.verified_spiffe_id = spiffe_id
    request.state.tls_peer_cert = peer_cert_der
    
    return await call_next(request)
```

**Security Boundary:**
- **Trust Anchor:** Service mesh mTLS termination proxy (Envoy, Istio, Linkerd) validates certificate chains against the SPIFFE trust bundle before forwarding to the gateway.
- **Zero Trust Assumption:** CAGE Layer 1 code MUST NOT accept identity claims from application-layer protocols. The TLS layer is the sole source of truth.

---

## §2 Double-Binding Mechanism (mTLS + DPoP)

### 2.1 Rationale: Defense Against Token Exfiltration

Even with mTLS authentication, bearer tokens (JWT access tokens, API keys) can be exfiltrated via compromised logs, stolen memory dumps, or server-side request forgery (SSRF). **Demonstrating Proof-of-Possession (DPoP)** cryptographically binds tokens to the specific TLS client certificate, rendering stolen tokens unusable without the corresponding private key.

### 2.2 DPoP Token Structure (RFC 9449)

A DPoP proof is a signed JWT containing:
- `jkt` (JSON Key Thumbprint): SHA-256 hash of the TLS client certificate's public key
- `htm` (HTTP Method): The method of the request (`POST`, `GET`, etc.)
- `htu` (HTTP URI): The target endpoint URI
- `iat` (Issued At): Timestamp (prevents replay)
- `nonce` (optional): Server-provided challenge for freshness

**Example DPoP JWT Header & Payload:**
```json
// Header
{
  "alg": "ES256",
  "typ": "dpop+jwt",
  "jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "...",
    "y": "..."
  }
}

// Payload
{
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "htm": "POST",
  "htu": "https://gateway.cage.altostrat.com/v1/evaluate",
  "iat": 1726939200,
  "jkt": "fZI9TRd8LNX7p6M3yD0WYvgKa2klGvNM8xJ1NqQw8Zs"  // SHA-256 hash of TLS cert pubkey
}
```

### 2.3 Pure Python Implementation (No Proprietary SDKs)

```python
import hashlib
import json
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.backends import default_backend
import jwt  # PyJWT library


def compute_certificate_thumbprint(cert_der: bytes) -> str:
    """
    Compute SHA-256 thumbprint (jkt) of the certificate's public key.

    Returns:
        Base64url-encoded SHA-256 hash of the DER-encoded public key
    """
    cert = load_der_x509_certificate(cert_der, default_backend())
    public_key_der = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    digest = hashlib.sha256(public_key_der).digest()
    # Base64url encoding (RFC 4648 §5)
    return jwt.utils.base64url_encode(digest).decode("utf-8")


def create_dpop_proof(
    signing_key: ec.EllipticCurvePrivateKey,
    http_method: str,
    http_uri: str,
    tls_cert_der: bytes,
    nonce: str | None = None,
) -> str:
    """
    Generate a DPoP proof JWT bound to the TLS client certificate.

    Args:
        signing_key: EC private key corresponding to the TLS certificate
        http_method: HTTP method (e.g., "POST")
        http_uri: Target URI (e.g., "https://gateway.cage.altostrat.com/v1/evaluate")
        tls_cert_der: DER-encoded TLS client certificate
        nonce: Optional server-provided nonce

    Returns:
        Signed DPoP JWT string
    """
    jkt = compute_certificate_thumbprint(tls_cert_der)

    # Extract public key for JWK representation
    public_key = signing_key.public_key()
    public_numbers = public_key.public_numbers()

    # Convert coordinates to base64url
    x_bytes = public_numbers.x.to_bytes(32, byteorder="big")
    y_bytes = public_numbers.y.to_bytes(32, byteorder="big")

    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": jwt.utils.base64url_encode(x_bytes).decode("utf-8"),
        "y": jwt.utils.base64url_encode(y_bytes).decode("utf-8"),
    }

    headers = {"alg": "ES256", "typ": "dpop+jwt", "jwk": jwk}

    payload = {
        "jti": str(uuid.uuid4()),
        "htm": http_method,
        "htu": http_uri,
        "iat": int(time.time()),
        "jkt": jkt,
    }

    if nonce:
        payload["nonce"] = nonce

    return jwt.encode(payload, signing_key, algorithm="ES256", headers=headers)


def verify_dpop_binding(
    dpop_jwt: str, tls_cert_der: bytes, http_method: str, http_uri: str
) -> bool:
    """
    Verify that the DPoP proof is bound to the presented TLS certificate.

    Args:
        dpop_jwt: DPoP proof JWT from the 'DPoP' HTTP header
        tls_cert_der: DER-encoded TLS peer certificate from the connection
        http_method: Expected HTTP method
        http_uri: Expected HTTP URI

    Returns:
        True if binding is valid

    Raises:
        ValueError: If binding verification fails
    """
    # Decode without verification to extract JWK
    unverified_header = jwt.get_unverified_header(dpop_jwt)
    jwk = unverified_header.get("jwk")

    if not jwk:
        raise ValueError("DPoP JWT missing 'jwk' header")

    # Reconstruct public key from JWK
    x = int.from_bytes(jwt.utils.base64url_decode(jwk["x"]), byteorder="big")
    y = int.from_bytes(jwt.utils.base64url_decode(jwk["y"]), byteorder="big")

    public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
    public_key = public_numbers.public_key(default_backend())

    # Verify JWT signature
    payload = jwt.decode(dpop_jwt, public_key, algorithms=["ES256"])

    # Verify thumbprint binding
    expected_jkt = compute_certificate_thumbprint(tls_cert_der)
    if payload.get("jkt") != expected_jkt:
        raise ValueError(
            f"DPoP thumbprint mismatch: expected {expected_jkt}, got {payload.get('jkt')}"
        )

    # Verify HTTP method/URI binding
    if payload.get("htm") != http_method:
        raise ValueError(
            f"DPoP method mismatch: expected {http_method}, got {payload.get('htm')}"
        )

    if payload.get("htu") != http_uri:
        raise ValueError(
            f"DPoP URI mismatch: expected {http_uri}, got {payload.get('htu')}"
        )

    # Verify freshness (allow 60 second clock skew)
    iat = payload.get("iat")
    if not iat or abs(time.time() - iat) > 60:
        raise ValueError("DPoP proof expired or clock skew exceeds tolerance")

    return True
```

### 2.4 Gateway Integration

The DPoP proof is presented in the `DPoP` HTTP header:

```http
POST /v1/evaluate HTTP/1.1
Host: gateway.cage.altostrat.com
DPoP: eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6...
Content-Type: application/json
```

Gateway middleware validates the binding before routing to governance logic:

```python
async def dpop_validation_middleware(request: Request, call_next):
    dpop_header = request.headers.get("DPoP")

    if not dpop_header:
        raise Unauthorized("DPoP proof required")

    tls_cert_der = request.state.tls_peer_cert

    try:
        verify_dpop_binding(
            dpop_jwt=dpop_header,
            tls_cert_der=tls_cert_der,
            http_method=request.method,
            http_uri=str(request.url),
        )
    except ValueError as e:
        raise Forbidden(f"DPoP validation failed: {e}")

    return await call_next(request)
```

---

## §3 Handling Ephemerality & Prefix Matching

### 3.1 Problem Statement: Static UUIDs vs. Ephemeral Workloads

In Kubernetes/serverless environments, agent pods are continuously recreated with new SPIFFE IDs:
```
spiffe://cage.altostrat.com/agents/finance/trading-bot-abc123  # Pod 1 (terminated)
spiffe://cage.altostrat.com/agents/finance/trading-bot-xyz789  # Pod 2 (replacement)
```

Writing policies against exact UUIDs causes `POLICY_DRIFT_VIOLATION` errors whenever pods restart. The namespace prefix (`/agents/finance/`) represents the **logical agent role**, while the suffix represents the ephemeral instance.

### 3.2 OPA Rego Input Contract

The gateway constructs the OPA policy evaluation input as:

```json
{
  "input": {
    "agent_id": "spiffe://cage.altostrat.com/agents/finance/trading-bot-xyz789",
    "agent_namespace": "finance",
    "action": "ftra.market.place_order",
    "consequence": {
      "target_entity": "spiffe://nasdaq.external.com/trading/equities",
      "amount": 1000000,
      "asset": "AAPL"
    },
    "timestamp": "2026-09-22T17:33:35.411Z"
  }
}
```

### 3.3 Namespace Wildcard Matching in OPA Rego

Policies evaluate against the **namespace prefix** rather than the full SPIFFE ID:

```rego
package cage.finance.ftra

import future.keywords.if
import future.keywords.in

# Extract namespace from SPIFFE ID
agent_namespace := ns if {
    parts := split(input.agent_id, "/")
    # spiffe://cage.altostrat.com/agents/<namespace>/<instance-id>
    #   [0]      [1]                 [2]     [3]        [4]
    count(parts) >= 5
    parts[2] == "agents"
    ns := parts[3]
}

# Allow trading actions for any agent in the 'finance' namespace
allow if {
    agent_namespace == "finance"
    startswith(input.action, "ftra.market.")
    input.consequence.amount <= 10000000  # $10M limit
}

# Deny if outside authorized namespace
deny[msg] if {
    not agent_namespace == "finance"
    startswith(input.action, "ftra.market.")
    msg := sprintf("SPIFFE namespace '%s' not authorized for FTRA actions", [agent_namespace])
}
```

### 3.4 Preventing POLICY_DRIFT_VIOLATION

The [`ControlRegistry`](src/gateway/governance/control_registry.py) computes a deterministic hash of active policies to detect drift. Ephemeral instance IDs must **not** appear in policy bodies to prevent spurious drift alerts:

```python
# ❌ DRIFT-INDUCING: Exact SPIFFE ID in policy
allow if {
    input.agent_id == "spiffe://cage.altostrat.com/agents/finance/trading-bot-abc123"
}

# ✅ DRIFT-RESISTANT: Namespace prefix matching
allow if {
    startswith(input.agent_id, "spiffe://cage.altostrat.com/agents/finance/")
}
```

**Namespace Schema Convention:**
```
spiffe://<trust-domain>/agents/<domain>/<role>-<ephemeral-suffix>

Examples:
  spiffe://cage.altostrat.com/agents/finance/advisor-7f3a9b2c
  spiffe://cage.altostrat.com/agents/healthcare/hipaa-auditor-1a4c8d3e
  spiffe://cage.altostrat.com/agents/security/penetration-tester-9e2b5f1a
```

### 3.5 Policy Registration with Namespace Wildcards

When registering controls in the [`ControlRegistry`](src/gateway/governance/control_registry.py), use namespace patterns:

```python
from src.gateway.governance.control_registry import ControlRegistry

registry = ControlRegistry()

# Register FTRA control for the 'finance' namespace
registry.register_control(
    control_id="FTRA-001",
    policy_path="policies/ftra/market_access.rego",
    authorized_agent_pattern="spiffe://cage.altostrat.com/agents/finance/*",
    tier=GovernanceTier.TIER_3,
)
```

The registry compiles these patterns into OPA policy fragments automatically.

---

## §4 Declarative Agent-to-Agent (A2A) Authorization

### 4.1 Use Case: Parent Agents Delegating to Subagents

Multi-agent workflows require parent agents to spawn subagents for specialized tasks (e.g., a financial advisor delegating market analysis to a quantitative research subagent). The parent's SPIFFE ID establishes the **trust anchor** for the delegation.

### 4.2 Delegation Schema

Subagent SPIFFE IDs encode the parent relationship:
```
spiffe://cage.altostrat.com/agents/<domain>/<parent-role>/<subagent-role>-<suffix>

Example:
  Parent:   spiffe://cage.altostrat.com/agents/finance/advisor-7f3a9b2c
  Subagent: spiffe://cage.altostrat.com/agents/finance/advisor-7f3a9b2c/quant-researcher-4d2e1a9b
```

### 4.3 OPA Policy for A2A Authorization

```rego
package cage.finance.delegation

import future.keywords.if

# Extract parent SPIFFE ID from subagent ID
parent_spiffe_id(subagent_id) := parent if {
    parts := split(subagent_id, "/")
    count(parts) >= 6
    # Reconstruct parent: spiffe://<domain>/agents/<namespace>/<parent>
    parent := concat("/", array.slice(parts, 0, 5))
}

# Allow subagent action if parent is authorized
allow if {
    parent_id := parent_spiffe_id(input.agent_id)
    
    # Verify parent exists in authorized set
    parent_id in data.authorized_parents
    
    # Verify action is within delegated scope
    input.action in data.delegated_actions[parent_id]
}

# Deny direct subagent invocation without parent context
deny[msg] if {
    contains(input.agent_id, "/agents/finance/advisor-")
    contains(input.agent_id, "/quant-researcher-")
    not parent_spiffe_id(input.agent_id)
    msg := "Subagent invoked without parent authorization context"
}
```

### 4.4 Runtime Delegation Assertion

Parent agents inject delegation metadata into subagent invocations:

```python
from src.gateway.governance.governance_envelope import GovernanceEnvelopeBuilder

# Parent agent initiates subagent call
envelope = GovernanceEnvelopeBuilder.build(
    agent_id=request.state.verified_spiffe_id,  # Parent's SPIFFE ID
    action="ftra.market.analyze_volatility",
    consequence={"target_market": "NASDAQ", "timeframe": "30d"},
    delegation={
        "subagent_spiffe": "spiffe://cage.altostrat.com/agents/finance/advisor-7f3a9b2c/quant-researcher-4d2e1a9b",
        "delegated_actions": [
            "ftra.analytics.fetch_timeseries",
            "ftra.analytics.compute_volatility",
        ],
        "ttl_seconds": 300,
    },
)
```

The gateway validates that:
1. The **caller's TLS certificate** matches the parent SPIFFE ID.
2. The subagent SPIFFE ID is properly prefixed with the parent's path.
3. The requested action is within the `delegated_actions` allowlist.
4. The delegation has not exceeded its TTL.

### 4.5 Preventing Privilege Escalation

**Invariant:** Subagents MUST NOT have broader privileges than their parent.

```rego
# Subagent action scope must be a subset of parent scope
deny[msg] if {
    parent_id := parent_spiffe_id(input.agent_id)
    parent_tier := data.agent_tiers[parent_id]
    subagent_tier := data.agent_tiers[input.agent_id]
    
    # Numeric tier comparison (Tier 1 > Tier 2 > Tier 3 > Tier 4)
    subagent_tier < parent_tier
    
    msg := sprintf("Subagent tier %d exceeds parent tier %d", [subagent_tier, parent_tier])
}
```

---

## §5 Implementation Roadmap

### Phase 1: Transport-Layer Identity Extraction (Immediate)
- [ ] Implement [`mtls_extractor.py`](src/gateway/middleware/mtls_extractor.py) middleware
- [ ] Remove all `X-Agent-ID` / `X-SPIFFE-ID` header parsing code
- [ ] Update [`governance_envelope.py`](src/gateway/governance/governance_envelope.py) to consume `request.state.verified_spiffe_id`
- [ ] Add integration tests verifying rejection of forged headers

### Phase 2: DPoP Double-Binding (2-4 weeks)
- [ ] Implement DPoP proof generation/validation in [`src/gateway/middleware/dpop_validator.py`](src/gateway/middleware/dpop_validator.py)
- [ ] Add DPoP examples to agent SDK documentation
- [ ] Update Kubernetes pod manifests to mount agent signing keys
- [ ] Add load tests verifying DPoP overhead < 5ms p99

### Phase 3: Namespace Prefix Policies (Concurrent with Phase 2)
- [ ] Migrate all OPA policies from exact SPIFFE IDs to namespace patterns
- [ ] Update [`ControlRegistry.register_control()`](src/gateway/governance/control_registry.py) to accept `authorized_agent_pattern`
- [ ] Add `agent_namespace` to standard OPA input schema
- [ ] Verify `POLICY_DRIFT_VIOLATION` no longer triggers on pod restarts

### Phase 4: A2A Delegation Framework (4-6 weeks)
- [ ] Implement subagent SPIFFE ID generation in agent runtime
- [ ] Add delegation metadata to [`GovernanceEnvelopeBuilder`](src/gateway/governance/governance_envelope.py)
- [ ] Create OPA delegation policy library in `policies/delegation/`
- [ ] Add E2E tests for parent → subagent → external service call chains

---

## §6 Security Considerations

### 6.1 Trust Bundle Management
- **Rotation Frequency:** SPIFFE trust bundles MUST rotate at least every 90 days.
- **Distribution:** Use SPIFFE Federation API or Kubernetes ConfigMaps with `immutable: true`.
- **Revocation:** Implement Certificate Revocation List (CRL) checks before accepting certificates.

### 6.2 Replay Attack Mitigation
- DPoP `iat` timestamps MUST be validated with ≤60 second tolerance.
- Optional: Implement server-side nonce challenges for high-value transactions (Tier 1/2 actions).

### 6.3 Key Material Storage
- Agent signing keys (for DPoP) MUST reside in Kubernetes Secrets with `type: kubernetes.io/tls`.
- Production environments SHOULD use hardware security modules (HSMs) or Google Cloud KMS for key storage.

### 6.4 Monitoring & Alerting
- Alert on any `DPoP validation failed` errors (potential attack indicator).
- Log all SPIFFE ID extractions with certificate thumbprints for forensic auditability.
- Alert on SPIFFE namespace policy denials (potential misconfiguration or privilege escalation attempt).

---

## §7 Compliance Mappings

| Control Family | Mapped Controls | Implementation Reference |
|---|---|---|
| **NIST SP 800-53 Rev. 5** | IA-3 (Device Identification), IA-4 (Identifier Management), IA-5 (Authenticator Management), SC-8 (Transmission Confidentiality) | mTLS certificate extraction, DPoP binding |
| **ISO 27001:2022** | A.9.2.1 (User Registration), A.9.4.3 (Password Management System) | SPIFFE SVID as cryptographic authenticator |
| **PCI DSS v4.0** | Req 8.3.1 (Multi-Factor Authentication), Req 8.3.11 (MFA for Remote Access) | DPoP proof-of-possession as second factor |
| **GDPR Article 32** | Security of Processing (cryptographic protection) | End-to-end mTLS with certificate-bound tokens |

---

## §8 References

- **RFC 9449:** OAuth 2.0 Demonstrating Proof of Possession (DPoP)
- **SPIFFE Specification:** https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE.md
- **CAGE Architecture Decision Records:**
  - ADR-008: Fail-Closed Execution Boundary
  - ADR-015: Sovereign Telemetry with Langfuse (vs. LangSmith prohibition)
  - ADR-022: Three-Layer Architecture (Kernel, Domain Plugins, Rails)
- **NIST SP 800-204C:** DevSecOps for Microservices (Zero Trust mTLS guidance)

---

## §9 Changelog

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0.0 | 2026-09-22 | Principal Security & Governance Architect | Initial specification: SPIFFE extraction, DPoP binding, namespace prefix matching, A2A delegation |

---

**End of Specification**

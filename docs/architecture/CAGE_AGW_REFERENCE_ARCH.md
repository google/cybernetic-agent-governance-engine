# CAGE Agent Gateway Reference Architecture

> **Status:** Phase B — Work Stream D (D4)
> **Change category:** Cat-S (Standard) — documentation only
> **Compliance:** SC-8, SC-12, AC-3, IA-3, AU-2, SI-10
> **Last Updated:** 2026-09-22

---

## Table of Contents

1. [Overview](#1-overview)
2. [Cloud-Agnostic Path (Envoy ext_authz)](#2-cloud-agnostic-path-envoy-ext_authz)
3. [GCP Adaptation (Agent Gateway Service Extension)](#3-gcp-adaptation-agent-gateway-service-extension)
4. [DEFER Flow](#4-defer-flow)
5. [mTLS Certificate Lifecycle](#5-mtls-certificate-lifecycle)
6. [Compliance Controls](#6-compliance-controls)
7. [Deployment Configuration](#7-deployment-configuration)

---

## 1. Overview

The **Agent Gateway Adapter** (`src/gateway/server/agent_gateway_adapter.py`)
implements the Envoy `ext_authz` gRPC protocol
(`envoy.service.auth.v3.Authorization.Check`) as a cloud-agnostic governance
enforcement point.

**Key design principle:** The adapter contains zero cloud-provider-specific
code. GCP Agent Gateway (AGW) integration is an optional deployment
configuration — the same `AgentGatewayAdapter` serves both GCP AGW and
self-managed Envoy/Istio deployments with zero code difference.

### What the adapter does

Every agent tool call passes through the adapter before reaching the
application container:

1. Extract the caller's SPIFFE URI from the mTLS peer principal via
   `extract_spiffe_uri_from_grpc_context()`
   ([`src/gateway/governance/spiffe_extractor.py`](../../src/gateway/governance/spiffe_extractor.py));
   this value becomes `caller_principal`. Identity is **never** taken from a
   request header (the former `X-Agent-ID` header was removed in v3.1.0) or
   from the JSON-RPC body, and there is no anonymous fallback
2. Parse the JSON-RPC 2.0 body to extract `(tool_name, params)`
3. Run the full CAGE 8-tier governance pipeline (FTRA + 7 in-pipeline tiers) via `validate_action()`
4. Return `OkHttpResponse` + `x-cage-routing-seal` header on `APPROVED`
5. Return `DeniedHttpResponse(403)` + violation JSON on `DENIED`
6. Return `DeniedHttpResponse(202)` + `{verdict: DEFERRED, thread_id}` on `MANUAL_REVIEW`

**Fail-closed identity behaviour (step 1):**

| Condition | Response |
|-----------|----------|
| SPIFFE URI missing or not matching `^spiffe://[a-zA-Z0-9._-]+(/[a-zA-Z0-9._/-]*)?$` | `DeniedHttpResponse(401)` — `{"error": "authentication_required", "message": "Client certificate with valid SPIFFE URI required"}` |
| `CheckRequest` fields cannot be extracted at all | `DeniedHttpResponse(403)` — `{"error": "request_extraction_error"}` |

The equivalent HTTP/ASGI ingress (`inference_proxy.py`) returns plain HTTP 401
for the same identity failure. The canonical identity contract is
[`AGENT_IDENTITY_BINDING_SPEC.md`](AGENT_IDENTITY_BINDING_SPEC.md).

---

## 2. Cloud-Agnostic Path (Envoy ext_authz)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     Cloud-Agnostic Deployment                           │
│                                                                         │
│  [Agent / MCP Client]                                                   │
│         │                                                               │
│         │  HTTP/gRPC tool call                                          │
│         ▼                                                               │
│  [Envoy sidecar / Ingress]  ──ext_authz gRPC──▶  [CAGE :50051]         │
│         │                                              │                │
│         │                                    validate_action()          │
│         │                                    (8-tier pipeline)          │
│         │                                              │                │
│         │                              ┌───────────────┼───────────┐   │
│         │                              ▼               ▼           ▼   │
│         │                           APPROVED        DENIED    MANUAL_  │
│         │                              │               │       REVIEW  │
│         │                       OkHttpResponse    403 Denied  202 DEF  │
│         │                       + routing seal    + violation  + tid   │
│         │                              │                               │
│         │◀─────────────────────────────┘                               │
│         │                                                               │
│         ▼  (on APPROVED only)                                           │
│  [MCP Tool Server]  ──verify routing seal──▶  [Redis CBF]              │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Supported Envoy-based proxies

| Proxy | Configuration |
|-------|--------------|
| Istio sidecar | `EnvoyFilter` with `ext_authz` HTTP filter |
| Contour | `ExtensionService` resource |
| Emissary-ingress | `AuthService` resource |
| Standalone Envoy | `ext_authz` HTTP filter in `HttpConnectionManager` |
| **GCP Agent Gateway** | Service Extension (see §3) |

---

## 3. GCP Adaptation (Agent Gateway Service Extension)

> **This section describes a GCP-specific deployment configuration.**
> The adapter code is identical — only the surrounding infrastructure differs.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     GCP Agent Gateway Deployment                        │
│                                                                         │
│  [Agent / MCP Client]                                                   │
│         │                                                               │
│         │  HTTPS tool call                                              │
│         ▼                                                               │
│  [GCP Agent Gateway (AGW)]  ──ext_authz gRPC──▶  [CAGE :50051]         │
│         │                    (Service Extension)        │               │
│         │                                     validate_action()         │
│         │                                     (8-tier pipeline)         │
│         │                                              │                │
│         │                              ┌───────────────┼───────────┐   │
│         │                              ▼               ▼           ▼   │
│         │                           APPROVED        DENIED    MANUAL_  │
│         │                              │               │       REVIEW  │
│         │                       OkHttpResponse    403 Denied  202 DEF  │
│         │                       + routing seal    + violation  + tid   │
│         │                              │                               │
│         │◀─────────────────────────────┘                               │
│         │                                                               │
│         ▼  (on APPROVED only)                                           │
│  [GKE MCP Tool Server]  ──verify routing seal──▶  [Cloud Memorystore]  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### GCP-specific configuration (managed in `infra/` Terraform)

| Resource | Purpose |
|----------|---------|
| `google_network_services_gateway` | AGW resource pointing to CAGE endpoint |
| `google_network_services_extension` | Service Extension binding AGW → CAGE :50051 |
| `google_service_account` | AGW service account for mTLS authentication |
| `google_certificate_manager_certificate` | mTLS certificate for AGW → CAGE callout |
| `google_kms_crypto_key` | KMS key for governance seal signing |

### AGW evaluation order

AGW evaluates its built-in policy **before** calling the ext_authz Service
Extension. This means CAGE's adapter sees only AGW-approved requests. The
CAGE pipeline provides defense-in-depth for requests that pass AGW's initial
checks.

> **Open question (Q6 in IMPLEMENTATION_PLAN_V2.md):** Confirm whether AGW
> evaluates its SGP before or after the ext_authz callout. The ordering
> determines whether CAGE's adapter sees AGP-approved or AGP-rejected requests.

---

## 4. DEFER Flow

When the CAGE governance pipeline returns `MANUAL_REVIEW` (human-in-the-loop
required), the adapter returns `DeniedHttpResponse(202)` immediately because
the ext_authz timeout is typically 5 seconds.

```
[Agent]  ──tool call──▶  [Envoy/AGW]  ──ext_authz──▶  [CAGE :50051]
                                                              │
                                                    MANUAL_REVIEW verdict
                                                              │
                                                    202 DEFERRED + thread_id
                                                              │
[Agent]  ◀──202 DEFERRED──  [Envoy/AGW]  ◀──────────────────┘
   │
   │  poll GET /v1/approvals/pending?thread_id=<tid>
   ▼
[CAGE HTTP :8080]  ──lookup──▶  [Redis DEFER queue]
   │
   │  (human approves via HITL UI)
   ▼
[Agent]  ◀──200 APPROVED──  [CAGE HTTP :8080]
   │
   │  retry original tool call with routing seal
   ▼
[Envoy/AGW]  ──ext_authz──▶  [CAGE :50051]  ──APPROVED──▶  [MCP Tool Server]
```

---

## 5. mTLS Certificate Lifecycle

### Cloud-agnostic (Istio / service mesh)

```
[Istio CA]  ──issue SPIFFE cert──▶  [Envoy sidecar]
                                           │
                                    mTLS callout to CAGE :50051
                                           │
                                    CAGE extracts peer principal
                                    (SPIFFE ID from SAN, regex-validated)
                                           │
                                    OPA agent catalog lookup
                                    (input.caller_identity.sub)
```

### GCP Adaptation (Workload Identity)

```
[GCP Certificate Manager]  ──issue cert──▶  [AGW Service Extension]
                                                      │
                                             mTLS callout to CAGE :50051
                                                      │
                                             CAGE extracts peer principal
                                             (must be a SPIFFE URI)
                                                      │
                                             OPA agent catalog lookup
```

> **Corrected 2026-09-22:** earlier revisions of this document stated that the
> GCP path supplies a *GCP service account email* as the peer principal. That is
> no longer accurate. `extract_spiffe_uri_from_grpc_context()` validates the
> principal against `^spiffe://[a-zA-Z0-9._-]+(/[a-zA-Z0-9._/-]*)?$` and raises
> `SpiffeExtractionError` otherwise, so the AGW/Workload Identity deployment must
> present the caller as a SPIFFE URI. A bare service-account email is rejected.

**SC-12 compliance:** mTLS certificate lifecycle is managed by the service
mesh or GCP Workload Identity — not by CAGE. CAGE only reads the peer
principal from the already-validated mTLS connection.

**AC-3 compliance:** The gRPC endpoint must only accept calls from the
registered proxy service account. This is enforced by the service mesh
mTLS policy (Istio `PeerAuthentication`) or AGW IAM binding — not by CAGE.

**IA-3 compliance (fail-closed):** CAGE derives `caller_principal` solely from
the validated peer SPIFFE URI and feeds it to OPA as `input.caller_identity.sub`.
No header, body field, or anonymous fallback can supply it; an unresolvable
principal terminates the request with a denied `CheckResponse` before
`validate_action()` is reached.

---

## 6. Compliance Controls

| Control | Implementation |
|---------|---------------|
| **SC-8** (Transmission Confidentiality) | mTLS required between calling proxy and CAGE :50051; enforced by service mesh or AGW |
| **SC-12** (Cryptographic Key Establishment) | mTLS certificate lifecycle managed by Istio CA or GCP Certificate Manager |
| **AC-3** (Access Enforcement) | gRPC endpoint only accepts calls from registered proxy service account (mTLS CN/SAN validation) |
| **IA-3** (Device Identification & Authentication) | `extract_spiffe_uri_from_grpc_context()` in [`src/gateway/governance/spiffe_extractor.py`](../../src/gateway/governance/spiffe_extractor.py) derives `caller_principal` from the mTLS peer SPIFFE URI; header/body identity and anonymous fallback removed (v3.1.0); fail-closed denied response on extraction failure |
| **AU-2** (Audit Events) | Every `CheckRequest`/`CheckResponse` logged via OTel/Langfuse pipeline in `_emit_audit_event()` |
| **SI-10** (Information Input Validation) | `parse_jsonrpc_body()` validates JSON-RPC 2.0 structure before passing to `validate_action()`; fail-closed on parse error |

### OSCAL update obligation

An OSCAL component update in `compliance/oscal/` is required within
**2 business days** of PR merge for this Cat-S change.

### Lula validation obligation

If any existing Lula validation file in `compliance/lula/` references port
50051, update it in the same PR as D2.

---

## 7. Deployment Configuration

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENT_GW_GRPC_PORT` | `50051` | gRPC listen port |
| `AGENT_GW_BODY_SIZE_LIMIT` | `65536` | Max JSON-RPC body bytes (64KB) |
| `CAGE_DEPLOYMENT_REGION` | `US_FED` | Region guard for telemetry exports |

### Kubernetes Service (already declared)

Port 50051 is already declared in the existing Kubernetes Service manifest
and whitelisted in all network policies. No `NetworkPolicy` or Kubernetes
`Service` changes are required for Phase B.

### Starting the gRPC server

The gRPC server is started automatically by `hybrid_server.py` lifespan:

```python
# From hybrid_server.py _gateway_lifespan():
from src.gateway.server.agent_gateway_adapter import serve_agent_gateway

grpc_server = await serve_agent_gateway(
    port=int(os.getenv("AGENT_GW_GRPC_PORT", "50051"))
)
yield
await grpc_server.stop(grace=5.0)
```

### GCP Adaptation: Cloud Build deployment

For GKE targets, use Cloud Build (never `docker build` + `docker push`):

```bash
# APPROVED for GKE
./deploy_all.sh --target gcp-gke --env dev
gcloud builds submit --config deployment/docker/cloudbuild.gateway.yaml
```

The Cloud Build config at `deployment/docker/cloudbuild.gateway.yaml` builds
and pushes the gateway image (which now includes the gRPC server on port 50051)
to Artifact Registry and deploys to GKE.

# CAGE v2.0 — Combined Implementation Plan

**Status:** PLANNING — AO pre-approval required for Cat-M items before implementation begins
**Authors:** CAGE Engineering Team
**Last updated:** 2026-07-18
**Source documents:**
- [`docs/architecture/SUBSTRATE_MOAT_STRATEGY.md`](../architecture/SUBSTRATE_MOAT_STRATEGY.md) — Gap analysis and competitive roadmap
- [`docs/CAGE_OPEN_INTEROP_SPEC.md`](../CAGE_OPEN_INTEROP_SPEC.md) — External API surface contract
- [`docs/architecture/CAGE_AGW_SERVICE_EXTENSION_RESEARCH.md`](../architecture/CAGE_AGW_SERVICE_EXTENSION_RESEARCH.md) — AGW Service Extension protocol research
- [`docs/architecture/CAGE_STPA_TO_AGP_SEMANTIC_POLICY_RESEARCH.md`](../architecture/CAGE_STPA_TO_AGP_SEMANTIC_POLICY_RESEARCH.md) — AGP compiler target research
- [`docs/architecture/GOVERNANCE_SUBSTRATE_DUALITY.md`](../architecture/GOVERNANCE_SUBSTRATE_DUALITY.md) — Governance Layer / Enforcement Substrate duality analysis; source of Work Stream G

---

## 0. How to Read This Document

This plan is structured into two delivery phases derived from the AGW absorption strategy analysis (2026-07-17) and the Governance Layer / Enforcement Substrate duality analysis (2026-07-18):

- **Phase A — Strategy Blockers** (Q3 2026): Items that must ship before the "Substrate Moat" narrative can be credibly claimed to enterprise customers. All Phase A items are cloud-agnostic Python modules and CI/CD workflows — no new infrastructure. Includes Work Stream G (OSCAL/Lula ingestion adapters and governance webhook) derived from the duality analysis.
- **Phase B — Core AGW Absorption** (Q3–Q4 2026): The highest-ROI items from the AGW absorption analysis. Adds the Envoy ext_authz adapter (cloud-agnostic, also serves as GCP AGW Service Extension), OIDC identity middleware, and OPA agent catalog. No SPIFFE/SPIRE (deferred to Phase C, not in this plan).

Each work item is tagged with:
- **Gap ref** — gap number from `SUBSTRATE_MOAT_STRATEGY.md` (Gap 1–6)
- **Change category** — Cat-S (Standard), Cat-N (Normal), Cat-M (Major)
- **Files** — exact file paths, new or modified

**Cat-M items require AO pre-approval before any implementation work begins.**

Gaps 2 (full SDK), 3 (Semantic Context), and 4 (CNI/eBPF) are deferred to Phase C and Phase D (not in this plan). The AGW Terraform/IaC module (Gap 6 infrastructure) is deferred to Phase C pending SPIFFE/SPIRE operational readiness.

---

## 1. Executive Summary of Gaps (Phase A + Phase B scope)

| Gap | Title | Priority | Phase | Cat-M? |
|---|---|---|---|---|
| Gap 1 | No ACS/AAIF Ingress Adapter | CRITICAL — Strategy Blocker | Phase A | Cat-N |
| Gap 5 | No Egress Translation Pipeline | HIGH — Strategy Blocker | Phase A | Cat-N |
| Gap 2 (partial) | AGP Compiler Output Target | HIGH — Strategy Core | Phase A | Cat-N |
| Duality Gap | OSCAL/Lula Ingestion Adapters | HIGH — Handshake Completion | Phase A | Cat-N |
| Duality Gap | Governance Webhook Push | MEDIUM — Bidirectional Loop | Phase A | Cat-N |
| Gap 6 | Agent Gateway Adapter (Envoy ext_authz) | HIGH — GCP GTM + Cloud-Agnostic | Phase B | **Cat-M** |
| Gap 2 (partial) | OIDC Identity Middleware | HIGH — Enterprise Adoption | Phase B | Cat-N |
| Gap 2 (partial) | OPA Agent Catalog | HIGH — Per-Agent RBAC | Phase B | Cat-N |

---

## 2. Phase A — Strategy Blockers (Q3 2026)

Phase A closes the three gaps that block the "Substrate Moat" narrative. All items are Python modules and CI/CD workflows — no new infrastructure, no Cat-M changes, no AO pre-approval required.

---

### 2.1 Work Stream A — ACS/AAIF Ingress Adapter (Gap 1)

**Strategic rationale:** Allows developers to write agent policies in Microsoft ACS or Linux Foundation AAIF format and run them on CAGE's governance substrate. Closes the "write in any standard, run on CAGE iron" narrative gap that is the central thesis of the Substrate Moat Strategy.

**Change category:** Cat-N (Normal) — Python modules only, no new infrastructure.

#### A1. Ingress Package: `src/gateway/governance/ingress/`

**Files:** `src/gateway/governance/ingress/` (new package)

```
src/gateway/governance/ingress/
├── __init__.py
├── acs_adapter.py          ← ACS behavior declaration parser → CAGE UCA YAML
├── aaif_adapter.py         ← AAIF governed run loop spec parser → CAGE pipeline stages
└── policy_translator.py    ← unified translation pipeline; calls stpa_compiler.py
```

**`acs_adapter.py`** — accepts Microsoft ACS open standard behavior declarations (JSON/YAML) and translates them into CAGE's `stpa_control_structure.yaml` UCA format or directly into OPA Rego AST rules. ACS spec reference: https://github.com/microsoft/agent-control-specification

**`aaif_adapter.py`** — accepts AAIF governed run loop specifications and maps them to CAGE's 7-tier governance pipeline stages. AAIF spec reference: Linux Foundation AAIF working group.

**`policy_translator.py`** — unified pipeline:
1. Detect spec format (ACS vs AAIF vs native CAGE YAML)
2. Route to appropriate adapter
3. Call [`stpa_compiler.py`](../../src/gateway/governance/stpa_compiler.py) to produce compiled enforcement artifacts
4. Return `ControlRegistry`-compatible artifact bundle

**Spec ref:** Add as `CAGE_OPEN_INTEROP_SPEC.md §11 — Policy Ingestion API` (new section):
- `POST /governance/ingest-policy` — accepts ACS/AAIF spec, returns compiled artifact bundle + `policy_version_id`
- `GET /governance/policy-version` — already exists; no change needed

**Compliance obligations:**
- Apache 2.0 license header on all new `.py` files under `src/`
- OSCAL component update in `compliance/oscal/` within 2 business days of PR merge
- No new storage paths, object storage writes, or telemetry exports — no region guard obligation

**Tests required:**
- `tests/test_acs_adapter.py` — ACS spec → UCA YAML round-trip
- `tests/test_aaif_adapter.py` — AAIF spec → pipeline stage mapping
- `tests/test_policy_translator.py` — format detection, routing, artifact bundle output

#### A2. Substrate Contract Specification

**Files:** `docs/SUBSTRATE_CONTRACT.md` (new)

A versioned, documented API surface that external policy authors (writing in ACS or AAIF) can target. Includes:
- The `policy_version_id` pinning mechanism (already implemented in [`validate_action()`](../../src/gateway/governance/symbolic_governor.py:837))
- The ingress API surface (`POST /governance/ingest-policy`)
- The governance check surface (`POST /governance/validate-action`)
- The routing seal contract (`X-CAGE-Routing-Seal` header)
- Versioning guarantees and deprecation policy

**Spec ref:** Cross-reference from `CAGE_OPEN_INTEROP_SPEC.md §1` (Platform Overview).

**Open questions (blocking A1):**
- Is the ACS open standard specification publicly available in machine-readable form? What is the canonical schema?
- Is the AAIF governed run loop specification publicly available? What is the canonical schema?

---

### 2.2 Work Stream B — Egress Compilation Pipeline (Gap 5)

**Strategic rationale:** Closes the CI/CD integration gap — operators can compile ACS/AAIF specs into CAGE enforcement artifacts as part of their build pipeline. Completes the end-to-end policy compilation story that the Substrate Moat narrative requires.

**Change category:** Cat-N (Normal) — CI/CD workflow and scripts only.

**Dependency:** Requires Work Stream A (ingress adapters) to be complete first.

#### B1. CI/CD Integration Hook

**Files:** `.github/workflows/policy_compile.yml` (new)

Steps:
1. Run `src/gateway/governance/ingress/policy_translator.py` on the spec file
2. Run [`stpa_compiler.py`](../../src/gateway/governance/stpa_compiler.py) on the translated YAML (`--targets opa nemo python langgraph`)
3. Compare compiled artifact hash against `ControlRegistry.active_hash`
4. Fail build if hash mismatch (policy drift gate)
5. Upload compiled artifacts as build artifacts

Trigger conditions: push to `main`, PR targeting `main`, manual dispatch with `spec_path` input.

#### B2. Policy Drift Detection Gate

**Files:** `scripts/check_policy_drift.py` (new)

A script that compares the compiled artifact hash against the active `ControlRegistry.active_hash`. Called by the CI workflow and optionally by `scripts/check_stpa_freshness.py`. Exits non-zero on drift — fails the build.

**Compliance obligations:**
- No new storage paths or telemetry exports — no region guard obligation
- No OSCAL update required (CI/CD tooling only)

---

### 2.3 Work Stream C — AGP Compiler Output Target (Gap 2 / Gap 5 intersection)

**Strategic rationale:** CAGE's STPA/STAMP pipeline already compiles to OPA Rego, NeMo Colang, Python validator, and LangGraph Saga nodes. Adding a fifth output target — Google Agent Platform Semantic Governance Policy (SGP) natural language constraint text — allows CAGE to act as the authoritative compilation backend for any operator deploying agents on Vertex AI Agent Engine. The AGP SGP and CAGE's enforcement artifacts are compiled from the same STPA YAML source of truth, making policy drift structurally impossible.

**Full research:** [`CAGE_STPA_TO_AGP_SEMANTIC_POLICY_RESEARCH.md`](../architecture/CAGE_STPA_TO_AGP_SEMANTIC_POLICY_RESEARCH.md)

**Platform model (confirmed):** AGP Semantic Governance Policies are **natural language string constraints** (up to 5,000 characters), not structured JSON. The `generate_agp()` function emits NL constraint text, not a JSON document.

**Change category:** Cat-N (Normal) — new compiler output target; no new infrastructure.

#### C1. AGP Compiler Output Target

**Files:** Extend [`src/gateway/governance/stpa_compiler.py`](../../src/gateway/governance/stpa_compiler.py); new `config/agp/generated_semantic_policy.txt`

New function `generate_agp(cs: ControlStructureModel) -> str` emits natural language constraint text following the mapping in `CAGE_STPA_TO_AGP_SEMANTIC_POLICY_RESEARCH.md §4.1`:

| CAGE UCA condition | AGP NL template |
|---|---|
| `operator: is_null` | `"Do not execute {action} if {param} is null or missing."` |
| `operator: greater_than` | `"Do not execute {action} if {param} exceeds {threshold}."` |
| `operator: less_than` | `"Do not execute {action} if {param} is below {threshold}."` |
| `operator: is_false` | `"Do not execute {action} if {param} is false or not set to true."` |
| `operator: equals` | `"Do not execute {action} if {param} equals {value}."` |
| `nemo_rail.message` | `"Block any request that {nemo_rail.message}."` |
| RBAC `manual_review_below` | `"Require human approval for {action} where {param} exceeds {threshold} for {role} role users."` |
| RBAC `currency_denylist` | `"Deny {action} where {param} is {value} for {role} role users."` |
| CBF invariant | **Not mappable** — omit from AGP SGP output |

`threshold_ref` values resolved via existing `_resolve_threshold()` helper. Output must not exceed 5,000 characters; generator warns and truncates with `# TRUNCATED` sentinel if exceeded.

New CLI target: `python -m src.gateway.governance.stpa_compiler compile --targets agp`

New path constant: `_DEFAULT_AGP_OUT = _REPO_ROOT / "config" / "agp" / "generated_semantic_policy.txt"`

#### C2. AGP Policy Uploader

**Files:** `src/gateway/governance/ingress/agp_policy_uploader.py` (new)

Calls the Agent Platform API (`gcloud beta ai semantic-governance-policies` or equivalent REST endpoint) to create or update the SGP resource using the string-based `Constraints` field from `config/agp/generated_semantic_policy.txt`. Returns the policy resource name for audit logging.

**Note:** Exact Python SDK method for SGP creation must be verified against `google-cloud-aiplatform` at implementation time; `gcloud beta` CLI is the confirmed interface as of 2026-07. This module is GCP-specific and optional — operators on other platforms skip this step.

#### C3. CI/CD Extension

Extend `.github/workflows/policy_compile.yml` (from B1) to:
1. Run `stpa_compiler compile --targets agp` after the existing OPA/NeMo/Python/LangGraph targets
2. Validate the generated text does not exceed 5,000 characters
3. Optionally upload to a staging Agent Platform deployment for validation (GCP deployments only)

**Tests required:**
- `tests/test_stpa_compiler_agp.py` — verify each UCA operator type produces correct NL sentence; verify 5,000-char budget guard; verify CBF invariant is omitted

---

---

### 2.4 Work Stream G — Governance Layer Handshake Completion (Duality Analysis)

**Strategic rationale:** The Governance Layer / Enforcement Substrate duality analysis
([`GOVERNANCE_SUBSTRATE_DUALITY.md`](../architecture/GOVERNANCE_SUBSTRATE_DUALITY.md))
identifies that CAGE already implements the right side of the handshake (enforcement →
compliance evidence) but is missing the left side: ingesting OSCAL component definitions
and Lula validation manifests as policy ingestion inputs. Without this, the
"policy-as-code feeds into infrastructure-as-code" claim is architecturally correct but
not end-to-end demonstrable. Work Stream G closes this gap and adds a push notification
mechanism so the Governance Layer can react to substrate enforcement events in real time.

**Change category:** Cat-N (Normal) — Python modules only, no new infrastructure.

**Dependency:** Work Stream G1 (OSCAL adapter) and G2 (Lula adapter) can be delivered
in parallel with Work Stream A (ACS/AAIF adapters) — they share the same
`src/gateway/governance/ingress/` package and the same `policy_translator.py` routing
pipeline. G3 (governance webhook) is independent of G1/G2.

---

#### G1. OSCAL Ingestion Adapter: `src/gateway/governance/ingress/oscal_adapter.py`

**Files:** `src/gateway/governance/ingress/oscal_adapter.py` (new)

**What it does:** Accepts an OSCAL component definition
(`compliance/oscal/component-definition.yaml` or any OSCAL 1.1.2 component definition
document) and translates the implemented controls into CAGE UCA YAML format, feeding
[`stpa_compiler.py`](../../src/gateway/governance/stpa_compiler.py).

**Why it closes the gap:** OSCAL is the machine-readable output of the Governance Layer
(NIST RMF, FedRAMP, DoD RMF). When CAGE can ingest OSCAL directly, the handshake
becomes: "author your controls in OSCAL, CAGE compiles them into enforcement artifacts
automatically." This makes the "policy-as-code feeds into infrastructure-as-code" claim
technically complete.

**Mapping logic:**

| OSCAL element | CAGE UCA field |
|---|---|
| `component.control-implementations[].implemented-requirements[].control-id` | `hazard_refs` (maps to `CTRL_*` enum via `ControlRegistry`) |
| `implemented-requirement.description` | `description` |
| `implemented-requirement.props[name=status].value` | `uca_type` (`implemented` → `unsafe_action`; `planned` → `not_provided`) |
| `implemented-requirement.statements[].description` | `condition.composite` (free-form; evaluated by Python validator) |
| `implemented-requirement.props[name=enforcement-target].value` | `enforcement` list |

**Integration point:** Registers as a new format handler in
`src/gateway/governance/ingress/policy_translator.py` alongside the ACS and AAIF
adapters. Format detection: presence of `oscal-version` key in the parsed document.

**Compliance note:** This adapter touches NIST SP 800-53 control implementations. An
OSCAL component update in `compliance/oscal/` is required within 2 business days of PR
merge per Code Mode compliance obligations.

**Tests required:**
- `tests/test_oscal_adapter.py` (new):
  - Valid OSCAL component definition → UCA YAML round-trip
  - Unknown `control-id` → logged warning, UCA omitted (not a hard failure)
  - Missing `oscal-version` → format detection returns `None` (not OSCAL format)
  - `enforcement-target` prop absent → defaults to `["python"]`

---

#### G2. Lula Validation Manifest Adapter: `src/gateway/governance/ingress/lula_adapter.py`

**Files:** `src/gateway/governance/ingress/lula_adapter.py` (new)

**What it does:** Accepts a Lula validation manifest (`compliance/lula/*.yaml`) and
extracts the Kubernetes resource assertions as CAGE governance constraints, feeding the
OPA policy engine. Also enables bidirectional feedback: Lula validation results can feed
back into `ControlRegistry` as runtime compliance evidence.

**Why it closes the gap:** Lula is the policy-as-code layer that validates Kubernetes
resources against OSCAL controls. If CAGE can ingest Lula manifests, the handshake
becomes bidirectional: CAGE enforcement artifacts can be validated by Lula, and Lula
validation results can feed back into CAGE's `ControlRegistry.active_hash` as runtime
compliance evidence.

**Mapping logic:**

| Lula manifest element | CAGE target |
|---|---|
| `metadata.name` | OPA policy rule name (`lula_<name>`) |
| `spec.domain.kubernetes-spec.resources[].name` | OPA input field reference |
| `spec.domain.kubernetes-spec.resources[].resource-rule.version` | OPA input validation constraint |
| `spec.policy.opa.rego` | Injected directly into OPA bundle as a named policy module |
| `spec.policy.opa.modules[]` | Additional OPA modules appended to the bundle |

**Integration point:** Registers as a new format handler in `policy_translator.py`.
Format detection: presence of `kind: LulaValidation` key in the parsed document.

**Compliance note:** Adding `lula_adapter.py` adds a new Kubernetes resource reference.
A Lula validation update in `compliance/lula/` must be included in the same PR or
flagged for a follow-on PR per Code Mode compliance obligations.

**Tests required:**
- `tests/test_lula_adapter.py` (new):
  - Valid Lula manifest → OPA module extraction round-trip
  - `spec.policy.opa.rego` present → injected as named OPA module
  - `spec.policy.opa.modules` present → all modules appended
  - Missing `kind: LulaValidation` → format detection returns `None`

---

#### G3. Governance Webhook Push: `src/compliance_bridge/governance_webhook.py`

**Files:**
- `src/compliance_bridge/governance_webhook.py` (new)
- Extend `src/compliance_bridge/main.py` with `POST /v1/webhooks/register` endpoint

**What it does:** Pushes governance enforcement events to registered Governance Layer
endpoints when a substrate enforcement event occurs (CBF violation, DEFER parking, HITL
interrupt, OPA deny). Complements the existing pull-based SSE stream
(`GET /v1/events/stream`) with a push notification mechanism.

**Why it closes the gap:** The SSE stream requires the Governance Layer to maintain a
persistent connection and poll for events. A webhook push allows the Governance Layer to
react in real time without polling — the substrate notifies the specification layer when
an enforcement event occurs, closing the bidirectional feedback loop.

**Webhook registration:**

```
POST /v1/webhooks/register
{
  "endpoint_url": "https://governance-layer.example.com/cage-events",
  "event_types": ["CBF_VIOLATION", "DEFER_PARKING", "HITL_INTERRUPT", "OPA_DENY"],
  "secret": "<hmac-signing-secret>"
}
→ 200 { "webhook_id": "uuid", "registered_at": "ISO8601" }
```

**Webhook payload** (same shape as SSE `governance-event` data field, plus `webhook_id`
and HMAC-SHA256 signature in `X-CAGE-Webhook-Signature` header):

```json
{
  "type": "CBF_VIOLATION | DEFER_PARKING | HITL_INTERRUPT | OPA_DENY",
  "traceId": "string",
  "controlId": "A.9.2",
  "result": "FAIL",
  "safetyRate": 0.87,
  "auditId": "uuid",
  "timestamp": "2026-07-18T01:00:00Z",
  "webhook_id": "uuid"
}
```

**Security:** Webhook payloads are signed with HMAC-SHA256 using the registered secret.
The `X-CAGE-Webhook-Signature` header carries the hex-encoded signature. Receiving
endpoints must verify the signature before processing. Webhook secrets must never be
logged or included in telemetry exports.

**`CAGE_DEPLOYMENT_REGION` guard:** Any outbound HTTP call in `governance_webhook.py`
must be gated on `CAGE_DEPLOYMENT_REGION`. EU_ECB webhook endpoints must remain within
`europe-west1`; APAC_MAS within `asia-southeast1`. Webhook registrations from
cross-region endpoints must be rejected with HTTP 422.

**Compliance obligations:**
- Apache 2.0 license header on `governance_webhook.py`
- `CAGE_DEPLOYMENT_REGION` guard on all outbound HTTP calls (shared-module obligation)
- Webhook secrets must use `secretKeyRef` in Kubernetes manifests — never hardcoded
- No OSCAL update required (compliance bridge extension only)

**Tests required:**
- `tests/test_governance_webhook.py` (new):
  - Webhook registration → `webhook_id` returned
  - CBF violation event → outbound POST to registered endpoint with correct payload
  - HMAC-SHA256 signature present and verifiable in `X-CAGE-Webhook-Signature`
  - Cross-region endpoint → HTTP 422 rejected
  - Unregistered event type → event not dispatched

---

#### G4. `policy_translator.py` — Format Detection Extension

**Files:** `src/gateway/governance/ingress/policy_translator.py` (modify, from Work Stream A)

Extend the format detection logic to handle OSCAL and Lula formats alongside ACS and
AAIF:

```python
def detect_format(spec: dict) -> Literal["acs", "aaif", "oscal", "lula", "cage_yaml"]:
    if "oscal-version" in spec:
        return "oscal"
    if spec.get("kind") == "LulaValidation":
        return "lula"
    if "behaviorDeclarations" in spec:   # ACS
        return "acs"
    if "governedRunLoop" in spec:        # AAIF
        return "aaif"
    return "cage_yaml"
```

**No new file** — this is an extension of the Work Stream A `policy_translator.py`
module. Deliver in the same PR as G1 and G2.

---

#### G5. `CAGE_OPEN_INTEROP_SPEC.md` — §12 Governance Webhook

**Files:** [`docs/CAGE_OPEN_INTEROP_SPEC.md`](../CAGE_OPEN_INTEROP_SPEC.md) (modify)

Add §12 — Governance Webhook:
- `POST /v1/webhooks/register` — register a Governance Layer endpoint
- `DELETE /v1/webhooks/{webhook_id}` — deregister
- `GET /v1/webhooks` — list registered webhooks
- Webhook payload schema (same as SSE `governance-event` + `webhook_id`)
- `X-CAGE-Webhook-Signature` header specification
- Retry policy: exponential backoff, 3 retries, 30s timeout per attempt
- Region guard: cross-region endpoints rejected with HTTP 422

**Change category:** Cat-S (Standard) — documentation only.

---

## 3. Phase B — Core AGW Absorption (Q3–Q4 2026)

Phase B absorbs the highest-ROI capabilities from Google Agent Gateway into CAGE's architecture using open standards (Envoy ext_authz, OIDC, OPA). All new components are cloud-agnostic. The GCP AGW integration is preserved as an optional deployment configuration — the same `AgentGatewayAdapter` serves both GCP AGW and self-managed Envoy/Istio deployments with zero code difference.

**What does NOT change in Phase B:**
- [`cbf.py`](../../src/gateway/governance/cbf.py) — Redis atomic Lua enforcement
- [`symbolic_governor.py`](../../src/gateway/governance/symbolic_governor.py) — 7-tier pipeline
- [`routing_seal.py`](../../src/gateway/governance/routing_seal.py) — HMAC-SHA256 seal
- [`stpa_compiler.py`](../../src/gateway/governance/stpa_compiler.py) — STPA compilation pipeline
- [`defer_queue.py`](../../src/gateway/governance/defer_queue.py) — DEFER state machine
- [`constants.py`](../../src/gateway/governance/constants.py) — ControlRegistry, regional profiles

---

### 3.1 Work Stream D — Agent Gateway Adapter / Envoy ext_authz (Gap 6)

**Strategic rationale:** The single highest-ROI item in the entire absorption strategy. Implements the Envoy `ext_authz` gRPC protocol — an open standard supported by Istio, Contour, Emissary, and any Envoy-based proxy. The same adapter also serves as a GCP AGW Service Extension with zero code changes. Enables network-layer governance enforcement (prompt injection + STPA Tier 0) before requests reach the application container.

**Change category:** Cat-M (Major) — new external API integration (ext_authz gRPC). **AO pre-approval required.**

**Full protocol analysis:** [`CAGE_AGW_SERVICE_EXTENSION_RESEARCH.md`](../architecture/CAGE_AGW_SERVICE_EXTENSION_RESEARCH.md)

#### D1. Proto: Vendor Envoy auth v3 types

**Files:** `src/gateway/protos/envoy/` (new directory tree)

```
src/gateway/protos/envoy/
├── service/auth/v3/
│   ├── attribute_context.proto   ← vendored from envoy-api (Apache 2.0)
│   └── authorization.proto       ← defines Authorization.Check
├── config/core/v3/
│   └── base.proto                ← HeaderValueOption, HeaderValue
└── type/v3/
    └── http_status.proto         ← HttpStatus, StatusCode
```

Alternatively, use `buf` with a `buf.yaml` dependency on `buf.build/envoyproxy/envoy` — avoids vendoring but adds a `buf` build step.

**Acceptance criteria:**
- `grpc_tools.protoc` compiles all four proto files without errors
- Generated Python stubs are importable from `src/gateway/protos/envoy/`

#### D2. Agent Gateway Adapter: `src/gateway/server/agent_gateway_adapter.py`

**Files:** `src/gateway/server/agent_gateway_adapter.py` (new)

**Name rationale:** Named `agent_gateway_adapter` (not `agw_service_extension`) because this is a cloud-agnostic Envoy ext_authz adapter that happens to also work as a GCP AGW Service Extension. The name reflects the general capability, not the GCP-specific deployment.

**What it does:**

```
Envoy ext_authz callout (gRPC CheckRequest)
    │  [from: GCP AGW, Istio, Contour, Emissary, or any Envoy proxy]
    │
    ▼  parse JSON-RPC 2.0 body → (tool_name, params)
    │
    ▼  symbolic_governor.validate_action(tool_name, params)
    │
    ├─ APPROVED      → OkHttpResponse + X-CAGE-Routing-Seal header
    ├─ DENIED        → DeniedHttpResponse(403) + violation JSON body
    └─ MANUAL_REVIEW → DeniedHttpResponse(202) + {verdict: DEFERRED, thread_id}
```

**Key implementation requirements:**

1. **Async gRPC servicer** — `grpc.aio.ServicerContext`; shares the FastAPI asyncio event loop so `validate_action()` can be awaited directly without thread-pool overhead
2. **JSON-RPC 2.0 body parser** — extracts `params.name` (tool name) and `params.arguments` (params dict); fail-closed on parse error (return `DeniedHttpResponse(403)`)
3. **Routing seal injection** — on `APPROVED`, inject `x-cage-routing-seal: <hmac-sha256>` into `OkHttpResponse.headers`; [`mcp_tool_server.py`](../../src/gateway/server/mcp_tool_server.py) already calls `enforce_routing_seal()` — no changes needed there
4. **DEFER handling** — `MANUAL_REVIEW` verdict returns `DeniedHttpResponse` immediately (ext_authz timeout is typically 5s); body contains `{"verdict": "DEFERRED", "thread_id": "..."}` so the MCP client can poll `GET /v1/approvals/pending`
5. **`CAGE_DEPLOYMENT_REGION` guard** — any telemetry export in this module must be gated on the region env var per shared-module region guard obligations
6. **Apache 2.0 license header** — required for all new `.py` files under `src/`
7. **gRPC port** — listen on port 50051; this port is already declared in the existing Kubernetes Service manifest and whitelisted in all network policies — no NetworkPolicy or Kubernetes Service changes required

**`serve_agent_gateway()` coroutine** — called from [`hybrid_server.py`](../../src/gateway/server/hybrid_server.py) lifespan. Must return the running `grpc.aio.Server` instance for graceful shutdown:

```python
# Addition to hybrid_server.py _gateway_lifespan():
from src.gateway.server.agent_gateway_adapter import serve_agent_gateway
# Startup:
grpc_server = await serve_agent_gateway(
    port=int(os.getenv("AGENT_GW_GRPC_PORT", "50051"))
)
yield
# Shutdown:
await grpc_server.stop(grace=5.0)
```

**Spec ref:** Add as `CAGE_OPEN_INTEROP_SPEC.md §7.3 — Agent Gateway Adapter (Envoy ext_authz gRPC)`:
- Endpoint: `grpc://<host>:50051`
- Service: `envoy.service.auth.v3.Authorization`
- Method: `rpc Check(CheckRequest) returns (CheckResponse)`
- Auth: mTLS (caller's certificate validated by service mesh or AGW)
- Timeout: 5s (recommended; configurable by the calling proxy)

**Tests required:**
- `tests/test_agent_gateway_adapter.py` (new):
  - Parse error → `DeniedHttpResponse(403)`
  - Governance deny → `DeniedHttpResponse(403)` with violation detail
  - Governance approve → `OkHttpResponse` with `x-cage-routing-seal` header
  - `MANUAL_REVIEW` → `DeniedHttpResponse` with `verdict: DEFERRED`
  - Body truncation (> 64KB) → `DeniedHttpResponse(403)` fail-closed

#### D3. `hybrid_server.py` — Minimal Addition

**Files:** [`src/gateway/server/hybrid_server.py`](../../src/gateway/server/hybrid_server.py) (modify)

Add `serve_agent_gateway()` call to `_gateway_lifespan()` startup block and `grpc_server.stop(grace=5.0)` to the shutdown block. No other changes to `hybrid_server.py`.

**Port note:** Port 50051 is already declared in the existing Kubernetes Service and Terraform module. No NetworkPolicy or Kubernetes Service changes are required.

#### D4. Reference Architecture Document

**Files:** `docs/architecture/CAGE_AGW_REFERENCE_ARCH.md` (new)

Content: The defense-in-depth stack diagram showing:
- Cloud-agnostic path: `[Agent] → [Envoy sidecar ext_authz:50051] → [CAGE AgentGatewayAdapter] → [CAGE 7-tier pipeline] → [Redis CBF]`
- GCP path: `[Agent] → [AGW ext_authz callout:50051] → [CAGE AgentGatewayAdapter] → [CAGE 7-tier pipeline] → [Redis CBF]`
- DEFER flow: adapter returns 202 DEFERRED → client polls `/v1/approvals/pending` → human approves → client retries
- mTLS certificate lifecycle for both paths

**Compliance obligations:**
- SC-8 (Transmission Confidentiality): mTLS required between calling proxy and CAGE's ext_authz endpoint
- SC-12 (Cryptographic Key Establishment): mTLS certificate lifecycle; use existing KMS or workload identity
- AC-3 (Access Enforcement): ext_authz endpoint must only accept calls from the registered proxy service account
- AU-2 (Audit Events): every `CheckRequest` / `CheckResponse` must be logged via existing OTel/Langfuse pipeline
- SI-10 (Information Input Validation): JSON-RPC body parser must validate structure before passing to `validate_action()`
- OSCAL component update in `compliance/oscal/` within 2 business days of PR merge
- Lula validation check: if any existing Lula validation file references port 50051, update in same PR

---

### 3.2 Work Stream E — OIDC Identity Middleware (Gap 2 partial)

**Strategic rationale:** AGW's IAP provides OAuth2/OIDC token validation at the proxy layer. The vendor-neutral equivalent is OIDC JWT validation middleware in [`governance_middleware.py`](../../src/gateway/server/governance_middleware.py) with a configurable JWKS endpoint. This enables per-caller identity in OPA RBAC decisions — currently impossible because CAGE has no reliable caller identity. Works with any OIDC provider: Keycloak, Dex, Auth0, Google, Azure AD, Okta.

**Change category:** Cat-N (Normal) — extends existing middleware; no new infrastructure.

**Dependency:** Can be delivered independently of Work Stream D. Delivers value even without the ext_authz adapter.

#### E1. OIDC Validation Middleware

**Files:** [`src/gateway/server/governance_middleware.py`](../../src/gateway/server/governance_middleware.py) (modify)

Add a new middleware tier that runs before the existing governance pipeline:

1. Read `Authorization: Bearer <jwt>` header from the incoming request
2. Validate the JWT signature against the JWKS endpoint at `CAGE_OIDC_JWKS_URI` (env var)
3. Extract `sub` (subject), `iss` (issuer), and `scope` claims from the validated JWT
4. Inject `caller_identity` into the request context so `validate_action()` can pass it to OPA as input
5. If `CAGE_OIDC_JWKS_URI` is not set, skip validation (backward-compatible; existing deployments unaffected)
6. If JWT is present but invalid, return HTTP 401 with `WWW-Authenticate: Bearer error="invalid_token"`

**Environment variables:**
- `CAGE_OIDC_JWKS_URI` — JWKS endpoint URL (e.g., `https://accounts.google.com/.well-known/jwks.json`); if unset, OIDC validation is disabled
- `CAGE_OIDC_ISSUER` — expected `iss` claim value; if set, validate issuer; if unset, skip issuer check
- `CAGE_OIDC_AUDIENCE` — expected `aud` claim value; if set, validate audience; if unset, skip audience check

**OPA integration:** The `caller_identity` dict (`{sub, iss, scope}`) is added to the OPA input payload so existing OPA policies can use `input.caller_identity.sub` for RBAC decisions. No changes to existing OPA policies required — the field is additive.

**Compliance obligations:**
- No new storage paths or telemetry exports — no region guard obligation
- No OSCAL update required (middleware extension only)
- Apache 2.0 license header not required (modifying existing file, not creating new one)

**Tests required:**
- `tests/test_oidc_middleware.py` (new):
  - Valid JWT → `caller_identity` injected into request context
  - Invalid JWT signature → HTTP 401
  - Expired JWT → HTTP 401
  - `CAGE_OIDC_JWKS_URI` not set → request passes through unchanged (backward compat)
  - Missing `Authorization` header → request passes through unchanged (backward compat)

---

### 3.3 Work Stream F — OPA Agent Catalog (Gap 2 partial)

**Strategic rationale:** AGW's Agent Registry provides a centralized catalog of approved agents and tools with IAM-enforced access control. The vendor-neutral equivalent is an OPA-backed agent catalog — a new OPA policy package that enforces which caller identities are allowed to call which tools. Evaluated by the existing OPA instance; no new infrastructure required. Enables per-agent tool authorization that CAGE currently cannot provide.

**Change category:** Cat-N (Normal) — new OPA policy and data file; no new infrastructure.

**Dependency:** Requires Work Stream E (OIDC middleware) to provide `caller_identity` in the OPA input. Can be delivered in the same sprint as E.

#### F1. Agent Catalog OPA Policy

**Files:** `config/opa/agent_catalog.rego` (new)

New OPA policy package `data.agent_catalog`:

```rego
package agent_catalog

import future.keywords.in

# Allow if: caller is in approved_agents AND tool is in caller's allowed_tools
allow {
    agent := approved_agents[input.caller_identity.sub]
    input.tool_name in agent.allowed_tools
}

# Deny with reason if caller is not in approved_agents
violation[msg] {
    not approved_agents[input.caller_identity.sub]
    msg := sprintf("caller '%v' is not in the approved agent catalog", [input.caller_identity.sub])
}

# Deny with reason if tool is not in caller's allowed_tools
violation[msg] {
    agent := approved_agents[input.caller_identity.sub]
    not input.tool_name in agent.allowed_tools
    msg := sprintf("caller '%v' is not authorized to call tool '%v'", [input.caller_identity.sub, input.tool_name])
}

# Data loaded from config/agent_catalog.json
approved_agents := data.agent_catalog_data.agents
```

#### F2. Agent Catalog Data Document

**Files:** `config/agent_catalog.json` (new)

```json
{
  "agents": {
    "spiffe://trust-domain/ns/default/sa/trader-agent": {
      "display_name": "Governed Trader Agent",
      "allowed_tools": ["execute_trade", "market_analysis", "get_portfolio"],
      "trust_domain": "trust-domain"
    },
    "spiffe://trust-domain/ns/default/sa/risk-agent": {
      "display_name": "Risk Analyst Agent",
      "allowed_tools": ["market_analysis", "get_portfolio", "risk_assessment"],
      "trust_domain": "trust-domain"
    }
  }
}
```

**Security note:** `config/agent_catalog.json` is a security-critical configuration file. It must be:
- Version-controlled and reviewed in PRs (same posture as OPA policy files)
- Validated in CI (schema check + OPA bundle compilation)
- Never modified directly in production — changes must go through the standard PR + CI pipeline

**OPA integration:** The catalog data is loaded into OPA as a data document at startup. The `agent_catalog.rego` policy is evaluated as part of the existing OPA policy bundle — no changes to the OPA client or evaluation pipeline required.

**`AgentGatewayAdapter` integration:** The ext_authz adapter (Work Stream D) extracts `X-SPIFFE-ID` or the OIDC `sub` claim from the request context and passes it as `caller_identity.sub` in the OPA input. The `agent_catalog` policy runs as part of the OPA evaluation in the adapter's fast path.

**Compliance obligations:**
- No new storage paths or telemetry exports — no region guard obligation
- No OSCAL update required (OPA policy addition only)
- CI validation step: add `config/agent_catalog.json` schema check to `.github/workflows/policy_compile.yml`

**Tests required:**
- `tests/test_agent_catalog.py` (new):
  - Approved caller + allowed tool → `allow = true`
  - Approved caller + disallowed tool → `allow = false` + violation message
  - Unknown caller → `allow = false` + violation message
  - Empty catalog → all callers denied

---

## 4. `CAGE_OPEN_INTEROP_SPEC.md` — Required Updates

The following sections of [`CAGE_OPEN_INTEROP_SPEC.md`](../CAGE_OPEN_INTEROP_SPEC.md) require updates as each phase is implemented.

| Spec section | Current state | Required update | Phase |
|---|---|---|---|
| §1 Platform Overview | Three services listed | Add Agent Gateway Adapter as a fourth integration surface; add cross-reference to `SUBSTRATE_CONTRACT.md` | Phase A (A2) |
| §7 gRPC Services | Two services: `Chat`, `ExecuteTool` | Add §7.3: `envoy.service.auth.v3.Authorization.Check` (Envoy ext_authz) | Phase B (D2) |
| §9.3 HTTP 403 Forbidden | Governance block | Add `X-CAGE-Routing-Seal-Missing` as a distinct 403 sub-type; add 401 for OIDC validation failure | Phase B (D2, E1) |
| §10 Rate Limits | Four limits documented | Add §10.5: ext_authz callout rate limit (per-client, per-region) | Phase B (D2) |
| §11 Policy Ingestion API | Does not exist | Add: `POST /governance/ingest-policy`, `GET /governance/policy-version`; extend format list to include `oscal` and `lula` | Phase A (A1, G1, G2) |
| §12 Governance Webhook | Does not exist | Add: `POST /v1/webhooks/register`, `DELETE /v1/webhooks/{webhook_id}`, `GET /v1/webhooks`; webhook payload schema; `X-CAGE-Webhook-Signature` spec; region guard | Phase A (G3, G5) |

---

## 5. Compliance Obligations Summary

| Work item | NIST controls | OSCAL update? | Lula update? | Change cat |
|---|---|---|---|---|
| A1 — Ingress adapters (ACS/AAIF) | AC-3, SI-10 | Yes (within 2 business days) | No | Cat-N |
| A2 — Substrate contract doc | None | No | No | Cat-S |
| B1 — CI/CD policy compile workflow | None | No | No | Cat-N |
| B2 — Policy drift detection script | None | No | No | Cat-N |
| C1 — AGP compiler target (`generate_agp()`) | None | No | No | Cat-N |
| C2 — AGP policy uploader | None | No | No | Cat-N |
| G1 — OSCAL ingestion adapter | AC-3, SI-10, NIST SP 800-53 | Yes (within 2 business days) | No | Cat-N |
| G2 — Lula validation manifest adapter | AC-3, SI-10 | No | Yes (same PR or follow-on) | Cat-N |
| G3 — Governance webhook push | SC-8, AU-2 | No | No | Cat-N |
| G4 — `policy_translator.py` format extension | None | No | No | Cat-N |
| G5 — Interop spec §12 (webhook) | None | No | No | Cat-S |
| D1 — Envoy proto vendoring | None | No | No | Cat-S |
| D2 — `agent_gateway_adapter.py` | SC-8, SC-12, AC-3, AU-2, SI-10 | Yes (within 2 business days) | Yes if port 50051 referenced | **Cat-M** |
| D3 — `hybrid_server.py` gRPC startup | SC-8 | No | No | Cat-N |
| D4 — Reference arch doc | None | No | No | Cat-S |
| E1 — OIDC identity middleware | AC-3, IA-8 | No | No | Cat-N |
| F1 — Agent catalog OPA policy | AC-3 | No | No | Cat-N |
| F2 — Agent catalog data document | AC-3 | No | No | Cat-N |

**Region guard obligation:** Any new storage path, object storage write, or telemetry export in `src/gateway/server/agent_gateway_adapter.py`, `src/gateway/governance/ingress/`, or `src/compliance_bridge/governance_webhook.py` must be gated on `CAGE_DEPLOYMENT_REGION`. EU_ECB data paths must remain within `europe-west1`; APAC_MAS within `asia-southeast1`. Webhook outbound calls in G3 must also be region-gated — cross-region webhook endpoints rejected with HTTP 422.

---

## 6. Sequenced Delivery — Sprint-Level Breakdown

### Sprint 1 (Weeks 1–2): AO Approval + Schema Research

- [ ] Submit Cat-M change request for Work Stream D (Agent Gateway Adapter ext_authz)
- [ ] Research ACS open standard schema (blocking A1)
- [ ] Research AAIF governed run loop schema (blocking A1)
- [ ] Vendor Envoy auth v3 proto files into `src/gateway/protos/envoy/` (D1)

### Sprint 2 (Weeks 3–4): Ingress Adapters (pending schema research) + OSCAL/Lula Adapters

- [ ] Implement `src/gateway/governance/ingress/acs_adapter.py` (A1)
- [ ] Implement `src/gateway/governance/ingress/aaif_adapter.py` (A1)
- [ ] Implement `src/gateway/governance/ingress/oscal_adapter.py` (G1)
- [ ] Implement `src/gateway/governance/ingress/lula_adapter.py` (G2)
- [ ] Implement `src/gateway/governance/ingress/policy_translator.py` with 4-format detection (A1, G4)
- [ ] Write `docs/SUBSTRATE_CONTRACT.md` (A2)
- [ ] Unit tests: `tests/test_acs_adapter.py`, `tests/test_aaif_adapter.py`, `tests/test_oscal_adapter.py`, `tests/test_lula_adapter.py`, `tests/test_policy_translator.py`
- [ ] OSCAL component update in `compliance/oscal/` for G1 (within 2 business days)
- [ ] Lula validation update in `compliance/lula/` for G2 (same PR or follow-on)

### Sprint 3 (Weeks 5–6): Egress Pipeline + AGP Compiler Target + Governance Webhook

- [ ] Implement `scripts/check_policy_drift.py` (B2)
- [ ] Implement `.github/workflows/policy_compile.yml` (B1)
- [ ] Add `generate_agp()` to `stpa_compiler.py` (C1)
- [ ] Add `--targets agp` CLI option to `stpa_compiler.py` (C1)
- [ ] Implement `src/gateway/governance/ingress/agp_policy_uploader.py` (C2)
- [ ] Extend `policy_compile.yml` to include `--targets agp` and character-budget check (C3)
- [ ] Implement `src/compliance_bridge/governance_webhook.py` (G3)
- [ ] Add `POST /v1/webhooks/register`, `DELETE /v1/webhooks/{webhook_id}`, `GET /v1/webhooks` to `compliance_bridge/main.py` (G3)
- [ ] Unit tests: `tests/test_stpa_compiler_agp.py`, `tests/test_governance_webhook.py`
- [ ] Update `CAGE_OPEN_INTEROP_SPEC.md §11` (Policy Ingestion API — extend format list)
- [ ] Update `CAGE_OPEN_INTEROP_SPEC.md §12` (Governance Webhook — new section) (G5)

### Sprint 4 (Weeks 7–8): Agent Gateway Adapter Core (pending AO approval)

- [ ] Implement `CAGEAuthorizationServicer.Check()` in `agent_gateway_adapter.py` (D2)
- [ ] Implement JSON-RPC 2.0 body parser (fail-closed on parse error) (D2)
- [ ] Implement `OkHttpResponse` + `x-cage-routing-seal` header injection (D2)
- [ ] Implement `DeniedHttpResponse(403)` for DENIED and MANUAL_REVIEW (D2)
- [ ] Add `serve_agent_gateway()` call to `hybrid_server.py` lifespan with graceful shutdown (D3)
- [ ] Unit tests: `tests/test_agent_gateway_adapter.py`
- [ ] Update `CAGE_OPEN_INTEROP_SPEC.md §7.3`, `§9.3`, `§10.5`

### Sprint 5 (Weeks 9–10): OIDC Middleware + Agent Catalog

- [ ] Implement OIDC JWT validation middleware in `governance_middleware.py` (E1)
- [ ] Implement `config/opa/agent_catalog.rego` (F1)
- [ ] Implement `config/agent_catalog.json` with example entries (F2)
- [ ] Add `config/agent_catalog.json` schema check to `policy_compile.yml` (F2)
- [ ] Unit tests: `tests/test_oidc_middleware.py`, `tests/test_agent_catalog.py`

### Sprint 6 (Weeks 11–12): Integration Testing + Compliance

- [ ] End-to-end test: MCP client → Envoy ext_authz (mock) → CAGE adapter (port 50051) → MCP server
- [ ] End-to-end test: ACS spec → ingress adapter → stpa_compiler → OPA enforcement
- [ ] End-to-end test: OSCAL component definition → oscal_adapter → stpa_compiler → OPA enforcement (G1)
- [ ] End-to-end test: Lula manifest → lula_adapter → OPA bundle → enforcement (G2)
- [ ] End-to-end test: CBF violation → governance_webhook → registered endpoint (G3)
- [ ] End-to-end test: OIDC JWT → `caller_identity` → OPA agent catalog → tool authorization
- [ ] OSCAL component update in `compliance/oscal/` for D2, A1, and G1
- [ ] Lula validation check for port 50051 (D2) and G2 follow-on
- [ ] Write `docs/architecture/CAGE_AGW_REFERENCE_ARCH.md` (D4)
- [ ] Update `docs/POAM.md` with commit SHAs and Lula results

---

## 7. Open Questions (Blocking or Near-Blocking)

| # | Question | Blocks | Priority |
|---|---|---|---|
| 1 | Is the ACS open standard specification publicly available in machine-readable form? What is the canonical schema? | A1 | **HIGH** |
| 2 | Is the AAIF governed run loop specification publicly available? What is the canonical schema? | A1 | **HIGH** |
| 3 | Does the Envoy ext_authz proxy (AGW or self-managed) truncate the JSON-RPC body in `CheckRequest.attributes.request.http.body`? What is the size limit? | D2 | **HIGH** |
| 4 | What mTLS CA does the calling proxy (AGW or Istio) use for callout authentication? | D2 | **HIGH** |
| 5 | Is the AGP SGP attached at agent deployment time (static) or can it be updated at runtime without redeployment? | C2 | MEDIUM |
| 6 | Does AGP evaluate its SGP before or after the ext_authz callout? The ordering determines whether CAGE's adapter sees AGP-approved or AGP-rejected requests. | D2 | MEDIUM |
| 7 | Does the DEFER state machine need to be extended to track ext_authz-originated HITL escalations separately from GFA-originated ones? | D2 | MEDIUM |
| 8 | What is the exact Python SDK method for SGP creation in `google-cloud-aiplatform`? Is it available or is `gcloud beta` CLI the only confirmed interface? | C2 | HIGH |
| 9 | Which OSCAL 1.1.2 `implemented-requirement` fields carry the enforcement target (OPA vs NeMo vs Python vs LangGraph)? Is this a standard OSCAL prop or a CAGE extension? | G1 | **HIGH** |
| 10 | Do existing Lula validation manifests in `compliance/lula/` use `spec.policy.opa.rego` inline or `spec.policy.opa.modules[]` references? This determines the primary parsing path for G2. | G2 | MEDIUM |
| 11 | Should the governance webhook (G3) use a persistent store (Redis) for webhook registrations, or is in-memory registration sufficient for the initial implementation? | G3 | MEDIUM |
| 12 | What is the maximum acceptable latency for webhook delivery? Should failed deliveries be retried asynchronously (background task) or synchronously (blocking the enforcement event)? | G3 | MEDIUM |

---

## 8. References

| Document | Role in this plan |
|---|---|
| [`docs/architecture/SUBSTRATE_MOAT_STRATEGY.md`](../architecture/SUBSTRATE_MOAT_STRATEGY.md) | Gap definitions (§3), roadmap (§4), competitive matrix (§9.7), AGW absorption strategy |
| [`docs/architecture/GOVERNANCE_SUBSTRATE_DUALITY.md`](../architecture/GOVERNANCE_SUBSTRATE_DUALITY.md) | Governance Layer / Enforcement Substrate duality analysis; source of Work Stream G (§2.4) |
| [`docs/CAGE_OPEN_INTEROP_SPEC.md`](../CAGE_OPEN_INTEROP_SPEC.md) | External API surface contract; updated by §4 of this plan |
| [`docs/architecture/CAGE_AGW_SERVICE_EXTENSION_RESEARCH.md`](../architecture/CAGE_AGW_SERVICE_EXTENSION_RESEARCH.md) | AGW/ext_authz protocol analysis, implementation skeleton, compliance obligations for Gap 6 |
| [`docs/architecture/CAGE_STPA_TO_AGP_SEMANTIC_POLICY_RESEARCH.md`](../architecture/CAGE_STPA_TO_AGP_SEMANTIC_POLICY_RESEARCH.md) | AGP compiler target research; NL mapping table; platform model correction |
| [`src/gateway/governance/symbolic_governor.py`](../../src/gateway/governance/symbolic_governor.py) | `validate_action()` — the single choke point called by the Agent Gateway Adapter |
| [`src/gateway/server/governance_middleware.py`](../../src/gateway/server/governance_middleware.py) | `enforce_routing_seal()`; OIDC middleware addition target (E1) |
| [`src/gateway/server/hybrid_server.py`](../../src/gateway/server/hybrid_server.py) | Composition root; receives `serve_agent_gateway()` task (D3) |
| [`src/gateway/governance/stpa_compiler.py`](../../src/gateway/governance/stpa_compiler.py) | Compilation pipeline; `generate_agp()` addition target (C1); ingestion target for G1/G2 adapters |
| [`src/compliance_bridge/governance_webhook.py`](../../src/compliance_bridge/governance_webhook.py) | Governance webhook push implementation target (G3) — new file |
| [`compliance/oscal/sp800-53-component-definition.yaml`](../../compliance/oscal/sp800-53-component-definition.yaml) | Reference OSCAL document for G1 adapter mapping validation |
| [`compliance/lula/`](../../compliance/lula/) | Reference Lula manifests for G2 adapter parsing path determination |
| [`src/gateway/governance/stpa_compiler.py`](../../src/gateway/governance/stpa_compiler.py) | Compilation pipeline; `generate_agp()` addition target (C1) |
| [`docs/governance/CHANGE_MANAGEMENT_PROCESS.md`](../governance/CHANGE_MANAGEMENT_PROCESS.md) | Cat-M approval process for Work Stream D |

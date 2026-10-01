# Vendor Neutrality Contract & Architecture Invariants

> **Reference Architecture — Clean Architecture Over Operational Continuity.** CAGE
> demonstrates governance patterns for AI systems. Because CAGE is a reference
> architecture and not a deployed production service, **breaking changes and
> operational considerations are far less important than a clean, legible
> architecture.** The optimization target is clean code structure, modularity,
> and architectural clarity — not operational safety, uptime, or backward
> compatibility. There is no live production instance to protect. Breaking
> changes are therefore **acceptable and often desirable**: they remove designs
> the project is deliberately moving away from, and no deprecation window is owed
> to anyone. Where a choice exists between operational completeness and
> structural clarity, always choose structural clarity.

This document formalizes the vendor neutrality guarantees, architectural layer
invariants, and storage contracts for the Cybernetic AI Governance Engine (CAGE).

---

## 1. Architectural Layers & Boundary Rules

CAGE enforces strict separation between the universal governance kernel, domain-specific plugins, and external integration rails:

| Layer | Path | Responsibilities | Boundary & Dependency Invariants |
|---|---|---|---|
| **Layer 1: Governance Kernel** | `src/gateway/` | Universal dispatch loop, composition root (`assemble_governor()` / `bootstrap_governor()`), consensus engine, CBF engine, evidence accumulator, routing seals, and audit rails. | **Strictly domain-agnostic and vendor-neutral.** Must NEVER import from Layer 2 (`src/cage_*`), Layer 3 (`src/compliance_bridge/`), or Layer 4 (`src/governed_financial_advisor/`). Must NOT import vendor SDKs (`google.cloud`, `boto3`, `botocore`, `azure`, `langfuse`); only allowlisted factories (e.g. [`signer_factory.py`](../../src/gateway/governance/signer_factory.py)) may lazily import `src/integrations/` inside a function. Enforced in CI by Gate G3 ([`scripts/check_import_boundaries.py`](../../scripts/check_import_boundaries.py)), which also enforces kernel AST purity: no domain path literals, no domain action/field literals (`FORBIDDEN_DOMAIN_LITERALS`), and no domain or vendor class definitions (`FORBIDDEN_KERNEL_DEFINITIONS`, e.g. `FiscalLimitGuard`, `TradingKnowledgeGraph`, `GCPKMSProvider`). |
| **Layer 2: Domain Plugins** | `src/cage_{domain}/` (`src/cage_finance/`, `src/cage_healthcare/`, `src/cage_physical_ai/`) | Domain-specific tiers (`ReadOnlyTier` / `MutatingTier`, ADR-009), CBF invariants, STPA UCA rules and saga compensators, `domains.<domain>` threshold schemas, action registries, ontologies, policies, and causal graphs. | Each process runs exactly one domain, selected by `CAGE_DOMAIN`. The plugin returns a frozen `PluginContribution` from `CagePlugin.contribute()` ([`contracts.py`](../../src/gateway/governance/contracts.py)); the kernel validates it and builds an immutable `SymbolicGovernor` in [`assemble_governor()`](../../src/gateway/governance/governor/assembly.py). Plugins never mutate the governor. Encapsulates domain vocabulary and semantics without polluting kernel code. |
| **Layer 3: Integrations & Rails** | `src/compliance_bridge/`, `src/integrations/` | External vendor normative/attestation adapters, durable sinks (ClickHouse, GCS, S3), NeMo Guardrails, Langfuse telemetry. | Adheres to the Secure Plugin & Adapter Architecture. Communicates with the kernel exclusively via canonical data structures and contracts. |

---

## 2. Core Neutrality Guarantees

### 2.1 Zero-Vendor-SDK Kernel
The core governance kernel (`src/gateway/`) has zero runtime requirements on proprietary cloud SDKs (`google-cloud-storage`, `boto3`, `azure-storage-blob`, `langfuse`).
- The kernel boots and runs in bare environments (e.g. local developer machine, edge nodes, offline CI).
- Kernel code paths need no vendor SDK: in development and CI postures, governance decisions and routing seals run against software signers and local backends. Enforcing postures additionally require a Cloud KMS provider and Redis, which the startup posture check ([`posture.py`](../../src/gateway/governance/governor/posture.py)) verifies before serving.
- Cloud-specific capabilities are implemented behind decoupled kernel contracts and loaded lazily only when configured:
  - **Signing:** `KMSGovernanceSigner` and the `BaseKMSProvider` contract live in [`kms_signer.py`](../../src/gateway/governance/kms_signer.py), together with the vendor-free software providers (`SoftwareEd25519Provider`, `SoftwareHMACProvider`). The cloud providers (`GCPKMSProvider`, `AWSKMSProvider`, `AzureKMSProvider`) live in `src/integrations/{gcp,aws,azure}/kms_provider.py` and are imported inside [`signer_factory.py`](../../src/gateway/governance/signer_factory.py) according to `KMS_PROVIDER`. Software providers are refused under an enforcing posture.
  - **Cold storage:** `EvidenceColdStore` backends are selected by `EVIDENCE_COLD_STORE` in [`evidence/factory.py`](../../src/gateway/governance/evidence/factory.py); the GCS and S3 backends live in `src/integrations/storage_gcs/` and `src/integrations/storage_s3/`.

### 2.2 Telemetry Neutrality (OTLP Standard)
All telemetry emitted by the kernel conforms strictly to the OpenTelemetry (OTEL) standard wire protocol:
- Telemetry is exported over standard OTLP/gRPC or OTLP/HTTP.
- The kernel uses generic semantic attributes (`src.gateway.observability.attributes`) without hardcoded proprietary vendor strings.
- Telemetry backends (whether sovereign on-cluster Langfuse, Google Cloud Trace, AWS X-Ray, or Prometheus) ingest standard OTLP streams without requiring kernel code modifications.
- Enforced in CI by Gate G7 (`scripts/check_telemetry_literals.py`).

### 2.3 Vendor-Neutral Protocol Inventory

Every boundary at which CAGE could otherwise acquire a vendor dependency is expressed as a kernel-side `Protocol` or abstract base class. The kernel holds the **contract only**; the concrete client — and therefore the vendor SDK — lives in Layer 3 and is injected at construction or resolved lazily through a factory.

| Boundary | Kernel-side contract | Kernel location | Concrete implementations |
|---|---|---|---|
| Normative baselines / FRIA | `NormativeProvider`, `NormativeBaseline`, `ValidationResult` | [`seams/normative.py`](../../src/gateway/governance/seams/normative.py) | `src/integrations/provider_01/`, `src/integrations/provider_02/` |
| External attestations | `AttestationProvider`, `ExternalAttestation`, `AttestationStatus` | [`seams/attestation.py`](../../src/gateway/governance/seams/attestation.py) | `src/integrations/provider_02/`, `src/integrations/provider_05/` |
| Downstream execution | `ExecutionActuator`, `ExecutionClearance`, `ActuationReceipt` | [`seams/actuation.py`](../../src/gateway/governance/seams/actuation.py) | `src/integrations/actuator_01/` |
| Graph topology inspection | `GraphTopology` | [`seams/graph_topology.py`](../../src/gateway/governance/seams/graph_topology.py) | Domain agent workflows (Layer 2/4) |
| **Outbound tool credentials** | `CredentialBrokerAdapter` plus `CredentialBrokerError` / `CredentialNotFound` / `CredentialAccessDenied` | [`seams/credential_broker.py`](../../src/gateway/governance/seams/credential_broker.py) | Deployment-supplied (vault, workload-identity exchange, cloud secret manager); injected into the actuator as `credential_broker` |
| Evidence cold storage | `EvidenceColdStore`, `ColdStoreReceipt`, `ColdStoreHealth` | [`evidence/cold_store.py`](../../src/gateway/governance/evidence/cold_store.py) | `GcsColdStore` (`src/integrations/storage_gcs/`), `S3ColdStore` (`src/integrations/storage_s3/`), `NullColdStore` ([`evidence/null_cold_store.py`](../../src/gateway/governance/evidence/null_cold_store.py)) (§3) |
| Asymmetric signing (KMS/HSM) | `BaseKMSProvider`, `KMSGovernanceSigner` | [`kms_signer.py`](../../src/gateway/governance/kms_signer.py), [`signer_factory.py`](../../src/gateway/governance/signer_factory.py) | `src/integrations/gcp/kms_provider.py`, `src/integrations/aws/kms_provider.py`, `src/integrations/azure/kms_provider.py`; software Ed25519/HMAC providers for non-enforcing postures only |

#### Credential Broker: Protocol in Layer 1, Secrets Client in Layer 3

The credential broker seam is the newest entry and the one most exposed to vendor gravity — every cloud offers its own secrets product. The invariant is therefore stated explicitly:

- [`credential_broker.py`](../../src/gateway/governance/seams/credential_broker.py) contains **only** a `typing.Protocol` and three exception classes. Its entire import list is `from __future__ import annotations` and `from typing import Protocol`.
- The kernel never imports a secrets SDK (`google-cloud-secret-manager`, `hvac`, `boto3`, `azure-keyvault-secrets`) and never constructs a broker. A broker instance arrives from outside, as the optional `credential_broker` argument to an actuator adapter.
- The contract is expressed in vendor-free vocabulary: a SPIFFE SVID string, a canonical tool name, an optional scope string, and a plain `dict[str, str]` of HTTP headers. No vendor token type, client handle, or credential object crosses the boundary.
- Consequently the seam adds no packaging extra and no import-boundary exception: a kernel built with zero cloud extras still imports and type-checks against `CredentialBrokerAdapter`.
- Swapping secret backends is a deployment-time substitution of the injected object. No kernel file changes.

---

## 3. Evidence Cold Store Contract

Off-cluster durability for the tamper-evident evidence stream (`src/gateway/governance/evidence/`) is abstracted behind the runtime-checkable `EvidenceColdStore` protocol ([`cold_store.py`](../../src/gateway/governance/evidence/cold_store.py)):

```python
@runtime_checkable
class EvidenceColdStore(Protocol):
    @property
    def backend_id(self) -> str: ...  # 'gcs', 's3', 'null'

    async def put_batch(
        self,
        key: str,
        content: bytes,
        metadata: Mapping[str, str] | None = None,
    ) -> ColdStoreReceipt: ...

    async def exists(self, key: str) -> bool: ...

    async def put_if_absent(
        self,
        key: str,
        content: bytes,
        metadata: Mapping[str, str] | None = None,
    ) -> tuple[ColdStoreReceipt, bool]: ...

    def health(self) -> ColdStoreHealth: ...
```

On the GKE reference target the GCS backend writes to the retention-locked WORM bucket (`infra/modules/worm_bucket`), which is the evidence system of record.

### Atomicity & Consistency Model (Atomicity Honesty Table)

Different storage backends offer varying concurrency and atomicity semantics. Deployments must select the storage backend appropriate for their compliance tier:

| Backend | Atomicity Guarantee (`put_if_absent`) | Consistency Model | Known Limitations & Operational Considerations |
|---|---|---|---|
| **Google Cloud Storage (GCS)** | Native atomic compare-and-swap via generation preconditions (`if_generation_match=0`). | Strong consistency globally for object creation and metadata reads. | Requires Workload Identity / ADC and GCP project configuration (`google-cloud-storage`). |
| **AWS S3 / S3-Compatible** | Conditional write via `If-None-Match: *` header (S3 conditional write API). | Strong read-after-write consistency (for all new S3 objects since Dec 2020). | MinIO and S3-compatible endpoints must support `If-None-Match` conditional writes (supported in modern MinIO). Requires `boto3`. |
| **Null Cold Store (Local/Dev)** | In-memory atomic dictionary operations within a single process. | Process-local memory only. | Ephemeral: all data is lost upon process termination. Default when `EVIDENCE_COLD_STORE` is unset. Refuses to construct when `CAGE_ENV=prod` unless `CAGE_ALLOW_NONBLOCKING_PROD=true`. |

---

## 4. Packaging Extras

CAGE packaging in `pyproject.toml` isolates optional cloud and sink dependencies into explicit extras:

- `cybernetic-governance-engine[gateway]`: Core gateway execution requirements (including `google-cloud-kms`, used only by the lazily loaded GCP KMS provider).
- `cybernetic-governance-engine[gcs]`: Google Cloud Storage SDK (`google-cloud-storage`).
- `cybernetic-governance-engine[s3]`: AWS S3 SDK (`boto3`).
- `cybernetic-governance-engine[clickhouse]`: ClickHouse client (`clickhouse-connect`).
- `cybernetic-governance-engine[compliance]`: Full compliance bridge dependencies including storage backends and causal validation (`dowhy`).
- `cybernetic-governance-engine[langfuse]`: Langfuse SDK for the compliance bridge.
- `cybernetic-governance-engine[finance]`: Finance domain market-data dependency (`yfinance`).
- `cybernetic-governance-engine[advisor]`: LangGraph agent and financial advisor tools (pulls in `[finance]`).

CI enforces that the bare kernel imports and executes without any of the cloud extras installed via the `bare-kernel-smoke` workflow job.


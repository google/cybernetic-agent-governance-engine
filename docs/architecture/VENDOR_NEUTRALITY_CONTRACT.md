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
| **Layer 1: Governance Kernel** | `src/gateway/` | Universal dispatch loop, standing assembly, consensus engine, CBF engine, evidence accumulator, routing seals, and audit rails. | **Strictly domain-agnostic and vendor-neutral.** Must NEVER import from Layer 2 (`src/cage_*`), Layer 3 (`src/compliance_bridge/`), or Layer 4 (`src/governed_financial_advisor/`). Must NOT import vendor SDKs (`google.cloud`, `boto3`, `azure`, `langfuse`). Enforced in CI by Gate G3 (`scripts/check_import_boundaries.py`). |
| **Layer 2: Domain Plugins** | `src/cage_{domain}/` (e.g. `src/cage_finance/`, `src/cage_healthcare/`) | Domain-specific tiers (`GovernanceTierPlugin`), domain action registries, ontologies, policies, and causal graphs. | Registers into the kernel via `SymbolicGovernor.register_tier()`. Encapsulates domain vocabulary and semantics without polluting kernel code. |
| **Layer 3: Integrations & Rails** | `src/compliance_bridge/`, `src/integrations/` | External vendor normative/attestation adapters, durable sinks (ClickHouse, GCS, S3), NeMo Guardrails, Langfuse telemetry. | Adheres to the Secure Plugin & Adapter Architecture. Communicates with the kernel exclusively via canonical data structures and contracts. |

---

## 2. Core Neutrality Guarantees

### 2.1 Zero-Vendor-SDK Kernel
The core governance kernel (`src/gateway/`) has zero runtime requirements on proprietary cloud SDKs (`google-cloud-storage`, `boto3`, `azure-storage-blob`, `langfuse`).
- The kernel boots and runs in bare environments (e.g. local developer machine, edge nodes, offline CI).
- Governance decisions, routing seal generation, and CBF state checks execute hermetically without establishing network sockets.
- Cloud-specific capabilities (such as GCP KMS HSM signing or GCS cold storage) are implemented via decoupled adapter interfaces (`KMSGovernanceSigner`, `EvidenceColdStore`) and loaded lazily only when configured.

### 2.2 Telemetry Neutrality (OTLP Standard)
All telemetry emitted by the kernel conforms strictly to the OpenTelemetry (OTEL) standard wire protocol:
- Telemetry is exported over standard OTLP/gRPC or OTLP/HTTP.
- The kernel uses generic semantic attributes (`src.gateway.observability.attributes`) without hardcoded proprietary vendor strings.
- Telemetry backends (whether sovereign on-cluster Langfuse, Google Cloud Trace, AWS X-Ray, or Prometheus) ingest standard OTLP streams without requiring kernel code modifications.
- Enforced in CI by Gate G7 (`scripts/check_telemetry_literals.py`).

---

## 3. Evidence Cold Store Contract

Off-cluster durability for the tamper-evident evidence stream (`src/gateway/governance/evidence/`) is abstracted behind the `EvidenceColdStore` interface:

```python
class EvidenceColdStore(abc.ABC):
    @abc.abstractmethod
    async def put_batch(
        self,
        key: str,
        content: bytes,
        metadata: Mapping[str, str] | None = None,
    ) -> ColdStoreReceipt: ...

    @abc.abstractmethod
    async def put_if_absent(
        self,
        key: str,
        content: bytes,
        metadata: Mapping[str, str] | None = None,
    ) -> tuple[ColdStoreReceipt, bool]: ...

    @abc.abstractmethod
    def health(self) -> ColdStoreHealth: ...
```

### Atomicity & Consistency Model (Atomicity Honesty Table)

Different storage backends offer varying concurrency and atomicity semantics. Deployments must select the storage backend appropriate for their compliance tier:

| Backend | Atomicity Guarantee (`put_if_absent`) | Consistency Model | Known Limitations & Operational Considerations |
|---|---|---|---|
| **Google Cloud Storage (GCS)** | Native atomic compare-and-swap via generation preconditions (`if_generation_match=0`). | Strong consistency globally for object creation and metadata reads. | Requires Workload Identity / ADC and GCP project configuration (`google-cloud-storage`). |
| **AWS S3 / S3-Compatible** | Conditional write via `If-None-Match: *` header (S3 conditional write API). | Strong read-after-write consistency (for all new S3 objects since Dec 2020). | MinIO and S3-compatible endpoints must support `If-None-Match` conditional writes (supported in modern MinIO). Requires `boto3`. |
| **Null Cold Store (Local/Dev)** | In-memory atomic dictionary operations within a single process. | Process-local memory only. | Ephemeral: all data is lost upon process termination. Permitted in dev/test only (`CAGE_ENV=dev`); production requires explicit override. |

---

## 4. Packaging Extras

CAGE packaging in `pyproject.toml` isolates optional cloud and sink dependencies into explicit extras:

- `cybernetic-governance-engine[gateway]`: Core gateway execution requirements.
- `cybernetic-governance-engine[gcs]`: Google Cloud Storage SDK (`google-cloud-storage`).
- `cybernetic-governance-engine[s3]`: AWS S3 SDK (`boto3`).
- `cybernetic-governance-engine[clickhouse]`: ClickHouse client (`clickhouse-connect`).
- `cybernetic-governance-engine[compliance]`: Full compliance bridge dependencies including storage backends and causal validation (`dowhy`).
- `cybernetic-governance-engine[advisor]`: LangGraph agent and financial advisor tools.

CI enforces that the bare kernel imports and executes without any of the cloud extras installed via the `bare-kernel-smoke` workflow job.


# Evidence Stream & Cold Storage Chain

## 1. Architectural Role & Domain Boundary

The Evidence Chain is a core component of the Layer 1 Kernel responsible for maintaining a cryptographically verifiable, durable ledger of all governance and compliance events. It elevates standard application logging into a tamper-evident, hash-chained evidence sequence required by ISO 42001 and AARM compliance mandates.

**Trust Boundaries**:
- **Upstream (Governance Event Bus)**: Accepts execution events, safety evaluations, and audit findings.
- **Downstream (Storage Adapters)**: The Evidence Chain is vendor-agnostic and relies strictly on an abstract `EvidenceColdStore` protocol. Concrete storage operations (GCS, S3) are injected from Layer 3, preventing kernel pollution.

## 2. Data & Execution Flow

To achieve sub-millisecond synchronous latency on the critical path, the Evidence Chain utilizes a two-tiered architecture: high-speed ingestion via Redis Streams, followed by asynchronous background flushing to immutable cold storage.

```mermaid
flowchart TD
    EventBus[GovernanceEventBus.publish()] --> Ingest[EvidenceStreamSink.ingest()]
    
    subgraph Hot Path (Sub-millisecond)
        Ingest --> JCS[JCS Normalization]
        JCS --> Hash[SHA-256 Hash Chaining]
        Hash --> KMS[Optional KMS Signing]
        KMS --> Redis[(Redis Streams\ndb=1, noeviction)]
    end
    
    subgraph Cold Path (Async 60s Interval)
        Redis --> Flush[Cold Store Flush Daemon]
        Flush --> Protocol[EvidenceColdStore Protocol]
    end
    
    Protocol --> Integrations[Layer 3 Integrations\n(GCS / S3)]
```

## 3. State Machine & Lifecycle

The lifecycle of an evidence record spans multiple durability tiers:

- **Ingestion & Normalization**: Incoming payloads are strictly normalized using JCS (JSON Canonicalization Scheme, RFC 8785) to ensure deterministic byte representation.
- **Cryptographic Chaining**: A SHA-256 digest is computed combining the JCS payload and the `prev_hash` of the immediately preceding record, forming an unbroken cryptographically linked list.
- **Hot Storage**: The chained record is appended to a Redis Stream (`cage:evidence:stream`) on `db=1` configured with a `noeviction` policy to guarantee no data loss during burst traffic.
- **Cold Storage Archival**: A background daemon wakes every 60 seconds, reads unacknowledged stream entries, persists them in bulk to the `EvidenceColdStore`, and receives an immutable `ColdStoreReceipt` (containing the final URI and content SHA-256). The entries are then acknowledged and truncated from Redis.

## 4. Operational Guarantees & Edge Cases

- **Fail-Closed on Redis Ingestion**: If the `EvidenceStreamSink` cannot write to Redis (e.g., Redis is down or OOM), the ingestion call fails, bubbling an exception up to the `GovernanceEventBus`. Depending on the caller's configuration, this may block the primary transaction.
- **Fail-Open on Cold Store Flushing**: If the background flush daemon fails to reach GCS/S3, it safely backs off and leaves the records in the Redis Stream. The records are not acknowledged or dropped, preserving them for the next flush attempt.
- **Vendor Decoupling**: The Layer 1 kernel is strictly decoupled from cloud SDKs (like `boto3` or `google-cloud-storage`). It operates entirely on raw bytes and relies on the `ColdStoreReceipt` contract for persistence verification.

## 5. Configuration Contracts & Runtime Matrix

The Evidence Chain is driven by several environment parameters:

- `EVIDENCE_STREAM_ENABLED`: Must be set to `true` to activate ingestion (default: `false`).
- `EVIDENCE_STREAM_REDIS_URL`: Overrides the standard `REDIS_URL` for dedicated evidence ingestion.
- `EVIDENCE_STREAM_REDIS_DB`: The target Redis database (default: `1`).
- `EVIDENCE_STREAM_KEY`: The stream name (default: `cage:evidence:stream`).
- `EVIDENCE_COLD_STORE_FLUSH_SECONDS`: Flush interval in seconds (default: `60`).
- `EVIDENCE_STREAM_KMS_SIGN`: If `true`, enables per-record asynchronous KMS signing before Redis insertion.


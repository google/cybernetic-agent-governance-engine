# Compliance Bridge Module

Deploys the CAGE v0.1.0 ISO 42001 compliance bridge service — a standalone FastAPI microservice providing OSCAL audit ingestion, AARM threat vector conformance reporting, DEFER queue lifecycle management, and a real-time SSE event bus.

## Features

- ✅ FastAPI-based compliance service
- ✅ Langfuse integration (dual-project: governance metrics + compliance audit)
- ✅ Health checks (readiness + liveness probes on `/health`)
- ✅ Configurable resources
- ✅ **AARM Conformance Engine** — 11-vector threat ledger, `GET /v1/aarm/conformance-report`
- ✅ **Cryptographic Context Accumulator** — SHA-256 hash-chained OSCAL audit trail (AARM-V1)
- ✅ **DEFER Queue API** — `GET /v1/defer/pending`, `POST /v1/defer/{id}/inject`, `POST /v1/defer/{id}/escalate`
- ✅ **SSE Event Bus** — `AUDIT_FINDING`, `CONTEXT_CHAIN_SEALED`, `DEFER_PARKING`, `DEFER_RESOLVED`
- ✅ GCS/S3 artifact persistence (context chain NDJSON + AARM conformance JSON)

## Usage

```hcl
module "compliance_bridge" {
  source = "../../modules/compliance_bridge"
  
  namespace     = "my-namespace"
  image         = "gcr.io/my-project/compliance-bridge:latest"
  langfuse_host = module.langfuse.web_url
  redis_url     = "redis://REDACTED@redis-node-0.redis-headless.my-namespace.svc.cluster.local:6379"
}
```

## Inputs

| Name | Description | Default |
|------|-------------|---------|
| namespace | Kubernetes namespace | - |
| image | Container image | - |
| replicas | Number of replicas | 1 |
| langfuse_host | Langfuse URL | "http://langfuse-web:3000" |
| redis_url | Redis URL for DEFER queue (`db=1`, `noeviction` policy required) | "redis://localhost:6379" |

## Outputs

| Name | Description |
|------|-------------|
| endpoint_url | Service URL |

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Service health check |
| `/v1/controls` | GET | List compliance controls (optionally filtered by `?framework=`) |
| `/v1/audit/ingest` | POST | Ingest OSCAL Assessment Results |
| `/v1/audit/status/{audit_id}` | GET | Poll audit status |
| `/v1/oscal/assessment-results` | GET | Export OSCAL Assessment Results (JSON/YAML) |
| `/v1/metrics/summary` | GET | Aggregate compliance metrics |
| `/v1/metrics/{control_id}` | GET | Per-control metrics |
| `/v1/aarm/conformance-report` | GET | **AARM 11-vector Conformance Report Card** |
| `/v1/defer/pending` | GET | List parked DEFER tokens |
| `/v1/defer/{id}/inject` | POST | Resolve DEFER token via data injection |
| `/v1/defer/{id}/escalate` | POST | Escalate DEFER token to MANUAL_REVIEW |
| `/v1/events/stream` | GET | SSE real-time event stream |

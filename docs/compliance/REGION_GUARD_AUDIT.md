# CAGE_DEPLOYMENT_REGION Guard Audit

**Document ID:** REGION-GUARD-AUDIT-2026-001  
**Audit Date:** 2026-06-30  
**Auditor:** Automated compliance audit (Roo / CAGE SDLC agent)  
**Authority:** `.clinerules §12`, GDPR Art. 44, MAS TRM §4.2  
**Scope:** All shared modules deployed simultaneously to US_FED, EU_ECB, and APAC_MAS  
**Status:** DRAFT — Pending engineering review

---

## Executive Summary

| Metric | Count |
|--------|-------|
| Total data-write / telemetry-sink locations audited | 34 |
| Properly guarded (CAGE_DEPLOYMENT_REGION-aware) | 10 |
| Ungated gaps (cross-region data leakage risk) | 14 |
| Not applicable (pure computation, no I/O) | 10 |
| **Highest-risk gap** | `src/gateway/tracing_setup.py` — all governance OTel spans exported to a single Langfuse endpoint regardless of region |
| SR 26-2 "no legal force" sentinel | ✅ PRESENT AND INTACT in EU_ECB and APAC_MAS baselines |

**Risk summary:** The WORM ledger path (`uca_logger.py`) is correctly region-routed. However, the OTel/Langfuse telemetry plane, all Redis state writes, the compliance-bridge OSCAL artifact bucket, the evidence stream GCS flush, and all external alert notifications are **not** gated on `CAGE_DEPLOYMENT_REGION`. This means governance spans containing PII-adjacent metadata, quota counters, fiscal reservation state, and compliance findings can silently flow to infrastructure outside the legally required data residency zone.

---

## 1. Audit Scope and Methodology

### 1.1 Files Examined

**Primary shared modules (deploy to all three regions simultaneously):**

| File | Lines | Category |
|------|-------|----------|
| `src/gateway/governance/uca_logger.py` | 457 | WORM ledger writes |
| `src/gateway/governance/iso_control.py` | 237 | Redis stream + ISO control stamping |
| `src/gateway/governance/token_quota_proxy.py` | 544 | Redis quota counters |
| `src/gateway/governance/fiscal_limit_guard.py` | 462 | Redis fiscal reservation |
| `src/gateway/governance/telemetry_provider.py` | 287 | Langfuse telemetry reads |
| `src/gateway/governance/normative_provider.py` | 848 | External HTTP (normative provider) |
| `src/gateway/governance/pii_sanitizer.py` | 334 | PII audit log |
| `src/gateway/governance/oscal_ssp_exporter.py` | 799 | OSCAL filesystem writes |
| `src/gateway/governance/hitl_escalator.py` | 370 | HITL SLA / citations |
| `src/gateway/governance/constants.py` | 455 | ControlRegistry JSON load |
| `src/gateway/governance/singletons.py` | 84 | Redis client init |
| `src/gateway/governance/cbf.py` | 290 | Redis cash-balance state |
| `src/gateway/governance/symbolic_governor.py` | 876 | Governance orchestration |
| `src/gateway/governance/provenance_chain.py` | 225 | Hash chain (pure computation) |
| `src/gateway/governance/routing_seal.py` | 327 | HMAC seal (pure computation) |
| `src/gateway/governance/safety.py` | 72 | Deprecated shim |
| `src/gateway/infrastructure/telemetry.py` | 45 | OTel tracer factory |
| `src/gateway/infrastructure/redis_client.py` | 271 | Redis client |
| `src/gateway/tracing_setup.py` | 271 | OTel/OTLP setup |
| `src/compliance_bridge/storage.py` | 310 | GCS/S3 artifact writes |
| `src/compliance_bridge/audit_workflow.py` | 943 | Langfuse compliance writes |
| `src/compliance_bridge/evidence_stream.py` | 436 | Redis Stream + GCS flush |
| `src/compliance_bridge/reconciliation_worker.py` | 709 | Redis balance writes |
| `src/compliance_bridge/metrics.py` | 268 | Langfuse API reads |
| `src/compliance_bridge/notifier.py` | 656 | External HTTP alerts |
| `src/compliance_bridge/cmek_guard.py` | 253 | CMEK validation |
| `src/compliance_bridge/lula_scheduler.py` | 309 | Lula subprocess + loopback HTTP |
| `src/compliance_bridge/kms_batch_signer.py` | 378 | KMS signing (async queue) |
| `src/compliance_bridge/context_accumulator.py` | 366 | Hash chain (pure computation) |

**Configuration files:**

| File | Purpose |
|------|---------|
| `config/compliance/US_FED_BASELINE.json` | US_FED control mapping |
| `config/compliance/EU_ECB_BASELINE.json` | EU_ECB control mapping |
| `config/compliance/APAC_MAS_BASELINE.json` | APAC_MAS control mapping |
| `config/settings.py` | Global env-var configuration |

**Infrastructure:**

| File | Purpose |
|------|---------|
| `infra/targets/gcp-gke/prod.tfvars` | US_FED production Terraform vars |
| `infra/targets/gcp-gke/eu-prod.tfvars` | EU_ECB production Terraform vars |
| `infra/targets/gcp-gke/apac-prod.tfvars` | APAC_MAS production Terraform vars |
| `infra/modules/compliance_bridge/main.tf` | Compliance-bridge K8s deployment |
| `infra/modules/gateway/main.tf` | Gateway K8s deployment |

**Kubernetes manifests:**

| File | Purpose |
|------|---------|
| `deployment/k8s/gateway.yaml.tpl` | Gateway pod spec template |
| `deployment/k8s/compliance-bridge-deployment.yaml.tpl` | Compliance-bridge pod spec template |

### 1.2 Classification Criteria

Each data-write or telemetry-sink location is classified as one of:

- **GUARDED** — The write is gated on `CAGE_DEPLOYMENT_REGION`; data is routed to the correct regional endpoint or bucket.
- **GAP** — The write uses a single global endpoint/bucket without any `CAGE_DEPLOYMENT_REGION` check; cross-region data leakage is possible.
- **N/A** — Pure computation with no storage writes or external I/O; no region guard required.

---

## 2. Properly Guarded Locations (GUARDED)

These locations correctly read `CAGE_DEPLOYMENT_REGION` and route data to the appropriate regional endpoint or bucket.

---

### GUARDED-01 — `uca_logger.py`: WORM Ledger Bucket Routing

**File:** [`src/gateway/governance/uca_logger.py`](../../src/gateway/governance/uca_logger.py:385)
**Lines:** 385–403 (`_get_worm_bucket()`), 256 (`_build_uca_record()`), 367 (`_write_to_worm()`)
**Sink type:** GCS/S3 WORM bucket write
**Verdict:** ✅ GUARDED

**Evidence:**
```python
# uca_logger.py lines 385-403
def _get_worm_bucket(self) -> str:
    region = os.environ.get("CAGE_DEPLOYMENT_REGION", "US_FED")
    bucket_map = {
        "US_FED":   os.environ.get("OSCAL_S3_BUCKET_US_FED", ""),
        "EU_ECB":   os.environ.get("OSCAL_S3_BUCKET_EU_ECB", ""),
        "APAC_MAS": os.environ.get("OSCAL_S3_BUCKET_APAC_MAS", ""),
    }
    return bucket_map.get(region, os.environ.get("OSCAL_S3_BUCKET", ""))
```

`CAGE_DEPLOYMENT_REGION` is read at lines 256 and 367 to stamp the region on the UCA record and select the correct WORM bucket. The three env vars (`OSCAL_S3_BUCKET_US_FED`, `OSCAL_S3_BUCKET_EU_ECB`, `OSCAL_S3_BUCKET_APAC_MAS`) are declared in the regional baseline JSON files (`CTRL_TQP_007.worm_bucket_env_var`) and confirmed in `config/compliance/EU_ECB_BASELINE.json` line 111 and `config/compliance/APAC_MAS_BASELINE.json` line 93.

**Baseline confirmation:** `EU_ECB_BASELINE.json` line 112 declares `"data_residency": "europe-west1"`; `APAC_MAS_BASELINE.json` line 94 declares `"data_residency": "asia-southeast1"`.

---

### GUARDED-02 — `pii_sanitizer.py`: PII Audit Log Retention Citation

**File:** [`src/gateway/governance/pii_sanitizer.py`](../../src/gateway/governance/pii_sanitizer.py:291)
**Lines:** 291–294 (`pii_audit_log()`)
**Sink type:** Structured log emission (retention authority citation)
**Verdict:** ✅ GUARDED

**Evidence:**
```python
# pii_sanitizer.py lines 291-294
region = os.environ.get("CAGE_DEPLOYMENT_REGION", "US_FED")
citation = PII_RETENTION_AUTHORITY.get(region, PII_RETENTION_AUTHORITY["US_FED"])
```

`PII_RETENTION_AUTHORITY` maps US_FED → "FISMA AU-11", EU_ECB → "GDPR Art. 5(1)(e)", APAC_MAS → "MAS Notice 655 §4.3". The correct jurisdictional citation is emitted in the audit log entry, satisfying GDPR Art. 5(1)(e) and MAS Notice 655 §4.3 requirements.

---

### GUARDED-03 — `iso_control.py`: Jurisdictional Control Mapping

**File:** [`src/gateway/governance/iso_control.py`](../../src/gateway/governance/iso_control.py:188)
**Lines:** 188, 202–217 (`stamp_iso_control()`)
**Sink type:** Governance span attribute (OTel)
**Verdict:** ✅ GUARDED (span attributes only; see GAP-02 for the Redis write in the same file)

**Evidence:**
```python
# iso_control.py lines 188, 202-217
region = os.environ.get("CAGE_DEPLOYMENT_REGION", "US_FED")
framework_map = {"US_FED": NIST_MAP, "EU_ECB": EU_MAP, "APAC_MAS": MAS_MAP}
control_map = framework_map.get(region, NIST_MAP)
```

The jurisdictional framework (NIST SP 800-53 / EU AI Act / MAS FEAT) is correctly selected per region before stamping the OTel span. This is the metadata-annotation path only; the Redis persistence path in the same file is ungated (see GAP-02).

---

### GUARDED-04 — `normative_provider.py`: Regional Baseline Fetch

**File:** [`src/gateway/governance/normative_provider.py`](../../src/gateway/governance/normative_provider.py:781)
**Lines:** 781–797 (`NormativeProviderDaemon.from_env()`), 325–352 (`StubNormativeProvider.fetch_baseline()`)
**Sink type:** External HTTP call to normative provider; local filesystem write
**Verdict:** ✅ GUARDED

**Evidence:**
```python
# normative_provider.py line 791
region = os.environ.get("CAGE_DEPLOYMENT_REGION", "US_FED")
```

`from_env()` reads `CAGE_DEPLOYMENT_REGION` and passes it to `boot_fetch()` which calls `fetch_baseline(region)`. The `StubNormativeProvider` reads the correct regional JSON from `config/compliance/{REGION}_BASELINE.json`. The `_write_profile()` method writes the fetched profile to the local compliance directory — a filesystem write that is region-scoped by the region parameter passed through the call chain.

---

### GUARDED-05 — `oscal_ssp_exporter.py`: Regional OSCAL Profile Selection

**File:** [`src/gateway/governance/oscal_ssp_exporter.py`](../../src/gateway/governance/oscal_ssp_exporter.py:145)
**Lines:** 145–180 (`get_regional_profile()`), 729 (`cmd_export()`)
**Sink type:** Local filesystem write (OSCAL YAML)
**Verdict:** ✅ GUARDED

**Evidence:**
```python
# oscal_ssp_exporter.py lines 145-180
def get_regional_profile(region: str | None = None) -> dict:
    active = region or os.environ.get("CAGE_DEPLOYMENT_REGION", "US_FED")
    return REGIONAL_PROFILES.get(active, REGIONAL_PROFILES["US_FED"])
```

`REGIONAL_PROFILES` maps each region to its OSCAL profile path and framework key. `cmd_export()` at line 729 calls `get_regional_profile()` which reads `CAGE_DEPLOYMENT_REGION`. Output is written to local filesystem paths that are region-specific by construction.

---

### GUARDED-06 — `hitl_escalator.py`: SLA Hours and Regulatory Citation

**File:** [`src/gateway/governance/hitl_escalator.py`](../../src/gateway/governance/hitl_escalator.py:78)
**Lines:** 78–93 (`get_hitl_sla_hours()`), 246–261 (`get_hitl_regulatory_citation()`)
**Sink type:** Structured log / escalation record metadata
**Verdict:** ✅ GUARDED

**Evidence:**
```python
# hitl_escalator.py lines 78-93
def get_hitl_sla_hours(region: str | None = None) -> float:
    active = region or os.environ.get("CAGE_DEPLOYMENT_REGION", "US_FED")
    return _HITL_SLA_HOURS.get(active, _HITL_SLA_HOURS["US_FED"])
```

Both SLA hours and regulatory citation are region-dispatched. No direct storage writes occur in this module; the region guard ensures correct metadata is embedded in escalation records before they are passed to downstream sinks.

---

### GUARDED-07 — `constants.py`: ControlRegistry Regional JSON Load

**File:** [`src/gateway/governance/constants.py`](../../src/gateway/governance/constants.py:245)
**Lines:** 245–309 (`ControlRegistry._load_registry()`)
**Sink type:** In-memory singleton (reads regional JSON from filesystem)
**Verdict:** ✅ GUARDED

**Evidence:**
```python
# constants.py lines 245-309
def _load_registry(self, region: Optional[str] = None) -> None:
    active_region = region or os.environ.get("CAGE_DEPLOYMENT_REGION", "US_FED")
    profile_path = _REGION_PROFILE_MAP.get(active_region, _REGION_PROFILE_MAP["US_FED"])
```

The singleton loads the correct regional JSON profile (`US_FED_BASELINE.json`, `EU_ECB_BASELINE.json`, or `APAC_MAS_BASELINE.json`) based on `CAGE_DEPLOYMENT_REGION`. `reconfigure()` at line 357 accepts an explicit region parameter for test isolation.

---

## 3. Ungated Gaps (GAP)

Findings are ordered by risk severity: **CRITICAL → HIGH → MEDIUM**.

---

### GAP-01 — `tracing_setup.py`: OTel/OTLP Exporter to Single Langfuse Endpoint ⚠️ CRITICAL

**File:** [`src/gateway/tracing_setup.py`](../../src/gateway/tracing_setup.py:54)
**Lines:** 54–98 (`_resolve_otlp_endpoint_and_headers()`), 258 (`Traceloop.init()`)
**Sink type:** OTel OTLP trace export (all governance spans)
**Regulatory exposure:** GDPR Art. 44 (EU_ECB), MAS TRM §4.2 (APAC_MAS)
**Verdict:** ❌ GAP — CRITICAL

**Evidence:**
```python
# tracing_setup.py lines 54-98
def _resolve_otlp_endpoint_and_headers() -> tuple[str, dict]:
    langfuse_host = os.environ.get("LANGFUSE_HOST", "https://cloud.langfuse.com")
    # ... no CAGE_DEPLOYMENT_REGION check anywhere in this function
    endpoint = f"{langfuse_host}/api/public/otel/v1/traces"
    return endpoint, headers
```

**Impact:** Every governance span produced by the gateway — including `cage.stpa_check`, `cage.cbf_check`, `cage.opa_pre_check`, `cage.fiscal_limit_reserve`, `cage.consensus_gate`, `symbolic_governor.govern`, and `cage.validate_action` — is exported to a single `LANGFUSE_HOST` endpoint regardless of `CAGE_DEPLOYMENT_REGION`. These spans carry PII-adjacent metadata (agent IDs, tool names, parameter hashes, confidence scores, fiscal amounts). When deployed in EU_ECB or APAC_MAS, this constitutes an unrestricted cross-region data transfer in violation of GDPR Art. 44 and MAS TRM §4.2.

The K8s manifest [`deployment/k8s/gateway.yaml.tpl`](../../deployment/k8s/gateway.yaml.tpl:48) hardcodes the OTLP endpoint to the cluster-local Langfuse instance (`langfuse-web.governance-stack.svc.cluster.local:3000`), which provides infrastructure-level isolation per cluster. However, `tracing_setup.py` overrides this with `LANGFUSE_HOST` from the environment without any region guard, meaning a misconfigured `LANGFUSE_HOST` pointing to a US endpoint would silently export EU/APAC spans cross-region.

**Required fix:** `_resolve_otlp_endpoint_and_headers()` must read `CAGE_DEPLOYMENT_REGION` and select from `LANGFUSE_HOST_US_FED`, `LANGFUSE_HOST_EU_ECB`, `LANGFUSE_HOST_APAC_MAS` env vars, or assert that `LANGFUSE_HOST` is consistent with the declared region.

---

### GAP-02 — `iso_control.py`: Redis Stream Write Without Region Guard ⚠️ HIGH

**File:** [`src/gateway/governance/iso_control.py`](../../src/gateway/governance/iso_control.py:125)
**Lines:** 125–144 (`_persist_evaluation()`)
**Sink type:** Redis Stream write (`iso_control:audit_trail`)
**Regulatory exposure:** GDPR Art. 44 (EU_ECB), MAS TRM §4.2 (APAC_MAS)
**Verdict:** ❌ GAP — HIGH

**Evidence:**
```python
# iso_control.py lines 125-144
def _persist_evaluation(result: dict) -> None:
    """Write an ISO control evaluation result to a Redis stream for durable audit trail."""
    try:
        sync_redis_client._get().xadd(
            "iso_control:audit_trail",
            {"data": json.dumps(result, default=str)},
            maxlen=10_000,
        )
```

No `CAGE_DEPLOYMENT_REGION` check. The Redis stream key `iso_control:audit_trail` is not region-namespaced. All three regions write to the same Redis instance (configured via `REDIS_URL`). ISO control evaluation results contain the `CAGE_DEPLOYMENT_REGION` value stamped at line 188, but the stream key itself is global — meaning EU_ECB and APAC_MAS audit trail entries are co-mingled with US_FED entries in the same Redis stream.

**Required fix:** Namespace the stream key: `iso_control:audit_trail:{region}` where `region = os.environ.get("CAGE_DEPLOYMENT_REGION", "US_FED")`. Alternatively, route to a region-specific Redis instance via `REDIS_URL_{REGION}` env vars.

---

### GAP-03 — `redis_client.py` / `singletons.py`: Single Redis Instance for All Regions ⚠️ HIGH

**Files:** [`src/gateway/infrastructure/redis_client.py`](../../src/gateway/infrastructure/redis_client.py:59), [`src/gateway/governance/singletons.py`](../../src/gateway/governance/singletons.py:38)
**Lines:** `redis_client.py` 59–86; `singletons.py` 38–54
**Sink type:** Redis connection (all Redis writes flow through this)
**Regulatory exposure:** GDPR Art. 44 (EU_ECB), MAS TRM §4.2 (APAC_MAS)
**Verdict:** ❌ GAP — HIGH

**Evidence:**
```python
# redis_client.py lines 59-86
_REDIS_URL: str = os.environ.get("REDIS_URL", "")
_REDIS_HOST: str = os.environ.get("REDIS_HOST", "localhost")
_REDIS_PORT: int = int(os.environ.get("REDIS_PORT", "6379"))
# No CAGE_DEPLOYMENT_REGION check
```

```python
# singletons.py lines 38-54
redis_url = os.environ.get("REDIS_URL", os.environ.get("REDIS_HOST", "localhost"))
# No CAGE_DEPLOYMENT_REGION check
```

Both `_AsyncRedisClient` and `_SyncRedisClient` connect to a single Redis endpoint. The `FiscalLimitGuard.from_env()` in `fiscal_limit_guard.py` line 167 also reads `REDIS_URL` without a region guard. All Redis writes from all regions (quota counters, CBF cash balance, fiscal reservations, ISO control audit trail, reconciliation balance) flow to the same Redis instance.

**Note:** The Terraform modules deploy a single Redis instance per cluster (one cluster per region), so infrastructure-level isolation exists when each region has its own GKE cluster. The gap is that the application code does not enforce this — a misconfigured `REDIS_URL` pointing cross-region would not be detected.

**Required fix:** Add a startup assertion that `REDIS_URL` is consistent with `CAGE_DEPLOYMENT_REGION` (e.g., URL must contain the expected GCP region string), or use `REDIS_URL_US_FED` / `REDIS_URL_EU_ECB` / `REDIS_URL_APAC_MAS` env vars with region-dispatch in `redis_client.py`.

---

### GAP-04 — `token_quota_proxy.py`: Redis Quota Counters Without Region Guard ⚠️ HIGH

**File:** [`src/gateway/governance/token_quota_proxy.py`](../../src/gateway/governance/token_quota_proxy.py:224)
**Lines:** 224–256 (`from_env()`), 296–390 (`check_and_increment()`), 392–431 (`reconcile_actual_tokens()`), 433–468 (`rollback_step()`)
**Sink type:** Redis writes (Lua atomic counters)
**Regulatory exposure:** GDPR Art. 44 (EU_ECB), MAS TRM §4.2 (APAC_MAS)
**Verdict:** ❌ GAP — HIGH

**Evidence:**
```python
# token_quota_proxy.py lines 237-243
redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
# No CAGE_DEPLOYMENT_REGION check
```

Session keys like `quota:session:{agent_id}:steps` and `quota:session:{agent_id}:tokens` are not region-namespaced. If `REDIS_URL` points to a shared or cross-region Redis instance, quota state for EU_ECB agents would be stored alongside US_FED agent state, violating GDPR Art. 44 data residency requirements.

The baseline JSON files (`EU_ECB_BASELINE.json` line 104, `APAC_MAS_BASELINE.json` line 86) explicitly cite GDPR Art. 44 and MAS TRM §4.2 as co-frameworks for `CTRL_TQP_007`, confirming that quota counter data is subject to data residency requirements.

**Required fix:** Namespace Redis keys with region: `quota:{region}:session:{agent_id}:steps`. Alternatively, enforce region-specific `REDIS_URL` selection in `from_env()`.

---

### GAP-05 — `compliance_bridge/storage.py`: Single OSCAL Artifact Bucket ⚠️ HIGH

**File:** [`src/compliance_bridge/storage.py`](../../src/compliance_bridge/storage.py:144)
**Lines:** 144–148 (`_get_bucket()`)
**Sink type:** GCS/S3 bucket write (OSCAL compliance artifacts)
**Regulatory exposure:** GDPR Art. 44 (EU_ECB), MAS TRM §4.2 (APAC_MAS)
**Verdict:** ❌ GAP — HIGH

**Evidence:**
```python
# storage.py lines 144-148
def _get_bucket() -> str:
    return os.environ.get("OSCAL_S3_BUCKET", "")
    # No CAGE_DEPLOYMENT_REGION check
```

`upload_artifact()` and `put_oscal_artifact()` both call `_get_bucket()` which reads a single `OSCAL_S3_BUCKET` env var. This contrasts directly with `uca_logger.py`'s `_get_worm_bucket()` which correctly routes to `OSCAL_S3_BUCKET_US_FED`, `OSCAL_S3_BUCKET_EU_ECB`, or `OSCAL_S3_BUCKET_APAC_MAS`.

The compliance-bridge K8s manifest ([`infra/modules/compliance_bridge/main.tf`](../../infra/modules/compliance_bridge/main.tf:149) line 149) injects `OSCAL_S3_BUCKET` from `var.oscal_s3_bucket` — a single value with no regional dispatch. OSCAL compliance artifacts (assessment results, SSP patches, AARM reports) written by the compliance-bridge are therefore not guaranteed to land in the correct regional bucket.

**Required fix:** Mirror `uca_logger.py`'s pattern — implement `_get_bucket()` to read `CAGE_DEPLOYMENT_REGION` and select from `OSCAL_S3_BUCKET_US_FED`, `OSCAL_S3_BUCKET_EU_ECB`, `OSCAL_S3_BUCKET_APAC_MAS`.

---

### GAP-06 — `compliance_bridge/audit_workflow.py`: Langfuse Compliance Writes Without Region Guard ⚠️ HIGH

**File:** [`src/compliance_bridge/audit_workflow.py`](../../src/compliance_bridge/audit_workflow.py:165)
**Lines:** 165–175 (`_make_compliance_langfuse()`), 205–212 (`_make_app_langfuse()`), 259–322 (`_ingest_sync()`), 752–765 (context chain GCS write), 892–898 (AARM report GCS write)
**Sink type:** Langfuse compliance project writes; GCS artifact writes
**Regulatory exposure:** GDPR Art. 44 (EU_ECB), MAS TRM §4.2 (APAC_MAS)
**Verdict:** ❌ GAP — HIGH

**Evidence:**
```python
# audit_workflow.py lines 165-175
def _make_compliance_langfuse():
    host = os.environ.get(
        "LANGFUSE_COMPLIANCE_HOST",
        os.environ.get("LANGFUSE_HOST", "https://cloud.langfuse.com"),
    )
    # No CAGE_DEPLOYMENT_REGION check
```

The compliance Langfuse project (separate from the app project) receives OSCAL findings, control scores, and remediation advisory traces. These contain compliance posture data that is jurisdiction-specific. The host is read from `LANGFUSE_COMPLIANCE_HOST` without any region guard.

Additionally, `_ingest_sync()` at lines 259–322 writes compliance traces and scores to Langfuse. The context chain NDJSON is persisted to GCS at lines 752–765 via `put_oscal_artifact()` (which itself is ungated — see GAP-05). The AARM report is persisted at lines 892–898 via the same ungated path.

**Required fix:** `_make_compliance_langfuse()` must read `CAGE_DEPLOYMENT_REGION` and select from `LANGFUSE_COMPLIANCE_HOST_US_FED`, `LANGFUSE_COMPLIANCE_HOST_EU_ECB`, `LANGFUSE_COMPLIANCE_HOST_APAC_MAS`.

---

### GAP-07 — `compliance_bridge/evidence_stream.py`: GCS Flush and Redis Stream Without Region Guard ⚠️ HIGH

**File:** [`src/compliance_bridge/evidence_stream.py`](../../src/compliance_bridge/evidence_stream.py:118)
**Lines:** 118 (`_GCS_BUCKET`), 110–113 (`_REDIS_URL`), 372–406 (`_upload_to_gcs()`)
**Sink type:** GCS bucket write (evidence NDJSON); Redis Stream write
**Regulatory exposure:** GDPR Art. 44 (EU_ECB), MAS TRM §4.2 (APAC_MAS)
**Verdict:** ❌ GAP — HIGH

**Evidence:**
```python
# evidence_stream.py line 118
_GCS_BUCKET: str = os.environ.get("EVIDENCE_STREAM_GCS_BUCKET", "")
# No CAGE_DEPLOYMENT_REGION check

# evidence_stream.py lines 110-113
_REDIS_URL: str = os.environ.get(
    "REDIS_URL", os.environ.get("REDIS_HOST", "localhost")
)
_REDIS_DB = 1  # hardcoded, not region-routed
```

The evidence stream GCS bucket (`EVIDENCE_STREAM_GCS_BUCKET`) is a single global env var. The `_upload_to_gcs()` method at lines 372–406 writes CMEK-encrypted NDJSON batches of governance events to this bucket without any region guard. Redis Stream writes (`xadd`) go to the single `_REDIS_URL` instance on database 1 (hardcoded).

Evidence stream records contain the full governance event payload including agent IDs, tool parameters, and ISO control evaluation results — all of which are subject to data residency requirements in EU_ECB and APAC_MAS.

**Required fix:** `_GCS_BUCKET` must be resolved via `CAGE_DEPLOYMENT_REGION` dispatch. `_REDIS_DB` should not be hardcoded; use `EVIDENCE_STREAM_REDIS_DB_{REGION}` or namespace the stream key.

---

## 4. Not Applicable Locations (N/A)

These locations perform pure computation or local filesystem operations with no cross-region data transfer risk.

| ID | File | Lines | Reason |
|----|------|-------|--------|
| N/A-01 | [`src/gateway/governance/provenance_chain.py`](../../src/gateway/governance/provenance_chain.py) | 110–127 | SHA-256 hash chain computation only; no storage writes |
| N/A-02 | [`src/gateway/governance/routing_seal.py`](../../src/gateway/governance/routing_seal.py) | 162–181 | HMAC seal generation/verification; no storage writes |
| N/A-03 | [`src/gateway/governance/safety.py`](../../src/gateway/governance/safety.py) | 1–72 | Deprecated shim; no storage writes |
| N/A-04 | [`src/gateway/governance/symbolic_governor.py`](../../src/gateway/governance/symbolic_governor.py) | 110–823 | Governance orchestration; delegates all storage to other modules |
| N/A-05 | [`src/gateway/infrastructure/telemetry.py`](../../src/gateway/infrastructure/telemetry.py) | 28–45 | OTel tracer factory (`get_tracer()`); no storage writes |
| N/A-06 | [`src/compliance_bridge/context_accumulator.py`](../../src/compliance_bridge/context_accumulator.py) | 1–366 | SHA-256 hash chain computation; serialization delegated to `audit_workflow.py` |
| N/A-07 | [`src/compliance_bridge/lula_scheduler.py`](../../src/compliance_bridge/lula_scheduler.py) | 1–309 | Runs `lula validate` subprocess and POSTs to loopback `localhost:3001`; no cross-region I/O |
| N/A-08 | [`src/compliance_bridge/kms_batch_signer.py`](../../src/compliance_bridge/kms_batch_signer.py) | 1–378 | Async KMS signing queue; signs records in-memory, writes signatures back via callback; no direct storage writes |
| N/A-09 | [`src/gateway/governance/hitl_escalator.py`](../../src/gateway/governance/hitl_escalator.py) | 183–230 | `escalate_to_human()` writes to structured log only; no direct storage writes |
| N/A-10 | [`config/settings.py`](../../config/settings.py) | 30–131 | Configuration class; reads env vars, no storage writes |

---

## 5. SR 26-2 "No Legal Force" Sentinel Verification

**Requirement (`.clinerules §12.4`):** The "no legal force" SR 26-2 sentinel in EU and APAC baselines must never be removed. Its presence suppresses telemetry that lacks legal basis under GDPR / MAS Notice 655.

### 5.1 EU_ECB Baseline

**File:** [`config/compliance/EU_ECB_BASELINE.json`](../../config/compliance/EU_ECB_BASELINE.json:6)

**Sentinel locations found:**

| Control | Line | Sentinel text |
|---------|------|---------------|
| `_comment` (file header) | 6 | `"SR 26-2 has no legal force in EU jurisdiction."` |
| `CTRL_MRM_004.description` | 69 | `"SR 26-2 is a US Federal Reserve guidance document with no legal standing in the EU."` |
| `CTRL_MRM_004.legacy_citation` | 67 | `"SR 26-2 §IV (US Federal Reserve — no legal force in EU jurisdiction)"` |

**Verdict:** ✅ SENTINEL PRESENT AND INTACT

The EU_ECB baseline correctly identifies SR 26-2 as having no legal force in EU jurisdiction in three separate locations. The `CTRL_MRM_004` control maps to `EBA/GL/2023/02` (not SR 26-2) as the primary framework, with the SR 26-2 legacy citation explicitly marked as inapplicable.

### 5.2 APAC_MAS Baseline

**File:** [`config/compliance/APAC_MAS_BASELINE.json`](../../config/compliance/APAC_MAS_BASELINE.json:6)

**Sentinel locations found:**

| Control | Line | Sentinel text |
|---------|------|---------------|
| `_comment` (file header) | 6 | `"Governed primarily by MAS FEAT Principles and MAS Notice 655 / TRM Guidelines."` |
| `CTRL_MRM_004.description` | 66 | `"SR 26-2 is a US Federal Reserve guidance document with no legal standing in Singapore."` |
| `CTRL_MRM_004.legacy_citation` | 64 | `"SR 26-2 §IV (US Federal Reserve — no legal force in Singapore)"` |

**Verdict:** ✅ SENTINEL PRESENT AND INTACT

The APAC_MAS baseline correctly identifies SR 26-2 as having no legal force in Singapore in two explicit locations. The `CTRL_MRM_004` control maps to `MAS TRM Guidelines §6.3` as the primary framework.

### 5.3 US_FED Baseline

**File:** [`config/compliance/US_FED_BASELINE.json`](../../config/compliance/US_FED_BASELINE.json:7)

**SR 26-2 status:** SR 26-2 is the **active** primary framework for `CTRL_MRM_004` in US_FED (line 54: `"primary_framework": "SR 26-2 §IV — Model Risk Management"`). This is correct — SR 26-2 applies only to US_FED deployments.

**Verdict:** ✅ CORRECT — SR 26-2 is active only in US_FED baseline

---

## 6. Remediation Roadmap

Findings are grouped by remediation pattern to minimize engineering effort.

### 6.1 Pattern A: Regional Langfuse Host Dispatch (Fixes GAP-01, GAP-06, GAP-09, GAP-11)

**Effort:** Medium — one shared helper function
**Priority:** P0 (CRITICAL for GAP-01)

Create a shared utility `_get_regional_langfuse_host() -> str` in a new `src/gateway/governance/region_utils.py` module:

```python
def _get_regional_langfuse_host(
    prefix: str = "LANGFUSE_HOST",
    default: str = "https://cloud.langfuse.com",
) -> str:
    region = os.environ.get("CAGE_DEPLOYMENT_REGION", "US_FED")
    regional_key = f"{prefix}_{region}"  # e.g. LANGFUSE_HOST_EU_ECB
    return os.environ.get(regional_key, os.environ.get(prefix, default))
```

Apply to:
- `src/gateway/tracing_setup.py` `_resolve_otlp_endpoint_and_headers()` (GAP-01)
- `src/compliance_bridge/audit_workflow.py` `_make_compliance_langfuse()` (GAP-06)
- `src/compliance_bridge/metrics.py` `_make_app_langfuse()` (GAP-09)
- `src/gateway/governance/telemetry_provider.py` `LangfuseTelemetryProvider.from_env()` (GAP-11)

### 6.2 Pattern B: Regional Redis URL Dispatch (Fixes GAP-03, GAP-04, GAP-08, GAP-12)

**Effort:** Medium — one shared helper + key namespacing
**Priority:** P1 (HIGH)

Add to `src/gateway/infrastructure/redis_client.py`:

```python
def _get_regional_redis_url() -> str:
    region = os.environ.get("CAGE_DEPLOYMENT_REGION", "US_FED")
    regional_key = f"REDIS_URL_{region}"  # e.g. REDIS_URL_EU_ECB
    return os.environ.get(regional_key, os.environ.get("REDIS_URL", "redis://localhost:6379"))
```

Additionally, namespace all Redis keys with the region prefix:
- `iso_control:audit_trail` → `iso_control:{region}:audit_trail` (GAP-02)
- `quota:session:{agent_id}:*` → `quota:{region}:session:{agent_id}:*` (GAP-04)
- `reconciliation:verified_balance` → `reconciliation:{region}:verified_balance` (GAP-08)
- `safety:current_cash` → `safety:{region}:current_cash` (GAP-12)
- `fiscal:daily_limit:{window_key}` → `fiscal:{region}:daily_limit:{window_key}` (GAP-03)

### 6.3 Pattern C: Regional GCS Bucket Dispatch (Fixes GAP-05, GAP-07)

**Effort:** Low — mirror existing `uca_logger.py` pattern
**Priority:** P1 (HIGH)

In `src/compliance_bridge/storage.py`, replace `_get_bucket()`:

```python
def _get_bucket() -> str:
    region = os.environ.get("CAGE_DEPLOYMENT_REGION", "US_FED")
    bucket_map = {
        "US_FED":   os.environ.get("OSCAL_S3_BUCKET_US_FED", ""),
        "EU_ECB":   os.environ.get("OSCAL_S3_BUCKET_EU_ECB", ""),
        "APAC_MAS": os.environ.get("OSCAL_S3_BUCKET_APAC_MAS", ""),
    }
    return bucket_map.get(region, os.environ.get("OSCAL_S3_BUCKET", ""))
```

Apply the same pattern to `EVIDENCE_STREAM_GCS_BUCKET` in `src/compliance_bridge/evidence_stream.py` (GAP-07).

### 6.4 Pattern D: Terraform Module Updates (Fixes GAP-13, GAP-14)

**Effort:** Low — add env var declarations
**Priority:** P1 (HIGH)

In `infra/modules/gateway/main.tf`, add:
```hcl
env {
  name  = "CAGE_DEPLOYMENT_REGION"
  value = var.cage_deployment_region
}
```

In `infra/modules/compliance_bridge/main.tf`, add:
```hcl
env { name = "OSCAL_S3_BUCKET_US_FED";   value = var.oscal_s3_bucket_us_fed }
env { name = "OSCAL_S3_BUCKET_EU_ECB";   value = var.oscal_s3_bucket_eu_ecb }
env { name = "OSCAL_S3_BUCKET_APAC_MAS"; value = var.oscal_s3_bucket_apac_mas }
env { name = "CAGE_DEPLOYMENT_REGION";   value = var.cage_deployment_region }
```

---

## 7. Consolidated Findings Table

| ID | File | Lines | Sink Type | Severity | Status |
|----|------|-------|-----------|----------|--------|
| GUARDED-01 | `src/gateway/governance/uca_logger.py` | 385–403 | GCS/S3 WORM bucket | — | ✅ GUARDED |
| GUARDED-02 | `src/gateway/governance/pii_sanitizer.py` | 291–294 | Audit log citation | — | ✅ GUARDED |
| GUARDED-03 | `src/gateway/governance/iso_control.py` | 188, 202–217 | OTel span attributes | — | ✅ GUARDED |
| GUARDED-04 | `src/gateway/governance/normative_provider.py` | 781–797 | External HTTP + filesystem | — | ✅ GUARDED |
| GUARDED-05 | `src/gateway/governance/oscal_ssp_exporter.py` | 145–180 | Local filesystem | — | ✅ GUARDED |
| GUARDED-06 | `src/gateway/governance/hitl_escalator.py` | 78–93, 246–261 | Log metadata | — | ✅ GUARDED |
| GUARDED-07 | `src/gateway/governance/constants.py` | 245–309 | In-memory singleton | — | ✅ GUARDED |
| GUARDED-08 | `src/compliance_bridge/cmek_guard.py` | 93–94, 133–134 | Startup log | — | ✅ GUARDED |
| GUARDED-09 | `infra/targets/gcp-gke/*.tfvars` | — | Terraform region decl. | — | ✅ GUARDED |
| GUARDED-10 | `deployment/k8s/gateway.yaml.tpl` | 39–43 | K8s env var | — | ✅ GUARDED |
| GAP-01 | `src/gateway/tracing_setup.py` | 54–98 | OTel OTLP export | **CRITICAL** | ❌ GAP |
| GAP-02 | `src/gateway/governance/iso_control.py` | 125–144 | Redis Stream | **HIGH** | ❌ GAP |
| GAP-03 | `src/gateway/infrastructure/redis_client.py` | 59–86 | Redis connection | **HIGH** | ❌ GAP |
| GAP-04 | `src/gateway/governance/token_quota_proxy.py` | 224–256 | Redis quota counters | **HIGH** | ❌ GAP |
| GAP-05 | `src/compliance_bridge/storage.py` | 144–148 | GCS/S3 artifact bucket | **HIGH** | ❌ GAP |
| GAP-06 | `src/compliance_bridge/audit_workflow.py` | 165–175 | Langfuse compliance writes | **HIGH** | ❌ GAP |
| GAP-07 | `src/compliance_bridge/evidence_stream.py` | 118, 372–406 | GCS flush + Redis Stream | **HIGH** | ❌ GAP |
| GAP-08 | `src/compliance_bridge/reconciliation_worker.py` | 539–561 | Redis balance writes | **MEDIUM** | ❌ GAP |
| GAP-09 | `src/compliance_bridge/metrics.py` | 100–108 | Langfuse API reads | **MEDIUM** | ❌ GAP |
| GAP-10 | `src/compliance_bridge/notifier.py` | 565–634 | External HTTP alerts | **MEDIUM** | ❌ GAP |
| GAP-11 | `src/gateway/governance/telemetry_provider.py` | 163–206 | Langfuse telemetry reads | **MEDIUM** | ❌ GAP |
| GAP-12 | `src/gateway/governance/cbf.py` | 72, 201–240 | Redis cash-balance | **MEDIUM** | ❌ GAP |
| GAP-13 | `infra/modules/compliance_bridge/main.tf` | 148–156 | Terraform env injection | **MEDIUM** | ❌ GAP |
| GAP-14 | `infra/modules/gateway/main.tf` | 86–219 | Terraform env injection | **MEDIUM** | ❌ GAP |
| N/A-01 | `src/gateway/governance/provenance_chain.py` | 110–127 | Pure computation | — | ➖ N/A |
| N/A-02 | `src/gateway/governance/routing_seal.py` | 162–181 | Pure computation | — | ➖ N/A |
| N/A-03 | `src/gateway/governance/safety.py` | 1–72 | Deprecated shim | — | ➖ N/A |
| N/A-04 | `src/gateway/governance/symbolic_governor.py` | 110–823 | Orchestration only | — | ➖ N/A |
| N/A-05 | `src/gateway/infrastructure/telemetry.py` | 28–45 | Tracer factory | — | ➖ N/A |
| N/A-06 | `src/compliance_bridge/context_accumulator.py` | 1–366 | Pure computation | — | ➖ N/A |
| N/A-07 | `src/compliance_bridge/lula_scheduler.py` | 1–309 | Loopback HTTP only | — | ➖ N/A |
| N/A-08 | `src/compliance_bridge/kms_batch_signer.py` | 1–378 | In-memory queue | — | ➖ N/A |
| N/A-09 | `src/gateway/governance/hitl_escalator.py` | 183–230 | Log only | — | ➖ N/A |
| N/A-10 | `config/settings.py` | 30–131 | Config reads only | — | ➖ N/A |

---

## 8. Regulatory Cross-Reference

| Gap ID | GDPR Art. 44 | MAS TRM §4.2 | ISO 42001 | CLINERULES §12 |
|--------|-------------|--------------|-----------|----------------|
| GAP-01 | ❌ Violates | ❌ Violates | A.9.4 | §12.2 |
| GAP-02 | ❌ Violates | ❌ Violates | A.5.3 | §12.2 |
| GAP-03 | ❌ Violates | ❌ Violates | A.8.4 | §12.2 |
| GAP-04 | ❌ Violates | ❌ Violates | A.4 | §12.2 |
| GAP-05 | ❌ Violates | ❌ Violates | A.8.4 | §12.2 |
| GAP-06 | ❌ Violates | ❌ Violates | A.9.4 | §12.2 |
| GAP-07 | ❌ Violates | ❌ Violates | A.5.3 | §12.2 |
| GAP-08 | ❌ Violates | ❌ Violates | A.8.4 | §12.2 |
| GAP-09 | ❌ Violates | ❌ Violates | A.9.4 | §12.2 |
| GAP-10 | ❌ Violates | ❌ Violates | A.5.3 | §12.2 |
| GAP-11 | ❌ Violates | ❌ Violates | A.9.4 | §12.2 |
| GAP-12 | ❌ Violates | ❌ Violates | A.8.4 | §12.2 |
| GAP-13 | ❌ Violates | ❌ Violates | A.8.4 | §12.2 |
| GAP-14 | ❌ Violates | ❌ Violates | A.5.2 | §12.2 |

---

## 9. Audit Attestation

This audit was conducted by static code analysis of the files listed in Section 1.1. All findings are grounded in specific file paths and line numbers verified against the actual source code at the time of audit (2026-06-30).

**Limitations:**
- Dynamic analysis (runtime traffic inspection) was not performed.
- Infrastructure-level isolation (one GKE cluster per region) provides partial mitigation for GAP-03, GAP-04, GAP-07, GAP-08, GAP-12 when correctly deployed. The application-layer gaps remain and represent a defence-in-depth failure.
- The `advisor-secrets` Kubernetes Secret (referenced in `gateway.yaml.tpl` via `envFrom.secretRef`) may carry `CAGE_DEPLOYMENT_REGION` — this was not verified as the secret contents are not committed to the repository. GAP-14 remains open until explicit Terraform injection is confirmed.

**Next steps:**
1. Open engineering tickets for GAP-01 through GAP-14 in priority order.
2. Re-run this audit after each remediation batch.
3. Add a CI check (`scripts/check_region_guards.py`) that statically verifies all new storage/telemetry writes in `src/gateway/governance/` and `src/compliance_bridge/` include a `CAGE_DEPLOYMENT_REGION` guard.
4. Update `compliance/lula/lula-validation-tqp007.yaml` to assert `OSCAL_S3_BUCKET_EU_ECB` and `OSCAL_S3_BUCKET_APAC_MAS` are set when `CAGE_DEPLOYMENT_REGION` is EU_ECB or APAC_MAS respectively.

---

*End of REGION_GUARD_AUDIT.md*

### GAP-08 — `compliance_bridge/reconciliation_worker.py`: Redis Balance Writes Without Region Guard ⚠️ MEDIUM

**File:** [`src/compliance_bridge/reconciliation_worker.py`](../../src/compliance_bridge/reconciliation_worker.py:539)
**Lines:** 539–561 (`reconcile()` Redis write), 607–650 (`from_env()`)
**Sink type:** Redis writes (`reconciliation:verified_balance`)
**Regulatory exposure:** GDPR Art. 44 (EU_ECB), MAS TRM §4.2 (APAC_MAS)
**Verdict:** ❌ GAP — MEDIUM

**Evidence:**
```python
# reconciliation_worker.py lines 539-561
pipe.setex(
    "reconciliation:verified_balance",
    self._ttl_seconds,
    result.to_redis_payload(),
)
# No CAGE_DEPLOYMENT_REGION check; key not region-namespaced
```

```python
# reconciliation_worker.py lines 607-650
redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
# No CAGE_DEPLOYMENT_REGION check
```

The `reconciliation:verified_balance` key stores the externally reconciled ledger balance fetched from the Anchorage Digital gRPC API. This is financial data subject to data residency requirements. The key is not region-namespaced, meaning EU_ECB and APAC_MAS balance data would be stored in the same Redis keyspace as US_FED data if a shared Redis instance were used.

**Required fix:** Namespace the key: `reconciliation:{region}:verified_balance`. Use region-specific `REDIS_URL` selection in `from_env()`.

---

### GAP-09 — `compliance_bridge/metrics.py`: Langfuse API Reads Without Region Guard ⚠️ MEDIUM

**File:** [`src/compliance_bridge/metrics.py`](../../src/compliance_bridge/metrics.py:100)
**Lines:** 100–108 (`_make_app_langfuse()`)
**Sink type:** Langfuse API read (compliance metrics aggregation)
**Regulatory exposure:** GDPR Art. 44 (EU_ECB), MAS TRM §4.2 (APAC_MAS)
**Verdict:** ❌ GAP — MEDIUM

**Evidence:**
```python
# metrics.py lines 100-108
def _make_app_langfuse():
    host = os.environ.get("LANGFUSE_HOST", "https://cloud.langfuse.com")
    # No CAGE_DEPLOYMENT_REGION check
```

`get_compliance_metrics()` reads governance telemetry from Langfuse to compute compliance posture metrics. While this is a read operation, it reads from a single `LANGFUSE_HOST` without region dispatch. If EU_ECB or APAC_MAS governance spans were correctly stored in a regional Langfuse instance (after GAP-01 is fixed), this function would still read from the wrong instance, producing incorrect compliance metrics for those regions.

**Required fix:** `_make_app_langfuse()` must read `CAGE_DEPLOYMENT_REGION` and select the correct regional Langfuse host.

---

### GAP-10 — `compliance_bridge/notifier.py`: External Alert Calls Without Region Guard ⚠️ MEDIUM

**File:** [`src/compliance_bridge/notifier.py`](../../src/compliance_bridge/notifier.py:565)
**Lines:** 565–634 (`create_notifier()`), 230–283 (`SlackNotifier`), 301–401 (`PagerDutyNotifier`), 417–481 (`WebhookNotifier`)
**Sink type:** External HTTP calls (Slack, PagerDuty, webhook)
**Regulatory exposure:** GDPR Art. 44 (EU_ECB), MAS TRM §4.2 (APAC_MAS)
**Verdict:** ❌ GAP — MEDIUM

**Evidence:**
```python
# notifier.py lines 565-634
def create_notifier() -> ...:
    channel = os.environ.get("ALERT_CHANNEL", "console")
    webhook_url = os.environ.get("COMPLIANCE_ALERT_WEBHOOK_URL", "")
    # No CAGE_DEPLOYMENT_REGION check
```

Critical compliance findings (OSCAL control failures) are sent to Slack/PagerDuty/webhook endpoints without any region guard. The alert body includes `control_id`, `finding` details, and `audit_id` — compliance posture data that may be subject to data residency requirements. A single `COMPLIANCE_ALERT_WEBHOOK_URL` is used regardless of region.

**Required fix:** `create_notifier()` must read `CAGE_DEPLOYMENT_REGION` and select from `COMPLIANCE_ALERT_WEBHOOK_URL_US_FED`, `COMPLIANCE_ALERT_WEBHOOK_URL_EU_ECB`, `COMPLIANCE_ALERT_WEBHOOK_URL_APAC_MAS`, or assert that the configured webhook endpoint is consistent with the declared region.

---

### GAP-11 — `telemetry_provider.py`: Langfuse Telemetry Reads Without Region Guard ⚠️ MEDIUM

**File:** [`src/gateway/governance/telemetry_provider.py`](../../src/gateway/governance/telemetry_provider.py:163)
**Lines:** 163–206 (`LangfuseTelemetryProvider.from_env()`)
**Sink type:** Langfuse API read (causal gatekeeper telemetry)
**Regulatory exposure:** GDPR Art. 44 (EU_ECB), MAS TRM §4.2 (APAC_MAS)
**Verdict:** ❌ GAP — MEDIUM

**Evidence:**
```python
# telemetry_provider.py lines 163-206
@classmethod
def from_env(cls) -> "LangfuseTelemetryProvider":
    host = os.environ.get("LANGFUSE_HOST", "https://cloud.langfuse.com")
    # No CAGE_DEPLOYMENT_REGION check
```

The causal gatekeeper reads live governance telemetry from Langfuse to perform DoWhy placebo refutation. This is a read operation, but it reads from a single `LANGFUSE_HOST` without region dispatch. After GAP-01 is fixed and governance spans are stored in regional Langfuse instances, this function would read from the wrong instance for EU_ECB and APAC_MAS deployments, causing the causal gatekeeper to evaluate against incorrect telemetry data.

**Required fix:** `from_env()` must read `CAGE_DEPLOYMENT_REGION` and select the correct regional Langfuse host.

---

### GAP-12 — `cbf.py`: Redis Cash-Balance State Without Region Guard ⚠️ MEDIUM

**File:** [`src/gateway/governance/cbf.py`](../../src/gateway/governance/cbf.py:72)
**Lines:** 72 (`redis_key`), 75–81 (`setup()`), 201–240 (`update_state()`), 246–285 (`rollback_state()`)
**Sink type:** Redis writes (`safety:current_cash`)
**Regulatory exposure:** GDPR Art. 44 (EU_ECB), MAS TRM §4.2 (APAC_MAS)
**Verdict:** ❌ GAP — MEDIUM

**Evidence:**
```python
# cbf.py line 72
self.redis_key: str = "safety:current_cash"
# Hardcoded key, not region-namespaced
```

The CBF cash balance key `safety:current_cash` is hardcoded and not region-namespaced. `update_state()` and `rollback_state()` write to this key via the shared `redis_client` singleton (which itself is ungated — see GAP-03). If a shared Redis instance were used across regions, EU_ECB and APAC_MAS cash balance state would be co-mingled with US_FED state.

**Required fix:** Namespace the key: `safety:{region}:current_cash` where `region = os.environ.get("CAGE_DEPLOYMENT_REGION", "US_FED")`.

---

### GAP-13 — `infra/modules/compliance_bridge/main.tf`: Single `OSCAL_S3_BUCKET` Injection ⚠️ MEDIUM

**File:** [`infra/modules/compliance_bridge/main.tf`](../../infra/modules/compliance_bridge/main.tf:148)
**Lines:** 148–156
**Sink type:** Terraform env var injection (infrastructure gap)
**Verdict:** ❌ GAP — MEDIUM

**Evidence:**
```hcl
# compliance_bridge/main.tf lines 148-156
env {
  name  = "OSCAL_S3_BUCKET"
  value = var.oscal_s3_bucket
}
env {
  name  = "OSCAL_S3_REGION"
  value = var.oscal_s3_region
}
```

The Terraform module injects a single `OSCAL_S3_BUCKET` value. There is no injection of `OSCAL_S3_BUCKET_US_FED`, `OSCAL_S3_BUCKET_EU_ECB`, or `OSCAL_S3_BUCKET_APAC_MAS`. This means even if `storage.py` is fixed to read region-specific env vars (GAP-05), the Terraform module would need to be updated to inject them.

**Required fix:** Add `OSCAL_S3_BUCKET_US_FED`, `OSCAL_S3_BUCKET_EU_ECB`, `OSCAL_S3_BUCKET_APAC_MAS` env var injections to the compliance-bridge Terraform module, sourced from regional variables.

---

### GAP-14 — `infra/modules/gateway/main.tf`: `CAGE_DEPLOYMENT_REGION` Not Injected ⚠️ MEDIUM

**File:** [`infra/modules/gateway/main.tf`](../../infra/modules/gateway/main.tf:24)
**Lines:** 86–219 (full env block)
**Sink type:** Terraform env var injection (infrastructure gap)
**Verdict:** ❌ GAP — MEDIUM

**Evidence:**

Scanning the full env block of `infra/modules/gateway/main.tf` (lines 86–219), `CAGE_DEPLOYMENT_REGION` is **not injected** as an environment variable into the gateway pod. The gateway receives `CAGE_ENV`, `GOOGLE_CLOUD_PROJECT`, `GOOGLE_CLOUD_LOCATION`, `REDIS_URL`, `REDIS_HOST`, `REDIS_PORT`, and `REDIS_PASSWORD` — but not `CAGE_DEPLOYMENT_REGION`.

This means all application-level `CAGE_DEPLOYMENT_REGION` guards in the gateway (e.g., `uca_logger.py`, `iso_control.py`, `pii_sanitizer.py`, `constants.py`) fall back to the default value `"US_FED"` when deployed via this Terraform module, even for EU_ECB and APAC_MAS clusters.

The K8s template `gateway.yaml.tpl` also does not inject `CAGE_DEPLOYMENT_REGION` — it relies on `advisor-secrets` (via `envFrom.secretRef`) to carry this value, which is an implicit and unverified dependency.

**Required fix:** Add an explicit `CAGE_DEPLOYMENT_REGION` env var injection to `infra/modules/gateway/main.tf`, sourced from `var.cage_deployment_region` (which is already declared in the tfvars files).

---

### GUARDED-08 — `cmek_guard.py`: Jurisdictional Encryption Citation

**File:** [`src/compliance_bridge/cmek_guard.py`](../../src/compliance_bridge/cmek_guard.py:93)
**Lines:** 93–94 (`_get_region()`), 133–134 (`validate_cmek_configuration()`)
**Sink type:** Startup validation log
**Verdict:** ✅ GUARDED

**Evidence:**
```python
# cmek_guard.py lines 93-94, 133-134
def _get_region() -> str:
    return os.environ.get("CAGE_DEPLOYMENT_REGION", "").strip().upper()

active_region = region if region is not None else _get_region()
citation = _ENCRYPTION_CITATION.get(active_region, _ENCRYPTION_CITATION_DEFAULT)
```

`_ENCRYPTION_CITATION` maps US_FED → "NIST SC-28 / FedRAMP HIGH", EU_ECB → "GDPR Art. 32", APAC_MAS → "MAS TRM §9.1". The correct citation is emitted in startup logs and error messages. No storage writes occur in this module.

---

### GUARDED-09 — `infra/targets/gcp-gke/*.tfvars`: Terraform Region Declarations

**Files:** [`infra/targets/gcp-gke/prod.tfvars`](../../infra/targets/gcp-gke/prod.tfvars:45), [`infra/targets/gcp-gke/eu-prod.tfvars`](../../infra/targets/gcp-gke/eu-prod.tfvars:68), [`infra/targets/gcp-gke/apac-prod.tfvars`](../../infra/targets/gcp-gke/apac-prod.tfvars:67)
**Verdict:** ✅ GUARDED

Each production tfvars file explicitly sets `cage_deployment_region` and `region` to the correct GCP region:

| File | `cage_deployment_region` | `region` |
|------|--------------------------|----------|
| `prod.tfvars` | `US_FED` | `us-central1` |
| `eu-prod.tfvars` | `EU_ECB` | `europe-west1` |
| `apac-prod.tfvars` | `APAC_MAS` | `asia-southeast1` |

The Langfuse S3-compatible storage bucket is auto-generated in the declared GCP region, providing infrastructure-level data residency enforcement. The `eu-prod.tfvars` comment at line 33 explicitly states the DEP-10 Terraform precondition validates `region` starts with `"europe-"` for EU_ECB deployments.

---

### GUARDED-10 — `deployment/k8s/gateway.yaml.tpl`: GOOGLE_CLOUD_LOCATION Substitution

**File:** [`deployment/k8s/gateway.yaml.tpl`](../../deployment/k8s/gateway.yaml.tpl:43)
**Lines:** 39–43
**Verdict:** ✅ GUARDED (infrastructure layer)

**Evidence:**
```yaml
# gateway.yaml.tpl lines 39-43
# DEP-04: GOOGLE_CLOUD_LOCATION is substituted at deploy time from
# CAGE_DEPLOYMENT_REGION via deploy_all.sh / envsubst.
# US_FED → us-central1, EU_ECB → europe-west1, APAC_MAS → asia-southeast1
- name: GOOGLE_CLOUD_LOCATION
  value: "${GOOGLE_CLOUD_LOCATION}"
```

`GOOGLE_CLOUD_LOCATION` is substituted at deploy time from `CAGE_DEPLOYMENT_REGION` via `deploy_all.sh` / `envsubst`. This ensures the GCP client library uses the correct regional endpoint for Cloud KMS and GCS operations.

---

# Privacy Impact Assessment (PIA)

**System Name:** Cybernetic AI Governance Engine (CAGE) — Governed Financial Advisor  
**System Owner:** [SYSTEM OWNER — TBD]  
**Privacy Officer:** [PRIVACY OFFICER — TBD]  
**ISSO:** [ISSO NAME — TBD]  
**Version:** 1.1 (Draft — Corrected)  
**Date:** 2026-11-16 (initial draft: 2026-03-06)  
**Authority:** OMB Memorandum M-03-22; NIST SP 800-122 (Guide to Protecting the Confidentiality of PII)  
**Classification:** SENSITIVE — PRIVACY CONTROLLED  
**Status:** PENDING PRIVACY OFFICER REVIEW

> **CORRECTION NOTICE (`2026-11-16` — `POAM-2026-225`, `POAM-2026-226`):** Version `1.0` (`2026-03-06`) stated in `§6.1` that raw prompts were automatically purged after 90 days while retaining redacted summaries for 7 years, stated in `§6.2` that raw PII was never persisted in Langfuse traces, and stated across `§1.2`, `§2.1`, `§5.1`, `§8.2`, `§9.3`, `§10`, `§11.3`, and `§12` that OpenTelemetry spans and Langfuse traces carried user identifiers and prompt/response metadata. Audit on `2026-11-15`–`2026-11-16` established three defects: (1) no 90-day purge mechanism existed in `src/` or `infra/`, and raw prompts, model responses, and user identifiers were exported unredacted over OTLP into Langfuse's GCS event-upload bucket (which in `prod` and a retired `2026-05`–`2026-10` deployment carried a locked 2,555-day retention policy); (2) LangGraph working-state checkpoints in Redis carried no TTL (`POAM-2026-225` item 7), while the staging advisor silently fell back to ephemeral in-process `MemorySaver` (`POAM-2026-226`); and (3) NeMo/Presidio PII redaction ran only on the inference rail, never on span export. Version `1.1` retains the 90-day ceiling for non-audit conversational content, replaces the unbacked schedule with a complete store-by-store inventory and enforceability assessment in `§6.2` (including the irreversible 2033 retention asymmetry on the retired locked synthetic-data bucket), and updates all telemetry, checkpointing, encryption, and individual-rights sections to match `#774` (`TC-1` in [`docs/BREAKING_CHANGES.md`](../../docs/BREAKING_CHANGES.md)) and `#779` (`CP-1` in [`docs/BREAKING_CHANGES.md`](../../docs/BREAKING_CHANGES.md)).

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Information Collected](#2-information-collected)
3. [Legal Authority](#3-legal-authority)
4. [Purpose and Use of PII](#4-purpose-and-use-of-pii)
5. [Data Sharing](#5-data-sharing)
6. [Data Retention](#6-data-retention)
7. [Access Controls](#7-access-controls)
8. [Data Quality](#8-data-quality)
9. [Security Controls](#9-security-controls)
10. [Privacy Risks and Mitigations](#10-privacy-risks-and-mitigations)
11. [PII Minimization](#11-pii-minimization)
12. [Individual Rights](#12-individual-rights)
13. [Approval Block](#13-approval-block)

---

## 1. System Overview

### 1.1 System Description

The Cybernetic AI Governance Engine (CAGE) is a HIGH-impact AI governance platform deployed on Google Kubernetes Engine (GKE) in Google Cloud Platform (GCP). It functions as an intelligent financial advisory gateway that enforces real-time policy controls on AI-generated financial recommendations.

CAGE intermediates between end-user financial advisors and large language model (LLM) inference services, applying multi-layered governance:

- **OPA (Open Policy Agent)** enforcing Rego-based access control and trade authorization policies over a pod-local Unix domain socket
- **NeMo Guardrails** providing LLM input/output filtering, Presidio-backed PII detection, and dialogue safety when an active model backend is enabled
- **LangGraph** orchestrating multi-agent reasoning and human-in-the-loop (HITL) defer/resume workflows
- **Compliance Bridge (`EvidenceCustodian`)** verifying hash-chained governance records and writing KMS-signed WORM batches to Cloud Storage
- **Langfuse** providing operational latency, verdict, and span-structure observability without prompt, response, or end-user identity content (`TC-1`)

The system handles PII in the context of financial advisory services, including user identity, financial portfolio data, trade requests, and short-lived workflow checkpoints. Given the HIGH system categorization (FIPS 199), this PIA applies the most stringent privacy analysis consistent with NIST SP 800-122.

### 1.2 Deployment Architecture

| Component                        | Technology                                                 | Privacy Relevance                                                                                              |
| -------------------------------- | ---------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| API Gateway                      | Python FastAPI / MCP                                       | Receives authenticated advisory/tool requests; brokers checkpoint storage and model inference                  |
| Governance Engine                | SymbolicGovernor + OPA sidecar (UDS)                       | Evaluates structured action parameters and verified role/identity claims in memory                             |
| LLM Inference                    | Self-hosted vLLM (via gateway inference proxy)             | Processes prompts (after NeMo/Presidio rail scrubbing when rails are active) without third-party API egress   |
| NeMo Guardrails                  | NVIDIA NeMo + Presidio                                     | Detects and redacts 15 PII entity types on the LLM inference rail (`config/rails/config.yml`)                  |
| Operational Telemetry            | OpenTelemetry → [`ContentFilterSpanExporter`](../../src/gateway/observability/content_filter.py) → Langfuse | Exports governance verdicts, control IDs, and content lengths only; strips all prompt, response, and user IDs |
| Governance Valkey (`memorystore_governance`) | GCP Memorystore for Valkey (CMEK, TLS, IAM auth, AOF) | Holds `4 h` defer tokens (DB `0`), transient evidence stream (DB `1`), and `4h 1m` LangGraph checkpoints (DB `3`) |
| Authoritative Audit Custody      | [`EvidenceCustodian`](../../src/compliance_bridge/evidence_custodian.py) → GCS WORM (`module.worm_bucket`) | Persists regex-sanitized (`PIISanitizer`) KMS-signed governance decision/refusal batches under 2,555-day lock |
| Langfuse Backing Stores          | Cloud SQL (PostgreSQL) + ClickHouse + GCS event bucket     | Operational trace/project metadata only (`TC-1` blocks prompts, responses, and user IDs at export)             |
| Secret & Key Management          | GCP Secret Manager + Cloud KMS                             | Stores service credentials, asymmetric signing keys, and CMEK encryption keys                                  |

### 1.3 System Categorization

- **FIPS 199 Impact Level:** HIGH (Confidentiality: HIGH, Integrity: HIGH, Availability: HIGH)
- **PII Confidentiality Impact:** HIGH (per NIST SP 800-122 §3.1 — financial PII is inherently sensitive)
- **Reference:** [`compliance/categorization/FIPS199_CATEGORIZATION.md`](../categorization/FIPS199_CATEGORIZATION.md)

---

## 2. Information Collected

### 2.1 PII Categories

The following categories of Personally Identifiable Information (PII) are collected, processed, or generated by the CAGE system:

| PII Category                    | Data Elements                                                                                  | Source / Plane                                                         | Sensitivity |
| ------------------------------- | ---------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- | ----------- |
| **User Identity**               | Authenticated principal (`initiator_urn`), role/title                                          | OIDC / JWT authentication layer                                        | HIGH        |
| **Financial Portfolio Data**    | Account numbers, portfolio holdings, asset values, trade history                               | User requests to financial advisory API                                | HIGH        |
| **Trade Requests**              | Trade action, symbol, quantity, dollar amount, `initiator_urn`                                 | User-submitted advisory / tool requests                                | HIGH        |
| **Working-State Checkpoints**   | Serialized LangGraph thread messages and paused HITL state (`4h 1m` write-only TTL, `CP-1`)    | [`GatewayCheckpointSaver`](../../src/governed_financial_advisor/graph/checkpointer.py) → [`GatewayCheckpointStore`](../../src/gateway/governance/checkpoint_store.py) (Valkey DB `3`) | HIGH        |
| **Authentication & Gate Seals** | Bearer JWTs, single-use `ConsequenceToken` JWS, HMAC routing seals (redacted before WORM sink) | Authentication and kernel governance layer                             | HIGH        |
| **Governance Audit Records**    | `initiator_urn`, timestamp, structured action/params (`PIISanitizer`-redacted), verdict, proof | [`EvidenceStreamSink`](../../src/gateway/governance/evidence/stream.py) → GCS WORM (`module.worm_bucket`) | HIGH        |
| **Market Data Requests**        | Ticker symbols queried during analysis                                                         | Market data tool integration                                           | MODERATE    |
| **Operational Span Metadata**   | Trace/span IDs, node names, verdict codes, latency, character lengths (`cage.content.*_length`) | OTel instrumentation (`TC-1`: zero prompt, response, or user ID fields) | LOW         |

### 2.2 PII Entity Types Recognized by NeMo Guardrails

The system's NeMo Guardrails PII detection layer (configured in [`config/rails/config.yml`](../../config/rails/config.yml)) recognizes and can redact the following 15 PII entity types in AI model inputs and outputs on the inference rail:

1. `PERSON` — personal names
2. `EMAIL_ADDRESS` — email addresses
3. `PHONE_NUMBER` — phone numbers
4. `US_SSN` — Social Security Numbers
5. `US_BANK_NUMBER` — bank account numbers
6. `CREDIT_CARD` — credit card numbers
7. `IBAN_CODE` — international bank account numbers
8. `US_ITIN` — Individual Taxpayer Identification Numbers
9. `US_PASSPORT` — US passport numbers
10. `LOCATION` — geographic locations
11. `DATE_TIME` — dates and times (when associated with identity)
12. `NRP` — Nationality, Religion, Political affiliation
13. `IP_ADDRESS` — IP addresses
14. `URL` — URLs (when containing user identifiers)
15. `MEDICAL_LICENSE` — medical license numbers

Separately, the kernel's deterministic pre-ledger [`PIISanitizer`](../../src/gateway/governance/pii_sanitizer.py) runs on every governance event before WORM persistence and redacts **6 structured token/identifier patterns** (`SSN`, `CREDIT_CARD`, `IBAN`, contextual or key-labelled `SWIFT/BIC`, `EMAIL`, `PHONE`) plus API keys/Bearer tokens, JWS tokens, and denylisted credential keys (`_KEY_DENYLIST`), while preserving canonical UUID correlation identifiers. Unlike Presidio NER on the inference rail, `PIISanitizer` does **not** redact unlabelled natural-language person names or street addresses if placed inside structured tool `params`.

### 2.3 PII Not Collected

The following categories of PII are explicitly **not** collected by CAGE:

- Social Security Numbers (except when inadvertently present in user queries — redacted on the inference rail by NeMo/Presidio and on the WORM evidence path by `PIISanitizer`)
- Biometric data
- Medical/health information in `cage_finance` deployments (the `cage_healthcare` domain plugin is isolated to separate single-domain processes via `CAGE_DOMAIN`)
- Minors' data (system restricted to professional financial advisors ≥18)

---

## 3. Legal Authority

### 3.1 Statutory Authority

The CAGE system operates under the following legal authorities permitting collection and use of PII in the financial services context:

| Authority                         | Citation                      | Scope                                                                            |
| --------------------------------- | ----------------------------- | -------------------------------------------------------------------------------- |
| **Gramm-Leach-Bliley Act (GLBA)** | 15 U.S.C. §§ 6801-6809        | Protects consumer financial information; requires privacy notices and safeguards |
| **SEC Regulation S-P**            | 17 C.F.R. Part 248            | Safeguards personal financial information held by SEC-registered advisors        |
| **SEC Regulation S-ID**           | 17 C.F.R. Part 248, Subpart C | Identity theft red flags program                                                 |
| **FINRA Rules & SEC Rule 17a-4**  | FINRA Rule 3110, 4511; 17 C.F.R. § 240.17a-4 | Books and records 7-year immutable WORM retention; supervision       |
| **E-Government Act of 2002**      | Pub. L. 107-347, §208         | PIA requirement for federal information systems                                  |
| **Privacy Act of 1974**           | 5 U.S.C. §552a                | Applicable when deployed in a federal agency system of records                   |

### 3.2 Regulatory Framework

All PII handling within CAGE is bounded by:

1. **NIST SP 800-122:** Guide to Protecting the Confidentiality of PII
2. **NIST SP 800-53 Rev 5:** Security and Privacy Controls (AU-3(3), SI-12(3), RA-8, SC-28, AC-3)
3. **OMB M-03-22:** OMB Guidance for Implementing the Privacy Provisions of the E-Gov Act
4. **OMB Circular A-130:** Managing Information as a Strategic Resource (Appendix II — Privacy)

---

## 4. Purpose and Use of PII

### 4.1 Authorized Purposes

PII collected and processed by CAGE is used exclusively for the following authorized purposes:

| Purpose                            | PII Used                                                                 | Legal Basis                              |
| ---------------------------------- | ------------------------------------------------------------------------ | ---------------------------------------- |
| **Governance Decision-Making**     | Authenticated identity/role, structured trade parameters                 | GLBA safeguards; SEC Reg S-P             |
| **Authoritative Audit Custody**    | `initiator_urn`, timestamp, `PIISanitizer`-redacted action/verdict proof | SEC Rule 17a-4; FINRA Rule 4511          |
| **HITL Defer / Resume Continuity** | Short-lived LangGraph checkpoint state and `DeferToken` (`≤ 4h 1m` TTL)  | Internal governance control (NIST SC-24) |
| **Policy Enforcement**             | User role, account/portfolio bounds, trade magnitude                     | GLBA; SEC Investment Advisers Act        |
| **AI Input/Output Safety**         | Prompt and response text (in-flight NeMo/Presidio screening)             | Internal safety & privacy minimization   |
| **Incident Response**              | Governance WORM records and 30-day operational logs (restricted IAM)     | NIST SP 800-61r2                         |

### 4.2 Prohibited Uses

PII collected by CAGE is explicitly **prohibited** from use for:

- Training or fine-tuning AI models (production/staging runtime stores have no pipeline to training jobs)
- Operational trace telemetry (`TC-1` forbids exporting prompts, responses, or end-user IDs in OTel spans)
- Marketing or commercial profiling
- Secondary disclosure to non-authorized third parties
- Any purpose inconsistent with the original advisory context

### 4.3 AI-Specific Processing Notice

Prompts submitted to the self-hosted vLLM inference service traverse the gateway inference proxy inside the GKE cluster. When NeMo Guardrails are enabled (`CAGE_INFERENCE_BACKEND="vllm"`), Presidio-backed PII detection and redaction screen prompts before model inference (see `§11`). Self-hosted inference ensures financial PII does not leave the GCP organizational boundary to external LLM APIs.

---

## 5. Data Sharing

### 5.1 Internal Data Flows

| Recipient System                                        | Data / PII Shared                                                                          | Purpose                          | Data Protection                                                                     |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------ | -------------------------------- | ----------------------------------------------------------------------------------- |
| **vLLM Inference Service**                              | Prompts (screened by NeMo/Presidio when rails are active) via gateway inference proxy      | AI model inference               | Self-hosted on GKE; Linkerd mTLS; NetworkPolicy admits only `gateway`               |
| **OPA Policy Sidecar**                                  | Structured action, parameters, and role claims                                             | Policy evaluation                | Pod-local Unix domain socket (`0` TCP ports); console decision logs, no persistence |
| **Governance Valkey (`module.memorystore_governance`)** | `DeferToken` (DB `0`, `4 h`), evidence stream (DB `1`), opaque checkpoints (DB `3`, `4h 1m`) | Defer/resume & evidence staging  | CMEK, TLS (`SERVER_AUTHENTICATION`), IAM auth, AOF persistence; gateway-only access |
| **GCS WORM Evidence Bucket (`module.worm_bucket`)**     | KMS-signed `cage-evidence-batch/2` batches (`PIISanitizer`-redacted structured events)     | Authoritative 7-year audit trail | CMEK, locked retention policy (`2,555 d` in `prod`), dual-project custody option    |
| **Langfuse (ClickHouse + Cloud SQL + GCS event bucket)** | Operational OTel spans (verdicts, control IDs, durations, character lengths — **zero PII**) | Runtime operational telemetry    | `ContentFilterSpanExporter` strips content & user IDs before OTLP export (`TC-1`)   |
| **GCP Cloud Logging (`_Default` bucket)**               | Structured JSON container logs (`50`/`200`-char snippets at `INFO`/`WARN`; 30-day TTL)     | Operational troubleshooting      | GCP IAM (`roles/logging.viewer`); automatic 30-day bucket expiration                |

### 5.2 External Disclosure

**No PII is disclosed to external third parties** outside the GCP organizational boundary:

| External System               | Data Shared                             | PII Included?     | Notes                                     |
| ----------------------------- | --------------------------------------- | ----------------- | ----------------------------------------- |
| **GCP Cloud APIs**            | Encrypted container images, GCS objects | No PII in transit | GCP DPA applies; TLS 1.3                  |
| **GitHub Actions CI/CD**      | Source code, security scan results      | No PII            | Static/hermetic tests and image scans     |
| **NVIDIA NeMo (open source)** | No runtime data                         | N/A               | Self-hosted; no cloud telemetry to NVIDIA |

### 5.3 Third-Party Data Processing Agreements

- **Google Cloud Platform:** GCP Data Processing Agreement (DPA) covers all GCP services used (GKE, Memorystore for Valkey, Cloud SQL, GCS, Cloud KMS, Cloud Logging, Secret Manager).
- No external SaaS telemetry or LLM DPAs are required because inference and Langfuse are self-hosted inside the deployment boundary (`is_enforcing()` refuses SaaS Langfuse fallbacks).

---

## 6. Data Retention

### 6.1 Retention Policy & 90-Day Conversational Content Ceiling

CAGE enforces a strict separation between **conversational / working-state data** and **regulatory governance audit records**:

1. **90-day maximum ceiling for non-audit conversational content:** Raw prompts, model responses, and conversational working state must never be retained beyond **90 days** in any operational store. In current CAGE code (`#774` `TC-1` and `#779` `CP-1`), every active store holding conversational text expires well inside 90 days (`4h 1m` for LangGraph checkpoints, pod-lifetime / `1 h` for non-personalized educational cache entries, `30 days` for Cloud Logging `_Default`), and telemetry stores receive **zero** prompt, response, or end-user identity attributes.
2. **7-year (`2,555`-day) immutable retention for authoritative governance audit records:** Structured governance decision, deferral, and refusal records (`cage-audit/3.0` / `cage-evidence-batch/2`) are sanitized by [`PIISanitizer`](../../src/gateway/governance/pii_sanitizer.py), KMS-signed by [`EvidenceCustodian`](../../src/compliance_bridge/evidence_custodian.py), and written to `module.worm_bucket` under a locked `2,555`-day retention policy in `prod` (`SEC Rule 17a-4` / `FINRA Rule 4511` / `NIST AU-11`).
3. **No long-term conversational memory:** CAGE provides no cross-session conversational memory store. Threads idle beyond the defer/HITL resumption window (`4h 1m` default) lose their LangGraph checkpoint history (`CP-1`). Any future long-term memory capability requires a dedicated store with its own declared retention schedule, automated TTL purge, and PIA revision before deployment.

### 6.2 Complete Store Inventory & Technical Enforceability (`2026-11-16`)

Every store in CAGE (including retired historical buckets from the staging GCP project audited under `POAM-2026-225`) is inventoried below with its actual content, actual retention, and whether retention is technically enforceable:

| Store | Plane | Conversation / Identity Content | Actual Retention | Technically Enforceable Within Policy? |
| --- | --- | --- | --- | --- |
| **Retired locked Langfuse event bucket** (`langfuse-events-<PROJECT_ID>-fe82cebc`, retired under `POAM-2026-159` / `POAM-2026-225`) | Historical telemetry (retired) | **Yes (pre-`#774` synthetic test traffic):** `35,639` objects (`5,522` request spans captured `2026-05-21`–`2026-10-29`, plus `2026-03`; attributed as synthetic test data on `2026-11-15` in [`docs/POAM.md`](../../docs/POAM.md) `POAM-2026-225`). | **Locked `2,555 d`** — objects expire **`2033-05-19` to `2033-10-27`**. | **No (irreversible retention asymmetry).** GCS `retention_policy { is_locked = true }` prevents early object or bucket deletion by any principal, including project owners. Compensating control applied `2026-11-15`: bucket IAM reduced to project owner only, plus an explicit GCP IAM deny policy (`privacy-hold=active`) denying object reads and policy changes to all other principals including the deployer service account. |
| **Historical unlocked Langfuse event buckets (`3` Feb–Mar buckets), `13` expired `1 d`-locked certification buckets (`2026-11-10`–`2026-11-14`), and `78` orphaned persistent disks** (`POAM-2026-225` item 4) | Historical telemetry / compute (disposed) | One unlocked bucket held pre-`#774` synthetic prompts; certification buckets held ~10 synthetic objects each. | **Purged and deleted** (`78` disks, `78` temporary snapshots, and `13` certification buckets deleted `2026-11-15`; all `3` unlocked Feb–Mar buckets emptied and deleted `2026-11-16`). | **Yes — disposal complete.** Zero objects or buckets remain. |
| **Langfuse GCS event-upload bucket — non-staging profiles** (`prod`, `eu-dev`, `apac-dev` in [`infra/targets/gcp-gke/main.tf`](../../infra/targets/gcp-gke/main.tf)) | Operational telemetry (not audit custody) | **None since `#774` (`b12706d4`, `TC-1`).** Spans carry verdicts, control IDs, durations, and character lengths only. *(Residual out-of-filter paths: raw Python `exception.message` strings on `ERROR` spans and [`compliance-bridge`](../../src/compliance_bridge/main.py) advisory SDK governance traces, neither of which carries chat prompts/responses.)* | **`2,555 d` locked** (`retention_posture` in [`infra/targets/gcp-gke/main.tf`](../../infra/targets/gcp-gke/main.tf)). | **Yes, by source & exporter exclusion (`TC-1`), not by bucket purge.** Because the bucket is locked for `2,555` days, any content written to it cannot be purged at 90 days; compliance rests on [`ContentFilterSpanExporter`](../../src/gateway/observability/content_filter.py), `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT="false"`, and CI canary gates ([`test_telemetry_content_filter.py`](../../tests/test_telemetry_content_filter.py), [`test_telemetry_content_capture.py`](../../tests/infrastructure/test_telemetry_content_capture.py)). |
| **Langfuse GCS event-upload bucket — `staging` profile** ([`infra/targets/gcp-gke/main.tf`](../../infra/targets/gcp-gke/main.tf)) | Operational telemetry (not audit custody) | **None since `#774` (`b12706d4`, `TC-1`)** (`25` synthetic probe objects pre-`#774`). | **`1 d` locked**, no lifecycle delete rule configured. | **Yes, by source & exporter exclusion (`TC-1`).** Bucket lock expires after 1 day; objects are not auto-deleted unless a lifecycle rule is added, so compliance rests on `TC-1` content exclusion. |
| **Langfuse ClickHouse (`traces`, `observations`, `scores`, `event_log`) & Cloud SQL PostgreSQL (`langfuse` DB)** | Operational telemetry (not audit custody) | **None since `#774` (`b12706d4`, `TC-1`).** Staging ClickHouse verified at `0` rows across `traces`, `observations`, `scores`, and `event_log` on `2026-11-16`; staging Cloud SQL held `0` trace/observation rows and was recreated under `UP-1` (`#712`). | **No row TTL configured** (`MergeTree` `has_ttl = 0`; Cloud SQL has no row-expiry job). | **Yes, by source & exporter exclusion (`TC-1`), not by DB TTL.** Neither database runs an automated 90-day purge; conversational content is kept out of both databases by `TC-1`. |
| **LangGraph working-state checkpoints — gateway-mediated Valkey DB `3`** ([`checkpoint_store.py`](../../src/gateway/governance/checkpoint_store.py), [`checkpointer.py`](../../src/governed_financial_advisor/graph/checkpointer.py), `CP-1` `#779`) | Working state (`module.memorystore_governance`, DB `3`) | **Full active-thread conversation & paused HITL state**, client-serialized as opaque base64 envelopes. Redis keys hash caller workload identity and `thread_id` (`ckpt:v1:<caller_sha256>:<thread_sha256>:...`), and `thread_id` travels in POST JSON bodies rather than URL paths. | **`14,460 s` (`4h 1m`) default** — computed directly from `_DEFAULT_TTL` (`14,400 s`), `_DEFAULT_HOLD_TTL` (`300 s`), and [`resolve_hitl_approval_ttl_seconds()`](../../src/governed_financial_advisor/graph/nodes/approval_node.py) (`300 s` default) + `60 s` margin rounded up to whole minutes; capped by `CAGE_CHECKPOINT_MAX_TTL_SECONDS` (`86,400 s` default, `90 d` hard ceiling). Refreshed on writes only, **never on reads**. | **Yes — enforced by Valkey `EXPIRE` on every write.** Idle threads expire automatically once past the resumption window (`≤ 4h 1m` default, hard-capped at `≤ 90 d`). Ephemeral `MemorySaver` fallback is refused (`CheckpointDurabilityError`) in all [`is_enforcing()`](../../src/gateway/governance/env_posture.py) postures (`POAM-2026-226`). |
| **Advisor educational query cache** ([`query_cache.py`](../../src/governed_financial_advisor/infrastructure/query_cache.py), [`server.py`](../../src/governed_financial_advisor/server.py)) | Application memory (or optional Redis) | **Non-personalized educational/regulatory responses only.** `NON_CACHEABLE_PATTERNS` rejects portfolio, personalized (`"my portfolio"`, `"should I"`), ticker-analysis, and trade queries; keys use `SHA-256(normalized_query):SHA-256(JCS(governance_context))`. | **Pod lifetime** in deployed `server.py` (`redis_client=None`, bounded `local_cache` of `1,000` entries); **`3,600 s` (`1 h`)** `SETEX` if a Redis client is injected (`QUERY_CACHE_TTL`). | **Yes.** Personalized PII queries are excluded by pattern guard, and cached educational entries are bounded to pod lifetime / `1 h` (`<< 90 d`). |
| **Application container logs — GCP Cloud Logging `_Default` bucket** | Operational logs (not audit custody) | At default `INFO`/`WARNING` level: `50`-char query/blocked-text fragments and `200`-char response fragments (full prompt text only if `DEBUG` logging is enabled). | **`30 d`** (`_Default` log bucket retention). | **Yes — enforced by GCP Cloud Logging bucket retention (`30 d ≤ 90 d`).** Operators must not enable `DEBUG` logging in enforcing environments or route container stdout to a locked sink without field scrubbing. |
| **Governance Valkey defer queue — DB `0`** ([`defer_queue.py`](../../src/gateway/governance/defer_queue.py), [`verdicts.py`](../../src/gateway/governance/governor/verdicts.py)) | Governance working state (`module.memorystore_governance`, DB `0`) | Structured `DeferToken` (`opa_input_snapshot`: `action`, `params`, `metadata`, `initiator_urn`, `violations`, `barrier_preview`, `narrow_hint`; FTRA stores `ftra_result` and `plan_id`). Contains no chat prompts unless a caller places free text inside tool `params`. | **`14,400 s` (`4 h`)** (`_DEFAULT_TTL`) or **`300 s` (`5 min`)** (`_DEFAULT_HOLD_TTL`), set atomically via Lua `EXPIRE` in `_PARK_LUA`. | **Yes — enforced by atomic Valkey `EXPIRE` at park time.** |
| **Governance evidence stream (Valkey DB `1`) & KMS-signed GCS WORM archive (`module.worm_bucket`)** ([`stream.py`](../../src/gateway/governance/evidence/stream.py), [`evidence_custodian.py`](../../src/compliance_bridge/evidence_custodian.py), [`pii_sanitizer.py`](../../src/gateway/governance/pii_sanitizer.py)) | Authoritative audit custody | Structured governance decision/refusal envelopes (`action`, `params`, `verdict`, `control_id`, `initiator_urn`) — **never chat transcripts**. Every string passes through `PIISanitizer.sanitize_dict()` before JCS canonicalization (`SSN`, `CREDIT_CARD`, `IBAN`, labelled/keyed `SWIFT/BIC`, `EMAIL`, `PHONE`, API/Bearer keys, JWS tokens redacted; unlabelled natural-language names/prose in `params` are **not** redacted by regex). | Stream staging cap `MAXLEN 100,000` in Valkey DB `1`; GCS WORM archive locked **`2,555 d` (`7 yr`)** in `prod` / `eu-dev` / `apac-dev` (`1 d` locked in `staging`, `2,555 d` unlocked in `dev`). | **Yes — mandatory 7-year regulatory retention** (`SEC Rule 17a-4` / `FINRA Rule 4511` / `NIST AU-9, AU-11`) enforced by GCS `retention_policy { is_locked = true }` and KMS batch signatures. |

### 6.3 NeMo-Recognized PII Handling vs. Telemetry & Audit Sanitization

Version `1.0` (`§6.2`) stated that NeMo Guardrails replaced PII with placeholders (`[PERSON]`, `[US_SSN]`) in stored Langfuse traces so raw PII was never persisted in traces. **That statement was incorrect and is withdrawn:**

1. **Inference rail (`NeMo` + `Presidio`):** The 15 PII entity types in `§2.2` are scanned on AI model inputs and outputs (`recognize_pii` in [`config/rails/config.yml`](../../config/rails/config.yml)) only when an active model backend with NeMo Guardrails is enabled (`CAGE_INFERENCE_BACKEND="vllm"`). NeMo does **not** sit on the OpenTelemetry exporter path.
2. **Operational telemetry (`ContentFilterSpanExporter`, `TC-1`):** Rather than relying on NER redaction, CAGE emits **no** prompt, response, or user-identifier attributes on OTel spans (`#774` `b12706d4`), and [`ContentFilterSpanExporter`](../../src/gateway/observability/content_filter.py) drops any denied attribute or un-sanitizable span before OTLP export. Neither raw PII nor `[PERSON]`-style redacted prompt text is stored in Langfuse.
3. **Authoritative WORM audit records (`PIISanitizer`):** Structured tool-governance records entering `cage:evidence:stream` and `module.worm_bucket` are scrubbed deterministically by [`PIISanitizer`](../../src/gateway/governance/pii_sanitizer.py) (`6` regex PII patterns + credential/JWS denylists), preserving cryptographic hash-chain determinism without ML NER nondeterminism.

---

## 7. Access Controls

### 7.1 Role-Based Access to PII

| Role                             | PII Access                                                            | System                                | Access Method                                               |
| -------------------------------- | --------------------------------------------------------------------- | ------------------------------------- | ----------------------------------------------------------- |
| **System Administrator**         | Break-glass infrastructure access (locked retired bucket owner-only)  | GKE, GCP IAM, GCS                     | GCP IAM — `roles/owner` (break-glass only; MFA required)    |
| **ISSO**                         | Operational logs (`30 d`) and span metadata (no prompt/user-ID text)  | Cloud Logging, Langfuse               | GCP IAM — `roles/logging.viewer`; Langfuse RBAC             |
| **Financial Advisor (End User)** | Own active session (`≤ 4h 1m` checkpoint window)                      | CAGE Advisory API                     | OIDC/JWT authentication; OPA RBAC enforced                  |
| **Senior Trader**                | Trade requests ≤$500k; own deferred/HITL requests                     | CAGE API                              | OPA Rego policy — `cage.io/role: senior-trader`             |
| **Junior Trader**                | Trade requests ≤$5k; own deferred/HITL requests                       | CAGE API                              | OPA Rego policy — `cage.io/role: junior-trader`             |
| **Compliance Officer**           | KMS-signed WORM governance evidence batches and OSCAL reports         | Compliance Bridge / WORM GCS          | Dedicated compliance-project / viewer IAM                   |
| **Security Control Assessor**    | OSCAL compliance artifacts and custody verification reports (no PII)  | OSCAL artifacts in GCS                | GCP IAM — `roles/storage.objectViewer` on compliance bucket |
| **Incident Responder**           | 30-day operational logs and WORM governance audit records             | Cloud Logging, WORM GCS               | Break-glass role + AO notification required                 |

### 7.2 Technical Access Controls

**Kubernetes RBAC & Mesh Workload Identity:**

- Namespace-level isolation in `governance-stack` namespace
- Lula validation [`compliance/lula/lula-validation-ac2.yaml`](../lula/lula-validation-ac2.yaml) enforces named ServiceAccounts with `cage.io/account-purpose` labels and `automountServiceAccountToken: false` on `default`
- Gateway checkpoint endpoints (`/governance/checkpoints/*`) require pod-local Linkerd mTLS (`l5d-client-id` in `CAGE_TRUSTED_CLIENT_IDENTITIES`) via [`WorkloadIdentityMiddleware`](../../src/gateway/server/workload_identity.py) and partition every Valkey key by `SHA-256(caller_identity)`

**GCP IAM:**

- Workload Identity Federation (WIF) binds each GKE Kubernetes ServiceAccount to a least-privilege Google ServiceAccount (see [`infra/targets/gcp-gke/iam.tf`](../../infra/targets/gcp-gke/iam.tf)); the advisor KSA holds **no** GCP service account (`POAM-2026-079`)
- Explicit IAM deny policy (`privacy-hold=active`) blocks non-owner access to the retired `2026-05`–`2026-10` locked Langfuse bucket (`POAM-2026-225` item 3)

**OPA Policy Enforcement:**

- Every governed action is evaluated against [`src/cage_finance/opa/trade_governance.rego`](../../src/cage_finance/opa/trade_governance.rego) over the gateway's read-only OPA UDS sidecar
- Role-based trade limits: junior traders ≤$5k, senior traders ≤$500k; unrecognized roles fail closed

**Network Policy (`POAM-2026-195`):**

- Default-deny ingress and egress in `governance-stack` ([`infra/targets/gcp-gke/network_policy.tf`](../../infra/targets/gcp-gke/network_policy.tf))
- `financial-advisor-egress-internal-only` restricts the advisor exclusively to `gateway`, `langfuse:3000` (content-filtered OTLP), Linkerd control plane, and cluster DNS — zero direct Valkey, Cloud SQL, or external egress

---

## 8. Data Quality

### 8.1 Accuracy

- **User Identity:** Sourced from the upstream OIDC/JWT identity provider; CAGE verifies claims without mutating them
- **Financial Data:** Sourced from caller-submitted requests; CAGE validates schema and magnitude bounds ([`ConsequenceMagnitudes`](../../src/gateway/governance/consequence_magnitude.py)) before policy evaluation
- **Governance Audit Records:** Canonicalized under RFC 8785 JCS, SHA-256 hash-chained in [`EvidenceStreamSink`](../../src/gateway/governance/evidence/stream.py), and KMS-signed in [`EvidenceCustodian`](../../src/compliance_bridge/evidence_custodian.py)

### 8.2 Completeness

- All governance decisions and refusals emit structured `cage-audit/3.0` records to `cage:evidence:stream` → `module.worm_bucket` (`Refusals Are Primary Evidence`)
- Operational OTel spans carry `iso42001.control`, `iso42001.verdict`, timestamps, and content lengths (`TC-1` omits `user` / `enduser.id` from spans by design)
- Active Lula validation [`compliance/lula/lula-validation-au12.yaml`](../lula/lula-validation-au12.yaml) and [`compliance/lula/lula-validation-metrics.yaml`](../lula/lula-validation-metrics.yaml) validate telemetry and Managed Prometheus scraping configuration

### 8.3 Relevance

- PII processing is limited to attributes required for real-time authorization, short-lived HITL resumption (`≤ 4h 1m`), and regulatory books-and-records evidence
- `TC-1` eliminates prompt, response, and user-ID collection from the observability plane entirely

### 8.4 Data Correction

- Identity corrections are handled at the upstream OIDC/IAM identity provider
- WORM governance records in `module.worm_bucket` are append-only — corrections are recorded as new superseding audit entries rather than overwrites

---

## 9. Security Controls

### 9.1 Encryption at Rest

| Data Store                                                    | Encryption Method                                  | Status         |
| ------------------------------------------------------------- | -------------------------------------------------- | -------------- |
| Governance Valkey (`module.memorystore_governance`, DB `0/1/3`) | Cloud KMS CMEK + AOF persistence (`enforcing`)     | ✅ Implemented |
| GCS WORM Evidence & Langfuse Buckets                          | Cloud KMS CMEK (`module.kms`)                      | ✅ Implemented |
| Cloud SQL PostgreSQL (`module.cloudsql_postgres`)             | Cloud KMS CMEK (`encryption_key_name`)             | ✅ Implemented |
| GKE Persistent Disks & Secrets (`database_encryption`)        | Cloud KMS CMEK                                     | ✅ Implemented |
| GCP Secret Manager (credentials)                              | GCP-managed / CMEK encryption                      | ✅ Implemented |

### 9.2 Encryption in Transit

| Connection                                         | Protocol                                                   | Status         |
| -------------------------------------------------- | ---------------------------------------------------------- | -------------- |
| Client → CAGE API Gateway                          | TLS 1.3 (Ingress)                                          | ✅ Implemented |
| Advisor ↔ Gateway (`/governance/checkpoints/*`, MCP, proxy) | Linkerd mTLS (`l5d-client-id` verified)            | ✅ Implemented |
| Gateway → vLLM / Inference Stub (intra-cluster)    | Linkerd mTLS                                               | ✅ Implemented |
| Gateway → OPA (sidecar)                            | Pod-local Unix domain socket (`0` TCP ports)               | ✅ Implemented |
| Gateway / Advisor → Langfuse (intra-cluster)       | Linkerd mTLS                                               | ✅ Implemented |
| Gateway → Governance Valkey                        | TLS (`SERVER_AUTHENTICATION`) + GCP IAM auth               | ✅ Implemented |
| Langfuse → Cloud SQL                               | Cloud SQL Auth Proxy TLS 1.2+                              | ✅ Implemented |
| Workloads → GCS / Cloud KMS                        | TLS 1.3 (GCP APIs)                                         | ✅ Implemented |

### 9.3 Access Logging

All access to systems handling PII or audit evidence is logged via:

- **GCP Cloud Audit Logs:** Admin activity and data access logs for GCS (including `module.worm_bucket` and the privacy-hold retired bucket), Cloud KMS, Cloud SQL, and Secret Manager
- **Authoritative Governance Evidence Chain:** Every `ALLOW`, `DENY`, and `DEFER` decision is hash-chained into `cage:evidence:stream` and KMS-signed into `module.worm_bucket`
- **OpenTelemetry / Langfuse (PII-free):** Operational decision spans without user IDs or message content (`TC-1`)
- **Kubernetes Audit Logs & Dataplane V2 Verdict Logs:** GKE control-plane audit logs and NetworkPolicy allow/deny verdict logs in enforcing postures

### 9.4 Incident Response

Runtime governance and PII-incident events publish through `GovernanceEventBus` (IR-6 reporting — see [`docs/POAM.md`](../../docs/POAM.md)). Deploying organizations author environment-specific Incident Response Plans covering:

- AI-specific incident categories (governance bypass, prompt injection, telemetry/log content leakage — see `POAM-2026-225` containment sequence)
- GLBA / SEC Reg S-P customer notification procedures
- 72-hour regulatory notification windows where applicable

---

## 10. Privacy Risks and Mitigations

| #        | Privacy Risk                                                                                                                                                                     | Likelihood | Impact   | Mitigation                                                                                                                                                                                                                                     | Residual Risk |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------- |
| **PR-1** | **PII exposure in AI prompts & checkpoints:** User financial data included in prompts is held in working-state checkpoints during active/deferred sessions                       | MODERATE   | HIGH     | NeMo/Presidio screens 15 entity types before vLLM inference; checkpoints traverse Linkerd mTLS into CMEK-encrypted Valkey DB `3` under `SHA-256` hashed keys and expire `14,460 s` (`4h 1m`) after last write (`CP-1`)                         | LOW           |
| **PR-2** | **Telemetry export into immutable storage (`POAM-2026-225`):** Raw prompts/user IDs exported to Langfuse land in a `2,555`-day locked GCS event bucket that cannot be purged early | LOW        | HIGH     | Source capture removed across gateway/advisor/NeMo, capture env vars pinned `"false"`, and fail-closed [`ContentFilterSpanExporter`](../../src/gateway/observability/content_filter.py) drops content/identity keys (`#774` `TC-1`); retired locked synthetic bucket isolated under IAM deny policy `privacy-hold=active` until `2033-10-27` | LOW           |
| **PR-3** | **Free-text PII placed inside structured tool `params`:** `PIISanitizer` on the WORM path is regex-based (`6` structured patterns) and does not NER-redact unlabelled prose names | MODERATE   | MODERATE | Tool schemas use typed ticker/amount/quantity fields rather than free-text prose; `PIISanitizer` scrubs SSN, CC, IBAN, labelled/keyed BIC, email, phone, and tokens before `module.worm_bucket`                                                | MODERATE      |
| **PR-4** | **Shared HMAC key compromise (IA-5/SC-12):** `CAGE_ROUTING_SEAL_SECRET` exposure could permit forged internal routing seals                                                      | LOW        | HIGH     | Secret provisioned via GCP Secret Manager, startup fails closed in enforcing postures when absent or default, and [`compliance/lula/lula-validation-ia5.yaml`](../lula/lula-validation-ia5.yaml) validates secret posture                       | LOW           |
| **PR-5** | **Silent fallback to non-durable memory (`POAM-2026-226`):** Ephemeral checkpointer fallback loses deferred HITL state across restarts without operator visibility               | LOW        | MODERATE | Enforcing postures refuse `MemorySaver` (`CheckpointDurabilityError`), verify `/governance/checkpoints/health` at boot, and return HTTP `503` on `/health` readiness when non-durable (`#779` `CP-1`)                                          | LOW           |
| **PR-6** | **Operational container log snippets:** `INFO`/`WARNING` logs emit `50`/`200`-char snippets (`DEBUG` logs full prompts) to Cloud Logging `_Default`                              | MODERATE   | LOW      | `_Default` bucket enforces automatic `30`-day deletion (`≤ 90 d`); enforcing deployments run at `INFO` level and restrict `roles/logging.viewer`                                                                                               | LOW           |
| **PR-7** | **Model training data leakage:** Financial PII in prompts could be reused for fine-tuning                                                                                        | LOW        | HIGH     | Self-hosted vLLM is inference-only with read-only weights; Langfuse holds zero prompt/response text (`TC-1`) and has no export path to training pipelines                                                                                      | LOW           |
| **PR-8** | **Retention mismatch between 90-day privacy ceiling and 7-year SEC/FINRA audit rule:** Mixing conversational text into 7-year locked buckets prevents timely disposal            | LOW        | HIGH     | Store separation enforced (`§6.2`): conversational checkpoints expire in `4h 1m` (Valkey DB `3`), logs expire in `30 d`, telemetry carries zero content (`TC-1`), and only structured `PIISanitizer`-scrubbed governance proofs enter `2,555 d` WORM storage | LOW           |

---

## 11. PII Minimization

### 11.1 NeMo Guardrails PII Detection (Inference Rail)

When an active model backend with NeMo Guardrails is enabled, the Presidio-backed `recognize_pii` rail ([`config/rails/config.yml`](../../config/rails/config.yml)):

1. **Scans user prompts** before they reach the vLLM inference service
2. **Detects 15 PII entity types** (`§2.2`)
3. **Redacts detected PII** in-flight with entity tags (`[US_SSN]`, `[CREDIT_CARD]`, etc.)
4. **Blocks high-risk prompts** inconsistent with advisory policy

### 11.2 Schema & Identifier Minimization

- OPA Rego policies ([`src/cage_finance/opa/trade_governance.rego`](../../src/cage_finance/opa/trade_governance.rego)) evaluate role claims and numeric/symbolic trade parameters rather than raw account numbers
- Gateway checkpoint endpoints transport `thread_id` exclusively in POST JSON bodies and hash `caller_identity` and `thread_id` with `SHA-256` in Redis keys (`CP-1`)

### 11.3 Telemetry Minimization (`TC-1`)

- OTel spans export **zero** prompt text, model response text, tool argument bodies, or end-user identifiers (`enduser.id`, `user.id`, email headers)
- Text-handling spans record integer character counts only (`cage.content.input_length`, `cage.content.output_length`)
- [`ContentFilterSpanExporter`](../../src/gateway/observability/content_filter.py) enforces a deny-list of exact keys, prefixes, and suffixes on every span, event, and link, dropping any span it cannot sanitize

### 11.4 Logging Minimization

- Container stdout/stderr logs in GCP Cloud Logging `_Default` retain for `30` days (`INFO` level emits bounded `50`/`200`-char operational snippets only; `DEBUG` must remain off in enforcing postures)
- Cloud Logging exclusion or transformation filters may be layered by adopters requiring sub-30-day log retention

---

## 12. Individual Rights

### 12.1 Right of Access

Individuals whose PII is processed by CAGE may submit written access requests to the designated Privacy Officer:

1. Privacy Officer verifies requester identity and authorization
2. Because operational telemetry (`Langfuse`) stores **no** user identifiers or conversation text (`TC-1`) and LangGraph checkpoints expire `4h 1m` after the last write (`CP-1`), retrievable records after session expiry consist of authoritative governance audit entries (`initiator_urn`) in `module.worm_bucket` and any log entries within the `30`-day Cloud Logging window
3. Response is provided within 30 days (or applicable statutory window)

### 12.2 Right of Correction

- Identity attributes derive from the upstream OIDC/IAM identity provider and must be corrected at that source of truth
- KMS-signed WORM governance records in `module.worm_bucket` are immutable; factual annotations or superseding entries are appended without altering historical hashes

### 12.3 Right of Deletion

Deletion requests are honored according to the technical store boundaries in `§6.2`:

- **Working-state checkpoints (Valkey DB `3`):** Expire automatically within `4h 1m` of last write (`CP-1`), or can be purged immediately via authenticated `POST /governance/checkpoints/delete` (`GatewayCheckpointSaver.adelete_thread`)
- **Application logs (`_Default`):** Expire automatically at `30` days
- **Authoritative governance audit records (`module.worm_bucket`):** Subject to mandatory `2,555`-day (`7`-year) SEC Rule 17a-4 / FINRA Rule 4511 WORM lock — **cannot be deleted prior to lock expiry**
- **Retired `2026-05`–`2026-10` synthetic telemetry bucket (`POAM-2026-225`):** Contains synthetic test data only; locked at the GCS storage layer until `2033-05-19`–`2033-10-27` under IAM deny policy `privacy-hold=active` and cannot be deleted early

### 12.4 Right to Object / Opt-Out

The CAGE system is an enterprise financial advisory governance control plane, not a consumer-facing service. Authorized personnel cannot opt out of governance evaluation or mandatory regulatory audit logging when executing governed actions.

### 12.5 Privacy Complaints

Individuals may submit privacy complaints to:

- **Internal:** Privacy Officer (contact designated prior to ATO)
- **Regulatory:** SEC Office of Investor Education and Advocacy; FINRA Investor Complaint Center

---

## 13. Approval Block

---

**[SIGNATURE REQUIRED — PENDING PRIVACY OFFICER APPROVAL]**

This Privacy Impact Assessment has been prepared in accordance with OMB Memorandum M-03-22 and NIST SP 800-122. It requires review and approval by the designated Privacy Officer prior to system authorization.

| Role                     | Name  | Signature                      | Date           |
| ------------------------ | ----- | ------------------------------ | -------------- |
| **System Owner**         | [TBD] | ************\_\_\_************ | ****\_\_\_**** |
| **Privacy Officer**      | [TBD] | ************\_\_\_************ | ****\_\_\_**** |
| **ISSO**                 | [TBD] | ************\_\_\_************ | ****\_\_\_**** |
| **Authorizing Official** | [TBD] | ************\_\_\_************ | ****\_\_\_**** |

---

**Review Schedule:**  
This PIA must be reviewed and updated:

- Prior to system ATO issuance
- When new PII categories or new stateful stores (such as long-term memory) are introduced
- When new external data sharing arrangements are established
- When significant system changes affect PII handling or retention enforceability
- Annually during the ATO renewal cycle

**Document Control:**

| Version                | Date       | Author     | Change Summary                                                                                                                                                                    |
| ---------------------- | ---------- | ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1.0 (Draft)            | 2026-03-06 | ISSO       | Initial PIA draft per NIST RMF Phase 2A requirements                                                                                                                              |
| 1.1 (Draft, Corrected) | 2026-11-16 | Maintainer | `POAM-2026-225` & `POAM-2026-226` correction: added complete store-by-store retention & enforceability inventory (`§6.2`), documented retired locked bucket 2033 asymmetry, withdrew false `§6.2` NeMo trace-redaction claim, and aligned all sections with `#774` (`TC-1`) and `#779` (`CP-1`) |

---

_This document is SENSITIVE — PRIVACY CONTROLLED. Distribute only to personnel with a need-to-know for privacy review and authorization purposes._

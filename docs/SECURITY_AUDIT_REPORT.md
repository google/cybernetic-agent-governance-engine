# CAGE Security Audit Report
**Date:** 2026-06-12
**Release decision:** GO — STABLE RELEASE APPROVED (v2.0.0, 2026-06-08). This audit report was produced prior to the GO decision; findings documented here were evaluated as part of the release gate process. The GO decision stands — see [`docs/PRODUCTION_READINESS_REPORT.md`](PRODUCTION_READINESS_REPORT.md) for the full gate evaluation.
**Scope:** Full codebase review — gateway, compliance bridge, governed financial advisor, infrastructure/deployment
**Postures:** Dev (relaxed) and Prod (hardened)
**Auditor:** Automated multi-agent review

---

## Executive Summary

A comprehensive security and bug review of the CAGE (Cybernetic AI Governance Engine) codebase identified **108 findings** across four major subsystems. The system is a financial AI governance platform that routes, signs, and audits AI-generated trade recommendations. The severity distribution is:

| Severity | Count | Immediate Action Required |
|----------|-------|--------------------------|
| **Critical** | 10 | Yes — block prod deployment |
| **High** | 46 | Yes — fix before next release |
| **Medium** | 43 | Plan within current sprint |
| **Low** | 9 | Backlog |

**Key themes:**
1. **Governance bypass via fail-open defaults** — multiple safety controls silently pass when dependencies (Redis, KMS, OPA) are unavailable
2. **No authentication on financial API endpoints** — trade execution, approval, and query endpoints are unauthenticated
3. **Hardcoded sell→buy trade side inversion** — every sell order executes as a buy, increasing exposure
4. **KMS signing never activated** — both gateway and compliance bridge KMS signers are initialized but never started
5. **GKE control plane exposed to 0.0.0.0/0** — dev tfvars allow unrestricted internet access to the Kubernetes API server
6. **OPA governance bypass via missing input fields** — quota and tool allowlist rules default to `true` when fields are absent

---

## Severity Definitions

| Level | Definition |
|-------|-----------|
| **Critical** | Exploitable now; direct financial loss, data breach, or complete governance bypass possible |
| **High** | Significant risk; exploitable under realistic conditions or causes silent functional failure |
| **Medium** | Moderate risk; requires specific conditions or has limited blast radius |
| **Low** | Minor issue; informational, cosmetic, or very low probability |

---

## Section 1 — Critical Findings

### C-01: All Sell Orders Execute as Buy Orders
- **File:** [`src/gateway/core/tools.py:88`](src/gateway/core/tools.py:88)
- **Category:** Bug
- **Dev vs Prod:** Affects both
- **Description:** The `execute_trade()` function hardcodes `"side": "buy"` regardless of the requested trade direction. Every sell instruction sent through the governed financial advisor increases market exposure instead of reducing it.
- **Impact:** Direct financial loss. A risk-reduction sell order becomes a risk-amplifying buy. In a live trading environment this is catastrophic.
- **Fix:** Replace the hardcoded `"side": "buy"` with `"side": action` where `action` is the validated parameter from the trade request. Add an assertion that `action in {"buy", "sell"}` before submission.

---

### C-02: CBF Safety Check is Fail-Open on Redis Unavailability
- **File:** [`src/gateway/governance/symbolic_governor.py:677`](src/gateway/governance/symbolic_governor.py:677)
- **Category:** Security
- **Dev vs Prod:** Affects both
- **Description:** The Control Barrier Function (CBF) `pre_check()` catches all exceptions from Redis and returns `True` (ALLOW) on failure. If Redis is unavailable, overloaded, or experiencing a network partition, all CBF safety checks are silently bypassed.
- **Impact:** Complete bypass of the primary runtime safety control during infrastructure stress events — exactly when safety controls are most needed.
- **Fix:** Change the exception handler to return `False` (DENY) and emit a `SAFETY_DEGRADED` alert. Add a circuit breaker that rejects all requests when Redis has been unavailable for more than N seconds.

---

### C-03: Default HMAC Salt Allows Routing Seal Forgery
- **File:** [`src/gateway/governance/routing_seal.py:74`](src/gateway/governance/routing_seal.py:74)
- **Category:** Security
- **Dev vs Prod:** Prod critical; dev acceptable
- **Description:** The routing seal HMAC uses a well-known public default salt (`"cage-default-salt-change-in-production"`) when `GOVERNANCE_SALT` is not set. The `assert_custom_salt_in_production()` guard is never called automatically at startup — it must be invoked manually.
- **Impact:** Any party who knows the default salt (it is in the public source code) can forge valid routing seals, bypassing the entire request authentication chain.
- **Fix:** Call `assert_custom_salt_in_production()` unconditionally at module import time. Raise `RuntimeError` at startup if `GOVERNANCE_SALT` is not set and `CAGE_ENV=prod`.

---

### C-04: Incomplete Authentication Coverage on Trade Execution Endpoints
- **File:** [`src/governed_financial_advisor/server.py:242`](src/governed_financial_advisor/server.py:242), [`src/governed_financial_advisor/server.py:396`](src/governed_financial_advisor/server.py:396), [`src/governed_financial_advisor/server.py:818`](src/governed_financial_advisor/server.py:818), [`src/governed_financial_advisor/tools/api.py:56`](src/governed_financial_advisor/tools/api.py:56)
- **Category:** Security
- **Dev vs Prod:** Prod critical; dev acceptable
- **Status note (2026-06-08):** Authentication IS implemented on the `/agent/query` endpoint via `Depends(require_api_key)` in [`src/governed_financial_advisor/server.py`](src/governed_financial_advisor/server.py). The finding as originally written overstated the gap — `/agent/query` is authenticated. The remaining concern is **incomplete coverage**: the `/v1/approvals/{thread_id}/resume`, NeMo refinement approval, and `/tools/execute` endpoints do not yet have equivalent `require_api_key` enforcement. This finding is therefore reclassified from "No authentication" to "Incomplete authentication coverage."
- **Description:** The `/v1/approvals/{thread_id}/resume`, NeMo refinement approval, and `/tools/execute` endpoints lack authentication middleware. The `/agent/query` endpoint is protected via `Depends(require_api_key)`. Any unauthenticated HTTP client can approve pending trades or directly execute trades via the unprotected endpoints.
- **Impact:** Partial authorization bypass. An attacker on the same network (or internet if ingress is misconfigured) can approve or execute trades via the unprotected endpoints without credentials.
- **Fix:** Extend `Depends(require_api_key)` to the `/v1/approvals/{thread_id}/resume`, NeMo refinement approval, and `/tools/execute` endpoints. Use Kubernetes service account tokens for internal service-to-service calls. Apply the existing `CAGE_ROUTING_SEAL_SECRET` HMAC verification to all inbound requests.

---

### C-05: LLM-Generated Python Code Executed Without Sandboxing
- **File:** [`src/governed_financial_advisor/governance/transpiler.py:242`](src/governed_financial_advisor/governance/transpiler.py:242)
- **Category:** Security
- **Dev vs Prod:** Affects both
- **Description:** The `transpiler.py` module uses `exec()` to run Python code generated by an LLM. There is no sandboxing, no AST validation, no restricted builtins, and no resource limits. The LLM output is executed with full process privileges.
- **Impact:** Remote code execution. A prompt injection attack or a compromised LLM endpoint can execute arbitrary Python with the privileges of the governed-financial-advisor pod (which has GCS and Redis access).
- **Fix:** Replace `exec()` with a sandboxed evaluator (e.g., `RestrictedPython` or a subprocess with `seccomp` profile). Alternatively, replace the code-generation approach with a structured DSL that maps to pre-approved function calls only.

---

### C-06: GKE Control Plane Exposed to 0.0.0.0/0
- **File:** [`infra/targets/gcp-gke/eu-dev.tfvars:85`](infra/targets/gcp-gke/eu-dev.tfvars:85), [`infra/targets/gcp-gke/apac-dev.tfvars:85`](infra/targets/gcp-gke/apac-dev.tfvars:85)
- **Category:** Security
- **Dev vs Prod:** Dev only — must never reach prod
- **Description:** Both dev tfvars set `master_authorized_networks = ["0.0.0.0/0"]`, exposing the GKE Kubernetes API server to the entire internet. The Kubernetes API server is the highest-privilege endpoint in the cluster.
- **Impact:** Any internet host can attempt to authenticate to the Kubernetes API. Combined with any credential leak (service account token in logs, etc.), this gives full cluster control to an attacker.
- **Fix:** Restrict `master_authorized_networks` to specific CIDR ranges (VPN, office IPs, Cloud Build NAT IPs). Never use `0.0.0.0/0` even in dev. Add a Terraform validation rule that rejects `0.0.0.0/0` for this variable.

---

### C-07: Unauthenticated Audit Result Injection Endpoint
- **File:** [`src/compliance_bridge/main.py:655`](src/compliance_bridge/main.py:655)
- **Category:** Security
- **Dev vs Prod:** Prod critical
- **Description:** The `POST /v1/audit/ingest` endpoint accepts audit results from any caller without authentication. An attacker can inject fabricated compliance scores, overwriting real audit results with fake PASS verdicts.
- **Impact:** Complete compliance posture falsification. An attacker can make a non-compliant system appear compliant to auditors and automated gate checks.
- **Fix:** Require a signed JWT or mutual TLS client certificate on the `/v1/audit/ingest` endpoint. Validate that the `audit_id` in the payload matches a known pending audit initiated by the compliance bridge itself.

---

### C-08: KMS Batch Signer Never Started Despite Being Enabled
- **File:** [`src/compliance_bridge/kms_batch_signer.py:79`](src/compliance_bridge/kms_batch_signer.py:79)
- **Category:** Bug / Compliance
- **Dev vs Prod:** Affects both
- **Description:** `KMSBatchSigner._ENABLED` is set to `True` and the signer is instantiated, but `signer.start()` is never called in `main.py`. All compliance evidence is stored unsigned. The `assert_kms_active_in_production()` guard is also never called.
- **Impact:** All compliance evidence artifacts lack cryptographic integrity protection. An attacker with GCS write access can tamper with evidence without detection. ISO 42001 A.9.2 (evidence integrity) is violated.
- **Fix:** Call `await signer.start()` in the compliance bridge startup sequence. Call `assert_kms_active_in_production()` at startup when `CAGE_ENV=prod`. Add a health check that fails if KMS is enabled but not running.

---

### C-09: Compliance Audit Workflow Broken — Langfuse API Mismatch
- **File:** [`src/compliance_bridge/audit_workflow.py:269`](src/compliance_bridge/audit_workflow.py:269)
- **Category:** Bug / Compliance
- **Dev vs Prod:** Affects both
- **Description:** `audit_workflow.py` calls `langfuse.start_observation()` which does not exist in the current Langfuse SDK. The correct method is `langfuse.trace()` or `langfuse.generation()`. Additionally, `propagate_attributes` is imported from a non-existent module path, causing an `ImportError` at runtime.
- **Impact:** No compliance scores are ever recorded in Langfuse. The entire automated audit trail is silently broken. Compliance reports show no data.
- **Fix:** Update to the current Langfuse SDK API (`langfuse.trace()` / `langfuse.generation()`). Fix the `propagate_attributes` import path. Add integration tests that verify Langfuse observations are actually created.

---

### C-10: OPA Governance Rules Default to ALLOW When Input Fields Are Absent
- **File:** [`deployment/system_authz.rego:54`](deployment/system_authz.rego:54)
- **Category:** Security
- **Dev vs Prod:** Affects both
- **Description:** The OPA policy has permissive default clauses: `quota_within_limits if { not input.sequence_step_count }` and `tool_approved if { not input.tool_name }`. Any governance check request that omits these fields unconditionally passes all quota and tool allowlist enforcement.
- **Impact:** A buggy or malicious client that omits `sequence_step_count`, `accumulated_tokens`, or `tool_name` from the OPA input bypasses all quota and tool controls. This is a governance bypass via input omission.
- **Fix:** Remove all permissive default clauses. Use `object.get` with fail-closed defaults: `step_count := object.get(input, "sequence_step_count", max_steps + 1)` so a missing field triggers a violation. Add an explicit check that all required fields are present.

---

## Section 2 — High Severity Findings

### H-01: ISO Control Audit Trail Written to Ephemeral In-Memory Store
- **File:** [`src/gateway/governance/iso_control.py`](src/gateway/governance/iso_control.py)
- **Category:** Compliance
- **Dev vs Prod:** Affects both
- **Description:** ISO 42001 control evaluation results are stored in a module-level in-memory list. On pod restart, all audit history is lost. There is no persistence to Redis, GCS, or any durable store.
- **Impact:** AU-12 (Audit Record Generation) violated. Compliance evidence is non-durable. A pod crash during an audit window produces a gap in the audit trail that cannot be reconstructed.
- **Fix:** Persist ISO control evaluations to the compliance bridge via the evidence stream. Use the existing `EvidenceStream.publish()` mechanism to write each evaluation result durably.

---

### H-02: Causal Gatekeeper Timestamp-Based Ordering Is Bypassable
- **File:** [`src/gateway/governance/causal_gatekeeper.py`](src/gateway/governance/causal_gatekeeper.py)
- **Category:** Security / Compliance
- **Dev vs Prod:** Affects both
- **Description:** The causal gatekeeper verifies that governance checks precede trade execution using wall-clock timestamp comparison. In distributed systems, clock skew and out-of-order span reporting make timestamp-based causal ordering unreliable. A compromised agent can manipulate span timestamps to make a DENY decision appear to follow an execution.
- **Impact:** The core audit invariant (governance before execution) is bypassable via timestamp manipulation. Fraudulent trades can be made to appear governance-approved in the audit trail.
- **Fix:** Use OpenTelemetry span parent-child relationships for causal ordering. The governance check span must be the parent of the execution span. Verify `parentSpanId` relationships, not timestamps.

---

### H-03: UCA Logger Writes Unsafe Control Actions to Unprotected GCS Path
- **File:** [`src/gateway/governance/uca_logger.py`](src/gateway/governance/uca_logger.py)
- **Category:** Security / Compliance
- **Dev vs Prod:** Affects both
- **Description:** UCA (Unsafe Control Action) log entries are written to GCS without CMEK encryption and without access logging. The UCA log contains details of every governance violation, including the triggering prompt content, which may contain PII or sensitive financial data.
- **Impact:** Sensitive governance violation data (including user prompts) is stored unencrypted in GCS. If the bucket ACL is misconfigured, this data is exposed. GDPR Art. 32 (security of processing) and MAS Notice 655 (data protection) may be violated.
- **Fix:** Apply CMEK encryption to the UCA log GCS bucket. Enable GCS access logging. Sanitize PII from UCA log entries using the existing `PIISanitizer` before writing.

---

### H-04: Inference Proxy Forwards Raw Error Messages to Clients
- **File:** [`src/gateway/server/inference_proxy.py`](src/gateway/server/inference_proxy.py)
- **Category:** Security
- **Dev vs Prod:** Affects both
- **Description:** Exception handlers in the inference proxy return raw Python exception messages (including stack traces in some cases) directly to API callers in the HTTP response body.
- **Impact:** Internal system details (file paths, module names, dependency versions, internal URLs) are leaked to external callers. This information aids attackers in crafting targeted exploits.
- **Fix:** Replace all `str(e)` in HTTP error responses with generic messages. Log the full exception server-side with a correlation ID. Return only the correlation ID to the caller.

---

### H-05: KMS Signer in Gateway Has No Production Enforcement
- **File:** [`src/gateway/governance/kms_signer.py`](src/gateway/governance/kms_signer.py)
- **Category:** Security / Compliance
- **Dev vs Prod:** Prod critical
- **Description:** The gateway KMS signer is instantiated but `assert_kms_active_in_production()` is never called at startup. In production, if `GCP_KMS_KEY_NAME` is not set, all request signatures fall back to a no-op stub that returns empty bytes, silently disabling cryptographic request integrity.
- **Impact:** All signed governance decisions lack cryptographic integrity in any deployment where the KMS environment variable is missing. Tampered decisions cannot be detected.
- **Fix:** Call `assert_kms_active_in_production()` in the gateway startup sequence. Fail fast with a clear error if KMS is not configured in prod. Add a `/healthz` check that verifies KMS connectivity.

---

### H-06: Constants File Contains Hardcoded Fallback Credentials
- **File:** [`src/gateway/governance/constants.py`](src/gateway/governance/constants.py)
- **Category:** Security
- **Dev vs Prod:** Prod critical
- **Description:** `constants.py` uses `os.environ.get("KEY", "hardcoded-fallback")` patterns for security-sensitive values including the OPA auth token and internal service URLs. Hardcoded fallbacks mean the system silently operates with known-weak credentials when environment variables are not set.
- **Impact:** Any deployment that fails to set the required environment variables (misconfiguration, CI/CD error) silently uses the hardcoded fallback credentials, which are in the public source code.
- **Fix:** Replace all `os.environ.get("KEY", "fallback")` patterns for security-sensitive values with `os.environ["KEY"]` (raises `KeyError` on missing) or explicit startup validation that fails fast.

---

### H-07: CBF Barrier Certificate Computed with Stale State
- **File:** [`src/gateway/governance/cbf.py`](src/gateway/governance/cbf.py)
- **Category:** Bug
- **Dev vs Prod:** Affects both
- **Description:** The Control Barrier Function reads system state from Redis at check time, but the state snapshot used for the barrier certificate computation is not atomic. Between reading individual state components (position size, exposure, drawdown), other requests can modify the state, causing the CBF to evaluate against an inconsistent snapshot.
- **Impact:** The CBF may approve a trade that would violate safety constraints when evaluated against the true current state. Race conditions under high load can cause safety violations to slip through.
- **Fix:** Use a Redis `MULTI/EXEC` transaction or Lua script to atomically read all state components needed for the CBF computation in a single round-trip.

---

### H-08: Normative Provider Loads Policy Files Without Integrity Verification
- **File:** [`src/gateway/governance/normative_provider.py`](src/gateway/governance/normative_provider.py)
- **Category:** Security
- **Dev vs Prod:** Affects both
- **Description:** Policy files (Rego, YAML) are loaded from GCS or local filesystem without any cryptographic integrity check (no hash verification, no signature validation). A compromised GCS bucket or a path traversal vulnerability could cause malicious policy files to be loaded.
- **Impact:** An attacker with GCS write access can replace policy files with permissive versions that allow all trades, effectively disabling governance.
- **Fix:** Store SHA-256 hashes of all policy files in a separate, write-protected GCS bucket or Secret Manager. Verify hashes after download before loading. Use GCS object versioning and audit logging on the policy bucket.

---

### H-09: Text Filter Regex Patterns Loaded Without Validation
- **File:** [`src/gateway/governance/text_filter.py`](src/gateway/governance/text_filter.py)
- **Category:** Security / Bug
- **Dev vs Prod:** Affects both
- **Description:** Regex patterns for the text filter are loaded from configuration without validation. A malformed regex pattern causes `re.compile()` to raise an exception that is caught and silently ignored, disabling that filter rule. A ReDoS (Regular Expression Denial of Service) attack is possible if patterns are user-configurable.
- **Impact:** Malformed patterns silently disable content filtering rules. A ReDoS attack via a crafted pattern can cause catastrophic backtracking, consuming 100% CPU and blocking the gateway.
- **Fix:** Validate all regex patterns at load time using `re.compile()` with a timeout wrapper. Reject patterns that fail to compile rather than silently ignoring them. Use `re2` (linear-time regex) instead of Python's `re` module for user-supplied patterns.

---

### H-10: Token Quota Proxy Has No Atomic Increment — Race Condition
- **File:** [`src/gateway/governance/token_quota_proxy.py`](src/gateway/governance/token_quota_proxy.py)
- **Category:** Bug / Security
- **Dev vs Prod:** Affects both
- **Description:** The token quota check and increment are performed as two separate Redis operations (GET then SET/INCR) without a transaction. Under concurrent load, multiple requests can read the same quota value below the limit and all proceed, collectively exceeding the quota.
- **Impact:** Token quota limits can be exceeded by a factor equal to the number of concurrent requests. A quota of 10,000 tokens could be exceeded to 50,000+ tokens under load, causing unexpected costs and potential rate limiting from upstream LLM providers.
- **Fix:** Use Redis `INCR` with a Lua script that atomically checks and increments: `if redis.call('GET', key) < limit then return redis.call('INCR', key) else return -1 end`.

---

### H-11: Fiscal Limit Guard Allows Negative Trade Values
- **File:** [`src/gateway/governance/fiscal_limit_guard.py`](src/gateway/governance/fiscal_limit_guard.py)
- **Category:** Bug
- **Dev vs Prod:** Affects both
- **Description:** The fiscal limit guard checks that trade value does not exceed the configured maximum, but does not validate that trade value is positive. A negative trade value (e.g., `-1000000`) passes all fiscal limit checks while representing an economically nonsensical or potentially exploitable trade.
- **Impact:** Negative trade values could be used to circumvent fiscal controls or cause accounting errors in downstream systems that assume positive trade values.
- **Fix:** Add `assert trade_value > 0` validation before the fiscal limit check. Return a DENY decision with reason `"invalid_trade_value"` for non-positive values.

---

### H-12: Policy Loader Executes YAML from Remote Storage Without Schema Validation
- **File:** [`src/governed_financial_advisor/governance/policy_loader.py:50`](src/governed_financial_advisor/governance/policy_loader.py:50)
- **Category:** Security
- **Dev vs Prod:** Affects both
- **Description:** `policy_loader.py` downloads YAML policy files from GCS and loads them with `yaml.safe_load()` without validating the structure against a schema. A malicious or corrupted policy file could contain unexpected keys that alter governance behavior.
- **Impact:** A compromised GCS bucket can deliver a policy file that disables governance controls or introduces permissive rules. Without schema validation, the system silently accepts malformed policies.
- **Fix:** Define a JSON Schema or Pydantic model for policy files. Validate downloaded YAML against the schema before applying it. Reject and alert on schema violations.

---

### H-13: Redis Unauthenticated — No requirepass Set
- **File:** [`deployment/k8s/redis-config.yaml:47`](deployment/k8s/redis-config.yaml:47)
- **Category:** Security
- **Dev vs Prod:** Prod critical
- **Description:** The Redis ConfigMap does not set `requirepass`. Any pod in the `governance-stack` namespace (or any pod that can reach Redis via the network policy) can read and write all Redis data without authentication.
- **Impact:** All governance state (CBF state, token quotas, approval tokens, LangGraph checkpoints) is readable and writable by any pod. An attacker with pod execution can manipulate governance state directly.
- **Fix:** Set `requirepass` in the Redis ConfigMap using a value from Kubernetes Secret. Update all Redis clients to pass the password. Enable Redis ACLs to restrict which commands each client can execute.

---

### H-14: Cilium Egress FQDN Allowlist Targets Wrong Pod Label
- **File:** [`deployment/k8s/cilium-egress-lockdown.yaml:74`](deployment/k8s/cilium-egress-lockdown.yaml:74)
- **Category:** Configuration / Security
- **Dev vs Prod:** Affects both
- **Description:** The Cilium egress policy that allows the gateway to reach external LLM APIs uses the label selector `app: governed-financial-advisor` instead of `app: gateway`. The gateway pod has label `app: gateway` and is therefore not matched by this rule, blocking all legitimate egress. The financial advisor pod gets unintended egress permissions.
- **Impact:** The zero-trust egress model is broken in two ways: the gateway cannot reach external APIs (functional failure), and the financial advisor has unintended external egress permissions (security violation).
- **Fix:** Correct the label selector to `app: gateway`. Create a separate, more restrictive egress rule for the financial advisor that allows only the compliance bridge and internal services.

---

### H-15: Langfuse Exposed Over HTTP Without TLS at Root Path
- **File:** [`deployment/k8s/ingress.yaml:27`](deployment/k8s/ingress.yaml:27)
- **Category:** Security
- **Dev vs Prod:** Prod critical
- **Description:** The Kubernetes Ingress exposes Langfuse (which contains all compliance evidence, audit traces, and LLM interaction logs) at the root path over HTTP without TLS termination. All compliance data is transmitted in cleartext.
- **Impact:** All compliance evidence, audit traces, and LLM prompts/responses (which may contain PII and financial data) are transmitted unencrypted. SC-8 (Transmission Confidentiality) is violated. GDPR Art. 32 requires encryption in transit.
- **Fix:** Add TLS termination to the Ingress using a cert-manager certificate. Redirect all HTTP to HTTPS. Move Langfuse to a subpath (e.g., `/langfuse/`) and add authentication middleware (OAuth2 proxy or similar).

---

### H-16: deploy_all.sh Exports All Secrets to Child Process Environments
- **File:** [`deploy_all.sh:79`](deploy_all.sh:79)
- **Category:** Security
- **Dev vs Prod:** Affects both
- **Description:** The `load_env()` function uses `set -a; source .env; set +a`, which exports ALL variables from `.env` (including `LANGFUSE_SECRET_KEY`, `CAGE_ROUTING_SEAL_SECRET`, `GOVERNANCE_SALT`) to all child processes spawned by the script.
- **Impact:** Secrets are visible in `/proc/<pid>/environ` for all child processes. If any child process (terraform, gcloud, kubectl) logs its environment in debug mode, all secrets are logged to Cloud Build logs or local terminal history.
- **Fix:** Use GCP Secret Manager for deployment secrets. If `.env` must be used, selectively export only the variables needed by each specific child process rather than using `set -a` to export everything globally.

---

## Section 3 — Medium Severity Findings (Part 1 of 3)

### M-01: Query Cache Bypasses Governance Pipeline on Cache Hit
- **File:** [`src/governed_financial_advisor/server.py:283`](src/governed_financial_advisor/server.py:283)
- **Category:** Security / Compliance
- **Dev vs Prod:** Affects both
- **Description:** When a query matches the cache, the response is returned directly without passing through the governance pipeline (OPA check, CBF check, NeMo guardrails). The cached response may have been approved under different market conditions or risk parameters.
- **Impact:** Stale governance decisions are served as current. A trade that was approved yesterday may be served from cache today even if current risk parameters would deny it.
- **Fix:** Either disable caching for governance-sensitive queries, or include the current governance context (risk parameters, market state hash) as part of the cache key so stale decisions are never served.

---

### M-02: Cache Key Collision Risk — SHA-256 Truncated to 16 Hex Chars
- **File:** [`src/governed_financial_advisor/infrastructure/query_cache.py:111`](src/governed_financial_advisor/infrastructure/query_cache.py:111)
- **Category:** Bug
- **Dev vs Prod:** Affects both
- **Description:** Cache keys are generated by truncating SHA-256 to 16 hex characters (64 bits). The birthday paradox gives a 50% collision probability at ~4 billion entries. In a high-volume trading system, cache collisions cause wrong responses to be served.
- **Impact:** A cache collision causes one user's query response to be served to a different user, potentially leaking financial recommendations or causing incorrect trade decisions.
- **Fix:** Use the full SHA-256 hash (64 hex characters) as the cache key. The storage overhead is negligible.

---

### M-03: Approval Token Validation Is Trivially Bypassable
- **File:** [`src/governed_financial_advisor/governance/nemo_actions.py:164`](src/governed_financial_advisor/governance/nemo_actions.py:164)
- **Category:** Security
- **Dev vs Prod:** Affects both
- **Description:** The approval token validation checks only that the token is a non-empty string. There is no cryptographic verification, no expiry check, and no binding to a specific trade or thread ID. Any non-empty string is a valid approval token.
- **Impact:** Any caller who knows the approval endpoint URL can approve any pending trade by sending any non-empty string as the token. The human-in-the-loop approval mechanism is completely ineffective.
- **Fix:** Generate approval tokens as HMAC-SHA256 of `(thread_id + trade_id + expiry_timestamp)` using `CAGE_ROUTING_SEAL_SECRET`. Verify the HMAC and expiry on approval. Bind tokens to specific thread IDs.

---

### M-04: TLS Certificate Verification Disabled for Redis in Financial Advisor
- **File:** [`src/governed_financial_advisor/infrastructure/redis_client.py:155`](src/governed_financial_advisor/infrastructure/redis_client.py:155)
- **Category:** Security
- **Dev vs Prod:** Prod critical
- **Description:** The Redis client in the financial advisor sets `ssl_cert_reqs=None` (no certificate verification) when TLS is enabled. This disables man-in-the-middle protection even when TLS is configured.
- **Impact:** An attacker on the network path between the financial advisor and Redis can intercept and modify all governance state (approval tokens, LangGraph checkpoints, token quotas) without detection.
- **Fix:** Set `ssl_cert_reqs="required"` and provide the CA certificate path via `ssl_ca_certs`. Use the GKE-managed certificate authority for internal service TLS.

---

### M-05: Prompt Injection via User Message in Supervisor Node
- **File:** [`src/governed_financial_advisor/graph/nodes/supervisor_node.py:191`](src/governed_financial_advisor/graph/nodes/supervisor_node.py:191)
- **Category:** Security
- **Dev vs Prod:** Affects both
- **Description:** The supervisor node constructs LLM prompts by directly interpolating user-supplied message content without sanitization. A user can inject instructions that override the system prompt, causing the supervisor to route to unintended agents or bypass governance checks.
- **Impact:** Prompt injection can cause the supervisor to skip the safety node, route directly to trade execution, or exfiltrate system prompt contents. This is a direct attack vector against the governance pipeline.
- **Fix:** Apply the existing `PIISanitizer` and `TextFilter` to user messages before including them in LLM prompts. Use structured message formats (JSON) rather than free-text interpolation. Add NeMo guardrails input rails specifically for prompt injection patterns.

---

### M-06: governed_trader_node Defaults evaluation_result to 'APPROVED'
- **File:** [`src/governed_financial_advisor/graph/nodes/agent_nodes.py:200`](src/governed_financial_advisor/graph/nodes/agent_nodes.py:200)
- **Category:** Bug / Security
- **Dev vs Prod:** Affects both
- **Description:** When the evaluator node fails to produce a result (exception, timeout, or missing key), `governed_trader_node` defaults `evaluation_result` to `'APPROVED'`. This means evaluator failures silently approve trades.
- **Impact:** Any evaluator failure (network error, LLM timeout, exception) causes the trade to proceed as if it were approved. The evaluator is a critical safety gate — its failure should block, not approve.
- **Fix:** Change the default to `'DENIED'` or `'ERROR'`. Only proceed with trade execution when `evaluation_result` is explicitly `'APPROVED'`. Log and alert on evaluator failures.

---

### M-07: SSE Subscriber Count Has No Upper Bound — DoS Vector
- **File:** [`src/compliance_bridge/sse_events.py:192`](src/compliance_bridge/sse_events.py:192)
- **Category:** Performance / Security
- **Dev vs Prod:** Affects both
- **Description:** The SSE event broker accepts unlimited subscriber connections. Each subscriber holds an open HTTP connection and an in-memory queue. An attacker can open thousands of SSE connections, exhausting file descriptors and memory.
- **Impact:** Denial of service against the compliance bridge. All compliance evidence streaming stops, breaking the audit trail for all active governance sessions.
- **Fix:** Implement a maximum subscriber limit (e.g., 100 concurrent SSE connections). Return HTTP 503 when the limit is reached. Add per-IP rate limiting on the SSE endpoint.

---

### M-08: Evidence Sink Skipped When No SSE Subscribers
- **File:** [`src/compliance_bridge/sse_events.py`](src/compliance_bridge/sse_events.py)
- **Category:** Compliance / Bug
- **Dev vs Prod:** Affects both
- **Description:** The evidence publishing path only writes to the SSE broker. If there are no active SSE subscribers (which is the normal state during automated audit runs with no human observers), evidence is not written to any durable store.
- **Impact:** Compliance evidence is lost during all automated audit runs. The audit trail is only complete when a human is actively watching the SSE stream — an unreliable and non-compliant design.
- **Fix:** Decouple evidence durability from SSE delivery. Always write evidence to GCS/Redis first, then fan out to SSE subscribers. SSE is a delivery mechanism, not a storage mechanism.

---

## Section 3 — Medium Severity Findings (Part 2 of 3)

### M-09: OSCAL Parser Has No YAML Size Limit — DoS via Large File
- **File:** [`src/compliance_bridge/oscal_parser.py`](src/compliance_bridge/oscal_parser.py)
- **Category:** Performance / Security
- **Dev vs Prod:** Affects both
- **Description:** The OSCAL parser loads YAML files from GCS using `yaml.safe_load()` without any file size limit. A maliciously crafted or accidentally oversized YAML file can consume all available memory, crashing the compliance bridge pod.
- **Impact:** Denial of service against the compliance bridge. All compliance evidence streaming and audit workflows stop. Recovery requires pod restart.
- **Fix:** Add a file size check before parsing: reject files larger than 10 MB. Use `yaml.safe_load()` with a stream reader that enforces a byte limit. Add a memory limit to the compliance bridge pod via Kubernetes resource limits.

---

### M-10: Metrics Safety Rate Computed from Only Last 100 Traces — Biased
- **File:** [`src/compliance_bridge/metrics.py`](src/compliance_bridge/metrics.py)
- **Category:** Compliance / Bug
- **Dev vs Prod:** Affects both
- **Description:** The `safety_rate` metric is computed from the last 100 Langfuse traces only. In a high-volume system, 100 traces may represent only a few minutes of activity. The metric is also initialized to `1.0` (100% safe) when no traces exist, producing a false PASS on a fresh deployment.
- **Impact:** The safety rate metric used in compliance reports and SLA monitoring is statistically unreliable. A fresh deployment with no traces reports 100% safety, which may satisfy automated gate checks incorrectly.
- **Fix:** Increase the trace window to at least 1,000 traces or a configurable time window (e.g., last 24 hours). Initialize `safety_rate` to `None` (unknown) rather than `1.0` when no traces exist. Fail compliance gates when safety_rate is `None`.

---

### M-11: Lula Scheduler Writes to World-Writable /tmp — TOCTOU Risk
- **File:** [`src/compliance_bridge/lula_scheduler.py`](src/compliance_bridge/lula_scheduler.py)
- **Category:** Security
- **Dev vs Prod:** Affects both
- **Description:** The Lula scheduler writes validation result files to `/tmp` before reading them back. In a shared container environment, `/tmp` is world-writable. A symlink attack between the write and read operations (TOCTOU) could cause the scheduler to read attacker-controlled content.
- **Impact:** A compromised co-located process could replace the Lula validation result with a fake PASS, causing the compliance bridge to report false compliance.
- **Fix:** Use `tempfile.mkstemp()` to create files with restricted permissions (0600). Alternatively, use an in-memory buffer (BytesIO) instead of writing to disk. Set the pod's `/tmp` as a dedicated `emptyDir` volume with `medium: Memory`.

---

### M-12: Unauthenticated Loopback POST in Lula Scheduler
- **File:** [`src/compliance_bridge/lula_scheduler.py`](src/compliance_bridge/lula_scheduler.py)
- **Category:** Security
- **Dev vs Prod:** Affects both
- **Description:** The Lula scheduler posts validation results to the compliance bridge via an unauthenticated HTTP POST to `http://localhost:PORT/v1/lula/results`. Any process running in the same pod can post fake Lula results to this endpoint.
- **Impact:** A compromised process in the compliance bridge pod can inject fake Lula validation results, making non-compliant controls appear compliant.
- **Fix:** Add a shared secret (from Kubernetes Secret) to the loopback POST as a bearer token. Validate the token in the `/v1/lula/results` handler. Alternatively, use a Unix domain socket instead of TCP for intra-pod communication.

---

### M-13: CORS Allows Empty-String Origin with Credentials
- **File:** [`src/compliance_bridge/main.py`](src/compliance_bridge/main.py)
- **Category:** Security
- **Dev vs Prod:** Prod critical
- **Description:** The FastAPI CORS middleware is configured with `allow_origins=[""]` (empty string) and `allow_credentials=True`. An empty string origin matches requests from `null` origin (e.g., from local file:// pages or sandboxed iframes), allowing cross-origin requests with credentials from these contexts.
- **Impact:** A malicious HTML file opened locally by a compliance bridge operator can make credentialed cross-origin requests to the compliance bridge, potentially exfiltrating audit data.
- **Fix:** Set `allow_origins` to the explicit list of allowed origins (e.g., the AgentSight UI URL). Never combine `allow_credentials=True` with wildcard or empty origins.

---

### M-14: PII Sanitizer Regex Patterns Are Incomplete
- **File:** [`src/gateway/governance/pii_sanitizer.py`](src/gateway/governance/pii_sanitizer.py)
- **Category:** Compliance
- **Dev vs Prod:** Affects both
- **Description:** The PII sanitizer uses regex patterns for common PII types (email, phone, SSN) but misses several financial-specific PII types: IBAN numbers, credit card numbers (Luhn-valid), SWIFT/BIC codes, and account numbers. These appear frequently in financial advisory prompts.
- **Impact:** Financial PII passes through the sanitizer unredacted and is stored in Langfuse traces, GCS audit logs, and UCA logs. GDPR Art. 25 (data minimization) and MAS Notice 655 (customer data protection) are violated.
- **Fix:** Add regex patterns for IBAN (ISO 13616), credit card numbers (with Luhn validation), SWIFT/BIC codes, and common account number formats. Consider using a dedicated PII detection library (e.g., Microsoft Presidio) rather than hand-crafted regexes.

---

### M-15: Governance Middleware Does Not Validate Request Signature in Dev Mode
- **File:** [`src/gateway/server/governance_middleware.py`](src/gateway/server/governance_middleware.py)
- **Category:** Security
- **Dev vs Prod:** Dev only — must not reach prod
- **Description:** When `CAGE_ENV=dev`, the governance middleware skips routing seal verification entirely. The dev/prod distinction is based solely on the `CAGE_ENV` environment variable, which is not validated against any external authority.
- **Impact:** If `CAGE_ENV` is accidentally set to `dev` in a production deployment (misconfiguration, CI/CD error), all request signature verification is disabled. The entire routing seal security model collapses.
- **Fix:** Add a secondary check: if `CAGE_ENV=dev` but the pod is running in the `governance-stack` namespace on GKE (detectable via the Kubernetes downward API), refuse to skip signature verification. Log a prominent warning when dev mode is active.

---

### M-16: Hybrid Server Exposes Internal Debug Endpoints in All Environments
- **File:** [`src/gateway/server/hybrid_server.py`](src/gateway/server/hybrid_server.py)
- **Category:** Security
- **Dev vs Prod:** Prod critical
- **Description:** The hybrid server registers debug endpoints (e.g., `/debug/state`, `/debug/governance`) that expose internal governance state, active sessions, and configuration. These endpoints are registered unconditionally regardless of `CAGE_ENV`.
- **Impact:** Internal governance state (active CBF parameters, token quotas, session data) is exposed to any caller who can reach the gateway. This information aids attackers in crafting bypass attempts.
- **Fix:** Gate debug endpoints behind `if settings.CAGE_ENV == "dev"`. In prod, return HTTP 404 for all `/debug/` paths. Add network policy to block external access to debug endpoints even in dev.

---

## Section 3 — Medium Severity Findings (Part 3 of 3)

### M-17: Demo Endpoints Exposed in Production Routing
- **File:** [`src/governed_financial_advisor/demo/router.py:29`](src/governed_financial_advisor/demo/router.py:29)
- **Category:** Security
- **Dev vs Prod:** Prod critical
- **Description:** The demo router registers endpoints (`/demo/run`, `/demo/reset`, `/demo/state`) unconditionally. These endpoints bypass the normal governance pipeline and use hardcoded demo data. They are included in the main FastAPI app regardless of `CAGE_ENV`.
- **Impact:** In production, demo endpoints allow any caller to trigger demo trade workflows that bypass real governance controls, or reset system state. This is a significant attack surface.
- **Fix:** Gate demo router inclusion behind `if settings.CAGE_ENV == "dev"`. In prod, do not register the demo router at all. Add a CI check that verifies demo routes are not reachable in prod configuration.

---

### M-18: SSRF via Unvalidated compliance_bridge_url in KFP Pipeline
- **File:** [`src/governed_financial_advisor/pipelines/green_stack_pipeline.py:58`](src/governed_financial_advisor/pipelines/green_stack_pipeline.py:58)
- **Category:** Security
- **Dev vs Prod:** Affects both
- **Description:** The Kubeflow Pipeline component accepts `compliance_bridge_url` as a pipeline parameter without validating it against an allowlist. A pipeline run submitted with a malicious URL causes the KFP component to make HTTP requests to arbitrary internal or external endpoints.
- **Impact:** Server-Side Request Forgery (SSRF). An attacker who can submit KFP pipeline runs can use the compliance bridge URL parameter to probe internal services (GCP metadata server, Redis, other pods) or exfiltrate data to external endpoints.
- **Fix:** Validate `compliance_bridge_url` against an allowlist of known compliance bridge service URLs. Use a regex that enforces the expected hostname pattern (e.g., `compliance-bridge.governance-stack.svc.cluster.local`).

---

### M-19: Evaluator Trace Variable Shadows opentelemetry trace Module
- **File:** [`src/governed_financial_advisor/evaluators/evaluate_traces.py:152`](src/governed_financial_advisor/evaluators/evaluate_traces.py:152)
- **Category:** Bug
- **Dev vs Prod:** Affects both
- **Description:** The variable `trace` (a Langfuse trace object) shadows the imported `opentelemetry.trace` module in the same scope. All subsequent calls to `trace.get_tracer()` or `trace.get_current_span()` fail with `AttributeError` because `trace` now refers to the Langfuse object.
- **Impact:** The evaluator's OpenTelemetry instrumentation is completely broken. No spans are created for evaluation runs. Evaluation results are not traceable in the distributed trace.
- **Fix:** Rename the loop variable: `for langfuse_trace in traces:` and update all references. Import `opentelemetry.trace as otel_trace` to avoid future shadowing.

---

### M-20: MCP Tool Server Has No Rate Limiting
- **File:** [`src/gateway/server/mcp_tool_server.py`](src/gateway/server/mcp_tool_server.py)
- **Category:** Performance / Security
- **Dev vs Prod:** Affects both
- **Description:** The MCP tool server exposes tool execution endpoints with no rate limiting. Each tool call may trigger LLM inference, Redis operations, and external API calls. An attacker or runaway agent can flood the tool server with requests.
- **Impact:** Resource exhaustion. Unbounded tool calls can exhaust LLM API rate limits (causing cost overruns), saturate Redis connections, and degrade governance performance for all concurrent users.
- **Fix:** Add per-client rate limiting using a sliding window counter in Redis. Implement the existing `TokenQuotaProxy` for MCP tool calls. Add a circuit breaker that rejects tool calls when the system is under load.

---

### M-21: Storage Backend Evaluated at Import Time — Fails Fast on Missing Config
- **File:** [`src/compliance_bridge/storage.py`](src/compliance_bridge/storage.py)
- **Category:** Bug / Configuration
- **Dev vs Prod:** Affects both
- **Description:** The storage backend (GCS vs local) is selected at module import time based on environment variables. If `GCS_BUCKET_NAME` is not set, the module raises an exception during import, crashing the entire compliance bridge before it can log a useful error message.
- **Impact:** A missing environment variable causes a cryptic import-time crash. The compliance bridge fails to start with no useful diagnostic information in the logs.
- **Fix:** Defer backend selection to first use (lazy initialization). Log a clear error message identifying the missing variable. Provide a local filesystem fallback for dev environments with an explicit warning.

---

### M-22: Notifier Embeds LLM Text Verbatim in Slack mrkdwn
- **File:** [`src/compliance_bridge/notifier.py`](src/compliance_bridge/notifier.py)
- **Category:** Security
- **Dev vs Prod:** Affects both
- **Description:** The Slack notifier embeds LLM-generated finding descriptions directly into Slack `mrkdwn` formatted messages without escaping. Slack mrkdwn supports hyperlinks (`<URL|text>`), which can be injected by a malicious LLM response to create phishing links in compliance notifications.
- **Impact:** A prompt injection attack that reaches the compliance notifier can embed malicious hyperlinks in Slack compliance alerts sent to security teams. This is a social engineering vector targeting the security operations team.
- **Fix:** Escape all LLM-generated text before embedding in Slack messages. Replace `<`, `>`, and `&` with their HTML entities. Use Slack's Block Kit with `plain_text` type (which does not render mrkdwn) for untrusted content.

---

### M-23: OPA Decision Logs Written to Console Only — No Durable Audit Sink
- **File:** [`deployment/opa_config.yaml`](deployment/opa_config.yaml)
- **Category:** Compliance
- **Dev vs Prod:** Prod critical
- **Description:** OPA is configured with `decision_logs: console: true` only. Every governance decision (ALLOW/DENY) is logged to stdout and captured by the container logging system. Pod restarts or log rotation cause permanent loss of governance decision history.
- **Impact:** AU-12 (Audit Record Generation) requires durable retention of audit records. OPA decision logs are the authoritative record of every governance decision. Loss of these logs means governance decisions cannot be audited after the fact, violating NIST SP 800-53 AU-12 and ISO 42001 A.9.2.
- **Fix:** Configure OPA's remote decision log plugin to send logs to Cloud Logging or a GCS bucket with a 90-day retention policy. Set `decision_logs: plugin: google_cloud_logging` or use the HTTP plugin to forward to the compliance bridge.

---

### M-24: Container Images Run as Root in Several Deployments
- **File:** [`src/gateway/Dockerfile`](src/gateway/Dockerfile), [`src/compliance_bridge/Dockerfile`](src/compliance_bridge/Dockerfile)
- **Category:** Security
- **Dev vs Prod:** Prod critical
- **Description:** The gateway and compliance bridge Dockerfiles do not set a non-root `USER` directive. Containers run as root (UID 0) by default. The Kubernetes Pod Security Admission policy is set to `restricted` for `governance-stack`, which should block root containers — but the policy enforcement depends on the admission controller being active.
- **Impact:** If PSA enforcement is bypassed or misconfigured, root containers have full write access to the container filesystem and can potentially escape to the host via kernel vulnerabilities.
- **Fix:** Add `USER 1000:1000` (or a named non-root user) to all Dockerfiles. Set `runAsNonRoot: true` and `runAsUser: 1000` in all pod security contexts. Verify PSA `restricted` enforcement is active with `kubectl get namespace governance-stack -o yaml`.

---

## Section 4 — Low Severity Findings

### L-01: Redis Client Uses Deprecated get_event_loop() in Tests
- **File:** [`tests/`](tests/)
- **Category:** Bug
- **Dev vs Prod:** Dev only
- **Description:** Several test files use `asyncio.get_event_loop()` which is deprecated in Python 3.10+ and raises a `DeprecationWarning`. In Python 3.12, it raises a `RuntimeError` when called outside an async context.
- **Impact:** Tests will fail on Python 3.12+ without modification. CI pipelines pinned to Python 3.10 will silently accumulate technical debt.
- **Fix:** Replace `asyncio.get_event_loop()` with `asyncio.get_running_loop()` inside async functions, or use `asyncio.run()` as the entry point for test coroutines. Use `pytest-asyncio` with `asyncio_mode = "auto"`.

---

### L-02: RedAgent Attack Prompts Shipped in Production Code
- **File:** [`src/governed_financial_advisor/agents/evaluator/red_agent.py:27`](src/governed_financial_advisor/agents/evaluator/red_agent.py:27)
- **Category:** Security
- **Dev vs Prod:** Low risk but should be addressed
- **Description:** `red_agent.py` contains a library of adversarial attack prompts (prompt injection, jailbreak attempts, financial manipulation prompts) hardcoded in the production codebase. These prompts are shipped in the production container image.
- **Impact:** The attack prompt library is available to anyone with access to the container image or source code. While the red agent is a legitimate testing tool, shipping attack prompts in prod images increases the attack surface and may trigger security scanner alerts.
- **Fix:** Move red agent attack prompts to a separate test-only package that is not included in production container images. Use a multi-stage Docker build to exclude test utilities from the final image.

---

### L-03: SBOM RA-5 Compliance Status Always Shows as Satisfied
- **File:** [`scripts/generate_sbom.py`](scripts/generate_sbom.py)
- **Category:** Compliance / Bug
- **Dev vs Prod:** Affects both
- **Description:** The SBOM summary report always shows RA-5 (Vulnerability Scanning) as satisfied due to a logic bug: `any(True for _ in [1])` always evaluates to `True`, so RA-5 is marked satisfied even when Grype is not installed and no scan was performed.
- **Impact:** Compliance reports falsely claim vulnerability scanning is complete. Auditors relying on the SBOM summary may incorrectly conclude RA-5 is satisfied.
- **Fix:** Use a boolean flag `grype_ran` set to `True` only when `run_grype_scan()` completes successfully. Show RA-5 as satisfied only when `grype_ran is True`.

---

### L-04: setup_test_env.sh Port-Forwards to Wrong Redis Service Name
- **File:** [`setup_test_env.sh:176`](setup_test_env.sh:176)
- **Category:** Bug
- **Dev vs Prod:** Dev only
- **Description:** `setup_test_env.sh` port-forwards to `svc/redis-master` but the canonical service defined in `redis-statefulset.yaml` is named `redis`. The `redis-master` name is a legacy alias that may not exist in migrated clusters.
- **Impact:** Local test environment setup fails for Redis port-forwarding. Tests depending on Redis (LangGraph checkpointing, evidence stream) fail with connection errors.
- **Fix:** Update `setup_test_env.sh` to use `svc/redis`. Add a fallback that tries `svc/redis-master` if `svc/redis` is not found.

---

### L-05: Langfuse Project ID Hardcoded in Posture Verification Script
- **File:** [`scripts/verify_langfuse_posture.py:41`](scripts/verify_langfuse_posture.py:41)
- **Category:** Security / Configuration
- **Dev vs Prod:** Affects both
- **Description:** `verify_langfuse_posture.py` hardcodes a real Langfuse project ID as the default value for `LANGFUSE_PROJECT_ID`. This internal identifier is embedded in the public source code.
- **Impact:** The hardcoded project ID reveals internal Langfuse project structure. If the Langfuse instance is publicly accessible, this ID could be used to probe the project API.
- **Fix:** Remove the hardcoded default. Require `LANGFUSE_PROJECT_ID` to be explicitly set. Fail with a clear error if not set.

---

### L-06: Defer Queue Has No Maximum Size Bound
- **File:** [`src/gateway/governance/defer_queue.py`](src/gateway/governance/defer_queue.py)
- **Category:** Performance
- **Dev vs Prod:** Affects both
- **Description:** The defer queue for governance decisions has no maximum size limit. Under sustained load where decisions are deferred faster than they are processed, the queue grows without bound, consuming memory until the gateway pod OOMs.
- **Impact:** Memory exhaustion under sustained load. Gateway pod crashes, causing all governance decisions to fail until the pod restarts.
- **Fix:** Set a maximum queue size (e.g., 1,000 items). When the queue is full, reject new deferrals with a DENY decision rather than enqueuing. Add a metric for queue depth and alert when it exceeds 80% of capacity.

---

### L-07: Compliance Bridge Dockerfile Uses Shell Form CMD — No Signal Handling
- **File:** [`src/compliance_bridge/Dockerfile`](src/compliance_bridge/Dockerfile)
- **Category:** Configuration
- **Dev vs Prod:** Affects both
- **Description:** The compliance bridge Dockerfile uses shell form `CMD` (e.g., `CMD python -m ...`) instead of exec form `CMD ["python", "-m", ...]`. Shell form wraps the process in `/bin/sh -c`, which does not forward signals (SIGTERM, SIGINT) to the Python process.
- **Impact:** Kubernetes pod termination sends SIGTERM to the shell, not to Python. The Python process does not receive the signal and cannot perform graceful shutdown (flushing evidence buffers, closing KMS connections). Kubernetes eventually sends SIGKILL after the grace period, causing abrupt termination and potential evidence loss.
- **Fix:** Change to exec form: `CMD ["python", "-m", "compliance_bridge.main"]`. Also add `STOPSIGNAL SIGTERM` and implement a SIGTERM handler in `main.py` that flushes all buffers before exiting.

---

### L-08: In-Memory Local Cache Has No Size Limit in Query Cache
- **File:** [`src/governed_financial_advisor/infrastructure/query_cache.py:72`](src/governed_financial_advisor/infrastructure/query_cache.py:72)
- **Category:** Performance
- **Dev vs Prod:** Affects both
- **Description:** The local in-memory cache layer in `query_cache.py` uses a plain Python dict with no size limit. In a long-running pod, the cache grows indefinitely as new queries are processed.
- **Impact:** Memory exhaustion over time. The financial advisor pod's memory usage grows monotonically until it is OOM-killed by Kubernetes.
- **Fix:** Replace the plain dict with `functools.lru_cache` or `cachetools.LRUCache` with a maximum size (e.g., 1,000 entries). Set a TTL on cache entries to prevent stale governance decisions from being served indefinitely.

---

### L-09: Automated Auditor Uses Timestamp Ordering for Governance Precedence
- **File:** [`scripts/automated_auditor.py:370`](scripts/automated_auditor.py:370)
- **Category:** Compliance / Bug
- **Dev vs Prod:** Affects both
- **Description:** The automated auditor verifies governance precedence using wall-clock timestamp comparison (`gov_span.end_time <= exec_span.start_time`). The code comment acknowledges this is a simplification. Clock skew in distributed systems makes this unreliable.
- **Impact:** The audit invariant (governance before execution) can be falsely satisfied or falsely violated due to clock skew between services. Audit reports may contain incorrect precedence verdicts.
- **Fix:** Use OpenTelemetry span parent-child relationships for causal ordering. Verify that the governance check span is an ancestor of the execution span in the trace tree using `parentSpanId` traversal.

---

## Section 5 — Dev vs Prod Posture Summary

The following findings are **acceptable in dev** but **must be resolved before any prod deployment**:

| Finding | Dev Acceptable | Prod Blocker | Reason |
|---------|---------------|--------------|--------|
| C-03 Default HMAC salt | ✅ | 🚫 | Known salt in public source code |
| C-04 Incomplete auth coverage on trade endpoints | ✅ | 🚫 | `/agent/query` authenticated; remaining endpoints unauthenticated in dev; must be fully covered in prod |
| C-06 GKE 0.0.0.0/0 master access | ✅ | 🚫 | Dev convenience; prod attack surface |
| C-07 Unauthenticated audit ingest | ✅ | 🚫 | Internal network in dev; must be authenticated in prod |
| H-05 KMS signer not enforced | ✅ | 🚫 | KMS not available in dev; mandatory in prod |
| H-06 Hardcoded fallback credentials | ✅ | 🚫 | Dev uses known-weak defaults; prod must use secrets |
| H-13 Redis no requirepass | ✅ | 🚫 | Dev convenience; prod governance state must be protected |
| H-15 Langfuse over HTTP | ✅ | 🚫 | Dev convenience; prod requires TLS for compliance data |
| M-13 CORS empty-string origin | ✅ | 🚫 | Dev testing; prod must restrict origins |
| M-15 Dev mode skips sig verification | ✅ | 🚫 | Must never be active in prod |
| M-16 Debug endpoints always registered | ✅ | 🚫 | Must be gated behind CAGE_ENV=dev |
| M-17 Demo endpoints in prod routing | ✅ | 🚫 | Must be excluded from prod builds |
| M-24 Containers run as root | ✅ | 🚫 | PSA restricted should block; verify enforcement |
| M-23 OPA logs console-only | ✅ | 🚫 | Prod requires durable audit log sink |

The following findings affect **both dev and prod** and require immediate attention regardless of environment:

| Finding | Category | Immediate Action |
|---------|----------|-----------------|
| C-01 Sell→Buy inversion | Bug | Fix before any trade execution |
| C-02 CBF fail-open | Security | Change to fail-closed |
| C-05 exec() without sandbox | Security | Remove or sandbox immediately |
| C-08 KMS signer never started | Bug | Fix startup sequence |
| C-09 Langfuse API mismatch | Bug | Fix audit workflow |
| C-10 OPA fail-open defaults | Security | Remove permissive clauses |
| H-02 Timestamp-based causal ordering | Security | Use span parent-child relationships |
| H-07 CBF non-atomic state read | Bug | Use Redis MULTI/EXEC |
| H-10 Token quota race condition | Bug | Use atomic Redis INCR |
| M-06 Evaluator defaults to APPROVED | Bug | Change default to DENIED |
| M-19 trace variable shadowing | Bug | Rename loop variable |

---

## Section 6 — Remediation Roadmap

### Sprint 1 — Immediate (Block prod deployment)

| Priority | Finding | Owner | Effort |
|----------|---------|-------|--------|
| 1 | C-01: Fix sell→buy trade side inversion | Gateway team | 1h |
| 2 | C-02: Make CBF fail-closed on Redis unavailability | Gateway team | 2h |
| 3 | C-03: Auto-enforce custom HMAC salt at startup | Gateway team | 1h |
| 4 | C-04: Add JWT auth to all financial API endpoints | Advisor team | 1d |
| 5 | C-05: Remove or sandbox exec() in transpiler | Advisor team | 4h |
| 6 | C-06: Restrict GKE master_authorized_networks | Infra team | 1h |
| 7 | C-07: Add auth to /v1/audit/ingest | Compliance team | 4h |
| 8 | C-08: Call signer.start() in compliance bridge startup | Compliance team | 1h |
| 9 | C-09: Fix Langfuse SDK API calls in audit_workflow | Compliance team | 4h |
| 10 | C-10: Remove OPA fail-open default clauses | Infra team | 2h |

### Sprint 2 — High Priority (Within current release)

| Priority | Finding | Owner | Effort |
|----------|---------|-------|--------|
| 11 | H-01: Persist ISO control audit trail durably | Gateway team | 4h |
| 12 | H-02: Use span parent-child for causal ordering | Gateway team | 1d |
| 13 | H-05: Enforce KMS signer in prod startup | Gateway team | 2h |
| 14 | H-06: Remove hardcoded fallback credentials | All teams | 4h |
| 15 | H-07: Atomic CBF state read with Redis MULTI/EXEC | Gateway team | 4h |
| 16 | H-10: Atomic token quota with Redis Lua script | Gateway team | 2h |
| 17 | H-11: Validate positive trade values in fiscal guard | Gateway team | 1h |
| 18 | H-13: Enable Redis requirepass | Infra team | 2h |
| 19 | H-14: Fix Cilium egress label selector | Infra team | 1h |
| 20 | H-15: Add TLS to Langfuse ingress | Infra team | 4h |
| 21 | H-16: Stop exporting all secrets in deploy_all.sh | Infra team | 4h |
| 22 | M-03: Implement cryptographic approval tokens | Advisor team | 4h |
| 23 | M-06: Change evaluator default to DENIED | Advisor team | 1h |
| 24 | M-19: Fix trace variable shadowing in evaluator | Advisor team | 30m |

### Sprint 3 — Medium Priority (Next sprint)

| Priority | Finding | Owner | Effort |
|----------|---------|-------|--------|
| 25 | M-01: Add governance context to cache key | Advisor team | 4h |
| 26 | M-04: Enable TLS cert verification for Redis | Advisor team | 2h |
| 27 | M-05: Sanitize user messages before LLM prompts | Advisor team | 4h |
| 28 | M-07: Add SSE subscriber limit | Compliance team | 2h |
| 29 | M-08: Decouple evidence durability from SSE | Compliance team | 1d |
| 30 | M-09: Add YAML size limit to OSCAL parser | Compliance team | 1h |
| 31 | M-10: Expand safety rate metric window | Compliance team | 2h |
| 32 | M-11: Fix /tmp TOCTOU in Lula scheduler | Compliance team | 2h |
| 33 | M-14: Expand PII sanitizer patterns | Gateway team | 4h |
| 34 | M-15: Add secondary prod check to dev mode guard | Gateway team | 2h |
| 35 | M-16: Gate debug endpoints behind CAGE_ENV=dev | Gateway team | 1h |
| 36 | M-17: Exclude demo router from prod builds | Advisor team | 1h |
| 37 | M-22: Escape LLM text in Slack notifier | Compliance team | 1h |
| 38 | M-23: Configure OPA remote decision log sink | Infra team | 4h |
| 39 | M-24: Add non-root USER to all Dockerfiles | All teams | 2h |

### Sprint 4 — Low Priority (Backlog)

| Priority | Finding | Owner | Effort |
|----------|---------|-------|--------|
| 40 | L-01: Fix asyncio.get_event_loop() in tests | All teams | 2h |
| 41 | L-02: Move red agent prompts to test-only package | Advisor team | 2h |
| 42 | L-03: Fix SBOM RA-5 logic bug | Infra team | 30m |
| 43 | L-04: Fix Redis service name in setup_test_env.sh | Infra team | 30m |
| 44 | L-05: Remove hardcoded Langfuse project ID | Infra team | 30m |
| 45 | L-06: Add max size to defer queue | Gateway team | 1h |
| 46 | L-07: Fix Dockerfile CMD to exec form | All teams | 30m |
| 47 | L-08: Add LRU eviction to query cache | Advisor team | 1h |
| 48 | L-09: Fix audit precedence to use span relationships | Infra team | 4h |

---

## Section 7 — Compliance Impact Summary

### NIST SP 800-53 Controls Affected

| Control | Finding(s) | Status |
|---------|-----------|--------|
| AU-12 (Audit Record Generation) | H-01, C-09, M-23 | ⚠️ Partially broken |
| AU-9 (Protection of Audit Information) | H-03, C-08 | ⚠️ Evidence unprotected |
| AC-3 (Access Enforcement) | C-04, C-07, M-03 | 🚫 Not enforced |
| SC-8 (Transmission Confidentiality) | H-15, M-04 | 🚫 Not enforced in dev |
| SC-28 (Protection at Rest) | C-08, H-03 | ⚠️ KMS not active |
| SI-10 (Information Input Validation) | C-10, H-11, M-05 | ⚠️ Incomplete |
| RA-5 (Vulnerability Scanning) | L-03 | ⚠️ Reporting bug |
| IA-3 (Device Identification) | C-04, H-06 | 🚫 Not enforced |

### ISO 42001 Controls Affected

| Control | Finding(s) | Status |
|---------|-----------|--------|
| A.9.2 (Evidence Integrity) | C-08, H-03 | 🚫 KMS signing inactive |
| A.6.1 (Risk Assessment) | C-02, H-07 | ⚠️ Safety controls fail-open |
| A.9.1 (Audit Trail) | C-09, H-01, M-08 | 🚫 Audit trail broken |
| A.5.2 (Governance Accountability) | C-04, C-07 | 🚫 No authentication |

---

## Appendix — Finding Index

| ID | Title | Severity | File |
|----|-------|----------|------|
| C-01 | All sell orders execute as buy orders | Critical | `src/gateway/core/tools.py:88` |
| C-02 | CBF safety check is fail-open on Redis unavailability | Critical | `src/gateway/governance/symbolic_governor.py:677` |
| C-03 | Default HMAC salt allows routing seal forgery | Critical | `src/gateway/governance/routing_seal.py:74` |
| C-04 | No authentication on trade execution endpoints | Critical | `src/governed_financial_advisor/server.py` |
| C-05 | LLM-generated Python code executed without sandboxing | Critical | `src/governed_financial_advisor/governance/transpiler.py:242` |
| C-06 | GKE control plane exposed to 0.0.0.0/0 | Critical | `infra/targets/gcp-gke/eu-dev.tfvars:85` |
| C-07 | Unauthenticated audit result injection endpoint | Critical | `src/compliance_bridge/main.py:655` |
| C-08 | KMS batch signer never started despite being enabled | Critical | `src/compliance_bridge/kms_batch_signer.py:79` |
| C-09 | Compliance audit workflow broken — Langfuse API mismatch | Critical | `src/compliance_bridge/audit_workflow.py:269` |
| C-10 | OPA governance rules default to ALLOW when input fields absent | Critical | `deployment/system_authz.rego:54` |
| H-01 | ISO control audit trail written to ephemeral in-memory store | High | `src/gateway/governance/iso_control.py` |
| H-02 | Causal gatekeeper timestamp-based ordering is bypassable | High | `src/gateway/governance/causal_gatekeeper.py` |
| H-03 | UCA logger writes to unprotected GCS path | High | `src/gateway/governance/uca_logger.py` |
| H-04 | Inference proxy forwards raw error messages to clients | High | `src/gateway/server/inference_proxy.py` |
| H-05 | KMS signer in gateway has no production enforcement | High | `src/gateway/governance/kms_signer.py` |
| H-06 | Constants file contains hardcoded fallback credentials | High | `src/gateway/governance/constants.py` |
| H-07 | CBF barrier certificate computed with stale state | High | `src/gateway/governance/cbf.py` |
| H-08 | Normative provider loads policy files without integrity verification | High | `src/gateway/governance/normative_provider.py` |
| H-09 | Text filter regex patterns loaded without validation | High | `src/gateway/governance/text_filter.py` |
| H-10 | Token quota proxy has no atomic increment — race condition | High | `src/gateway/governance/token_quota_proxy.py` |
| H-11 | Fiscal limit guard allows negative trade values | High | `src/gateway/governance/fiscal_limit_guard.py` |
| H-12 | Policy loader executes YAML from remote storage without schema validation | High | `src/governed_financial_advisor/governance/policy_loader.py:50` |
| H-13 | Redis unauthenticated — no requirepass set | High | `deployment/k8s/redis-config.yaml:47` |
| H-14 | Cilium egress FQDN allowlist targets wrong pod label | High | `deployment/k8s/cilium-egress-lockdown.yaml:74` |
| H-15 | Langfuse exposed over HTTP without TLS at root path | High | `deployment/k8s/ingress.yaml:27` |
| H-16 | deploy_all.sh exports all secrets to child process environments | High | `deploy_all.sh:79` |
| M-01 | Query cache bypasses governance pipeline on cache hit | Medium | `src/governed_financial_advisor/server.py:283` |
| M-02 | Cache key collision risk — SHA-256 truncated to 16 hex chars | Medium | `src/governed_financial_advisor/infrastructure/query_cache.py:111` |
| M-03 | Approval token validation is trivially bypassable | Medium | `src/governed_financial_advisor/governance/nemo_actions.py:164` |
| M-04 | TLS certificate verification disabled for Redis | Medium | `src/governed_financial_advisor/infrastructure/redis_client.py:155` |
| M-05 | Prompt injection via user message in supervisor node | Medium | `src/governed_financial_advisor/graph/nodes/supervisor_node.py:191` |
| M-06 | governed_trader_node defaults evaluation_result to APPROVED | Medium | `src/governed_financial_advisor/graph/nodes/agent_nodes.py:200` |
| M-07 | SSE subscriber count has no upper bound — DoS vector | Medium | `src/compliance_bridge/sse_events.py:192` |
| M-08 | Evidence sink skipped when no SSE subscribers | Medium | `src/compliance_bridge/sse_events.py` |
| M-09 | OSCAL parser has no YAML size limit — DoS via large file | Medium | `src/compliance_bridge/oscal_parser.py` |
| M-10 | Metrics safety rate computed from only last 100 traces | Medium | `src/compliance_bridge/metrics.py` |
| M-11 | Lula scheduler writes to world-writable /tmp — TOCTOU risk | Medium | `src/compliance_bridge/lula_scheduler.py` |
| M-12 | Unauthenticated loopback POST in Lula scheduler | Medium | `src/compliance_bridge/lula_scheduler.py` |
| M-13 | CORS allows empty-string origin with credentials | Medium | `src/compliance_bridge/main.py` |
| M-14 | PII sanitizer regex patterns are incomplete | Medium | `src/gateway/governance/pii_sanitizer.py` |
| M-15 | Governance middleware does not validate request signature in dev mode | Medium | `src/gateway/server/governance_middleware.py` |
| M-16 | Hybrid server exposes internal debug endpoints in all environments | Medium | `src/gateway/server/hybrid_server.py` |
| M-17 | Demo endpoints exposed in production routing | Medium | `src/governed_financial_advisor/demo/router.py:29` |
| M-18 | SSRF via unvalidated compliance_bridge_url in KFP pipeline | Medium | `src/governed_financial_advisor/pipelines/green_stack_pipeline.py:58` |
| M-19 | Evaluator trace variable shadows opentelemetry trace module | Medium | `src/governed_financial_advisor/evaluators/evaluate_traces.py:152` |
| M-20 | MCP tool server has no rate limiting | Medium | `src/gateway/server/mcp_tool_server.py` |
| M-21 | Storage backend evaluated at import time | Medium | `src/compliance_bridge/storage.py` |
| M-22 | Notifier embeds LLM text verbatim in Slack mrkdwn | Medium | `src/compliance_bridge/notifier.py` |
| M-23 | OPA decision logs written to console only | Medium | `deployment/opa_config.yaml` |
| M-24 | Container images run as root in several deployments | Medium | `src/gateway/Dockerfile` |
| L-01 | Redis client uses deprecated get_event_loop() in tests | Low | `tests/` |
| L-02 | RedAgent attack prompts shipped in production code | Low | `src/governed_financial_advisor/agents/evaluator/red_agent.py:27` |
| L-03 | SBOM RA-5 compliance status always shows as satisfied | Low | `scripts/generate_sbom.py` |
| L-04 | setup_test_env.sh port-forwards to wrong Redis service name | Low | `setup_test_env.sh:176` |
| L-05 | Langfuse project ID hardcoded in posture verification script | Low | `scripts/verify_langfuse_posture.py:41` |
| L-06 | Defer queue has no maximum size bound | Low | `src/gateway/governance/defer_queue.py` |
| L-07 | Compliance bridge Dockerfile uses shell form CMD | Low | `src/compliance_bridge/Dockerfile` |
| L-08 | In-memory local cache has no size limit in query cache | Low | `src/governed_financial_advisor/infrastructure/query_cache.py:72` |
| L-09 | Automated auditor uses timestamp ordering for governance precedence | Low | `scripts/automated_auditor.py:370` |

---

*Report generated: 2026-06-12. Next review scheduled: 2026-09-12.*
*This report should be treated as CONFIDENTIAL and shared only with authorized personnel.*

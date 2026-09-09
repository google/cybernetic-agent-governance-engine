# GKE Staging Environment Smoke Test Results

**Date:** 2026-09-09 00:59 UTC  
**Environment:** `staging` (via port-forward from `cage-staging` cluster)  
**Test Type:** Live service connectivity and functional validation

---

## Executive Summary

✅ **All critical services operational**  
✅ **9/9 service health checks passed**  
✅ **3/3 functional tests passed**  
⚠️ **KMS requirement blocks pytest integration tests** (known issue, separate task)

---

## 1. Service Health Validation

All port-forwarded services from the live GKE staging cluster are healthy and responsive:

### Core Infrastructure Services

| Service | Port | Status | Details |
|---------|------|--------|---------|
| **Redis** | 6379 | ✅ PASS | Version 8.10.1, Uptime: 53.4 hours, Max Memory: 256MB, Policy: allkeys-lru |
| **OPA** | 8181 | ✅ PASS | Policy engine responding |
| **Langfuse API** | 3001 | ✅ PASS | Version 3.225.7, Authentication working |

### Application Services

| Service | Port | Status | Details |
|---------|------|--------|---------|
| **Gateway** | 8080 | ✅ PASS | Mode: mcp-tool-server, NeMo: active |
| **Backend/GFA** | 8081 | ✅ PASS | Financial advisor graph agent operational |
| **Compliance Bridge** | 3002 | ✅ PASS | v0.1.0, Langfuse app & compliance configured |

### Inference Services

| Service | Port | Status | Model Loaded |
|---------|------|--------|--------------|
| **vLLM Fast** | 8001 | ✅ PASS | Qwen 2.5 7B Instruct |
| **vLLM Reasoning** | 8000 | ✅ PASS | DeepSeek-R1-Distill-Llama-8B |

---

## 2. Functional End-to-End Tests

### ✅ Gateway Governance Flow
- Health endpoint responding correctly
- MCP server active (307 redirect to SSE endpoint)
- Compliance bridge exposing 4 control endpoints

### ✅ vLLM Inference Test
- **Model:** Qwen 2.5 7B Instruct (fast inference)
- **Prompt:** "Hello, this is a test. Reply with 'OK' if you can read this."
- **Response:** "OK." (successful inference)
- **Latency:** < 30 seconds

### ✅ Langfuse Trace Creation
- Successfully created test trace: `test-trace-1788915610`
- Authentication with API keys working
- Trace ingestion pipeline operational

---

## 3. Known Issues

### KMS Requirement Blocking Pytest Tests

**Status:** Documented, separate task to fix test infrastructure

**Error:**
```
RuntimeError: [KMSSigner] KMS_GOVERNANCE_KEY is not set. 
Set it to the full Cloud KMS key version resource name. 
The legacy HMAC GOVERNANCE_SALT fallback has been removed.
```

**Impact:**
- Integration tests that import `symbolic_governor` fail at module load time
- Affects tests in: `test_langfuse_smoke.py`, `test_redis_eviction_envelope.py`, `test_compliance_bridge_smoke.py`

**Root Cause:**
- `KMS_GOVERNANCE_KEY` is set in `.env` file
- Test environment (`pytest --run-integration`) is not loading environment variables correctly
- Tests fail during import phase before fixtures can set up environment

**Workaround:**
- Use standalone HTTP smoke tests (provided in `scripts/test_live_gke_services.py` and `scripts/test_gke_e2e_flow.py`)
- These bypass module imports and test services directly

**Fix Required:**
- Update `tests/conftest.py` to load `.env` before any gateway module imports
- OR: Create a test-specific KMS mock that activates based on `CAGE_ENV=staging`
- OR: Modify `kms_signer.py` to support test mode without KMS in integration tests

---

## 4. Test Artifacts

### Created Test Scripts

1. **`scripts/test_live_gke_services.py`**
   - Comprehensive service health checks
   - Redis configuration validation
   - HTTP endpoint testing
   - Langfuse authentication test
   - **Usage:** `uv run python scripts/test_live_gke_services.py`

2. **`scripts/test_gke_e2e_flow.py`**
   - End-to-end functional validation
   - Gateway governance flow test
   - vLLM inference test
   - Langfuse trace creation test
   - **Usage:** `uv run python scripts/test_gke_e2e_flow.py`

### Port-Forward Status

Active port-forwards established via `scripts/port_forward_staging.sh`:

```
OPA:                8181 → governance-stack/svc/opa:8181
Langfuse API:       3001 → governance-stack/svc/langfuse-web:3000
Langfuse UI:        3000 → governance-stack/svc/langfuse-web:3000
vLLM Fast:          8001 → governance-stack/svc/vllm-service:8000
vLLM Reasoning:     8000 → governance-stack/svc/vllm-reasoning:8000
Gateway:            8080 → governance-stack/svc/gateway:8080
Backend:            8081 → governance-stack/svc/governed-financial-advisor:80
Redis:              6379 → governance-stack/svc/redis-master:6379
Compliance Bridge:  3002 → governance-stack/svc/compliance-bridge:80
```

---

## 5. Recommendations

### Immediate Actions
1. ✅ **COMPLETE:** Live services validated and operational
2. ⚠️ **PENDING:** Fix pytest integration test infrastructure to handle KMS requirement

### Test Infrastructure Improvements
1. Update `tests/conftest.py` to load `.env` file early in test bootstrap
2. Add environment variable validation in test setup
3. Consider adding a `@pytest.mark.requires_kms` marker for tests that need real KMS
4. Create mock KMS provider for integration tests against staging

### Documentation
1. Update `AGENTS.md` test execution section to reference these standalone smoke test scripts
2. Add troubleshooting section for KMS-related test failures
3. Document port-forward validation workflow in operations runbook

---

## 6. Conclusion

**Live GKE staging environment is fully operational** with all critical services responding correctly. The vLLM inference engines are serving models successfully, Langfuse telemetry is capturing traces, and the governance gateway is active.

The KMS requirement issue affects only the pytest integration test suite and does not impact actual service functionality. Standalone smoke tests provide adequate validation coverage until the test infrastructure is updated.

**Next Steps:**
- Continue using standalone smoke tests for rapid validation
- Schedule KMS test infrastructure fix as separate task
- Consider adding these smoke tests to CI for staging deployments

---

**Test Execution Commands:**

```bash
# Ensure port-forwards are active
ps aux | grep "kubectl port-forward" | grep -v grep

# Run service health checks
bash -c 'set -a; source .env; set +a; uv run python scripts/test_live_gke_services.py'

# Run functional end-to-end tests
bash -c 'set -a; source .env; set +a; uv run python scripts/test_gke_e2e_flow.py'
```

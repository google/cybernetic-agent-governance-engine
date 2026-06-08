# CAGE 2.0.0 — Token Quota Proxy: Comprehensive Technical Report

**Source plan:** `plans/token-quota-proxy-impl-plan.md` v4.0.0  
**Analysis date:** 2026-06-08  
**Sections:** A (pii_sanitizer gap analysis) · B (uca_logger spec) · C (inference_proxy spec) · D (hybrid_server spec) · E (constants spec) · F (token_quota.yaml spec) · G (test specs) · H (Rego rules spec)

---

## A. `pii_sanitizer.py` Gap Analysis

**Status: FULLY IMPLEMENTED — zero gaps.**

`src/gateway/governance/pii_sanitizer.py` matches the plan spec exactly and exceeds it in two ways.

### A.1 Regex Patterns — Exact Match

The plan (§4.3) specifies `_PII_PATTERNS` as raw string tuples. The implementation stores them as compiled `re.Pattern` objects — superior design (no per-call overhead). All five patterns are byte-identical to the plan:

| # | Target | Replacement | Status |
|---|---|---|---|
| 1 | SSN (`\b(?!000\|666\|9\d{2})…`) | `[REDACTED_SSN]` | ✓ Exact |
| 2 | Credit card (Visa/MC/Amex/Discover/JCB/Diners) | `[REDACTED_CC]` | ✓ Exact |
| 3 | Email (RFC 5321 simplified) | `[REDACTED_EMAIL]` | ✓ Exact |
| 4 | Phone (US/international) | `[REDACTED_PHONE]` | ✓ Exact |
| 5 | API key / Bearer token (`pk-lf-`, `sk-lf-`, `hf_`, `Bearer`) | `[REDACTED_API_KEY]` | ✓ Exact |

### A.2 Pipeline Stages — Exact Match

Sequential `re.sub()` application at `pii_sanitizer.py:126-127` matches §9.1 exactly:

```python
for pattern, replacement in _PII_PATTERNS:
    result = pattern.sub(replacement, result)
```

### A.3 Integration Points — Exact Match

Both integration points (§9.2) are in `uca_logger.py` (not yet implemented). The sanitizer's contract is complete.

### A.4 Extras Beyond the Plan

- `sanitize_dict(data: dict) -> dict` at line 138 — recursive dict/list sanitization (not in plan, useful addition for full request body sanitization)
- Debug logging on PII detection (lines 130–134)

### A.5 Acceptance Criteria — All Satisfied

| Input | Expected | Satisfied |
|---|---|---|
| `123-45-6789` | `[REDACTED_SSN]` | ✓ |
| `4111-1111-1111-1111` | `[REDACTED_CC]` | ✓ |
| `user@example.com` | `[REDACTED_EMAIL]` | ✓ |
| `+1 (555) 867-5309` | `[REDACTED_PHONE]` | ✓ |
| `pk-lf-abc123xyz` | `[REDACTED_API_KEY]` | ✓ |
| `Bearer eyJhbGc...` | `[REDACTED_API_KEY]` | ✓ |
| `clean text with no PII` | unchanged | ✓ |

**`pii_sanitizer.py` is complete. No missing pieces.**

---

## B. `uca_logger.py` Full Specification

`src/gateway/governance/uca_logger.py` **does not yet exist**. Complete specification follows.

### B.1 File Header

Apache 2.0 license header required (`.clinerules` §10.2). Implements ISO 42001 Clause 6.1.

### B.2 Class: `UCALogger` — All Methods, Parameters, Return Types

```python
class UCALogger:
    def __init__(
        self,
        signer: Optional[object],    # KMSGovernanceSigner or None in test mode
        redis_client: object,        # async Redis client (fakeredis in tests)
        bucket: str,                 # WORM bucket name (from _get_worm_bucket())
        pii_sanitizer: object,       # PIISanitizer instance
        test_mode: bool = False,     # True → HMAC-SHA256 stub signing
    ) -> None: ...

    @classmethod
    def from_env(cls) -> "UCALogger":
        """Construct from environment variables.
        Reads: CAGE_DEPLOYMENT_REGION, OSCAL_S3_BUCKET_*, KMS_GOVERNANCE_KEY,
               CAGE_ENV (test_mode=True when CAGE_ENV=test).
        """

    async def log_quota_exceeded(
        self,
        quota_result: "QuotaCheckResult",  # from token_quota_proxy.py
        request_body: dict,
    ) -> str:
        """Build, sign, and persist a quota_exceeded UCA record.
        Returns: worm_path string e.g. 'uca-records/2026-06-08/UCA-{uuid}.yaml'
        """

    async def log_prompt_injection(
        self,
        agent_id: str,
        injected_content: str,
        block_reason: str,
    ) -> str:
        """Build, sign, and persist a prompt_injection UCA record.
        Returns: worm_path string
        """

    async def log_pii_sanitization(
        self,
        agent_id: str,
        tool_name: str,
        original_args: str,
        sanitized_args: str,
    ) -> str:
        """Build, sign, and persist a pii_sanitization UCA record.
        Returns: worm_path string
        """

    async def _build_uca_record(
        self,
        uca_type: str,
        agent_id: str,
        quota_result: Optional["QuotaCheckResult"] = None,
        request_body: Optional[dict] = None,
        **kwargs,
    ) -> dict:
        """Build the ISO 42001 Clause 6.1 record dict.
        Applies PII sanitization to request_summary before signing.
        """

    async def _persist_uca_record(self, record: dict) -> str:
        """Sign the record, serialize to YAML, write to WORM ledger.
        On write failure: logs ERROR to stderr; block is still enforced.
        Returns: worm_path string
        """

    async def _generate_event_id(self) -> str:
        """Return 'UCA-{uuid4}' string."""

    def _get_worm_bucket(self) -> str:
        """Return region-gated WORM bucket name (see B.3)."""
```

### B.3 WORM Bucket Region Guard

```python
def _get_worm_bucket(self) -> str:
    region = os.environ.get("CAGE_DEPLOYMENT_REGION", "US_FED")
    bucket_map = {
        "US_FED":   os.environ.get("OSCAL_S3_BUCKET_US_FED",
                        os.environ.get("OSCAL_S3_BUCKET", "")),
        "EU_ECB":   os.environ.get("OSCAL_S3_BUCKET_EU_ECB",
                        os.environ.get("OSCAL_S3_BUCKET", "")),
        "APAC_MAS": os.environ.get("OSCAL_S3_BUCKET_APAC_MAS",
                        os.environ.get("OSCAL_S3_BUCKET", "")),
    }
    return bucket_map.get(region, os.environ.get("OSCAL_S3_BUCKET", ""))
```

Satisfies `.clinerules` §12.2: EU_ECB → `europe-west1`, APAC_MAS → `asia-southeast1`, US_FED → `us-central1`.

### B.4 ISO 42001 Clause 6.1 YAML Schema (§8.1)

Every UCA record written to the WORM ledger must conform to this schema:

```yaml
compliance_event_id: "UCA-{uuid4}"
timestamp: "2026-06-08T01:57:37Z"
iso42001_clause: "6.1"
iso42001_control: "A.4"
governance_control_id: "CTRL_TQP_007"
uca_type: "quota_exceeded"
agent_id: "{agent_uuid}"
session_key: "quota:session:{agent_uuid}"
block_reason: "step_count"
current_value: 13
quota_max: 12
request_summary: "{sanitized_body_excerpt}"
cryptographic_signature: "{kms_signature_hex}"
signing_key_id: "{kms_key_resource_name}"
deployment_region: "US_FED"
worm_path: "uca-records/2026-06-08/UCA-{uuid4}.yaml"
```

Valid `uca_type` values: `quota_exceeded`, `prompt_injection`, `pii_sanitization`.

### B.5 KMS Signing Procedure (§8.3)

1. Serialize record to JSON with `sort_keys=True` — matches `_canonicalise_plan()` in `kms_signer.py:101`
2. Call `KMSGovernanceSigner.sign(payload_bytes)` → returns hex signature
3. Set `record["cryptographic_signature"]` to hex string
4. Set `record["signing_key_id"]` to `_KMS_KEY_VERSION` from the signer

**Critical note:** `KMSGovernanceSigner.from_env()` raises `RuntimeError` if `KMS_GOVERNANCE_KEY` is unset — there is **no HMAC fallback in the signer itself**. The stub lives entirely in `UCALogger`. `UCALogger.from_env()` must detect `CAGE_ENV=test` and set `test_mode=True`, passing `signer=None`.

### B.6 Test Mode Signing (§4.2)

```python
if self.test_mode:
    import hmac, hashlib
    stub_sig = hmac.new(
        b"test-key",
        json.dumps(record, sort_keys=True).encode(),
        hashlib.sha256
    ).hexdigest()
    record["cryptographic_signature"] = f"0xSTUB_{stub_sig[:16]}"
```

### B.7 WORM Write Procedure (§8.4)

1. Serialize signed record to YAML
2. Call `WORMStorage.write(path, content, region)` with region-gated bucket
3. On write failure: log to structured stderr with `level=ERROR`; **block is still enforced**
4. Return `worm_path` string to caller

### B.8 Event ID Generation (§8.2)

```python
event_id = f"UCA-{uuid.uuid4()}"
worm_path = f"uca-records/{datetime.utcnow().strftime('%Y-%m-%d')}/{event_id}.yaml"
```

### B.9 Module-Level Singleton

```python
_uca_logger: Optional[UCALogger] = None

def _get_uca_logger() -> UCALogger:
    global _uca_logger
    if _uca_logger is None:
        _uca_logger = UCALogger.from_env()
    return _uca_logger
```

### B.10 Acceptance Criteria (Phase 1c)

- Apache 2.0 header present
- `_get_worm_bucket()` returns correct bucket for all three regions
- UCA record conforms to ISO 42001 Clause 6.1 schema (all 16 fields present)
- WORM write failure does not suppress the block

---

## C. `inference_proxy.py` Integration Spec

### C.1 Current State

`src/gateway/server/inference_proxy.py` currently has:

| Lines | Current Content | Status |
|---|---|---|
| 188 | `async def chat_completions(request: Request)` | Missing BackgroundTasks |
| 229-234 | Step 1: Tier-1 keyword scan | Present |
| 236-271 | Step 2: NeMo input verification | Becomes step 3 after insertion |
| 273-314 | Step 3: vLLM forward + output filter | Becomes steps 4-5 |
| - | Step 2: Token Quota Check | **ABSENT** |
| - | `_get_token_quota_proxy` import | **ABSENT** |
| - | `_get_uca_logger` import | **ABSENT** |
| - | try/except rollback wrapper | **ABSENT** |

### C.2 Required Changes (Section 4.4, Phase 2a)

**Change 1 — Update fastapi import (line 40):**

    from fastapi import FastAPI, HTTPException, Request, BackgroundTasks

**Change 2 — Add module-level imports (after line 49):**

    from src.gateway.governance.token_quota_proxy import _get_token_quota_proxy
    from src.gateway.governance.uca_logger import _get_uca_logger

**Change 3 — Update function signature (line 188):**

    @inference_app.post("/v1/chat/completions")
    async def chat_completions(
        request: Request,
        background_tasks: BackgroundTasks,
    ) -> JSONResponse:

**Change 4 — Insert Step 2 block** after line 234, before line 236 (NeMo block):

    # Step 2 (NEW): Token Quota Enforcement (ISO 42001 Annex A.4)
    agent_id = (body.get("agent_id")
                or request.headers.get("X-Agent-ID", "")
                or "anonymous")
    token_delta = int(body.get("max_tokens", 0))
    quota_result = await _get_token_quota_proxy().check_and_increment(
        agent_id=agent_id, token_delta=token_delta,
    )
    if not quota_result.allowed:
        stamp_iso_control(span, tier=2, control="A.4", outcome="BLOCK")
        # Awaited inline — NOT background_tasks.add_task.
        # WORM write must complete before 429 is returned.
        await _get_uca_logger().log_quota_exceeded(quota_result, body)
        return JSONResponse(content={
            "error": "quota_exceeded",
            "reason": quota_result.block_reason,
            "step_count": quota_result.step_count,
            "accumulated_tokens": quota_result.accumulated_tokens,
            "quota_max_steps": quota_result.step_quota_max,
            "quota_max_tokens": quota_result.token_quota_max,
            "agent_id": agent_id,
            "iso42001_control": "A.4",
            "dge_action": "TERMINATED_WITH_ROLLBACK",
        }, status_code=429)
    stamp_iso_control(span, tier=2, control="A.4", outcome="PASS")

**Change 5 — Wrap steps 3-5 in try/except for rollback:**

    try:
        # Step 3: NeMo input verification (existing lines 236-271)
        # Step 4: vLLM forward (existing lines 273-314)
        # Step 5: Output filtering (existing lines 316-342)
        return JSONResponse(content=vllm_response)
    except Exception:
        await _get_token_quota_proxy().rollback_step(
            agent_id, reserved_tokens=token_delta
        )
        raise

**Change 6 — Update module docstring** (lines 23-27) to list 6 steps including the new step 2.

### C.3 Acceptance Criteria (Phase 2a)

- Step 2 executes before NeMo (step 3)
- Quota exceeded returns 429 with all 9 JSON body fields
- Downstream failure triggers rollback_step(); counters decremented
- stamp_iso_control(A.4, BLOCK) called on quota exceeded
- stamp_iso_control(A.4, PASS) called on quota allowed

### C.4 Note on background_tasks Parameter

The plan explicitly states the WORM write is awaited inline (not via background_tasks.add_task) because quota blocks are rare circuit-breaker events and the WORM write must complete before the 429 is returned to guarantee ISO 42001 Clause 6.1 audit lineage survives spot-instance eviction.

---

## D. `hybrid_server.py` Integration Spec

### D.1 Current State

`src/gateway/server/hybrid_server.py` `_gateway_lifespan()` (lines 57-168) contains:

| Lines | Block | Status |
|---|---|---|
| 67-68 | OTel tracing setup | Present |
| 71-79 | NeMo rails pre-warm | Present |
| 82-122 | OPA pre-warm + trade policy assertion | Present |
| 124-128 | Production guard: seal enforcement | Present |
| 131-137 | Production guard: stub ledger | Present |
| 139-152 | External normative provider | Present |
| 154-157 | Consensus background audit worker | Present |
| 159 | yield | Present |
| - | Token Quota Proxy pre-warm | **ABSENT** |
| - | UCA Logger pre-warm | **ABSENT** |

### D.2 Required Change (Section 4.5, Phase 2b)

**Insertion point:** After line 122 (end of OPA pre-warm block), before line 124 (production guard).

    # Pre-warm Token Quota Proxy and UCA Logger
    try:
        from src.gateway.governance.token_quota_proxy import TokenQuotaProxy
        from src.gateway.governance.uca_logger import UCALogger
        app.state.token_quota_proxy = TokenQuotaProxy.from_env()
        app.state.uca_logger = UCALogger.from_env()
        logger.info("Token Quota Proxy and UCA Logger pre-warmed")
    except Exception as e:
        logger.warning("Token Quota Proxy pre-warm failed (non-blocking): %s", e)

### D.3 Design Rationale

Imports are inside the try block (not at module level) because:
1. `uca_logger.py` does not yet exist — a module-level import would break the gateway on startup
2. Matches the existing pattern used for NormativeProviderDaemon (lines 144-145) and _background_audit_worker (line 155)

### D.4 Acceptance Criteria (Phase 2b)

- `app.state.token_quota_proxy` set on startup when Redis is available
- `app.state.uca_logger` set on startup when KMS/env is configured
- Pre-warm failure does NOT prevent gateway from starting (logged as WARNING, not raised)
- Pre-warm block appears after OPA pre-warm, before production guards

---

## E. `constants.py` Spec

### E.1 Current State

`src/gateway/governance/constants.py` `GovernanceControl` enum has six members (CTRL_AGT_001 through CTRL_FRIA_006). No CTRL_TQP_007 entry exists.

**Critical architecture note:** The current `ControlRegistry` has **no `register()` classmethod**. The plan's §4.8 shows `ControlRegistry.register(...)` but this method does not exist. The registry is loaded from JSON files via `_load_registry()`. The correct implementation is a two-part change.

### E.2 Required Changes (Section 4.8, Phase 2d)

**Change 1 — Add enum member** after `FRIA_ASSESSMENT` at line 115:

    TOKEN_QUOTA_ENFORCEMENT = "CTRL_TQP_007"
    """Per-session token and step-count quota enforcement via Redis atomic counters.
    ISO 42001 Annex A.4. Enforcement tier 2. Primary enforcer: TokenQuotaProxy."""

**Change 2 — Add CTRL_TQP_007 to all three regional baseline JSON files** (Phase 4b):

Each of `config/compliance/US_FED_BASELINE.json`, `EU_ECB_BASELINE.json`, `APAC_MAS_BASELINE.json` must receive an entry. Required fields per Phase 4b: `control_id`, `iso_clause`, `description`, `enforcement_tier`, `worm_bucket_env_var`. Example for US_FED:

    "CTRL_TQP_007": {
      "control_id": "CTRL_TQP_007",
      "iso_clause": "A.4",
      "description": "Per-session token and step-count quota enforcement via Redis atomic counters",
      "enforcement_tier": 2,
      "worm_bucket_env_var": "OSCAL_S3_BUCKET_US_FED"
    }

The `worm_bucket_env_var` differs per region:
- US_FED: `OSCAL_S3_BUCKET_US_FED`
- EU_ECB: `OSCAL_S3_BUCKET_EU_ECB`
- APAC_MAS: `OSCAL_S3_BUCKET_APAC_MAS`

### E.3 Acceptance Criteria (Phase 2d)

- `GovernanceControl.TOKEN_QUOTA_ENFORCEMENT.value == "CTRL_TQP_007"`
- `ControlRegistry().get_mapping(GovernanceControl.TOKEN_QUOTA_ENFORCEMENT)` returns metadata dict (requires JSON baseline update)

---

## F. `config/thresholds/token_quota.yaml` Spec

### F.1 Current State

`config/thresholds/` directory exists and contains only three files:
- `APAC_MAS_BASELINE.json`
- `EU_ECB_BASELINE.json`
- `US_FED_BASELINE.json`

**`token_quota.yaml` does not exist.**

### F.2 Full YAML Content (Section 4.7, Phase 1d)

    defaults:
      step_quota_max: 12
      token_quota_max: 100000
      session_ttl_seconds: 3600

    model_overrides:
      "deepseek-r1":
        token_quota_max: 50000
      "deepseek-reasoning":
        token_quota_max: 50000

    iso42001_control: "A.4"
    evidence_mechanism: "stateful-redis-counter"
    enforcement_tier: 2

### F.3 Acceptance Criteria (Phase 1d)

- YAML parses without error
- `defaults.step_quota_max: 12` and `defaults.token_quota_max: 100000` present
- `model_overrides` for `deepseek-r1` and `deepseek-reasoning` present

---

## G. Test File Specifications (Section 18)

### G.1 `tests/test_pii_sanitizer.py`

**Commit:** `test(governance): add unit tests for pii sanitizer redaction pipeline` (70 chars)
**Marker:** `@pytest.mark.local` on all tests
**Run:** `uv run pytest tests/test_pii_sanitizer.py -m local -v`
**Note:** No license header required for test files (Section 18.6)

Required scenarios (Section 9.3, Section 13 Phase 3a, Section 18.2):

    import pytest
    from src.gateway.governance.pii_sanitizer import PIISanitizer, _get_pii_sanitizer

    @pytest.fixture
    def sanitizer() -> PIISanitizer:
        return PIISanitizer()

    @pytest.mark.local
    def test_ssn_redacted(sanitizer):
        assert sanitizer.sanitize("123-45-6789") == "[REDACTED_SSN]"

    @pytest.mark.local
    def test_credit_card_redacted(sanitizer):
        assert sanitizer.sanitize("4111-1111-1111-1111") == "[REDACTED_CC]"

    @pytest.mark.local
    def test_email_redacted(sanitizer):
        assert sanitizer.sanitize("user@example.com") == "[REDACTED_EMAIL]"

    @pytest.mark.local
    def test_phone_redacted(sanitizer):
        assert sanitizer.sanitize("+1 (555) 867-5309") == "[REDACTED_PHONE]"

    @pytest.mark.local
    def test_api_key_pk_lf_redacted(sanitizer):
        assert sanitizer.sanitize("pk-lf-abc123xyz") == "[REDACTED_API_KEY]"

    @pytest.mark.local
    def test_bearer_token_redacted(sanitizer):
        result = sanitizer.sanitize("Bearer eyJhbGciOiJSUzI1NiJ9")
        assert result == "[REDACTED_API_KEY]"

    @pytest.mark.local
    def test_clean_text_unchanged(sanitizer):
        assert sanitizer.sanitize("clean text with no PII") == "clean text with no PII"

    @pytest.mark.local
    def test_empty_string(sanitizer):
        assert sanitizer.sanitize("") == ""

    @pytest.mark.local
    def test_multi_pattern_single_string(sanitizer):
        result = sanitizer.sanitize("user@example.com or 123-45-6789")
        assert "[REDACTED_EMAIL]" in result
        assert "[REDACTED_SSN]" in result
        assert "user@example.com" not in result
        assert "123-45-6789" not in result

    @pytest.mark.local
    def test_singleton_returns_same_instance():
        a = _get_pii_sanitizer()
        b = _get_pii_sanitizer()
        assert a is b

---

### G.2 `tests/test_token_quota_proxy.py`

**Commit:** `test(governance): add unit tests for token quota proxy circuit breaker` (71 chars)
**Marker:** `@pytest.mark.local` on all tests
**Run:** `uv run pytest tests/test_token_quota_proxy.py -m local -v`
**Dependency:** `fakeredis` (same pattern as `test_fiscal_limit_guard.py:35`)

Required scenarios (Section 13 Phase 3b, Section 18.2):

    import pytest
    from unittest.mock import AsyncMock

    pytest.importorskip("fakeredis", reason="fakeredis required")
    import fakeredis.aioredis

    from src.gateway.governance.token_quota_proxy import (
        TokenQuotaProxy, QuotaExceededError, QuotaCheckResult
    )

    @pytest.fixture
    async def redis_client():
        return fakeredis.aioredis.FakeRedis(decode_responses=True)

    @pytest.fixture
    async def proxy(redis_client):
        return TokenQuotaProxy(
            redis_client=redis_client,
            step_quota_max=12,
            token_quota_max=100_000,
            session_ttl=3600,
        )

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_step_limit_enforcement(proxy):
        """Steps 1-12 allowed; step 13 blocked with block_reason=step_count."""
        for i in range(12):
            result = await proxy.check_and_increment("agent-test", token_delta=100)
            assert result.allowed, f"Step {i+1} should be allowed"
        result = await proxy.check_and_increment("agent-test", token_delta=100)
        assert not result.allowed
        assert result.block_reason == "step_count"
        assert result.step_count == 12

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_token_limit_enforcement(proxy):
        """Single call with token_delta > quota_max is blocked."""
        result = await proxy.check_and_increment("agent-token", token_delta=100_001)
        assert not result.allowed
        assert result.block_reason == "token_count"

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_rollback_decrements_counters(proxy):
        """rollback_step() decrements both step and token counters."""
        await proxy.check_and_increment("agent-rb", token_delta=500)
        await proxy.rollback_step("agent-rb", reserved_tokens=500)
        state = await proxy.get_session_state("agent-rb")
        assert state["steps"] == 0
        assert state["tokens"] == 0

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_reconcile_adjusts_token_counter(proxy):
        """reconcile_actual_tokens() corrects over-allocation."""
        await proxy.check_and_increment("agent-rec", token_delta=1000)
        await proxy.reconcile_actual_tokens(
            "agent-rec", reserved_tokens=1000, actual_tokens_used=876
        )
        state = await proxy.get_session_state("agent-rec")
        assert state["tokens"] == 876

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_fail_closed_redis_unavailable(redis_client):
        """Redis connection error raises QuotaExceededError (fail-CLOSED)."""
        proxy = TokenQuotaProxy(redis_client=redis_client, step_quota_max=12)
        proxy._redis.script_load = AsyncMock(
            side_effect=ConnectionError("Redis connection refused")
        )
        with pytest.raises(QuotaExceededError):
            await proxy.check_and_increment("agent-fail", token_delta=0)

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_session_ttl_set(proxy, redis_client):
        """After check_and_increment, Redis keys have TTL set."""
        await proxy.check_and_increment("agent-ttl", token_delta=0)
        ttl = await redis_client.ttl("quota:session:agent-ttl:steps")
        assert 0 < ttl <= 3600

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_reset_session_clears_keys(proxy):
        """reset_session() deletes all session keys."""
        await proxy.check_and_increment("agent-reset", token_delta=100)
        await proxy.reset_session("agent-reset")
        state = await proxy.get_session_state("agent-reset")
        assert state["steps"] == 0
        assert state["tokens"] == 0

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_quota_check_result_fields(proxy):
        """QuotaCheckResult has all required fields populated."""
        result = await proxy.check_and_increment("agent-fields", token_delta=500)
        assert result.allowed is True
        assert result.agent_id == "agent-fields"
        assert result.step_count == 1
        assert result.accumulated_tokens == 500
        assert result.step_quota_max == 12
        assert result.token_quota_max == 100_000
        assert result.block_reason is None
        assert result.session_ttl == 3600

**Implementation note on Lua TTL:** The plan's Section 6.2 Lua uses a fixed-window guard
(`if redis.call('TTL', KEYS[1]) < 0`). The current `token_quota_proxy.py:85-86` sets EXPIRE
unconditionally on every call. Tests should verify TTL is set but need not test fixed-window
behavior since the implementation intentionally differs from the plan's Lua spec on this point.

---

### G.3 `tests/test_uca_logger.py`

**Commit:** `test(governance): add unit tests for uca logger compliance records` (67 chars)
**Marker:** `@pytest.mark.local` on all tests
**Run:** `uv run pytest tests/test_uca_logger.py -m local -v`
**Dependencies:** `fakeredis`, `unittest.mock`

Required scenarios (Section 13 Phase 3c, Section 18.2):

    import pytest
    import os
    import re
    from unittest.mock import MagicMock, AsyncMock, patch

    pytest.importorskip("fakeredis", reason="fakeredis required")
    import fakeredis.aioredis

    from src.gateway.governance.token_quota_proxy import QuotaCheckResult
    from src.gateway.governance.pii_sanitizer import PIISanitizer

    def _mock_quota_result(step_count=13, block_reason="step_count"):
        return QuotaCheckResult(
            allowed=False, agent_id="test-agent",
            step_count=step_count, accumulated_tokens=1000,
            step_quota_max=12, token_quota_max=100_000,
            block_reason=block_reason, session_ttl=3600,
        )

    @pytest.fixture
    async def redis_client():
        return fakeredis.aioredis.FakeRedis(decode_responses=True)

    @pytest.fixture
    async def uca_logger(redis_client):
        from src.gateway.governance.uca_logger import UCALogger
        return UCALogger(
            signer=None,
            redis_client=redis_client,
            bucket="test-bucket",
            pii_sanitizer=PIISanitizer(),
            test_mode=True,
        )

    REQUIRED_SCHEMA_FIELDS = [
        "compliance_event_id", "timestamp", "iso42001_clause",
        "iso42001_control", "governance_control_id", "uca_type",
        "agent_id", "session_key", "block_reason", "current_value",
        "quota_max", "request_summary", "cryptographic_signature",
        "signing_key_id", "deployment_region", "worm_path",
    ]

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_uca_record_schema_conformance(uca_logger):
        """UCA record contains all 16 required ISO 42001 Clause 6.1 fields."""
        record = await uca_logger._build_uca_record(
            uca_type="quota_exceeded",
            agent_id="test-agent",
            quota_result=_mock_quota_result(),
            request_body={"model": "test"},
        )
        for field in REQUIRED_SCHEMA_FIELDS:
            assert field in record, f"Missing required field: {field}"

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_hmac_stub_signing_in_test_mode(uca_logger):
        """test_mode=True produces 0xSTUB_ prefixed signature."""
        record = await uca_logger._build_uca_record(
            uca_type="quota_exceeded",
            agent_id="test-agent",
            quota_result=_mock_quota_result(),
            request_body={},
        )
        assert record["cryptographic_signature"].startswith("0xSTUB_")

    @pytest.mark.local
    def test_region_bucket_us_fed():
        """_get_worm_bucket() returns OSCAL_S3_BUCKET_US_FED for US_FED."""
        from src.gateway.governance.uca_logger import UCALogger
        logger = UCALogger(signer=None, redis_client=MagicMock(),
                           bucket="", pii_sanitizer=PIISanitizer(), test_mode=True)
        with patch.dict(os.environ, {
            "CAGE_DEPLOYMENT_REGION": "US_FED",
            "OSCAL_S3_BUCKET_US_FED": "us-fed-bucket",
        }):
            assert logger._get_worm_bucket() == "us-fed-bucket"

    @pytest.mark.local
    def test_region_bucket_eu_ecb():
        """_get_worm_bucket() returns OSCAL_S3_BUCKET_EU_ECB for EU_ECB."""
        from src.gateway.governance.uca_logger import UCALogger
        logger = UCALogger(signer=None, redis_client=MagicMock(),
                           bucket="", pii_sanitizer=PIISanitizer(), test_mode=True)
        with patch.dict(os.environ, {
            "CAGE_DEPLOYMENT_REGION": "EU_ECB",
            "OSCAL_S3_BUCKET_EU_ECB": "eu-ecb-bucket",
        }):
            assert logger._get_worm_bucket() == "eu-ecb-bucket"

    @pytest.mark.local
    def test_region_bucket_apac_mas():
        """_get_worm_bucket() returns OSCAL_S3_BUCKET_APAC_MAS for APAC_MAS."""
        from src.gateway.governance.uca_logger import UCALogger
        logger = UCALogger(signer=None, redis_client=MagicMock(),
                           bucket="", pii_sanitizer=PIISanitizer(), test_mode=True)
        with patch.dict(os.environ, {
            "CAGE_DEPLOYMENT_REGION": "APAC_MAS",
            "OSCAL_S3_BUCKET_APAC_MAS": "apac-mas-bucket",
        }):
            assert logger._get_worm_bucket() == "apac-mas-bucket"

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_worm_write_failure_non_blocking(uca_logger):
        """WORM write failure does not suppress the block; method returns."""
        with patch.object(uca_logger, "_persist_uca_record",
                          side_effect=Exception("GCS unavailable")):
            # Should not raise; block is still enforced
            try:
                await uca_logger.log_quota_exceeded(_mock_quota_result(), {})
            except Exception as e:
                pytest.fail(f"log_quota_exceeded raised unexpectedly: {e}")

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_pii_sanitization_applied(uca_logger):
        """Request body SSN is redacted in UCA record request_summary."""
        record = await uca_logger._build_uca_record(
            uca_type="quota_exceeded",
            agent_id="test-agent",
            quota_result=_mock_quota_result(),
            request_body={"prompt": "My SSN is 123-45-6789"},
        )
        assert "[REDACTED_SSN]" in record["request_summary"]
        assert "123-45-6789" not in record["request_summary"]

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_event_id_format(uca_logger):
        """_generate_event_id() returns 'UCA-{uuid4}' format."""
        event_id = await uca_logger._generate_event_id()
        assert re.match(
            r"^UCA-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            event_id
        ), f"Event ID format invalid: {event_id}"

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_worm_path_format(uca_logger):
        """_persist_uca_record() returns path matching uca-records/YYYY-MM-DD/UCA-*.yaml."""
        with patch.object(uca_logger, "_write_to_worm", return_value=None):
            record = await uca_logger._build_uca_record(
                uca_type="quota_exceeded",
                agent_id="test-agent",
                quota_result=_mock_quota_result(),
                request_body={},
            )
            worm_path = await uca_logger._persist_uca_record(record)
            assert re.match(
                r"^uca-records/\d{4}-\d{2}-\d{2}/UCA-[0-9a-f-]+\.yaml$",
                worm_path
            ), f"WORM path format invalid: {worm_path}"

---

## H. Rego Rules Spec

### H.1 Current State of `deployment/system_authz.rego`

The current file (43 lines) contains:

    package system.authz
    import rego.v1

    default allow = false

    allow if { input.identity == data.auth_token }

    _min_confidence_normal := 0.95
    _min_confidence_slm_degraded := 0.97

    _effective_min_confidence := _min_confidence_slm_degraded if {
        input.slm_available == false
    }
    _effective_min_confidence := _min_confidence_normal if {
        input.slm_available != false
    }

    confidence_sufficient if {
        input.action == "execute_trade"
        confidence := object.get(input, "confidence", 0)
        confidence >= _effective_min_confidence
    }

    confidence_sufficient if { input.action != "execute_trade" }

    slm_degraded_warning := "SLM sidecar unavailable: elevated confidence threshold applied" if {
        input.slm_available == false
        input.action == "execute_trade"
    }

**Missing:** No quota rules, no tool allowlist, no `cage_systemic_governance_allow` rule.

### H.2 Exact Rego Rules to Append (Section 7.1, Phase 2c)

**Commit:** `feat(governance): add quota rego rules to system-authz` (53 chars — corrected per gap analysis)

Append the following block to the end of `deployment/system_authz.rego`:

    # Token Quota Enforcement (ISO 42001 Annex A.4)
    # CTRL_TQP_007 — secondary declarative evidence layer.
    # Primary enforcement: TokenQuotaProxy (Python, Redis Lua).
    # These rules activate when governance_middleware.py injects session state.
    # Until that injection is implemented (deferred — see Section 23.7 of plan),
    # quota_within_limits and token_quota_within_limits default to true via the
    # second clause of each rule.

    _max_sequence_steps := 12

    quota_within_limits if {
        step_count := object.get(input, "sequence_step_count", 0)
        step_count <= _max_sequence_steps
    }
    quota_within_limits if { not input.sequence_step_count }

    token_quota_within_limits if {
        accumulated := object.get(input, "accumulated_tokens", 0)
        quota_max   := object.get(input, "token_quota_max", 100000)
        accumulated <= quota_max
    }
    token_quota_within_limits if { not input.accumulated_tokens }

    # Tool Allowlist (ISO 42001 Annex A.2)
    _approved_tools := {
        "send_alert", "get_market_data", "execute_trade", "get_portfolio",
        "calculate_risk", "get_account_balance", "submit_order",
        "cancel_order", "get_order_status",
    }
    tool_approved if { input.tool_name; input.tool_name in _approved_tools }
    tool_approved if { not input.tool_name }

    # Combined governance allow rule
    cage_systemic_governance_allow if {
        confidence_sufficient
        quota_within_limits
        token_quota_within_limits
        tool_approved
    }

### H.3 Dead-Code Risk (Gap Analysis Finding)

These rules are **secondary evidence only**. They are dead code unless `governance_middleware.py` injects `sequence_step_count`, `accumulated_tokens`, and `token_quota_max` into the OPA `input` document. That injection is deferred to a follow-on PR (Section 23.7 of plan).

Until injection is implemented:
- `quota_within_limits` always evaluates to `true` (second clause fires because `input.sequence_step_count` is absent)
- `token_quota_within_limits` always evaluates to `true` (same reason)
- `tool_approved` always evaluates to `true` when no tool call is present

The Python `TokenQuotaProxy` is the primary enforcer. OPA rules provide secondary declarative evidence for ISO 42001 Clause 6.1 audit purposes.

### H.4 Acceptance Criteria (Phase 2c)

- `opa check deployment/system_authz.rego` passes (no syntax errors)
- `quota_within_limits` defaults to `true` when `input.sequence_step_count` is absent
- `token_quota_within_limits` defaults to `true` when `input.accumulated_tokens` is absent
- `tool_approved` defaults to `true` when `input.tool_name` is absent
- `cage_systemic_governance_allow` includes all four conditions: `confidence_sufficient`, `quota_within_limits`, `token_quota_within_limits`, `tool_approved`

### H.5 Note on `cage_systemic_governance_allow` vs. `allow`

The new rule is named `cage_systemic_governance_allow`, not `allow`. This is intentional — the existing `allow` rule (line 8 of current file) is based on `input.identity == data.auth_token` and must not be replaced. The new combined rule is a separate named rule that can be referenced by governance middleware when OPA injection is implemented.

---

## Summary Table

| Item | File | Status | Action Required |
|---|---|---|---|
| A | `src/gateway/governance/pii_sanitizer.py` | COMPLETE | None |
| B | `src/gateway/governance/uca_logger.py` | MISSING | Create new file |
| C | `src/gateway/server/inference_proxy.py` | NEEDS CHANGES | 6 changes (see C.2) |
| D | `src/gateway/server/hybrid_server.py` | NEEDS CHANGES | 1 insertion (see D.2) |
| E | `src/gateway/governance/constants.py` | NEEDS CHANGES | Add enum member + JSON baselines |
| F | `config/thresholds/token_quota.yaml` | MISSING | Create new file |
| G1 | `tests/test_pii_sanitizer.py` | MISSING | Create new file |
| G2 | `tests/test_token_quota_proxy.py` | MISSING | Create new file |
| G3 | `tests/test_uca_logger.py` | MISSING | Create new file |
| H | `deployment/system_authz.rego` | NEEDS CHANGES | Append quota + tool rules |

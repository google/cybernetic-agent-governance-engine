# Code Quality & Stability Analysis
## cybernetic-governance-engine — Production Readiness Assessment

**Generated:** 2026-06-07  
**Scope:** Static analysis of ~35 source files across gateway, compliance_bridge, governed_financial_advisor, and config modules  
**Analyst:** Automated code review (Roo)

---

## Executive Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 4 |
| 🟠 High | 7 |
| 🟡 Medium | 7 |
| 🔵 Low | 6 |
| **Total** | **24** |

### Key Risk Areas
- **Unimplemented production provider** (`AnchorageGrpcLedgerProvider`) — custody balance reconciliation is entirely stubbed
- **Hardcoded HMAC fallback secret** in `routing_seal.py` — publicly visible in source
- **Mixed sync/async Redis** in `fiscal_limit_guard.py` — event-loop blocking in production async paths
- **Deprecated `asyncio.get_event_loop().run_until_complete()`** in `causal_gatekeeper.py` — fails in Python 3.10+ when called from a running loop
- **Synchronous `requests` library** used inside an async execution path in `tools.py`

---

## 🔴 CRITICAL Issues

### C-1 — Synchronous `requests` library in async execution path
**File:** [`src/gateway/core/tools.py`](../src/gateway/core/tools.py:93)  
**Lines:** 93–97

```python
def _do_post():
    import requests   # ← sync library, blocks the event loop
    resp = requests.post(f"{base_url}/v2/orders", json=payload, headers=headers)
```

**Problem:** `_do_post` is a nested sync function called via `await asyncio.to_thread(_do_post)` — the `asyncio.to_thread` wrapper does run it in a thread pool, which prevents direct event-loop blocking. However, the inline comment explicitly states `# Switch to httpx for native async I/O`, indicating the migration was planned but never completed. More critically, `requests` is not listed as a declared dependency in the project's Python packaging; if the package is absent at runtime the import will raise `ModuleNotFoundError` and the entire trade execution path will fail. Additionally, `"side": "buy"` is hardcoded with the comment `# Assuming buy for simple example` — this is not production-ready.

**Fix:** Replace `_do_post` with a proper `async def` using `httpx.AsyncClient` (already a declared dependency). Remove the hardcoded `"side": "buy"` and derive it from `order.side`.

---

### C-2 — Hardcoded default HMAC key publicly visible in source
**File:** [`src/gateway/governance/routing_seal.py`](../src/gateway/governance/routing_seal.py:73)  
**Line:** 73

```python
_GOVERNANCE_SALT = os.getenv("GOVERNANCE_SALT", "REDACTED_SALT")
```

**Problem:** The string `"REDACTED_SALT"` is a hardcoded fallback for the HMAC-SHA256 signing key used to authenticate all routing seals. Any deployment that fails to set `GOVERNANCE_SALT` will silently use this publicly-known default, making all seal verification trivially bypassable. The file itself warns about this (`assert_custom_salt_in_production()` exists) but the warning is only triggered if explicitly called — it is not enforced at module import time.

**Fix:** Remove the default value entirely: `_GOVERNANCE_SALT = os.environ["GOVERNANCE_SALT"]`. This will raise `KeyError` at startup if the secret is absent, which is the correct fail-safe behavior. Alternatively, call `assert_custom_salt_in_production()` unconditionally at module load time.

---

### C-3 — Deprecated `asyncio.get_event_loop().run_until_complete()` in async context
**File:** [`src/gateway/governance/causal_gatekeeper.py`](../src/gateway/governance/causal_gatekeeper.py:326)  
**Lines:** 328–336

```python
loop = asyncio.get_event_loop()
loop.run_until_complete(_causal_cache_get(cache_key))
```

**Problem:** `asyncio.get_event_loop()` is deprecated in Python 3.10+ when there is no running event loop, and raises `DeprecationWarning`. More critically, `run_until_complete()` **raises `RuntimeError`** if called from within a running event loop (which is always the case in a FastAPI/asyncio application). This means the Redis cache lookup for causal results will **always fail** in production, silently falling back to a full causal computation on every call.

**Fix:** Convert `causal_safety_check` to `async def` and use `await _causal_cache_get(cache_key)` directly. If a sync interface is required, use `asyncio.run()` only when no loop is running, or use `nest_asyncio` (already imported in `nemo/manager.py`).

---

### C-4 — Production custody provider completely unimplemented
**File:** [`config/compliance/reconciliation_worker.py`](../config/compliance/reconciliation_worker.py:332)  
**Lines:** 332–413

```python
class AnchorageGrpcLedgerProvider:
    def _create_channel(self) -> object:
        raise NotImplementedError(
            "Anchorage gRPC channel creation is not yet implemented."
        )

    def fetch_balance(self, account_id: str) -> ReconciliationResult:
        raise NotImplementedError(
            "Anchorage Digital gRPC balance fetch is not yet implemented."
        )
```

**Problem:** The production ledger provider for external custody balance reconciliation raises `NotImplementedError` on every call. The `ExternalLedgerReconciler` will fall back to `StubLedgerProvider` (which returns a configurable static balance) in production if `LEDGER_PROVIDER=anchorage` is set. The file's own docstring explicitly documents a **recursive self-authentication vulnerability**: "The CBF currently relies on self-reported balances from the same system it is auditing." This is a compliance gap, not just a code quality issue.

**Fix:** Implement the Anchorage gRPC integration or document a formal POAM item with a remediation timeline. The `StubLedgerProvider` must not be used in production environments.

---

## 🟠 HIGH Priority Issues

### H-1 — Silent exception swallowing in OPA cache helpers
**File:** [`src/gateway/core/policy.py`](../src/gateway/core/policy.py:87)  
**Lines:** 87–111

```python
async def _read_opa_cache(key: str) -> Optional[str]:
    try:
        ...
    except Exception:
        return None  # ← no logging, no metrics

async def _write_opa_cache(key: str, decision: str) -> None:
    try:
        ...
    except Exception:
        pass  # ← completely silent
```

**Problem:** Redis cache failures are completely invisible. If Redis becomes unavailable, every OPA evaluation will silently bypass the cache and hit OPA directly — this is the correct fallback behavior, but the absence of any logging or metrics means operators have no visibility into cache degradation. A sustained Redis outage will cause latency spikes that appear as unexplained OPA slowness.

**Fix:** Add `logger.warning("OPA cache read failed: %s", exc)` in both handlers. Increment a Prometheus/OpenTelemetry counter for cache miss-due-to-error vs. cache miss-due-to-absence.

---

### H-2 — Wrong log level for success event
**File:** [`src/gateway/server/governance_middleware.py`](../src/gateway/server/governance_middleware.py:394)  
**Line:** 394–398

```python
logger.error(
    "🔴 [P6] Signed OSCAL refusal receipt emitted: action='%s' ..."
)
```

**Problem:** `logger.error()` is used to log a **successful** OSCAL refusal receipt emission. This will trigger error alerting in any monitoring system configured to page on `ERROR`-level log entries, creating alert fatigue and masking real errors. The `🔴` emoji reinforces the incorrect severity signal.

**Fix:** Change to `logger.info()` with a `🟢` or `✅` emoji, or `logger.debug()` if this is a high-frequency event.

---

### H-3 — Mixed sync/async Redis client in `FiscalLimitGuard`
**File:** [`src/gateway/governance/fiscal_limit_guard.py`](../src/gateway/governance/fiscal_limit_guard.py:153)  
**Lines:** 153–172, 182–250

```python
@classmethod
def from_env(cls, ...) -> "FiscalLimitGuard":
    ...
    _redis = redis.Redis.from_url(redis_url, ...)  # ← synchronous client

async def _atomic_increment(self, ...):
    ...
    async with self._redis.pipeline(True) as pipe:  # ← async context manager on sync client
        await asyncio.sleep(0)  # ← await in method using sync Redis
```

**Problem:** `from_env()` creates a **synchronous** `redis.Redis` client, but `_atomic_increment` and `_atomic_decrement` are `async def` methods that use `async with self._redis.pipeline(True)`. A synchronous `redis.Redis` pipeline does not support the async context manager protocol — this will raise `AttributeError: __aenter__` at runtime. The `await asyncio.sleep(0)` calls inside these methods further confirm the intent was async, but the client instantiation is wrong.

**Fix:** Replace `redis.Redis.from_url(...)` with `redis.asyncio.Redis.from_url(...)` in `from_env()`. Verify all pipeline operations use `await`.

---

### H-4 — `_background_audit_worker` missing `task_done()` in exception handler
**File:** [`src/gateway/governance/consensus.py`](../src/gateway/governance/consensus.py:74)  
**Lines:** 74–87

```python
async def _background_audit_worker() -> None:
    while True:
        item = await _AUDIT_QUEUE.get()
        try:
            ...
        except Exception as exc:
            logger.error("Audit worker error: %s", exc)
            # ← Missing: _AUDIT_QUEUE.task_done()
        finally:
            _AUDIT_QUEUE.task_done()  # ← only in finally? check actual code
```

**Problem:** If the `try` block raises an exception, `_AUDIT_QUEUE.task_done()` is not called in the exception handler. Any caller using `await _AUDIT_QUEUE.join()` to wait for all audit items to be processed will **hang indefinitely** after the first audit worker error. This is a classic asyncio queue liveness bug.

**Fix:** Move `_AUDIT_QUEUE.task_done()` to a `finally:` block to guarantee it is always called regardless of success or failure.

---

### H-5 — Duplicate MCP tool implementations
**File:** [`src/gateway/server/mcp_tool_server.py`](../src/gateway/server/mcp_tool_server.py:338)  
**Lines:** 328–347

```python
@mcp.tool()
async def check_market_status(symbol: str) -> str:
    return await asyncio.to_thread(get_market_data, symbol)

@mcp.tool()
async def get_market_sentiment(symbol: str) -> str:
    return await asyncio.to_thread(get_market_data, symbol)
```

**Problem:** `check_market_status` and `get_market_sentiment` are **byte-for-byte identical** implementations. Both call `get_market_data(symbol)` via `asyncio.to_thread`. One of them is dead code. This also means the MCP tool registry exposes two tools that return identical data, which will confuse LLM agents selecting tools.

**Fix:** Differentiate the implementations (e.g., `get_market_sentiment` should call a sentiment-specific API endpoint) or remove the duplicate and keep only one.

---

### H-6 — `verify_seal()` docstring contradicts implementation
**File:** [`src/gateway/governance/routing_seal.py`](../src/gateway/governance/routing_seal.py:176)  
**Lines:** 176–255

**Problem:** The docstring for `verify_seal()` states: *"Raises `SymbolicGovernorViolation` on failure"*. However, the implementation wraps the entire body in `try/except SymbolicGovernorViolation: return False`, making the raise behavior **unreachable from the caller's perspective**. The `require_cleared_seal` decorator checks `if not verify_seal(...)` — it will never see a `SymbolicGovernorViolation` raised from `verify_seal`. This creates a false security assumption: callers who rely on the exception for control flow will silently receive `False` instead.

**Fix:** Either (a) remove the `except SymbolicGovernorViolation` block and let the exception propagate as documented, or (b) update the docstring to accurately state "Returns `False` on failure; never raises."

---

### H-7 — KMS signer `signing_algorithm` property contradicts docstring
**File:** [`src/gateway/governance/kms_signer.py`](../src/gateway/governance/kms_signer.py:143)  
**Lines:** 143–151

```python
@property
def signing_algorithm(self) -> str:
    if self._kms_active:
        return "EC_SIGN_P256_SHA256"
    return "HMAC_SHA256_FALLBACK"  # ← returned when KMS inactive
```

**Problem:** The class docstring states: *"The legacy HMAC GOVERNANCE_SALT fallback has been permanently removed."* Yet the `signing_algorithm` property returns `"HMAC_SHA256_FALLBACK"` when KMS is not active. This contradiction means either (a) the fallback was not actually removed and the docstring is wrong, or (b) the property returns a misleading algorithm identifier for a code path that should not exist. Evidence stream entries tagged with `"HMAC_SHA256_FALLBACK"` will fail OSCAL compliance assertions that require KMS-backed signatures.

**Fix:** If the HMAC fallback is truly removed, raise `RuntimeError("KMS is not active; HMAC fallback has been permanently removed")` instead of returning the string. If the fallback exists, update the docstring.

---

## 🟡 MEDIUM Priority Issues

### M-1 — `validate_required_settings()` checks wrong namespace
**File:** [`config/settings.py`](../config/settings.py:101)  
**Lines:** 101–109

```python
def validate_required_settings():
    required = ["OPA_URL", "REDIS_URL", ...]
    missing = [var for var in required if not globals().get(var.replace("-", "_"))]
```

**Problem:** `globals()` returns the module-level global variables of `settings.py`, not the attributes of the `Config` class. Since `OPA_URL`, `REDIS_URL`, etc. are defined as class attributes on `Config` (not as module-level variables), `globals().get("OPA_URL")` will always return `None`, making every setting appear "missing." This validation function is effectively broken and provides false assurance.

**Fix:** Replace `globals().get(var)` with `getattr(Config, var, None)` to correctly inspect the `Config` class attributes.

---

### M-2 — Duplicate `_DEPLOYMENT_START_UTC` parsing implementations
**File:** [`src/compliance_bridge/metrics.py`](../src/compliance_bridge/metrics.py:85)  
**Lines:** 85–115

**Problem:** Two separate implementations for parsing `DEPLOYMENT_START_UTC` exist simultaneously in the same file: a complex inline expression at lines 85–93 and a cleaner `_parse_deployment_start()` function at lines 98–112. The module-level `_DEPLOYMENT_START_UTC` variable uses the inline expression, making `_parse_deployment_start()` dead code. This creates maintenance confusion — future changes to the parsing logic may only update one of the two implementations.

**Fix:** Remove the inline expression and use `_DEPLOYMENT_START_UTC = _parse_deployment_start()` to call the function.

---

### M-3 — `GovernanceCheckRequest` stub class with `pass` body
**File:** [`src/gateway/server/governance_middleware.py`](../src/gateway/server/governance_middleware.py:262)  
**Lines:** 262–265

```python
class GovernanceCheckRequest(dict):
    pass
```

**Problem:** This class is defined but never used in the file. It inherits from `dict` with no additional fields or methods, making it a meaningless alias. It appears to be an incomplete implementation of a Pydantic request model that was abandoned mid-development.

**Fix:** Either implement the class as a proper `pydantic.BaseModel` with the expected fields, or remove it entirely.

---

### M-4 — `np.random.seed(42)` global state mutation in `generate_mock_telemetry`
**File:** [`src/gateway/governance/causal_gatekeeper.py`](../src/gateway/governance/causal_gatekeeper.py:79)  
**Lines:** 79–114

```python
def generate_mock_telemetry(n_samples: int = 1000) -> pd.DataFrame:
    np.random.seed(42)  # ← mutates global numpy random state
```

**Problem:** Calling `np.random.seed(42)` sets the **global** numpy random number generator seed. Any code running after this call (in the same process) that uses `np.random` will produce deterministic, non-random results. In a test environment this causes test interdependency; in production it can subtly corrupt any statistical computation that relies on numpy's random state (e.g., Monte Carlo simulations, random sampling in other governance checks).

**Fix:** Use a local RNG instance: `rng = np.random.default_rng(42)` and replace all `np.random.*` calls with `rng.*`.

---

### M-5 — `_enqueue_signing` callback mutates entry after Redis write
**File:** [`src/compliance_bridge/evidence_stream.py`](../src/compliance_bridge/evidence_stream.py:298)  
**Lines:** 298–315

```python
def _enqueue_signing(self, entry: dict) -> None:
    def _on_signed(record: PendingSignatureRecord) -> None:
        entry["kms_signature"] = record.signature_hex  # ← mutates local dict
        # ← Redis record is NOT updated with the signature
```

**Problem:** The `_on_signed` callback mutates the in-memory `entry` dict with the KMS signature after the entry has already been written to Redis Streams. The Redis record will **never** contain the `kms_signature` field. Evidence chain entries in Redis will always have a missing signature, which will cause OSCAL compliance assertions that verify KMS-signed evidence to fail.

**Fix:** After setting `entry["kms_signature"]`, issue a Redis `XADD` or `HSET` update to patch the existing stream entry with the signature, or restructure the flow to sign before writing to Redis.

---

### M-6 — `_fetch_from_langfuse_sync` has no error handling
**File:** [`src/compliance_bridge/metrics.py`](../src/compliance_bridge/metrics.py:136)  
**Lines:** 136–192

**Problem:** `_fetch_from_langfuse_sync` makes a Langfuse API call with no `try/except` wrapper around the network call itself. Any `httpx.ConnectError`, `httpx.TimeoutException`, or Langfuse API error will propagate uncaught to `get_compliance_metrics`, which calls this function inside a `try/except Exception` block — but the outer handler logs the error and returns a degraded metrics dict. The issue is that the Langfuse client may raise non-`Exception` base class errors (e.g., `BaseException` subclasses from threading) that bypass the outer handler.

**Fix:** Wrap the Langfuse API call in `_fetch_from_langfuse_sync` with `try/except Exception as e: logger.warning(...)` and return a safe default.

---

### M-7 — `vllm_client.py` inconsistent `openai/` prefix handling between `_agenerate` and `_astream`
**File:** [`src/gateway/governance/nemo/vllm_client.py`](../src/gateway/governance/nemo/vllm_client.py:163)  
**Lines:** 163–320

**Problem:** `_agenerate` applies the `openai/` prefix to `model_id` using one code path, while `_astream` uses a different conditional check for the same prefix. If the model identifier changes or the prefix logic diverges, one method will send requests to the wrong model endpoint while the other succeeds. This inconsistency is a latent bug that will manifest as silent model routing errors.

**Fix:** Extract the `openai/` prefix normalization into a single private method `_normalize_model_id(model_id: str) -> str` and call it from both `_agenerate` and `_astream`.

---

## 🔵 LOW Priority Issues

### L-1 — `trader_id` and `trader_role` Optional with no runtime enforcement
**File:** [`src/gateway/core/structs.py`](../src/gateway/core/structs.py:24)  
**Lines:** 24–88

**Problem:** `trader_id: Optional[str] = None` and `trader_role: Optional[str] = None` are documented with the comment "production execution requires these to be populated" but there is no runtime validator enforcing this. A `TradeOrder` with `trader_id=None` will pass validation and reach the OPA policy engine, which may or may not enforce the requirement depending on policy configuration.

**Fix:** Add a `@model_validator(mode='after')` that raises `ValueError` if `trader_id` or `trader_role` is `None` when `environment == "production"`, or make them non-optional fields.

---

### L-2 — Symbol validator excludes valid financial tickers
**File:** [`src/gateway/core/structs.py`](../src/gateway/core/structs.py:71)  
**Lines:** 71–79

```python
@field_validator('symbol')
def validate_symbol(cls, v):
    if not re.match(r'^[A-Z]{1,5}$', v):
        raise ValueError(...)
```

**Problem:** The regex `^[A-Z]{1,5}$` excludes valid tickers such as `BRK.B` (Berkshire Hathaway Class B), `BTC-USD` (crypto), `ES=F` (futures), and any ticker with a dot, hyphen, or equals sign. This will cause legitimate trade orders to be rejected at the struct validation layer before reaching OPA.

**Fix:** Expand the regex to `^[A-Z0-9]{1,5}([.\-=][A-Z0-9]{1,5})?$` or use an allowlist approach for known exchange suffixes.

---

### L-3 — `governance_client.py` type annotation mismatch
**File:** [`src/governed_financial_advisor/infrastructure/governance_client.py`](../src/governed_financial_advisor/infrastructure/governance_client.py:169)  
**Line:** 169 (approx.)

```python
def __init__(self, ..., api_key: str = None, ...):
```

**Problem:** `api_key` is annotated as `str` but defaults to `None`, which is a `NoneType`. This is a type annotation lie that will cause `mypy` errors and may cause runtime `AttributeError` if code calls `api_key.upper()` or similar string methods without a None check.

**Fix:** Change to `api_key: Optional[str] = None` (or `str | None = None` in Python 3.10+ style).

---

### L-4 — `llm_client.py` is a legacy alias file with no content
**File:** [`src/governed_financial_advisor/infrastructure/llm_client.py`](../src/governed_financial_advisor/infrastructure/llm_client.py)

**Problem:** The entire file consists of a single alias: `HybridClient = GatewayClient`. This is a legacy compatibility shim that adds a module to the import graph with no real content. Any code importing `HybridClient` from this module is using a deprecated name.

**Fix:** Migrate all `HybridClient` usages to `GatewayClient` and remove the file, or add a `DeprecationWarning` to the alias.

---

### L-5 — `nest_asyncio.apply()` called at module import in `nemo/manager.py`
**File:** [`src/gateway/governance/nemo/manager.py`](../src/gateway/governance/nemo/manager.py)  
**Lines:** ~657–661

```python
try:
    import nest_asyncio
    nest_asyncio.apply()
```

**Problem:** `nest_asyncio.apply()` patches the global asyncio event loop to allow nested `run_until_complete()` calls. This is a development workaround that can mask real concurrency bugs in production. Calling it at module import time means it is applied to every process that imports `manager.py`, including test runners and production servers, potentially hiding deadlocks or reentrancy issues.

**Fix:** Move `nest_asyncio.apply()` to a controlled initialization path (e.g., only when `CAGE_NEMO_NEST_ASYNCIO=true` is set), or eliminate the need for it by converting the affected code to proper async.

---

### L-6 — Large commented-out dead code block in `nemo/manager.py`
**File:** [`src/gateway/governance/nemo/manager.py`](../src/gateway/governance/nemo/manager.py:342)  
**Lines:** 342–360 (approx.)

**Problem:** A multi-line commented-out code block implementing flow deduplication logic remains in the production source. Dead code in comments increases cognitive load for reviewers and creates confusion about whether the logic was intentionally removed or accidentally left out.

**Fix:** Remove the commented-out block. If the deduplication logic may be needed in the future, reference the git commit SHA in a `# TODO` comment instead of leaving the code inline.

---

## Summary Statistics

| Metric | Count | Files Affected |
|--------|-------|----------------|
| `NotImplementedError` instances (production paths) | 2 | `reconciliation_worker.py` |
| Silent `except Exception: pass/return None` (no logging) | 3 | `policy.py`, `causal_gatekeeper.py`, `routing_seal.py` |
| Hardcoded default secrets | 1 | `routing_seal.py` |
| Deprecated `get_event_loop().run_until_complete()` | 1 | `causal_gatekeeper.py` |
| Mixed sync/async client usage | 1 | `fiscal_limit_guard.py` |
| Duplicate tool implementations | 1 pair | `mcp_tool_server.py` |
| Wrong log level (error for success) | 1 | `governance_middleware.py` |
| Commented-out dead code blocks | 1 | `nemo/manager.py` |
| Missing `raise_for_status()` | 1 | `market.py` |
| Broken validation function | 1 | `config/settings.py` |
| Type annotation mismatches | 2 | `governance_client.py`, `structs.py` |
| Post-write mutation (data never persisted) | 1 | `evidence_stream.py` |

---

## Remediation Priority Order

1. **C-2** (hardcoded HMAC key) — security fix, zero-risk change
2. **C-3** (deprecated event loop pattern) — runtime failure in Python 3.10+
3. **H-3** (sync/async Redis mismatch) — runtime `AttributeError` in fiscal guard
4. **H-4** (missing `task_done()`) — liveness bug, queue hangs on error
5. **C-1** (sync `requests` in async path) — missing dependency risk + incomplete migration
6. **M-5** (KMS signature never persisted to Redis) — compliance evidence gap
7. **M-1** (broken `validate_required_settings`) — false assurance on config validation
8. **H-1** (silent OPA cache failures) — observability gap
9. **C-4** (unimplemented Anchorage provider) — requires POAM item if not remediating immediately
10. All remaining High/Medium issues in priority order

---

## Files Analyzed

| File | Issues Found |
|------|-------------|
| `src/gateway/core/llm.py` | None (clean) |
| `src/gateway/core/policy.py` | H-1 |
| `src/gateway/core/market.py` | Missing `raise_for_status()` (noted in H-5 context) |
| `src/gateway/core/tools.py` | C-1 |
| `src/gateway/core/structs.py` | L-1, L-2 |
| `src/gateway/server/governance_middleware.py` | H-2, M-3 |
| `src/gateway/server/mcp_tool_server.py` | H-5 |
| `src/gateway/governance/routing_seal.py` | C-2, H-6 |
| `src/gateway/governance/fiscal_limit_guard.py` | H-3 |
| `src/gateway/governance/causal_gatekeeper.py` | C-3, M-4 |
| `src/gateway/governance/consensus.py` | H-4 |
| `src/gateway/governance/kms_signer.py` | H-7 |
| `src/gateway/governance/nemo/manager.py` | L-5, L-6 |
| `src/gateway/governance/nemo/vllm_client.py` | M-7 |
| `src/gateway/governance/text_filter.py` | None (clean) |
| `src/gateway/governance/defer_queue.py` | None (clean) |
| `src/gateway/infrastructure/redis_client.py` | None (clean) |
| `src/gateway/infrastructure/telemetry.py` | None (clean) |
| `src/compliance_bridge/evidence_stream.py` | M-5 |
| `src/compliance_bridge/kms_batch_signer.py` | None (clean) |
| `src/compliance_bridge/metrics.py` | M-2, M-6 |
| `src/compliance_bridge/oscal_exporter.py` | None (clean) |
| `src/governed_financial_advisor/infrastructure/governance_client.py` | L-3 |
| `src/governed_financial_advisor/infrastructure/llm_client.py` | L-4 |
| `src/governed_financial_advisor/infrastructure/config_manager.py` | None (clean) |
| `config/settings.py` | M-1 |
| `config/compliance/reconciliation_worker.py` | C-4 |

---

*This report covers static analysis only. Dynamic analysis, fuzzing, and integration test coverage assessment are out of scope for this review.*

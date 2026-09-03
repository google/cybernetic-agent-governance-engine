# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Shared pytest configuration, hooks, and fixtures.

Environment defaults
--------------------
Variables are resolved in this priority order (highest → lowest):

  1. Shell environment (``export VAR=...`` or CI secrets)
  2. ``.env`` file at the project root (loaded with override=False)
  3. Hard-coded defaults set in ``pytest_configure`` below

Integration-marked tests are **skipped by default**.
Pass ``--run-integration`` on the CLI to include them:

    uv run pytest tests/ --run-integration

Port-forward prerequisites
--------------------------
Integration tests require live Kubernetes services.  Start them with:

    ./setup_test_env.sh
"""

import logging
import os

# Set test environment defaults BEFORE any application imports
os.environ.setdefault("CAGE_ENV", "test")
os.environ.setdefault("CAGE_ACTIVE_PLUGINS", "finance")
os.environ.setdefault("CAGE_OPA_DEFAULT_PATH", "src/cage_finance/opa")

os.environ.setdefault(
    "CAGE_ROUTING_SEAL_SECRET", "dev-only-insecure-placeholder-not-for-production-use"
)
os.environ.setdefault(
    "GOVERNANCE_SALT", "dev-only-insecure-placeholder-not-for-production-use"
)
os.environ.setdefault("CAGE_DEPLOYMENT_REGION", "LOCAL")
os.environ.setdefault("LANGFUSE_POSTURE_DRY_RUN", "true")
os.environ.setdefault(
    "CMEK_KEY_RESOURCE_NAME",
    "projects/test-project/locations/us-central1/keyRings/test-keyring/cryptoKeys/test-key/cryptoKeyVersions/1",
)

import pytest

os.environ.setdefault("LANGCHAIN_TRACING_V2", "false")
os.environ.setdefault("LANGSMITH_TRACING", "false")
os.environ.setdefault("OBJC_DISABLE_INITIALIZE_FORK_SAFETY", "YES")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
os.environ.setdefault("EVIDENCE_STREAM_ENABLED", "true")

# ── Load .env early (before any test module is imported) ─────────────────────
# override=False means existing shell env vars always win.
try:
    from dotenv import load_dotenv

    load_dotenv(override=False)
except ImportError:
    pass  # python-dotenv not installed — rely on shell env only

# Sanitize cluster-internal Kubernetes DNS URLs that cannot be resolved outside GKE
_cluster_internal_replacements = {
    "BACKEND_URL": "http://localhost:18080",
    "GATEWAY_URL": "http://localhost:8080",
    "LANGFUSE_HOST": "http://localhost:3001",
    "LANGFUSE_BASEURL": "http://localhost:3001",
    "COMPLIANCE_BRIDGE_URL": "http://localhost:3002",
    "OPA_URL": "http://localhost:8181/v1/data/trade/governance",
    "REDIS_URL": "redis://localhost:6379",
    "VLLM_SERVICE_URL": "http://localhost:8001",
    "VLLM_REASONING_API_BASE": "http://localhost:8000/v1",
}
for _k, _default_url in _cluster_internal_replacements.items():
    _v = os.environ.get(_k)
    if (
        not _v
        or ".svc.cluster.local" in _v
        or "http://opa:8181" in _v
        or "<YOUR_" in _v
        or _v.startswith("<")
    ):
        os.environ[_k] = _default_url

# ── Suppress OTLP BatchSpanProcessor retry noise in test runs ─────────────────
# Set OTEL_TRACES_EXPORTER=none at module-import time (before any test module
# is collected) so that:
#   1. test_langfuse_evaluation.py's module-level BatchSpanProcessor guard
#      fires correctly at collection time.
#   2. The _SuppressOTLPRetryNoise filter below can check the env var at
#      record-emit time and suppress retry warnings after teardown.
# override=False: honour an explicit shell override (e.g. OTEL_TRACES_EXPORTER=otlp
# to re-enable tracing in a local integration run).
if not os.environ.get("OTEL_TRACES_EXPORTER"):
    os.environ["OTEL_TRACES_EXPORTER"] = "none"

# Install a logging filter on all relevant OTLP logger namespaces here —
# before any test module is imported — so the filter is in place before any
# TracerProvider is created.  The BatchSpanProcessor background thread emits
# "Transient error HTTPConnectionPool … retrying in Xs" warnings to stderr
# after pytest teardown when no local OTLP collector is running.
_OTLP_NOISY_PHRASES = (
    "Transient error",
    "Max retries exceeded",
    "Failed to establish a new connection",
    "Failed to export",
    "Retrying in",
    "Connection refused",
    "Failed to upload JSON to S3",
)
_OTLP_LOGGER_NAMESPACES = (
    "opentelemetry.exporter.otlp.proto.http.trace_exporter",
    "opentelemetry.exporter.otlp.proto.http.metric_exporter",
    "opentelemetry.exporter.otlp.proto.http._log_exporter",
    "opentelemetry.exporter.otlp.proto.grpc.exporter",
    "opentelemetry.sdk.trace.export",
)


class _SuppressOTLPRetryNoise(logging.Filter):
    """Suppress noisy OTLP retry warnings when OTEL_TRACES_EXPORTER=none."""

    def filter(self, record: logging.LogRecord) -> bool:
        if os.environ.get("OTEL_TRACES_EXPORTER") == "none":
            msg = record.getMessage()
            if any(phrase in msg for phrase in _OTLP_NOISY_PHRASES):
                return False  # suppress
        return True


_otlp_noise_filter = _SuppressOTLPRetryNoise()
for _ns in _OTLP_LOGGER_NAMESPACES:
    logging.getLogger(_ns).addFilter(_otlp_noise_filter)


# ── Default environment values ────────────────────────────────────────────────


def pytest_configure(config: pytest.Config) -> None:
    """Set environment variable defaults that tests expect."""
    _setdefault("BACKEND_URL", "http://localhost:18080")
    _setdefault("GATEWAY_URL", "http://localhost:8080")
    _setdefault("LANGFUSE_HOST", "http://localhost:3001")
    _setdefault("VLLM_REASONING_API_BASE", "http://localhost:8000/v1")
    # OTEL_EXPORTER_OTLP_ENDPOINT: default points at the Langfuse native OTLP
    # endpoint forwarded to localhost:3001 by setup_test_env.sh.
    # The standalone OTel Collector (port 4318) is deprecated and removed.
    _setdefault(
        "OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:3001/api/public/otel/v1/traces"
    )
    # Disable OTEL span export during tests — no live Langfuse instance is
    # available in the unit-test environment.  Without this, the BatchSpanProcessor
    # background thread retries failed exports for several seconds after each test,
    # adding noise to the output and slowing teardown.  Set OTEL_TRACES_EXPORTER=otlp
    # in the shell to re-enable when a Langfuse port-forward is active.
    _setdefault("OTEL_TRACES_EXPORTER", "none")
    _setdefault("OPENLLMETRY_ENABLED", "false")
    # compliance-bridge port-forward runs on :3002 (Langfuse occupies :3001)
    _setdefault("COMPLIANCE_BRIDGE_URL", "http://localhost:3002")
    # Integration tests: force OPA_URL to the locally port-forwarded instance.
    # The .env file may contain the cluster-internal address (http://opa:8181/...)
    # which is unreachable from the developer workstation — always override to localhost.
    # OPA data path is region-aware: each deployment region has its own policy namespace.
    _region = os.environ.get("CAGE_DEPLOYMENT_REGION", "US_FED")
    _region_locations = {
        "US_FED": "us-central1",
        "EU_ECB": "europe-west1",
        "APAC_MAS": "asia-southeast1",
    }
    if _region in _region_locations:
        os.environ["GOOGLE_CLOUD_LOCATION"] = _region_locations[_region]
    _opa_paths = {
        "US_FED": "http://localhost:8181/v1/data/trade/governance",
        "EU_ECB": "http://localhost:8181/v1/data/eu_ecb/governance",
        "APAC_MAS": "http://localhost:8181/v1/data/apac_mas/governance",
    }
    _setdefault(
        "OPA_URL",
        os.environ.get(
            "OPA_URL_TEST_OVERRIDE",
            _opa_paths.get(_region, _opa_paths["US_FED"]),
        ),
    )
    # Disable OPA Redis decision cache in all test runs to prevent cross-test
    # cache pollution (a warm cache from test_opa_allow would cause test_opa_deny
    # to return a stale ALLOW).  The cache is enabled in production by default.
    _setdefault("OPA_CACHE_ENABLED", "false")
    # GOVERNANCE_SALT must be consistent so routing seals issued during tests
    # can be verified by both the gateway module and the GFA mirror module.
    _setdefault("GOVERNANCE_SALT", "CYBERNETIC_GOVERNANCE_TEST_SALT_32C!")
    # CAGE_ENV must be set to "test" to enable HMAC fallback in routing_seal
    # and kms_signer when KMS_GOVERNANCE_KEY is not configured.
    _setdefault("CAGE_ENV", "test")
    # Remove KMS credentials to force HMAC fallback mode
    os.environ.pop("KMS_GOVERNANCE_KEY", None)
    os.environ.pop("KMS_GOVERNANCE_PUBLIC_PEM", None)
    # EVIDENCE_STREAM_ENABLED default true to satisfy EVIDENCE_CHAIN_BLOCKING precondition in tests
    _setdefault("EVIDENCE_STREAM_ENABLED", "true")

    # Reset KMS signer singleton to ensure HMAC fallback mode is used
    # This must happen AFTER setting CAGE_ENV=test and removing KMS credentials
    try:
        from src.gateway.governance.kms_signer import reset_governance_signer

        reset_governance_signer()
    except ImportError:
        pass  # Module not yet importable during early configuration


def _setdefault(key: str, value: str) -> None:
    """Set an env var only when it is not already present or is a placeholder or cluster-internal."""
    current = os.environ.get(key)
    if (
        not current
        or "<YOUR_" in current
        or current.startswith("<")
        or ".svc.cluster.local" in current
        or "http://opa:8181" in current
    ):
        os.environ[key] = value


# ── KMS signer reset for HMAC fallback in tests ────────────────────────────────


@pytest.fixture(autouse=True)
def reset_kms_signer_for_tests():
    """Reset the KMS signer singleton before each test to ensure HMAC fallback mode.

    This fixture runs automatically for every test to ensure the signer is
    properly initialized in test environment (HMAC fallback when KMS unavailable).
    """
    # Save original values
    orig_cage_env = os.environ.get("CAGE_ENV")
    orig_kms_key = os.environ.get("KMS_GOVERNANCE_KEY")
    orig_kms_pem = os.environ.get("KMS_GOVERNANCE_PUBLIC_PEM")

    # Set test environment and remove KMS credentials to force HMAC fallback
    os.environ["CAGE_ENV"] = "test"
    os.environ.pop("KMS_GOVERNANCE_KEY", None)
    os.environ.pop("KMS_GOVERNANCE_PUBLIC_PEM", None)

    # Reset the signer singleton
    from src.gateway.governance.kms_signer import reset_governance_signer

    reset_governance_signer()

    yield

    # Restore original values
    if orig_cage_env is not None:
        os.environ["CAGE_ENV"] = orig_cage_env
    else:
        os.environ.pop("CAGE_ENV", None)
    if orig_kms_key is not None:
        os.environ["KMS_GOVERNANCE_KEY"] = orig_kms_key
    if orig_kms_pem is not None:
        os.environ["KMS_GOVERNANCE_PUBLIC_PEM"] = orig_kms_pem

    # Reset again after test to ensure clean state
    reset_governance_signer()


# ── Redis WAIT command mock (fakeredis compatibility) ──────────────────────────


@pytest.fixture(autouse=True)
def mock_redis_wait_command(monkeypatch):
    """Mock Redis WAIT command which fakeredis doesn't support.

    The Redis WAIT command is called in src/gateway/governance/cbf.py:576 via
    client.execute_command("WAIT", replicas, timeout) to ensure synchronous
    replication of CBF writes across replicas. fakeredis doesn't implement this
    command, causing 'ResponseError: unknown command WAIT' in tests.

    This fixture patches execute_command on fakeredis to intercept WAIT commands
    and return the requested replica count (indicating successful replication).
    """
    try:
        import fakeredis

        # Store original execute_command
        original_execute_command = fakeredis.FakeRedis.execute_command
        original_execute_command_async = None
        try:
            from fakeredis import aioredis

            original_execute_command_async = aioredis.FakeRedis.execute_command
        except (ImportError, AttributeError):
            pass

        # Wrapper that handles WAIT commands
        def patched_execute_command(self, command, *args, **kwargs):
            if isinstance(command, str) and command.upper() == "WAIT":
                # WAIT numreplicas timeout — return numreplicas to indicate success
                num_replicas = int(args[0]) if args else 0
                return num_replicas
            return original_execute_command(self, command, *args, **kwargs)

        # Async wrapper for FakeRedis from fakeredis.aioredis
        async def patched_execute_command_async(self, command, *args, **kwargs):
            if isinstance(command, str) and command.upper() == "WAIT":
                # WAIT numreplicas timeout — return numreplicas to indicate success
                num_replicas = int(args[0]) if args else 0
                return num_replicas
            result = original_execute_command_async(self, command, *args, **kwargs)
            # Handle both sync and async return values
            if hasattr(result, "__await__"):
                return await result
            return result

        # Apply patches
        monkeypatch.setattr(
            fakeredis.FakeRedis, "execute_command", patched_execute_command
        )
        if original_execute_command_async is not None:
            monkeypatch.setattr(
                aioredis.FakeRedis, "execute_command", patched_execute_command_async
            )

    except ImportError:
        pass  # fakeredis not available


@pytest.fixture(autouse=True)
def reset_cbf_epoch_state():
    """Reset CBF fence epoch tracking between tests to prevent state bleeding.

    The CBF instance's _last_seen_epoch attribute accumulates during test
    execution. When tests run sequentially in the same pytest-xdist worker,
    a test creating a fresh fakeredis (fence_epoch=0) but using a CBF instance
    from a previous test (with _last_seen_epoch=12) triggers false epoch
    regression errors.

    This fixture resets the module-level singleton and any test-created instances
    BEFORE each test to ensure clean isolation.
    """
    # Reset module-level singleton state BEFORE each test
    try:
        from src.gateway.governance.cbf import safety_filter

        safety_filter._last_seen_epoch = 0
        safety_filter._last_verified_fence_epoch = None
        safety_filter._local_debits = 0.0
    except (ImportError, AttributeError):
        pass  # Module not loaded or attributes don't exist

    yield  # Run the test


# ── CLI option ────────────────────────────────────────────────────────────────


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--run-integration",
        action="store_true",
        default=False,
        help="Run tests marked with @pytest.mark.integration (require live services).",
    )
    parser.addoption(
        "--run-live-external",
        action="store_true",
        default=False,
        help="Run tests marked with @pytest.mark.live_external (hit live partner APIs).",
    )
    parser.addoption(
        "--run-chaos",
        action="store_true",
        default=False,
        help="Run chaos tests (Redis failover scenarios). Skipped by default.",
    )


# ── Auto-skip integration tests unless opted in ───────────────────────────────


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Auto-skip @pytest.mark.integration and @pytest.mark.chaos tests unless opted in."""
    run_integration = config.getoption("--run-integration")
    run_live_external = config.getoption("--run-live-external")
    run_chaos = config.getoption("--run-chaos")

    skip_integration = pytest.mark.skip(
        reason=(
            "Integration test — requires live external services. "
            "Pass --run-integration to enable."
        )
    )
    skip_live_external = pytest.mark.skip(
        reason=(
            "Live external test — hits partner APIs. "
            "Pass --run-live-external to enable."
        )
    )
    skip_chaos = pytest.mark.skip(
        reason=("Chaos test — Redis failover scenarios. Pass --run-chaos to enable.")
    )

    for item in items:
        if "integration" in item.keywords and not run_integration:
            item.add_marker(skip_integration)
        if "live_external" in item.keywords and not run_live_external:
            item.add_marker(skip_live_external)
        if "chaos" in item.keywords and not run_chaos:
            item.add_marker(skip_chaos)


# ── OPA reachability fixtures ────────────────────────────────────────────────


@pytest.fixture(scope="session")
def require_opa_trade_policy():
    """Skip the requesting test if OPA is unreachable or the trade.governance policy is not loaded.

    Use via ``@pytest.mark.usefixtures("require_opa_trade_policy")`` on any
    class or test that needs a live OPA instance with the trade.governance
    policy loaded.  This fixture runs at test-setup time (not collection time),
    so it never causes collection-time side effects.
    """
    opa_url = os.environ.get("OPA_URL")
    if not opa_url:
        pytest.skip("OPA_URL not set — skipping OPA integration test")

    import urllib.parse

    import httpx

    raw = opa_url.rstrip("/")
    parsed = urllib.parse.urlparse(raw)
    base = f"{parsed.scheme}://{parsed.netloc}"

    try:
        resp = httpx.get(f"{base}/health", timeout=2)
        if not resp.is_success:
            pytest.skip(
                f"OPA health check failed ({resp.status_code}) — skipping OPA integration test"
            )
        resp2 = httpx.post(
            f"{base}/v1/data/trade/governance",
            json={"input": {"action": "market_analysis", "trader_role": "junior"}},
            timeout=2,
        )
        if not resp2.is_success:
            pytest.skip(
                "OPA trade.governance policy not loaded — skipping OPA integration test"
            )
        result = resp2.json().get("result", {})
        if "allow" not in result:
            pytest.skip(
                "OPA trade.governance policy missing 'allow' key — skipping OPA integration test"
            )
    except Exception as exc:
        pytest.skip(f"OPA not reachable ({exc}) — skipping OPA integration test")


@pytest.fixture(scope="session")
def require_opa_reachable():
    """Skip the requesting test if OPA health endpoint is not reachable.

    Use via ``@pytest.mark.usefixtures("require_opa_reachable")`` on any
    class or test that needs a live OPA instance.  Runs at test-setup time,
    not collection time.
    """
    opa_url = os.environ.get("OPA_URL")
    if not opa_url:
        pytest.skip("OPA_URL not set — skipping OPA integration test")

    import urllib.parse

    import requests as _requests

    parsed = urllib.parse.urlparse(opa_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    try:
        _requests.get(f"{base}/health", timeout=2)
    except Exception as exc:
        pytest.skip(f"OPA not reachable ({exc}) — skipping OPA integration test")


# ── Session-scoped fixtures ───────────────────────────────────────────────────


@pytest.fixture()
async def cleanup_redis_client():
    """Reset the async Redis client between tests to prevent closed event loop errors.

    Not autouse — request this fixture explicitly in tests that open an async
    Redis connection so it doesn't add teardown overhead to unrelated tests.
    """
    yield
    try:
        from src.gateway.infrastructure.redis_client import redis_client

        if redis_client is not None:
            await redis_client.close()
    except Exception:
        pass


@pytest.fixture()
def mock_gateway_client(monkeypatch):
    """Stub GatewayClient.validate_action with a pre-approved HMAC routing seal.

    Prevents unit tests from making real HTTP calls to the Hybrid Gateway when
    testing the ``tools/api.py`` execute_trade path.  The seal is generated
    using ``GOVERNANCE_SALT`` from the test environment so that
    ``verify_seal()`` in ``api.py`` accepts it without network access.

    Usage::

        async def test_execute_trade_approved(mock_gateway_client):
            # GatewayClient.validate_action is pre-stubbed — no real HTTP call.
            response = await client.post("/tools/execute", json={...})
            assert response.json()["status"] == "SUCCESS"
    """
    from src.gateway.governance.routing_seal import generate_seal
    from src.governed_financial_advisor.infrastructure import (
        gateway_client as gc_module,
    )

    async def _approved_validate_action(self, action: str, params, **kwargs):
        seal = generate_seal(action, params)
        return {
            "verdict": "APPROVED",
            "violations": [],
            "seal": seal,
            "latency_ms": 1.0,
        }

    monkeypatch.setattr(
        gc_module.GatewayClient,
        "validate_action",
        _approved_validate_action,
    )
    return _approved_validate_action


@pytest.fixture()
def mock_gateway_client_denied(monkeypatch):
    """Stub GatewayClient.validate_action to return a DENIED verdict.

    Use this fixture to test that the execute_trade branch correctly blocks
    actuation when the Gateway refuses the governance check.
    """
    from src.governed_financial_advisor.infrastructure import (
        gateway_client as gc_module,
    )

    async def _denied_validate_action(self, action: str, params, **kwargs):
        raise PermissionError(
            f"Governance DENIED '{action}': OPA: policy denied 'execute_trade'"
        )

    monkeypatch.setattr(
        gc_module.GatewayClient,
        "validate_action",
        _denied_validate_action,
    )
    return _denied_validate_action


@pytest.fixture(scope="session")
def backend_url() -> str:
    """Return the backend service URL (resolved from BACKEND_URL env var)."""
    return os.environ["BACKEND_URL"]


@pytest.fixture(scope="session")
def langfuse_client():
    """
    Return a configured Langfuse SDK client.

    Skips the requesting test if Langfuse credentials are not present in the
    environment.  Requires:

        LANGFUSE_PUBLIC_KEY
        LANGFUSE_SECRET_KEY
        LANGFUSE_HOST  (defaulted to http://localhost:3001 by pytest_configure)
    """
    public_key = os.environ.get("LANGFUSE_PUBLIC_KEY", "")
    secret_key = os.environ.get("LANGFUSE_SECRET_KEY", "")
    host = os.environ.get("LANGFUSE_HOST", "http://localhost:3001")

    if not public_key or not secret_key:
        pytest.skip(
            "Langfuse credentials not set — define LANGFUSE_PUBLIC_KEY and "
            "LANGFUSE_SECRET_KEY to run this test."
        )

    try:
        from langfuse import Langfuse  # type: ignore[import]
    except ImportError:
        pytest.skip("langfuse package is not installed.")

    return Langfuse(public_key=public_key, secret_key=secret_key, host=host)


@pytest.fixture(scope="session", autouse=True)
def requires_port_forward(pytestconfig, backend_url: str) -> None:
    """
    Session-scoped guard that verifies backend and Langfuse are reachable.

    Tests that depend on this fixture are skipped when the port-forwards are
    not running.  Start them with ``./setup_test_env.sh``.
    """
    if not pytestconfig.getoption("--run-integration"):
        return

    import base64
    import json
    import subprocess

    import bcrypt
    import redis
    import requests

    # Dynamic backend port detection/fallback
    current_backend = backend_url
    if current_backend == "http://localhost:18080":
        try:
            requests.get("http://localhost:18080/health", timeout=1)
        except requests.exceptions.RequestException:
            try:
                requests.get("http://localhost:8081/health", timeout=1)
                os.environ["BACKEND_URL"] = "http://localhost:8081"
                current_backend = "http://localhost:8081"
                print(
                    "\n🔄 [pytest bootstrap] Detected Backend at :8081 instead of :18080. Overriding BACKEND_URL."
                )
            except requests.exceptions.RequestException:
                pass

    langfuse_host = os.environ.get("LANGFUSE_HOST", "http://localhost:3001")
    skip_langfuse = os.environ.get("SKIP_LANGFUSE_CHECKS", "0").strip() in (
        "1",
        "true",
        "yes",
    )
    timeout = 3

    unreachable: list[str] = []

    # Always require Backend; Langfuse is optional when SKIP_LANGFUSE_CHECKS=1
    services_to_check = [("Backend", f"{current_backend}/health")]
    if not skip_langfuse:
        services_to_check.append(("Langfuse", langfuse_host))

    for label, url in services_to_check:
        try:
            requests.get(url, timeout=timeout)
        except requests.exceptions.RequestException:
            unreachable.append(f"{label} ({url})")

    if unreachable:
        pytest.skip(
            "Required services are not reachable — run ./setup_test_env.sh to "
            "start port-forwards.\n"
            "Unreachable: " + ", ".join(unreachable)
        )

    if skip_langfuse:
        print(
            "\n⚠️  [pytest bootstrap] SKIP_LANGFUSE_CHECKS=1 — Langfuse reachability check bypassed."
        )
        # Ensure SKIP_LANGFUSE_CHECKS is propagated so tests can skip Langfuse-dependent assertions
        os.environ["SKIP_LANGFUSE_CHECKS"] = "1"

    # ─── Issue 3: Pure Python Redis Seeding ───
    try:
        # Redis password sourced from REDIS_PASSWORD env var (set via setup_test_env.sh
        # or CI secrets — never hardcoded). Falls back to empty string (no-auth Redis).
        redis_password = os.environ.get("REDIS_PASSWORD", "")
        r = redis.Redis(
            host="localhost",
            port=6379,
            db=0,
            password=redis_password or None,
            socket_timeout=3,
        )
        r.set("safety:current_cash", "10000000")
        print(
            "\n💰 [pytest bootstrap] Seeded Redis cash balance to safety:current_cash = 10000000"
        )
    except Exception as e:
        print(
            f"\n⚠️ [pytest bootstrap] Redis seed failed (port-forward may not be active yet): {e}"
        )

    # ─── Issue 4: Langfuse Compliance Project & Key Bootstrap ───
    try:
        pk_comp = os.environ.get(
            "LANGFUSE_COMPLIANCE_PUBLIC_KEY", "REDACTED_LANGFUSE_COMPLIANCE_PK"
        )
        sk_comp = os.environ.get(
            "LANGFUSE_COMPLIANCE_SECRET_KEY", "REDACTED_LANGFUSE_COMPLIANCE_SK"
        )

        # 1. PostgreSQL DB Seeding via kubectl exec
        # Generate a fresh bcrypt hash of the secret key (11 rounds, matches Langfuse default)
        hashed_secret = bcrypt.hashpw(sk_comp.encode(), bcrypt.gensalt(11)).decode(
            "utf-8"
        )
        display_secret = "sk-lf-...3162"

        sql_script = f"""
        -- Ensure cage-compliance project exists
        INSERT INTO projects (id, name, org_id, created_at, updated_at, has_traces)
        VALUES ('cage-compliance', 'cage-compliance', 'CAGE', NOW(), NOW(), false)
        ON CONFLICT (id) DO NOTHING;

        -- Upsert compliance api key.
        -- fast_hashed_secret_key is intentionally NULL: Langfuse's apiAuth.ts lazily
        -- populates it via bcrypt fallback on the first successful authentication.
        INSERT INTO api_keys (id, note, public_key, hashed_secret_key, display_secret_key, project_id, fast_hashed_secret_key, scope)
        VALUES (
          'cmpa7dkag0001zt07e609comp',
          'Provisioned Compliance Key',
          '{pk_comp}',
          '{hashed_secret}',
          '{display_secret}',
          'cage-compliance',
          NULL,
          'PROJECT'::"ApiKeyScope"
        )
        ON CONFLICT (public_key) DO UPDATE SET
          hashed_secret_key     = EXCLUDED.hashed_secret_key,
          fast_hashed_secret_key = NULL;
        """

        print(
            "🗄️ [pytest bootstrap] Seeding Langfuse compliance project in GKE PostgreSQL..."
        )
        pg_password = os.environ.get("PGPASSWORD", "")
        env_vars = f"PGPASSWORD={pg_password}"
        subprocess.run(
            [
                "kubectl",
                "exec",
                "-i",
                "postgresql-0",
                "-n",
                "governance-stack",
                "--",
                "sh",
                "-c",
                f"env {env_vars} psql -U langfuse -d langfuse",
            ],
            input=sql_script,
            text=True,
            check=True,
            capture_output=True,
        )
        print(
            "✅ [pytest bootstrap] GKE PostgreSQL Langfuse compliance project and keys seeded successfully."
        )

        # 2. Update Kubernetes Secret if out of date
        try:
            res = subprocess.run(
                [
                    "kubectl",
                    "get",
                    "secret",
                    "langfuse-compliance-secrets",
                    "-n",
                    "governance-stack",
                    "-o",
                    "json",
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            secret_data = json.loads(res.stdout).get("data", {})
            existing_pub = base64.b64decode(secret_data.get("public-key", "")).decode(
                "utf-8"
            )
        except Exception:
            secret_data = {}
            existing_pub = None

        if existing_pub != pk_comp:
            print(
                f"🔄 [pytest bootstrap] Langfuse compliance secret out-of-date ({existing_pub}). Updating secret..."
            )
            secret_manifest = {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {
                    "name": "langfuse-compliance-secrets",
                    "namespace": "governance-stack",
                },
                "type": "Opaque",
                "data": {
                    "LANGFUSE_COMPLIANCE_PUBLIC_KEY": base64.b64encode(
                        pk_comp.encode()
                    ).decode(),
                    "LANGFUSE_COMPLIANCE_SECRET_KEY": base64.b64encode(
                        sk_comp.encode()
                    ).decode(),
                    "LANGFUSE_HOST": base64.b64encode(
                        b"http://langfuse-web.governance-stack.svc.cluster.local"
                    ).decode(),
                    "public-key": base64.b64encode(pk_comp.encode()).decode(),
                    "secret-key": base64.b64encode(sk_comp.encode()).decode(),
                },
            }
            subprocess.run(
                ["kubectl", "apply", "-f", "-"],
                input=json.dumps(secret_manifest),
                text=True,
                check=True,
                capture_output=True,
            )
            print("✅ [pytest bootstrap] Langfuse compliance secret updated.")

            # Trigger Rollout Restart for compliance-bridge
            print(
                "🔄 [pytest bootstrap] Triggering rollout restart of deployment/compliance-bridge..."
            )
            subprocess.run(
                [
                    "kubectl",
                    "rollout",
                    "restart",
                    "deployment/compliance-bridge",
                    "-n",
                    "governance-stack",
                ],
                check=True,
                capture_output=True,
            )
            print("⏳ [pytest bootstrap] Waiting for rollout restart to complete...")
            subprocess.run(
                [
                    "kubectl",
                    "rollout",
                    "status",
                    "deployment/compliance-bridge",
                    "-n",
                    "governance-stack",
                    "--timeout=120s",
                ],
                check=True,
                capture_output=True,
            )
            print(
                "✅ [pytest bootstrap] compliance-bridge deployment successfully restarted and ready."
            )
        else:
            print(
                "✅ [pytest bootstrap] Langfuse compliance secret is already up-to-date in GKE."
            )

        # 3. Inject keys into os.environ for integration tests
        # Keys are sourced from env vars (set via setup_test_env.sh or CI secrets).
        # LANGFUSE_PUBLIC_KEY / LANGFUSE_SECRET_KEY must be set before running
        # integration tests — see .env.example for the required variable names.
        if not os.environ.get("LANGFUSE_PUBLIC_KEY"):
            print(
                "\n⚠️ [pytest bootstrap] LANGFUSE_PUBLIC_KEY not set — Langfuse integration tests will be skipped."
            )
        if not os.environ.get("LANGFUSE_SECRET_KEY"):
            print(
                "\n⚠️ [pytest bootstrap] LANGFUSE_SECRET_KEY not set — Langfuse integration tests will be skipped."
            )
        os.environ["LANGFUSE_COMPLIANCE_PUBLIC_KEY"] = pk_comp
        os.environ["LANGFUSE_COMPLIANCE_SECRET_KEY"] = sk_comp
        os.environ["SKIP_LANGFUSE_CHECKS"] = "0"
        print(
            "🚀 [pytest bootstrap] Set LANGFUSE_COMPLIANCE_* env vars and set SKIP_LANGFUSE_CHECKS=0."
        )

    except Exception as e:
        print(f"\n⚠️ [pytest bootstrap] Langfuse compliance bootstrapping failed: {e}")


@pytest.fixture(scope="session", autouse=True)
def assert_formal_tier_ordering_matches():
    """
    Session-scoped fixture asserting the registered tier order matches the formal model.
    See Formal Proof Synchronization.
    """
    from src.gateway.governance.plugin_loader import discover_plugins
    from src.gateway.governance.singletons import symbolic_governor

    # Ensure plugins are loaded
    loaded_plugins = discover_plugins()
    for plugin in loaded_plugins:
        plugin.register(governor=symbolic_governor, tool_server=None)

    tiers = symbolic_governor.registered_tier_names()
    # The formal model mandates the following order for finance package tiers
    expected = ["consensus_tier", "causal_tier", "cbf_tier", "fiscal_tier"]
    if all(t in tiers for t in expected):
        actual = [t for t in tiers if t in expected]
        assert actual == expected, (
            f"Tier order mismatch! Expected {expected}, got {actual}"
        )

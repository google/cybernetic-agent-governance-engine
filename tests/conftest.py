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

  1. Shell environment (``export VAR=...``, CI secrets, or
     ``uv run --env-file <file>``)
  2. Hard-coded defaults set in ``pytest_configure`` below

No ``.env`` file is read. A hermetic session refuses to start while one can
reach it, because litellm loads it at import (``tests/fixtures/dotenv_guard.py``).

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
os.environ.setdefault("CAGE_DOMAIN", "finance")

os.environ.setdefault(
    "GOVERNANCE_SALT", "dev-only-insecure-placeholder-not-for-production-use"
)
# Import-time default only; pytest_configure pins the session region
# (tests/fixtures/deployment_region.py) before any test runs. The shell's own
# value is kept so a live run can refuse an export that contradicts the
# deployment.
_EXPORTED_REGION = os.environ.get("CAGE_DEPLOYMENT_REGION")
os.environ.setdefault("CAGE_DEPLOYMENT_REGION", "US_FED")
os.environ.setdefault("LANGFUSE_POSTURE_DRY_RUN", "true")
os.environ.setdefault(
    "CMEK_KEY_RESOURCE_NAME",
    "projects/test-project/locations/us-central1/keyRings/test-keyring/cryptoKeys/test-key/cryptoKeyVersions/1",
)
os.environ.setdefault(
    "CAGE_TRUSTED_CLIENT_IDENTITIES",
    "cage-advisor-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local",
)

import pytest

from tests.fixtures.deployment_region import REGION_MARKERS
from tests.fixtures.dotenv_guard import (
    LIVE_RUN_OPTIONS,
    reachable_dotenv_files,
    refusal,
    search_starts,
)
from tests.fixtures.selection_flags import applied_marker_names

os.environ.setdefault("LANGCHAIN_TRACING_V2", "false")
os.environ.setdefault("LANGSMITH_TRACING", "false")
os.environ.setdefault("OBJC_DISABLE_INITIALIZE_FORK_SAFETY", "YES")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
os.environ.setdefault("EVIDENCE_STREAM_ENABLED", "true")

# ── KMS key requirement for staging/production integration tests ─────────────
# If CAGE_ENV is staging/production and KMS_GOVERNANCE_KEY is not set, fail now
# with a clear message, rather than later in the startup posture check / KMS
# signer during integration tests.
if os.environ.get("CAGE_ENV", "test").lower() not in (
    "development",
    "test",
    "dev",
    "ci",
):
    if not os.environ.get("KMS_GOVERNANCE_KEY"):
        raise RuntimeError(
            f"[TEST CONFIG] CAGE_ENV={os.environ.get('CAGE_ENV')} requires KMS_GOVERNANCE_KEY. "
            "Export it, or pass it with `uv run --env-file <file>`; tests never read .env. "
            "For local testing without KMS, set CAGE_ENV=test."
        )

# Sanitize cluster-internal Kubernetes DNS URLs that cannot be resolved outside GKE
_cluster_internal_replacements = {
    "BACKEND_URL": "http://localhost:18080",
    "GATEWAY_URL": "http://localhost:8080",
    "LANGFUSE_HOST": "http://localhost:3001",
    "LANGFUSE_BASEURL": "http://localhost:3001",
    "COMPLIANCE_BRIDGE_URL": "http://localhost:3002",
    "OPA_URL": "http://localhost:8181",
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
    # Before anything else: no .env file may reach a hermetic session.
    _refuse_reachable_dotenv(config)

    # One region for the whole session: US_FED for hermetic runs, the
    # deployment's ConfigMap value for live runs (fails closed on mismatch).
    _region = _pin_session_region(config)
    _region_locations = {
        "US_FED": "us-central1",
        "EU_ECB": "europe-west1",
        "APAC_MAS": "asia-southeast1",
    }
    os.environ["GOOGLE_CLOUD_LOCATION"] = _region_locations[_region]

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
    # The shell may export the cluster-internal address (http://opa:8181),
    # which is unreachable from the developer workstation — always override to localhost.
    # OPA_URL is a base URL; the decision package comes from the active
    # domain's DomainConfig.opa_package.
    _setdefault(
        "OPA_URL",
        os.environ.get("OPA_URL_TEST_OVERRIDE", "http://localhost:8181"),
    )
    # GOVERNANCE_SALT must be consistent so routing seals issued during tests
    # can be verified by both the gateway module and the GFA mirror module.
    _setdefault("GOVERNANCE_SALT", "CYBERNETIC_GOVERNANCE_TEST_SALT_32C!")
    # CAGE_ENV must be set to "test" to enable HMAC fallback in routing_seal
    # and kms_signer when KMS_GOVERNANCE_KEY is not configured.
    _setdefault("CAGE_ENV", "test")
    _setdefault(
        "CAGE_TRUSTED_CLIENT_IDENTITIES",
        "cage-advisor-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local",
    )

    # For integration tests against staging/production with real KMS, preserve KMS credentials
    # Only remove KMS credentials for unit tests (when CAGE_ENV=test and not running integration tests)
    _is_integration_run = config.getoption("--run-integration", default=False)
    _cage_env = os.environ.get("CAGE_ENV", "test").lower()
    _needs_real_kms = _is_integration_run and _cage_env not in (
        "test",
        "dev",
        "development",
        "ci",
    )

    if not _needs_real_kms:
        # Remove KMS credentials to force HMAC fallback mode for unit tests
        os.environ.pop("KMS_GOVERNANCE_KEY", None)
        os.environ.pop("KMS_GOVERNANCE_PUBLIC_PEM", None)
        # Reset KMS signer singleton to ensure HMAC fallback mode is used
        try:
            from src.gateway.governance.kms_signer import reset_governance_signer

            reset_governance_signer()
        except ImportError:
            pass  # Module not yet importable during early configuration

    # EVIDENCE_STREAM_ENABLED default true to satisfy EVIDENCE_CHAIN_BLOCKING precondition in tests
    _setdefault("EVIDENCE_STREAM_ENABLED", "true")

    # For integration runs, unmask skip reasons in terminal summary (reportchars += 's')
    # so skipped tests are never silent or mistaken for bugs.
    if _is_integration_run:
        try:
            current_chars = getattr(config.option, "reportchars", "") or ""
            if "s" not in current_chars and "a" not in current_chars:
                config.option.reportchars = current_chars + "s"
        except Exception:
            pass


def _refuse_reachable_dotenv(config: pytest.Config) -> None:
    """Refuse a hermetic session that a ``.env`` file can reach (``dotenv_guard``)."""
    live_run = any(
        config.getoption(option, default=False) for option in LIVE_RUN_OPTIONS
    )
    reason = refusal(reachable_dotenv_files(search_starts()), live_run=live_run)
    if reason is not None:
        raise pytest.UsageError(reason)


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


# ── ControlRegistry region isolation ───────────────────────────────────────────

_SESSION_REGION = pytest.StashKey[str]()


def _pin_session_region(config: pytest.Config) -> str:
    """Resolve the session region once (controller) and export it.

    xdist workers inherit the controller's environment, so they reuse the
    exported value rather than querying the cluster again.
    """
    from src.gateway.governance.constants import ControlRegistry
    from tests.fixtures.deployment_region import (
        DEFAULT_NAMESPACE,
        REGION_ENV_VAR,
        DeploymentRegionError,
        is_live_run,
        resolve_session_region,
    )

    if hasattr(config, "workerinput"):
        region = os.environ[REGION_ENV_VAR]
    else:
        try:
            region = resolve_session_region(
                live=is_live_run(config),
                namespace=config.getoption("--cage-namespace") or DEFAULT_NAMESPACE,
                env_region=_EXPORTED_REGION,
            )
        except DeploymentRegionError as exc:
            raise pytest.UsageError(f"Deployment region: {exc}") from exc
    os.environ[REGION_ENV_VAR] = region
    config.stash[_SESSION_REGION] = region
    # A registry loaded at import time may hold the shell's region.
    if ControlRegistry._instance is not None:
        ControlRegistry.reconfigure(region)
    return region


@pytest.fixture(autouse=True)
def control_registry_region(request: pytest.FixtureRequest, monkeypatch):
    """Run each test under its region and undo any region change afterwards.

    A hermetic test marked ``us_fed`` / ``eu_ecb`` / ``apac_mas`` runs under
    that region (env + ``ControlRegistry``); everything else runs under the
    session region. The active region selects the jurisdiction contribution at
    governor assembly (``resolve_jurisdiction``): a registry left on
    ``EU_ECB`` would give every later governor on this worker the ``fria``
    tier, so the prior state is always restored.
    """
    from src.gateway.governance.constants import ControlRegistry
    from tests.fixtures.deployment_region import REGION_ENV_VAR, region_pin

    # Class attribute: reading it never instantiates (loads) the singleton.
    was_loaded = ControlRegistry._instance is not None
    region = ControlRegistry._active_region
    pinned = region_pin(request.node)
    if pinned is not None:
        monkeypatch.setenv(REGION_ENV_VAR, pinned)
        if was_loaded:
            ControlRegistry.reconfigure(pinned)
        _pin_thresholds_region(monkeypatch, pinned)
    yield
    if ControlRegistry._instance is not None:
        if not was_loaded:
            ControlRegistry.reset_for_testing()
        elif ControlRegistry._active_region != region:
            ControlRegistry.reconfigure(region)


@pytest.fixture(params=sorted(REGION_MARKERS.values()))
def each_region(request: pytest.FixtureRequest, monkeypatch) -> str:
    """Parametrize a hermetic test over every jurisdiction region.

    For cross-region invariants. The region is applied to the environment and
    ``ControlRegistry``; ``control_registry_region`` restores the prior state.
    ``tests/test_deployment_region.py`` keeps ``REGION_MARKERS`` equal to
    ``JURISDICTIONS``.
    """
    from src.gateway.governance.constants import ControlRegistry
    from tests.fixtures.deployment_region import REGION_ENV_VAR

    region: str = request.param
    monkeypatch.setenv(REGION_ENV_VAR, region)
    ControlRegistry.reconfigure(region)
    _pin_thresholds_region(monkeypatch, region)
    return region


def _pin_thresholds_region(monkeypatch: pytest.MonkeyPatch, region: str) -> None:
    """Swap in the region's effective thresholds for the duration of a test.

    ``THRESHOLDS`` is resolved once per process (the session region); governor
    assembly refuses a jurisdiction whose region differs from it, so a test
    pinned to another region needs that region's thresholds. Modules that bound
    ``THRESHOLDS`` at import keep the session values.
    """
    from src.gateway.governance.schemas import thresholds as thresholds_module

    monkeypatch.setattr(
        thresholds_module,
        "THRESHOLDS",
        thresholds_module.load_and_validate_thresholds(region=region),
    )


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
        "--run-partner-integration",
        action="store_true",
        default=False,
        help="Run partner integration tests marked with @pytest.mark.partner_integration (hit external partner APIs).",
    )
    parser.addoption(
        "--run-chaos",
        action="store_true",
        default=False,
        help="Run chaos tests (Redis failover scenarios). Skipped by default.",
    )
    parser.addoption(
        "--run-e2e",
        action="store_true",
        default=False,
        help="Run live end-to-end tests marked with @pytest.mark.e2e (require a deployed gateway).",
    )
    parser.addoption(
        "--cage-namespace",
        default=os.environ.get("K8S_NAMESPACE", "governance-stack"),
        help=(
            "Namespace of the CAGE deployment under test. Live runs "
            "(--run-integration / --run-e2e) read the session region from its "
            "cage-deployment ConfigMap."
        ),
    )
    parser.addoption(
        "--regen-golden",
        action="store_true",
        default=False,
        help="Regenerate golden expected outcomes in tests/governor/golden/expected.json.",
    )


# ── Selection-marker contract ─────────────────────────────────────────────────
# Every collected test MUST carry at least one of these markers.  CI selects tests
# by marker expression (`-m "local or unit"`, `-m integration`, ...), so a test
# without one of these is collected locally but silently excluded from every gate.
#
# This mirrors CAGE's fail-closed posture (AGENTS.md § FTRA): an unclassified
# *action* is rejected rather than admitted, and likewise an unclassified *test*
# aborts collection rather than disappearing from the gate.
#
# Additive facet markers (`slow`, `regression`, `red_team`, `layer_isolation`,
# `financial`, `healthcare`, `us_fed`, `eu_ecb`, `apac_mas`) deliberately do NOT
# appear here: they qualify a test, they do not make it selectable by a CI gate.
SELECTION_MARKERS: frozenset[str] = frozenset(
    {
        "unit",
        "local",
        "integration",
        "load",
        "chaos",
        "live_external",
        "partner_integration",
        "e2e",
    }
)

# Modules exempted from the selection-marker contract.  Ships EMPTY by design.
# Prefer excluding a non-test helper from collection over adding it here; every
# entry must carry an inline comment naming the reason it cannot be marked.
MARKER_GUARD_EXEMPT_MODULES: frozenset[str] = frozenset()


def _assert_selection_markers(items: list[pytest.Item]) -> None:
    """Abort the run if any collected test lacks a selection marker (fail-closed)."""
    offenders: dict[str, list[str]] = {}
    for item in items:
        module_path = str(item.nodeid).split("::", 1)[0]
        if module_path in MARKER_GUARD_EXEMPT_MODULES:
            continue
        if SELECTION_MARKERS & applied_marker_names(item):
            continue
        offenders.setdefault(module_path, []).append(item.name)

    if not offenders:
        return

    total = sum(len(names) for names in offenders.values())
    lines = [
        "",
        "=" * 78,
        "PYTEST MARKER CONTRACT VIOLATION (fail-closed)",
        "=" * 78,
        f"{total} test(s) across {len(offenders)} module(s) carry no selection marker.",
        "",
        "CI selects tests by marker expression, so these tests would be collected",
        "locally but silently EXCLUDED from every CI gate.",
        "",
        "Offending modules:",
    ]
    for module_path in sorted(offenders):
        names = offenders[module_path]
        preview = ", ".join(names[:3]) + (" ..." if len(names) > 3 else "")
        lines.append(f"  - {module_path}  ({len(names)} test(s): {preview})")
    lines += [
        "",
        "Fix: add a module-level marker after the import block, e.g.",
        "",
        "    pytestmark = [pytest.mark.unit, pytest.mark.local]",
        "",
        f"Valid selection markers: {', '.join(sorted(SELECTION_MARKERS))}",
        "See tests/README.md § Pytest Markers for the unit-vs-local distinction.",
        "=" * 78,
    ]
    raise pytest.UsageError("\n".join(lines))


_LIVE_SUITE_MARKER_FLAGS: tuple[tuple[str, str], ...] = (
    ("integration", "--run-integration"),
    ("live_external", "--run-live-external"),
    ("partner_integration", "--run-partner-integration"),
    ("e2e", "--run-e2e"),
    ("chaos", "--run-chaos"),
)
_AUTOSKIPPED_LIVE_COUNTS = pytest.StashKey[dict[str, int]]()
_DESELECTED_LIVE_COUNTS = pytest.StashKey[dict[str, int]]()


def format_unexecuted_live_suites_notice(
    autoskipped: dict[str, int],
    deselected: dict[str, int],
) -> list[str]:
    """Build terminal notice lines for opt-in live suites omitted from the session."""
    lines: list[str] = []
    for marker_name, cli_flag in _LIVE_SUITE_MARKER_FLAGS:
        skipped_n = int(autoskipped.get(marker_name, 0))
        deselected_n = int(deselected.get(marker_name, 0))
        if skipped_n <= 0 and deselected_n <= 0:
            continue
        parts: list[str] = []
        if skipped_n > 0:
            parts.append(f"{skipped_n} auto-skipped")
        if deselected_n > 0:
            parts.append(f"{deselected_n} deselected")
        detail = ", ".join(parts)
        lines.append(
            f"  [NOT EXECUTED] @{marker_name}: {detail} — pass {cli_flag} against a live target to execute"
        )
    return lines


def pytest_deselected(items: list[pytest.Item]) -> None:
    """Track opt-in live suites excluded by `-m` / `-k` selection so omission is visible."""
    if not items:
        return
    config = items[0].config
    deselected = config.stash.setdefault(_DESELECTED_LIVE_COUNTS, {})
    for item in items:
        marks = applied_marker_names(item)
        for marker_name, _cli_flag in _LIVE_SUITE_MARKER_FLAGS:
            if marker_name in marks:
                deselected[marker_name] = deselected.get(marker_name, 0) + 1


def pytest_terminal_summary(
    terminalreporter: pytest.TerminalReporter,
    exitstatus: int,
    config: pytest.Config,
) -> None:
    """Emit a controller-only summary whenever opt-in live suites were omitted."""
    del exitstatus
    if hasattr(config, "workerinput"):
        return
    lines = format_unexecuted_live_suites_notice(
        config.stash.get(_AUTOSKIPPED_LIVE_COUNTS, {}),
        config.stash.get(_DESELECTED_LIVE_COUNTS, {}),
    )
    if not lines:
        return
    terminalreporter.section("live / opt-in suites not executed", sep="-")
    for line in lines:
        terminalreporter.write_line(line)


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Enforce the selection-marker contract, then auto-skip opt-in test classes.

    Live (integration / e2e) tests marked for a region other than the deployed
    one are skipped; hermetic region-marked tests are pinned to their region by
    the ``control_registry_region`` fixture instead.
    """
    # Fail-closed guard runs FIRST: an unmarked item must not be maskable by a
    # skip marker applied later in this same hook.
    _assert_selection_markers(items)

    run_integration = config.getoption("--run-integration")
    run_live_external = config.getoption("--run-live-external")
    run_partner_integration = config.getoption("--run-partner-integration")
    run_chaos = config.getoption("--run-chaos")
    run_e2e = config.getoption("--run-e2e")

    skip_integration = pytest.mark.skip(
        reason=(
            "Integration test — requires live external services. "
            "Pass --run-integration to enable (or run 'make test-mesh' for Linkerd mesh conformance)."
        )
    )
    skip_live_external = pytest.mark.skip(
        reason=(
            "Live external test — hits partner APIs. "
            "Pass --run-live-external to enable."
        )
    )
    skip_partner_integration = pytest.mark.skip(
        reason=(
            "Partner integration test — hits third-party partner APIs. "
            "Pass --run-partner-integration or --run-live-external to enable."
        )
    )
    skip_chaos = pytest.mark.skip(
        reason=("Chaos test — Redis failover scenarios. Pass --run-chaos to enable.")
    )
    skip_e2e = pytest.mark.skip(
        reason="Live e2e test — requires a deployed gateway. Pass --run-e2e to enable."
    )

    from tests.fixtures.deployment_region import live_region_mismatch, marked_region
    from tests.fixtures.selection_flags import live_external_enabled

    session_region = config.stash[_SESSION_REGION]
    autoskipped = config.stash.setdefault(_AUTOSKIPPED_LIVE_COUNTS, {})

    for item in items:
        marked_region(item)  # fail closed on ambiguous region markers
        if (reason := live_region_mismatch(item, session_region)) is not None:
            item.add_marker(pytest.mark.skip(reason=reason))
        # Applied markers only: a directory such as tests/integration/ must not
        # skip the hermetic (unit/local) tests it holds.
        marks = applied_marker_names(item)
        if "integration" in marks and not run_integration:
            item.add_marker(skip_integration)
            autoskipped["integration"] = autoskipped.get("integration", 0) + 1
        if "live_external" in marks and not live_external_enabled(
            marks,
            run_live_external=run_live_external,
            run_partner_integration=run_partner_integration,
        ):
            item.add_marker(skip_live_external)
            autoskipped["live_external"] = autoskipped.get("live_external", 0) + 1
        if "partner_integration" in marks and not (
            run_partner_integration or run_live_external
        ):
            item.add_marker(skip_partner_integration)
            autoskipped["partner_integration"] = (
                autoskipped.get("partner_integration", 0) + 1
            )
        if "chaos" in marks and not run_chaos:
            item.add_marker(skip_chaos)
            autoskipped["chaos"] = autoskipped.get("chaos", 0) + 1
        if "e2e" in marks and not run_e2e:
            item.add_marker(skip_e2e)
            autoskipped["e2e"] = autoskipped.get("e2e", 0) + 1


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
        seal = await generate_seal(action, params)
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
    if os.environ.get("SKIP_PORT_FORWARD_CHECKS", "0").strip().lower() in (
        "1",
        "true",
        "yes",
    ):
        return
    args = [str(a) for a in pytestconfig.args]
    if args and all("test_linkerd_mesh_conformance" in a for a in args):
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

    unreachable: list[str] = []

    # Always require Backend; Langfuse is optional when SKIP_LANGFUSE_CHECKS=1
    services_to_check = [("Backend", f"{current_backend}/health")]
    if not skip_langfuse:
        services_to_check.append(("Langfuse", langfuse_host))

    for label, url in services_to_check:
        try:
            requests.get(url, timeout=3)
        except requests.exceptions.RequestException:
            unreachable.append(f"{label} ({url})")

    if unreachable:
        pytest.skip(
            "Required services are not reachable — run ./setup_test_env.sh to start port-forwards.\n"
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
        if not redis_password:
            try:
                secret_out = subprocess.check_output(
                    [
                        "kubectl",
                        "get",
                        "secret",
                        "redis",
                        "-n",
                        "governance-stack",
                        "-o",
                        "jsonpath={.data.redis-password}",
                    ],
                    text=True,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                )
                if secret_out:
                    redis_password = base64.b64decode(secret_out.strip()).decode()
                    os.environ["REDIS_PASSWORD"] = redis_password
            except Exception:
                pass
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

        # Check if in-cluster postgresql-0 exists (legacy StatefulSet) vs Cloud SQL (Track 6c)
        has_incluster_pg = (
            subprocess.run(
                [
                    "kubectl",
                    "get",
                    "pod",
                    "postgresql-0",
                    "-n",
                    "governance-stack",
                ],
                capture_output=True,
                timeout=5,
            ).returncode
            == 0
        )

        if has_incluster_pg:
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
            if not pg_password:
                try:
                    secret_out = subprocess.check_output(
                        [
                            "kubectl",
                            "get",
                            "secret",
                            "postgresql",
                            "-n",
                            "governance-stack",
                            "-o",
                            "jsonpath={.data.password}",
                        ],
                        text=True,
                        stderr=subprocess.DEVNULL,
                        timeout=5,
                    )
                    if secret_out:
                        pg_password = base64.b64decode(secret_out.strip()).decode()
                except Exception:
                    pass
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
        else:
            # Cloud SQL posture: module.langfuse_stack seeds the isolated
            # cage-compliance project and API keys at pod startup. Never copy
            # operational LANGFUSE_PUBLIC_KEY / LANGFUSE_SECRET_KEY into
            # LANGFUSE_COMPLIANCE_* or mutate Secret/langfuse-compliance-secrets
            # out-of-band (which collapses POAM-018 / POAM-019 isolation and
            # introduces Terraform configuration drift).
            print(
                "✅ [pytest bootstrap] Cloud SQL posture: preserving isolated LANGFUSE_COMPLIANCE_* credentials."
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
    Session-scoped fixture asserting the assembled tier order matches the formal model.
    See Formal Proof Synchronization.
    """
    from src.gateway.governance.env_posture import DeploymentPosture
    from src.gateway.governance.governor.assembly import assemble_governor
    from src.gateway.governance.plugin_loader import load_domain_plugin
    from tests.fixtures.governor import allow_opa, clean_stpa

    plugin = load_domain_plugin()
    governor = assemble_governor(
        [plugin],
        posture=DeploymentPosture.DEV,
        opa=allow_opa(),
        stpa_validator=clean_stpa(),
    )
    # Production registers the domain's compliance overlays in bootstrap_governor();
    # do the same once per session so the domain's own controls resolve.
    from src.gateway.governance.constants import register_overlay_dir

    for contribution in governor.components.contributions:
        for overlay_dir in contribution.compliance_overlay_dirs:
            register_overlay_dir(overlay_dir)

    tiers = governor.registered_tier_names()
    if plugin.name == "finance":
        # The formal model mandates this relative order for the finance tiers.
        expected = (
            ["consensus", "causal", "cbf", "fiscal"]
            if "causal" in tiers
            else ["consensus", "cbf", "fiscal"]
        )
        actual = [t for t in tiers if t in expected]
        assert actual == expected, (
            f"Tier order mismatch! Expected {expected}, got {actual}"
        )


# ── W1/W3 Post-v3 Remediation: Register fixture modules ───────────────────────

pytest_plugins = [
    "tests.fixtures.cbf",
]


@pytest.fixture()
def governor_factory():
    """Build a ``SymbolicGovernor`` from explicit parts (see ``tests.fixtures.governor``).

    Replaces patching a process-wide governor: tests construct the governor
    they need and pass it to the code under test.
    """
    from tests.fixtures.governor import make_governor

    return make_governor


# ── Classification Engine & Narrower Registry Fixtures ───────────────────────


@pytest.fixture()
def narrower_registry():
    """Provide a NarrowerRegistry instance for testing."""
    from src.gateway.governance.narrower import NarrowerRegistry

    return NarrowerRegistry()


@pytest.fixture()
def classification_engine(narrower_registry):
    """Provide a ClassificationEngine instance for testing."""
    from src.gateway.governance.classification_engine import ClassificationEngine

    return ClassificationEngine(
        narrower_registry=narrower_registry,
        confidence_threshold=0.70,
        defer_enabled=True,
        narrow_enabled=False,
    )


@pytest.fixture()
def connected_evidence_sink(monkeypatch: pytest.MonkeyPatch):
    """Attach an isolated FakeRedis-backed EvidenceStreamSink for hermetic unit tests."""
    import fakeredis.aioredis

    import src.gateway.governance.evidence.stream as es

    sink = es.EvidenceStreamSink()
    sink._redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    sink._running = True
    monkeypatch.setattr(es, "_evidence_sink", sink)
    try:
        yield sink
    finally:
        sink._stopping = True
        sink._running = False
        task = sink._appender_task
        if task is not None and not task.done():
            try:
                task.get_loop().call_soon_threadsafe(task.cancel)
            except RuntimeError:
                pass
        sink._redis = None

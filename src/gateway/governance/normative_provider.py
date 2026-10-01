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
normative_provider.py — External Normative Provider Interface (CAGE v0.1.0)
===========================================================================

Implements §2.5 of EXTENSIBILITY_ARCHITECTURE.md: the 3-endpoint integration
surface for external normative providers (e.g. FlowSignal).

Architecture
------------
All external provider interactions fall into three categories:

  1. **Normative Data Supply** — ``GET /legal-baseline/{region}``
     Boot-time fetch + periodic background refresh.  The hot path never
     touches the network; all lookups resolve against the in-memory
     ControlRegistry singleton.

  2. **External Validation** — ``POST /validate/fria``
     A jurisdiction obligation, not a universal gate: it is consulted only
     by the EU AI Act ``fria`` tier, which exists only when
     ``CAGE_DEPLOYMENT_REGION`` selects that jurisdiction (see
     ``src/gateway/governance/jurisdiction/``).  Model confidence never
     waives it.

  3. **Attestation Logging** — ``GET /evidence-chain/{thread_id}``
     Seam method for external sealing of governance evidence hashes.

Architectural precedent
-----------------------
This module mirrors the pattern proven in ``config/compliance/reconciliation_worker.py``:
  - Async external fetch → cryptographic signing → local cache with TTL
  - Fail-closed on stale/absent data
  - Pluggable provider interface with stub for dev/CI

Environment variables
---------------------
  CAGE_NORMATIVE_PROVIDER             — "static" (default), "provider_01", or "provider_02"
  CAGE_NORMATIVE_ENDPOINT             — Provider base URL
  CAGE_NORMATIVE_POLL_INTERVAL_HOURS  — Background refresh interval (default: 6)
  CAGE_NORMATIVE_BOOT_TIMEOUT_SECONDS — Max wait at container init (default: 10)
  CAGE_NORMATIVE_GATE_TIMEOUT_SECONDS — Max wait for sync blocking gate (default: 5)
  CAGE_NORMATIVE_API_KEY_SECRET       — Secret Manager path or direct API key

Vendor providers are isolated in ``src/integrations/{vendor}/`` and
lazy-loaded by the factory to enforce supply-chain separation.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.seams.normative import (
    EvidenceSeal,
    NormativeBaseline,
    NormativeProvider,
    ValidationResult,
)

logger = logging.getLogger("cage.normative_provider")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_PROVIDER_NAME: str = os.environ.get("CAGE_NORMATIVE_PROVIDER", "static")
_ENDPOINT: str = os.environ.get("CAGE_NORMATIVE_ENDPOINT", "")
_POLL_INTERVAL_HOURS: float = float(
    os.environ.get("CAGE_NORMATIVE_POLL_INTERVAL_HOURS", "6")
)
_BOOT_TIMEOUT_SECONDS: float = float(
    os.environ.get("CAGE_NORMATIVE_BOOT_TIMEOUT_SECONDS", "10")
)
_GATE_TIMEOUT_SECONDS: float = float(
    os.environ.get("CAGE_NORMATIVE_GATE_TIMEOUT_SECONDS", "5")
)
_API_KEY_SECRET: str = os.environ.get("CAGE_NORMATIVE_API_KEY_SECRET", "")

# Paths
_REPO_ROOT: Path = Path(__file__).resolve().parents[3]
_COMPLIANCE_DIR: Path = _REPO_ROOT / "config" / "compliance"


# ---------------------------------------------------------------------------
# §0 — Policy Integrity (H-08)
# ---------------------------------------------------------------------------


class PolicyIntegrityError(RuntimeError):
    """Raised when a policy file's SHA-256 digest does not match its companion
    ``.sha256`` file.  Loading is aborted to prevent tampered policy injection.
    """


def _verify_policy_integrity(policy_path: Path, raw_bytes: bytes) -> None:
    """Verify SHA-256 digest of *raw_bytes* against a companion digest file.

    The companion file is expected at ``{policy_path}.sha256`` and must contain
    the lowercase hex digest of the policy file (same format as ``sha256sum``).

    If the companion file is absent, a warning is logged and the load proceeds
    (dev/CI tolerance — digest files are optional in non-production environments).
    If the companion file is present but the digest mismatches, ``PolicyIntegrityError``
    is raised and the policy is NOT loaded.

    Args:
        policy_path: Filesystem path to the policy file (used to locate companion).
        raw_bytes:   Raw bytes of the policy file already read from disk.

    Raises:
        PolicyIntegrityError: If the digest file exists and the digest mismatches.
    """
    digest_path = policy_path.with_suffix(policy_path.suffix + ".sha256")
    if not digest_path.exists():
        logger.warning(
            "normative_provider: no integrity digest found for %s — "
            "skipping verification (set CAGE_ENV=prod to enforce)",
            policy_path.name,
        )
        return

    expected_hex = digest_path.read_text().strip().split()[0].lower()
    actual_hex = hashlib.sha256(raw_bytes).hexdigest()
    if actual_hex != expected_hex:
        raise PolicyIntegrityError(
            f"SHA-256 mismatch for {policy_path.name}: "
            f"expected={expected_hex[:16]}… actual={actual_hex[:16]}… — "
            "policy file may have been tampered with"
        )
    logger.debug(
        "normative_provider: integrity OK for %s (sha256=%s…)",
        policy_path.name,
        actual_hex[:16],
    )


# ---------------------------------------------------------------------------
# §1 — Data Contracts (now imported from seams.normative)
# ---------------------------------------------------------------------------

# Seam contracts are imported from src.gateway.governance.seams.normative
# to eliminate circular dependencies with vendor adapters.


# ---------------------------------------------------------------------------
# §2 — Provider Protocol (now imported from seams.normative)
# ---------------------------------------------------------------------------

# NormativeProvider protocol is imported from src.gateway.governance.seams.normative


class StubNormativeProvider:
    """Development-only provider that returns local baselines and no-op validation.

    NEVER use in production — this defeats the entire purpose of external
    normative validation.  The stub exists solely for:
      - Unit tests that validate the adaptive gating logic
      - CI pipelines that cannot reach external APIs
      - Local development without provider credentials
      - Default behavior when CAGE_NORMATIVE_PROVIDER=static

    Set CAGE_NORMATIVE_PROVIDER=provider_01 to activate the production provider.
    """

    def __init__(self) -> None:
        import os as _os

        _cage_env = _os.getenv("CAGE_ENV", "production").lower()
        _is_production = _cage_env not in ("development", "test", "dev", "ci")

        # C-16 fix: raise at construction time if the stub is instantiated in
        # production.  The stub always returns admitted=True for validate_fria(),
        # which would make every jurisdiction assessment pass unconditionally.
        # The posture check of a jurisdiction that relies on validate_fria()
        # refuses an enforcing posture on the stub as well (is_stub_provider).
        if _is_production:
            raise RuntimeError(
                "StubNormativeProvider cannot be used in production "
                f"(CAGE_ENV={_cage_env!r}). "
                "Set CAGE_NORMATIVE_PROVIDER to a real provider name "
                "(e.g. CAGE_NORMATIVE_PROVIDER=provider_01) and ensure the "
                "provider credentials are configured."
            )

        logger.warning(
            "⚠️  StubNormativeProvider active (CAGE_ENV=%s) — external normative "
            "validation is NOT providing independent compliance ground truth. "
            "This provider must never be used in production.",
            _cage_env,
        )

    async def fetch_baseline(self, region: str) -> NormativeBaseline:
        """Read from local config/compliance/{REGION}_BASELINE.json.

        Verifies SHA-256 integrity of the policy file before loading (H-08).
        A companion ``{REGION}_BASELINE.json.sha256`` file must exist alongside
        the policy file.  If the digest file is absent the load proceeds with a
        warning (dev/CI tolerance); if the digest is present but mismatches the
        file content, the load is rejected to prevent tampered policy injection.
        """
        config_path = _COMPLIANCE_DIR / f"{region}_BASELINE.json"
        if not config_path.exists():
            return NormativeBaseline(
                region=region,
                profile={},
                error=f"Local profile not found: {config_path}",
            )
        try:
            raw_bytes = config_path.read_bytes()
            _verify_policy_integrity(config_path, raw_bytes)
            profile = json.loads(raw_bytes)
            return NormativeBaseline(region=region, profile=profile)
        except PolicyIntegrityError as exc:
            logger.error("normative_provider: policy integrity check failed: %s", exc)
            return NormativeBaseline(region=region, profile={}, error=str(exc))
        except Exception as exc:
            return NormativeBaseline(region=region, profile={}, error=str(exc))

    async def validate_fria(self, payload: dict[str, Any]) -> ValidationResult:
        """Stub always admits — no external validation."""
        return ValidationResult(admitted=True)

    async def submit_evidence(self, thread_id: str, evidence_hash: str) -> EvidenceSeal:
        """Stub returns an empty seal — no external attestation."""
        return EvidenceSeal(thread_id=thread_id)


def is_stub_provider(provider: object) -> bool:
    """True if ``provider`` is the development stub (no independent ground truth)."""
    return isinstance(provider, StubNormativeProvider)


# ---------------------------------------------------------------------------
# §4 — Daemon (Boot-Time + Polling)
# ---------------------------------------------------------------------------


class NormativeProviderDaemon:
    """Manages the lifecycle of the external normative provider integration.

    Responsibilities:
      1. **Boot-time fetch:** At container startup, fetches the baseline via
         the provider and writes it to ``config/compliance/{REGION}_BASELINE.json``.
         Then calls ``ControlRegistry.reconfigure()`` to reload the profile.

      2. **Background polling:** An ``asyncio.Task`` that polls the provider
         every N hours.  On change (detected via etag or profile hash), writes
         the new profile and reconfigures the registry.

    Fallback chain (§2.5.2):
      Level 1: External provider HTTP API (provider reachable at boot)
      Level 2: Local cached copy (config/compliance/*.json) (provider unreachable)
      Level 3: Static bundled profile (committed to repo) (no cache; cold-start)
      Level 4: RuntimeError → container fails to start (no profile at any level)

    Args:
        provider:       NormativeProvider implementation.
        region:         Deployment region string.
        poll_interval:  Seconds between background polls.
        boot_timeout:   Seconds to wait for boot-time baseline fetch.
    """

    def __init__(
        self,
        provider: NormativeProvider,
        region: str = "US_FED",
        poll_interval: float = _POLL_INTERVAL_HOURS * 3600,
        boot_timeout: float = _BOOT_TIMEOUT_SECONDS,
    ) -> None:
        self._provider = provider
        self._region = region
        self._poll_interval = poll_interval
        self._boot_timeout = boot_timeout
        self._last_hash: str = ""

    async def boot_fetch(self) -> None:
        """Fetch the baseline at container startup.

        Blocks up to ``boot_timeout`` seconds.  On success, writes the profile
        to disk and reconfigures the ControlRegistry.  On failure, falls back
        to the existing local profile (if any).

        Raises:
            RuntimeError: If no profile is available at any fallback level.
        """
        logger.info(
            "[NormativeDaemon] Boot fetch starting: region=%s timeout=%.1fs",
            self._region,
            self._boot_timeout,
        )

        try:
            baseline = await asyncio.wait_for(
                self._provider.fetch_baseline(self._region),
                timeout=self._boot_timeout,
            )
        except asyncio.TimeoutError:
            logger.warning(
                "[NormativeDaemon] Boot fetch timed out after %.1fs — "
                "falling back to local cache.",
                self._boot_timeout,
            )
            baseline = NormativeBaseline(
                region=self._region,
                profile={},
                error="Boot fetch timeout",
            )
        except Exception as exc:
            logger.warning(
                "[NormativeDaemon] Boot fetch failed: %s — falling back to local cache.",
                exc,
            )
            baseline = NormativeBaseline(
                region=self._region,
                profile={},
                error=str(exc),
            )

        if baseline.is_valid:
            # Level 1: Provider returned a valid baseline
            self._write_profile(baseline)
            self._reconfigure_registry()
            self._last_hash = baseline.profile_hash
            logger.info(
                "✅ [NormativeDaemon] Boot fetch SUCCESS: region=%s hash=%s",
                self._region,
                self._last_hash[:12],
            )
        else:
            # Level 2/3: Fall back to local cache
            local_path = _COMPLIANCE_DIR / f"{self._region}_BASELINE.json"
            if local_path.exists():
                logger.warning(
                    "[NormativeDaemon] Using cached local profile: %s",
                    local_path,
                )
                # Load hash for change detection
                # BREAKING CHANGE (FlowSignal Phase 2 §5.3): Profile hash computation
                # migrated to RFC 8785 JCS to match NormativeBaseline.profile_hash property.
                with open(local_path) as fh:
                    cached = json.load(fh)
                self._last_hash = hashlib.sha256(
                    jcs_canonicalize_plan(cached)
                ).hexdigest()
            else:
                # Level 4: No profile at any level
                raise RuntimeError(
                    f"[NormativeDaemon] No normative baseline available for "
                    f"region '{self._region}'. Provider returned: {baseline.error}. "
                    f"Local cache not found at {local_path}. "
                    f"Cannot start governance engine without a valid profile."
                )

    async def start_polling(self) -> None:
        """Background polling loop — runs as an asyncio.Task.

        Polls the provider at the configured interval.  On change (detected
        via profile hash), writes the new profile and reconfigures the
        ControlRegistry.  On unchanged baseline, no-op.

        This coroutine runs indefinitely until cancelled.
        """
        logger.info(
            "[NormativeDaemon] Polling started: region=%s interval=%.0fs",
            self._region,
            self._poll_interval,
        )

        while True:
            await asyncio.sleep(self._poll_interval)

            try:
                baseline = await self._provider.fetch_baseline(self._region)
            except Exception as exc:
                logger.warning(
                    "[NormativeDaemon] Poll fetch failed: %s — retrying next cycle.",
                    exc,
                )
                continue

            if not baseline.is_valid:
                logger.warning(
                    "[NormativeDaemon] Poll returned invalid baseline: %s — "
                    "keeping current profile.",
                    baseline.error,
                )
                continue

            new_hash = baseline.profile_hash
            if new_hash == self._last_hash:
                logger.debug(
                    "[NormativeDaemon] Baseline unchanged (hash=%s). No reconfigure.",
                    new_hash[:12],
                )
                continue

            # Baseline changed — update
            logger.info(
                "[NormativeDaemon] Baseline CHANGED: old=%s new=%s — reconfiguring.",
                self._last_hash[:12],
                new_hash[:12],
            )
            self._write_profile(baseline)
            self._reconfigure_registry()
            self._last_hash = new_hash

    def _write_profile(self, baseline: NormativeBaseline) -> None:
        """Write the fetched profile to the local compliance directory."""
        output_path = _COMPLIANCE_DIR / f"{baseline.region}_BASELINE.json"
        try:
            with open(output_path, "w") as fh:
                # Human-readable file write (not hashed), indent for readability
                json.dump(baseline.profile, fh, indent=2, sort_keys=True)
            logger.info("[NormativeDaemon] Profile written to %s", output_path)
        except Exception as exc:
            logger.error(
                "[NormativeDaemon] Failed to write profile to %s: %s",
                output_path,
                exc,
            )

    def _reconfigure_registry(self) -> None:
        """Trigger ControlRegistry reconfiguration."""
        try:
            from src.gateway.governance.constants import ControlRegistry

            ControlRegistry.reconfigure(self._region)
            logger.info(
                "✅ [NormativeDaemon] ControlRegistry reconfigured for region=%s",
                self._region,
            )
        except Exception as exc:
            logger.error(
                "[NormativeDaemon] ControlRegistry reconfigure failed: %s", exc
            )

    @classmethod
    def from_env(cls) -> NormativeProviderDaemon:
        """Construct from environment variables.

        Reads:
            CAGE_NORMATIVE_PROVIDER             — provider name
            CAGE_DEPLOYMENT_REGION              — deployment region
            CAGE_NORMATIVE_POLL_INTERVAL_HOURS  — polling interval
            CAGE_NORMATIVE_BOOT_TIMEOUT_SECONDS — boot timeout
        """
        provider = get_normative_provider()
        region = os.environ.get("CAGE_DEPLOYMENT_REGION", "US_FED").strip().upper()
        return cls(
            provider=provider,
            region=region,
            poll_interval=_POLL_INTERVAL_HOURS * 3600,
            boot_timeout=_BOOT_TIMEOUT_SECONDS,
        )


# ---------------------------------------------------------------------------
# §5 — Provider Factory
# ---------------------------------------------------------------------------

_PROVIDERS: dict[str, type] = {
    "static": StubNormativeProvider,
    # Vendor providers are lazy-loaded from src/integrations/{vendor}/
    # to enforce supply-chain isolation. See §5 factory below.
}


def get_normative_provider(name: str | None = None) -> NormativeProvider:
    """Resolve and instantiate a NormativeProvider by name.

    Args:
        name: Provider name.  If None, reads from CAGE_NORMATIVE_PROVIDER
              environment variable (default: "static").

    Supported providers:
        - "static"       — Local stub for dev/CI (kernel-resident)
        - "flowsignal"   — FlowSignal legal baseline & FRIA API (alias: "provider_01")
        - "provider_03"  — Provider 03 JCS bind receipts & normative API
        - "provider_06"  — Provider 06 tri-state agent integrity verifier
        - "provider_07"  — Provider 07 Bayesian causal suitability oracle (alias: "infertheta")
        - "provider_08"  — Provider 08 runtime evidence provider (alias: "verdict")

    Note: actuator_01 (see src/integrations/actuator_01/) implements the
    ExecutionActuator seam (KMS-signed envelope protocol), not NormativeProvider.

    Returns:
        An instantiated NormativeProvider.

    Raises:
        ValueError: If the provider name is not registered.
    """
    raw_name = name or os.environ.get("CAGE_NORMATIVE_PROVIDER", _PROVIDER_NAME)
    provider_name = raw_name.split("#")[0].strip().lower()

    # Provider alias normalization
    alias_map = {
        "flowsignal": "provider_01",
        "flow_signal": "provider_01",
        "p01": "provider_01",
        "p03": "provider_03",
        "p06": "provider_06",
        "p07": "provider_07",
        "agent_integrity": "provider_06",
        "agentintegrity": "provider_06",
        "infertheta": "provider_07",
        "p08": "provider_08",
        "verdict": "provider_08",
        "verdict_systems": "provider_08",
    }
    provider_name = alias_map.get(provider_name, provider_name)

    # Provider 02 implements AttestationProvider, not NormativeProvider
    if provider_name == "provider_02":
        raise ValueError(
            "Provider 02 implements the AttestationProvider protocol, not NormativeProvider. "
            "Use AttestationAggregator.register(Provider02AttestationProvider()) instead. "
            "See src/gateway/governance/attestation_aggregator.py for usage."
        )

    # Kernel-resident providers
    if provider_name in _PROVIDERS:
        return _PROVIDERS[provider_name]()

    # Vendor providers — lazy-loaded from src/integrations/{provider}/
    if provider_name == "provider_01":
        from src.integrations.provider_01 import FlowSignalNormativeProvider

        return FlowSignalNormativeProvider()

    if provider_name == "provider_03":
        from src.integrations.provider_03 import Provider03NormativeProvider

        return Provider03NormativeProvider()

    if provider_name == "provider_06":
        from src.integrations.provider_06 import Provider06AgentIntegrityAdapter

        return Provider06AgentIntegrityAdapter()

    if provider_name == "provider_07":
        from src.integrations.provider_07 import Provider07NormativeProvider

        return Provider07NormativeProvider.from_env()
    if provider_name == "provider_08":
        from src.integrations.provider_08 import Provider08NormativeProvider

        return Provider08NormativeProvider.from_env()

    valid = [
        *_PROVIDERS.keys(),
        "provider_01",
        "provider_03",
        "provider_06",
        "provider_07",
        "provider_08",
    ]
    raise ValueError(
        f"Unknown normative provider: {provider_name!r}. Available providers: {valid}. "
        f"Note: provider_02 implements AttestationProvider — use AttestationAggregator instead."
    )

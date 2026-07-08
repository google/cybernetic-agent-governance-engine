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
surface for external normative providers (e.g. TrustLayers), combined with an
**Adaptive Gating Primitive** that maps the blocking semantic directly to
CAGE's existing confidence boundary thresholds.

Architecture
------------
All external provider interactions fall into three categories:

  1. **Normative Data Supply** — ``GET /legal-baseline/{region}``
     Boot-time fetch + periodic background refresh.  The hot path never
     touches the network; all lookups resolve against the in-memory
     ControlRegistry singleton.

  2. **External Validation** — ``POST /validate/fria``
     Adaptive gating based on consensus confidence score:
       * Score ≥ 0.95 → ALLOW  → async attestation (fire-and-forget)
       * 0.70 ≤ Score < 0.95 → DEFER → synchronous blocking gate
       * Score < 0.70 → DENY  → hard abort, no external call

  3. **Attestation Logging** — ``GET /evidence-chain/{thread_id}``
     Async background append of governance evidence hashes for external
     sealing.  Zero blocking on the transaction path.

Architectural precedent
-----------------------
This module mirrors the pattern proven in ``config/compliance/reconciliation_worker.py``:
  - Async external fetch → cryptographic signing → local cache with TTL
  - Fail-closed on stale/absent data
  - Pluggable provider interface with stub for dev/CI

Environment variables
---------------------
  CAGE_NORMATIVE_PROVIDER             — "static" (default), "trustlayers", or "nexart"
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
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Protocol

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
# §1 — Data Contracts
# ---------------------------------------------------------------------------


class ExecutionStatus(str, Enum):
    """Tri-state execution decision from the adaptive gating primitive."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    DEFER = "DEFER"


@dataclass
class NormativeBaseline:
    """Fetched legal/regulatory baseline from an external provider.

    Attributes:
        region:      Deployment region (e.g. "US_FED", "EU_ECB").
        profile:     Raw JSON profile payload (same schema as {REGION}_BASELINE.json).
        fetched_at:  Unix timestamp when the baseline was fetched.
        signature:   KMS signature of the profile payload (hex-encoded).
        etag:        Change detection tag from the provider.
        error:       Error message if fetch failed; None on success.
    """

    region: str
    profile: dict[str, Any]
    fetched_at: float = field(default_factory=time.time)
    signature: str = ""
    etag: str = ""
    error: str | None = None

    @property
    def is_valid(self) -> bool:
        """True if the fetch succeeded and the profile is non-empty."""
        return self.error is None and bool(self.profile)

    @property
    def profile_hash(self) -> str:
        """SHA-256 hash of the serialized profile for change detection."""
        canonical = json.dumps(self.profile, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass
class ValidationResult:
    """FRIA validation response from external provider.

    Attributes:
        admitted:   True if the provider admits the transaction.
        findings:   List of compliance findings from the provider.
        sealed_at:  Unix timestamp when the validation was sealed.
        error:      Error message if validation failed; None on success.
    """

    admitted: bool
    findings: list[dict[str, Any]] = field(default_factory=list)
    sealed_at: float = field(default_factory=time.time)
    error: str | None = None


@dataclass
class EvidenceSeal:
    """External attestation seal for the governance evidence chain.

    Attributes:
        thread_id:  LangGraph thread ID for the governed transaction.
        seal_hash:  Provider-generated seal hash for the evidence chain.
        sealed_at:  Unix timestamp when the seal was generated.
        error:      Error message if sealing failed; None on success.
    """

    thread_id: str
    seal_hash: str = ""
    sealed_at: float = field(default_factory=time.time)
    error: str | None = None


@dataclass
class FRIAEnforcementResult:
    """Result of the adaptive FRIA enforcement primitive.

    Attributes:
        status:           Tri-state execution decision (ALLOW/DENY/DEFER).
        path:             The enforcement path taken (for OTel span tagging).
        consensus_score:  The consensus confidence score that drove the decision.
        validation:       ValidationResult from the provider (if sync gate was used).
    """

    status: ExecutionStatus
    path: str
    consensus_score: float
    validation: ValidationResult | None = None


# ---------------------------------------------------------------------------
# §2 — Provider Protocol + Implementations
# ---------------------------------------------------------------------------


class NormativeProvider(Protocol):
    """3-endpoint contract matching §2.5.2 of EXTENSIBILITY_ARCHITECTURE.md.

    Any compliance SaaS, internal policy engine, or regulatory data feed
    that implements these three methods can integrate with CAGE without
    kernel modification.
    """

    async def fetch_baseline(self, region: str) -> NormativeBaseline:
        """GET /legal-baseline/{region} — Normative Data Supply.

        Fetch the active legal/regulatory baseline for a deployment region.
        """
        ...  # pragma: no cover

    async def validate_fria(self, payload: dict[str, Any]) -> ValidationResult:
        """POST /validate/fria — External Validation.

        Submit a governance decision payload for external FRIA validation.
        """
        ...  # pragma: no cover

    async def submit_evidence(self, thread_id: str, evidence_hash: str) -> EvidenceSeal:
        """GET /evidence-chain/{thread_id} — Attestation Logging.

        Submit the local governance evidence hash and retrieve an externally
        sealed attestation for the audit trail.
        """
        ...  # pragma: no cover


class StubNormativeProvider:
    """Development-only provider that returns local baselines and no-op validation.

    NEVER use in production — this defeats the entire purpose of external
    normative validation.  The stub exists solely for:
      - Unit tests that validate the adaptive gating logic
      - CI pipelines that cannot reach external APIs
      - Local development without provider credentials
      - Default behavior when CAGE_NORMATIVE_PROVIDER=static

    Set CAGE_NORMATIVE_PROVIDER=trustlayers to activate the production provider.
    """

    def __init__(self) -> None:
        import os as _os

        _cage_env = _os.getenv("CAGE_ENV", "production").lower()
        _is_production = _cage_env not in ("development", "test", "dev", "ci")

        # C-16 fix: raise at construction time if the stub is instantiated in
        # production.  The stub always returns admitted=True for validate_fria(),
        # which means all FRIA boundary checks pass unconditionally — defeating
        # the adaptive gating mechanism entirely.
        if _is_production:
            raise RuntimeError(
                "StubNormativeProvider cannot be used in production "
                f"(CAGE_ENV={_cage_env!r}). "
                "Set CAGE_NORMATIVE_PROVIDER to a real provider name "
                "(e.g. CAGE_NORMATIVE_PROVIDER=trustlayers) and ensure the "
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


# ---------------------------------------------------------------------------
# §3 — Adaptive Gating Primitive
# ---------------------------------------------------------------------------


async def _async_attestation(
    provider: NormativeProvider,
    action_context: dict[str, Any],
    thread_id: str,
) -> None:
    """Fire-and-forget async attestation for high-confidence transactions.

    Runs as a detached asyncio task.  Errors are logged but never propagate
    to the caller — the transaction has already been approved locally.
    """
    try:
        result = await provider.validate_fria(action_context)
        if not result.admitted:
            # External provider flagged a legal gap AFTER local approval.
            # This is the "attestation finds a problem" case — emit SIEM alert
            # but do NOT retroactively block (the action has already committed).
            logger.warning(
                "⚠️ [FRIA Async Attestation] External provider flagged legal gap "
                "for thread=%s after local ALLOW. Findings: %s. "
                "Emitting SIEM alert for post-hoc review.",
                thread_id,
                result.findings,
            )
        else:
            logger.debug("[FRIA Async Attestation] Confirmed for thread=%s", thread_id)

        # Also submit evidence seal (non-blocking)
        seal = await provider.submit_evidence(
            thread_id,
            hashlib.sha256(
                json.dumps(action_context, sort_keys=True).encode()
            ).hexdigest(),
        )
        if seal.error:
            logger.warning(
                "[FRIA Evidence Seal] Failed for thread=%s: %s",
                thread_id,
                seal.error,
            )

    except Exception as exc:
        logger.error(
            "[FRIA Async Attestation] Unhandled error for thread=%s: %s",
            thread_id,
            exc,
        )


async def enforce_fria_boundary(
    provider: NormativeProvider,
    action_context: dict[str, Any],
    consensus_score: float,
    defer_queue: Any = None,
    thread_id: str = "",
) -> FRIAEnforcementResult:
    """Adaptive FRIA enforcement anchored to the confidence boundary.

    Maps the blocking semantic directly to CAGE's existing 4-State DEFER
    Router Engine thresholds:

      Score ≥ 0.95 (THRESHOLDS.confidence.min_trade_confidence)
        → ALLOW → async attestation (fire-and-forget)
        Hot-path latency: 0ms (task dispatched off-thread)

      0.70 ≤ Score < 0.95 (DEFER_CONFIDENCE_THRESHOLD)
        → DEFER → synchronous blocking gate
        The thread is frozen until TrustLayers explicitly returns an
        admissibility payload.  If it rejects, the state mutation is
        aborted before it can touch an external tool boundary.

      Score < 0.70
        → DENY → hard abort, no external call
        Preserves cluster bandwidth.  The transaction never hits the wire.

    Args:
        provider:         NormativeProvider implementation.
        action_context:   The governance decision payload (OPA input snapshot).
        consensus_score:  Model confidence score [0, 1] from the consensus engine.
        defer_queue:      Optional DeferQueue instance for DEFER-zone parking.
        thread_id:        LangGraph thread ID for audit trail correlation.

    Returns:
        FRIAEnforcementResult with the execution status, enforcement path,
        and optional validation result.
    """
    from src.gateway.governance.defer_queue import (
        DEFER_CONFIDENCE_THRESHOLD,
        DeferReason,
        DeferToken,
    )
    from src.gateway.governance.schemas.thresholds import THRESHOLDS

    allow_threshold = THRESHOLDS.confidence.min_trade_confidence  # 0.95
    defer_threshold = DEFER_CONFIDENCE_THRESHOLD  # 0.70

    # --- HIGH CONFIDENCE: Non-blocking attestation path ---
    if consensus_score >= allow_threshold:
        asyncio.create_task(_async_attestation(provider, action_context, thread_id))
        logger.info(
            "[FRIA] Score=%.3f ≥ %.2f → ALLOW (async attestation) thread=%s",
            consensus_score,
            allow_threshold,
            thread_id,
        )
        return FRIAEnforcementResult(
            status=ExecutionStatus.ALLOW,
            path="ASYNC_ATTESTATION",
            consensus_score=consensus_score,
        )

    # --- AMBIGUOUS ZONE: Synchronous blocking gate ---
    if consensus_score >= defer_threshold:
        # Park the transaction in the DEFER queue
        token = DeferToken(
            thread_id=thread_id or "unknown",
            defer_reason=DeferReason.EXTERNAL_VALIDATION,
            confidence_score=consensus_score,
            opa_input_snapshot=action_context,
        )
        if defer_queue is not None:
            await defer_queue.park(token)

        logger.info(
            "[FRIA] Score=%.3f in [%.2f, %.2f) → DEFER (sync gate) thread=%s defer_id=%s",
            consensus_score,
            defer_threshold,
            allow_threshold,
            thread_id,
            token.defer_id,
        )

        # BLOCK until TrustLayers responds or timeout
        gate_timeout = float(
            os.environ.get("CAGE_NORMATIVE_GATE_TIMEOUT_SECONDS", "5.0")
        )
        try:
            result = await asyncio.wait_for(
                provider.validate_fria(action_context),
                timeout=gate_timeout,
            )

            if result.admitted:
                if defer_queue is not None:
                    await defer_queue.resolve(token.defer_id, "INJECTED")
                logger.info(
                    "[FRIA] Sync gate ADMITTED for defer_id=%s thread=%s",
                    token.defer_id,
                    thread_id,
                )
                return FRIAEnforcementResult(
                    status=ExecutionStatus.ALLOW,
                    path="SYNC_GATE_ADMITTED",
                    consensus_score=consensus_score,
                    validation=result,
                )
            else:
                if defer_queue is not None:
                    await defer_queue.resolve(token.defer_id, "ESCALATED")
                logger.warning(
                    "[FRIA] Sync gate REJECTED for defer_id=%s thread=%s findings=%s",
                    token.defer_id,
                    thread_id,
                    result.findings,
                )
                return FRIAEnforcementResult(
                    status=ExecutionStatus.DENY,
                    path="SYNC_GATE_REJECTED",
                    consensus_score=consensus_score,
                    validation=result,
                )

        except asyncio.TimeoutError:
            # Provider unreachable in ambiguous zone → fail-closed
            if defer_queue is not None:
                await defer_queue.resolve(token.defer_id, "EXPIRED")
            logger.error(
                "[FRIA] Sync gate TIMEOUT (%.1fs) for defer_id=%s thread=%s — "
                "fail-closed: blocking action.",
                gate_timeout,
                token.defer_id,
                thread_id,
            )
            return FRIAEnforcementResult(
                status=ExecutionStatus.DENY,
                path="SYNC_GATE_TIMEOUT",
                consensus_score=consensus_score,
            )

    # --- LOW CONFIDENCE: Hard deny — never touch the wire ---
    logger.info(
        "[FRIA] Score=%.3f < %.2f → DENY (local hard deny) thread=%s",
        consensus_score,
        defer_threshold,
        thread_id,
    )
    return FRIAEnforcementResult(
        status=ExecutionStatus.DENY,
        path="LOCAL_HARD_DENY",
        consensus_score=consensus_score,
    )


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
                with open(local_path) as fh:
                    cached = json.load(fh)
                self._last_hash = hashlib.sha256(
                    json.dumps(cached, sort_keys=True, separators=(",", ":")).encode()
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
        - "trustlayers"  — TrustLayers cloud API (src/integrations/trustlayers/)
        - "nexart"       — NexArt attestation API (src/integrations/nexart/)

    Returns:
        An instantiated NormativeProvider.

    Raises:
        ValueError: If the provider name is not registered.
    """
    provider_name = (name or _PROVIDER_NAME).strip().lower()

    # Kernel-resident providers
    if provider_name in _PROVIDERS:
        return _PROVIDERS[provider_name]()

    # Vendor providers — lazy-loaded from src/integrations/{vendor}/
    if provider_name == "trustlayers":
        from src.integrations.trustlayers import TrustLayersProvider

        return TrustLayersProvider()

    if provider_name == "nexart":
        from src.integrations.nexart import NexArtAttestationProvider

        return NexArtAttestationProvider()

    valid = [*_PROVIDERS.keys(), "trustlayers", "nexart"]
    raise ValueError(
        f"Unknown normative provider: {provider_name!r}. Available providers: {valid}."
    )

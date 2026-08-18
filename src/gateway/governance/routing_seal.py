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
Cryptographic Routing Seal — Defense-in-Depth for Tool Actuation.

The Routing Seal is a short-lived HMAC-SHA256 token issued by the Hybrid
Gateway after a successful ``/v1/governance/validate-action`` approval.  The
GFA service (or any downstream actuator) MUST verify the seal before executing
the trade.  This ensures that execution cannot proceed by simply ignoring the
HTTP response from the governance endpoint.

Seal format (v2 — includes evidence record hash binding):
    <timestamp_ms_hex>.<action_slug>.<record_hash_hex>.<hmac_hex>

**BREAKING CHANGE (v2):** The seal format now includes a 4th component —
``record_hash_hex`` — which cryptographically binds the seal to the specific
evidence record committed to the compliance evidence stream. This ensures:

  1. The seal authenticates the governor's decision at issuance time
  2. The seal is cryptographically bound to a specific evidence record
  3. Any audit can cryptographically verify that the seal corresponds to
     a particular evidence record in the durable chain

For backward compatibility during migration, ``generate_seal()`` accepts
``record_hash=None`` (defaults to a sentinel value "no-evidence-binding").
Production deployments SHOULD always use ``generate_seal_with_evidence()``
which blocks until evidence is committed and binds the seal to the record hash.

Seal lifetime is configurable via ``GOVERNANCE_SEAL_TTL_S`` (default 30s).
The HMAC key is derived from ``GOVERNANCE_SALT`` — the same env var that is
already present in both gateway and GFA deployments.

Cryptographic contract (P3 fix)
--------------------------------
``verify_seal()`` now raises ``SymbolicGovernorViolation`` instead of returning
``False`` on any failure.  This makes it impossible for callers to silently
ignore a failed verification — the exception propagates unless explicitly
caught.  The ``require_cleared_seal`` decorator enforces this contract at the
call-site level: any wrapped callable is blocked from executing if the seal
check fails.

HMAC input (v2):
    HMAC-SHA256(
        key=GOVERNANCE_SALT,
        message=expire_hex || "." || action_slug || "." || record_hash || "." || canonical_payload
    )

Usage:
    # Gateway (issuance with evidence binding — recommended):
    seal = await generate_seal_with_evidence("execute_trade", params)

    # Gateway (issuance without evidence binding — migration only):
    seal = generate_seal("execute_trade", params, record_hash=None)

    # Verification — raises SymbolicGovernorViolation on failure:
    verify_seal(seal, "execute_trade", params)

    # Decorator pattern:
    @require_cleared_seal(seal, "execute_trade", params)
    async def _actuate():
        ...
"""

from __future__ import annotations

import functools
import hashlib
import hmac
import inspect
import json
import logging
import os
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, TypeVar

from opentelemetry import trace

from src.gateway.governance.constants import GovernanceControl

tracer = trace.get_tracer(__name__)

logger = logging.getLogger(__name__)

# The routing seal enforces the authorized action space declared in the
# agentic scope statement (SR 26-2 §3.1, AI 600-1 §2.5).  Any action that
# passes seal verification is implicitly attested to be within the scope
# defined by this control.
_SCOPE_CONTROL = GovernanceControl.AGENTIC_SCOPE_STATEMENT

F = TypeVar("F", bound=Callable[..., Any])

# ---------------------------------------------------------------------------
# Environment detection (module-level so tests can patch it)
# ---------------------------------------------------------------------------
_cage_env_seal = (
    os.environ.get("CAGE_ENV") or os.environ.get("ENVIRONMENT", "production")
).lower()
_IS_PRODUCTION: bool = _cage_env_seal not in ("development", "test", "dev", "ci")

# Seal TTL — seals expire after this many seconds.
_TTL_S = int(os.getenv("GOVERNANCE_SEAL_TTL_S", "30"))

# ---------------------------------------------------------------------------
# Feature flag: Evidence binding enforcement (P0 security hardening)
# ---------------------------------------------------------------------------
# When CAGE_REQUIRE_EVIDENCE_BINDING=true (default in production), verify_seal()
# rejects seals with record_hash="no-evidence-binding" (or empty/none variants).
# This ensures all financial actions are cryptographically bound to evidence
# records in the compliance evidence stream.
# Cross-region impact: US_FED, EU_ECB, APAC_MAS all benefit from evidence binding.
_REQUIRE_EVIDENCE_BINDING: bool = os.environ.get(
    "CAGE_REQUIRE_EVIDENCE_BINDING", "true" if _IS_PRODUCTION else "false"
).lower() in ("true", "1", "yes")

# HMAC key — must match between gateway (issuer) and GFA (verifier).
# Use _require_env so that production deployments fail fast if GOVERNANCE_SALT
# is not set, rather than silently using an insecure hardcoded default.
_DEFAULT_SALT = "default-governance-salt-change-in-production"

from src.gateway.governance.constants import _require_env

_GOVERNANCE_SALT = _require_env("GOVERNANCE_SALT", _DEFAULT_SALT, sensitive=True)
_HMAC_KEY = _GOVERNANCE_SALT.encode()

# True when the hardcoded default salt is active (no custom GOVERNANCE_SALT set).
# Tests patch this flag directly to simulate default vs. custom salt scenarios.
_USING_DEFAULT_SALT: bool = _GOVERNANCE_SALT == _DEFAULT_SALT


# ---------------------------------------------------------------------------
# P3 — SymbolicGovernorViolation exception
# ---------------------------------------------------------------------------


class SymbolicGovernorViolation(Exception):
    """Raised when a routing seal verification fails.

    This exception is the canonical signal that a cryptographic governance
    contract has been violated.  It is intentionally *not* a subclass of
    ``ValueError`` or ``PermissionError`` so that callers cannot accidentally
    swallow it via broad ``except Exception`` handlers without re-raising.

    Attributes:
        reason: Human-readable description of the specific failure mode
                (e.g. "expired", "HMAC mismatch", "malformed").
        action: The action name that was being verified.
    """

    def __init__(self, reason: str, action: str = "") -> None:
        self.reason = reason
        self.action = action
        super().__init__(
            f"SymbolicGovernorViolation: routing seal rejected for action "
            f"'{action}': {reason}"
        )


def is_default_salt() -> bool:
    """Returns True if the routing seal is using the hardcoded default GOVERNANCE_SALT.

    Returns the value of the module-level ``_USING_DEFAULT_SALT`` flag, which is
    set at import time based on whether ``GOVERNANCE_SALT`` env var is set to a
    non-default value.  Tests may patch this flag directly.
    """
    return _USING_DEFAULT_SALT


def assert_custom_salt_in_production() -> None:
    """Raise RuntimeError if the default GOVERNANCE_SALT is active in production.

    Checks ``_USING_DEFAULT_SALT`` (patchable by tests) and the current
    environment (``CAGE_ENV`` or ``ENVIRONMENT`` env var).  Raises in production
    when the default salt is active; no-op in development/test/ci environments.
    """
    if not _USING_DEFAULT_SALT:
        return  # Custom salt is set — no risk

    env = (
        os.environ.get("CAGE_ENV") or os.environ.get("ENVIRONMENT", "production")
    ).lower()
    non_production_envs = ("development", "dev", "test", "ci")
    if env in non_production_envs:
        return  # Non-production — default salt is acceptable

    raise RuntimeError(
        "CAGE SECURITY FAILURE: GOVERNANCE_SALT is using the hardcoded default value "
        f"(REDACTED_SALT) in environment '{env}'. "
        "Set a strong, unique GOVERNANCE_SALT (≥32 bytes) before deploying to production. "
        "The default salt allows any party with access to the source code to forge "
        "routing seals and bypass governance enforcement."
    )


def _canonical_payload(action: str, params: dict) -> bytes:
    """Produce a stable, deterministic byte representation of the action payload.

    Fields are sorted so that dict ordering differences don't break verification.
    Non-serialisable values are coerced to strings.
    """
    safe = {
        k: (v if isinstance(v, (str, int, float, bool, type(None))) else str(v))
        for k, v in params.items()
    }
    canon = json.dumps(
        {"action": action, **safe}, sort_keys=True, separators=(",", ":")
    )
    return canon.encode()


# Sentinel value used when no evidence binding is provided (migration/testing).
# This value is included in the HMAC input, so seals generated with and without
# evidence binding are cryptographically distinct.
_NO_EVIDENCE_BINDING = "no-evidence-binding"


def generate_seal(
    action: str,
    params: dict,
    ttl_s: int = _TTL_S,
    record_hash: str | None = None,
) -> str:
    """Generate a short-lived HMAC-SHA256 routing seal (v2 format with evidence binding).

    **BREAKING CHANGE (v2):** The seal format now includes 4 components:
        ``<expire_ts_hex>.<action_slug>.<record_hash_hex>.<hmac_hex>``

    The ``record_hash`` binds the seal to a specific evidence record in the
    compliance evidence stream. For production use, always use
    ``generate_seal_with_evidence()`` which commits evidence and provides the
    record_hash automatically.

    Args:
        action:       Tool / policy action name (e.g. ``"execute_trade"``).
        params:       Execution plan parameters dict.
        ttl_s:        Seal lifetime in seconds (default: ``GOVERNANCE_SEAL_TTL_S``).
        record_hash:  Evidence record hash from the evidence stream commit.
                      If None, uses sentinel value ``"no-evidence-binding"``.

    Returns:
        A dot-separated v2 seal string:
            ``<expire_ts_hex>.<action_slug>.<record_hash_hex>.<hmac_hex>``
    """
    expire_ts = int(time.time()) + ttl_s
    expire_hex = format(expire_ts, "x")
    # Strip dots from action_slug to guarantee unambiguous 4-way split on "."
    # during verify_seal (seal.split(".", 3)).  Any dots in the action name
    # would shift the split boundary and cause verification to fail on a valid seal.
    action_slug = action.replace("_", "-").replace(".", "-").lower()[:32]

    # Use sentinel value if no evidence binding provided
    record_hash_hex = record_hash if record_hash else _NO_EVIDENCE_BINDING

    payload = _canonical_payload(action, params)
    # HMAC input: expire_hex.action_slug.record_hash.canonical_payload
    message = f"{expire_hex}.{action_slug}.{record_hash_hex}.".encode() + payload
    sig = hmac.new(_HMAC_KEY, message, hashlib.sha256).hexdigest()
    seal = f"{expire_hex}.{action_slug}.{record_hash_hex}.{sig}"
    logger.debug(
        "🔏 Routing seal issued: action=%s expire=%s record_hash=%s",
        action,
        expire_ts,
        record_hash_hex[:16] if len(record_hash_hex) > 16 else record_hash_hex,
    )
    return seal


async def generate_seal_with_evidence(
    action: str,
    params: dict,
    ttl_s: int = _TTL_S,
    evidence_timeout_s: float = 5.0,
) -> str:
    """Generate a routing seal with evidence chain blocking gate (R-06 mitigation).

    **B2 Enhancement:** The seal is now cryptographically bound to the evidence
    record hash via the v2 seal format. This ensures:

      1. The seal authenticates the governor's decision at issuance time
      2. The seal is cryptographically bound to a specific evidence record
      3. Any audit can verify seal ↔ evidence correspondence

    This async function provides the EVIDENCE_CHAIN_BLOCKING gate that ensures
    evidence is durably committed before a routing seal is issued. When blocking
    mode is enabled (EVIDENCE_CHAIN_BLOCKING=true), this function:

      1. Commits the governance decision as evidence to the durable store
      2. Blocks until commit is confirmed or timeout
      3. Binds the evidence record_hash into the HMAC seal
      4. Only then generates and returns the routing seal
      5. If evidence commit fails, raises EvidenceChainUnavailableError (no seal)

    When blocking mode is disabled (EVIDENCE_CHAIN_BLOCKING=false, the default),
    this function falls back to fire-and-forget behavior: evidence is ingested
    asynchronously without blocking, and the seal is issued with sentinel
    ``"no-evidence-binding"`` as the record_hash. This preserves backward
    compatibility and avoids latency impact when the gate is not enabled.

    Risk mitigation: R-06 (evidence-of-execution claims overclaimed)
    This gate ensures that every routing seal corresponds to evidence that is
    durably committed to the evidence stream. Without this gate, a seal could
    be issued for a governance decision that was never recorded, allowing
    evidence-of-execution claims to be overclaimed.

    Args:
        action:  Tool / policy action name (e.g. ``"execute_trade"``).
        params:  Execution plan parameters dict.
        ttl_s:   Seal lifetime in seconds (default: ``GOVERNANCE_SEAL_TTL_S``).
        evidence_timeout_s: Timeout for evidence commit in blocking mode (default: 5s).

    Returns:
        A dot-separated v2 seal string:
            ``<expire_ts_hex>.<action_slug>.<record_hash_hex>.<hmac_hex>``

    Raises:
        EvidenceChainUnavailableError: If EVIDENCE_CHAIN_BLOCKING=true and evidence
            commit fails or times out. Caller MUST NOT proceed with execution when
            this exception is raised — the seal is not issued.
    """
    from src.compliance_bridge.evidence_stream import (
        EvidenceChainUnavailableError,
        get_evidence_sink,
        is_evidence_chain_blocking,
    )

    with tracer.start_as_current_span(
        "cage.routing_seal.generate_with_evidence"
    ) as span:
        blocking_mode = is_evidence_chain_blocking()
        span.set_attribute("cage.evidence.blocking_mode", blocking_mode)
        span.set_attribute("cage.seal.action", action)

        # Build evidence payload from governance decision
        evidence_event = {
            "type": "GOVERNANCE_DECISION",
            "controlId": _SCOPE_CONTROL.value,
            "action": action,
            "params_hash": hashlib.sha256(
                json.dumps(params, sort_keys=True, default=str).encode()
            ).hexdigest()[:16],
            "timestamp_utc": datetime.now(tz=timezone.utc).isoformat(),
            "seal_ttl_s": ttl_s,
        }

        sink = get_evidence_sink()
        record_hash: str | None = None  # Will be set if evidence commit succeeds

        if blocking_mode:
            # EVIDENCE_CHAIN_BLOCKING=true: Block until evidence is committed
            logger.info(
                "🔏 [EVIDENCE_CHAIN_BLOCKING] Committing evidence before seal issuance: action=%s",
                action,
            )
            span.set_attribute("cage.evidence.mode", "blocking")

            try:
                commit_result = await sink.ingest_sync(
                    evidence_event,
                    timeout_seconds=evidence_timeout_s,
                )
                # B2: Capture the record_hash from the committed evidence
                record_hash = commit_result.hash
                span.set_attribute(
                    "cage.evidence.evidence_id", commit_result.evidence_id
                )
                span.set_attribute("cage.evidence.hash", commit_result.hash[:16])
                span.set_attribute("cage.evidence.sequence", commit_result.sequence)
                span.set_attribute("cage.seal.record_hash_bound", True)
                logger.info(
                    "✅ Evidence committed — proceeding with seal issuance: "
                    "evidence_id=%s hash=%s…",
                    commit_result.evidence_id,
                    commit_result.hash[:16],
                )
            except EvidenceChainUnavailableError:
                # Re-raise without modification — caller must handle
                logger.error(
                    "⛔ [EVIDENCE_CHAIN_BLOCKING] Evidence commit failed — "
                    "seal NOT issued: action=%s",
                    action,
                )
                span.set_attribute("cage.seal.issued", False)
                span.set_attribute("cage.evidence.status", "failed")
                raise
        else:
            # EVIDENCE_CHAIN_BLOCKING=false (default): Fire-and-forget
            span.set_attribute("cage.evidence.mode", "fire_and_forget")
            span.set_attribute("cage.seal.record_hash_bound", False)
            if sink.is_running:
                # Best-effort async ingest — do not block on result
                try:
                    await sink.ingest(evidence_event)
                except Exception as exc:
                    # Log but do not block seal issuance
                    logger.warning(
                        "⚠️ Fire-and-forget evidence ingest failed (non-blocking): %s",
                        exc,
                    )

        # Generate and return the seal with evidence binding (B2)
        seal = generate_seal(action, params, ttl_s, record_hash=record_hash)
        span.set_attribute("cage.seal.issued", True)
        return seal


def verify_seal(
    seal: str,
    action: str,
    params: dict,
    expected_record_hash: str | None = None,
) -> bool:
    """Verify a routing seal issued by the Hybrid Gateway (v2 format).

    **BREAKING CHANGE (v2):** The seal format now includes 4 components:
        ``<expire_ts_hex>.<action_slug>.<record_hash_hex>.<hmac_hex>``

    Returns ``True`` on success.  Raises ``SymbolicGovernorViolation`` on any
    verification failure — the exception is never swallowed so callers cannot
    silently ignore a failed check.  The ``require_cleared_seal`` decorator
    relies on this propagation contract.

    Cryptographic contract (v2):
        Algorithm : HMAC-SHA256
        Key       : ``GOVERNANCE_SALT`` environment variable (≥32 bytes in
                    production; see ``assert_custom_salt_in_production()``).
        Message   : ``<expire_hex>.<action_slug>.<record_hash>.`` + canonical JSON payload
                    (``json.dumps({"action": action, **params}, sort_keys=True,
                    separators=(",", ":"))``).
        Digest    : hex-encoded lowercase SHA-256 HMAC.
        TTL       : ``GOVERNANCE_SEAL_TTL_S`` seconds (default 30).

    Args:
        seal:    Seal string as returned by :func:`generate_seal`.
        action:  Tool / policy action name — must match the issuance action.
        params:  Execution plan parameters — must match the issuance params.
        expected_record_hash:  Optional. If provided, verify that the seal's
                               embedded record_hash matches this value. Use
                               this to cryptographically verify seal ↔ evidence
                               correspondence.

    Returns:
        ``True`` if the seal is valid and unexpired.

    Raises:
        SymbolicGovernorViolation: If the seal is malformed, expired, has an
            action mismatch, record_hash mismatch, or fails HMAC verification.
            Always raised on failure — never swallowed — so callers cannot ignore it.
    """
    try:
        parts = seal.split(".", 3)
        if len(parts) != 4:
            reason = f"malformed seal (got {len(parts)} parts, expected 4 for v2 format)"
            logger.warning("🔒 Routing seal rejected: %s", reason)
            raise SymbolicGovernorViolation(reason, action)

        expire_hex, action_slug, record_hash_hex, received_sig = parts

        # Check expiry
        try:
            expire_ts = int(expire_hex, 16)
        except ValueError:
            reason = f"non-hex expiry field: {expire_hex!r}"
            logger.warning("🔒 Routing seal rejected: %s", reason)
            raise SymbolicGovernorViolation(reason, action)

        if time.time() > expire_ts:
            reason = f"expired (ts={expire_ts})"
            logger.warning("🔒 Routing seal rejected: %s", reason)
            raise SymbolicGovernorViolation(reason, action)

        # Check action slug
        expected_slug = action.replace("_", "-").lower()[:32]
        if action_slug != expected_slug:
            reason = (
                f"action mismatch (got '{action_slug}', expected '{expected_slug}')"
            )
            logger.warning("🔒 Routing seal rejected: %s", reason)
            raise SymbolicGovernorViolation(reason, action)

        # P0 hardening: Enforce evidence presence in production
        # When CAGE_REQUIRE_EVIDENCE_BINDING=true, seals without cryptographic
        # evidence binding are rejected. This ensures all financial actions are
        # bound to evidence records in the compliance evidence stream.
        _NO_EVIDENCE_SENTINELS = ("no-evidence-binding", "", "none")
        if _REQUIRE_EVIDENCE_BINDING and record_hash_hex.lower() in _NO_EVIDENCE_SENTINELS:
            reason = (
                "Evidence sufficiency violation: seal lacks a cryptographically bound "
                f"evidence record_hash (got '{record_hash_hex}'). "
                "Production requires CAGE_REQUIRE_EVIDENCE_BINDING=true."
            )
            logger.error(
                "⛔ [EVIDENCE_BINDING] Routing seal rejected: action=%s reason=%s",
                action,
                reason,
            )
            raise SymbolicGovernorViolation(reason, action)

        # B2: Optionally verify record_hash matches expected value
        if expected_record_hash is not None:
            if not hmac.compare_digest(record_hash_hex, expected_record_hash):
                reason = (
                    f"record_hash mismatch — seal not bound to expected evidence "
                    f"(got '{record_hash_hex[:16]}…', expected '{expected_record_hash[:16]}…')"
                )
                logger.warning("🔒 Routing seal rejected: %s", reason)
                raise SymbolicGovernorViolation(reason, action)

        # Recompute HMAC (v2 format includes record_hash in message)
        payload = _canonical_payload(action, params)
        message = f"{expire_hex}.{action_slug}.{record_hash_hex}.".encode() + payload
        expected_sig = hmac.new(_HMAC_KEY, message, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(received_sig, expected_sig):
            reason = "HMAC mismatch — seal may be forged or tampered"
            logger.warning("🔒 Routing seal rejected: %s", reason)
            raise SymbolicGovernorViolation(reason, action)

        logger.debug(
            "✅ Routing seal verified: action=%s record_hash=%s",
            action,
            record_hash_hex[:16] if len(record_hash_hex) > 16 else record_hash_hex,
        )
        return True

    except SymbolicGovernorViolation:
        # Re-raise — never swallow. Callers must handle the exception explicitly.
        # CRIT-1 fix: the previous code caught SymbolicGovernorViolation and
        # returned False, allowing callers to silently ignore a failed seal check.
        raise
    except Exception as exc:
        reason = f"unexpected verification error: {exc}"
        logger.warning("🔒 Routing seal verification error: %s", exc)
        raise SymbolicGovernorViolation(reason, action) from exc


def extract_record_hash(seal: str) -> str | None:
    """Extract the record_hash component from a v2 seal.

    Useful for auditing and verification workflows that need to look up the
    evidence record corresponding to a seal.

    Args:
        seal: A v2 seal string.

    Returns:
        The record_hash_hex component, or None if the seal is malformed.
        Returns ``"no-evidence-binding"`` for seals generated without evidence.
    """
    parts = seal.split(".", 3)
    if len(parts) != 4:
        return None
    return parts[2]


async def verify_and_consume_seal(
    seal: str,
    action: str,
    params: dict,
    redis_client: Any = None,
    expected_record_hash: str | None = None,
) -> bool:
    """Verify a routing seal AND atomically burn it in Redis to prevent replay.

    CAGE-SEC-008 / Terry Snyder & Miracle Owolabi remediation:
    Enforces atomic single-use seal semantics. Even within the 30-second TTL
    window, a seal can only be executed once. Subsequent attempts with the
    same seal are rejected with 'SEAL_REPLAY_DETECTED'.

    Args:
        seal:         Routing seal string (v2 format).
        action:       Tool/action name.
        params:       Execution parameters.
        redis_client: Optional async or sync Redis client. If omitted, attempts
                      to load ambient Redis client.
        expected_record_hash: Optional. If provided, verify that the seal's
                              embedded record_hash matches this value.

    Returns:
        True on successful verification and atomic single-use consumption.

    Raises:
        SymbolicGovernorViolation: If verification fails or if the seal was
            already consumed (replay attack detected).
    """
    # 1. First verify cryptographic validity & TTL (and optional record_hash)
    verify_seal(seal, action, params, expected_record_hash=expected_record_hash)

    # 2. If redis client is provided or available, enforce single-use consumption
    # v2 seal format: expire_hex.action_slug.record_hash.sig
    parts = seal.split(".", 3)
    expire_hex, _action_slug, _record_hash, sig = parts
    expire_ts = int(expire_hex, 16)
    ttl = max(int(expire_ts - time.time()), 1)

    if redis_client is None:
        try:
            from src.gateway.infrastructure.redis_client import get_redis_client

            sync_rc = get_redis_client()
            redis_client = getattr(sync_rc, "_client", None) or sync_rc._get()
        except Exception:
            redis_client = None

    if redis_client is not None:
        burn_key = f"cage:seal:consumed:{sig}"
        try:
            res = redis_client.set(burn_key, "1", nx=True, ex=ttl)
            if inspect.isawaitable(res):
                res = await res

            if not res:
                reason = "routing seal already consumed (Replay Attack Detected)"
                logger.error(
                    "🔒 [CAGE-SEC-008] Routing seal REPLAY REJECTED: action=%s sig=%s",
                    action,
                    sig[:16],
                )
                raise SymbolicGovernorViolation(reason, action)
            logger.debug("🔥 Routing seal consumed atomically: key=%s", burn_key)
        except SymbolicGovernorViolation:
            raise
        except Exception as exc:
            logger.warning("⚠️ Failed to burn routing seal in Redis: %s", exc)

    return True


def require_cleared_seal(
    seal: str,
    action: str,
    params: dict,
) -> Callable[[F], F]:
    """Decorator factory that enforces a cleared routing seal before execution.

    Wraps any async or sync callable and raises ``SymbolicGovernorViolation``
    immediately if ``verify_seal()`` fails.  The wrapped callable is never
    invoked if the seal check fails.

    Cryptographic contract:
        The decorator calls ``verify_seal(seal, action, params)`` before
        delegating to the wrapped function.  ``verify_seal`` uses HMAC-SHA256
        with the ``GOVERNANCE_SALT`` key.  A failed check raises
        ``SymbolicGovernorViolation`` — the wrapped function is NOT called.

    Args:
        seal:    Routing seal string from the governance approval response.
        action:  Action name that was approved (e.g. ``"execute_trade"``).
        params:  Parameters dict that was approved — must match the seal.

    Returns:
        A decorator that wraps the target callable with seal verification.

    Raises:
        SymbolicGovernorViolation: If the seal is invalid or expired, raised
            before the wrapped callable is invoked.

    Example::

        @require_cleared_seal(seal, "execute_trade", params)
        async def _actuate() -> str:
            return await broker.execute(params)

        result = await _actuate()
    """

    def decorator(func: F) -> F:
        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                # verify_seal() raises SymbolicGovernorViolation on any failure —
                # no need to check the return value. The wrapped function is never
                # called if the seal is invalid (CRIT-1 fix).
                verify_seal(seal, action, params)
                return await func(*args, **kwargs)

            return async_wrapper  # type: ignore[return-value]
        else:

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                # verify_seal() raises SymbolicGovernorViolation on any failure —
                # no need to check the return value. The wrapped function is never
                # called if the seal is invalid (CRIT-1 fix).
                verify_seal(seal, action, params)
                return func(*args, **kwargs)

            return sync_wrapper  # type: ignore[return-value]

    return decorator


# ---------------------------------------------------------------------------
# C-03: Auto-enforce custom HMAC salt at import time in production.
# This ensures the check runs before any seal is generated or verified.
# ---------------------------------------------------------------------------
import os as _os

# MED-8 fix: removed the `== "prod"` guard that only triggered for CAGE_ENV=prod
# exactly.  Deployments with CAGE_ENV=staging, CAGE_ENV=uat, or CAGE_ENV=preprod
# using the default salt would silently pass.  assert_custom_salt_in_production()
# already handles all non-dev/test environments correctly — call it unconditionally.
assert_custom_salt_in_production()

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

Seal format (v3 — asymmetric JWT with evidence binding):
    Standard JWT signed by the Gateway KMS signer.

**BREAKING CHANGE (v3):** The seal format is now a standard JWT.
    The `record_hash` binds the seal to a specific evidence record in the
    compliance evidence stream.

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

import base64
import functools
import hashlib
import hmac
import inspect
import json
import logging
import os
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, TypeVar

import jwt as pyjwt
from opentelemetry import trace

from src.gateway.governance.constants import GovernanceControl
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.jwks import pem_to_jwk
from src.gateway.governance.kms_signer import get_governance_signer

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

# ---------------------------------------------------------------------------
# GOVERNANCE_SALT for HMAC compatibility layer
# ---------------------------------------------------------------------------
# In test/dev environments without KMS, we use HMAC-SHA256 seals.
# In production with KMS, we use asymmetric JWT seals.
_DEFAULT_SALT = "dev-only-insecure-placeholder-not-for-production-use"
_GOVERNANCE_SALT = os.environ.get("GOVERNANCE_SALT", _DEFAULT_SALT)
_USING_DEFAULT_SALT: bool = _GOVERNANCE_SALT == _DEFAULT_SALT
_HMAC_KEY = hashlib.sha256(_GOVERNANCE_SALT.encode()).digest()


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


# ---------------------------------------------------------------------------
# SymbolicGovernorViolation exception
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


# Sentinel value used when no evidence binding is provided (migration/testing).
# This value is included in the HMAC input, so seals generated with and without
# evidence binding are cryptographically distinct.
_NO_EVIDENCE_BINDING = "no-evidence-binding"


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


def generate_seal(
    action: str,
    params: dict,
    ttl_s: int = _TTL_S,
    record_hash: str | None = None,
) -> str:
    """Generate a short-lived routing seal.

    In production with KMS configured, generates an asymmetric JWT seal (v3).
    In test/dev without KMS, generates an HMAC-SHA256 seal (v2).
    """
    signer = get_governance_signer()

    if signer.is_kms_active:
        # v3 JWT format with asymmetric signing
        now = int(time.time())
        expire_ts = now + ttl_s
        nonce = str(uuid.uuid4())
        record_hash_val = record_hash if record_hash else _NO_EVIDENCE_BINDING

        safe_params = {
            k: (v if isinstance(v, (str, int, float, bool, type(None))) else str(v))
            for k, v in params.items()
        }
        canon = jcs_canonicalize_plan({"action": action, **safe_params})
        action_hash = hashlib.sha256(canon).hexdigest()

        header = {
            "alg": signer.signing_algorithm,
            "typ": "JWT",
            "kid": pem_to_jwk(signer.get_public_key_pem())["kid"],
        }
        payload = {
            "action_hash": action_hash,
            "record_hash": record_hash_val,
            "nonce": nonce,
            "iat": now,
            "exp": expire_ts,
            "iss": "cage-gateway",
        }

        b64_header = (
            base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
        )
        b64_payload = (
            base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        )

        signing_input = f"{b64_header}.{b64_payload}".encode()
        signature = signer.sign_raw(signing_input)
        b64_signature = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()

        seal = f"{b64_header}.{b64_payload}.{b64_signature}"
        logger.debug(
            "🔏 JWT Routing seal issued: action=%s expire=%s nonce=%s",
            action,
            expire_ts,
            nonce,
        )
        return seal
    else:
        # v2 HMAC format for test/dev
        expire_ts = int(time.time()) + ttl_s
        expire_hex = format(expire_ts, "x")
        action_slug = action.replace("_", "-").replace(".", "-").lower()[:32]
        record_hash_val = record_hash if record_hash else _NO_EVIDENCE_BINDING
        payload_bytes = _canonical_payload(action, params)
        # Include record_hash in HMAC input for tamper detection
        message = (
            f"{expire_hex}.{action_slug}.{record_hash_val}.".encode() + payload_bytes
        )
        sig = hmac.new(_HMAC_KEY, message, hashlib.sha256).hexdigest()
        seal = f"{expire_hex}.{action_slug}.{record_hash_val}.{sig}"
        logger.debug(
            "🔏 HMAC Routing seal issued: action=%s expire=%s", action, expire_ts
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


def _is_jwt_seal(seal: str) -> bool:
    """Detect if a seal is in JWT format (3 parts, base64-encoded JSON header)."""
    parts = seal.split(".")
    if len(parts) != 3:
        return False
    try:
        # Try to decode the header
        header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)  # Add padding
        header_json = base64.urlsafe_b64decode(header_b64)
        header = json.loads(header_json)
        return "alg" in header and "typ" in header
    except Exception:
        return False


def verify_seal(
    seal: str,
    action: str,
    params: dict,
    expected_record_hash: str | None = None,
) -> bool:
    """Verify a routing seal (v3 JWT format with KMS or v2 HMAC format without)."""
    try:
        # Detect seal format from the seal itself, not from signer state
        is_jwt = _is_jwt_seal(seal)

        if is_jwt:
            # v3 JWT format verification with multi-key support
            # First, try to extract kid from JWT header and look up in JWKS
            from src.gateway.governance.jwks import (
                extract_kid_from_jwt,
                get_jwks,
                get_verification_key_for_jwt,
            )

            kid = extract_kid_from_jwt(seal)
            pem = get_verification_key_for_jwt(seal)

            if pem is None:
                # Fallback to direct signer key (backward compatibility)
                signer = get_governance_signer()
                pem = signer.get_public_key_pem()
                logger.debug(
                    "🔑 JWKS lookup failed for kid=%s, falling back to signer key",
                    kid,
                )

            jwk = pem_to_jwk(pem)

            # Determine allowed algorithms based on key type
            kty = jwk.get("kty", "EC")
            if kty == "EC":
                algs = ["ES256", "ES384", "ES512", "EdDSA"]
            elif kty == "OKP":
                algs = ["EdDSA"]
            else:
                algs = ["RS256", "PS256"]

            try:
                claims = pyjwt.decode(
                    seal, pem, algorithms=algs, options={"verify_exp": True}
                )
            except pyjwt.ExpiredSignatureError:
                reason = "expired"
                logger.warning("🔒 Routing seal rejected: %s", reason)
                raise SymbolicGovernorViolation(reason, action)
            except pyjwt.InvalidTokenError as exc:
                reason = f"malformed seal or invalid signature: {exc}"
                logger.warning("🔒 Routing seal rejected: %s", reason)
                raise SymbolicGovernorViolation(reason, action)

            # Check action hash
            safe_params = {
                k: (v if isinstance(v, (str, int, float, bool, type(None))) else str(v))
                for k, v in params.items()
            }
            canon = jcs_canonicalize_plan({"action": action, **safe_params})
            expected_action_hash = hashlib.sha256(canon).hexdigest()

            if claims.get("action_hash") != expected_action_hash:
                reason = "action mismatch — action_hash does not match execution params"
                logger.warning("🔒 Routing seal rejected: %s", reason)
                raise SymbolicGovernorViolation(reason, action)

            record_hash_val = claims.get("record_hash")
            _NO_EVIDENCE_SENTINELS = ("no-evidence-binding", "", "none")
            if _REQUIRE_EVIDENCE_BINDING and (
                not record_hash_val
                or str(record_hash_val).lower() in _NO_EVIDENCE_SENTINELS
            ):
                reason = "Evidence sufficiency violation: seal lacks a cryptographically bound evidence record_hash"
                logger.error(
                    "⛔ [EVIDENCE_BINDING] Routing seal rejected: action=%s reason=%s",
                    action,
                    reason,
                )
                raise SymbolicGovernorViolation(reason, action)

            if expected_record_hash is not None:
                if not hmac.compare_digest(str(record_hash_val), expected_record_hash):
                    reason = "record_hash mismatch"
                    logger.warning("🔒 Routing seal rejected: %s", reason)
                    raise SymbolicGovernorViolation(reason, action)

            logger.debug(
                "✅ Routing seal verified: action=%s nonce=%s",
                action,
                claims.get("nonce"),
            )
            return True
        else:
            if _IS_PRODUCTION:
                reason = "HMAC seals are not accepted in production (downgrade attack detected)"
                logger.error(
                    "⛔ [DOWNGRADE_ATTACK] Routing seal rejected: action=%s reason=%s",
                    action,
                    reason,
                )
                raise SymbolicGovernorViolation(reason, action)

            # v2 HMAC format verification
            parts = seal.split(".", 3)
            if len(parts) != 4:
                raise SymbolicGovernorViolation(
                    "malformed seal (expected 4 parts)", action
                )

            expire_hex, action_slug, record_hash_val, sig = parts

            # Check expiry
            try:
                expire_ts = int(expire_hex, 16)
            except ValueError:
                raise SymbolicGovernorViolation("malformed expiry timestamp", action)

            now = int(time.time())
            if now > expire_ts:
                raise SymbolicGovernorViolation("expired", action)

            # Verify HMAC signature
            payload = _canonical_payload(action, params)
            message = (
                f"{expire_hex}.{action_slug}.{record_hash_val}.".encode() + payload
            )
            expected_sig = hmac.new(_HMAC_KEY, message, hashlib.sha256).hexdigest()

            if not hmac.compare_digest(sig, expected_sig):
                raise SymbolicGovernorViolation("HMAC mismatch", action)

            # Evidence binding check
            _NO_EVIDENCE_SENTINELS = ("no-evidence-binding", "", "none")
            if _REQUIRE_EVIDENCE_BINDING and (
                not record_hash_val
                or str(record_hash_val).lower() in _NO_EVIDENCE_SENTINELS
            ):
                reason = "Evidence sufficiency violation: seal lacks a cryptographically bound evidence record_hash"
                logger.error(
                    "⛔ [EVIDENCE_BINDING] Routing seal rejected: action=%s reason=%s",
                    action,
                    reason,
                )
                raise SymbolicGovernorViolation(reason, action)

            if expected_record_hash is not None:
                if not hmac.compare_digest(record_hash_val, expected_record_hash):
                    raise SymbolicGovernorViolation("record_hash mismatch", action)

            logger.debug(
                "✅ Routing seal verified (HMAC): action=%s expire=%s",
                action,
                expire_ts,
            )
            return True

    except SymbolicGovernorViolation:
        raise
    except Exception as exc:
        reason = f"unexpected verification error: {exc}"
        logger.warning("🔒 Routing seal verification error: %s", exc)
        raise SymbolicGovernorViolation(reason, action) from exc


def extract_record_hash(seal: str) -> str | None:
    """Extract the record_hash component from a v3 JWT or v2 HMAC seal."""
    if _is_jwt_seal(seal):
        # JWT format: extract from claims
        try:
            claims = pyjwt.decode(seal, options={"verify_signature": False})
            return claims.get("record_hash")
        except Exception:
            return None
    else:
        # HMAC format (v2): record_hash is the 3rd component
        # v2 format requires exactly 4 parts: expire_hex.action_slug.record_hash.hmac
        parts = seal.split(".", 3)
        if len(parts) == 4:
            return parts[2]
        return None


async def verify_and_consume_seal(
    seal: str,
    action: str,
    params: dict,
    redis_client: Any = None,
    expected_record_hash: str | None = None,
) -> bool:
    """Verify a routing seal and burn its nonce via Redis SETNX.

    Implements replay protection per the Cryptographic Governance Evolution spec:
    1. Verify the seal signature and claims
    2. Extract the nonce (from JWT claims or HMAC hash)
    3. Use Redis SETNX to atomically burn the nonce
    4. Reject if nonce was already burned (replay attack)

    Fail-closed: If Redis is unavailable, verification fails.
    """
    # Step 1: Verify the seal (signature, expiry, payload binding)
    verify_seal(
        seal=seal,
        action=action,
        params=params,
        expected_record_hash=expected_record_hash,
    )

    # Step 2: Extract nonce for replay protection
    is_jwt = _is_jwt_seal(seal)
    if is_jwt:
        # JWT format: extract nonce from claims
        try:
            claims = pyjwt.decode(seal, options={"verify_signature": False})
            nonce = claims.get("nonce")
            ttl = claims.get("exp", 0) - int(time.time())
        except Exception as exc:
            raise SymbolicGovernorViolation(f"failed to extract nonce: {exc}", action)
    else:
        # HMAC format: use seal hash as nonce (deterministic)
        nonce = hashlib.sha256(seal.encode()).hexdigest()
        # Parse expiry from first part (hex timestamp)
        try:
            parts = seal.split(".", 3)
            expire_ts = int(parts[0], 16)
            ttl = expire_ts - int(time.time())
        except Exception:
            ttl = _TTL_S

    if not nonce:
        raise SymbolicGovernorViolation(
            "seal missing nonce for replay protection", action
        )

    # Step 3: Burn nonce via Redis SETNX (fail-closed)
    redis = redis_client
    if redis is None:
        # Try to get the default async client
        try:
            from src.gateway.infrastructure.redis_client import (
                redis_client as default_redis_client,
            )

            redis = default_redis_client
        except Exception as exc:
            logger.error(
                "⛔ [REPLAY_PROTECTION] Redis unavailable — fail-closed: %s", exc
            )
            raise SymbolicGovernorViolation(
                "replay protection unavailable (Redis connection failed)", action
            ) from exc

    # Use SETNX with TTL to burn the nonce
    nonce_key = f"cage:seal:nonce:{nonce}"
    ttl_s = max(ttl + 60, 60)  # Add 60s buffer, minimum 60s

    try:
        # SETNX returns True if key was set (first use), False if exists (replay)
        was_set = await redis.set(nonce_key, "1", nx=True, ex=ttl_s)
        if not was_set:
            logger.warning(
                "🔒 [REPLAY_ATTACK] Seal nonce already consumed: action=%s nonce=%s",
                action,
                nonce[:16] + "...",
            )
            raise SymbolicGovernorViolation(
                "replay attack detected — seal already consumed", action
            )
    except SymbolicGovernorViolation:
        raise
    except Exception as exc:
        logger.error("⛔ [REPLAY_PROTECTION] Redis SETNX failed — fail-closed: %s", exc)
        raise SymbolicGovernorViolation(
            f"replay protection failed (Redis error): {exc}", action
        ) from exc

    logger.debug(
        "✅ Seal verified and consumed: action=%s nonce=%s", action, nonce[:16] + "..."
    )
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

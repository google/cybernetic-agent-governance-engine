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

Theoretical Foundation:
    Enforces the 'Evidence Sufficiency' invariant defined by Krti Tallam (2026),
    "A Five-Plane Reference Architecture for Runtime Governance of Production AI Agents"
    (arXiv:2606.12320): actuation must strictly depend on prior, immutable evidence
    persistence rather than uncommitted in-memory claims.

Architectural Hardening:
    Identified during security review by K. Tallam: decoupling the cryptographic HMAC seal
    from durable hash-chain writes allowed an execution path where actions could be authorized
    even if the audit sink was unreachable or dropped events.

    ``generate_seal_with_evidence()`` enforces fail-closed semantics: seal issuance blocks
    on a synchronous, durable chain commit, raising ``EvidenceChainUnavailableError`` if the
    sink fails or times out.

Seal format (v3 — asymmetric JWT with evidence binding):
    Standard JWT signed by the Gateway KMS signer.

**BREAKING CHANGE (v3):** The seal format is now a standard JWT.
    The `record_hash` binds the seal to a specific evidence record in the
    compliance evidence stream.

Usage:
    # Gateway (issuance with evidence binding — recommended):
    seal = await generate_seal_with_evidence("execute_action", params)

    # Gateway (issuance without evidence binding — migration only):
    seal = generate_seal("execute_action", params, record_hash=None)

    # Verification — raises SymbolicGovernorViolation on failure:
    verify_seal(seal, "execute_action", params)

    # Decorator pattern:
    @require_cleared_seal(seal, "execute_action", params)
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
import math
import os
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from enum import Enum
from typing import Any, TypeVar

import jwt as pyjwt
from opentelemetry import trace

from src.gateway.governance.constants import GovernanceControl
from src.gateway.governance.evidence import stream as es
from src.gateway.governance.evidence.stream import (
    EvidenceChainUnavailableError,
)
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
# Evidence binding enforcement
# ---------------------------------------------------------------------------
# Every seal must be bound to a committed evidence record (issue #379): the
# seal's ``record_hash`` claim must be a real hash, and at consumption it must
# match the evidence index written when the seal was issued. Required in every
# posture by default. ``CAGE_REQUIRE_EVIDENCE_BINDING=false`` is honoured only
# outside production, for hermetic tests of the unbound path.
_NO_EVIDENCE_SENTINELS = ("no-evidence-binding", "", "none")


def _require_evidence_binding() -> bool:
    """Whether seals must carry, and consumption must check, an evidence binding."""
    raw = os.environ.get("CAGE_REQUIRE_EVIDENCE_BINDING", "true").strip().lower()
    if raw not in ("false", "0", "no"):
        return True
    if _is_production_env():
        logger.error(
            "⛔ CAGE_REQUIRE_EVIDENCE_BINDING=false ignored in production; "
            "evidence binding stays required."
        )
        return True
    return False


def _is_unbound(record_hash: Any) -> bool:
    return not record_hash or str(record_hash).lower() in _NO_EVIDENCE_SENTINELS


# ---------------------------------------------------------------------------
# Feature flag: Seal strict mode - prevents HMAC downgrade attacks
# ---------------------------------------------------------------------------
# When CAGE_SEAL_STRICT_MODE=true (default), JWT verification failures do NOT
# fall back to HMAC verification. This prevents downgrade attacks where an
# attacker crafts a malformed JWT to trigger the HMAC verification path.
# Set to "false" only in isolated development/test environments without KMS.
#
# NOTE: _SEAL_STRICT_MODE is kept for backwards compatibility but _get_seal_strict_mode()
# should be used at call time to allow test fixtures to override via monkeypatch.
_SEAL_STRICT_MODE: bool = os.environ.get("CAGE_SEAL_STRICT_MODE", "true").lower() in (
    "true",
    "1",
    "yes",
)


def _get_seal_strict_mode() -> bool:
    """Get seal strict mode setting at call time (allows test overrides)."""
    return os.environ.get("CAGE_SEAL_STRICT_MODE", "true").lower() in (
        "true",
        "1",
        "yes",
    )


def _is_production_env() -> bool:
    """Check if we're in a production environment at call time (allows test overrides)."""
    cage_env = (
        os.environ.get("CAGE_ENV") or os.environ.get("ENVIRONMENT", "production")
    ).lower()
    return cage_env not in ("development", "test", "dev", "ci")


# ---------------------------------------------------------------------------
# GOVERNANCE_SALT for HMAC compatibility layer
# ---------------------------------------------------------------------------
# In test/dev environments without KMS, we use HMAC-SHA256 seals.
# In production with KMS, we use asymmetric JWT seals.
_DEFAULT_SALT = "dev-only-insecure-placeholder-not-for-production-use"
_GOVERNANCE_SALT = os.environ.get("GOVERNANCE_SALT", _DEFAULT_SALT)
_USING_DEFAULT_SALT: bool = _GOVERNANCE_SALT == _DEFAULT_SALT
_HMAC_KEY = hashlib.sha256(_GOVERNANCE_SALT.encode()).digest()

# ---------------------------------------------------------------------------
# Atomic single-use nonce consumption via Redis Lua script
# ---------------------------------------------------------------------------
# This Lua script makes the check-and-consume of a seal nonce atomic. The script:
#   1. Attempts to SET the nonce key with NX (only if not exists) and EX (TTL)
#   2. Returns 0 if successfully consumed (first use), 1 if already consumed
#
# verify_and_consume_seal() runs it only AFTER verify_seal() has succeeded
# (POAM-2026-089, verify -> burn -> execute). Verification is stateless, so
# racing callers holding the same valid seal may all verify; this script then
# admits exactly one of them, and an unverified seal can never consume a nonce.
#
# KEYS[1]: nonce_key (e.g., "cage:seal:nonce:{nonce}")
# ARGV[1]: ttl_seconds (integer)
# ARGV[2]: metadata (JSON string with action, timestamp for audit trail)
#
# Returns:
#   0 = Successfully consumed (caller owns the seal and may execute)
#   1 = Already consumed (replay or concurrent loser - reject)
_ATOMIC_BURN_NONCE_LUA = """
local nonce_key = KEYS[1]
local ttl_s = tonumber(ARGV[1])
local metadata = ARGV[2]

-- Attempt atomic SET NX with TTL
-- SET returns OK if successful, nil if NX condition fails (key exists)
local result = redis.call('SET', nonce_key, metadata, 'NX', 'EX', ttl_s)
if result then
    return 0  -- Success: nonce consumed, caller owns the seal
else
    return 1  -- Replay: nonce was already burned by another request
end
"""

# SHA1 hash of the Lua script for EVALSHA optimization (computed at runtime)
_ATOMIC_BURN_NONCE_SHA: str | None = None


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
    non_production_envs = (
        "development",
        "dev",
        "test",
        "ci",
        "staging",
        "uat",
        "preprod",
    )
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

# Redis key prefixes. A seal's nonce key is written exactly once, either when
# the seal is consumed or when it is revoked; whichever comes first wins.
_NONCE_PREFIX = "cage:seal:nonce:"
_EVIDENCE_INDEX_PREFIX = "cage:seal:evidence:"


SEAL_CANON = "cage-action/1"
"""Identifier of the action-hash recipe below, carried as the seal's ``canon`` claim.

``action_hash = sha256(JCS({"action": action, "params": params})).hexdigest()``
with ``params`` restricted to I-JSON values (RFC 7493): strings, booleans,
null, finite numbers, integers within ±(2**53 - 1), arrays and string-keyed
objects. Any language with an RFC 8785 implementation can recompute it, which
is what lets a partner verify a seal independently (see
``docs/partners/actuator_02/SEAL_VERIFICATION_PROFILE.md``).
"""

_MAX_SAFE_INTEGER = 2**53 - 1


class SealCanonicalizationError(ValueError):
    """The action or params cannot be represented exactly in the seal's hash input."""


def _strict_json(value: Any, path: str) -> Any:
    """Return ``value`` if it is an I-JSON value, else raise.

    Nothing is coerced. ``str()`` coercion made ``{"x": [1, 2]}`` and
    ``{"x": "[1, 2]"}`` hash identically (issue #379), and a Python repr is not
    something another language can reproduce.
    """
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int):
        if abs(value) > _MAX_SAFE_INTEGER:
            raise SealCanonicalizationError(f"{path}: integer outside ±(2**53-1)")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise SealCanonicalizationError(f"{path}: non-finite number")
        return value
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise SealCanonicalizationError(f"{path}: non-string key {key!r}")
            out[key] = _strict_json(item, f"{path}.{key}")
        return out
    if isinstance(value, (list, tuple)):
        return [_strict_json(item, f"{path}[{i}]") for i, item in enumerate(value)]
    raise SealCanonicalizationError(
        f"{path}: {type(value).__name__} is not a JSON value"
    )


def canonical_action_bytes(action: str, params: dict) -> bytes:
    """RFC 8785 bytes of ``{"action": action, "params": params}`` (recipe ``SEAL_CANON``).

    ``params`` is nested rather than merged beside ``action``, so a param named
    ``action`` cannot shadow the action being authorised.

    Raises:
        SealCanonicalizationError: If ``action`` is not a non-empty string or
            ``params`` is not a dict of I-JSON values.
    """
    if not isinstance(action, str) or not action:
        raise SealCanonicalizationError("action must be a non-empty string")
    if not isinstance(params, dict):
        raise SealCanonicalizationError("params must be a JSON object")
    return jcs_canonicalize_plan(
        {"action": action, "params": _strict_json(params, "params")}
    )


def compute_action_hash(action: str, params: dict) -> str:
    """Lowercase hex SHA-256 of :func:`canonical_action_bytes`."""
    return hashlib.sha256(canonical_action_bytes(action, params)).hexdigest()


def generate_seal(
    action: str,
    params: dict,
    ttl_s: int = _TTL_S,
    record_hash: str | None = None,
    aud: str | None = None,
) -> str:
    """Generate a short-lived routing seal.

    In production with KMS configured, generates an asymmetric JWT seal (v3).
    In test/dev without KMS, generates an HMAC-SHA256 seal (v2).

    Raises:
        SealCanonicalizationError: If ``params`` are not exact JSON values;
            no seal is minted for params the hash cannot represent.
    """
    payload_bytes = canonical_action_bytes(action, params)
    signer = get_governance_signer()

    if signer.is_kms_active:
        # v3 JWT format with asymmetric signing
        now = int(time.time())
        expire_ts = now + ttl_s
        nonce = str(uuid.uuid4())
        record_hash_val = record_hash if record_hash else _NO_EVIDENCE_BINDING
        action_hash = hashlib.sha256(payload_bytes).hexdigest()

        # The JWS header must carry the RFC 7518 identifier (``ES256``,
        # ``EdDSA``…), never the provider label from ``signing_algorithm``
        # (``KMS_ASYMMETRIC``, ``SOFTWARE_ED25519``…) — verify_seal's PyJWT
        # allow-list only admits JOSE names.
        jose_alg = signer.jose_alg
        header = {
            "alg": jose_alg,
            "typ": "JWT",
            "kid": pem_to_jwk(signer.get_public_key_pem())["kid"],
        }
        payload = {
            "action_hash": action_hash,
            "canon": SEAL_CANON,
            "record_hash": record_hash_val,
            "nonce": nonce,
            "iat": now,
            "exp": expire_ts,
            "iss": "cage-gateway",
            "aud": aud or f"cage-actuator:{action}",
        }

        b64_header = (
            base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
        )
        b64_payload = (
            base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        )

        signing_input = f"{b64_header}.{b64_payload}".encode()
        # sign_jws normalises KMS DER ECDSA output to the JWS raw R||S form.
        signature = signer.sign_jws(signing_input)
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
    aud: str | None = None,
    redis_client: Any = None,
) -> str:
    """Generate a routing seal with evidence chain blocking gate (R-06 mitigation).

    **B2 Enhancement:** The seal is now cryptographically bound to the evidence
    record hash via the v2 seal format. This ensures:

      1. The seal authenticates the governor's decision at issuance time
      2. The seal is cryptographically bound to a specific evidence record
      3. Any audit can verify seal ↔ evidence correspondence

    This async function provides the EVIDENCE_CHAIN_BLOCKING gate that ensures
    evidence is durably committed before a routing seal is issued. When
    blocking mode is enabled (EVIDENCE_CHAIN_BLOCKING=true, the default — see
    ``evidence/stream.py``), this function:

      1. Commits the governance decision as evidence to the durable store
      2. Blocks until commit is confirmed or timeout
      3. Binds the evidence record_hash into the seal
      4. Only then generates and returns the routing seal
      5. If evidence commit fails, raises EvidenceChainUnavailableError (no seal)

    When blocking mode is explicitly disabled (EVIDENCE_CHAIN_BLOCKING=false;
    refused at startup in enforcing postures unless
    CAGE_ALLOW_NONBLOCKING_PROD=true), this function falls back to
    fire-and-forget behavior: evidence is ingested asynchronously without
    blocking, and the seal is issued with sentinel ``"no-evidence-binding"``
    as the record_hash.

    Risk mitigation: R-06 (evidence-of-execution claims overclaimed)
    This gate ensures that every routing seal corresponds to evidence that is
    durably committed to the evidence stream. Without this gate, a seal could
    be issued for a governance decision that was never recorded, allowing
    evidence-of-execution claims to be overclaimed.

    Args:
        action:  Tool / policy action name (e.g. ``"execute_action"``).
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
    with tracer.start_as_current_span(
        "cage.routing_seal.generate_with_evidence"
    ) as span:
        blocking_mode = es.is_evidence_chain_blocking()
        span.set_attribute("cage.evidence.blocking_mode", blocking_mode)
        span.set_attribute("cage.seal.action", action)

        # Same strict canonical bytes the seal signs (recipe SEAL_CANON). Params
        # the hash cannot represent exactly are refused here, before any
        # evidence is committed for an action that could never be sealed.
        action_bytes = canonical_action_bytes(action, params)

        evidence_event = {
            "type": "GOVERNANCE_DECISION",
            "controlId": _SCOPE_CONTROL.value,
            "action": action,
            "params_hash": hashlib.sha256(action_bytes).hexdigest()[:16],
            "timestamp_utc": datetime.now(tz=timezone.utc).isoformat(),
            "seal_ttl_s": ttl_s,
        }

        sink = es.get_evidence_sink()
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
            # EVIDENCE_CHAIN_BLOCKING=false (explicit opt-out): Fire-and-forget
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
        if record_hash is None and _require_evidence_binding():
            # An unbound seal could never be consumed; refuse to mint one.
            span.set_attribute("cage.seal.issued", False)
            raise EvidenceChainUnavailableError(
                "evidence binding is required but no evidence record was committed "
                "(EVIDENCE_CHAIN_BLOCKING=false); seal not issued"
            )
        seal = generate_seal(action, params, ttl_s, record_hash=record_hash, aud=aud)
        if record_hash is not None:
            await _index_evidence_binding(seal, record_hash, ttl_s, redis_client)
        span.set_attribute("cage.seal.issued", True)
        return seal


def _evidence_index_key(nonce: str) -> str:
    return f"{_EVIDENCE_INDEX_PREFIX}{nonce}"


async def _index_evidence_binding(
    seal: str, record_hash: str, ttl_s: int, redis_client: Any
) -> None:
    """Record which evidence record this seal is bound to, keyed by its nonce.

    :func:`verify_and_consume_seal` reads this index to obtain the expected
    ``record_hash`` independently of the seal. A seal whose ``record_hash``
    claim was never produced by an evidence commit therefore cannot be
    consumed, even if its signature verifies (issue #379).

    Raises:
        EvidenceChainUnavailableError: If the index cannot be written; the seal
            is then never returned, so it cannot be presented.
    """
    try:
        redis = await _resolve_redis(redis_client)
        await redis.set(
            _evidence_index_key(seal_nonce(seal)), record_hash, ex=max(ttl_s + 60, 60)
        )
    except Exception as exc:
        raise EvidenceChainUnavailableError(
            f"seal evidence index unavailable: {type(exc).__name__}"
        ) from exc


async def _resolve_redis(redis_client: Any) -> Any:
    """Return ``redis_client``, or the raw client behind the gateway's shared one.

    The seal store needs ``SET NX EX`` and Lua ``EVAL``/``EVALSHA``, which the
    shared wrapper does not expose, so the raw ``redis.asyncio`` client is used.
    """
    if redis_client is not None:
        return redis_client
    from src.gateway.infrastructure.redis_client import (
        redis_client as default_redis_client,
    )

    get_raw = getattr(default_redis_client, "get_raw_client", None)
    if get_raw is None:
        return default_redis_client
    return await get_raw()


def seal_nonce(seal: str) -> str:
    """The single-use identifier of a seal (parse only, no verification).

    JWT seals carry a ``nonce`` claim; HMAC seals use ``sha256(seal)``. The
    value keys the consume, revocation and evidence-index records.

    Raises:
        SymbolicGovernorViolation: If the seal is not a non-empty string or a
            JWT seal has no ``nonce``.
    """
    if not isinstance(seal, str) or not seal:
        raise SymbolicGovernorViolation(
            f"seal must be a non-empty string, got {type(seal).__name__}"
        )
    if not _is_jwt_seal(seal):
        return hashlib.sha256(seal.encode()).hexdigest()
    try:
        # Parse only: callers act on the nonce only after verify_seal().
        claims = _unverified_claims(seal)
    except Exception as exc:
        raise SymbolicGovernorViolation(f"failed to extract nonce: {exc}") from exc
    nonce = claims.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        raise SymbolicGovernorViolation("seal missing nonce for replay protection")
    return nonce


def _unverified_claims(seal: str) -> dict[str, Any]:
    """Parse a JWT seal's claims WITHOUT checking its signature.

    The single place where seal claims are read unverified. Callers use the
    result only as a lookup key or sizing hint (nonce, record_hash, exp for
    Redis TTLs); no authorisation decision is ever taken on it. Every trust
    decision goes through :func:`verify_seal`, which verifies the signature
    against a ``kid``-resolved key from the JWKS trust anchor.
    """
    # Metadata parse only; the signature is verified in verify_seal() before use.
    # nosemgrep: python.jwt.security.unverified-jwt-decode.unverified-jwt-decode
    claims: dict[str, Any] = pyjwt.decode(seal, options={"verify_signature": False})
    return claims


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
    expected_aud: str | None = None,
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
                get_verification_key_for_jwt,
            )

            kid = extract_kid_from_jwt(seal)
            pem = get_verification_key_for_jwt(seal)

            if pem is None:
                # Trust is decided by kid alone: a kid absent from the JWKS is
                # rejected, never re-tried against this process's own signer.
                logger.warning(
                    "⛔ [SEAL_VERIFICATION_FAILED] event=routing_seal_verification_failed "
                    "action=%s reason=unknown_kid kid=%s",
                    action,
                    kid,
                )
                raise SymbolicGovernorViolation(f"unknown kid: {kid!r}", action)

            jwk = pem_to_jwk(pem)

            # Determine allowed algorithms based on key type
            kty = jwk.get("kty", "EC")
            if kty == "EC":
                algs = ["ES256", "ES384", "ES512"]
            elif kty == "OKP":
                algs = ["EdDSA"]
            else:
                algs = ["RS256", "PS256"]

            def _reject_seal(fail_reason: str, fail_action: str) -> None:
                logger.warning(
                    "⛔ [SEAL_VERIFICATION_FAILED] event=routing_seal_verification_failed action=%s reason=%s",
                    fail_action,
                    fail_reason,
                )
                raise SymbolicGovernorViolation(fail_reason, fail_action)

            try:
                claims = pyjwt.decode(
                    seal,
                    pem,
                    algorithms=algs,
                    options={"verify_exp": True, "verify_aud": False},
                )
            except pyjwt.ExpiredSignatureError:
                _reject_seal("expired", action)
            except pyjwt.InvalidTokenError as exc:
                _reject_seal(f"malformed seal or invalid signature: {exc}", action)

            claim_aud = claims.get("aud")
            target_aud = expected_aud or f"cage-actuator:{action}"
            if claim_aud is not None and claim_aud != target_aud:
                _reject_seal(
                    "audience mismatch — aud does not match target executor",
                    action,
                )
            elif expected_aud is not None and claim_aud != expected_aud:
                _reject_seal(
                    "audience mismatch — aud does not match target executor",
                    action,
                )

            # Check the hash recipe, then the action hash
            if claims.get("canon") != SEAL_CANON:
                _reject_seal(
                    f"unsupported action-hash recipe {claims.get('canon')!r} "
                    f"(expected {SEAL_CANON!r})",
                    action,
                )
            try:
                expected_action_hash = compute_action_hash(action, params)
            except SealCanonicalizationError as exc:
                _reject_seal(f"params not canonicalizable: {exc}", action)

            if not hmac.compare_digest(
                str(claims.get("action_hash", "")), expected_action_hash
            ):
                _reject_seal(
                    "action mismatch — action_hash does not match execution params",
                    action,
                )

            record_hash_val = claims.get("record_hash")
            if _require_evidence_binding() and _is_unbound(record_hash_val):
                _reject_seal(
                    "Evidence sufficiency violation: seal lacks a cryptographically bound evidence record_hash",
                    action,
                )

            if expected_record_hash is not None:
                if not hmac.compare_digest(str(record_hash_val), expected_record_hash):
                    _reject_seal("record_hash mismatch", action)

            logger.debug(
                "✅ Routing seal verified: action=%s nonce=%s",
                action,
                claims.get("nonce"),
            )
            return True
        else:
            # SECURITY FIX: Strict mode prevents HMAC downgrade attacks
            # In strict mode (or production), reject HMAC seals to prevent attackers
            # from crafting malformed JWTs to trigger the HMAC verification path
            # NOTE: We use runtime functions instead of module-level constants to allow
            # test fixtures to override via monkeypatch.setenv().
            strict_mode = _get_seal_strict_mode()
            is_production = _is_production_env()
            if strict_mode or is_production:
                reason = (
                    "HMAC seals are not accepted in strict mode "
                    "(CAGE_SEAL_STRICT_MODE=true or production environment). "
                    "Possible downgrade attack detected."
                )
                logger.error(
                    "⛔ [DOWNGRADE_ATTACK] Routing seal rejected: action=%s reason=%s "
                    "strict_mode=%s is_production=%s",
                    action,
                    reason,
                    strict_mode,
                    is_production,
                )
                logger.warning(
                    "⛔ [SEAL_VERIFICATION_FAILED] event=routing_seal_verification_failed action=%s reason=%s",
                    action,
                    reason,
                )
                raise SymbolicGovernorViolation(reason, action)

            # v2 HMAC format verification (only allowed in non-strict development mode)
            logger.warning(
                "⚠️ [HMAC_FALLBACK] Using HMAC verification in non-strict mode: "
                "action=%s. This is insecure and should not be used in production.",
                action,
            )
            parts = seal.split(".", 3)
            if len(parts) != 4:
                logger.warning(
                    "⛔ [SEAL_VERIFICATION_FAILED] event=routing_seal_verification_failed action=%s reason=%s",
                    action,
                    "malformed seal (expected 4 parts)",
                )
                raise SymbolicGovernorViolation(
                    "malformed seal (expected 4 parts)", action
                )

            expire_hex, action_slug, record_hash_val, sig = parts

            # Check expiry
            try:
                expire_ts = int(expire_hex, 16)
            except ValueError:
                logger.warning(
                    "⛔ [SEAL_VERIFICATION_FAILED] event=routing_seal_verification_failed action=%s reason=%s",
                    action,
                    "malformed expiry timestamp",
                )
                raise SymbolicGovernorViolation("malformed expiry timestamp", action)

            now = int(time.time())
            if now > expire_ts:
                logger.warning(
                    "⛔ [SEAL_VERIFICATION_FAILED] event=routing_seal_verification_failed action=%s reason=%s",
                    action,
                    "expired",
                )
                raise SymbolicGovernorViolation("expired", action)

            # Verify HMAC signature
            try:
                payload = canonical_action_bytes(action, params)
            except SealCanonicalizationError as exc:
                raise SymbolicGovernorViolation(
                    f"params not canonicalizable: {exc}", action
                ) from exc
            message = (
                f"{expire_hex}.{action_slug}.{record_hash_val}.".encode() + payload
            )
            expected_sig = hmac.new(_HMAC_KEY, message, hashlib.sha256).hexdigest()

            if not hmac.compare_digest(sig, expected_sig):
                logger.warning(
                    "⛔ [SEAL_VERIFICATION_FAILED] event=routing_seal_verification_failed action=%s reason=%s",
                    action,
                    "HMAC mismatch",
                )
                raise SymbolicGovernorViolation("HMAC mismatch", action)

            # Evidence binding check
            if _require_evidence_binding() and _is_unbound(record_hash_val):
                reason = "Evidence sufficiency violation: seal lacks a cryptographically bound evidence record_hash"
                logger.error(
                    "⛔ [EVIDENCE_BINDING] Routing seal rejected: action=%s reason=%s",
                    action,
                    reason,
                )
                logger.warning(
                    "⛔ [SEAL_VERIFICATION_FAILED] event=routing_seal_verification_failed action=%s reason=%s",
                    action,
                    reason,
                )
                raise SymbolicGovernorViolation(reason, action)

            if expected_record_hash is not None:
                if not hmac.compare_digest(record_hash_val, expected_record_hash):
                    logger.warning(
                        "⛔ [SEAL_VERIFICATION_FAILED] event=routing_seal_verification_failed action=%s reason=%s",
                        action,
                        "record_hash mismatch",
                    )
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
            # SECURITY NOTE: Signature verification is intentionally disabled here because
            # this function only extracts metadata from the seal. Cryptographic verification
            # happens in verify_seal() via KMS public key validation. This pattern prevents
            # double-verification overhead while maintaining security boundaries.
            # See: verify_seal() for signature verification logic.
            claims = _unverified_claims(seal)
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


async def _atomic_burn_nonce(
    redis: Any,
    nonce_key: str,
    ttl_s: int,
    metadata: str,
) -> int:
    """Execute atomic nonce burning via Redis Lua script.

    This function encapsulates the Lua script execution with EVALSHA optimization.
    On first call, it registers the script and caches the SHA. Subsequent calls
    use EVALSHA for efficiency.

    Args:
        redis: Async Redis client instance.
        nonce_key: The Redis key for this nonce (e.g., "cage:seal:nonce:{nonce}").
        ttl_s: TTL in seconds for the burned nonce key.
        metadata: JSON string with audit metadata (action, timestamp).

    Returns:
        0 if nonce was successfully burned (first use).
        1 if nonce was already burned (replay attack).

    Raises:
        Exception: On Redis communication errors (caller should fail-closed).
    """
    global _ATOMIC_BURN_NONCE_SHA

    # Try EVALSHA first if we have a cached SHA
    if _ATOMIC_BURN_NONCE_SHA is not None:
        try:
            result = await redis.evalsha(
                _ATOMIC_BURN_NONCE_SHA,
                1,  # number of keys
                nonce_key,
                str(ttl_s),
                metadata,
            )
            return int(result)
        except Exception as evalsha_exc:
            # NOSCRIPT error means script not cached on this Redis instance
            # Fall through to EVAL which will re-cache it.
            # Check both exception type name and message for compatibility
            # with real Redis (raises ResponseError with "NOSCRIPT") and
            # fakeredis (raises NoScriptError with different message).
            exc_type_name = type(evalsha_exc).__name__
            exc_str = str(evalsha_exc).upper()
            is_noscript = (
                "NOSCRIPT" in exc_str
                or "NoScriptError" in exc_type_name
                or "No matching script" in str(evalsha_exc)
            )
            if not is_noscript:
                raise
            # Clear cached SHA so next call will use EVAL
            _ATOMIC_BURN_NONCE_SHA = None

    # Use EVAL (slower but always works) and cache the SHA for future calls
    result = await redis.eval(
        _ATOMIC_BURN_NONCE_LUA,
        1,  # number of keys
        nonce_key,
        str(ttl_s),
        metadata,
    )

    # Cache the script SHA for future EVALSHA calls
    # Note: We compute SHA1 of the script to match Redis's script SHA
    import hashlib as _hashlib

    # SHA1 is mandated by the Redis EVALSHA protocol as the script-cache key;
    # it carries no security property here (usedforsecurity=False).
    # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
    _ATOMIC_BURN_NONCE_SHA = _hashlib.sha1(
        _ATOMIC_BURN_NONCE_LUA.encode(), usedforsecurity=False
    ).hexdigest()

    return int(result)


async def verify_and_consume_seal(
    seal: str,
    action: str,
    params: dict,
    redis_client: Any = None,
    expected_record_hash: str | None = None,
    expected_aud: str | None = None,
) -> bool:
    """Verify a routing seal, then consume its nonce exactly once.

    Implements replay protection per the Cryptographic Governance Evolution spec
    (POAM-2026-089, decision D1: verify -> burn -> execute).

    Security invariant: a seal authorizes execution only for the single caller
    that wins the atomic nonce consume, and only a seal that has already passed
    cryptographic verification can consume a nonce. Verification is stateless
    (signature, ``kid`` trust anchor, expiry, ``action_hash``, evidence binding),
    so any number of concurrent callers may verify the same seal; the Redis
    ``SET NX EX`` Lua script then admits exactly one of them. A forged or
    mismatched seal is rejected before Redis is written, so it cannot burn the
    nonce of a genuine seal.

    Sequence:
        1. Parse the nonce and expiry (trusted only after step 3 verifies the
           same token).
        2. Resolve the expected evidence binding. Unless the caller supplies
           ``expected_record_hash``, it is read from the evidence index written
           at issuance, never from the seal itself (issue #379). A seal with
           no index entry is refused.
        3. ``verify_seal()`` -- stateless; any failure raises, nothing is written.
        4. Atomically write the nonce key via the Redis Lua script.
        5. If the key already existed, reject: as revoked if
           :func:`revoke_seal` wrote it, otherwise as a replay.

    Fail-closed: if Redis is unavailable or the script errors, a seal that
    verified is still refused.

    Args:
        seal: The routing seal string (JWT or HMAC format).
        action: The action being authorized (e.g., "execute_action").
        params: The parameters being authorized.
        redis_client: Optional async Redis client (defaults to global client).
        expected_record_hash: Expected evidence record hash. When omitted and
            evidence binding is required, it comes from the evidence index.
        expected_aud: Optional expected audience / executor identifier.

    Returns:
        True if the seal verified and this caller consumed its nonce.

    Raises:
        SymbolicGovernorViolation: On any failure (invalid seal, revoked,
            replay, Redis error).
    """
    import time as _time_module

    _start_ns = _time_module.time_ns()

    # Step 1: parse only. A non-string seal refuses here rather than escaping
    # as AttributeError (issue #379).
    try:
        nonce = seal_nonce(seal)
    except SymbolicGovernorViolation as exc:
        raise SymbolicGovernorViolation(exc.reason, action) from exc
    ttl = _seal_remaining_ttl(seal)

    try:
        redis = await _resolve_redis(redis_client)
    except Exception as exc:
        logger.error("⛔ [REPLAY_PROTECTION] Redis unavailable — fail-closed: %s", exc)
        raise SymbolicGovernorViolation(
            "replay protection unavailable (Redis connection failed)", action
        ) from exc

    # Step 2: the expected binding comes from the issuance-side index.
    if expected_record_hash is None and _require_evidence_binding():
        try:
            indexed = await redis.get(_evidence_index_key(nonce))
        except Exception as exc:
            raise SymbolicGovernorViolation(
                f"evidence index unavailable (Redis error): {type(exc).__name__}",
                action,
            ) from exc
        if isinstance(indexed, bytes):
            indexed = indexed.decode()
        if not indexed:
            logger.warning(
                "⛔ [EVIDENCE_BINDING] Seal has no evidence index entry: action=%s nonce=%s",
                action,
                nonce[:16] + "...",
            )
            raise SymbolicGovernorViolation(
                "seal is not bound to a committed evidence record", action
            )
        expected_record_hash = indexed

    # Step 3: verify before touching the nonce store.
    _verify_start_ns = _time_module.time_ns()
    try:
        verify_seal(
            seal=seal,
            action=action,
            params=params,
            expected_record_hash=expected_record_hash,
            expected_aud=expected_aud,
        )
    except SymbolicGovernorViolation:
        logger.warning(
            "🔒 [SEAL_INVALID] Seal verification failed; nonce not consumed: "
            "action=%s nonce=%s",
            action,
            nonce[:16] + "...",
        )
        raise
    _verify_elapsed_us = (_time_module.time_ns() - _verify_start_ns) // 1000

    # Step 4: single-winner consume.
    nonce_key = f"{_NONCE_PREFIX}{nonce}"
    burn_metadata = json.dumps(
        {
            "state": SealState.CONSUMED.value,
            "action": action,
            "burned_at": datetime.now(tz=timezone.utc).isoformat(),
            "nonce_prefix": nonce[:16],
        }
    )
    _burn_start_ns = _time_module.time_ns()
    try:
        burn_result = await _atomic_burn_nonce(
            redis, nonce_key, max(ttl + 60, 60), burn_metadata
        )
        _burn_elapsed_us = (_time_module.time_ns() - _burn_start_ns) // 1000

        if burn_result == 1:
            # Step 5: someone wrote the key first — a revocation or a consume.
            record = _parse_nonce_record(await redis.get(nonce_key))
            if record.get("state") == SealState.REVOKED.value:
                logger.warning(
                    "🔒 [SEAL_REVOKED] Revoked seal presented: action=%s nonce=%s",
                    action,
                    nonce[:16] + "...",
                )
                raise SymbolicGovernorViolation(
                    f"seal revoked: {record.get('reason', 'unspecified')}", action
                )
            logger.warning(
                "🔒 [REPLAY_ATTACK] Seal nonce already consumed (atomic check): "
                "action=%s nonce=%s burn_elapsed_us=%d",
                action,
                nonce[:16] + "...",
                _burn_elapsed_us,
            )
            raise SymbolicGovernorViolation(
                "replay attack detected — seal already consumed", action
            )
    except SymbolicGovernorViolation:
        raise
    except Exception as exc:
        logger.error(
            "⛔ [REPLAY_PROTECTION] Redis Lua script failed — fail-closed: %s", exc
        )
        raise SymbolicGovernorViolation(
            f"replay protection failed (Redis error): {exc}", action
        ) from exc

    _total_elapsed_us = (_time_module.time_ns() - _start_ns) // 1000
    logger.debug(
        "✅ [SEAL_CONSUMED] Seal verified, then nonce consumed atomically: "
        "action=%s nonce=%s total_us=%d verify_us=%d burn_us=%d",
        action,
        nonce[:16] + "...",
        _total_elapsed_us,
        _verify_elapsed_us,
        _burn_elapsed_us,
    )
    # This caller owns the seal: the model's SEAL_ISSUED -> EXECUTED step.
    # Best effort; the trace never changes the authorisation decided above.
    from src.gateway.governance.governor.trace import (
        executed_trace_event,
        publish_trace,
    )

    await publish_trace(executed_trace_event(seal, action=action))
    return True


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------


class SealState(str, Enum):
    """Lifecycle of a seal's single-use nonce record."""

    UNUSED = "unused"
    CONSUMED = "consumed"
    REVOKED = "revoked"


def _seal_remaining_ttl(seal: str) -> int:
    """Seconds until the seal's (unverified) expiry; ``_TTL_S`` if unparseable.

    Only sizes Redis key lifetimes. Expiry itself is enforced by
    :func:`verify_seal` on the verified token.
    """
    try:
        if _is_jwt_seal(seal):
            claims = _unverified_claims(seal)
            return int(claims.get("exp", 0)) - int(time.time())
        return int(seal.split(".", 1)[0], 16) - int(time.time())
    except Exception:
        return _TTL_S


def _parse_nonce_record(raw: Any) -> dict[str, Any]:
    if isinstance(raw, bytes):
        raw = raw.decode()
    if not raw:
        return {}
    try:
        record = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return record if isinstance(record, dict) else {}


async def revoke_seal(seal: str, reason: str, redis_client: Any = None) -> bool:
    """Revoke an unconsumed seal before it expires.

    Revocation writes the seal's nonce key, the same key consumption writes,
    with the same ``SET NX``. Whichever happens first wins: a revoked seal can
    never be consumed (:func:`verify_and_consume_seal` reports it as revoked),
    and a consumed seal cannot be revoked after the fact, because the action
    it authorised may already have run.

    The key outlives the seal's own expiry, after which ``verify_seal`` refuses
    it anyway. Revocation never requires the seal to verify: refusing a forged
    or malformed seal costs nothing.

    Args:
        seal: The seal to revoke.
        reason: Short operator-supplied reason, recorded and reported.
        redis_client: Optional async Redis client (defaults to global client).

    Returns:
        True if this call revoked the seal; False if it was already consumed
        or revoked.

    Raises:
        SymbolicGovernorViolation: If the seal is malformed or Redis fails.
    """
    nonce = seal_nonce(seal)
    record = json.dumps(
        {
            "state": SealState.REVOKED.value,
            "reason": reason[:200],
            "revoked_at": datetime.now(tz=timezone.utc).isoformat(),
            "nonce_prefix": nonce[:16],
        }
    )
    try:
        redis = await _resolve_redis(redis_client)
        written = await redis.set(
            f"{_NONCE_PREFIX}{nonce}",
            record,
            nx=True,
            ex=max(_seal_remaining_ttl(seal) + 60, 60),
        )
    except Exception as exc:
        raise SymbolicGovernorViolation(
            f"revocation failed (Redis error): {type(exc).__name__}"
        ) from exc
    if written:
        logger.warning(
            "🔒 [SEAL_REVOKED] nonce=%s reason=%s", nonce[:16] + "...", reason[:200]
        )
    return bool(written)


async def seal_state(seal: str, redis_client: Any = None) -> SealState:
    """Report whether a seal's nonce is unused, consumed or revoked.

    Raises:
        SymbolicGovernorViolation: If the seal is malformed or Redis fails.
    """
    nonce = seal_nonce(seal)
    try:
        raw = await (await _resolve_redis(redis_client)).get(f"{_NONCE_PREFIX}{nonce}")
    except Exception as exc:
        raise SymbolicGovernorViolation(
            f"seal state unavailable (Redis error): {type(exc).__name__}"
        ) from exc
    if not raw:
        return SealState.UNUSED
    if _parse_nonce_record(raw).get("state") == SealState.REVOKED.value:
        return SealState.REVOKED
    return SealState.CONSUMED


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
        action:  Action name that was approved (e.g. ``"execute_action"``).
        params:  Parameters dict that was approved — must match the seal.

    Returns:
        A decorator that wraps the target callable with seal verification.

    Raises:
        SymbolicGovernorViolation: If the seal is invalid or expired, raised
            before the wrapped callable is invoked.

    Example::

        @require_cleared_seal(seal, "execute_action", params)
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

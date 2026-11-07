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
CAGE Gateway Client - Out-of-Process Policy Enforcement Point (PEP).

This module provides the ``CageClient`` HTTP client that communicates with the
CAGE Gateway Policy Decision Point (PDP) over TLS/mTLS (with optional HTTP/2)
and verifies returned ``GovernanceEnvelope`` decisions fail-closed by default:
  - Out-of-band ``kid`` public-key resolution via ``/governance/.well-known/jwks.json``
    (``JwksKeyResolver`` with bounded TTL and ``max_jwks_staleness_s`` eviction)
    or pinned ``public_keys`` — never from embedded envelope keys
  - Signature verification over RFC 8785 JCS canonical bytes accepting exactly
    ``ES256`` (EC P-256) and ``EdDSA`` (Ed25519), the two algorithms the gateway
    signs with; every other algorithm and key type is rejected
  - ``expires_at`` freshness (within ``clock_skew_seconds``) and ``expires_at > issued_at``
  - ``subject.action`` and ``subject.action_hash`` request binding against replay
  - Values acted on exactly as signed: the response is parsed as strict JSON (a
    repeated key or ``NaN`` is refused) and nothing is stripped, case-folded or
    coerced before the signature block, timestamps, subject and verdict are read

Security & Verification Scope:
    1. By default (``verify_signature=True``, ``verify_expiration=True``,
       ``verify_subject=True``), ``CageClient`` verifies cryptographic signature,
       temporal freshness, and request-subject binding on every HTTP ``200``
       ``GovernanceEnvelope`` **before** returning ``ALLOW`` or dispatching
       ``NARROW`` / ``DENY`` / ``DEFER`` / ``REQUIRE_APPROVAL`` verdicts.
       Disabling verification is blocked at startup in any non-dev/test
       ``CAGE_ENV`` posture.
    2. **TLS/mTLS in ``transport.py`` protects only the point-to-point transport
       channel and does NOT substitute for end-to-end ``GovernanceEnvelope.signature``
       verification** (the envelope carries an asymmetric signature specifically
       so trust does not rest solely on transport or proxy configuration).
"""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import logging
import math
import os
import re
import secrets
import time
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from types import TracebackType
from typing import Any, NoReturn

import httpx

from . import transport
from ._jcs import canonicalize
from .crypto import (
    compute_expected_action_hash,
    generate_w3c_traceparent,
    load_pinned_public_key,
    verify_envelope_signature,
)
from .envelope import GovernanceEnvelope
from .exceptions import (
    CageGatewayError,
    DeferralPending,
    PolicyViolationException,
    RoutingSealVerificationError,
)
from .jwks import JwksKeyResolver, PublicKey, validate_http_url

# Check for optional HTTP/2 support (h2 package)
_HTTP2_AVAILABLE = importlib.util.find_spec("h2") is not None

_BRACKETED_CODE_RE = re.compile(r"^\[([A-Za-z0-9_.:-]+)\]\s+")
_DEV_POSTURES: frozenset[str] = frozenset(
    {"dev", "development", "local", "test", "testing"}
)
_ALLOWED_SIGNATURE_KEYS: frozenset[str] = frozenset({"algorithm", "kid", "value"})
_EMBEDDED_KEY_FIELDS: frozenset[str] = frozenset(
    {"public_key", "public_key_pem", "jwk", "jwks", "x5c", "x5u", "jku"}
)

logger = logging.getLogger("CageClient")


def _first_violation_code(violations: Any) -> str | None:
    """Return the first non-empty code from structured violation dicts or ``[CODE] msg`` strings."""
    if not isinstance(violations, list):
        return None
    for item in violations:
        if isinstance(item, dict):
            code = item.get("code")
            if isinstance(code, str) and code.strip():
                return code.strip()
        elif isinstance(item, str):
            match = _BRACKETED_CODE_RE.match(item.strip())
            if match:
                return match.group(1)
    return None


def _refuse_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """JSON object hook: a key named twice is refused, never resolved last-wins."""
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise RoutingSealVerificationError(
                f"Refusing GovernanceEnvelope response with duplicate JSON object key {key!r}"
            )
        obj[key] = value
    return obj


def _refuse_non_finite_number(token: str) -> NoReturn:
    """JSON constant hook: ``NaN`` and ``Infinity`` are not JSON (RFC 8259)."""
    raise RoutingSealVerificationError(
        f"Refusing GovernanceEnvelope response with non-finite JSON number {token}"
    )


def enforce_verification_posture(
    *,
    verify_signature: bool = True,
    verify_expiration: bool = True,
    verify_subject: bool = True,
) -> None:
    """Reject verification opt-outs when running in any non-dev/test posture."""
    raw_env = (
        os.environ.get("CAGE_ENV", "").strip()
        or os.environ.get("ENVIRONMENT", "").strip()
    ).lower()
    if raw_env and raw_env not in _DEV_POSTURES:
        if not verify_signature or not verify_expiration or not verify_subject:
            raise ValueError(
                f"Disabling GovernanceEnvelope verification "
                f"(verify_signature={verify_signature}, "
                f"verify_expiration={verify_expiration}, "
                f"verify_subject={verify_subject}) is forbidden in "
                f"enforcing posture {raw_env!r}"
            )


class CageClient:
    """
    Out-of-process Policy Enforcement Point for CAGE governance.

    Submits proposed actions to the CAGE Gateway for governance evaluation over
    a persistent connection pool with optional mTLS transport authentication and
    default fail-closed ``GovernanceEnvelope`` cryptographic verification.
    """

    def __init__(
        self,
        gateway_url: str,
        mtls_certs: tuple[str, str, str] | None = None,
        timeout_s: float = 5.0,
        public_keys: Mapping[str, Any] | None = None,
        verify_signature: bool = True,
        verify_expiration: bool = True,
        verify_subject: bool = True,
        clock_skew_seconds: float = 5.0,
        jwks_ttl_s: float = 300.0,
        max_jwks_staleness_s: float = 3600.0,
        *,
        jwks_uri: str | None = None,
        jwks_clock: Callable[[], float] | None = None,
        jwks_min_refresh_interval_s: float = 5.0,
    ) -> None:
        """
        Initialize the CAGE Gateway client.

        Args:
            gateway_url: Base URL of the CAGE Gateway API (no trailing slash)
            mtls_certs: Optional tuple of (cert_path, key_path, ca_path) for mutual TLS
            timeout_s: Request timeout in seconds (default: 5.0)
            public_keys: Optional out-of-band ``kid -> PEM/PublicKey/JWK`` trust anchors.
                When ``None`` and ``verify_signature=True``, keys are resolved via
                ``{gateway_url}/governance/.well-known/jwks.json``.
            verify_signature: Verify ``GovernanceEnvelope.signature`` out-of-band (default: True)
            verify_expiration: Enforce ``GovernanceEnvelope.expires_at`` freshness (default: True)
            verify_subject: Enforce ``subject.action`` and ``subject.action_hash`` binding (default: True)
            clock_skew_seconds: Allowed clock skew in seconds for ``expires_at`` (default: 5.0)
            jwks_ttl_s: Monotonic TTL in seconds before inline JWKS refresh (default: 300.0)
            max_jwks_staleness_s: Hard staleness ceiling in seconds before fail-closed eviction (default: 3600.0)
            jwks_uri: Optional explicit JWKS URL override
            jwks_clock: Optional monotonic clock callable for JWKS cache testing
            jwks_min_refresh_interval_s: Cooldown between unknown-``kid`` JWKS refresh retries (default: 5.0)

        Raises:
            ValueError: Invalid URL/timing config, half-configured mTLS, or verification opt-out in enforcing ``CAGE_ENV``
            FileNotFoundError: If mTLS certificate paths are invalid (fail-closed)
        """
        cleaned_gateway = validate_http_url(
            gateway_url, field_name="gateway_url"
        ).rstrip("/")
        if not math.isfinite(timeout_s) or timeout_s <= 0:
            raise ValueError("timeout_s must be a finite number > 0")
        if not math.isfinite(clock_skew_seconds) or clock_skew_seconds < 0:
            raise ValueError("clock_skew_seconds must be a finite number >= 0")
        if not math.isfinite(jwks_ttl_s) or jwks_ttl_s <= 0:
            raise ValueError("jwks_ttl_s must be a finite number > 0")
        if not math.isfinite(max_jwks_staleness_s) or max_jwks_staleness_s < jwks_ttl_s:
            raise ValueError("max_jwks_staleness_s must be finite and >= jwks_ttl_s")

        enforce_verification_posture(
            verify_signature=verify_signature,
            verify_expiration=verify_expiration,
            verify_subject=verify_subject,
        )

        self.gateway_url = cleaned_gateway
        self.timeout_s = timeout_s
        self._verify_signature = verify_signature
        self._verify_expiration = verify_expiration
        self._verify_subject = verify_subject
        self._clock_skew_seconds = float(clock_skew_seconds)
        self._public_keys: dict[str, Any] | None = (
            dict(public_keys) if public_keys is not None else None
        )
        self._parsed_pinned_keys: dict[str, PublicKey] = {}
        if self._public_keys is not None:
            for pinned_kid, pinned_raw in self._public_keys.items():
                if not isinstance(pinned_kid, str) or not pinned_kid.strip():
                    raise RoutingSealVerificationError(
                        "Pinned public_keys must use non-empty string kid keys"
                    )
                self._parsed_pinned_keys[pinned_kid] = load_pinned_public_key(
                    pinned_raw, kid=pinned_kid
                )

        effective_jwks_uri = jwks_uri
        if (
            effective_jwks_uri is None
            and verify_signature
            and self._public_keys is None
        ):
            effective_jwks_uri = f"{self.gateway_url}/governance/.well-known/jwks.json"
        self._jwks_resolver: JwksKeyResolver | None = (
            JwksKeyResolver(
                jwks_uri=effective_jwks_uri,
                ttl_s=jwks_ttl_s,
                max_staleness_s=max_jwks_staleness_s,
                min_refresh_interval_s=jwks_min_refresh_interval_s,
                clock=jwks_clock or time.monotonic,
            )
            if effective_jwks_uri is not None
            else None
        )

        if mtls_certs:
            cert_path, key_path, ca_path = mtls_certs
            http_transport = transport.create_mtls_transport(
                cert_path=cert_path, key_path=key_path, ca_path=ca_path
            )
        else:
            http_transport = transport.create_mtls_transport()

        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_s),
            http2=_HTTP2_AVAILABLE,
            follow_redirects=False,
            transport=http_transport,
        )

        logger.info(
            "CageClient initialized: gateway=%s, mtls_enabled=%s, verify_signature=%s",
            self.gateway_url,
            mtls_certs is not None,
            self._verify_signature,
        )

    async def validate_action(
        self,
        action: str,
        parameters: dict[str, Any],
        agent_id: str,
        context: dict[str, Any] | None = None,
    ) -> GovernanceEnvelope:
        """
        Submit an action to the CAGE Gateway for HTTP PEP governance mediation.

        Sends ``POST /governance/validate-action`` and verifies + mediates the
        gateway response fail-closed:
          - 200 OK (verified ``ALLOW``) → Return verified ``GovernanceEnvelope``
          - 200 OK (verified ``NARROW`` / ``DENY`` / ``DENIED``) or 403/422 → Raise ``PolicyViolationException``
          - 200 OK (verified ``DEFER`` / ``REQUIRE_APPROVAL``) or 202/409 → Raise ``DeferralPending``
          - Signature, ``kid``, freshness, or ``subject.action_hash`` failure → Raise ``RoutingSealVerificationError``

        Security & Verification Scope:
            1. By default, ``CageClient`` verifies ``GovernanceEnvelope.signature``
               against an out-of-band ``kid`` trust anchor (``JwksKeyResolver`` or
               pinned ``public_keys``), enforces ``expires_at`` freshness, and
               verifies ``subject.action`` + ``subject.action_hash`` request
               binding before dispatching any HTTP 200 verdict.
            2. **TLS/mTLS in ``transport.py`` protects only the point-to-point
               transport channel and does NOT substitute for end-to-end envelope
               signature verification.**
        """
        canonical_params = self._canonicalize_params(parameters)
        param_hash = hashlib.sha256(canonical_params.encode("utf-8")).hexdigest()

        traceparent = generate_w3c_traceparent()
        correlation_id = secrets.token_hex(16)

        payload: dict[str, Any] = {
            "action": action,
            "params": parameters,
            "parameters": parameters,
            "parameter_hash": param_hash,
            "agent_id": agent_id,
            "context": context or {},
            "correlation_id": correlation_id,
        }

        headers = {
            "Content-Type": "application/json",
            "traceparent": traceparent,
            "X-Correlation-ID": correlation_id,
            "User-Agent": "CageClient/3.0",
        }

        endpoint = f"{self.gateway_url}/governance/validate-action"

        logger.debug(
            "Submitting action for validation: action=%s, agent_id=%s, correlation_id=%s",
            action,
            agent_id,
            correlation_id,
        )

        try:
            response = await self._client.post(endpoint, json=payload, headers=headers)
        except httpx.RequestError as exc:
            logger.error(
                "Network error communicating with gateway: %s", exc, exc_info=True
            )
            raise CageGatewayError(
                f"Failed to reach CAGE Gateway at {endpoint}: {exc}"
            ) from exc

        if response.status_code == 200:
            return await self._handle_allow_response(
                response, action=action, parameters=parameters
            )

        if response.status_code in (403, 422):
            self._handle_deny_response(response)
            raise AssertionError("_handle_deny_response must raise")

        if response.status_code in (202, 409):
            self._handle_defer_response(response)
            raise AssertionError("_handle_defer_response must raise")

        if response.status_code >= 500:
            logger.error(
                "Gateway server error: status=%s, body=%s",
                response.status_code,
                response.text[:500],
            )
            raise CageGatewayError(
                f"Gateway server error (status {response.status_code}): {response.text[:200]}"
            )

        logger.error(
            "Unexpected gateway response: status=%s, body=%s",
            response.status_code,
            response.text[:500],
        )
        raise CageGatewayError(
            f"Unexpected gateway response (status {response.status_code}): {response.text[:200]}"
        )

    async def _resolve_public_key(self, kid: str) -> PublicKey:
        """Resolve ``kid`` strictly out-of-band from pinned ``public_keys`` or ``JwksKeyResolver``."""
        if self._public_keys is not None:
            if kid in self._public_keys:
                cached = self._parsed_pinned_keys.get(kid)
                if cached is None:
                    cached = load_pinned_public_key(self._public_keys[kid], kid=kid)
                    self._parsed_pinned_keys[kid] = cached
                return cached
            if self._jwks_resolver is None:
                raise RoutingSealVerificationError(
                    f"GovernanceEnvelope signed by unknown kid={kid!r}"
                )
        if self._jwks_resolver is not None:
            return await self._jwks_resolver.resolve_key(kid, self._client)
        raise RoutingSealVerificationError(
            "No out-of-band trust anchor configured for signature verification"
        )

    @staticmethod
    def _reject_embedded_key_material(raw_envelope_data: dict[str, Any]) -> None:
        """Reject self-supplied public keys or unexpected fields inside ``signature``."""
        if _EMBEDDED_KEY_FIELDS.intersection(raw_envelope_data.keys()):
            raise RoutingSealVerificationError(
                "Refusing GovernanceEnvelope containing embedded key material"
            )
        issuer = raw_envelope_data.get("issuer")
        if isinstance(issuer, Mapping) and _EMBEDDED_KEY_FIELDS.intersection(
            issuer.keys()
        ):
            raise RoutingSealVerificationError(
                "Refusing GovernanceEnvelope containing embedded key material in issuer"
            )
        raw_sig = raw_envelope_data.get("signature")
        if isinstance(raw_sig, Mapping):
            unexpected_sig_keys = set(raw_sig.keys()) - _ALLOWED_SIGNATURE_KEYS
            if unexpected_sig_keys:
                raise RoutingSealVerificationError(
                    f"GovernanceEnvelope signature block contains unexpected or embedded-key fields: "
                    f"{sorted(unexpected_sig_keys)!r}"
                )

    async def _verify_signature_block(
        self, raw_envelope_data: dict[str, Any], envelope: GovernanceEnvelope
    ) -> None:
        sig = envelope.signature
        if not isinstance(sig, dict):
            raise RoutingSealVerificationError(
                "GovernanceEnvelope is missing required 'signature' block"
            )
        unexpected_sig_keys = set(sig.keys()) - _ALLOWED_SIGNATURE_KEYS
        if unexpected_sig_keys:
            raise RoutingSealVerificationError(
                f"GovernanceEnvelope signature block contains unexpected fields: "
                f"{sorted(unexpected_sig_keys)!r}"
            )
        kid = sig.get("kid", "")
        alg = sig.get("algorithm", "")
        sig_val = sig.get("value", "")
        if not kid or not alg or not sig_val:
            raise RoutingSealVerificationError(
                "GovernanceEnvelope signature block is incomplete (requires algorithm, kid, value)"
            )

        public_key = await self._resolve_public_key(kid)
        unsigned_dict = {k: v for k, v in raw_envelope_data.items() if k != "signature"}
        try:
            canonical_bytes = canonicalize(unsigned_dict)
        except Exception as exc:
            raise RoutingSealVerificationError(
                f"Failed to canonicalize GovernanceEnvelope with RFC 8785 JCS: {exc}"
            ) from exc

        verify_envelope_signature(
            canonical_bytes=canonical_bytes,
            algorithm=alg,
            signature_b64=sig_val,
            public_key=public_key,
        )

    def _verify_timestamps(self, envelope: GovernanceEnvelope) -> None:
        if (
            envelope.issued_at.tzinfo is None
            or envelope.issued_at.utcoffset() is None
            or envelope.expires_at.tzinfo is None
            or envelope.expires_at.utcoffset() is None
        ):
            raise RoutingSealVerificationError(
                "GovernanceEnvelope issued_at and expires_at must be timezone-aware"
            )
        if envelope.expires_at <= envelope.issued_at:
            raise RoutingSealVerificationError(
                "GovernanceEnvelope expires_at must be strictly after issued_at"
            )
        if self._verify_expiration:
            now_utc = datetime.now(timezone.utc)
            skew = timedelta(seconds=self._clock_skew_seconds)
            if envelope.issued_at - skew > now_utc:
                raise RoutingSealVerificationError(
                    f"GovernanceEnvelope issued_at is in the future beyond clock skew "
                    f"(issued_at={envelope.issued_at.isoformat()})"
                )
            if envelope.expires_at + skew <= now_utc:
                raise RoutingSealVerificationError(
                    f"GovernanceEnvelope has expired (expires_at={envelope.expires_at.isoformat()})"
                )

    def _verify_subject_binding(
        self,
        envelope: GovernanceEnvelope,
        *,
        action: str | None,
        parameters: Mapping[str, Any] | None,
    ) -> None:
        if not action or parameters is None:
            raise RoutingSealVerificationError(
                "GovernanceEnvelope subject verification requires request action and parameters"
            )
        subject_action = envelope.subject.get("action")
        if not isinstance(subject_action, str) or subject_action != action:
            raise RoutingSealVerificationError(
                f"GovernanceEnvelope subject.action mismatch: expected {action!r}, got {subject_action!r}"
            )
        subject_hash = envelope.subject.get("action_hash")
        if not isinstance(subject_hash, str) or not subject_hash:
            raise RoutingSealVerificationError(
                "GovernanceEnvelope subject is missing required 'action_hash'"
            )
        expected_hash = compute_expected_action_hash(action, parameters)
        if not hmac.compare_digest(
            subject_hash.encode("utf-8"),
            expected_hash.encode("utf-8"),
        ):
            raise RoutingSealVerificationError(
                "GovernanceEnvelope subject.action_hash does not match requested action parameters"
            )

    @staticmethod
    def _extract_envelope_dict(response_data: Any) -> dict[str, Any]:
        """Extract canonical envelope dict from wrapped or top-level wire format."""
        if not isinstance(response_data, dict):
            raise CageGatewayError("ALLOW response must be a JSON object")
        envelope_data = response_data.get("envelope")
        if isinstance(envelope_data, dict) and envelope_data:
            return envelope_data
        if (
            not envelope_data
            and "envelope_version" in response_data
            and "payload" in response_data
            and "subject" in response_data
        ):
            return response_data
        raise CageGatewayError("ALLOW response missing required 'envelope' field")

    @staticmethod
    def _mediate_narrow_verdict(envelope: GovernanceEnvelope) -> None:
        narrowed_params = envelope.payload.get("narrowed_params")
        if not isinstance(narrowed_params, dict):
            raise CageGatewayError(
                "NARROW envelope missing required 'narrowed_params' object"
            )
        audit_id = envelope.payload.get("audit_id") or envelope.envelope_id
        if not audit_id:
            raise CageGatewayError(
                "NARROW envelope missing required 'audit_id' or 'envelope_id'"
            )
        raise PolicyViolationException(
            reason_code="NARROWED",
            violation_details={
                "narrowed_params": narrowed_params,
                "violations": envelope.payload.get("violations") or [],
            },
            audit_id=str(audit_id),
            recoverable=True,
        )

    @staticmethod
    def _mediate_deny_verdict(envelope: GovernanceEnvelope) -> None:
        audit_id = envelope.payload.get("audit_id") or envelope.envelope_id
        if not audit_id:
            raise CageGatewayError(
                "DENY envelope missing required 'audit_id' or 'envelope_id'"
            )
        violations = envelope.payload.get("violations", [])
        reason_code = (
            envelope.payload.get("reason_code")
            or _first_violation_code(violations)
            or "POLICY_DENIED"
        )
        raw_details = envelope.payload.get("details")
        details = (
            raw_details if isinstance(raw_details, dict) else {"violations": violations}
        )
        recoverable = bool(envelope.payload.get("recoverable", True))
        raise PolicyViolationException(
            reason_code=str(reason_code),
            violation_details=details,
            audit_id=str(audit_id),
            recoverable=recoverable,
        )

    @staticmethod
    def _mediate_defer_verdict(envelope: GovernanceEnvelope) -> None:
        # Never fall back to envelope.envelope_id: when DeferQueue persistence
        # fails on REQUIRE_APPROVAL, the gateway sets deferred_id=None so the
        # client treats the unpersisted hold as a fail-closed error rather than
        # polling an unapprovable envelope UUID.
        ticket_id = (
            envelope.payload.get("deferred_id")
            or envelope.payload.get("defer_token")
            or envelope.payload.get("defer_id")
            or envelope.payload.get("ticket_id")
        )
        if not ticket_id:
            raise CageGatewayError(
                "DEFER envelope missing required 'deferred_id', 'defer_token', 'defer_id', or 'ticket_id'"
            )
        defer_reason = str(
            envelope.payload.get("defer_reason")
            or envelope.payload.get("classification_reason")
            or envelope.payload.get("reason")
            or "Human approval required"
        )
        ttl_seconds = int(
            envelope.payload.get("ttl_seconds")
            or envelope.payload.get("retry_after_seconds")
            or 14400
        )
        raise DeferralPending(
            ticket_id=str(ticket_id),
            defer_reason=defer_reason,
            expires_at=envelope.expires_at,
            ttl_seconds=ttl_seconds,
        )

    async def _handle_allow_response(
        self,
        response: httpx.Response,
        *,
        action: str | None = None,
        parameters: Mapping[str, Any] | None = None,
    ) -> GovernanceEnvelope:
        """
        Parse, cryptographically verify, and mediate an HTTP 200 envelope response.

        Verifies out-of-band ``kid`` signature, ``expires_at`` freshness, and
        ``subject.action`` + ``subject.action_hash`` request binding **before**
        returning ``ALLOW`` or dispatching ``NARROW``, ``DENY``/``DENIED``, or
        ``DEFER``/``REQUIRE_APPROVAL`` verdicts.

        Security & Verification Scope:
            1. ``GovernanceEnvelope.signature``, ``expires_at``, and ``subject``
               request binding are verified fail-closed by default (raising
               ``RoutingSealVerificationError`` on any failure).
            2. **TLS/mTLS in ``transport.py`` protects only the point-to-point
               transport channel and does NOT substitute for end-to-end envelope
               signature verification.**
        """
        # The signature covers one reading of these bytes, so refuse JSON that a
        # second parser could read differently (a repeated key) or that is not
        # JSON at all (NaN, Infinity) rather than resolving it silently.
        try:
            response_data = json.loads(
                response.content,
                object_pairs_hook=_refuse_duplicate_keys,
                parse_constant=_refuse_non_finite_number,
            )
        except json.JSONDecodeError as exc:
            raise CageGatewayError(f"Invalid JSON in ALLOW response: {exc}") from exc

        envelope_data = self._extract_envelope_dict(response_data)
        if self._verify_signature:
            self._reject_embedded_key_material(envelope_data)

        try:
            envelope = GovernanceEnvelope(**envelope_data)
        except Exception as exc:
            raise CageGatewayError(
                f"Failed to parse governance envelope: {exc}"
            ) from exc

        if self._verify_signature:
            await self._verify_signature_block(envelope_data, envelope)
        self._verify_timestamps(envelope)
        if self._verify_subject:
            self._verify_subject_binding(envelope, action=action, parameters=parameters)

        # Matched exactly as signed: no case folding, no coercion to str.
        verdict = envelope.payload.get("verdict") or envelope.payload.get("decision")

        if verdict == "NARROW":
            self._mediate_narrow_verdict(envelope)
        if verdict in ("DENY", "DENIED"):
            self._mediate_deny_verdict(envelope)
        if verdict in ("DEFER", "REQUIRE_APPROVAL"):
            self._mediate_defer_verdict(envelope)
        if verdict != "ALLOW":
            raise CageGatewayError(
                f"Gateway envelope carries unrecognised verdict {verdict!r}"
            )

        logger.info(
            "Action ALLOWED: action=%s, agent_id=%s",
            envelope.subject.get("action"),
            envelope.subject.get("agent_id"),
        )
        return envelope

    def _handle_deny_response(self, response: httpx.Response) -> None:
        """
        Parse a 403/422 (DENY) response and raise PolicyViolationException.

        Supports both the canonical gateway v2.0.0 refusal wire format
        (``proof_hash``, ``violations``, ``refusal_receipt``) and legacy
        ``audit_id`` / ``reason_code`` / ``details`` payloads.
        """
        try:
            response_data = response.json()
        except json.JSONDecodeError as exc:
            raise CageGatewayError(f"Invalid JSON in DENY response: {exc}") from exc

        if not isinstance(response_data, dict):
            raise CageGatewayError("DENY response must be a JSON object")

        raw_receipt = response_data.get("refusal_receipt")
        receipt_dict = raw_receipt if isinstance(raw_receipt, dict) else {}

        audit_id = (
            response_data.get("audit_id")
            or response_data.get("proof_hash")
            or receipt_dict.get("proof_hash")
        )
        if not audit_id:
            raise CageGatewayError(
                "DENY response missing required 'audit_id' field (or 'proof_hash')"
            )

        violations = response_data.get("violations", [])
        reason_code = (
            response_data.get("reason_code")
            or _first_violation_code(violations)
            or receipt_dict.get("violated_rule")
            or "UNKNOWN_VIOLATION"
        )

        if "details" in response_data and isinstance(response_data["details"], dict):
            violation_details = response_data["details"]
        else:
            violation_details = {"violations": violations}
            if "refusal_receipt" in response_data:
                violation_details["refusal_receipt"] = response_data["refusal_receipt"]

        recoverable = bool(response_data.get("recoverable", True))

        logger.warning(
            "Action DENIED: reason_code=%s, audit_id=%s, recoverable=%s",
            reason_code,
            audit_id,
            recoverable,
        )

        raise PolicyViolationException(
            reason_code=str(reason_code),
            violation_details=violation_details,
            audit_id=str(audit_id),
            recoverable=recoverable,
        )

    def _handle_defer_response(self, response: httpx.Response) -> None:
        """
        Parse a 202/409 (DEFER) response and raise DeferralPending.

        Supports both the canonical gateway v1.0.0 EXTERNAL_HOLD receipt format
        (``defer_id``, ``defer_reason``, ``poll_url``, ``ttl_seconds``) and
        legacy ``ticket_id`` / ``reason`` payloads.
        """
        try:
            response_data = response.json()
        except json.JSONDecodeError as exc:
            raise CageGatewayError(f"Invalid JSON in DEFER response: {exc}") from exc

        if not isinstance(response_data, dict):
            raise CageGatewayError("DEFER response must be a JSON object")

        ticket_id = (
            response_data.get("ticket_id")
            or response_data.get("defer_id")
            or response_data.get("deferred_id")
            or response_data.get("defer_token")
        )
        if not ticket_id:
            raise CageGatewayError(
                "DEFER response missing required 'ticket_id' field (or 'defer_id')"
            )

        defer_reason = str(
            response_data.get("defer_reason")
            or response_data.get("reason")
            or "Human approval required"
        )
        expires_at_str = response_data.get("expires_at")
        ttl_seconds = int(response_data.get("ttl_seconds", 14400))

        if expires_at_str:
            try:
                expires_at = datetime.fromisoformat(
                    str(expires_at_str).replace("Z", "+00:00")
                )
            except ValueError as exc:
                raise CageGatewayError(
                    f"Invalid expires_at timestamp: {expires_at_str}"
                ) from exc
        else:
            expires_at = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(
                seconds=ttl_seconds
            )

        logger.info(
            "Action DEFERRED: ticket_id=%s, expires_at=%s",
            ticket_id,
            expires_at.isoformat(),
        )

        raise DeferralPending(
            ticket_id=str(ticket_id),
            defer_reason=defer_reason,
            expires_at=expires_at,
            ttl_seconds=ttl_seconds,
        )

    @staticmethod
    def _canonicalize_params(params: dict[str, Any]) -> str:
        """Canonicalize parameters dictionary into deterministic sorted-key JSON."""
        return json.dumps(params, sort_keys=True, separators=(",", ":"))

    async def aclose(self) -> None:
        """Cleanly shut down the HTTP/2 client and release connection pool resources."""
        await self._client.aclose()
        logger.info("CageClient closed")

    async def __aenter__(self) -> CageClient:
        """Async context manager entry."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> bool:
        """Async context manager exit."""
        await self.aclose()
        return False

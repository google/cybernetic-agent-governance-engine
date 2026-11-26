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
       temporal freshness, and request-subject binding on every HTTP ``200`` and
       HTTP ``403`` ``GovernanceEnvelope`` **before** returning ``ALLOW`` or
       dispatching ``NARROW`` / ``DENY`` / ``DEFER`` / ``REQUIRE_APPROVAL``
       verdicts. Unsigned ``202`` / ``409`` / ``422`` responses and non-envelope
       ``403`` responses fail closed with ``CageGatewayError`` and are never
       mediated as verified deferrals or policy denials. Disabling verification
       is blocked at startup in any non-dev/test ``CAGE_ENV`` posture.
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
from .envelope import _RFC3339_TIMESTAMP, GovernanceEnvelope
from .exceptions import (
    CageGatewayError,
    CommitOutcomeDecodeError,
    DeferralPending,
    GatewayUnavailableError,
    PolicyViolationException,
    RoutingSealVerificationError,
)
from .jwks import JwksKeyResolver, PublicKey, validate_http_url
from .outcomes import (
    INDETERMINATE_STATUSES,
    CommitOutcome,
    CommitStatus,
    GovernanceDecision,
    IndeterminateProvenance,
    PreviewResult,
    _validate_json_scalars,
    verify_commit_outcome_payload,
)

# Check for optional HTTP/2 support (h2 package)
_HTTP2_AVAILABLE = importlib.util.find_spec("h2") is not None

_USER_AGENT = "CageClient/0.5.0"
_DEFAULT_DEFER_TTL_S = 14400
_BRACKETED_CODE_RE = re.compile(r"^\[([A-Za-z0-9_.:-]+)\]\s+")
_DEV_POSTURES: frozenset[str] = frozenset({"dev", "development", "test", "testing"})
_ALLOWED_SIGNATURE_KEYS: frozenset[str] = frozenset({"algorithm", "kid", "value"})
_EMBEDDED_KEY_FIELDS: frozenset[str] = frozenset(
    {"public_key", "public_key_pem", "jwk", "jwks", "x5c", "x5u", "jku"}
)
_PRE_DISPATCH_CONNECT_ERRORS = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.PoolTimeout,
)

logger = logging.getLogger("CageClient")


def _non_blank_str(value: Any) -> str | None:
    """Return ``value`` as-is when it is a string with non-whitespace content, else ``None``."""
    if isinstance(value, str) and value.strip():
        return value
    return None


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
    subject_label: str = "GovernanceEnvelope",
) -> None:
    """Reject verification opt-outs unless running in an explicit dev/test posture.

    Unset/blank ``CAGE_ENV`` and ``ENVIRONMENT`` default fail-secure to
    ``"production"``, and ``"local"`` is enforcing (matching kernel
    ``env_posture.is_enforcing()``; POAM-2026-241). Whenever an opt-out is
    permitted in an explicit dev/test posture, emit a warning so permissive
    settings are never silent.
    """
    raw_env = (
        os.environ.get("CAGE_ENV", "").strip()
        or os.environ.get("ENVIRONMENT", "").strip()
        or "production"
    ).lower()
    if not verify_signature or not verify_expiration or not verify_subject:
        if raw_env not in _DEV_POSTURES:
            raise ValueError(
                f"Disabling {subject_label} verification "
                f"(verify_signature={verify_signature}, "
                f"verify_expiration={verify_expiration}, "
                f"verify_subject={verify_subject}) is forbidden in "
                f"enforcing posture {raw_env!r}"
            )
        logger.warning(
            "Disabling %s verification (verify_signature=%s, verify_expiration=%s, "
            "verify_subject=%s) under non-enforcing posture %r; never use this in production.",
            subject_label,
            verify_signature,
            verify_expiration,
            verify_subject,
            raw_env,
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
        http_transport: httpx.AsyncBaseTransport | None = None,
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
            http_transport: Optional custom ``httpx.AsyncBaseTransport`` (mutually exclusive
                with ``mtls_certs``) for callers that route SDK traffic through an existing
                HTTP client or ASGI/mock transport.

        Raises:
            ValueError: Invalid URL/timing config, half-configured mTLS, conflicting
                ``mtls_certs`` + ``http_transport``, or verification opt-out in enforcing ``CAGE_ENV``
            FileNotFoundError: If mTLS certificate paths are invalid (fail-closed)
        """
        cleaned_gateway = validate_http_url(
            gateway_url, field_name="gateway_url"
        ).rstrip("/")
        if mtls_certs is not None and http_transport is not None:
            raise ValueError(
                "mtls_certs and http_transport are mutually exclusive; configure TLS on the custom transport"
            )
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

        resolved_transport: httpx.AsyncBaseTransport
        if http_transport is not None:
            resolved_transport = http_transport
        elif mtls_certs:
            cert_path, key_path, ca_path = mtls_certs
            resolved_transport = transport.create_mtls_transport(
                cert_path=cert_path, key_path=key_path, ca_path=ca_path
            )
        else:
            resolved_transport = transport.create_mtls_transport()

        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_s),
            http2=_HTTP2_AVAILABLE if http_transport is None else False,
            follow_redirects=False,
            transport=resolved_transport,
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
          - 200 OK (verified ``NARROW`` / ``DENY`` / ``DENIED``) or 403 Forbidden (verified ``DENY`` / ``DENIED``) → Raise ``PolicyViolationException``
          - 200 OK (verified ``DEFER`` / ``REQUIRE_APPROVAL``) → Raise ``DeferralPending``
          - Signature, ``kid``, freshness, or ``subject.action_hash`` failure (on 200 or 403) → Raise ``RoutingSealVerificationError``
          - Non-envelope 403 (proxy/mesh error), legacy 202/409/422, 5xx, or transport error → Raise ``CageGatewayError``

        Security & Verification Scope:
            1. By default, ``CageClient`` verifies ``GovernanceEnvelope.signature``
               against an out-of-band ``kid`` trust anchor (``JwksKeyResolver`` or
               pinned ``public_keys``), enforces ``expires_at`` freshness, and
               verifies ``subject.action`` + ``subject.action_hash`` request
               binding on **every** HTTP 200 and HTTP 403 response before
               returning or dispatching any verdict.
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
            "User-Agent": _USER_AGENT,
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
                response,
                action=action,
                parameters=parameters,
                correlation_id=correlation_id,
            )

        if response.status_code == 403:
            await self._handle_deny_response(
                response,
                action=action,
                parameters=parameters,
                correlation_id=correlation_id,
            )
            raise AssertionError("_handle_deny_response must raise")

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
        correlation_id: str | None = None,
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
        if correlation_id is not None:
            envelope_corr = envelope.payload.get("correlation_id")
            if not isinstance(envelope_corr, str) or not envelope_corr.strip():
                raise RoutingSealVerificationError(
                    "GovernanceEnvelope payload is missing required non-empty 'correlation_id' binding"
                )
            if not hmac.compare_digest(
                envelope_corr.encode("utf-8"),
                correlation_id.encode("utf-8"),
            ):
                raise RoutingSealVerificationError(
                    "GovernanceEnvelope payload.correlation_id does not match request correlation_id"
                )

    @staticmethod
    def _extract_envelope_dict(
        response_data: Any, *, response_label: str = "ALLOW"
    ) -> dict[str, Any]:
        """Extract canonical envelope dict from wrapped or top-level wire format."""
        if not isinstance(response_data, dict):
            raise CageGatewayError(f"{response_label} response must be a JSON object")
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
        raise CageGatewayError(
            f"{response_label} response missing required 'envelope' field"
        )

    @staticmethod
    def _extract_verdict(envelope: GovernanceEnvelope) -> Any:
        """Read ``verdict`` (or fallback ``decision``) strictly as signed, with no coercion."""
        if "verdict" in envelope.payload:
            return envelope.payload["verdict"]
        return envelope.payload.get("decision")

    async def _verify_envelope_response(
        self,
        response: httpx.Response,
        *,
        action: str | None = None,
        parameters: Mapping[str, Any] | None = None,
        correlation_id: str | None = None,
        response_label: str = "ALLOW",
    ) -> GovernanceEnvelope:
        """Parse and cryptographically verify a ``GovernanceEnvelope`` response fail-closed.

        Enforces strict JSON parsing (refusing duplicate keys and ``NaN``/``Infinity``),
        embedded-key rejection, strict immutable Pydantic parsing, out-of-band ``kid``
        ``ES256``/``EdDSA`` signature verification over RFC 8785 JCS canonical bytes,
        timezone-aware ``issued_at``/``expires_at`` freshness, and ``subject.action`` +
        ``subject.action_hash`` + ``payload.correlation_id`` request binding before any
        verdict is read or dispatched.
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
            raise CageGatewayError(
                f"Invalid JSON in {response_label} response: {exc}"
            ) from exc

        envelope_data = self._extract_envelope_dict(
            response_data, response_label=response_label
        )
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
            self._verify_subject_binding(
                envelope,
                action=action,
                parameters=parameters,
                correlation_id=correlation_id,
            )
        return envelope

    @staticmethod
    def _mediate_narrow_verdict(envelope: GovernanceEnvelope) -> NoReturn:
        narrowed_params = envelope.payload.get("narrowed_params")
        if not isinstance(narrowed_params, dict):
            raise CageGatewayError(
                "NARROW envelope missing required 'narrowed_params' object"
            )
        audit_id = _non_blank_str(envelope.payload.get("audit_id")) or _non_blank_str(
            envelope.envelope_id
        )
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
            audit_id=audit_id,
            recoverable=True,
        )

    @staticmethod
    def _mediate_deny_verdict(
        envelope: GovernanceEnvelope,
        *,
        require_refusal_evidence: bool = False,
    ) -> NoReturn:
        raw_receipt = envelope.payload.get("refusal_receipt")
        receipt_dict = raw_receipt if isinstance(raw_receipt, dict) else {}

        audit_id = (
            _non_blank_str(envelope.payload.get("audit_id"))
            or _non_blank_str(envelope.payload.get("proof_hash"))
            or _non_blank_str(receipt_dict.get("proof_hash"))
        )
        if audit_id is None and not require_refusal_evidence:
            audit_id = _non_blank_str(envelope.envelope_id)
        if audit_id is None:
            if require_refusal_evidence:
                raise CageGatewayError(
                    "DENY envelope missing required non-blank 'audit_id' or 'proof_hash'"
                )
            raise CageGatewayError(
                "DENY envelope missing required 'audit_id', 'proof_hash', or 'envelope_id'"
            )

        violations = envelope.payload.get("violations", [])
        reason_code = (
            _non_blank_str(envelope.payload.get("reason_code"))
            or _first_violation_code(violations)
            or _non_blank_str(receipt_dict.get("violated_rule"))
            or ("UNKNOWN_VIOLATION" if require_refusal_evidence else "POLICY_DENIED")
        )
        raw_details = envelope.payload.get("details")
        if isinstance(raw_details, dict):
            details = raw_details
        else:
            details = {"violations": violations}
            if "refusal_receipt" in envelope.payload:
                details["refusal_receipt"] = envelope.payload["refusal_receipt"]
        recoverable = bool(envelope.payload.get("recoverable", True))

        logger.warning(
            "Action DENIED: reason_code=%s, audit_id=%s, recoverable=%s",
            reason_code,
            audit_id,
            recoverable,
        )

        raise PolicyViolationException(
            reason_code=reason_code,
            violation_details=details,
            audit_id=audit_id,
            recoverable=recoverable,
        )

    @staticmethod
    def _mediate_defer_verdict(envelope: GovernanceEnvelope) -> NoReturn:
        # Never fall back to envelope.envelope_id: when DeferQueue persistence
        # fails on REQUIRE_APPROVAL, the gateway sets deferred_id=None so the
        # client treats the unpersisted hold as a fail-closed error rather than
        # polling an unapprovable envelope UUID.
        ticket_id = (
            _non_blank_str(envelope.payload.get("deferred_id"))
            or _non_blank_str(envelope.payload.get("defer_token"))
            or _non_blank_str(envelope.payload.get("defer_id"))
            or _non_blank_str(envelope.payload.get("ticket_id"))
        )
        if not ticket_id:
            raise CageGatewayError(
                "DEFER envelope missing required 'deferred_id', 'defer_token', 'defer_id', or 'ticket_id'"
            )
        defer_reason = (
            _non_blank_str(envelope.payload.get("defer_reason"))
            or _non_blank_str(envelope.payload.get("classification_reason"))
            or _non_blank_str(envelope.payload.get("reason"))
            or "Human approval required"
        )

        raw_ttl = envelope.payload.get("ttl_seconds")
        if raw_ttl is None:
            raw_ttl = envelope.payload.get("retry_after_seconds")
        parsed_ttl: int | None = None
        if raw_ttl is not None:
            if (
                isinstance(raw_ttl, bool)
                or not isinstance(raw_ttl, int)
                or raw_ttl <= 0
            ):
                raise CageGatewayError(
                    "DEFER envelope carries invalid non-positive 'ttl_seconds' or 'retry_after_seconds'"
                )
            parsed_ttl = raw_ttl

        raw_defer_exp = envelope.payload.get("defer_expires_at")
        parsed_defer_exp: datetime | None = None
        if raw_defer_exp is not None:
            if not isinstance(raw_defer_exp, str) or not _RFC3339_TIMESTAMP.fullmatch(
                raw_defer_exp
            ):
                raise CageGatewayError(
                    "DEFER envelope carries invalid RFC 3339 'defer_expires_at'"
                )
            parsed_defer_exp = datetime.fromisoformat(
                raw_defer_exp.replace("Z", "+00:00")
            )

        if parsed_defer_exp is not None:
            defer_expires_at = parsed_defer_exp
            ttl_seconds = (
                parsed_ttl
                if parsed_ttl is not None
                else max(
                    1, int((parsed_defer_exp - envelope.issued_at).total_seconds())
                )
            )
        else:
            if parsed_ttl is not None:
                ttl_seconds = parsed_ttl
            else:
                logger.warning(
                    "DEFER envelope missing 'defer_expires_at' and 'ttl_seconds'; "
                    "defaulting deferral TTL to %ds (envelope_id=%s)",
                    _DEFAULT_DEFER_TTL_S,
                    envelope.envelope_id,
                )
                ttl_seconds = _DEFAULT_DEFER_TTL_S
            defer_expires_at = envelope.issued_at + timedelta(seconds=ttl_seconds)

        verdict_val = CageClient._extract_verdict(envelope)
        raise DeferralPending(
            ticket_id=ticket_id,
            defer_reason=defer_reason,
            expires_at=defer_expires_at,
            ttl_seconds=ttl_seconds,
            verdict=str(verdict_val) if isinstance(verdict_val, str) else None,
            defer_expires_at=defer_expires_at,
            envelope_expires_at=envelope.expires_at,
        )

    async def preview(
        self,
        action: str,
        parameters: Mapping[str, Any],
        agent_id: str,
        context: Mapping[str, Any] | None = None,
    ) -> PreviewResult:
        """Evaluate a proposed action in dry-run preview mode and return a 5-outcome ``PreviewResult``.

        Wraps :meth:`validate_action` without raising on policy/infra verdicts so
        workflow routers can branch explicitly on :class:`GovernanceDecision`
        (``ALLOWED``, ``NARROWED``, ``DENIED``, ``DEFERRED``, ``UNAVAILABLE``).
        """
        if not isinstance(action, str) or not action.strip():
            raise ValueError("preview() requires a non-empty 'action' string")
        if not isinstance(parameters, Mapping):
            raise ValueError("preview() requires a mapping for 'parameters'")
        if not isinstance(agent_id, str) or not agent_id.strip():
            raise ValueError("preview() requires a non-empty 'agent_id' string")

        try:
            envelope = await self.validate_action(
                action=action,
                parameters=dict(parameters),
                agent_id=agent_id,
                context=dict(context) if context is not None else None,
            )
            return PreviewResult(
                decision=GovernanceDecision.ALLOWED,
                envelope=envelope,
                gateway_verdict="ALLOW",
            )
        except PolicyViolationException as exc:
            details = (
                exc.violation_details
                if isinstance(exc.violation_details, Mapping)
                else {}
            )
            raw_violations = details.get("violations")
            violations = (
                tuple(raw_violations) if isinstance(raw_violations, list) else ()
            )
            if exc.reason_code == "NARROWED":
                narrowed = details.get("narrowed_params")
                return PreviewResult(
                    decision=GovernanceDecision.NARROWED,
                    gateway_verdict="NARROW",
                    narrowed_params=(
                        dict(narrowed) if isinstance(narrowed, Mapping) else None
                    ),
                    reason_code="NARROWED",
                    audit_id=exc.audit_id,
                    violations=violations,
                    recoverable=True,
                )
            return PreviewResult(
                decision=GovernanceDecision.DENIED,
                gateway_verdict="DENY",
                reason_code=exc.reason_code,
                audit_id=exc.audit_id,
                violations=violations,
                recoverable=exc.recoverable,
            )
        except DeferralPending as exc:
            verdict_str = exc.verdict or "DEFER"
            return PreviewResult(
                decision=GovernanceDecision.DEFERRED,
                gateway_verdict=verdict_str,
                deferred_id=exc.ticket_id,
                defer_reason=exc.defer_reason,
                defer_expires_at=exc.defer_expires_at,
                requires_approval=(verdict_str == "REQUIRE_APPROVAL"),
            )
        except RoutingSealVerificationError as exc:
            logger.error("Preview verification failed fail-closed: %s", exc)
            return PreviewResult(
                decision=GovernanceDecision.UNAVAILABLE,
                reason_code="VERIFICATION_FAILED",
                recoverable=False,
                error=str(exc),
            )
        except (CageGatewayError, httpx.RequestError) as exc:
            logger.error("Preview gateway call unavailable fail-closed: %s", exc)
            return PreviewResult(
                decision=GovernanceDecision.UNAVAILABLE,
                reason_code="GATEWAY_UNAVAILABLE",
                recoverable=False,
                error=str(exc),
            )

    @staticmethod
    def _build_execute_unavailable_error(
        response: httpx.Response,
    ) -> GatewayUnavailableError:
        """Build a pre-dispatch ``GatewayUnavailableError`` from HTTP 429/503 responses."""
        status = response.status_code
        retry_after: int | None = None
        if status == 429:
            raw_ra = response.headers.get("Retry-After")
            if raw_ra:
                try:
                    retry_after = int(float(raw_ra))
                except ValueError:
                    retry_after = None
        body: Mapping[str, Any] = {}
        try:
            parsed = response.json()
            if isinstance(parsed, Mapping):
                body = parsed
        except Exception:
            body = {}
        error_code = _non_blank_str(body.get("error")) or (
            "rate_limit_exceeded" if status == 429 else f"http_{status}_unavailable"
        )
        dependency = _non_blank_str(body.get("dependency"))
        failure_code = _non_blank_str(body.get("failure_code"))
        detail = (
            _non_blank_str(body.get("detail"))
            or _non_blank_str(body.get("error"))
            or f"Gateway /tools/execute returned HTTP {status}"
        )
        return GatewayUnavailableError(
            f"Gateway /tools/execute unavailable (HTTP {status}: {detail})",
            status_code=status,
            error_code=error_code,
            dependency=dependency,
            failure_code=failure_code,
            retry_after_seconds=retry_after,
        )

    @staticmethod
    def _client_inferred_indeterminate(
        *,
        message: str,
        tool_name: str,
        idempotency_key: str | None,
        http_status: int | None = None,
    ) -> CommitOutcome:
        return CommitOutcome(
            status=CommitStatus.INDETERMINATE,
            message=message,
            tool_name=tool_name,
            idempotency_key=idempotency_key,
            provenance=IndeterminateProvenance.CLIENT_INFERRED,
            verified=False,
            may_have_executed=True,
            http_status=http_status,
        )

    async def execute_tool(
        self,
        tool_name: str,
        params: Mapping[str, Any],
        *,
        idempotency_key: str | None = None,
        approval_token: str | None = None,
        verify_signature: bool | None = None,
        require_commit_outcome: bool = True,
        timeout_s: float | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> CommitOutcome:
        """Invoke a named tool via ``POST /tools/execute`` and verify the returned ``CommitOutcome``.

        Verifies KMS-signed ``CommitOutcome`` payloads across HTTP ``200``, ``202``
        (``DEFERRED``), and ``403`` (``REFUSED``) by default via the single
        ``enforce_verification_posture()`` policy (mandatory in enforcing postures;
        opt-out allowed only in explicit ``dev``/``test`` postures with a warning).

        Args:
            tool_name: Registered gateway tool name (e.g. ``"execute_trade_action"``).
            params: Tool call arguments (model-supplied ``deferred_id`` is stripped
                unless ``approval_token`` is passed explicitly).
            idempotency_key: Optional caller idempotency key injected into tool params
                and verified against the signed outcome's ``idempotency_key`` binding.
            approval_token: Optional human-approved ``deferred_id`` forwarded as
                ``params["deferred_id"]`` on resume.
            verify_signature: Optional per-call override (defaults to client's
                ``verify_signature`` setting). Forbidden as ``False`` in enforcing
                postures via ``enforce_verification_posture()``.
            require_commit_outcome: Whether HTTP ``200`` responses must include a
                structured ``"outcome"`` block (``True`` for committing tools;
                ``False`` permits plain read-only tool outputs while still verifying
                any ``"outcome"`` that is present).
            timeout_s: Optional per-call HTTP timeout override in seconds.
            headers: Optional additional request headers (e.g. ``x-cage-principal``).
        """
        if not isinstance(tool_name, str) or not tool_name.strip():
            raise ValueError("execute_tool() requires a non-empty 'tool_name' string")
        if not isinstance(params, Mapping):
            raise ValueError("execute_tool() requires a mapping for 'params'")
        if timeout_s is not None and (not math.isfinite(timeout_s) or timeout_s <= 0):
            raise ValueError("timeout_s must be a finite number > 0")

        effective_verify = (
            self._verify_signature if verify_signature is None else verify_signature
        )
        enforce_verification_posture(
            verify_signature=effective_verify,
            subject_label="CommitOutcome",
        )

        wire_params: dict[str, Any] = {
            k: v
            for k, v in params.items()
            if k not in ("deferred_id", "approval_token")
        }
        _validate_json_scalars(wire_params, "params")

        if approval_token is not None:
            if not isinstance(approval_token, str) or not approval_token.strip():
                raise ValueError(
                    "approval_token must be a non-empty string when provided"
                )
            wire_params["deferred_id"] = approval_token.strip()

        if idempotency_key is not None:
            if not isinstance(idempotency_key, str) or not idempotency_key.strip():
                raise ValueError(
                    "idempotency_key must be a non-empty string when provided"
                )
            wire_params["idempotency_key"] = idempotency_key

        expected_key = (
            _non_blank_str(idempotency_key)
            or _non_blank_str(wire_params.get("idempotency_key"))
            or _non_blank_str(wire_params.get("transaction_id"))
        )

        traceparent = generate_w3c_traceparent()
        correlation_id = secrets.token_hex(16)
        req_headers = {
            "Content-Type": "application/json",
            "traceparent": traceparent,
            "X-Correlation-ID": correlation_id,
            "User-Agent": _USER_AGENT,
        }
        if headers:
            for k, v in headers.items():
                req_headers[k] = v

        endpoint = f"{self.gateway_url}/tools/execute"
        body_payload = {"tool_name": tool_name, "params": wire_params}
        effective_timeout = self.timeout_s if timeout_s is None else float(timeout_s)

        try:
            response = await self._client.post(
                endpoint,
                json=body_payload,
                headers=req_headers,
                timeout=effective_timeout,
            )
        except _PRE_DISPATCH_CONNECT_ERRORS as exc:
            logger.error(
                "Gateway /tools/execute pre-dispatch connect failure (%s): %s",
                tool_name,
                exc,
            )
            raise GatewayUnavailableError(
                f"Failed to connect to CAGE Gateway at {endpoint}: {exc}"
            ) from exc
        except httpx.RequestError as exc:
            logger.warning(
                "Gateway /tools/execute transport ambiguity (%s): %s — classifying client-inferred INDETERMINATE",
                tool_name,
                exc,
            )
            return self._client_inferred_indeterminate(
                message=(
                    f"Gateway transport error after /tools/execute transmission ({type(exc).__name__}); "
                    "execution state unknown — do not retry until reconciled."
                ),
                tool_name=tool_name,
                idempotency_key=expected_key,
            )

        if response.status_code in (429, 503):
            raise self._build_execute_unavailable_error(response)

        if response.status_code in (500, 502, 504):
            logger.warning(
                "Gateway /tools/execute HTTP %d for %s — classifying client-inferred INDETERMINATE",
                response.status_code,
                tool_name,
            )
            return self._client_inferred_indeterminate(
                message=(
                    f"Gateway returned HTTP {response.status_code} during /tools/execute; "
                    "execution state unknown — do not retry until reconciled."
                ),
                tool_name=tool_name,
                idempotency_key=expected_key,
                http_status=response.status_code,
            )

        if response.status_code not in (200, 202, 403):
            raise CageGatewayError(
                f"Unexpected /tools/execute status {response.status_code}: {response.text[:200]}"
            )

        try:
            body = json.loads(
                response.content,
                object_pairs_hook=_refuse_duplicate_keys,
                parse_constant=_refuse_non_finite_number,
            )
        except RoutingSealVerificationError:
            raise
        except json.JSONDecodeError as exc:
            if response.status_code == 403:
                raise GatewayUnavailableError(
                    f"Gateway /tools/execute rejected request without JSON outcome (HTTP 403): {exc}",
                    status_code=403,
                    error_code="proxy_or_identity_forbidden",
                ) from exc
            return self._client_inferred_indeterminate(
                message=(
                    f"Malformed JSON in /tools/execute HTTP {response.status_code} response; "
                    "execution state unknown — do not retry until reconciled."
                ),
                tool_name=tool_name,
                idempotency_key=expected_key,
                http_status=response.status_code,
            )

        if not isinstance(body, Mapping):
            raise CageGatewayError("/tools/execute response must be a JSON object")

        raw_outcome = body.get("outcome")
        if raw_outcome is not None:
            raw_mhe = body.get("may_have_executed")
            mhe = raw_mhe if isinstance(raw_mhe, bool) else None
            raw_output = body.get("output")
            output_str = raw_output if isinstance(raw_output, str) else None
            return await verify_commit_outcome_payload(
                raw_outcome,
                resolve_key=self._resolve_public_key,
                require_signature=effective_verify,
                expected_tool_name=tool_name,
                expected_idempotency_key=expected_key,
                may_have_executed=mhe,
                http_status=response.status_code,
                proof_hash=_non_blank_str(body.get("proof_hash")),
                output=output_str,
                output_redacted=bool(body.get("output_redacted", False)),
            )

        if response.status_code == 403:
            raise GatewayUnavailableError(
                "Gateway /tools/execute HTTP 403 missing signed 'outcome'",
                status_code=403,
                error_code="unverified_403_without_outcome",
            )
        if response.status_code == 202 or require_commit_outcome:
            raise CommitOutcomeDecodeError(
                f"Gateway /tools/execute HTTP {response.status_code} response missing required 'outcome'"
            )

        plain_status = body.get("status")
        if plain_status == "SUCCESS":
            plain_output = str(body.get("output") or "")
            return CommitOutcome(
                status=CommitStatus.EXECUTED,
                message=plain_output,
                tool_name=tool_name,
                idempotency_key=expected_key,
                verified=False,
                may_have_executed=None,
                http_status=response.status_code,
                output=plain_output,
            )
        raise CageGatewayError(
            f"Read-only /tools/execute failed without CommitOutcome (status={plain_status!r})"
        )

    async def _handle_allow_response(
        self,
        response: httpx.Response,
        *,
        action: str | None = None,
        parameters: Mapping[str, Any] | None = None,
        correlation_id: str | None = None,
    ) -> GovernanceEnvelope:
        """
        Parse, cryptographically verify, and mediate an HTTP 200 envelope response.

        Verifies out-of-band ``kid`` signature, ``expires_at`` freshness, and
        ``subject.action`` + ``subject.action_hash`` + ``payload.correlation_id``
        request binding **before** returning ``ALLOW`` or dispatching ``NARROW``,
        ``DENY``/``DENIED``, or ``DEFER``/``REQUIRE_APPROVAL`` verdicts.

        Security & Verification Scope:
            1. ``GovernanceEnvelope.signature``, ``expires_at``, and ``subject``
               request binding are verified fail-closed by default (raising
               ``RoutingSealVerificationError`` on any failure).
            2. **TLS/mTLS in ``transport.py`` protects only the point-to-point
               transport channel and does NOT substitute for end-to-end envelope
               signature verification.**
        """
        envelope = await self._verify_envelope_response(
            response,
            action=action,
            parameters=parameters,
            correlation_id=correlation_id,
            response_label="ALLOW",
        )

        # Matched exactly as signed: no case folding, no coercion to str.
        verdict = self._extract_verdict(envelope)

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

    async def _handle_deny_response(
        self,
        response: httpx.Response,
        *,
        action: str | None = None,
        parameters: Mapping[str, Any] | None = None,
        correlation_id: str | None = None,
    ) -> NoReturn:
        """
        Parse, cryptographically verify, and mediate an HTTP 403 refusal envelope.

        Applies the exact same strict JSON parsing, out-of-band ``kid`` ``ES256`` /
        ``EdDSA`` signature verification, ``expires_at`` freshness, and
        ``subject.action`` + ``subject.action_hash`` + ``payload.correlation_id``
        request binding as HTTP 200 before raising ``PolicyViolationException``.
        Non-envelope 403 responses (for example, mesh/proxy rejections) raise
        ``CageGatewayError``; unsigned, tampered, expired, or misbound 403 envelopes
        raise ``RoutingSealVerificationError``.
        """
        envelope = await self._verify_envelope_response(
            response,
            action=action,
            parameters=parameters,
            correlation_id=correlation_id,
            response_label="DENY",
        )

        verdict = self._extract_verdict(envelope)
        if verdict not in ("DENY", "DENIED"):
            raise CageGatewayError(
                f"HTTP 403 GovernanceEnvelope carries non-DENY verdict {verdict!r}"
            )

        self._mediate_deny_verdict(envelope, require_refusal_evidence=True)

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

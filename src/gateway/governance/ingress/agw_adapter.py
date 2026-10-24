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

"""Agent Gateway (AGW) absorption adapter (Modules M1 & M2).

Translates GEAP Agent Gateway ``REQUEST_AUTHZ`` callouts (including decoded
MCP JSON-RPC 2.0 ``tools/call`` payloads) into CAGE governance pipeline inputs,
enforces ``kid``-resolved OIDC token validation and GEAP Tri-Identity
(``ID-1`` user, ``ID-2`` agent principal, ``ID-3`` delegated OAuth scope/token
hash) binding, and injects ``X-CAGE-Routing-Seal`` on ``ALLOW`` decisions.
"""

from __future__ import annotations

import base64
import hashlib
import inspect
import json
import logging
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt as pyjwt

from src.gateway.governance.env_posture import env_flag, is_enforcing
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.routing_seal import generate_seal

logger = logging.getLogger(__name__)

AGW_OIDC_ISSUER = os.environ.get("AGW_OIDC_ISSUER", "")
AGW_OIDC_AUDIENCE = os.environ.get("AGW_OIDC_AUDIENCE", "cage-gateway")
AGW_ENDPOINT = os.environ.get("AGW_ENDPOINT", "")

_ALLOWED_OIDC_ALGS: tuple[str, ...] = ("RS256", "ES256", "EdDSA")
_EMBEDDED_KEY_HEADERS: frozenset[str] = frozenset({"jwk", "x5c", "x5u", "jku"})


@dataclass(frozen=True)
class GeapTriIdentityContext:
    """GEAP Three-Identity context bound into CAGE governance envelopes (Module M2).

    Attributes:
        user_id: ``ID-1`` — End-user or upstream caller identity.
        agent_principal: ``ID-2`` — GEAP Agent Runtime principal
            (``principal://agents.global.org-...`` or ``spiffe://...``).
        oauth_scopes: ``ID-3`` — Delegated OAuth 2.0 scopes for outbound tools.
        delegated_token_sha256: ``ID-3`` — SHA-256 hex digest of the delegated
            OAuth 2.0 token (raw token is never persisted in governance state).
        kid: Key ID from the verified ``ID-2`` OIDC token header.
        user_verified: ``True`` only when ``user_id`` came from the ``act_sub``
            or ``user_sub`` claim of a token verified by
            :meth:`AgwAdapter.validate_oidc_token`. ``False`` when it came from
            the unverified request payload or headers, in which case it is an
            asserted value fit for attribution only.
    """

    user_id: str
    agent_principal: str
    oauth_scopes: tuple[str, ...] = field(default_factory=tuple)
    delegated_token_sha256: str = ""
    kid: str = ""
    user_verified: bool = False

    @property
    def is_valid_agent_principal(self) -> bool:
        """True iff ``agent_principal`` carries a GEAP ``principal://`` or ``spiffe://`` URI."""
        return self.agent_principal.startswith(
            ("principal://agents.global.org-", "spiffe://")
        )

    def compute_binding_digest(self) -> str:
        """Compute deterministic RFC 8785 JCS SHA-256 digest over ``ID-1``, ``ID-2``, and ``ID-3``.

        The digest binds identity values only. It does not attest that ``ID-1``
        was verified; that is recorded as ``id1_user_verified`` in
        :meth:`to_envelope_claims`.
        """
        canonical = jcs_canonicalize_plan(
            {
                "id1_user": self.user_id,
                "id2_agent_principal": self.agent_principal,
                "id3_scopes": list(self.oauth_scopes),
                "id3_token_sha256": self.delegated_token_sha256,
            }
        )
        return hashlib.sha256(canonical).hexdigest()

    def to_envelope_claims(self) -> dict[str, Any]:
        """Return safe, non-secret tri-identity claims for ``GovernanceEnvelope`` binding."""
        return {
            "id1_user": self.user_id,
            "id1_user_verified": self.user_verified,
            "id2_agent_principal": self.agent_principal,
            "id3_scopes": list(self.oauth_scopes),
            "id3_token_sha256": self.delegated_token_sha256,
            "kid": self.kid,
            "tri_identity_digest": self.compute_binding_digest(),
        }


@dataclass
class AgwRequest:
    """Normalized AGW request for CAGE governance pipeline."""

    agent_id: str
    tool_name: str
    parameters: dict[str, Any]
    oidc_token: str = ""
    trace_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgwAdapterResult:
    """Result of AGW adapter processing."""

    success: bool
    agent_id: str
    tool_name: str
    parameters: dict[str, Any]
    identity_verified: bool = False
    error: str = ""


@dataclass(frozen=True)
class AgwRequestAuthzDecision:
    """Decision returned to GEAP Agent Gateway ``REQUEST_AUTHZ`` callout (Module M1).

    Attributes:
        allowed: True iff identity verification and CAGE governance succeeded.
        http_status: ``200`` on ``ALLOW``; ``403`` on ``DENY``, ``DEFER``, or
            ``UNAUTHENTICATED`` (fail-closed: ``failOpen: false``).
        decision: Canonical verdict (``ALLOW``, ``DENY``, ``DEFER``,
            ``UNAUTHENTICATED``).
        headers_to_inject: Headers injected into the outbound MCP tool request
            (includes ``X-CAGE-Routing-Seal`` and ``X-CAGE-Tri-Identity-Digest``
            on ``ALLOW``; empty on non-ALLOW).
        agent_id: Authenticated ``ID-2`` agent identity.
        tool_name: Decoded MCP tool name.
        tri_identity: Bound ``GeapTriIdentityContext`` when available.
        reason: Diagnostic explanation when denied or deferred.
        defer_token: Optional deferral token when ``decision == "DEFER"``.
    """

    allowed: bool
    http_status: int
    decision: str
    headers_to_inject: dict[str, str]
    agent_id: str
    tool_name: str
    tri_identity: GeapTriIdentityContext | None = None
    reason: str = ""
    defer_token: str | None = None


def _parse_unverified_jws_header(token: str) -> dict[str, Any] | None:
    """Decode the JWS header without trusting its contents."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        padded = parts[0] + "=" * ((4 - len(parts[0]) % 4) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        header = json.loads(raw.decode("utf-8"))
        return header if isinstance(header, dict) else None
    except Exception:
        return None


class AgwAdapter:
    """Adapter for Agent Gateway protocol absorption into CAGE governance.

    Validates OIDC tokens via out-of-band ``kid`` resolution, normalizes both
    legacy AGW payloads and GEAP MCP JSON-RPC 2.0 ``tools/call`` callouts,
    binds ``ID-1``/``ID-2``/``ID-3`` identities, and mints ``X-CAGE-Routing-Seal``
    headers for approved outbound tool calls.
    """

    def __init__(
        self,
        jwks_cache: dict[str, Any] | None = None,
        *,
        require_verified_user: bool | None = None,
    ) -> None:
        self._http_client: httpx.AsyncClient | None = None
        self._jwks_cache: dict[str, Any] = dict(jwks_cache) if jwks_cache else {}
        self._require_verified_user: bool | None = require_verified_user

    async def validate_oidc_token(
        self,
        token: str,
        *,
        key_resolver: Callable[[str], str | bytes | None] | None = None,
    ) -> tuple[bool, dict[str, Any]]:
        """Validate OIDC token against AGW issuer using out-of-band ``kid`` resolution.

        Enforces CAGE Trust Anchor invariants:
          - Fails closed if ``AGW_OIDC_ISSUER`` is unset or ``token`` is empty.
          - Rejects tokens carrying embedded keys (``jwk``, ``x5c``, ``x5u``, ``jku``)
            or disallowed algorithms (``none``).
          - Resolves the verification key strictly by ``kid`` from ``key_resolver``
            or ``self._jwks_cache``. Fails closed on unknown ``kid``.
        """
        if not AGW_OIDC_ISSUER:
            logger.warning("AGW_OIDC_ISSUER not configured; skipping OIDC validation")
            return False, {}

        if not token or not isinstance(token, str):
            return False, {}

        if key_resolver is None and not self._jwks_cache:
            return False, {}

        header = _parse_unverified_jws_header(token)
        if header is None:
            logger.warning("AGW OIDC validation failed: malformed JWS header")
            return False, {}

        # Never verify against a key embedded in the signed document
        if any(k in header for k in _EMBEDDED_KEY_HEADERS):
            logger.warning("AGW OIDC validation rejected: embedded key header present")
            return False, {}

        alg = str(header.get("alg", ""))
        if alg not in _ALLOWED_OIDC_ALGS:
            logger.warning("AGW OIDC validation rejected: disallowed alg=%r", alg)
            return False, {}

        kid = str(header.get("kid", ""))
        if not kid:
            logger.warning("AGW OIDC validation rejected: missing kid in JWS header")
            return False, {}

        pub_key = (
            key_resolver(kid) if key_resolver is not None else self._jwks_cache.get(kid)
        )
        if not pub_key:
            logger.warning("AGW OIDC validation rejected: unknown kid=%r", kid)
            return False, {}

        try:
            claims: dict[str, Any] = pyjwt.decode(
                token,
                pub_key,
                algorithms=list(_ALLOWED_OIDC_ALGS),
                issuer=AGW_OIDC_ISSUER,
                audience=AGW_OIDC_AUDIENCE,
                options={"require": ["exp", "iss", "aud", "sub"]},
            )
            claims["_verified_kid"] = kid
            return True, claims
        except Exception as exc:
            logger.warning(
                "AGW OIDC signature validation failed: %s", type(exc).__name__
            )
            return False, {}

    def extract_tri_identity(
        self,
        raw_request: dict[str, Any],
        verified_claims: Mapping[str, Any] | None = None,
    ) -> GeapTriIdentityContext:
        """Extract and bind ``ID-1`` (user), ``ID-2`` (agent), and ``ID-3`` (OAuth) context.

        ``ID-1`` prefers the ``act_sub`` / ``user_sub`` claim. It is marked
        ``user_verified`` only when ``verified_claims`` carries the
        ``_verified_kid`` stamp that :meth:`validate_oidc_token` adds after
        signature verification. The fallbacks (``tri_identity.user_id``,
        ``auth.user_id``, the ``x-geap-user-id`` header) are caller-asserted.
        """
        claims = dict(verified_claims or {})
        tri_raw = raw_request.get("tri_identity") or {}
        auth_raw = raw_request.get("auth") or {}
        headers_raw = raw_request.get("headers") or {}

        claimed_user = str(claims.get("act_sub") or claims.get("user_sub") or "")
        user_verified = bool(claimed_user) and bool(claims.get("_verified_kid"))
        user_id = claimed_user or str(
            tri_raw.get("user_id")
            or auth_raw.get("user_id")
            or headers_raw.get("x-geap-user-id")
            or ""
        )
        agent_principal = str(
            claims.get("sub")
            or tri_raw.get("agent_principal")
            or raw_request.get("agent_id")
            or headers_raw.get("l5d-client-id")
            or "unknown"
        )

        raw_scopes = (
            tri_raw.get("oauth_scopes")
            or auth_raw.get("scopes")
            or claims.get("scope")
            or ()
        )
        if isinstance(raw_scopes, str):
            scopes = tuple(s for s in raw_scopes.split() if s)
        elif isinstance(raw_scopes, (list, tuple, set)):
            scopes = tuple(str(s) for s in raw_scopes if s)
        else:
            scopes = ()

        delegated_token = str(
            tri_raw.get("delegated_token")
            or auth_raw.get("delegated_token")
            or headers_raw.get("x-geap-delegated-oauth-token")
            or ""
        )
        token_sha256 = (
            hashlib.sha256(delegated_token.encode("utf-8")).hexdigest()
            if delegated_token
            else str(tri_raw.get("delegated_token_sha256", ""))
        )

        return GeapTriIdentityContext(
            user_id=user_id,
            agent_principal=agent_principal,
            oauth_scopes=scopes,
            delegated_token_sha256=token_sha256,
            kid=str(claims.get("_verified_kid", "")),
            user_verified=user_verified,
        )

    async def translate_request(self, raw_request: dict[str, Any]) -> AgwRequest:
        """Translate raw AGW or MCP JSON-RPC 2.0 ``tools/call`` dict into ``AgwRequest``."""
        tool_name = ""
        parameters: dict[str, Any] = {}

        # Support GEAP Agent Gateway decoded MCP JSON-RPC 2.0 tools/call payload
        mcp_frame = (
            raw_request.get("mcp")
            if isinstance(raw_request.get("mcp"), dict)
            else raw_request
        )
        if (
            isinstance(mcp_frame, dict)
            and mcp_frame.get("method") == "tools/call"
            and isinstance(mcp_frame.get("params"), dict)
        ):
            mcp_params = mcp_frame["params"]
            tool_name = str(mcp_params.get("name", ""))
            raw_args = mcp_params.get("arguments")
            parameters = dict(raw_args) if isinstance(raw_args, dict) else {}
        else:
            tool_block = raw_request.get("tool", {})
            if isinstance(tool_block, dict):
                tool_name = str(tool_block.get("name", ""))
                raw_params = tool_block.get("parameters", {})
                parameters = dict(raw_params) if isinstance(raw_params, dict) else {}

        auth_block = raw_request.get("auth", {})
        oidc_token = (
            str(auth_block.get("token", "")) if isinstance(auth_block, dict) else ""
        )
        headers_block = raw_request.get("headers", {})
        if not oidc_token and isinstance(headers_block, dict):
            bearer = str(
                headers_block.get("authorization")
                or headers_block.get("Authorization")
                or ""
            )
            if bearer.lower().startswith("bearer "):
                oidc_token = bearer[7:].strip()

        return AgwRequest(
            agent_id=raw_request.get("agent_id", "unknown"),
            tool_name=tool_name,
            parameters=parameters,
            oidc_token=oidc_token,
            trace_id=raw_request.get("trace_id", ""),
            metadata=raw_request.get("metadata", {}),
        )

    async def process(
        self,
        raw_request: dict[str, Any],
        *,
        key_resolver: Callable[[str], str | bytes | None] | None = None,
    ) -> AgwAdapterResult:
        """Full AGW request processing: translate + OIDC validate.

        Issue #2 remediation: Fail-closed authentication semantics.
        If OIDC validation fails (identity_verified=False), the adapter
        returns success=False to prevent unauthenticated traffic from
        being admitted by callers that gate on success rather than
        identity_verified.

        Callers MUST check identity_verified before trusting the request.
        success=True AND identity_verified=True are both required for
        authenticated admission.
        """
        req = await self.translate_request(raw_request)
        identity_verified, claims = await self.validate_oidc_token(
            req.oidc_token, key_resolver=key_resolver
        )
        effective_agent_id = str(claims.get("sub") or req.agent_id)

        return AgwAdapterResult(
            success=identity_verified,
            agent_id=effective_agent_id,
            tool_name=req.tool_name,
            parameters=req.parameters,
            identity_verified=identity_verified,
            error="" if identity_verified else "OIDC token validation failed",
        )

    async def evaluate_request_authz(
        self,
        raw_request: dict[str, Any],
        *,
        governor: Any = None,
        seal_minter: Callable[[str, dict[str, Any]], Any] | None = None,
        key_resolver: Callable[[str], str | bytes | None] | None = None,
        require_verified_user: bool | None = None,
    ) -> AgwRequestAuthzDecision:
        """Evaluate a GEAP Agent Gateway ``REQUEST_AUTHZ`` callout (Modules M1 & M2).

        Enforces ``failOpen: false``:
          1. Translates MCP JSON-RPC 2.0 ``tools/call`` or AGW tool payload.
          2. Validates ``ID-2`` OIDC token via out-of-band ``kid`` resolution and
             extracts ``GeapTriIdentityContext`` (``ID-1``, ``ID-2``, ``ID-3``).
             When ``require_verified_user`` holds (default True via
             ``AGW_REQUIRE_VERIFIED_USER`` or enforcing posture), an unverified
             ``ID-1`` is refused with ``UNAUTHENTICATED`` (HTTP 403).
          3. Evaluates ``governor.validate_action(tool_name, governed_params)``.
          4. On ``ALLOW``, mints ``X-CAGE-Routing-Seal`` and ``X-CAGE-Tri-Identity-Digest``.
             On ``DENY`` or ``DEFER``, returns HTTP 403 with no routing seal.
        """
        if raw_request.get("fail_open") is True or raw_request.get("failOpen") is True:
            logger.warning(
                "AGW REQUEST_AUTHZ callout requested failOpen=True; CAGE enforces failOpen=False."
            )

        req = await self.translate_request(raw_request)
        if not req.tool_name:
            return AgwRequestAuthzDecision(
                allowed=False,
                http_status=403,
                decision="DENY",
                headers_to_inject={},
                agent_id=req.agent_id,
                tool_name="",
                reason="Missing MCP tool name in REQUEST_AUTHZ payload",
            )

        identity_verified, claims = await self.validate_oidc_token(
            req.oidc_token, key_resolver=key_resolver
        )
        tri_identity = self.extract_tri_identity(raw_request, claims)

        if not identity_verified or not tri_identity.is_valid_agent_principal:
            return AgwRequestAuthzDecision(
                allowed=False,
                http_status=403,
                decision="UNAUTHENTICATED",
                headers_to_inject={},
                agent_id=tri_identity.agent_principal,
                tool_name=req.tool_name,
                tri_identity=tri_identity,
                reason="OIDC token validation or GEAP agent principal check failed",
            )

        effective_require_verified = (
            require_verified_user
            if require_verified_user is not None
            else self._require_verified_user
        )
        enforce_verified_user = (
            effective_require_verified
            if effective_require_verified is not None
            else (is_enforcing() or env_flag("AGW_REQUIRE_VERIFIED_USER", True))
        )
        if enforce_verified_user and not tri_identity.user_verified:
            return AgwRequestAuthzDecision(
                allowed=False,
                http_status=403,
                decision="UNAUTHENTICATED",
                headers_to_inject={},
                agent_id=tri_identity.agent_principal,
                tool_name=req.tool_name,
                tri_identity=tri_identity,
                reason="Verified ID-1 end-user principal required for REQUEST_AUTHZ",
            )

        if governor is None:
            return AgwRequestAuthzDecision(
                allowed=False,
                http_status=403,
                decision="DENY",
                headers_to_inject={},
                agent_id=tri_identity.agent_principal,
                tool_name=req.tool_name,
                tri_identity=tri_identity,
                reason="No SymbolicGovernor configured for REQUEST_AUTHZ evaluation",
            )

        governed_params = dict(req.parameters)
        governed_params["_tri_identity"] = tri_identity.to_envelope_claims()

        try:
            verdict = governor.validate_action(req.tool_name, governed_params)
            if inspect.isawaitable(verdict):
                verdict = await verdict
        except Exception as exc:
            logger.error("AGW REQUEST_AUTHZ governor error (failing closed): %s", exc)
            return AgwRequestAuthzDecision(
                allowed=False,
                http_status=403,
                decision="DENY",
                headers_to_inject={},
                agent_id=tri_identity.agent_principal,
                tool_name=req.tool_name,
                tri_identity=tri_identity,
                reason=f"Governor evaluation error: {exc}",
            )

        if isinstance(verdict, Mapping):
            raw_decision = verdict.get("decision") or verdict.get("verdict")
            raw_decision_str = (
                str(getattr(raw_decision, "value", raw_decision)).upper()
                if raw_decision is not None
                else ""
            )
            if "allowed" in verdict:
                allowed = bool(verdict.get("allowed", False))
            elif "execution_allowed" in verdict:
                allowed = bool(verdict.get("execution_allowed", False))
            else:
                allowed = raw_decision_str in ("ALLOW", "NARROW")
            decision_str = raw_decision_str or ("ALLOW" if allowed else "DENY")
            reason = str(
                verdict.get("reason")
                or verdict.get("classification_reason")
                or verdict.get("defer_reason")
                or verdict.get("narrowing_reason")
                or ""
            )
            defer_token = (
                verdict.get("defer_token")
                or verdict.get("deferred_id")
                or verdict.get("approval_token")
            )
            existing_seal = verdict.get("seal")
            narrowed_params = verdict.get("narrowed_params")
        else:
            raw_decision = getattr(verdict, "decision", None) or getattr(
                verdict, "verdict", None
            )
            raw_decision_str = (
                str(getattr(raw_decision, "value", raw_decision)).upper()
                if raw_decision is not None
                else ""
            )
            if hasattr(verdict, "allowed"):
                allowed = bool(getattr(verdict, "allowed", False))
            elif hasattr(verdict, "execution_allowed"):
                allowed = bool(getattr(verdict, "execution_allowed", False))
            else:
                allowed = raw_decision_str in ("ALLOW", "NARROW")
            decision_str = raw_decision_str or ("ALLOW" if allowed else "DENY")
            reason = str(
                getattr(verdict, "reason", None)
                or getattr(verdict, "classification_reason", None)
                or getattr(verdict, "defer_reason", None)
                or getattr(verdict, "narrowing_reason", None)
                or ""
            )
            defer_token = (
                getattr(verdict, "defer_token", None)
                or getattr(verdict, "deferred_id", None)
                or getattr(verdict, "approval_token", None)
            )
            existing_seal = getattr(verdict, "seal", None)
            narrowed_params = getattr(verdict, "narrowed_params", None)

        if not allowed or decision_str not in ("ALLOW", "NARROW"):
            effective_decision = (
                decision_str
                if decision_str in ("DENY", "DEFER", "REQUIRE_APPROVAL")
                else "DENY"
            )
            default_reason = (
                "Action requires human approval"
                if effective_decision == "REQUIRE_APPROVAL"
                else "Governance policy denied or deferred action"
            )
            return AgwRequestAuthzDecision(
                allowed=False,
                http_status=403,
                decision=effective_decision,
                headers_to_inject={},
                agent_id=tri_identity.agent_principal,
                tool_name=req.tool_name,
                tri_identity=tri_identity,
                reason=reason or default_reason,
                defer_token=str(defer_token) if defer_token else None,
            )

        effective_params = (
            dict(narrowed_params)
            if isinstance(narrowed_params, Mapping)
            else req.parameters
        )
        if (
            isinstance(narrowed_params, Mapping)
            and "_tri_identity" in effective_params
            and "_tri_identity" not in req.parameters
        ):
            effective_params.pop("_tri_identity", None)

        # Reuse governor-provided seal or mint X-CAGE-Routing-Seal over effective parameters
        try:
            if seal_minter is not None:
                seal_res = seal_minter(req.tool_name, effective_params)
                seal = (
                    await seal_res if inspect.isawaitable(seal_res) else str(seal_res)
                )
            elif isinstance(existing_seal, str) and existing_seal.strip():
                seal = existing_seal.strip()
            else:
                seal = await generate_seal(
                    req.tool_name,
                    effective_params,
                    aud=f"cage-actuator:{req.tool_name}",
                )
        except Exception as exc:
            logger.error("AGW REQUEST_AUTHZ seal minting failed: %s", exc)
            return AgwRequestAuthzDecision(
                allowed=False,
                http_status=403,
                decision="DENY",
                headers_to_inject={},
                agent_id=tri_identity.agent_principal,
                tool_name=req.tool_name,
                tri_identity=tri_identity,
                reason=f"Routing seal minting failed: {exc}",
            )

        headers = {
            "X-CAGE-Routing-Seal": seal,
            "X-CAGE-Tri-Identity-Digest": tri_identity.compute_binding_digest(),
            "X-CAGE-Agent-Principal": tri_identity.agent_principal,
        }
        if tri_identity.user_id:
            headers["X-CAGE-User-Identity"] = tri_identity.user_id

        return AgwRequestAuthzDecision(
            allowed=True,
            http_status=200,
            decision="ALLOW",
            headers_to_inject=headers,
            agent_id=tri_identity.agent_principal,
            tool_name=req.tool_name,
            tri_identity=tri_identity,
            reason=reason or "Approved by CAGE SymbolicGovernor",
        )


_agw_adapter: AgwAdapter | None = None


def get_agw_adapter() -> AgwAdapter:
    """Lazy singleton for AGW adapter."""
    global _agw_adapter
    if _agw_adapter is None:
        _agw_adapter = AgwAdapter()
    return _agw_adapter

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

"""Authentication and authorization helpers for compliance-bridge endpoints."""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
from dataclasses import dataclass
from typing import Any, Literal

from fastapi import Header, HTTPException, Request

from src.compliance_bridge.oidc_verifier import (
    load_static_operator_jwks,
    validate_jwks_uri,
    verify_operator_oidc_token,
)
from src.gateway.governance.env_posture import is_enforcing
from src.gateway.server.workload_identity import is_pod_local_connection

logger = logging.getLogger(__name__)

_CAGE_ENV = os.environ.get("CAGE_ENV", "production")

# Strict SPIFFE ID grammar for transport-supplied operator SVIDs
# (request.attributes.source.principal): a lowercase trust domain followed by
# zero or more non-dot path segments, anchored end to end.
_SPIFFE_ID = re.compile(
    r"^spiffe://[a-z0-9][a-z0-9._-]{0,254}(?:/(?!\.\.?(?:/|\Z))[A-Za-z0-9._-]+)*\Z"
)

# Linkerd inbound proxy workload identity grammar (l5d-client-id):
# <service-account>.<namespace>.serviceaccount.identity.linkerd.<trust-domain>
_LINKERD_IDENTITY = re.compile(
    r"^([a-z0-9](?:[-a-z0-9]*[a-z0-9])?)"  # group 1: service account
    r"\.([a-z0-9](?:[-a-z0-9]*[a-z0-9])?)"  # group 2: namespace
    r"\.serviceaccount\.identity\.linkerd\."
    r"([a-z0-9](?:[-a-z0-9.]*[a-z0-9])?)\Z"  # group 3: trust domain
)


def _linkerd_client_id_header(request: Request) -> tuple[str | None, bool]:
    """Return ``(l5d_client_id, duplicate_detected)`` for ``l5d-client-id``.

    The Linkerd inbound proxy terminates mTLS and either sets ``l5d-client-id``
    from the verified peer certificate SAN or strips it when no verified peer
    certificate is present. That holds only for requests that came through the
    proxy, so :func:`require_operator_identity` also requires the connection to
    come from inside the pod (``is_pod_local_connection``). Multiple
    ``l5d-client-id`` headers indicate header smuggling and fail closed.

    Note (GHSA-529c-23c8-3m42 / GHSA-qrg7-27x4-mq39): ``x-cage-source-principal``
    is a client-controllable HTTP header not managed by Linkerd and is never
    accepted as an operator identity source.
    """
    headers = request.headers
    getlist = getattr(headers, "getlist", None)
    if callable(getlist):
        values = [v for v in getlist("l5d-client-id") if v]
    else:  # pragma: no cover - real requests always expose getlist
        single = headers.get("l5d-client-id") if hasattr(headers, "get") else None
        values = [single] if single else []
    if len(values) > 1:
        logger.warning(
            "Multiple l5d-client-id headers presented (%d) — rejecting",
            len(values),
        )
        return None, True
    if len(values) == 1:
        return values[0], False
    return None, False


def _linkerd_id_to_spiffe(l5d_id: str) -> str | None:
    """Convert a verified Linkerd ``l5d-client-id`` to its canonical ``spiffe://`` URN."""
    match = _LINKERD_IDENTITY.fullmatch(l5d_id)
    if not match:
        return None
    sa, namespace, trust_domain = match.group(1), match.group(2), match.group(3)
    return f"spiffe://{trust_domain}/ns/{namespace}/sa/{sa}"


def _trusted_operator_identities() -> frozenset[str]:
    """Return configured trusted human operator identities."""
    raw = os.environ.get("CAGE_TRUSTED_OPERATOR_IDENTITIES", "")
    return frozenset(part.strip() for part in raw.split(",") if part.strip())


@dataclass(frozen=True)
class OperatorPrincipal:
    """Verified operator identity from substrate-level transport or OIDC claims.

    Attributes:
        operator_urn: Canonical operator identity (SPIFFE ID or OIDC sub claim)
        channel_provenance: Source of identity verification
        auth_principal_hash: SHA-256 hash of the raw principal for audit correlation
    """

    operator_urn: str
    channel_provenance: Literal["SVID", "OIDC", "DEV_SYNTHETIC"]
    auth_principal_hash: str


async def require_internal_token(
    request: Request,
    x_cage_internal_token: str | None = Header(None, alias="X-Cage-Internal-Token"),
) -> str:
    """Verify the X-Cage-Internal-Token or Authorization header for internal-only endpoints.

    Fails closed by default (``CAGE_ENV`` defaults to ``production``).
    Unauthenticated dev access requires a dual-condition opt-in:
    ``CAGE_ENV`` in ``("dev", "development")`` AND
    ``CAGE_ALLOW_DEV_UNAUTHENTICATED=true`` (GHSA-529c-23c8-3m42 / GHSA-qrg7-27x4-mq39).
    Accepts token from X-Cage-Internal-Token or Authorization: Bearer.
    Matches against CAGE_INTERNAL_TOKEN or COMPLIANCE_BRIDGE_INTERNAL_TOKEN.
    """
    expected_token = os.environ.get("CAGE_INTERNAL_TOKEN") or os.environ.get(
        "COMPLIANCE_BRIDGE_INTERNAL_TOKEN"
    )

    token_val = x_cage_internal_token
    if not token_val:
        auth_header = request.headers.get("authorization") or request.headers.get(
            "Authorization"
        )
        if auth_header and auth_header.startswith("Bearer "):
            token_val = auth_header[7:].strip()

    cage_env = os.environ.get("CAGE_ENV", _CAGE_ENV)
    allow_dev_unauth = (
        os.environ.get("CAGE_ALLOW_DEV_UNAUTHENTICATED", "false").lower() == "true"
    )
    if cage_env in ("dev", "development") and allow_dev_unauth and not token_val:
        logger.warning(
            "⚠️  Internal token missing in dev mode (CAGE_ALLOW_DEV_UNAUTHENTICATED=true); allowing unauthenticated access"
        )
        return "dev-unauthenticated"

    if not token_val:
        raise HTTPException(
            status_code=401,
            detail="Missing X-Cage-Internal-Token or Authorization header",
        )

    if not expected_token:
        raise HTTPException(
            status_code=500,
            detail="CAGE_INTERNAL_TOKEN or COMPLIANCE_BRIDGE_INTERNAL_TOKEN not configured",
        )

    if not hmac.compare_digest(token_val, expected_token):
        raise HTTPException(status_code=401, detail="Invalid internal token")

    return token_val


def is_workload_identity(urn: str) -> bool:
    """Return True if ``urn`` is a workload/service-account identity rather than a human operator."""
    if not isinstance(urn, str):
        return False
    candidate = urn.strip()
    if not candidate:
        return False
    return (
        candidate.startswith("spiffe://")
        or candidate.startswith("principal://agents.")
        or ".serviceaccount.identity.linkerd." in candidate
        or candidate.endswith(".svc.cluster.local")
        or bool(_LINKERD_IDENTITY.fullmatch(candidate))
    )


def get_trusted_operator_identities() -> frozenset[str]:
    """Return the configured frozenset of trusted human operator identities."""
    return _trusted_operator_identities()


def validate_operator_identity_posture() -> None:
    """Validate HITL operator identity posture at startup (POAM-2026-196, F-40, F-41).

    Under an enforcing posture (staging/prod), ``CAGE_TRUSTED_OPERATOR_IDENTITIES``
    must be non-empty and must never contain workload identities (``spiffe://`` or
    Linkerd ``.serviceaccount.identity.linkerd.``). Workload identities in
    ``CAGE_TRUSTED_OPERATOR_IDENTITIES`` are rejected in all postures, and any
    configured ``CAGE_OPERATOR_JWKS_URI`` must pass scheme validation.
    """
    trusted = get_trusted_operator_identities()
    for entry in sorted(trusted):
        if is_workload_identity(entry):
            raise RuntimeError(
                f"FATAL [POAM-2026-196]: Workload identity {entry!r} is not permitted in "
                "CAGE_TRUSTED_OPERATOR_IDENTITIES; only human OIDC operator identities may "
                "be allowlisted as HITL approvers."
            )
    if is_enforcing() and not trusted:
        raise RuntimeError(
            "FATAL [POAM-2026-196]: CAGE_TRUSTED_OPERATOR_IDENTITIES is empty in an "
            "enforcing posture. Configure at least one human OIDC operator identity."
        )
    jwks_uri = os.environ.get("CAGE_OPERATOR_JWKS_URI", "").strip()
    if jwks_uri:
        try:
            validate_jwks_uri(jwks_uri)
        except ValueError as exc:
            raise RuntimeError(
                f"FATAL [POAM-2026-196]: Invalid CAGE_OPERATOR_JWKS_URI: {exc}"
            ) from exc


def _load_operator_jwks_by_kid() -> dict[str, Any]:
    """Load out-of-band static operator OIDC verification keys indexed by ``kid``."""
    return load_static_operator_jwks()


async def validate_operator_oidc_token(
    token: str,
) -> tuple[bool, dict[str, Any], str]:
    """Cryptographically verify an operator OIDC JWT via ``oidc_verifier``."""
    return await verify_operator_oidc_token(token)


def ensure_human_operator_principal(operator: OperatorPrincipal) -> OperatorPrincipal:
    """Refuse workload identities (SVID) as HITL approvers and enforce the human operator allowlist."""
    if operator.channel_provenance == "SVID" or is_workload_identity(
        operator.operator_urn
    ):
        logger.warning(
            "Refused HITL approval from workload identity %r (channel=%s)",
            operator.operator_urn,
            operator.channel_provenance,
        )
        raise HTTPException(
            status_code=403,
            detail=(
                "Workload identities (SVID) cannot approve HITL escalations; "
                "human OIDC operator identity required."
            ),
        )

    if operator.channel_provenance == "DEV_SYNTHETIC":
        cage_env = os.environ.get("CAGE_ENV", _CAGE_ENV)
        allow_dev_syn = (
            os.environ.get(
                "CAGE_OPERATOR_IDENTITY_ALLOW_DEV_SYNTHETIC", "false"
            ).lower()
            == "true"
        )
        if (
            cage_env != "dev"
            or not allow_dev_syn
            or not operator.operator_urn.startswith("urn:cage:dev:")
        ):
            raise HTTPException(
                status_code=403,
                detail="DEV_SYNTHETIC operator identity is not permitted outside dual-condition dev mode.",
            )
        return operator

    if operator.channel_provenance != "OIDC":
        raise HTTPException(
            status_code=403,
            detail=f"Unsupported operator channel {operator.channel_provenance!r} for HITL approval.",
        )

    trusted = get_trusted_operator_identities()
    if not trusted:
        logger.warning(
            "Refused HITL approval for %r: CAGE_TRUSTED_OPERATOR_IDENTITIES is empty",
            operator.operator_urn,
        )
        raise HTTPException(
            status_code=403,
            detail=(
                "CAGE_TRUSTED_OPERATOR_IDENTITIES is empty; fail-closed operator "
                "allowlist denies all HITL approvals."
            ),
        )
    for entry in sorted(trusted):
        if is_workload_identity(entry):
            logger.error(
                "Refused HITL approval: workload identity %r found in CAGE_TRUSTED_OPERATOR_IDENTITIES",
                entry,
            )
            raise HTTPException(
                status_code=403,
                detail=(
                    f"Workload identity '{entry}' is not permitted in "
                    "CAGE_TRUSTED_OPERATOR_IDENTITIES."
                ),
            )
    if operator.operator_urn not in trusted:
        logger.warning(
            "OIDC principal %r not in CAGE_TRUSTED_OPERATOR_IDENTITIES",
            operator.operator_urn,
        )
        raise HTTPException(
            status_code=403,
            detail=(
                f"OIDC principal '{operator.operator_urn}' is not authorized in "
                "CAGE_TRUSTED_OPERATOR_IDENTITIES"
            ),
        )
    return operator


def _extract_oidc_bearer_candidate(request: Request) -> str | None:
    """Extract an OIDC JWT candidate from ``X-Cage-Operator-Token`` or ``Authorization: Bearer``."""
    headers = getattr(request, "headers", None)
    if headers is None:
        return None
    op_token = headers.get("x-cage-operator-token") or headers.get(
        "X-Cage-Operator-Token"
    )
    if isinstance(op_token, str) and op_token.strip():
        raw = op_token.strip()
        return raw[7:].strip() if raw.startswith("Bearer ") else raw

    auth_header = headers.get("authorization") or headers.get("Authorization") or ""
    if isinstance(auth_header, str) and auth_header.startswith("Bearer "):
        candidate = auth_header[7:].strip()
        expected_internal = os.environ.get("CAGE_INTERNAL_TOKEN") or os.environ.get(
            "COMPLIANCE_BRIDGE_INTERNAL_TOKEN"
        )
        if expected_internal and hmac.compare_digest(candidate, expected_internal):
            return None
        return candidate
    return None


async def require_operator_identity(request: Request) -> OperatorPrincipal:
    """Extract and verify operator or caller identity from substrate headers or OIDC claims."""
    l5d_id, multi_l5d = _linkerd_client_id_header(request)
    if multi_l5d:
        logger.warning(
            "Multiple or comma-joined l5d-client-id headers detected — rejecting request"
        )
        raise HTTPException(
            status_code=401,
            detail="Multiple l5d-client-id headers presented",
        )
    if l5d_id is not None and not is_pod_local_connection(
        getattr(request, "scope", {})
    ):
        client = getattr(request, "client", None)
        logger.warning(
            "Refused l5d-client-id from %s: it did not come through the pod's "
            "Linkerd proxy",
            getattr(client, "host", "<none>"),
        )
        raise HTTPException(
            status_code=401,
            detail="l5d-client-id did not come through the Linkerd proxy",
        )

    # Channel 1 (Human Operator OIDC): Evaluated when OIDC is enabled and an OIDC
    # token is presented, even if the request also traversed a Linkerd proxy.
    allow_oidc = (
        os.environ.get("CAGE_OPERATOR_IDENTITY_ALLOW_OIDC", "false").lower() == "true"
    )
    oidc_token = _extract_oidc_bearer_candidate(request) if allow_oidc else None
    if allow_oidc and oidc_token:
        is_valid, jwt_claims, err_reason = await validate_operator_oidc_token(
            oidc_token
        )
        if not is_valid:
            logger.warning("OIDC operator assertion rejected: %s", err_reason)
            raise HTTPException(
                status_code=401,
                detail=f"OIDC JWT validation failed: {err_reason}",
            )
        jwt_sub = str(jwt_claims.get("sub", "")).strip()
        if is_workload_identity(jwt_sub):
            logger.warning("Rejected workload identity %r in OIDC sub claim", jwt_sub)
            raise HTTPException(
                status_code=403,
                detail=(
                    f"Workload identity '{jwt_sub}' cannot authenticate as a "
                    "human OIDC operator."
                ),
            )
        trusted = get_trusted_operator_identities()
        if not trusted:
            logger.warning(
                "OIDC operator authentication failed closed: CAGE_TRUSTED_OPERATOR_IDENTITIES is empty"
            )
            raise HTTPException(
                status_code=403,
                detail=(
                    "CAGE_TRUSTED_OPERATOR_IDENTITIES is empty; fail-closed operator "
                    "allowlist denies all OIDC principals."
                ),
            )
        for entry in sorted(trusted):
            if is_workload_identity(entry):
                logger.error(
                    "Workload identity %r found in CAGE_TRUSTED_OPERATOR_IDENTITIES",
                    entry,
                )
                raise HTTPException(
                    status_code=403,
                    detail=(
                        f"Workload identity '{entry}' is not permitted in "
                        "CAGE_TRUSTED_OPERATOR_IDENTITIES."
                    ),
                )
        if jwt_sub not in trusted:
            logger.warning(
                "OIDC principal %r not in CAGE_TRUSTED_OPERATOR_IDENTITIES",
                jwt_sub,
            )
            raise HTTPException(
                status_code=403,
                detail=(
                    f"OIDC principal '{jwt_sub}' is not authorized in "
                    "CAGE_TRUSTED_OPERATOR_IDENTITIES"
                ),
            )
        principal_hash = hashlib.sha256(jwt_sub.encode("utf-8")).hexdigest()
        return OperatorPrincipal(
            operator_urn=jwt_sub,
            channel_provenance="OIDC",
            auth_principal_hash=principal_hash,
        )

    # Channel 2 (SPIFFE SVID / Linkerd mTLS workload identity)
    try:
        svid: str | None = None
        if isinstance(l5d_id, str):
            svid = _linkerd_id_to_spiffe(l5d_id)
            if svid is None:
                logger.warning("Malformed l5d-client-id header rejected: %r", l5d_id)
                raise HTTPException(
                    status_code=401,
                    detail="Malformed l5d-client-id workload identity header",
                )
        else:
            raw_attr = None
            attrs = getattr(request, "attributes", None)
            if isinstance(attrs, dict):
                raw_attr = attrs.get("source.principal")
            elif attrs is not None:
                src = getattr(attrs, "source", None)
                if isinstance(src, dict):
                    raw_attr = src.get("principal")
            if isinstance(raw_attr, str) and _SPIFFE_ID.fullmatch(raw_attr):
                svid = raw_attr

        if svid:
            trusted = _trusted_operator_identities()
            if trusted and svid not in trusted and (l5d_id not in trusted):
                logger.warning(
                    "SVID principal %r (raw=%r) not in CAGE_TRUSTED_OPERATOR_IDENTITIES",
                    svid,
                    l5d_id,
                )
                raise HTTPException(
                    status_code=403,
                    detail=f"Operator principal '{svid}' is not authorized in CAGE_TRUSTED_OPERATOR_IDENTITIES",
                )
            principal_hash = hashlib.sha256(svid.encode("utf-8")).hexdigest()
            return OperatorPrincipal(
                operator_urn=svid,
                channel_provenance="SVID",
                auth_principal_hash=principal_hash,
            )
    except HTTPException:
        raise
    except Exception as exc:
        logger.debug("SVID extraction failed: %s", exc)

    # Channel 3: Dev-mode synthetic (dual-condition gate)
    env_override = os.environ.get("CAGE_ENV")
    enforcing_env = (env_override or _CAGE_ENV) in ("staging", "production", "prod")
    is_dev = not enforcing_env and (_CAGE_ENV == "dev" or env_override == "dev")
    allow_dev_syn = (
        os.environ.get("CAGE_OPERATOR_IDENTITY_ALLOW_DEV_SYNTHETIC", "false").lower()
        == "true"
    )
    if is_dev and allow_dev_syn:
        dev_urn = request.headers.get("x-cage-dev-operator-urn")
        if dev_urn:
            if not dev_urn.startswith("urn:cage:dev:"):
                raise HTTPException(
                    status_code=400,
                    detail="Dev synthetic operator URN must start with 'urn:cage:dev:' prefix",
                )
            logger.warning(
                "⚠️  Using DEV_SYNTHETIC operator identity: %s (never valid in production)",
                dev_urn,
            )
            principal_hash = hashlib.sha256(dev_urn.encode("utf-8")).hexdigest()
            return OperatorPrincipal(
                operator_urn=dev_urn,
                channel_provenance="DEV_SYNTHETIC",
                auth_principal_hash=principal_hash,
            )

    # Fail-closed: No valid operator identity found
    raise HTTPException(
        status_code=401,
        detail=(
            "No verified operator identity found. Required: OIDC JWT "
            "(if CAGE_OPERATOR_IDENTITY_ALLOW_OIDC=true), SPIFFE SVID "
            "(l5d-client-id), or dev header (if CAGE_ENV=dev and "
            "CAGE_OPERATOR_IDENTITY_ALLOW_DEV_SYNTHETIC=true)."
        ),
    )


async def require_human_operator_identity(request: Request) -> OperatorPrincipal:
    """Extract and verify a human operator identity for HITL approval endpoints (POAM-2026-196)."""
    principal = await require_operator_identity(request)
    return ensure_human_operator_principal(principal)


# ---------------------------------------------------------------------------
# Producer mesh-identity authentication (/v1/infra/events, /v1/audit/ingest)
# ---------------------------------------------------------------------------

TRUSTED_INFRA_PRODUCERS_ENV = "CAGE_TRUSTED_INFRA_PRODUCERS"
TRUSTED_AUDIT_PRODUCERS_ENV = "CAGE_TRUSTED_AUDIT_PRODUCERS"

_DEFAULT_TRUSTED_INFRA_PRODUCERS: frozenset[str] = frozenset(
    {
        "agentsight-daemon.governance-stack.serviceaccount.identity.linkerd.cluster.local",
        "cage-agentsight-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local",
        "cilium-monitor-exporter.kube-system.serviceaccount.identity.linkerd.cluster.local",
        "cilium-monitor-exporter.governance-stack.serviceaccount.identity.linkerd.cluster.local",
        "cage-lula-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local",
    }
)

_DEFAULT_TRUSTED_AUDIT_PRODUCERS: frozenset[str] = frozenset(
    {
        "lula-auditor.governance-stack.serviceaccount.identity.linkerd.cluster.local",
        "cage-lula-auditor-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local",
        "cage-lula-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local",
    }
)

# Transport-attested pod-scoped SPIFFE ID:
# spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>/pod/<pod-name>
_SPIFFE_POD_SVID = re.compile(
    r"^spiffe://([a-z0-9](?:[-a-z0-9.]*[a-z0-9])?)"
    r"/ns/([a-z0-9](?:[-a-z0-9]*[a-z0-9])?)"
    r"/sa/([a-z0-9](?:[-a-z0-9]*[a-z0-9])?)"
    r"/pod/([a-z0-9](?:[-a-z0-9.]*[a-z0-9])?)\Z"
)


@dataclass(frozen=True)
class ProducerPrincipal:
    """Verified Linkerd mesh workload identity of an evidence or audit producer.

    Attributes:
        linkerd_id: Canonical ``l5d-client-id`` DNS workload identity.
        spiffe_id: Canonical ``spiffe://<trust-domain>/ns/<ns>/sa/<sa>`` URI.
        service_account: Mesh-verified Kubernetes ServiceAccount (derived ``source``).
        namespace: Mesh-verified Kubernetes namespace.
        trust_domain: Mesh trust domain (for example ``cluster.local``).
        channel_provenance: ``LINKERD_MTLS`` (pod-local proxy) or ``DEV_LOOPBACK`` (LT-1).
        auth_principal_hash: SHA-256 hex digest of ``spiffe_id``.
        verified_pod_name: Pod name bound by a transport-level pod SVID, or ``None``
            when only ServiceAccount-level Linkerd mTLS is present.
    """

    linkerd_id: str
    spiffe_id: str
    service_account: str
    namespace: str
    trust_domain: str
    channel_provenance: Literal["LINKERD_MTLS", "DEV_LOOPBACK"]
    auth_principal_hash: str
    verified_pod_name: str | None = None


def _is_loopback_peer(scope: dict[str, object]) -> bool:
    """Return True if ``scope['client']`` is an IPv4/IPv6/IPv4-mapped loopback address."""
    import ipaddress

    endpoint = scope.get("client")
    if not isinstance(endpoint, (tuple, list)) or not endpoint:
        return False
    try:
        addr = ipaddress.ip_address(str(endpoint[0]))
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr.is_loopback


def _load_trusted_producers(env_var: str, defaults: frozenset[str]) -> frozenset[str]:
    """Resolve explicit trusted producer identities from ``env_var`` or ``defaults``.

    When ``env_var`` is unset, returns ``defaults``. When ``env_var`` is set to
    an empty/whitespace string, returns ``frozenset()`` (denies all producers).
    Raises HTTP 500 fail-closed if any configured identity violates Linkerd DNS
    or SPIFFE URI syntax.
    """
    raw = os.environ.get(env_var)
    if raw is None:
        return defaults
    entries = frozenset(part.strip() for part in raw.split(",") if part.strip())
    malformed = sorted(
        item
        for item in entries
        if not _LINKERD_IDENTITY.fullmatch(item) and not _SPIFFE_ID.fullmatch(item)
    )
    if malformed:
        logger.error(
            "%s contains malformed workload identity entries: %s",
            env_var,
            malformed,
        )
        raise HTTPException(
            status_code=500,
            detail=f"{env_var} contains malformed workload identity entries",
        )
    return entries


def _extract_verified_pod_name(
    request: Request,
    *,
    trust_domain: str,
    namespace: str,
    service_account: str,
) -> str | None:
    """Extract pod name ONLY from substrate transport pod SVID, never HTTP headers."""
    candidates: list[object] = []
    scope = getattr(request, "scope", None)
    if isinstance(scope, dict) and "transport_pod_svid" in scope:
        candidates.append(scope.get("transport_pod_svid"))
    attr_source = getattr(getattr(request, "attributes", None), "source", None)
    if isinstance(attr_source, dict) and "principal" in attr_source:
        candidates.append(attr_source.get("principal"))

    expected_sa_svid = f"spiffe://{trust_domain}/ns/{namespace}/sa/{service_account}"
    for raw in candidates:
        if raw is None:
            continue
        if not isinstance(raw, str):
            raise HTTPException(
                status_code=403,
                detail="Malformed transport pod SVID attribute",
            )
        if raw == expected_sa_svid:
            # ServiceAccount-level transport SVID matches Linkerd identity; no pod claim bound.
            continue
        match = _SPIFFE_POD_SVID.fullmatch(raw)
        if match is None:
            raise HTTPException(
                status_code=403,
                detail="Transport pod SVID does not satisfy pod-scoped SPIFFE grammar",
            )
        td, ns, sa, pod_name = (
            match.group(1),
            match.group(2),
            match.group(3),
            match.group(4),
        )
        if td != trust_domain or ns != namespace or sa != service_account:
            logger.warning(
                "Transport pod SVID (%s/%s/%s) disagrees with Linkerd identity (%s/%s/%s)",
                td,
                ns,
                sa,
                trust_domain,
                namespace,
                service_account,
            )
            raise HTTPException(
                status_code=403,
                detail="Transport pod SVID does not match verified Linkerd identity",
            )
        if len(pod_name) > 128:
            raise HTTPException(
                status_code=403,
                detail="Transport pod SVID pod name exceeds maximum length",
            )
        return pod_name
    return None


def _verify_mesh_producer(
    request: Request,
    *,
    trusted: frozenset[str],
    env_var: str,
    endpoint_label: str,
) -> ProducerPrincipal:
    """Authenticate and authorize a workload producer via Linkerd ``l5d-client-id``.

    Shared bearer tokens (``CAGE_INTERNAL_TOKEN``) are never accepted as a
    substitute for verified Linkerd mTLS identity (``F-85`` / ``POAM-2026-167``).
    """
    from src.gateway.server.workload_identity import is_dev_loopback_identity_allowed

    if hasattr(request.headers, "get") and request.headers.get(
        "x-cage-source-principal"
    ):
        logger.warning(
            "Ignored unverified client-supplied x-cage-source-principal header on %s",
            endpoint_label,
        )

    l5d_id, duplicate_headers = _linkerd_client_id_header(request)
    if duplicate_headers:
        raise HTTPException(
            status_code=401,
            detail="Multiple l5d-client-id headers presented",
        )
    if l5d_id is None:
        raise HTTPException(
            status_code=401,
            detail="Missing Linkerd workload identity header (l5d-client-id)",
        )

    scope_obj = getattr(request, "scope", {})
    scope: dict[str, object] = scope_obj if isinstance(scope_obj, dict) else {}
    channel: Literal["LINKERD_MTLS", "DEV_LOOPBACK"]
    if is_pod_local_connection(scope):
        channel = "LINKERD_MTLS"
    elif is_dev_loopback_identity_allowed(os.environ) and _is_loopback_peer(scope):
        channel = "DEV_LOOPBACK"
    else:
        client = getattr(request, "client", None)
        logger.warning(
            "Refused producer l5d-client-id on %s from %s: not from pod-local Linkerd proxy",
            endpoint_label,
            getattr(client, "host", "<none>"),
        )
        raise HTTPException(
            status_code=401,
            detail="l5d-client-id did not come through the Linkerd proxy",
        )

    match = _LINKERD_IDENTITY.fullmatch(l5d_id)
    if match is None:
        raise HTTPException(
            status_code=401,
            detail="Malformed l5d-client-id workload identity header",
        )

    sa, namespace, trust_domain = match.group(1), match.group(2), match.group(3)
    spiffe_id = f"spiffe://{trust_domain}/ns/{namespace}/sa/{sa}"

    if l5d_id not in trusted and spiffe_id not in trusted:
        logger.warning(
            "Rejected unauthorized %s producer workload %s (not in %s)",
            endpoint_label,
            l5d_id,
            env_var,
        )
        raise HTTPException(
            status_code=403,
            detail=f"Workload identity is not an authorized {endpoint_label} producer",
        )

    verified_pod_name = _extract_verified_pod_name(
        request,
        trust_domain=trust_domain,
        namespace=namespace,
        service_account=sa,
    )
    principal_hash = hashlib.sha256(spiffe_id.encode()).hexdigest()
    return ProducerPrincipal(
        linkerd_id=l5d_id,
        spiffe_id=spiffe_id,
        service_account=sa,
        namespace=namespace,
        trust_domain=trust_domain,
        channel_provenance=channel,
        auth_principal_hash=principal_hash,
        verified_pod_name=verified_pod_name,
    )


async def require_infra_event_producer(request: Request) -> ProducerPrincipal:
    """Authenticate and authorize a ``POST /v1/infra/events`` mesh producer."""
    trusted = _load_trusted_producers(
        TRUSTED_INFRA_PRODUCERS_ENV, _DEFAULT_TRUSTED_INFRA_PRODUCERS
    )
    return _verify_mesh_producer(
        request,
        trusted=trusted,
        env_var=TRUSTED_INFRA_PRODUCERS_ENV,
        endpoint_label="infra-event",
    )


async def require_audit_ingest_producer(request: Request) -> ProducerPrincipal:
    """Authenticate and authorize a ``POST /v1/audit/ingest`` mesh producer."""
    trusted = _load_trusted_producers(
        TRUSTED_AUDIT_PRODUCERS_ENV, _DEFAULT_TRUSTED_AUDIT_PRODUCERS
    )
    return _verify_mesh_producer(
        request,
        trusted=trusted,
        env_var=TRUSTED_AUDIT_PRODUCERS_ENV,
        endpoint_label="audit-ingest",
    )

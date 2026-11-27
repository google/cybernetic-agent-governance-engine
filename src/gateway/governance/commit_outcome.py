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

"""Typed outcomes of a governed committing run and of an approval redemption.

A committing run (a governed tool that commits, seals and actuates) ends in
one of a few outcomes that demand different client responses. They used to
reach clients as free text (``"BLOCKED: ..."``, ``"DEFERRED: ..."``), and an
approval that could not be redeemed was one generic sentence whatever the
reason (POAM-2026-245). A client that must decide whether to wait for the
same approval or give up therefore had nothing to decide on but prose.

This module is the kernel's single definition of those outcomes:

* :class:`ApprovalRedemptionRefusal` names every reason an approval
  (``deferred_id``) is not redeemable, one member per distinct queue state;
* :data:`RETRYABLE_REDEMPTION_REFUSALS` says which of them can still turn
  into a redeemable approval *on the same ticket* (the approval has simply
  not been recorded yet). Clients read retryability from here; they never
  re-derive it;
* :class:`CommitStatus` / :class:`CommitOutcome` are the committing run's
  structured result, with the human ``message`` kept separate and never
  load-bearing. :meth:`CommitOutcome.to_wire` / :meth:`CommitOutcome.from_wire`
  are the wire form carried in an MCP ``CallToolResult.structuredContent``.

The wire form carries an additive KMS signature (``signature``) and request-binding
fields (``tool_name``, ``idempotency_key``, plus informational ``issued_at``)
verified out of band by ``kid`` against the gateway's JWKS (POAM-2026-249).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import inspect
import logging
import re
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from mcp.types import CallToolResult

logger = logging.getLogger("Gateway.Governance.CommitOutcome")


class ApprovalRedemptionRefusal(str, Enum):
    """Why an approval (``deferred_id``) could not be redeemed.

    One member per distinct state the approval can be in; none is a
    catch-all hiding a distinction the client must act on.

    PENDING:                   Parked, no approval recorded yet.
    QUORUM_INCOMPLETE:         Some, but not enough, approvals recorded yet.
    UNKNOWN_OR_EXPIRED:        No such ticket: never parked, or its key expired
                               (the two cannot be told apart).
    NOT_AN_APPROVAL:           The ticket is not a human-approval deferral.
    CONSUMED:                  Already redeemed (spent exactly once).
    EXPIRED:                   Resolved by the expiry sweep, never approved.
    RESOLVED_WITHOUT_APPROVAL: Resolved by automated context injection, not by
                               an approval quorum.
    QUORUM_NOT_DISTINCT:       Resolved, but its approvals collapse to fewer
                               distinct approvers than the quorum. A resolved
                               ticket is immutable, so this never recovers.
    UNRECOGNIZED_STATE:        The ticket's status or resolution is not one the
                               kernel knows.
    ACTION_MISMATCH:           Parked for another action.
    STALE_BARRIER_PREVIEW:     Approvals were given against a barrier preview
                               other than the ticket's current one.
    NO_APPROVED_PARAMS:        The ticket carries no approved params.
    PARAMS_NOT_COVERED:        The approved params do not cover the params the
                               committing run evaluated.
    """

    PENDING = "PENDING"
    QUORUM_INCOMPLETE = "QUORUM_INCOMPLETE"
    UNKNOWN_OR_EXPIRED = "UNKNOWN_OR_EXPIRED"
    NOT_AN_APPROVAL = "NOT_AN_APPROVAL"
    CONSUMED = "CONSUMED"
    EXPIRED = "EXPIRED"
    RESOLVED_WITHOUT_APPROVAL = "RESOLVED_WITHOUT_APPROVAL"
    QUORUM_NOT_DISTINCT = "QUORUM_NOT_DISTINCT"
    UNRECOGNIZED_STATE = "UNRECOGNIZED_STATE"
    ACTION_MISMATCH = "ACTION_MISMATCH"
    STALE_BARRIER_PREVIEW = "STALE_BARRIER_PREVIEW"
    NO_APPROVED_PARAMS = "NO_APPROVED_PARAMS"
    PARAMS_NOT_COVERED = "PARAMS_NOT_COVERED"


#: Refusals after which the *same* ticket can still become redeemable: the
#: approval has not been recorded (or not fully) yet. Every other refusal is
#: terminal for that ticket.
RETRYABLE_REDEMPTION_REFUSALS: Final[frozenset[ApprovalRedemptionRefusal]] = frozenset(
    {
        ApprovalRedemptionRefusal.PENDING,
        ApprovalRedemptionRefusal.QUORUM_INCOMPLETE,
    }
)


def is_retryable_refusal(refusal: ApprovalRedemptionRefusal | None) -> bool:
    """Whether ``refusal`` leaves the same ticket redeemable later.

    ``None`` (no refusal reason, or one that could not be decoded) is
    terminal: an unknown reason never earns a retry.
    """
    return refusal in RETRYABLE_REDEMPTION_REFUSALS


def decode_redemption_refusal(raw: object) -> ApprovalRedemptionRefusal | None:
    """The member whose value is exactly ``raw``; ``None`` for anything else."""
    if not isinstance(raw, str):
        return None
    try:
        return ApprovalRedemptionRefusal(raw)
    except ValueError:
        return None


class CommitStatus(str, Enum):
    """How a committing run ended.

    EXECUTED:            The action was sealed and actuated.
    DRY_RUN:             The action was sealed; a dry run actuates nothing.
    REFUSED:             Nothing was executed; the run was refused.
    DEFERRED:            Nothing was sealed, committed or refused; the run deferred.
    INDETERMINATE:       Post-wire outcome is UNKNOWN; reservations remain held.
    UNSETTLED_DUPLICATE: Duplicate idempotency key whose prior attempt is IN_FLIGHT/UNKNOWN.
    """

    EXECUTED = "EXECUTED"
    DRY_RUN = "DRY_RUN"
    REFUSED = "REFUSED"
    DEFERRED = "DEFERRED"
    INDETERMINATE = "INDETERMINATE"
    UNSETTLED_DUPLICATE = "UNSETTLED_DUPLICATE"


#: Statuses after which nothing was guaranteed executed.
NOT_EXECUTED_STATUSES: Final[frozenset[CommitStatus]] = frozenset(
    {
        CommitStatus.REFUSED,
        CommitStatus.DEFERRED,
        CommitStatus.INDETERMINATE,
        CommitStatus.UNSETTLED_DUPLICATE,
    }
)

#: Statuses indicating outcome is indeterminate or awaiting settlement, not a policy refusal.
INDETERMINATE_STATUSES: Final[frozenset[CommitStatus]] = frozenset(
    {CommitStatus.INDETERMINATE, CommitStatus.UNSETTLED_DUPLICATE}
)
NON_REFUSAL_STATUSES: Final[frozenset[CommitStatus]] = INDETERMINATE_STATUSES

#: Version tag of :meth:`CommitOutcome.to_wire`. A payload without exactly
#: this tag is not a commit outcome.
COMMIT_OUTCOME_SCHEMA: Final[str] = "cage.commit_outcome/1"


#: Valid fields inside the ``CommitOutcome.signature`` block.
_ALLOWED_SIGNATURE_KEYS: Final[frozenset[str]] = frozenset(
    {"algorithm", "kid", "value"}
)
#: Signature algorithms admitted for CommitOutcome verification (matching JWKS).
_ALLOWED_SIGNATURE_ALGORITHMS: Final[frozenset[str]] = frozenset({"ES256", "EdDSA"})
#: Embedded key fields rejected anywhere in an envelope/outcome payload.
_EMBEDDED_KEY_FIELDS: Final[frozenset[str]] = frozenset(
    {"jwk", "jku", "x5c", "x5u", "public_key", "publicKey", "pem"}
)
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
_P256_COORDINATE_BYTES: Final[int] = 32


class CommitOutcomeDecodeError(ValueError):
    """A payload is not a :class:`CommitOutcome` this kernel understands."""


def _validate_optional_str(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise CommitOutcomeDecodeError(
            f"commit outcome {field_name} must be a non-empty string"
        )
    return value


def _validate_signature_mapping(sig: object) -> Mapping[str, str] | None:
    if sig is None:
        return None
    if not isinstance(sig, Mapping):
        raise CommitOutcomeDecodeError("commit outcome signature must be a mapping")
    unexpected = set(sig.keys()) - _ALLOWED_SIGNATURE_KEYS
    if unexpected:
        raise CommitOutcomeDecodeError(
            f"commit outcome signature contains unexpected fields: {sorted(unexpected)!r}"
        )
    alg = sig.get("algorithm")
    kid = sig.get("kid")
    val = sig.get("value")
    if (
        not isinstance(alg, str)
        or not alg
        or not isinstance(kid, str)
        or not kid
        or not isinstance(val, str)
        or not val
    ):
        raise CommitOutcomeDecodeError(
            "commit outcome signature requires non-empty algorithm, kid, and value"
        )
    if alg not in _ALLOWED_SIGNATURE_ALGORITHMS:
        raise CommitOutcomeDecodeError(
            f"unsupported commit outcome signature algorithm {alg!r}"
        )
    return MappingProxyType({"algorithm": alg, "kid": kid, "value": val})


def _check_expected_binding(
    *,
    tool_name: str | None,
    idempotency_key: str | None,
    expected_tool_name: str | None,
    expected_idempotency_key: str | None,
) -> None:
    """Enforce exact request binding when ``tool_name`` or ``idempotency_key`` is checked."""
    if expected_tool_name is not None and tool_name is not None:
        if tool_name != expected_tool_name:
            raise CommitOutcomeDecodeError(
                f"commit outcome tool_name mismatch: {tool_name!r} != {expected_tool_name!r}"
            )
    if expected_idempotency_key is not None and idempotency_key is not None:
        if idempotency_key != expected_idempotency_key:
            raise CommitOutcomeDecodeError("commit outcome idempotency_key mismatch")


@dataclass(frozen=True)
class CommitOutcome:
    """The structured result of one committing run.

    Attributes:
        status: How the run ended.
        message: Human-readable account. Never load-bearing: no decision may
            be taken on it.
        redemption_refusal: Why the approval named by the request could not
            be redeemed, when that is why the run was ``REFUSED``; otherwise
            ``None``.
        deferred_id: For ``DEFERRED``: the ticket that stays resolvable (the
            retained approval itself when ``approval_retained``).
        approval_retained: For ``DEFERRED`` after an approval: the approval was
            not spent and stays redeemable (POAM-2026-104).
        tool_name: Bound gateway tool name for cross-tool replay prevention.
        idempotency_key: Bound client idempotency key for per-request replay
            prevention.
        issued_at: Informational ISO-8601 UTC signing timestamp.
        signature: Detached-format ``{algorithm, kid, value}`` block over the
            RFC 8785 JCS canonical body excluding ``signature``.
    """

    status: CommitStatus
    message: str
    redemption_refusal: ApprovalRedemptionRefusal | None = None
    deferred_id: str | None = None
    approval_retained: bool = False
    tool_name: str | None = None
    idempotency_key: str | None = None
    issued_at: str | None = None
    signature: Mapping[str, str] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, CommitStatus):
            raise TypeError(f"status must be a CommitStatus, not {self.status!r}")
        if self.redemption_refusal is not None and (
            self.status is not CommitStatus.REFUSED
            or not isinstance(self.redemption_refusal, ApprovalRedemptionRefusal)
        ):
            raise ValueError("redemption_refusal is only set on a REFUSED outcome")
        if self.approval_retained and self.status is not CommitStatus.DEFERRED:
            raise ValueError("approval_retained is only set on a DEFERRED outcome")
        if self.tool_name is not None and (
            not isinstance(self.tool_name, str) or not self.tool_name
        ):
            raise ValueError("tool_name must be a non-empty string when set")
        if self.idempotency_key is not None and (
            not isinstance(self.idempotency_key, str) or not self.idempotency_key
        ):
            raise ValueError("idempotency_key must be a non-empty string when set")
        if self.issued_at is not None and (
            not isinstance(self.issued_at, str) or not self.issued_at
        ):
            raise ValueError("issued_at must be a non-empty string when set")
        if self.signature is not None and not isinstance(
            self.signature, MappingProxyType
        ):
            object.__setattr__(
                self, "signature", _validate_signature_mapping(self.signature)
            )

    @property
    def executed(self) -> bool:
        """Whether the action was actuated."""
        return self.status is CommitStatus.EXECUTED

    def to_wire(self, *, include_signature: bool = True) -> dict[str, Any]:
        """JSON-safe wire form (MCP ``structuredContent`` & HTTP ``outcome``)."""
        wire: dict[str, Any] = {
            "schema": COMMIT_OUTCOME_SCHEMA,
            "status": self.status.value,
            "message": self.message,
            "redemption_refusal": (
                self.redemption_refusal.value
                if self.redemption_refusal is not None
                else None
            ),
            "deferred_id": self.deferred_id,
            "approval_retained": self.approval_retained,
        }
        if self.tool_name is not None:
            wire["tool_name"] = self.tool_name
        if self.idempotency_key is not None:
            wire["idempotency_key"] = self.idempotency_key
        if self.issued_at is not None:
            wire["issued_at"] = self.issued_at
        if include_signature and self.signature is not None:
            wire["signature"] = dict(self.signature)
        return wire

    def with_binding(
        self,
        *,
        tool_name: str | None = None,
        idempotency_key: str | None = None,
        issued_at: str | None = None,
        signature: Mapping[str, str] | None = None,
    ) -> CommitOutcome:
        """Return a copy with additive request binding / signature metadata."""
        return replace(
            self,
            tool_name=tool_name if tool_name is not None else self.tool_name,
            idempotency_key=(
                idempotency_key if idempotency_key is not None else self.idempotency_key
            ),
            issued_at=issued_at if issued_at is not None else self.issued_at,
            signature=signature if signature is not None else self.signature,
        )

    @classmethod
    def from_wire(
        cls,
        payload: object,
        *,
        expected_tool_name: str | None = None,
        expected_idempotency_key: str | None = None,
    ) -> CommitOutcome:
        """Decode :meth:`to_wire` output, failing closed.

        Raises:
            CommitOutcomeDecodeError: ``payload`` is not a mapping, embeds public
                key material, lacks the exact schema tag, carries an unknown or
                missing status, has malformed signature/binding fields, or
                violates an expected bound field.
        """
        if not isinstance(payload, Mapping):
            raise CommitOutcomeDecodeError("commit outcome is not a mapping")
        embedded = _EMBEDDED_KEY_FIELDS.intersection(payload.keys())
        if embedded:
            raise CommitOutcomeDecodeError(
                f"commit outcome contains embedded key material: {sorted(embedded)!r}"
            )
        if payload.get("schema") != COMMIT_OUTCOME_SCHEMA:
            raise CommitOutcomeDecodeError(
                f"commit outcome schema is not {COMMIT_OUTCOME_SCHEMA!r}"
            )
        raw_status = payload.get("status")
        if not isinstance(raw_status, str):
            raise CommitOutcomeDecodeError("commit outcome carries no status")
        try:
            status = CommitStatus(raw_status)
        except ValueError as exc:
            raise CommitOutcomeDecodeError(
                f"unknown commit outcome status {raw_status[:32]!r}"
            ) from exc
        tool_name = _validate_optional_str(payload.get("tool_name"), "tool_name")
        idempotency_key = _validate_optional_str(
            payload.get("idempotency_key"), "idempotency_key"
        )
        issued_at = _validate_optional_str(payload.get("issued_at"), "issued_at")
        signature = _validate_signature_mapping(payload.get("signature"))

        _check_expected_binding(
            tool_name=tool_name,
            idempotency_key=idempotency_key,
            expected_tool_name=expected_tool_name,
            expected_idempotency_key=expected_idempotency_key,
        )

        message = payload.get("message")
        deferred_id = payload.get("deferred_id")
        return cls(
            status=status,
            message=message if isinstance(message, str) else "",
            redemption_refusal=(
                decode_redemption_refusal(payload.get("redemption_refusal"))
                if status is CommitStatus.REFUSED
                else None
            ),
            deferred_id=(
                deferred_id
                if status is CommitStatus.DEFERRED
                and isinstance(deferred_id, str)
                and deferred_id
                else None
            ),
            approval_retained=(
                status is CommitStatus.DEFERRED
                and payload.get("approval_retained") is True
            ),
            tool_name=tool_name,
            idempotency_key=idempotency_key,
            issued_at=issued_at,
            signature=signature,
        )


def extract_request_idempotency_key(
    params: Mapping[str, Any] | None, *, attempt: Any | None = None
) -> str | None:
    """Return the caller's request idempotency key from tool args or active attempt."""
    if isinstance(params, Mapping):
        val = params.get("idempotency_key")
        if isinstance(val, str) and val:
            return val
    if attempt is not None:
        claimed = getattr(attempt, "_claimed_idempotency_key", None)
        if isinstance(claimed, str) and claimed:
            return claimed
    return None


def _normalize_signing_alg(raw_alg: str) -> str:
    upper = raw_alg.strip().upper()
    if upper in {"EDDSA", "ED25519"}:
        return "EdDSA"
    if upper in {"ES256", "ECDSA_P256_SHA256"}:
        return "ES256"
    raise ValueError(
        f"Unsupported CommitOutcome signing algorithm {raw_alg!r} (expected ES256 or EdDSA)"
    )


async def sign_commit_outcome_wire(
    outcome_or_wire: CommitOutcome | Mapping[str, Any],
    *,
    tool_name: str | None = None,
    idempotency_key: str | None = None,
    issued_at: str | None = None,
    signer: Any | None = None,
) -> dict[str, Any]:
    """Attach request binding + KMS signature (or posture-gated dev fallback) to a wire outcome."""
    from src.gateway.governance.env_posture import is_enforcing, resolve_posture
    from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
    from src.gateway.governance.kms_signer import get_governance_signer

    if isinstance(outcome_or_wire, CommitOutcome):
        wire = outcome_or_wire.to_wire(include_signature=False)
    elif isinstance(outcome_or_wire, Mapping):
        CommitOutcome.from_wire(outcome_or_wire)
        wire = {k: v for k, v in outcome_or_wire.items() if k != "signature"}
    else:
        raise TypeError(
            f"Expected CommitOutcome or mapping, got {type(outcome_or_wire).__name__}"
        )

    if tool_name and not wire.get("tool_name"):
        wire["tool_name"] = tool_name
    if idempotency_key and not wire.get("idempotency_key"):
        wire["idempotency_key"] = idempotency_key
    if not wire.get("issued_at"):
        wire["issued_at"] = issued_at or (
            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        )

    active_signer = signer if signer is not None else get_governance_signer()
    kms_active = bool(
        getattr(active_signer, "is_kms_active", False)
        and getattr(active_signer, "kms_active", True) is not False
    )
    if not kms_active:
        if is_enforcing(resolve_posture()):
            raise RuntimeError(
                "Cannot emit unsigned CommitOutcome in enforcing posture: KMS signer is inactive"
            )
        logger.warning(
            "KMS not active in non-enforcing posture — CommitOutcome emitted unsigned"
        )
        return wire

    jwk = active_signer.public_jwk
    kid = str(jwk["kid"])
    alg_label = _normalize_signing_alg(str(jwk.get("alg", "ES256")))
    canonical = jcs_canonicalize_plan(wire)

    if alg_label == "EdDSA":
        if not hasattr(active_signer, "sign_raw_async"):
            raise RuntimeError("EdDSA CommitOutcome signing requires sign_raw_async")
        sig_bytes = await active_signer.sign_raw_async(canonical)
    else:
        digest = hashlib.sha256(canonical).digest()
        sig_hex = await active_signer.sign_precomputed_digest_async(digest)
        sig_bytes = bytes.fromhex(sig_hex)

    sig_b64 = base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode("ascii")
    wire["signature"] = {
        "algorithm": alg_label,
        "kid": kid,
        "value": sig_b64,
    }
    return wire


def _decode_b64url_strict(value: str, *, field_name: str) -> bytes:
    if not _B64URL_RE.match(value):
        raise CommitOutcomeDecodeError(f"invalid base64url in {field_name}")
    unpadded = value.rstrip("=")
    if not unpadded or len(unpadded) % 4 == 1:
        raise CommitOutcomeDecodeError(f"invalid base64url length in {field_name}")
    padded = unpadded + ("=" * ((4 - len(unpadded) % 4) % 4))
    try:
        decoded = base64.urlsafe_b64decode(padded)
    except Exception as exc:
        raise CommitOutcomeDecodeError(
            f"failed to decode base64url in {field_name}: {exc}"
        ) from exc
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical != unpadded:
        raise CommitOutcomeDecodeError(
            f"non-canonical base64url padding in {field_name}"
        )
    return decoded


def _coerce_public_key(raw_key: Any) -> Any:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519

    if isinstance(raw_key, (ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey)):
        return raw_key
    if isinstance(raw_key, bytes):
        return serialization.load_pem_public_key(raw_key)
    if isinstance(raw_key, str):
        return serialization.load_pem_public_key(raw_key.encode("utf-8"))
    if isinstance(raw_key, Mapping):
        if any(f in raw_key for f in ("d", "p", "q", "dp", "dq", "qi", "oth", "k")):
            raise CommitOutcomeDecodeError("refusing private key material in JWK")
        kty = raw_key.get("kty")
        if kty == "EC":
            if raw_key.get("crv") != "P-256":
                raise CommitOutcomeDecodeError(
                    f"unsupported EC curve {raw_key.get('crv')!r}"
                )
            x_b = _decode_b64url_strict(str(raw_key.get("x", "")), field_name="JWK.x")
            y_b = _decode_b64url_strict(str(raw_key.get("y", "")), field_name="JWK.y")
            if len(x_b) != _P256_COORDINATE_BYTES or len(y_b) != _P256_COORDINATE_BYTES:
                raise CommitOutcomeDecodeError("EC P-256 coordinates must be 32 bytes")
            return ec.EllipticCurvePublicNumbers(
                int.from_bytes(x_b, "big"), int.from_bytes(y_b, "big"), ec.SECP256R1()
            ).public_key()
        if kty == "OKP":
            if raw_key.get("crv") != "Ed25519":
                raise CommitOutcomeDecodeError(
                    f"unsupported OKP curve {raw_key.get('crv')!r}"
                )
            x_b = _decode_b64url_strict(str(raw_key.get("x", "")), field_name="JWK.x")
            if len(x_b) != _P256_COORDINATE_BYTES:
                raise CommitOutcomeDecodeError("Ed25519 public key must be 32 bytes")
            return ed25519.Ed25519PublicKey.from_public_bytes(x_b)
        raise CommitOutcomeDecodeError(f"unsupported JWK kty={kty!r}")
    raise CommitOutcomeDecodeError(
        f"unsupported public key object {type(raw_key).__name__}"
    )


def _verify_outcome_signature_bytes(
    *,
    canonical_bytes: bytes,
    algorithm: str,
    signature_b64: str,
    public_key: Any,
) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils

    sig_bytes = _decode_b64url_strict(signature_b64, field_name="signature.value")
    try:
        if algorithm == "EdDSA":
            if not isinstance(public_key, ed25519.Ed25519PublicKey):
                raise CommitOutcomeDecodeError(
                    f"algorithm EdDSA requires Ed25519 key, got {type(public_key).__name__}"
                )
            public_key.verify(sig_bytes, canonical_bytes)
            return
        if algorithm == "ES256":
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise CommitOutcomeDecodeError(
                    f"algorithm ES256 requires EC key, got {type(public_key).__name__}"
                )
            if public_key.curve.name != "secp256r1":
                raise CommitOutcomeDecodeError(
                    f"algorithm ES256 requires P-256 key, got {public_key.curve.name!r}"
                )
            key_size = 32
            if len(sig_bytes) == key_size * 2:
                try:
                    utils.decode_dss_signature(sig_bytes)
                    der_sig = sig_bytes
                except ValueError:
                    r = int.from_bytes(sig_bytes[:key_size], "big")
                    s = int.from_bytes(sig_bytes[key_size:], "big")
                    der_sig = utils.encode_dss_signature(r, s)
            else:
                der_sig = sig_bytes
            public_key.verify(der_sig, canonical_bytes, ec.ECDSA(hashes.SHA256()))
            return
    except InvalidSignature as exc:
        raise CommitOutcomeDecodeError("commit outcome signature invalid") from exc
    raise CommitOutcomeDecodeError(f"unsupported signature algorithm {algorithm!r}")


async def verify_commit_outcome_wire(
    payload: object,
    *,
    key_resolver: Callable[[str], Awaitable[Any] | Any] | None = None,
    public_keys: Mapping[str, Any] | None = None,
    require_signature: bool | None = None,
    expected_tool_name: str | None = None,
    expected_idempotency_key: str | None = None,
) -> CommitOutcome:
    """Decode and cryptographically verify a ``CommitOutcome`` payload fail-closed.

    Verification rules:
    1. Reject embedded keys, malformed JSON types, and schema mismatches.
    2. In enforcing postures (or when ``require_signature=True``), disabling
       verification is refused at call time and an absent signature fails closed.
    3. Whenever ``signature`` is present (in ANY posture, including dev/test),
       resolve the signing key strictly out of band by ``kid`` (never falling
       back on unknown ``kid``), verify ``ES256``/``EdDSA`` over RFC 8785 JCS
       bytes excluding ``signature``, and require exact agreement on
       ``expected_tool_name`` and ``expected_idempotency_key`` when provided.
    """
    from src.gateway.governance.env_posture import is_enforcing, resolve_posture
    from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

    enforcing = is_enforcing(resolve_posture())
    if require_signature is False and enforcing:
        raise ValueError(
            "Disabling CommitOutcome signature verification is prohibited in enforcing posture"
        )
    must_sign = bool(enforcing or require_signature is True)

    outcome = CommitOutcome.from_wire(
        payload,
        expected_tool_name=expected_tool_name,
        expected_idempotency_key=expected_idempotency_key,
    )
    if outcome.signature is None:
        if must_sign:
            raise CommitOutcomeDecodeError(
                "commit outcome is missing required KMS signature"
            )
        return outcome

    # When signed, any requested request bindings must be present in the signed body.
    if expected_tool_name is not None and outcome.tool_name is None:
        raise CommitOutcomeDecodeError(
            "signed commit outcome is missing required bound 'tool_name'"
        )
    if expected_idempotency_key is not None and outcome.idempotency_key is None:
        raise CommitOutcomeDecodeError(
            "signed commit outcome is missing required bound 'idempotency_key'"
        )

    assert isinstance(payload, Mapping)
    kid = outcome.signature["kid"]
    alg = outcome.signature["algorithm"]
    sig_val = outcome.signature["value"]

    raw_key: Any = None
    if public_keys is not None:
        raw_key = public_keys.get(kid)
    elif key_resolver is not None:
        resolved = key_resolver(kid)
        raw_key = await resolved if inspect.isawaitable(resolved) else resolved
    else:
        from src.gateway.governance.jwks import get_jwks

        raw_key = get_jwks().get_pem(kid)

    if raw_key is None:
        raise CommitOutcomeDecodeError(f"commit outcome signed by unknown kid={kid!r}")

    public_key = _coerce_public_key(raw_key)
    unsigned_dict = {k: v for k, v in payload.items() if k != "signature"}
    canonical = jcs_canonicalize_plan(unsigned_dict)
    _verify_outcome_signature_bytes(
        canonical_bytes=canonical,
        algorithm=alg,
        signature_b64=sig_val,
        public_key=public_key,
    )
    return outcome


def commit_tool_result(
    outcome: CommitOutcome,
    *,
    structured_override: Mapping[str, Any] | None = None,
) -> CallToolResult:
    """Build the MCP ``CallToolResult`` for a committing run's :class:`CommitOutcome`.

    The typed outcome rides in ``structuredContent`` (:meth:`CommitOutcome.to_wire`
    or a pre-signed payload override); ``content`` carries only its prose. ``isError``
    is set whenever nothing was guaranteed executed (:data:`NOT_EXECUTED_STATUSES`),
    so a caller that reads only ``isError`` or text still fails closed
    (POAM-2026-245 / POAM-2026-255).
    """
    from mcp.types import CallToolResult, TextContent

    return CallToolResult(
        content=[TextContent(type="text", text=outcome.message)],
        structuredContent=(
            dict(structured_override)
            if structured_override is not None
            else outcome.to_wire()
        ),
        isError=outcome.status in NOT_EXECUTED_STATUSES,
    )


async def signed_commit_tool_result(
    outcome: CommitOutcome,
    *,
    tool_name: str | None = None,
    idempotency_key: str | None = None,
    signer: Any | None = None,
) -> CallToolResult:
    """Build a ``CallToolResult`` carrying a request-bound, KMS-signed ``CommitOutcome``."""
    signed_wire = await sign_commit_outcome_wire(
        outcome,
        tool_name=tool_name,
        idempotency_key=idempotency_key,
        signer=signer,
    )
    return commit_tool_result(outcome, structured_override=signed_wire)

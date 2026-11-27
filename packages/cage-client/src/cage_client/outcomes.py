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

"""Structured governance preview decisions and signed committing-tool outcomes.

Mirrors the gateway's ``CommitOutcome`` (``cage.commit_outcome/1``) and
``ApprovalRedemptionRefusal`` contracts cleanly in the standalone ``cage-client``
package (zero monorepo ``src`` imports).
"""

from __future__ import annotations

import math
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from types import MappingProxyType
from typing import Any

from ._jcs import canonicalize
from .crypto import verify_envelope_signature
from .envelope import GovernanceEnvelope
from .exceptions import CommitOutcomeDecodeError
from .jwks import PublicKey

COMMIT_OUTCOME_SCHEMA = "cage.commit_outcome/1"

_ALLOWED_SIGNATURE_KEYS: frozenset[str] = frozenset({"algorithm", "kid", "value"})
_ALLOWED_SIGNATURE_ALGORITHMS: frozenset[str] = frozenset({"ES256", "EdDSA"})
_EMBEDDED_KEY_FIELDS: frozenset[str] = frozenset(
    {"public_key", "public_key_pem", "jwk", "jwks", "x5c", "x5u", "jku"}
)


class GovernanceDecision(str, Enum):
    """Canonical five-outcome client preview decision vocabulary."""

    ALLOWED = "ALLOWED"
    NARROWED = "NARROWED"
    DENIED = "DENIED"
    DEFERRED = "DEFERRED"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass(frozen=True)
class PreviewResult:
    """Structured result returned by ``CageClient.preview()``."""

    decision: GovernanceDecision
    envelope: GovernanceEnvelope | None = None
    gateway_verdict: str | None = None
    narrowed_params: dict[str, Any] | None = None
    deferred_id: str | None = None
    defer_reason: str | None = None
    defer_expires_at: datetime | None = None
    requires_approval: bool = False
    reason_code: str | None = None
    audit_id: str | None = None
    violations: tuple[Any, ...] = ()
    recoverable: bool | None = None
    error: str | None = None

    @property
    def is_executable(self) -> bool:
        """Return True iff the preview verdict allows immediate execution or narrowed execution."""
        return self.decision in (
            GovernanceDecision.ALLOWED,
            GovernanceDecision.NARROWED,
        )


class CommitStatus(str, Enum):
    """Canonical wire status of one committing gateway tool run."""

    EXECUTED = "EXECUTED"
    DRY_RUN = "DRY_RUN"
    REFUSED = "REFUSED"
    DEFERRED = "DEFERRED"
    INDETERMINATE = "INDETERMINATE"
    UNSETTLED_DUPLICATE = "UNSETTLED_DUPLICATE"


COMPLETED_STATUSES: frozenset[CommitStatus] = frozenset(
    {CommitStatus.EXECUTED, CommitStatus.DRY_RUN}
)
INDETERMINATE_STATUSES: frozenset[CommitStatus] = frozenset(
    {CommitStatus.INDETERMINATE, CommitStatus.UNSETTLED_DUPLICATE}
)
NOT_EXECUTED_STATUSES: frozenset[CommitStatus] = frozenset(
    {
        CommitStatus.REFUSED,
        CommitStatus.DEFERRED,
        CommitStatus.INDETERMINATE,
        CommitStatus.UNSETTLED_DUPLICATE,
    }
)


class ApprovalRedemptionRefusal(str, Enum):
    """Why a ``deferred_id`` submitted on an approved resume could not be redeemed."""

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


RETRYABLE_REFUSALS: frozenset[ApprovalRedemptionRefusal] = frozenset(
    {
        ApprovalRedemptionRefusal.PENDING,
        ApprovalRedemptionRefusal.QUORUM_INCOMPLETE,
    }
)


def is_retryable_refusal(code: ApprovalRedemptionRefusal | None) -> bool:
    """Return True iff ``code`` leaves the approval ticket redeemable on a later resume."""
    return code in RETRYABLE_REFUSALS


REFUSAL_DESCRIPTIONS: dict[ApprovalRedemptionRefusal, str] = {
    ApprovalRedemptionRefusal.PENDING: "it has no reviewer approval yet",
    ApprovalRedemptionRefusal.QUORUM_INCOMPLETE: (
        "it does not have all the reviewer approvals it needs yet"
    ),
    ApprovalRedemptionRefusal.UNKNOWN_OR_EXPIRED: (
        "its approval request no longer exists (it expired or was never recorded)"
    ),
    ApprovalRedemptionRefusal.NOT_AN_APPROVAL: (
        "the hold on it is not one a reviewer approval can release"
    ),
    ApprovalRedemptionRefusal.CONSUMED: "its approval has already been used",
    ApprovalRedemptionRefusal.EXPIRED: (
        "its approval request expired before reviewers approved it"
    ),
    ApprovalRedemptionRefusal.RESOLVED_WITHOUT_APPROVAL: (
        "its approval request was closed without a reviewer approval"
    ),
    ApprovalRedemptionRefusal.QUORUM_NOT_DISTINCT: (
        "its approvals did not come from enough distinct reviewers"
    ),
    ApprovalRedemptionRefusal.UNRECOGNIZED_STATE: (
        "its approval request is in a state the gateway does not recognise"
    ),
    ApprovalRedemptionRefusal.ACTION_MISMATCH: (
        "its approval was granted for a different action"
    ),
    ApprovalRedemptionRefusal.STALE_BARRIER_PREVIEW: (
        "it was approved against conditions that have since changed"
    ),
    ApprovalRedemptionRefusal.NO_APPROVED_PARAMS: (
        "its approval does not record what was approved"
    ),
    ApprovalRedemptionRefusal.PARAMS_NOT_COVERED: (
        "it no longer matches what reviewers approved"
    ),
}


class IndeterminateProvenance(str, Enum):
    """Whether an ``INDETERMINATE`` outcome came from the gateway or client inference."""

    GATEWAY_ASSERTED = "gateway_asserted"
    CLIENT_INFERRED = "client_inferred"


def _decode_redemption_refusal(raw: object) -> ApprovalRedemptionRefusal | None:
    if raw is None:
        return None
    if isinstance(raw, ApprovalRedemptionRefusal):
        return raw
    if not isinstance(raw, str):
        raise CommitOutcomeDecodeError(
            f"commit outcome carries non-string redemption_refusal {raw!r}"
        )
    try:
        return ApprovalRedemptionRefusal(raw)
    except ValueError as exc:
        raise CommitOutcomeDecodeError(
            f"unknown redemption_refusal code {raw[:40]!r}"
        ) from exc


def _validate_optional_str(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise CommitOutcomeDecodeError(
            f"commit outcome field {field_name!r} must be a non-empty string"
        )
    return value


def _reject_embedded_keys(payload: Mapping[str, Any]) -> None:
    if _EMBEDDED_KEY_FIELDS.intersection(payload.keys()):
        raise CommitOutcomeDecodeError(
            "commit outcome contains embedded key material; out-of-band kid resolution required"
        )


def _validate_json_scalars(value: object, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CommitOutcomeDecodeError(
                f"commit outcome {path} contains non-finite float"
            )
        return
    if isinstance(value, Mapping):
        for k, v in value.items():
            if not isinstance(k, str):
                raise CommitOutcomeDecodeError(
                    f"commit outcome {path} contains non-string mapping key"
                )
            _validate_json_scalars(v, f"{path}.{k}")
        return
    if isinstance(value, list):
        for idx, item in enumerate(value):
            _validate_json_scalars(item, f"{path}[{idx}]")
        return
    raise CommitOutcomeDecodeError(
        f"commit outcome {path} contains non-JSON type {type(value).__name__}"
    )


def _validate_signature_mapping(sig: object) -> Mapping[str, str] | None:
    if sig is None:
        return None
    if not isinstance(sig, Mapping):
        raise CommitOutcomeDecodeError("commit outcome signature must be an object")
    if _EMBEDDED_KEY_FIELDS.intersection(sig.keys()):
        raise CommitOutcomeDecodeError(
            "commit outcome signature contains embedded key material"
        )
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
    """Structured, optionally KMS-signed outcome of one committing tool call."""

    status: CommitStatus
    message: str
    redemption_refusal: ApprovalRedemptionRefusal | None = None
    deferred_id: str | None = None
    approval_retained: bool = False
    tool_name: str | None = None
    idempotency_key: str | None = None
    issued_at: str | None = None
    signature: Mapping[str, str] | None = None
    provenance: IndeterminateProvenance | None = None
    verified: bool = False
    may_have_executed: bool | None = None
    http_status: int | None = None
    proof_hash: str | None = None
    output: str | None = None
    output_redacted: bool = False

    @property
    def is_completed(self) -> bool:
        """Return True iff actuation completed or ran in approved dry-run mode."""
        return self.status in COMPLETED_STATUSES

    @property
    def is_indeterminate(self) -> bool:
        """Return True iff execution state is ambiguous and must NOT be retried."""
        return self.status in INDETERMINATE_STATUSES

    @property
    def awaits_same_ticket(self) -> bool:
        """Return True iff the approval ticket remains redeemable on a later resume."""
        if self.status is CommitStatus.DEFERRED:
            return self.approval_retained
        return self.status is CommitStatus.REFUSED and is_retryable_refusal(
            self.redemption_refusal
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON/msgpack-serializable dict representation for state checkpointing."""
        return {
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
            "tool_name": self.tool_name,
            "idempotency_key": self.idempotency_key,
            "issued_at": self.issued_at,
            "signature": dict(self.signature) if self.signature is not None else None,
            "provenance": (
                self.provenance.value if self.provenance is not None else None
            ),
            "verified": self.verified,
            "may_have_executed": self.may_have_executed,
            "http_status": self.http_status,
            "proof_hash": self.proof_hash,
            "output": self.output,
            "output_redacted": self.output_redacted,
        }

    @classmethod
    def from_wire(
        cls,
        payload: object,
        *,
        expected_tool_name: str | None = None,
        expected_idempotency_key: str | None = None,
        provenance: IndeterminateProvenance | None = None,
        verified: bool = False,
        may_have_executed: bool | None = None,
        http_status: int | None = None,
        proof_hash: str | None = None,
        output: str | None = None,
        output_redacted: bool = False,
    ) -> CommitOutcome:
        """Decode ``payload`` strictly without reading prose."""
        if not isinstance(payload, Mapping):
            raise CommitOutcomeDecodeError("commit outcome is not a mapping")
        _reject_embedded_keys(payload)
        _validate_json_scalars(payload)
        schema = payload.get("schema")
        if schema != COMMIT_OUTCOME_SCHEMA:
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
                _decode_redemption_refusal(payload.get("redemption_refusal"))
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
                bool(payload.get("approval_retained"))
                if status is CommitStatus.DEFERRED
                else False
            ),
            tool_name=tool_name,
            idempotency_key=idempotency_key,
            issued_at=issued_at,
            signature=signature,
            provenance=(
                provenance
                if provenance is not None
                else (
                    IndeterminateProvenance.GATEWAY_ASSERTED
                    if status in INDETERMINATE_STATUSES
                    else None
                )
            ),
            verified=verified,
            may_have_executed=may_have_executed,
            http_status=http_status,
            proof_hash=proof_hash,
            output=output,
            output_redacted=output_redacted,
        )


async def verify_commit_outcome_payload(
    payload: object,
    *,
    resolve_key: Callable[[str], Awaitable[PublicKey]],
    require_signature: bool,
    expected_tool_name: str | None = None,
    expected_idempotency_key: str | None = None,
    may_have_executed: bool | None = None,
    http_status: int | None = None,
    proof_hash: str | None = None,
    output: str | None = None,
    output_redacted: bool = False,
) -> CommitOutcome:
    """Decode and cryptographically verify a wire ``CommitOutcome`` payload fail-closed.

    When ``require_signature`` is True, an unsigned outcome is refused.
    Whenever ``signature`` is present (even when ``require_signature=False`` in
    dev/test), the out-of-band ``kid`` key is resolved via ``resolve_key``, the
    signature is verified over RFC 8785 JCS canonical bytes excluding
    ``signature``, and any requested ``expected_tool_name`` /
    ``expected_idempotency_key`` binding must be present in the signed body.
    """
    decoded = CommitOutcome.from_wire(
        payload,
        expected_tool_name=expected_tool_name,
        expected_idempotency_key=expected_idempotency_key,
        may_have_executed=may_have_executed,
        http_status=http_status,
        proof_hash=proof_hash,
        output=output,
        output_redacted=output_redacted,
    )
    if decoded.signature is None:
        if require_signature:
            raise CommitOutcomeDecodeError(
                "commit outcome is missing required KMS signature"
            )
        return decoded

    if expected_tool_name is not None and decoded.tool_name is None:
        raise CommitOutcomeDecodeError(
            "signed commit outcome is missing required bound 'tool_name'"
        )
    if expected_idempotency_key is not None and decoded.idempotency_key is None:
        raise CommitOutcomeDecodeError(
            "signed commit outcome is missing required bound 'idempotency_key'"
        )

    assert isinstance(payload, Mapping)
    kid = decoded.signature["kid"]
    alg = decoded.signature["algorithm"]
    sig_val = decoded.signature["value"]

    public_key = await resolve_key(kid)
    unsigned_dict = {k: v for k, v in payload.items() if k != "signature"}
    try:
        canonical_bytes = canonicalize(unsigned_dict)
    except Exception as exc:
        raise CommitOutcomeDecodeError(
            f"Failed to canonicalize CommitOutcome with RFC 8785 JCS: {exc}"
        ) from exc

    verify_envelope_signature(
        canonical_bytes=canonical_bytes,
        algorithm=alg,
        signature_b64=sig_val,
        public_key=public_key,
    )
    return CommitOutcome(
        status=decoded.status,
        message=decoded.message,
        redemption_refusal=decoded.redemption_refusal,
        deferred_id=decoded.deferred_id,
        approval_retained=decoded.approval_retained,
        tool_name=decoded.tool_name,
        idempotency_key=decoded.idempotency_key,
        issued_at=decoded.issued_at,
        signature=decoded.signature,
        provenance=decoded.provenance,
        verified=True,
        may_have_executed=decoded.may_have_executed,
        http_status=decoded.http_status,
        proof_hash=decoded.proof_hash,
        output=decoded.output,
        output_redacted=decoded.output_redacted,
    )

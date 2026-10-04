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

"""Gateway state-commitment service — sanitize, canonicalize, hash, retain.

A producer (e.g. an attestation adapter in the advisor process) sends the
gateway an agent-state snapshot. This service:

1. **Sanitizes** it with the same :class:`PIISanitizer` the evidence chain
   uses (``_get_pii_sanitizer().sanitize_dict``), then normalizes it to
   JSON-native types with the same ``_normalize_for_jcs`` helper — no fork.
2. **Canonicalizes** the sanitized state once with RFC 8785 JCS and hashes the
   bytes with SHA-256. That digest is the ``stateHash``.
3. **Retains** the sanitized state by appending a ``STATE_COMMITMENT`` event to
   the evidence chain through :meth:`EvidenceStreamSink.ingest_sync`, which
   blocks until Redis acknowledges and raises on any failure. The compliance
   bridge's ``EvidenceCustodian`` then re-verifies, KMS-attests and writes the
   record to the WORM bucket like every other evidence record.

The gateway itself therefore holds **no cold store and no signing key**
(``docs/architecture/EVIDENCE_CHAIN.md``): retention rides the existing
producer/custodian separation instead of opening a second write path to WORM.

Why the stored bytes equal the preimage
---------------------------------------
The sink stores ``payload_json = JCS(_normalize_for_jcs(sanitize_dict(event)))``.
This service builds the event from state that is *already* sanitized and
normalized and refuses (fail closed) unless re-applying both is a no-op on the
whole event. Under that check ``payload_json["state"]`` parses back to exactly
the object that was hashed, so ``sha256(JCS(record["state"])) == stateHash``
— which :func:`verify_state_commitment` recomputes.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from collections.abc import Mapping
from typing import Any, Protocol

from src.gateway.governance.env_posture import is_enforcing
from src.gateway.governance.evidence.stream import (
    ConfigurationError,
    EvidenceChainUnavailableError,
    EvidenceCommitResult,
    _normalize_for_jcs,
)
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.pii_sanitizer import _get_pii_sanitizer
from src.gateway.governance.seams.state_commitment import (
    STATE_COMMITMENT_EVENT_TYPE,
    STATE_COMMITMENT_METHOD,
    InvalidStateSnapshotError,
    StateCommitmentError,
    StateCommitmentLinkage,
    StateCommitmentReceipt,
    StateSnapshotTooLargeError,
)

logger = logging.getLogger("cage.governance.evidence.state_commitment")

MAX_PREIMAGE_BYTES = 256 * 1024
"""Upper bound on canonical preimage size; larger snapshots are refused."""

_BINDING_FIELDS = (
    "type",
    "stateHash",
    "linkageDigest",
    *STATE_COMMITMENT_METHOD.keys(),
)
"""Record fields (besides ``state``) that verification relies on verbatim."""


class EvidenceAppender(Protocol):
    """The slice of :class:`EvidenceStreamSink` this service depends on."""

    @property
    def is_running(self) -> bool:  # pragma: no cover - protocol
        ...

    async def ingest_sync(
        self, event: dict[str, Any]
    ) -> EvidenceCommitResult:  # pragma: no cover - protocol
        ...


def json_native(value: Any) -> Any:
    """Normalize ``value`` to JSON-native types exactly as the evidence chain does.

    Public wrapper over the evidence stream's JCS pre-normalizer (datetime →
    ISO 8601, Decimal → str, tuple → list, unknown → str) so producers can
    take a JSON-safe copy of a snapshot without forking the rules.
    """
    return _normalize_for_jcs(value)


def _sanitize(value: dict[str, Any]) -> dict[str, Any]:
    return _normalize_for_jcs(_get_pii_sanitizer().sanitize_dict(value))


def _has_string_keys(value: Any) -> bool:
    if isinstance(value, Mapping):
        return all(isinstance(k, str) and _has_string_keys(v) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return all(_has_string_keys(v) for v in value)
    return True


def canonicalize_state(
    snapshot: Mapping[str, Any],
) -> tuple[dict[str, Any], bytes, str]:
    """Sanitize, canonicalize and hash an agent-state snapshot.

    Args:
        snapshot: The raw snapshot. Must be a mapping with string keys.

    Returns:
        ``(sanitized_state, preimage_bytes, state_hash)`` where
        ``state_hash == sha256(preimage_bytes).hexdigest()`` and
        ``preimage_bytes == JCS(sanitized_state)``.

    Raises:
        InvalidStateSnapshotError: The snapshot is not a mapping, is not
            canonicalizable (non-string keys, NaN/Infinity), exceeds
            :data:`MAX_PREIMAGE_BYTES` (:class:`StateSnapshotTooLargeError`),
            or sanitization is not idempotent on it.
    """
    if not isinstance(snapshot, Mapping):
        raise InvalidStateSnapshotError("state snapshot must be a JSON object")
    if not _has_string_keys(snapshot):
        raise InvalidStateSnapshotError("state snapshot keys must all be strings")
    # Normalize first so tuples become lists the sanitizer can traverse.
    sanitized = _sanitize(_normalize_for_jcs(dict(snapshot)))
    if _sanitize(sanitized) != sanitized:
        raise InvalidStateSnapshotError(
            "PII sanitization is not idempotent on this snapshot; the stored "
            "preimage would not reproduce the committed hash"
        )
    try:
        preimage = jcs_canonicalize_plan(sanitized)
    except Exception as exc:
        raise InvalidStateSnapshotError(
            f"snapshot is not JCS-canonicalizable: {exc}"
        ) from exc
    if len(preimage) > MAX_PREIMAGE_BYTES:
        raise StateSnapshotTooLargeError(
            f"canonical preimage is {len(preimage)} bytes; limit {MAX_PREIMAGE_BYTES}"
        )
    return sanitized, preimage, hashlib.sha256(preimage).hexdigest()


def linkage_digest(linkage: StateCommitmentLinkage) -> str:
    """SHA-256 over the JCS bytes of the linkage wire form.

    The plain ``linkage`` object in an evidence record passes through the
    evidence-chain sanitizer like every other field, and the card-number
    patterns occasionally match random UUIDs (8-4-4 hex groups that happen to
    be all digits). The digest — a single 64-hex token the sanitizer never
    alters — is the exact binding between a record and an attestation step.
    """
    return hashlib.sha256(jcs_canonicalize_plan(linkage.to_dict())).hexdigest()


def verify_state_commitment(
    state_hash: str,
    record_payload: str | bytes | Mapping[str, Any],
    *,
    linkage: StateCommitmentLinkage | None = None,
) -> bool:
    """Recompute ``state_hash`` from a custodied ``STATE_COMMITMENT`` record.

    Args:
        state_hash: The digest carried by the external attestation step.
        record_payload: The evidence record's ``payload_json`` (text, bytes, or
            already parsed).
        linkage: Optionally, the step's linkage as reconstructed from the
            external bundle; when given, the record's ``linkageDigest`` must
            match it.

    Returns:
        True only if the record is a ``STATE_COMMITMENT`` event with the
        expected method, its own ``stateHash`` equals ``state_hash``,
        ``sha256(JCS(record["state"]))`` equals ``state_hash`` and (if
        requested) the linkage digest matches.
    """
    try:
        record = (
            json.loads(record_payload)
            if isinstance(record_payload, (str, bytes))
            else dict(record_payload)
        )
    except (ValueError, TypeError):
        return False
    if (
        not isinstance(record, dict)
        or record.get("type") != STATE_COMMITMENT_EVENT_TYPE
    ):
        return False
    if any(record.get(k) != v for k, v in STATE_COMMITMENT_METHOD.items()):
        return False
    state = record.get("state")
    recorded = record.get("stateHash")
    if not isinstance(state, dict) or not isinstance(recorded, str):
        return False
    try:
        recomputed = hashlib.sha256(jcs_canonicalize_plan(state)).hexdigest()
    except Exception:
        return False
    if linkage is not None and not hmac.compare_digest(
        str(record.get("linkageDigest", "")), linkage_digest(linkage)
    ):
        return False
    return hmac.compare_digest(recomputed, state_hash) and hmac.compare_digest(
        recorded, state_hash
    )


class StateCommitmentService:
    """Commits sanitized state snapshots to the gateway evidence chain.

    Constructed once by the gateway lifespan via
    :func:`build_state_commitment_service` and read by handlers through
    :func:`~src.gateway.server.app_state.state_commitment_service_of`.
    """

    def __init__(self, sink: EvidenceAppender | None) -> None:
        self._sink = sink

    async def commit_state(
        self,
        snapshot: Mapping[str, Any],
        *,
        linkage: StateCommitmentLinkage,
        caller_identity: str | None = None,
    ) -> StateCommitmentReceipt:
        """Sanitize, hash and durably append ``snapshot``; return the receipt.

        Args:
            snapshot: Raw agent-state snapshot from the producer.
            linkage: Which attestation step the snapshot belongs to.
            caller_identity: Verified workload identity of the producer.

        Raises:
            InvalidStateSnapshotError: The snapshot or linkage is invalid, or
                sanitization would alter the stored record.
            StateCommitmentError: The evidence chain did not commit.
            In either case no receipt exists for the snapshot.
        """
        state, _preimage, state_hash = canonicalize_state(snapshot)

        event: dict[str, Any] = {
            "type": STATE_COMMITMENT_EVENT_TYPE,
            "stateHash": state_hash,
            "state": state,
            "linkage": linkage.to_dict(),  # informational; see linkage_digest()
            "linkageDigest": linkage_digest(linkage),
            **STATE_COMMITMENT_METHOD,
        }
        if caller_identity:
            event["callerIdentity"] = caller_identity
        # The sink re-sanitizes the whole event before hashing it into the
        # chain. Every field verification depends on must survive unchanged.
        stored = _sanitize(event)
        if stored.get("state") != state or any(
            stored.get(key) != event[key] for key in _BINDING_FIELDS
        ):
            raise InvalidStateSnapshotError(
                "evidence-chain sanitization would alter the committed preimage"
            )

        if self._sink is None:
            raise StateCommitmentError(
                "evidence stream is disabled; state commitments cannot be retained"
            )
        try:
            result = await self._sink.ingest_sync(event)
        except EvidenceChainUnavailableError as exc:
            raise StateCommitmentError(f"evidence chain unavailable: {exc}") from exc

        receipt = StateCommitmentReceipt(
            state_hash=state_hash,
            evidence_id=result.evidence_id,
            evidence_record_hash=result.hash,
            sequence=result.sequence,
            method=STATE_COMMITMENT_METHOD,
        )
        receipt.validate()
        logger.info(
            "[StateCommitment] committed stateHash=%s… evidence_id=%s seq=%d label=%s",
            state_hash[:16],
            result.evidence_id,
            result.sequence,
            linkage.label,
        )
        return receipt


def build_state_commitment_service(
    sink: EvidenceAppender | None,
) -> StateCommitmentService:
    """Composition-time constructor with the posture guard.

    Under an enforcing posture (:func:`~src.gateway.governance.env_posture.is_enforcing`)
    a state commitment must be durable, so a missing or disconnected evidence
    sink is refused here rather than on the first request. Permissive postures
    (development, test, CI) may run without one; every commit then fails
    closed with :class:`StateCommitmentError`.

    Raises:
        ConfigurationError: Enforcing posture without a running evidence sink.
    """
    if is_enforcing() and (sink is None or not sink.is_running):
        raise ConfigurationError(
            "State commitments require a running evidence stream sink under an "
            "enforcing posture (EVIDENCE_STREAM_ENABLED=true and Redis reachable); "
            "refusing to accept stateHash commitments that cannot be retained."
        )
    if sink is None:
        logger.warning(
            "[StateCommitment] No evidence sink (permissive posture); every "
            "state commitment will be refused."
        )
    return StateCommitmentService(sink)

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

"""State commitment seam — the contract for committing an agent-state snapshot.

A *state commitment* is a SHA-256 digest over the RFC 8785 (JCS) canonical
bytes of a PII-sanitized agent-state snapshot. External attestation producers
(Layer 3) carry the digest as an opaque ``stateHash``; the gateway appends the
exact preimage to the tamper-evident evidence chain so the digest can be
recomputed later by anyone holding the custodied record.

This module is the single definition of:

* the commitment method (:data:`STATE_COMMITMENT_METHOD`), stamped into every
  attestation step that carries a ``stateHash``;
* the linkage/receipt data contracts exchanged between a producer and the
  gateway;
* the :class:`StateCommitter` protocol producers depend on.

It is domain-agnostic and vendor-neutral: nothing here names a domain plugin
or an attestation provider.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Protocol, runtime_checkable

# ---------------------------------------------------------------------------
# Commitment method
# ---------------------------------------------------------------------------

STATE_HASH_ALG = "sha256"
"""Digest algorithm applied to the canonical preimage bytes."""

STATE_HASH_CANON = "RFC8785-JCS"
"""Canonicalization applied to the sanitized snapshot before hashing."""

STATE_HASH_SCOPE = "agentstate-pii-sanitized/v1"
"""What the preimage contains. The version tag distinguishes commitments made
over PII-sanitized state from earlier digests computed over raw state."""

STATE_COMMITMENT_METHOD: Mapping[str, str] = MappingProxyType(
    {
        "stateHashAlg": STATE_HASH_ALG,
        "stateHashCanon": STATE_HASH_CANON,
        "stateHashScope": STATE_HASH_SCOPE,
    }
)
"""Step-metadata keys and values describing how a ``stateHash`` was computed."""

STATE_COMMITMENT_EVENT_TYPE = "STATE_COMMITMENT"
"""Evidence-chain event type that carries a committed preimage."""

STATE_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
"""Lowercase hex SHA-256 digest."""

LINKAGE_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
"""Allowed shape of every :class:`StateCommitmentLinkage` field."""


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class StateCommitmentError(Exception):
    """A state commitment could not be made or verified (fail closed).

    Producers that receive this error must not emit an attestation step for
    the affected snapshot.
    """


class InvalidStateSnapshotError(StateCommitmentError):
    """The snapshot or linkage itself is unacceptable (a caller error).

    Distinct from an unavailable evidence chain so a transport can answer
    4xx instead of 5xx; producers fail closed on both.
    """


class StateSnapshotTooLargeError(InvalidStateSnapshotError):
    """The canonical preimage exceeds the gateway's size limit."""


# ---------------------------------------------------------------------------
# Data contracts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StateCommitmentLinkage:
    """Identifies which attestation step a committed snapshot belongs to.

    Every field must match :data:`LINKAGE_ID_PATTERN`. The values are stored
    alongside the preimage so an auditor can join a ``stateHash`` in an
    external bundle back to its evidence record.

    Attributes:
        namespace: Producer namespace (e.g. an anonymized integration name).
        bundle_id: Identifier of the bundle the step belongs to.
        step_id: Identifier of the step within the bundle.
        thread_id: Execution thread / run identifier.
        label: Name of the node or pause point that produced the snapshot.
    """

    namespace: str
    bundle_id: str
    step_id: str
    thread_id: str
    label: str

    def __post_init__(self) -> None:
        for name in ("namespace", "bundle_id", "step_id", "thread_id", "label"):
            value = getattr(self, name)
            if not isinstance(value, str) or not LINKAGE_ID_PATTERN.match(value):
                raise InvalidStateSnapshotError(
                    f"linkage field {name!r} must match {LINKAGE_ID_PATTERN.pattern}"
                )

    def to_dict(self) -> dict[str, str]:
        """Wire form (camelCase keys)."""
        return {
            "namespace": self.namespace,
            "bundleId": self.bundle_id,
            "stepId": self.step_id,
            "threadId": self.thread_id,
            "label": self.label,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> StateCommitmentLinkage:
        """Parse the wire form produced by :meth:`to_dict`.

        Raises:
            StateCommitmentError: A field is missing or malformed.
        """
        try:
            return cls(
                namespace=data["namespace"],
                bundle_id=data["bundleId"],
                step_id=data["stepId"],
                thread_id=data["threadId"],
                label=data["label"],
            )
        except (KeyError, TypeError) as exc:
            raise InvalidStateSnapshotError(f"malformed linkage: {exc}") from exc


@dataclass(frozen=True)
class StateCommitmentReceipt:
    """Proof that a snapshot's preimage entered the evidence chain.

    Attributes:
        state_hash: Lowercase hex SHA-256 of the canonical sanitized preimage.
        evidence_id: Identifier of the evidence record holding the preimage.
        evidence_record_hash: Chain hash of that evidence record.
        sequence: Position of the record in the evidence chain.
        method: The commitment method; must equal :data:`STATE_COMMITMENT_METHOD`.
    """

    state_hash: str
    evidence_id: str
    evidence_record_hash: str
    sequence: int
    method: Mapping[str, str]

    def to_dict(self) -> dict[str, Any]:
        """Wire form (camelCase keys)."""
        return {
            "stateHash": self.state_hash,
            "evidenceId": self.evidence_id,
            "evidenceRecordHash": self.evidence_record_hash,
            "sequence": self.sequence,
            "method": dict(self.method),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> StateCommitmentReceipt:
        """Parse and validate the wire form produced by :meth:`to_dict`.

        Raises:
            StateCommitmentError: A field is missing, the digest is malformed,
                or the method does not equal :data:`STATE_COMMITMENT_METHOD`.
        """
        try:
            receipt = cls(
                state_hash=data["stateHash"],
                evidence_id=data["evidenceId"],
                evidence_record_hash=data["evidenceRecordHash"],
                sequence=int(data["sequence"]),
                method=MappingProxyType(dict(data["method"])),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise StateCommitmentError(f"malformed commitment receipt: {exc}") from exc
        receipt.validate()
        return receipt

    def validate(self) -> None:
        """Fail closed unless the digest and method are exactly as specified.

        Raises:
            StateCommitmentError: On a malformed digest, a missing evidence id,
                or a method other than :data:`STATE_COMMITMENT_METHOD`.
        """
        if not isinstance(self.state_hash, str) or not STATE_HASH_PATTERN.match(
            self.state_hash
        ):
            raise StateCommitmentError("receipt stateHash is not a sha256 hex digest")
        if not self.evidence_id:
            raise StateCommitmentError("receipt carries no evidence id")
        if dict(self.method) != dict(STATE_COMMITMENT_METHOD):
            raise StateCommitmentError(
                f"receipt method {dict(self.method)!r} does not match "
                f"{dict(STATE_COMMITMENT_METHOD)!r}"
            )


# ---------------------------------------------------------------------------
# Producer-facing protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class StateCommitter(Protocol):
    """Commits a state snapshot and returns the gateway's receipt.

    Implementations must raise :class:`StateCommitmentError` on any failure;
    they must never return a receipt for a preimage that was not durably
    appended to the evidence chain.
    """

    async def commit_state(
        self,
        snapshot: Mapping[str, Any],
        *,
        linkage: StateCommitmentLinkage,
    ) -> StateCommitmentReceipt:
        """Commit ``snapshot`` for the step identified by ``linkage``."""
        ...

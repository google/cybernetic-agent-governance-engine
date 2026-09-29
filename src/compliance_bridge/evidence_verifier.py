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

"""evidence_verifier.py — Independent verification of custodied evidence (Layer 3)

The :mod:`evidence_custodian` writes gateway evidence to the WORM cold store
as NDJSON batches, each with a ``cage-evidence-batch/1`` attestation signed by
``EVIDENCE_KMS_KEY``. This module reads that archive back and decides what
may be cited as evidence. It trusts nothing it reads: every property the
custodian claims is recomputed.

Per batch (:meth:`CustodyVerifier.verify_batch`)
------------------------------------------------
1. Parse the attestation and pass it through
   :func:`~src.compliance_bridge.evidence_custodian.assert_citable`.
2. Reject a ``signature.key_id`` that belongs to the gateway seal key or the
   reconciler snapshot key.
3. Verify the signature over the attestation body (everything except
   ``signature``) against a public key resolved **by kid from an
   independently loaded trust-anchor set**, never from the document.
4. Bind the attestation to its data object: the attestation key, the
   ``data_key`` and the chain/sequence range in the object path must agree.
5. Read the data object and check its SHA-256 against ``content_sha256``.
6. Re-verify every record: hash, ``prev_hash`` link, contiguous sequence,
   ``chain_id``, first/last stream IDs, entry count and last record hash.

Across batches (:meth:`CustodyVerifier.verify_all`)
---------------------------------------------------
Signed batches are grouped by ``chain_id`` and ordered by sequence. Each
batch must continue the previous one (next sequence, ``prev_hash`` equal to
the previous ``last_record_hash``). A jump is acceptable only when the later
attestation itself declares the gap (the custodian records trimming it
observed); an undeclared jump means a batch is missing and fails. A data
object with no attestation also fails.

Unsigned attestations (``.attestation.unsigned.json``, dev/test/ci only) are
listed as non-evidentiary and never counted as verified. Their sequence
ranges are therefore absent from a signed chain, which fails continuity:
evidence that was never signed cannot be cited.

Trust anchors
-------------
:func:`load_evidence_trust_anchors` fetches the public key(s) of
``EVIDENCE_KMS_KEY`` from the KMS provider, plus an optional operator-mounted
manifest ``EVIDENCE_TRUST_ANCHORS_FILE`` (JSON ``{kid: pem}``) for retired key
versions. Manifest kids must belong to the same crypto key as
``EVIDENCE_KMS_KEY`` when it is set, and never to the gateway or reconciler
key. With no anchors every signed attestation fails closed on unknown kid.

Usage::

    uv run python -m src.compliance_bridge.evidence_verifier [--prefix P] [--json]

Exit status is 0 only when the report has no failures.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from typing import Any

from src.gateway.governance.env_posture import is_enforcing
from src.gateway.governance.evidence.cold_store import (
    ColdStoreNotFoundError,
    EvidenceColdStore,
)
from src.gateway.governance.evidence.stream import verify_record
from src.gateway.governance.kms_signer import KMSGovernanceSigner

from .evidence_custodian import (
    NonEvidentiaryAttestationError,
    assert_citable,
)
from .kms_batch_signer import (
    EVIDENCE_KMS_KEY_ENV,
    _crypto_key_of,
    is_foreign_signing_kid,
)

logger = logging.getLogger("cage.compliance_bridge.evidence_verifier")

DEFAULT_PREFIX = "evidence-stream/"
TRUST_ANCHORS_FILE_ENV = "EVIDENCE_TRUST_ANCHORS_FILE"

_DATA_SUFFIX = ".ndjson"
_SIGNED_SUFFIX = ".attestation.json"
_UNSIGNED_SUFFIX = ".attestation.unsigned.json"
_RANGE_RE = re.compile(r"/(?P<chain>[^/]+)/(?P<first>\d{12})-(?P<last>\d{12})\.ndjson$")


class EvidenceVerificationError(Exception):
    """A custodied batch failed verification and must not be cited."""


# ---------------------------------------------------------------------------
# Trust anchors
# ---------------------------------------------------------------------------


def _load_manifest(path: str) -> dict[str, bytes]:
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)
    if not isinstance(raw, dict) or not all(
        isinstance(k, str) and k and isinstance(v, str) and v for k, v in raw.items()
    ):
        raise ValueError(
            f"{TRUST_ANCHORS_FILE_ENV} must be a JSON object of kid -> PEM"
        )
    return {kid: pem.encode("utf-8") for kid, pem in raw.items()}


def load_evidence_trust_anchors() -> dict[str, bytes]:
    """Load ``kid -> PEM`` for the evidence key from out-of-band sources.

    Sources: the KMS provider for ``EVIDENCE_KMS_KEY`` and the optional
    ``EVIDENCE_TRUST_ANCHORS_FILE`` manifest. Foreign kids (gateway seal or
    reconciler snapshot keys) are always dropped, as are manifest kids from a
    different crypto key than ``EVIDENCE_KMS_KEY``.

    Returns an empty mapping when neither source is configured, so every
    signed attestation fails closed on an unknown kid.

    Raises:
        ValueError: The manifest is malformed or names a foreign kid.
    """
    anchors: dict[str, bytes] = {}
    key_name = os.environ.get(EVIDENCE_KMS_KEY_ENV, "").strip()

    if key_name:
        from .kms_batch_signer import build_evidence_signer

        provider = getattr(build_evidence_signer(), "_provider", None)
        if provider is not None:
            anchors.update(
                {kid: pem for kid, pem in provider.get_public_keys_pem().items() if pem}
            )

    manifest_path = os.environ.get(TRUST_ANCHORS_FILE_ENV, "").strip()
    if manifest_path:
        for kid, pem in _load_manifest(manifest_path).items():
            if is_foreign_signing_kid(kid):
                raise ValueError(
                    f"{TRUST_ANCHORS_FILE_ENV} lists kid {kid!r}, which belongs to "
                    "the gateway or reconciler signing key."
                )
            if key_name and _crypto_key_of(kid) != _crypto_key_of(key_name):
                raise ValueError(
                    f"{TRUST_ANCHORS_FILE_ENV} lists kid {kid!r}, which is not a "
                    f"version of {EVIDENCE_KMS_KEY_ENV}."
                )
            anchors[kid] = pem

    anchors = {
        kid: pem for kid, pem in anchors.items() if not is_foreign_signing_kid(kid)
    }
    if not anchors:
        logger.warning(
            "[EvidenceVerifier] No evidence trust anchors loaded; every signed "
            "attestation will fail verification."
        )
    return anchors


def build_attestation_verifier(
    trust_anchors: dict[str, bytes] | None = None,
) -> KMSGovernanceSigner:
    """Build a verify-only signer whose only trust anchors are the evidence key's.

    The instance has no provider and no own key, so it can only resolve the
    injected kids.
    """
    anchors = load_evidence_trust_anchors() if trust_anchors is None else trust_anchors
    return KMSGovernanceSigner(provider=None, trust_anchors=dict(anchors))


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VerifiedBatch:
    """A batch whose attestation, data object and records all verified."""

    attestation_key: str
    data_key: str
    chain_id: str
    first_sequence: int
    last_sequence: int
    entries: int
    first_prev_hash: str
    last_record_hash: str
    key_id: str
    gap_declared: bool
    gap_expected_sequence: int | None


@dataclass(frozen=True)
class VerificationFailure:
    """One reason the archive (or part of it) cannot be cited."""

    key: str
    reason: str


@dataclass(frozen=True)
class DeclaredGap:
    """A sequence range the custodian recorded as trimmed before custody."""

    chain_id: str
    missing_from: int
    missing_to: int
    attestation_key: str


@dataclass
class CustodyVerificationReport:
    """Outcome of :meth:`CustodyVerifier.verify_all`.

    ``ok`` is true only when there are no failures. Declared gaps and
    non-evidentiary attestations do not fail the report, but neither is
    evidence: gaps are ranges that were never custodied, and unsigned
    batches are never counted in ``verified``.
    """

    prefix: str
    verified: list[VerifiedBatch] = field(default_factory=list)
    failures: list[VerificationFailure] = field(default_factory=list)
    declared_gaps: list[DeclaredGap] = field(default_factory=list)
    non_evidentiary: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.failures

    def to_dict(self) -> dict[str, Any]:
        return {
            "prefix": self.prefix,
            "ok": self.ok,
            "verified": [asdict(b) for b in self.verified],
            "failures": [asdict(f) for f in self.failures],
            "declared_gaps": [asdict(g) for g in self.declared_gaps],
            "non_evidentiary": list(self.non_evidentiary),
        }


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------


def _fail(key: str, reason: str) -> EvidenceVerificationError:
    logger.critical("[EvidenceVerifier] %s: %s", key, reason)
    return EvidenceVerificationError(f"{key}: {reason}")


def _require_int(att: dict[str, Any], name: str, key: str) -> int:
    value = att.get(name)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise _fail(key, f"attestation field {name!r} is not a non-negative integer")
    return value


def _require_str(
    att: dict[str, Any], name: str, key: str, *, empty: bool = False
) -> str:
    value = att.get(name)
    if not isinstance(value, str) or (not empty and not value):
        raise _fail(key, f"attestation field {name!r} is missing or not a string")
    return value


class CustodyVerifier:
    """Verifies custodied evidence batches in a WORM cold store.

    Args:
        cold_store: Backend holding the custodied objects.
        verifier: Verify-only signer from :func:`build_attestation_verifier`.
    """

    def __init__(
        self, cold_store: EvidenceColdStore, verifier: KMSGovernanceSigner
    ) -> None:
        self._cold_store = cold_store
        self._verifier = verifier

    async def _read(self, key: str, *, what: str) -> bytes:
        try:
            return await self._cold_store.get(key)
        except ColdStoreNotFoundError as exc:
            raise _fail(key, f"{what} object is missing") from exc

    async def verify_batch(self, attestation_key: str) -> VerifiedBatch:
        """Verify one signed attestation and the batch it covers.

        Raises:
            NonEvidentiaryAttestationError: The attestation is unsigned or
                marked non-evidentiary.
            EvidenceVerificationError: Any other check failed.
            ColdStoreError: The backend could not be read (not a verdict).
        """
        key = attestation_key
        if not key.endswith(_SIGNED_SUFFIX):
            raise _fail(key, "not a signed attestation key")
        try:
            att = json.loads(await self._read(key, what="attestation"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _fail(key, "attestation is not valid JSON") from exc
        if not isinstance(att, dict):
            raise _fail(key, "attestation is not a JSON object")

        assert_citable(att)
        signature = att["signature"]
        kid = signature["key_id"]
        if is_foreign_signing_kid(kid):
            raise _fail(key, f"signed by a non-evidence key (kid={kid!r})")
        body = {k: v for k, v in att.items() if k != "signature"}
        if not self._verifier.verify_decision(
            body, signature["value"], kid=kid, algorithm=signature["algorithm"]
        ):
            raise _fail(key, f"signature does not verify against trust anchor {kid!r}")

        # -- bind attestation <-> data object <-> claimed range ----------------
        chain_id = _require_str(att, "chain_id", key)
        first_seq = _require_int(att, "first_sequence", key)
        last_seq = _require_int(att, "last_sequence", key)
        entries = _require_int(att, "entries_count", key)
        data_key = _require_str(att, "data_key", key)
        first_prev = _require_str(att, "first_prev_hash", key, empty=True)
        last_hash = _require_str(att, "last_record_hash", key)
        content_sha256 = _require_str(att, "content_sha256", key)
        first_sid = _require_str(att, "first_stream_id", key)
        last_sid = _require_str(att, "last_stream_id", key)

        if not data_key.endswith(_DATA_SUFFIX) or (
            key != data_key[: -len(_DATA_SUFFIX)] + _SIGNED_SUFFIX
        ):
            raise _fail(key, f"attestation does not belong to data_key {data_key!r}")
        match = _RANGE_RE.search(data_key)
        if not match or (
            match["chain"] != chain_id
            or int(match["first"]) != first_seq
            or int(match["last"]) != last_seq
        ):
            raise _fail(key, "data_key path disagrees with the attested chain/range")
        if last_seq < first_seq or entries != last_seq - first_seq + 1:
            raise _fail(key, "entries_count does not match the attested range")

        gap = att.get("gap")
        if not isinstance(gap, dict) or not isinstance(gap.get("detected"), bool):
            raise _fail(key, "attestation gap field is malformed")
        gap_expected: int | None = None
        if gap["detected"]:
            gap_expected = gap.get("expected_sequence")
            if (
                not isinstance(gap_expected, int)
                or isinstance(gap_expected, bool)
                or not 0 <= gap_expected < first_seq
            ):
                raise _fail(key, "declared gap has an invalid expected_sequence")

        # -- data object -------------------------------------------------------
        content = await self._read(data_key, what="data")
        if hashlib.sha256(content).hexdigest() != content_sha256:
            raise _fail(data_key, "content SHA-256 does not match the attestation")
        try:
            lines = [json.loads(line) for line in content.decode("utf-8").splitlines()]
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _fail(data_key, "data object is not valid NDJSON") from exc
        if len(lines) != entries:
            raise _fail(data_key, f"{len(lines)} records, attestation says {entries}")

        prev_hash = first_prev
        for offset, record in enumerate(lines):
            if not isinstance(record, dict):
                raise _fail(data_key, f"line {offset} is not a JSON object")
            fields = dict(record)
            stream_id = fields.pop("stream_id", None)
            seq = first_seq + offset
            if fields.get("chain_id") != chain_id:
                raise _fail(data_key, f"line {offset} has a different chain_id")
            if fields.get("sequence") != str(seq):
                raise _fail(data_key, f"line {offset} is not sequence {seq}")
            if fields.get("prev_hash", "") != prev_hash:
                raise _fail(
                    data_key, f"sequence {seq} does not link to its predecessor"
                )
            result = verify_record(fields, prev_hash=prev_hash)
            if not result.valid:
                raise _fail(
                    data_key,
                    f"sequence {seq}: {result.error or 'record_hash mismatch'}",
                )
            if offset == 0 and stream_id != first_sid:
                raise _fail(data_key, "first stream ID does not match the attestation")
            if offset == entries - 1 and stream_id != last_sid:
                raise _fail(data_key, "last stream ID does not match the attestation")
            prev_hash = fields["record_hash"]
        if prev_hash != last_hash:
            raise _fail(data_key, "last record hash does not match the attestation")

        return VerifiedBatch(
            attestation_key=key,
            data_key=data_key,
            chain_id=chain_id,
            first_sequence=first_seq,
            last_sequence=last_seq,
            entries=entries,
            first_prev_hash=first_prev,
            last_record_hash=last_hash,
            key_id=kid,
            gap_declared=gap["detected"],
            gap_expected_sequence=gap_expected,
        )

    async def verify_all(
        self, prefix: str = DEFAULT_PREFIX
    ) -> CustodyVerificationReport:
        """Verify every custodied batch under ``prefix`` and chain continuity.

        Raises:
            ColdStoreError: The backend could not be listed or read. A backend
                outage is not a verdict about the evidence.
        """
        report = CustodyVerificationReport(prefix=prefix)
        keys = await self._cold_store.list_keys(prefix)
        key_set = set(keys)

        for key in keys:
            if key.endswith(_DATA_SUFFIX):
                base = key[: -len(_DATA_SUFFIX)]
                if (
                    base + _SIGNED_SUFFIX not in key_set
                    and base + _UNSIGNED_SUFFIX not in key_set
                ):
                    report.failures.append(
                        VerificationFailure(key, "data object has no attestation")
                    )
            elif key.endswith(_UNSIGNED_SUFFIX):
                report.non_evidentiary.append(key)
            elif key.endswith(_SIGNED_SUFFIX):
                try:
                    report.verified.append(await self.verify_batch(key))
                except (
                    EvidenceVerificationError,
                    NonEvidentiaryAttestationError,
                ) as exc:
                    report.failures.append(VerificationFailure(key, str(exc)))
            else:
                report.failures.append(
                    VerificationFailure(
                        key, "unexpected object in the evidence archive"
                    )
                )

        self._check_continuity(report)
        logger.info(
            "[EvidenceVerifier] prefix=%s verified=%d failures=%d gaps=%d unsigned=%d",
            prefix,
            len(report.verified),
            len(report.failures),
            len(report.declared_gaps),
            len(report.non_evidentiary),
        )
        return report

    @staticmethod
    def _check_continuity(report: CustodyVerificationReport) -> None:
        by_chain: dict[str, list[VerifiedBatch]] = {}
        for batch in report.verified:
            by_chain.setdefault(batch.chain_id, []).append(batch)

        for chain_id, batches in sorted(by_chain.items()):
            batches.sort(key=lambda b: b.first_sequence)
            expected_seq, expected_prev = 0, ""
            for batch in batches:
                key = batch.attestation_key
                if batch.first_sequence < expected_seq:
                    report.failures.append(
                        VerificationFailure(
                            key,
                            f"chain {chain_id} overlaps at sequence {batch.first_sequence}",
                        )
                    )
                elif batch.first_sequence == expected_seq:
                    if batch.first_prev_hash != expected_prev:
                        report.failures.append(
                            VerificationFailure(
                                key,
                                f"chain {chain_id} sequence {expected_seq} does not "
                                "link to the previous batch",
                            )
                        )
                elif batch.gap_declared and batch.gap_expected_sequence == expected_seq:
                    report.declared_gaps.append(
                        DeclaredGap(
                            chain_id, expected_seq, batch.first_sequence - 1, key
                        )
                    )
                else:
                    report.failures.append(
                        VerificationFailure(
                            key,
                            f"chain {chain_id} is missing sequences {expected_seq}.."
                            f"{batch.first_sequence - 1} and the batch declares no gap",
                        )
                    )
                expected_seq = batch.last_sequence + 1
                expected_prev = batch.last_record_hash


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


async def _run(prefix: str) -> CustodyVerificationReport:
    from src.gateway.governance.evidence.factory import get_cold_store

    cold_store = get_cold_store()
    if is_enforcing() and cold_store.backend_id == "null":
        raise SystemExit(
            "EVIDENCE_COLD_STORE=null under an enforcing posture: there is no "
            "archive to verify."
        )
    return await CustodyVerifier(cold_store, build_attestation_verifier()).verify_all(
        prefix
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify custodied CAGE evidence.")
    parser.add_argument("--prefix", default=DEFAULT_PREFIX, help="object key prefix")
    parser.add_argument("--json", action="store_true", help="print the full report")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    report = asyncio.run(_run(args.prefix))
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(
            f"verified={len(report.verified)} failures={len(report.failures)} "
            f"declared_gaps={len(report.declared_gaps)} "
            f"non_evidentiary={len(report.non_evidentiary)}"
        )
        for failure in report.failures:
            print(f"FAIL {failure.key}: {failure.reason}")
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())

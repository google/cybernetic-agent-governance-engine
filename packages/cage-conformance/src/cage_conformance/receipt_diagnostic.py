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

"""Offline preimage and field diagnostic for ``actuator_01`` (Archytan) receipts.

Compares the signed-message preimage and required fields that CAGE's
``verify_partner_receipt()`` (``src/integrations/actuator_01/receipt_verifier.py``
lines 193-234) expects against Archytan's receipt signing scheme
(``"ARCHYTAN_RECEIPT_V1:" || SHA-256(intent_hash)``), using only the Python
standard library. Does not verify Ed25519 signatures and never contacts a live
endpoint.

Usage (one paragraph):
    Run ``cage-conformance diagnose-receipt path/to/receipt.json`` (or pipe a
    receipt over stdin with ``cage-conformance diagnose-receipt < receipt.json``,
    or run ``python3 -m cage_conformance.receipt_diagnostic receipt.json`` with
    ``PYTHONPATH=packages/cage-conformance/src`` and no package install) against
    any captured Archytan receipt JSON. The tool makes no network calls and does
    not verify the Ed25519 signature; instead, it prints the exact preimage and
    SHA-256 digest CAGE constructs (``"ARCHYTAN_RECEIPT_V1:" || JCS(body without
    "signature" and "ingress_signature")``) alongside the preimage and SHA-256
    digest for Archytan's signing scheme (``"ARCHYTAN_RECEIPT_V1:" ||
    SHA-256(intent_hash)``), lists which required fields (``envelope_digest``
    for CAGE, ``intent_hash`` for Archytan) are absent, and states the specific
    reconciliation failure reason (``preimage digest mismatch``, ``missing
    envelope_digest``, or ``both``). It exits ``0`` when the candidate preimage
    digests agree and ``envelope_digest`` is present, ``1`` on any mismatch, and
    ``2`` if the input cannot be parsed as a JSON object.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

if __package__:
    from .stream_invariants import jcs_bytes
else:  # pragma: no cover - direct script execution without -m or pip install
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from cage_conformance.stream_invariants import jcs_bytes

RECEIPT_DOMAIN_TAG = b"ARCHYTAN_RECEIPT_V1:"
RECEIPT_DOMAIN_TAG_STR = "ARCHYTAN_RECEIPT_V1:"
STRIPPED_SIGNATURE_FIELDS: tuple[str, ...] = ("signature", "ingress_signature")
_HEX64_RE = re.compile(r"[0-9a-fA-F]{64}")

PreimageBuilder = Callable[[Mapping[str, Any]], bytes]


@dataclass(frozen=True)
class ReceiptDiagnosis:
    """Comparison of CAGE receipt verification against Archytan receipt signing."""

    input_name: str
    input_sha256: str
    signature_verification: str
    reconciled: bool
    reason: str
    preimage_digest_mismatch: bool
    missing_envelope_digest: bool
    missing_intent_hash: bool
    absent_fields: tuple[str, ...]
    cage_domain_tag: str
    cage_canonical_body_utf8: str
    cage_preimage_utf8: str
    cage_preimage_sha256: str
    archytan_domain_tag: str
    intent_digest_source: str | None
    intent_sha256_hex: str | None
    archytan_preimage_utf8: str | None
    archytan_preimage_sha256: str | None
    archytan_raw_preimage_hex: str | None
    archytan_raw_preimage_sha256: str | None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["absent_fields"] = list(self.absent_fields)
        return data


def strip_signature_fields(body: Mapping[str, Any]) -> dict[str, Any]:
    """Return ``body`` without ``signature`` and ``ingress_signature``."""
    return {k: v for k, v in body.items() if k not in STRIPPED_SIGNATURE_FIELDS}


def build_cage_preimage(body: Mapping[str, Any]) -> bytes:
    """Build CAGE's signed-message preimage: ``RECEIPT_DOMAIN_TAG || JCS(stripped_body)``."""
    return RECEIPT_DOMAIN_TAG + jcs_bytes(strip_signature_fields(body))


def _resolve_intent_sha256(
    body: Mapping[str, Any],
) -> tuple[str | None, bytes | None, str | None]:
    """Return ``(sha256_hex, sha256_raw_bytes, source_label)`` for ``intent_hash``.

    Archytan receipts carry ``intent_hash`` (the JCS-canonicalized governance
    envelope) and sign ``"ARCHYTAN_RECEIPT_V1:" || SHA-256(intent_hash)``.
    When diagnosing a CAGE README-shaped receipt that carries ``envelope_digest``
    (already the 64-hex SHA-256 of the canonical envelope) and no ``intent_hash``,
    fall back to ``envelope_digest`` so both candidate preimages can still be
    displayed side by side while reporting ``intent_hash`` as absent.
    """
    raw_intent = body.get("intent_hash")
    if isinstance(raw_intent, str) and raw_intent.strip():
        intent_bytes = raw_intent.encode("utf-8")
        digest = hashlib.sha256(intent_bytes)
        return digest.hexdigest(), digest.digest(), "sha256(intent_hash)"
    if isinstance(raw_intent, (Mapping, list, tuple)) and raw_intent:
        intent_bytes = jcs_bytes(raw_intent)
        digest = hashlib.sha256(intent_bytes)
        return digest.hexdigest(), digest.digest(), "sha256(JCS(intent_hash))"

    raw_envelope_digest = body.get("envelope_digest")
    if isinstance(raw_envelope_digest, str) and raw_envelope_digest.strip():
        candidate = raw_envelope_digest.strip()
        if _HEX64_RE.fullmatch(candidate):
            lower_hex = candidate.lower()
            return (
                lower_hex,
                bytes.fromhex(lower_hex),
                "envelope_digest (intent_hash absent)",
            )
        digest = hashlib.sha256(candidate.encode("utf-8"))
        return (
            digest.hexdigest(),
            digest.digest(),
            "sha256(envelope_digest) (intent_hash absent)",
        )

    return None, None, None


def build_archytan_preimage(body: Mapping[str, Any]) -> bytes | None:
    """Build Archytan's candidate preimage: ``"ARCHYTAN_RECEIPT_V1:" || SHA-256(intent_hash)``."""
    intent_sha256_hex, _, _ = _resolve_intent_sha256(body)
    if intent_sha256_hex is None:
        return None
    return RECEIPT_DOMAIN_TAG + intent_sha256_hex.encode("ascii")


def _has_field(body: Mapping[str, Any], field: str) -> bool:
    value = body.get(field)
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (Mapping, list, tuple)):
        return bool(value)
    return False


def diagnose_receipt(
    body: Mapping[str, Any],
    *,
    input_name: str = "<memory>",
    input_sha256: str | None = None,
    cage_preimage_builder: PreimageBuilder = build_cage_preimage,
) -> ReceiptDiagnosis:
    """Compare CAGE's receipt preimage and field requirements against Archytan's."""
    if not isinstance(body, Mapping):
        raise ValueError("receipt must be a JSON object")

    effective_input_sha256 = (
        input_sha256
        if input_sha256 is not None
        else hashlib.sha256(jcs_bytes(body)).hexdigest()
    )

    stripped_body = strip_signature_fields(body)
    cage_canonical_bytes = jcs_bytes(stripped_body)
    cage_preimage = cage_preimage_builder(body)
    cage_preimage_sha256 = hashlib.sha256(cage_preimage).hexdigest()

    intent_sha256_hex, intent_sha256_raw, intent_source = _resolve_intent_sha256(body)
    if intent_sha256_hex is not None and intent_sha256_raw is not None:
        archytan_preimage = RECEIPT_DOMAIN_TAG + intent_sha256_hex.encode("ascii")
        archytan_preimage_utf8: str | None = archytan_preimage.decode("ascii")
        archytan_preimage_sha256: str | None = hashlib.sha256(
            archytan_preimage
        ).hexdigest()
        archytan_raw_preimage = RECEIPT_DOMAIN_TAG + intent_sha256_raw
        archytan_raw_preimage_hex: str | None = archytan_raw_preimage.hex()
        archytan_raw_preimage_sha256: str | None = hashlib.sha256(
            archytan_raw_preimage
        ).hexdigest()
    else:
        archytan_preimage_utf8 = None
        archytan_preimage_sha256 = None
        archytan_raw_preimage_hex = None
        archytan_raw_preimage_sha256 = None

    missing_envelope_digest = not _has_field(body, "envelope_digest")
    missing_intent_hash = not _has_field(body, "intent_hash")
    absent: list[str] = []
    if missing_envelope_digest:
        absent.append("envelope_digest")
    if missing_intent_hash:
        absent.append("intent_hash")

    preimage_digest_mismatch = (
        archytan_preimage_sha256 is None
        or cage_preimage_sha256
        not in {archytan_preimage_sha256, archytan_raw_preimage_sha256}
    )

    if preimage_digest_mismatch and missing_envelope_digest:
        reason = "both (preimage digest mismatch; missing envelope_digest)"
    elif preimage_digest_mismatch:
        reason = "preimage digest mismatch"
    elif missing_envelope_digest:
        reason = "missing envelope_digest"
    else:
        reason = "none"

    reconciled = not preimage_digest_mismatch and not missing_envelope_digest

    return ReceiptDiagnosis(
        input_name=input_name,
        input_sha256=effective_input_sha256,
        signature_verification="NOT_PERFORMED",
        reconciled=reconciled,
        reason=reason,
        preimage_digest_mismatch=preimage_digest_mismatch,
        missing_envelope_digest=missing_envelope_digest,
        missing_intent_hash=missing_intent_hash,
        absent_fields=tuple(absent),
        cage_domain_tag=RECEIPT_DOMAIN_TAG_STR,
        cage_canonical_body_utf8=cage_canonical_bytes.decode("utf-8"),
        cage_preimage_utf8=cage_preimage.decode("utf-8", errors="replace"),
        cage_preimage_sha256=cage_preimage_sha256,
        archytan_domain_tag=RECEIPT_DOMAIN_TAG_STR,
        intent_digest_source=intent_source,
        intent_sha256_hex=intent_sha256_hex,
        archytan_preimage_utf8=archytan_preimage_utf8,
        archytan_preimage_sha256=archytan_preimage_sha256,
        archytan_raw_preimage_hex=archytan_raw_preimage_hex,
        archytan_raw_preimage_sha256=archytan_raw_preimage_sha256,
    )


def format_diagnosis(diagnosis: ReceiptDiagnosis) -> str:
    """Render a human-readable diagnostic report."""
    status = "AGREEMENT" if diagnosis.reconciled else "MISMATCH"
    env_state = "absent" if diagnosis.missing_envelope_digest else "present"
    intent_state = "absent" if diagnosis.missing_intent_hash else "present"
    absent_str = (
        ", ".join(diagnosis.absent_fields) if diagnosis.absent_fields else "none"
    )
    lines = [
        f"actuator_01 receipt diagnostic: {status}",
        f"  input:                   {diagnosis.input_name} sha256:{diagnosis.input_sha256}",
        "  signature_verification:  NOT_PERFORMED (compares signed-message preimages and required fields only)",
        f"  reason:                  {diagnosis.reason}",
        "  required_fields:",
        f"    envelope_digest (CAGE receipt_verifier.py:230): {env_state}",
        f"    intent_hash (Archytan receipt schema):          {intent_state}",
        f"  absent_required_fields:  {absent_str}",
        "  cage_candidate (RECEIPT_SIGNATURE_DOMAIN_TAG || JCS(body - {signature, ingress_signature})):",
        f"    preimage_utf8:         {diagnosis.cage_preimage_utf8}",
        f"    preimage_sha256:       {diagnosis.cage_preimage_sha256}",
        '  archytan_candidate ("ARCHYTAN_RECEIPT_V1:" || SHA-256(intent_hash)):',
    ]
    if diagnosis.archytan_preimage_utf8 is not None:
        lines.extend(
            [
                f"    intent_digest_source:  {diagnosis.intent_digest_source}",
                f"    intent_sha256_hex:     {diagnosis.intent_sha256_hex}",
                f"    preimage_utf8 (hex):   {diagnosis.archytan_preimage_utf8}",
                f"    preimage_sha256 (hex): {diagnosis.archytan_preimage_sha256}",
                f"    preimage_hex (raw32):  {diagnosis.archytan_raw_preimage_hex}",
                f"    preimage_sha256 (raw): {diagnosis.archytan_raw_preimage_sha256}",
            ]
        )
    else:
        lines.append(
            "    unavailable:           neither intent_hash nor envelope_digest present"
        )
    return "\n".join(lines)


def _read_receipt_input(source: str | Path) -> tuple[dict[str, Any], str, str]:
    """Read a receipt JSON object from a file path or ``-`` (stdin)."""
    if str(source) == "-":
        name = "<stdin>"
        raw_bytes = sys.stdin.buffer.read()
    else:
        path = Path(source)
        name = path.name
        raw_bytes = path.read_bytes()
    input_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    parsed = json.loads(raw_bytes.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("receipt JSON root must be an object")
    return parsed, name, input_sha256


def add_diagnose_receipt_arguments(parser: argparse.ArgumentParser) -> None:
    """Attach CLI arguments for ``diagnose-receipt``."""
    parser.add_argument(
        "receipt",
        nargs="?",
        default="-",
        help="Path to receipt JSON file, or '-' (default) to read stdin",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit the diagnostic report as JSON",
    )


def run_diagnose_receipt(
    receipt_source: str | Path,
    *,
    as_json: bool = False,
    cage_preimage_builder: PreimageBuilder = build_cage_preimage,
) -> int:
    """Run the receipt diagnostic and print the result; return 0 on agreement, 1 on mismatch."""
    body, name, input_sha256 = _read_receipt_input(receipt_source)
    diagnosis = diagnose_receipt(
        body,
        input_name=name,
        input_sha256=input_sha256,
        cage_preimage_builder=cage_preimage_builder,
    )
    if as_json:
        print(json.dumps(diagnosis.to_dict(), indent=2))
    else:
        print(format_diagnosis(diagnosis))
    return 0 if diagnosis.reconciled else 1


def main(
    argv: list[str] | None = None,
    *,
    cage_preimage_builder: PreimageBuilder = build_cage_preimage,
) -> int:
    """Standalone CLI entry point for ``python3 -m cage_conformance.receipt_diagnostic``."""
    parser = argparse.ArgumentParser(
        prog="cage-conformance diagnose-receipt",
        description=(
            "Compare CAGE verify_partner_receipt() preimage and field requirements "
            "against Archytan's receipt signing scheme (offline, no signature check)"
        ),
        allow_abbrev=False,
    )
    add_diagnose_receipt_arguments(parser)
    args = parser.parse_args(argv)
    try:
        return run_diagnose_receipt(
            args.receipt,
            as_json=args.as_json,
            cage_preimage_builder=cage_preimage_builder,
        )
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

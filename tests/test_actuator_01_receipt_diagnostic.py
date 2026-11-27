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

"""Tests for the offline actuator_01 receipt preimage diagnostic."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_REPO_ROOT = Path(__file__).resolve().parents[1]
_PACKAGE_ROOT = _REPO_ROOT / "packages" / "cage-conformance"
_PACKAGE_SRC = _PACKAGE_ROOT / "src"
if str(_PACKAGE_SRC) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_SRC))

from cage_conformance.cli import main as cli_main  # noqa: E402
from cage_conformance.receipt_diagnostic import (  # noqa: E402
    RECEIPT_DOMAIN_TAG,
    build_cage_preimage,
    build_legacy_jcs_preimage,
    build_partner_preimage,
    diagnose_receipt,
    format_diagnosis,
)
from cage_conformance.receipt_diagnostic import (  # noqa: E402
    main as diag_main,
)
from cage_conformance.stream_invariants import jcs_bytes  # noqa: E402

from src.gateway.governance.seams.actuation import (  # noqa: E402
    ReceiptVerification,
)
from src.integrations.actuator_01.receipt_verifier import (  # noqa: E402
    ReceiptCheck,
    verify_partner_receipt,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

_README_FIXTURE_PATH = (
    _PACKAGE_SRC / "cage_conformance" / "vectors" / "actuator_01_readme_receipt.json"
)
_VECTOR1_PATH = (
    _REPO_ROOT / "tests" / "fixtures" / "actuator_01" / "vector1_direct.json"
)
_VECTOR1_SHA256 = "83398b88482ae07f5ef11a95f7a695849a407da398feef48e4701d9f67c35e6e"


class _CapturingPublicKey:
    """Spying Ed25519PublicKey wrapper that records the preimage bytes verify_partner_receipt passes to verify()."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.attempted_preimages: list[bytes] = []
        self.verified_preimage: bytes | None = None

    def verify(self, signature: bytes, data: bytes) -> None:
        self.attempted_preimages.append(data)
        self._inner.verify(signature, data)
        self.verified_preimage = data


class _StaticKeyResolver:
    def __init__(self, public_key: Any) -> None:
        self._public_key = public_key

    async def get_key(self, _kid: str) -> Any:
        return self._public_key


def _verify_with_receipt_verifier(
    body: dict[str, Any],
    *,
    signed_preimage: bytes,
    envelope_digest: str,
) -> tuple[_CapturingPublicKey, ReceiptCheck]:
    """Sign ``signed_preimage`` with a real Ed25519 key and run ``verify_partner_receipt`` to capture its preimage."""
    private_key = Ed25519PrivateKey.generate()
    sig_bytes = private_key.sign(signed_preimage)
    signed_body = dict(body)
    if isinstance(body.get("signature"), dict):
        signed_body["signature"] = {
            **body["signature"],
            "value": base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode("ascii"),
        }
    else:
        signed_body["signature"] = sig_bytes.hex()
    capturing_key = _CapturingPublicKey(private_key.public_key())
    check = asyncio.run(
        verify_partner_receipt(
            signed_body,
            envelope_digest=envelope_digest,
            key_resolver=_StaticKeyResolver(capturing_key),  # type: ignore[arg-type]
        )
    )
    return capturing_key, check


def _partner_receipt() -> dict[str, Any]:
    """Build a partner-shaped receipt with intent_hash and no envelope_digest."""
    vector1_obj = json.loads(_VECTOR1_PATH.read_text(encoding="utf-8"))
    intent_jcs = jcs_bytes(vector1_obj).decode("utf-8")
    return {
        "receipt_id": "r-actuator-01-0001",
        "timestamp_ns": 1785012000000000000,
        "status": "ACCEPTED",
        "intent_hash": intent_jcs,
        "signature": "a" * 128,
        "ingress_signature": "b" * 128,
    }


def _legacy_envelope_digest_receipt() -> dict[str, Any]:
    """Build a retired legacy receipt carrying envelope_digest and no intent_hash."""
    return {
        "receipt_id": "r-legacy-0001",
        "session_uuid": "550e8400-e29b-41d4-a716-446655440000",
        "status": "accepted",
        "envelope_digest": _VECTOR1_SHA256,
        "signature": {
            "alg": "EdDSA",
            "kid": "actuator-01-sandbox-receipt-2026-01",
            "value": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        },
    }


def test_cage_preimage_matches_receipt_verifier_path() -> None:
    """Bind build_cage_preimage() 1:1 to verify_partner_receipt()'s preimage path."""
    fixture_body = json.loads(_README_FIXTURE_PATH.read_text(encoding="utf-8"))
    diag_fixture_preimage = build_cage_preimage(fixture_body)
    assert diag_fixture_preimage is not None
    assert diag_fixture_preimage == build_partner_preimage(fixture_body)
    capturing_fixture_key, fixture_check = _verify_with_receipt_verifier(
        fixture_body,
        signed_preimage=diag_fixture_preimage,
        envelope_digest=_VECTOR1_SHA256,
    )
    assert capturing_fixture_key.attempted_preimages == [diag_fixture_preimage]
    assert capturing_fixture_key.verified_preimage == diag_fixture_preimage
    assert fixture_check.verification == ReceiptVerification.VERIFIED

    partner_body = _partner_receipt()
    diag_partner_preimage = build_cage_preimage(partner_body)
    assert diag_partner_preimage is not None
    capturing_partner_key, partner_check = _verify_with_receipt_verifier(
        partner_body,
        signed_preimage=diag_partner_preimage,
        envelope_digest=_VECTOR1_SHA256,
    )
    assert capturing_partner_key.attempted_preimages == [diag_partner_preimage]
    assert capturing_partner_key.verified_preimage == diag_partner_preimage
    assert partner_check.verification == ReceiptVerification.VERIFIED

    legacy_body = _legacy_envelope_digest_receipt()
    assert build_cage_preimage(legacy_body) is None
    capturing_legacy_key, legacy_check = _verify_with_receipt_verifier(
        legacy_body,
        signed_preimage=build_legacy_jcs_preimage(legacy_body),
        envelope_digest=_VECTOR1_SHA256,
    )
    assert capturing_legacy_key.attempted_preimages == []
    assert capturing_legacy_key.verified_preimage is None
    assert legacy_check.verification == ReceiptVerification.INVALID
    assert legacy_check.finding is not None
    assert legacy_check.finding["code"] == "RECEIPT_MISSING_INTENT_HASH"


def test_readme_fixture_and_partner_receipt_report_agreement_and_exit_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The aligned README fixture and partner intent_hash receipt report AGREEMENT and exit 0."""
    assert _README_FIXTURE_PATH.is_file()
    exit_code = cli_main(["diagnose-receipt", str(_README_FIXTURE_PATH)])
    assert exit_code == 0

    out = capsys.readouterr().out
    assert "actuator_01 receipt diagnostic: AGREEMENT" in out
    assert "signature_verification:  NOT_PERFORMED" in out
    assert "reason:                  none" in out
    assert "intent_hash (CAGE & partner receipt schema):    present" in out
    assert "envelope_digest (legacy optional echo):         absent (optional)" in out
    assert "absent_required_fields:  none" in out
    assert f"intent_sha256_hex:     {_VECTOR1_SHA256}" in out
    expected_preimage = RECEIPT_DOMAIN_TAG + _VECTOR1_SHA256.encode("ascii")
    assert expected_preimage.decode("ascii") in out
    assert hashlib.sha256(expected_preimage).hexdigest() in out

    partner_file = tmp_path / "partner_receipt.json"
    partner_file.write_text(json.dumps(_partner_receipt()), encoding="utf-8")
    assert cli_main(["diagnose-receipt", str(partner_file)]) == 0
    assert "actuator_01 receipt diagnostic: AGREEMENT" in capsys.readouterr().out


def test_legacy_envelope_digest_only_receipt_reports_missing_intent_hash(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A legacy envelope_digest-only receipt (no intent_hash) reports MISMATCH and exits 1."""
    legacy_body = _legacy_envelope_digest_receipt()
    receipt_file = tmp_path / "legacy_receipt.json"
    receipt_file.write_text(json.dumps(legacy_body), encoding="utf-8")

    exit_code = cli_main(["diagnose-receipt", str(receipt_file)])
    assert exit_code == 1

    out = capsys.readouterr().out
    assert "actuator_01 receipt diagnostic: MISMATCH" in out
    assert (
        "reason:                  missing intent_hash (legacy envelope_digest-only receipt)"
        in out
    )
    assert "intent_hash (CAGE & partner receipt schema):    absent" in out
    assert "envelope_digest (legacy optional echo):         present" in out
    assert "absent_required_fields:  intent_hash" in out
    assert "envelope_digest (intent_hash absent)" in out


def test_legacy_jcs_preimage_builder_reports_mismatch(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Diagnosing against the retired JCS(body) preimage builder reports preimage digest mismatch."""
    body = _partner_receipt()
    receipt_file = tmp_path / "partner_vs_legacy_jcs.json"
    receipt_file.write_text(json.dumps(body), encoding="utf-8")

    exit_code = diag_main(
        [str(receipt_file)], cage_preimage_builder=build_legacy_jcs_preimage
    )
    assert exit_code == 1

    out = capsys.readouterr().out
    assert "actuator_01 receipt diagnostic: MISMATCH" in out
    assert "reason:                  preimage digest mismatch" in out

    # Legacy receipt missing intent_hash with legacy JCS builder reports both reasons
    legacy_file = tmp_path / "legacy_both.json"
    legacy_file.write_text(
        json.dumps(_legacy_envelope_digest_receipt()), encoding="utf-8"
    )
    assert (
        diag_main([str(legacy_file)], cage_preimage_builder=build_legacy_jcs_preimage)
        == 1
    )
    out_both = capsys.readouterr().out
    assert (
        "reason:                  both (preimage digest mismatch; missing intent_hash)"
        in out_both
    )


def test_conflicting_envelope_digest_reports_mismatch(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A receipt carrying both intent_hash and a conflicting envelope_digest fails reconciliation."""
    body = {**_partner_receipt(), "envelope_digest": "f" * 64}
    receipt_file = tmp_path / "conflicting.json"
    receipt_file.write_text(json.dumps(body), encoding="utf-8")

    assert cli_main(["diagnose-receipt", str(receipt_file)]) == 1
    out = capsys.readouterr().out
    assert "actuator_01 receipt diagnostic: MISMATCH" in out
    assert (
        "reason:                  envelope_digest conflicts with sha256(intent_hash)"
        in out
    )


def test_reads_from_stdin_and_supports_json_flag(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Diagnostic accepts receipt JSON from stdin (default or '-') and emits JSON with --json."""
    raw_bytes = _README_FIXTURE_PATH.read_bytes()

    class _StdinStub:
        def __init__(self, data: bytes) -> None:
            self.buffer = io.BytesIO(data)

    monkeypatch.setattr(sys, "stdin", _StdinStub(raw_bytes))
    exit_code = cli_main(["diagnose-receipt", "--json"])
    assert exit_code == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["input_name"] == "<stdin>"
    assert payload["signature_verification"] == "NOT_PERFORMED"
    assert payload["reconciled"] is True
    assert payload["reason"] == "none"
    assert payload["absent_fields"] == []


def test_dict_intent_hash_and_missing_both_digests() -> None:
    """Supports dict intent_hash and handles receipts missing both intent_hash and envelope_digest."""
    vector1_obj = json.loads(_VECTOR1_PATH.read_text(encoding="utf-8"))
    diag_dict_intent = diagnose_receipt(
        {"receipt_id": "r-1", "status": "ACCEPTED", "intent_hash": vector1_obj}
    )
    assert diag_dict_intent.intent_sha256_hex == _VECTOR1_SHA256
    assert diag_dict_intent.intent_digest_source == "sha256(JCS(intent_hash))"
    assert diag_dict_intent.reconciled is True
    assert diag_dict_intent.reason == "none"

    diag_empty = diagnose_receipt({"receipt_id": "r-empty", "status": "ACCEPTED"})
    assert diag_empty.partner_preimage_utf8 is None
    assert diag_empty.absent_fields == ("intent_hash",)
    assert diag_empty.reconciled is False
    assert diag_empty.reason == "missing intent_hash"
    assert "neither intent_hash nor envelope_digest present" in format_diagnosis(
        diag_empty
    )


def test_invalid_input_returns_exit_code_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Non-JSON or non-object JSON returns exit code 2."""
    bad = tmp_path / "array.json"
    bad.write_text("[1, 2, 3]\n", encoding="utf-8")
    assert cli_main(["diagnose-receipt", str(bad)]) == 2
    assert "error:" in capsys.readouterr().err


def test_runs_under_python_isolated_stdlib_only(tmp_path: Path) -> None:
    """Runs under python -I -S with no CAGE checkout and no cryptography dependency."""
    site = tmp_path / "site"
    shutil.copytree(
        _PACKAGE_SRC / "cage_conformance",
        site / "cage_conformance",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    fixture = site / "cage_conformance" / "vectors" / "actuator_01_readme_receipt.json"
    script = "\n".join(
        [
            "import sys",
            f"sys.path.insert(0, {str(site)!r})",
            "from cage_conformance.cli import main",
            f"code = main(['diagnose-receipt', {str(fixture)!r}])",
            "leaked = sorted(m for m in sys.modules if m.split('.')[0] in {'src', 'proof'})",
            "assert not leaked, leaked",
            "assert 'cryptography' not in sys.modules",
            "raise SystemExit(code)",
        ]
    )
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-I", "-S", "-c", script],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "actuator_01 receipt diagnostic: AGREEMENT" in proc.stdout
    assert "RECEIPT_DOMAIN_TAG" not in proc.stderr
    assert RECEIPT_DOMAIN_TAG.decode("ascii") in proc.stdout


def test_receipt_domain_tag_matches_actuator_01_constants() -> None:
    """Offline diagnostic domain tag must match actuator_01 runtime verifier constant."""
    from src.integrations.actuator_01.constants import RECEIPT_SIGNATURE_DOMAIN_TAG

    assert RECEIPT_DOMAIN_TAG == RECEIPT_SIGNATURE_DOMAIN_TAG

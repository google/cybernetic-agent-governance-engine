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


def test_cage_preimage_matches_receipt_verifier_path() -> None:
    """Bind build_cage_preimage() directly to verify_partner_receipt()'s preimage path (lines 193-224).

    Exercises key stripping (signature and ingress_signature), domain-tag prefix,
    JCS canonicalization, and concatenation by passing a signature over
    build_cage_preimage(body) through verify_partner_receipt() and asserting the
    exact bytes passed to public_key.verify() equal build_cage_preimage(body).
    """
    fixture_body = json.loads(_README_FIXTURE_PATH.read_text(encoding="utf-8"))
    diag_fixture_preimage = build_cage_preimage(fixture_body)
    capturing_fixture_key, fixture_check = _verify_with_receipt_verifier(
        fixture_body,
        signed_preimage=diag_fixture_preimage,
        envelope_digest=fixture_body["envelope_digest"],
    )
    assert capturing_fixture_key.attempted_preimages[0] == diag_fixture_preimage
    assert capturing_fixture_key.verified_preimage == diag_fixture_preimage
    assert fixture_check.verification == ReceiptVerification.VERIFIED

    partner_body = _partner_receipt()
    diag_partner_preimage = build_cage_preimage(partner_body)
    capturing_partner_key, partner_check = _verify_with_receipt_verifier(
        partner_body,
        signed_preimage=diag_partner_preimage,
        envelope_digest=_VECTOR1_SHA256,
    )
    # verify_partner_receipt tries body minus "signature" first, then body minus
    # ("signature", "ingress_signature") with RECEIPT_SIGNATURE_DOMAIN_TAG, which
    # matches build_cage_preimage(partner_body) and passes Ed25519 verification
    # before failing on the missing envelope_digest at line 230.
    assert capturing_partner_key.verified_preimage == diag_partner_preimage
    assert partner_check.verification == ReceiptVerification.INVALID
    assert partner_check.finding is not None
    assert partner_check.finding["code"] == "RECEIPT_ENVELOPE_MISMATCH"


def test_readme_fixture_reports_preimage_digest_mismatch_and_exits_nonzero(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The shipped README-shaped fixture reports preimage digest mismatch and exits 1."""
    assert _README_FIXTURE_PATH.is_file()
    fixture_body = json.loads(_README_FIXTURE_PATH.read_text(encoding="utf-8"))

    diag_preimage = build_cage_preimage(fixture_body)
    capturing_key, check = _verify_with_receipt_verifier(
        fixture_body,
        signed_preimage=diag_preimage,
        envelope_digest=fixture_body["envelope_digest"],
    )
    assert check.verification == ReceiptVerification.VERIFIED
    assert capturing_key.verified_preimage == diag_preimage

    exit_code = cli_main(["diagnose-receipt", str(_README_FIXTURE_PATH)])
    assert exit_code == 1

    out = capsys.readouterr().out
    assert "actuator_01 receipt diagnostic: MISMATCH" in out
    assert "signature_verification:  NOT_PERFORMED" in out
    assert "reason:                  preimage digest mismatch" in out
    assert "envelope_digest (CAGE receipt_verifier.py:230): present" in out
    assert "intent_hash (partner receipt schema):           absent" in out
    assert "absent_required_fields:  intent_hash" in out

    expected_cage_sha256 = hashlib.sha256(capturing_key.verified_preimage).hexdigest()
    expected_partner_preimage = f"ARCHYTAN_RECEIPT_V1:{_VECTOR1_SHA256}".encode(
        "ascii"
    )
    expected_partner_sha256 = hashlib.sha256(expected_partner_preimage).hexdigest()

    assert capturing_key.verified_preimage.decode("utf-8") in out
    assert expected_cage_sha256 in out
    assert expected_partner_preimage.decode("ascii") in out
    assert expected_partner_sha256 in out


def test_partner_shaped_receipt_reports_both_preimage_and_missing_envelope_digest(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A partner receipt (intent_hash, no envelope_digest) reports both reasons and exits 1."""
    body = _partner_receipt()
    receipt_file = tmp_path / "partner_receipt.json"
    receipt_file.write_text(json.dumps(body), encoding="utf-8")

    diag_preimage = build_cage_preimage(body)
    capturing_key, _ = _verify_with_receipt_verifier(
        body,
        signed_preimage=diag_preimage,
        envelope_digest=_VECTOR1_SHA256,
    )
    assert capturing_key.verified_preimage == diag_preimage

    exit_code = cli_main(["diagnose-receipt", str(receipt_file)])
    assert exit_code == 1

    out = capsys.readouterr().out
    assert "actuator_01 receipt diagnostic: MISMATCH" in out
    assert (
        "reason:                  both (preimage digest mismatch; missing envelope_digest)"
        in out
    )
    assert "envelope_digest (CAGE receipt_verifier.py:230): absent" in out
    assert "intent_hash (partner receipt schema):           present" in out
    assert "absent_required_fields:  envelope_digest" in out
    assert f"intent_sha256_hex:     {_VECTOR1_SHA256}" in out
    assert f"ARCHYTAN_RECEIPT_V1:{_VECTOR1_SHA256}" in out


def test_missing_envelope_digest_only_reason(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """When preimage digests match but envelope_digest is absent, reports missing envelope_digest."""
    body = _partner_receipt()
    receipt_file = tmp_path / "missing_env_only.json"
    receipt_file.write_text(json.dumps(body), encoding="utf-8")

    def matching_builder(b: Any) -> bytes:
        preimage = build_partner_preimage(b)
        assert preimage is not None
        return preimage

    exit_code = diag_main([str(receipt_file)], cage_preimage_builder=matching_builder)
    assert exit_code == 1

    out = capsys.readouterr().out
    assert "actuator_01 receipt diagnostic: MISMATCH" in out
    assert "reason:                  missing envelope_digest" in out


def test_agreement_exits_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """When preimage digests match and envelope_digest is present, reports AGREEMENT and exits 0."""
    body = {
        **_partner_receipt(),
        "envelope_digest": _VECTOR1_SHA256,
    }
    receipt_file = tmp_path / "reconciled.json"
    receipt_file.write_text(json.dumps(body), encoding="utf-8")

    def matching_builder(b: Any) -> bytes:
        preimage = build_partner_preimage(b)
        assert preimage is not None
        return preimage

    exit_code = diag_main([str(receipt_file)], cage_preimage_builder=matching_builder)
    assert exit_code == 0

    out = capsys.readouterr().out
    assert "actuator_01 receipt diagnostic: AGREEMENT" in out
    assert "reason:                  none" in out
    assert "absent_required_fields:  none" in out


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
    assert exit_code == 1

    payload = json.loads(capsys.readouterr().out)
    assert payload["input_name"] == "<stdin>"
    assert payload["signature_verification"] == "NOT_PERFORMED"
    assert payload["reconciled"] is False
    assert payload["reason"] == "preimage digest mismatch"
    assert payload["absent_fields"] == ["intent_hash"]


def test_dict_intent_hash_and_missing_both_digests() -> None:
    """Supports dict intent_hash and handles receipts missing both intent_hash and envelope_digest."""
    vector1_obj = json.loads(_VECTOR1_PATH.read_text(encoding="utf-8"))
    diag_dict_intent = diagnose_receipt(
        {"receipt_id": "r-1", "status": "ACCEPTED", "intent_hash": vector1_obj}
    )
    assert diag_dict_intent.intent_sha256_hex == _VECTOR1_SHA256
    assert diag_dict_intent.intent_digest_source == "sha256(JCS(intent_hash))"
    assert (
        diag_dict_intent.reason
        == "both (preimage digest mismatch; missing envelope_digest)"
    )

    diag_empty = diagnose_receipt({"receipt_id": "r-empty", "status": "ACCEPTED"})
    assert diag_empty.partner_preimage_utf8 is None
    assert diag_empty.absent_fields == ("envelope_digest", "intent_hash")
    assert (
        diag_empty.reason == "both (preimage digest mismatch; missing envelope_digest)"
    )
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
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "reason:                  preimage digest mismatch" in proc.stdout
    assert "RECEIPT_DOMAIN_TAG" not in proc.stderr
    assert RECEIPT_DOMAIN_TAG.decode("ascii") in proc.stdout

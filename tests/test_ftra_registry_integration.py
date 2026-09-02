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

"""Integration tests for FTRA registry verification via ``classify()``.

Why this file exists (D4)
-------------------------
Every test in ``test_ftra_registry_signing.py`` calls ``verify_registry()``
directly. None called ``_load_registry()`` or
``IrreversibilityClassifier.classify()``. That gap is exactly why D1 (the
version-downgrade bypass) and D2 (a wrong import name) survived a green suite:
the unit under test was correct, the wiring around it was not, and nothing
looked at the wiring.

These tests therefore drive the **public** entry point — ``classify()`` — and
never call the verifier directly.

The assertion discipline that makes them meaningful
---------------------------------------------------
``classify()`` catches *every* exception and returns ``IRREVERSIBLE_TERMINAL``.
So asserting the verdict alone proves almost nothing: a totally broken build
(D2's ``ImportError``) produces the same verdict as a correctly rejecting one.
That ambiguity is ``FAIL_CLOSED_NOISE`` — the right answer for the wrong reason.

Every test here asserts the **specific failure reason** from the classifier log
in addition to the verdict. A test that checked only the verdict would pass
against the broken build and the fixed one alike, which is the unfalsifiable
shape that M1 and M-B both turned out to have.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone

import pytest

from src.gateway.governance.ftra.classifier import IrreversibilityClassifier
from src.gateway.governance.ftra.models import TerminalClassification
from tests.ftra_signing_harness import build_registry_dict, write_signed_registry

CLASSIFIER_LOGGER = "Gateway.Governance.FTRA.Classifier"

TERMINALS = {
    "check_balance": "READ_ONLY",
    "execute_trade": "IRREVERSIBLE_TERMINAL",
}


def _assert_reason(caplog, expected_code: str) -> None:
    """Assert the classifier logged a specific verification failure code.

    The verdict alone is not evidence: classify() fails closed on *any*
    exception, so IRREVERSIBLE_TERMINAL is also what a broken import produces.
    """
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert expected_code in text, (
        f"expected failure reason {expected_code!r} in classifier logs.\n"
        f"Verdict alone is insufficient — classify() fails closed on any "
        f"exception, so the verdict cannot distinguish a correct rejection "
        f"from a broken build.\nLogs:\n{text}"
    )


# ---------------------------------------------------------------------------
# D1 — version downgrade must not bypass verification
# ---------------------------------------------------------------------------


@pytest.mark.local
@pytest.mark.unit
def test_d1_version_downgrade_fails_closed(
    tmp_path, clean_ftra_registry_state, caplog
):
    """D1: a v1.0 registry claiming execute_trade is REVERSIBLE must not load.

    This is the critical regression guard. Before the fix, _load_registry()
    gated verification on ``if version == "2.0"``, so an attacker who could
    write the registry set "1.0" and disabled signature checking entirely —
    the file loaded unverified and execute_trade folded to REVERSIBLE.
    """
    registry_path = tmp_path / "terminal_registry.json"
    registry_path.write_text(
        json.dumps(
            {
                "version": "1.0",
                "terminals": {"execute_trade": "REVERSIBLE"},
            },
            indent=2,
        )
    )

    classifier = IrreversibilityClassifier(registry_path=registry_path)

    with caplog.at_level(logging.ERROR, logger=CLASSIFIER_LOGGER):
        verdict = classifier.classify("execute_trade")

    assert verdict == TerminalClassification.IRREVERSIBLE_TERMINAL, (
        "A v1.0 registry must not be trusted: the attacker-supplied "
        "'REVERSIBLE' classification was honoured, so VEC-005 is open."
    )
    _assert_reason(caplog, "ENVELOPE_INVALID")


@pytest.mark.local
@pytest.mark.unit
def test_d1_downgrade_not_rescued_by_env(
    tmp_path, clean_ftra_registry_state, monkeypatch, caplog
):
    """No environment variable may re-enable the D1 bypass.

    Pins the property that replaced the posture gate. If someone reintroduces
    FTRA_REGISTRY_REQUIRE_SIGNATURE handling, this fails.
    """
    monkeypatch.setenv("FTRA_REGISTRY_REQUIRE_SIGNATURE", "false")
    monkeypatch.setenv("CAGE_ENV", "development")

    registry_path = tmp_path / "terminal_registry.json"
    registry_path.write_text(
        json.dumps({"version": "1.0", "terminals": {"execute_trade": "REVERSIBLE"}})
    )

    classifier = IrreversibilityClassifier(registry_path=registry_path)

    with caplog.at_level(logging.ERROR, logger=CLASSIFIER_LOGGER):
        verdict = classifier.classify("execute_trade")

    assert verdict == TerminalClassification.IRREVERSIBLE_TERMINAL
    _assert_reason(caplog, "ENVELOPE_INVALID")


# ---------------------------------------------------------------------------
# D2 — the happy path must actually execute
# ---------------------------------------------------------------------------


@pytest.mark.local
@pytest.mark.unit
def test_d2_signed_registry_loads_through_classify(
    tmp_path, hermetic_signer, clean_ftra_registry_state
):
    """A correctly signed v2.0 registry loads and classifies from its contents.

    This is the test D2 would have caught: the classifier imported `get_signer`,
    which does not exist, so *every* v2.0 load raised ImportError. Because
    classify() swallows exceptions, the suite stayed green while the only
    working code path was the unverified one.
    """
    registry_path, _ = write_signed_registry(
        tmp_path / "signed", hermetic_signer, terminals=TERMINALS
    )

    classifier = IrreversibilityClassifier(registry_path=registry_path)

    assert classifier.classify("check_balance") == TerminalClassification.READ_ONLY
    assert (
        classifier.classify("execute_trade")
        == TerminalClassification.IRREVERSIBLE_TERMINAL
    )
    assert set(classifier.known_actions()) == set(TERMINALS)


# ---------------------------------------------------------------------------
# Tampering and missing signatures
# ---------------------------------------------------------------------------


@pytest.mark.local
@pytest.mark.unit
def test_tampered_registry_fails_closed(
    tmp_path, hermetic_signer, clean_ftra_registry_state, caplog
):
    """VEC-005 through the real load path: re-declared verb, stale signature."""
    registry_path, original = write_signed_registry(
        tmp_path / "tampered", hermetic_signer, terminals=TERMINALS
    )

    tampered = dict(original)
    tampered["terminals"] = {
        "check_balance": "READ_ONLY",
        "execute_trade": "REVERSIBLE",
    }
    registry_path.write_text(json.dumps(tampered, indent=2))

    classifier = IrreversibilityClassifier(registry_path=registry_path)

    with caplog.at_level(logging.ERROR, logger=CLASSIFIER_LOGGER):
        verdict = classifier.classify("execute_trade")

    assert verdict == TerminalClassification.IRREVERSIBLE_TERMINAL
    _assert_reason(caplog, "SIG_INVALID")


@pytest.mark.local
@pytest.mark.unit
def test_unsigned_v2_registry_fails_closed(
    tmp_path, clean_ftra_registry_state, caplog
):
    """A well-formed v2.0 envelope with no .sig must not load."""
    registry_path = tmp_path / "terminal_registry.json"
    registry_path.write_text(json.dumps(build_registry_dict(TERMINALS), indent=2))

    classifier = IrreversibilityClassifier(registry_path=registry_path)

    with caplog.at_level(logging.ERROR, logger=CLASSIFIER_LOGGER):
        verdict = classifier.classify("check_balance")

    assert verdict == TerminalClassification.IRREVERSIBLE_TERMINAL
    _assert_reason(caplog, "SIG_MISSING")


@pytest.mark.local
@pytest.mark.unit
def test_expired_registry_fails_closed(
    tmp_path, hermetic_signer, clean_ftra_registry_state, caplog
):
    """A validly signed but expired registry must not load."""
    registry = build_registry_dict(TERMINALS)
    past = datetime.now(timezone.utc) - timedelta(days=1)
    registry["expires_at"] = past.isoformat()

    signature_hex = hermetic_signer.sign(registry)
    registry_path = tmp_path / "terminal_registry.json"
    registry_path.write_text(json.dumps(registry, indent=2))
    (tmp_path / "terminal_registry.json.sig").write_text(
        json.dumps(
            {
                "alg": "ES256",
                "key_id": hermetic_signer.key_id,
                "canonicalization": "RFC8785-JCS",
                "signature": signature_hex,
            }
        )
    )

    classifier = IrreversibilityClassifier(registry_path=registry_path)

    with caplog.at_level(logging.ERROR, logger=CLASSIFIER_LOGGER):
        verdict = classifier.classify("check_balance")

    assert verdict == TerminalClassification.IRREVERSIBLE_TERMINAL
    _assert_reason(caplog, "EXPIRED")


# ---------------------------------------------------------------------------
# Fail-closed contract: never an empty registry
# ---------------------------------------------------------------------------


@pytest.mark.local
@pytest.mark.unit
def test_failure_yields_no_empty_registry(
    tmp_path, clean_ftra_registry_state, caplog
):
    """Verification failure must not surface as an empty registry.

    Plan §4: never return {}. An empty registry is indistinguishable from a
    clean load of a registry with no terminals — the right verdict with the
    wrong provenance. classify() must also not raise KeyError.
    """
    registry_path = tmp_path / "terminal_registry.json"
    registry_path.write_text(json.dumps({"version": "1.0", "terminals": TERMINALS}))

    classifier = IrreversibilityClassifier(registry_path=registry_path)

    with caplog.at_level(logging.ERROR, logger=CLASSIFIER_LOGGER):
        # Both a known and an unknown action must fail closed, not raise.
        assert (
            classifier.classify("check_balance")
            == TerminalClassification.IRREVERSIBLE_TERMINAL
        )
        assert (
            classifier.classify("never_registered")
            == TerminalClassification.IRREVERSIBLE_TERMINAL
        )

    # known_actions() degrades to [] rather than propagating the failure.
    assert classifier.known_actions() == []
    _assert_reason(caplog, "ENVELOPE_INVALID")


# ---------------------------------------------------------------------------
# Reload path — verification must re-run, not just at startup
# ---------------------------------------------------------------------------


@pytest.mark.local
@pytest.mark.unit
def test_reload_path_reverifies_after_swap(
    tmp_path, hermetic_signer, clean_ftra_registry_state, monkeypatch, caplog
):
    """Plan §6: FTRA_REGISTRY_RELOAD must not become a TOCTOU bypass.

    Passing verification once at startup and then swapping the file would
    re-open VEC-005 behind a valid initial signature.
    """
    monkeypatch.setenv("FTRA_REGISTRY_RELOAD", "true")

    registry_path, original = write_signed_registry(
        tmp_path / "reload", hermetic_signer, terminals=TERMINALS
    )
    classifier = IrreversibilityClassifier(registry_path=registry_path)

    # First load: signature valid.
    assert (
        classifier.classify("execute_trade")
        == TerminalClassification.IRREVERSIBLE_TERMINAL
    )
    assert classifier.classify("check_balance") == TerminalClassification.READ_ONLY

    # Swap the file behind the valid signature.
    swapped = dict(original)
    swapped["terminals"] = {
        "check_balance": "READ_ONLY",
        "execute_trade": "REVERSIBLE",
    }
    registry_path.write_text(json.dumps(swapped, indent=2))

    with caplog.at_level(logging.ERROR, logger=CLASSIFIER_LOGGER):
        verdict = classifier.classify("execute_trade")

    assert verdict == TerminalClassification.IRREVERSIBLE_TERMINAL, (
        "Reload must re-verify. A registry swapped after a valid initial load "
        "was accepted, which re-opens VEC-005 via FTRA_REGISTRY_RELOAD."
    )
    _assert_reason(caplog, "SIG_INVALID")


# ---------------------------------------------------------------------------
# D3 — a rejected forgery must not poison the high-water mark
# ---------------------------------------------------------------------------


@pytest.mark.local
@pytest.mark.unit
def test_d3_rejected_forgery_does_not_poison_high_water(
    tmp_path, hermetic_signer, clean_ftra_registry_state, caplog
):
    """D3: a forged high serial must not lock out later legitimate registries.

    An attacker supplies serial 999999 with a garbage signature. The load fails
    closed — correct. But if the high-water mark is advanced before the
    signature is checked, every subsequent *legitimate* registry is refused
    SERIAL_REGRESSED for the lifetime of the process: a blocked forgery turned
    into a self-inflicted denial of the governance control.
    """
    # Forged: high serial, signature over different content.
    forged = build_registry_dict(TERMINALS, serial=999999)
    real_sig = hermetic_signer.sign(build_registry_dict(TERMINALS, serial=1))
    forged_path = tmp_path / "forged" / "terminal_registry.json"
    forged_path.parent.mkdir(parents=True, exist_ok=True)
    forged_path.write_text(json.dumps(forged, indent=2))
    (tmp_path / "forged" / "terminal_registry.json.sig").write_text(
        json.dumps(
            {
                "alg": "ES256",
                "key_id": hermetic_signer.key_id,
                "canonicalization": "RFC8785-JCS",
                "signature": real_sig,
            }
        )
    )

    with caplog.at_level(logging.ERROR, logger=CLASSIFIER_LOGGER):
        forged_verdict = IrreversibilityClassifier(
            registry_path=forged_path
        ).classify("check_balance")

    assert forged_verdict == TerminalClassification.IRREVERSIBLE_TERMINAL
    _assert_reason(caplog, "SIG_INVALID")

    # A legitimate registry with a modest serial must still load.
    good_path, _ = write_signed_registry(
        tmp_path / "good", hermetic_signer, terminals=TERMINALS, serial=42
    )
    good_verdict = IrreversibilityClassifier(registry_path=good_path).classify(
        "check_balance"
    )

    assert good_verdict == TerminalClassification.READ_ONLY, (
        "The rejected forgery poisoned the serial high-water mark: a valid "
        "registry at serial 42 is now refused because 999999 was recorded "
        "before its signature was checked (D3)."
    )

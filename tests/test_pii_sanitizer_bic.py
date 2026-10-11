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
"""SWIFT/BIC redaction: true positives in context, no vocabulary false positives.

The previous shape-only pattern redacted any eight- or eleven-letter
upper-case word, including governance verdicts written to the evidence stream
(APPROVED, REJECTED, ESCALATE). That corrupted audit records and made states
that differ only in such a word produce the same hash.
"""

from __future__ import annotations

import ast
import re
from enum import Enum
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.ftra.models import FTRAVerdict
from src.gateway.governance.governor.pipeline import OpaVerdict
from src.gateway.governance.pii_sanitizer import _ISO_3166_ALPHA2, PIISanitizer

pytestmark = [pytest.mark.unit, pytest.mark.local]

REDACTED = "[REDACTED_SWIFT]"
SRC = Path(__file__).resolve().parents[1] / "src"
_VOCAB = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")

sanitizer = PIISanitizer()


def _repo_upper_case_vocabulary() -> set[str]:
    """Every upper-case string literal in src/ (verdicts, statuses, event types)."""
    vocab: set[str] = set()
    for path in SRC.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if _VOCAB.match(node.value):
                    vocab.add(node.value)
    return vocab


def _enum_values(*enums: type[Enum]) -> set[str]:
    return {str(member.value) for enum in enums for member in enum}


REPO_VOCAB = sorted(_repo_upper_case_vocabulary())
VERDICTS = sorted(_enum_values(GovernanceDecision, OpaVerdict, FTRAVerdict))
COMMON_STATES = [
    "APPROVED",
    "REJECTED",
    "ESCALATE",
    "ESCALATED",
    "PENDING_",
    "COMPLETED",
    "CANCELLED",
    "DEPOSITS",
    "CONFIRMS",
    "BLOCKED",
    "REQUIRE_APPROVAL",
    "MANUAL_REVIEW",
    "HITL_REQUIRED",
]


# ---------------------------------------------------------------------------
# True positives
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "bic"),
    [
        ("BIC: DEUTDEFF", "DEUTDEFF"),
        ("SWIFT code DEUTDEFF500 for settlement", "DEUTDEFF500"),
        ("Beneficiary SWIFT/BIC BNPAFRPPXXX.", "BNPAFRPPXXX"),
        ("bic=DEUTDEDB", "DEUTDEDB"),
        ("Swift #CHASUS33", "CHASUS33"),
        ("BIC no. HSBCHKHHHKH", "HSBCHKHHHKH"),
    ],
)
def test_labelled_bic_is_redacted(text: str, bic: str) -> None:
    result = sanitizer.sanitize(text)
    assert bic not in result
    assert REDACTED in result


@pytest.mark.parametrize(
    "key",
    ["bic", "BIC", "swift", "swift_code", "beneficiaryBic", "payee_bic", "swiftCode"],
)
def test_bic_keyed_value_is_redacted(key: str) -> None:
    result = sanitizer.sanitize_dict(
        {key: "BNPAFRPPXXX", "nested": {key: ["DEUTDEFF"]}}
    )
    assert result[key] == REDACTED
    assert result["nested"][key] == [REDACTED]


# ---------------------------------------------------------------------------
# False positives that must not happen
# ---------------------------------------------------------------------------


def test_invalid_country_code_is_not_a_bic_even_when_labelled() -> None:
    # "OV" and "CT" are not ISO 3166 codes.
    assert sanitizer.sanitize("BIC: APPROVED") == "BIC: APPROVED"
    assert sanitizer.sanitize_dict({"bic": "REJECTED"}) == {"bic": "REJECTED"}


def test_unlabelled_bic_shaped_words_are_preserved() -> None:
    text = "Route via DEUTDEDB: verdict APPROVED, then ESCALATE (DEPOSITS)"
    assert sanitizer.sanitize(text) == text


def test_non_bic_keys_do_not_trigger_key_context() -> None:
    record = {"bicycle": "DEUTDEFF", "swiftly": "DEUTDEFF", "decision": "ESCALATE"}
    assert sanitizer.sanitize_dict(record) == record


@pytest.mark.parametrize("word", COMMON_STATES + VERDICTS)
def test_verdicts_and_common_states_are_never_redacted(word: str) -> None:
    for text in (word, f"verdict={word}", f"Decision: {word}", f"status {word}."):
        assert REDACTED not in sanitizer.sanitize(text)
    record = {"verdict": word, "decision": word, "status": word, "items": [word]}
    assert sanitizer.sanitize_dict(record) == record


def test_repo_upper_case_vocabulary_is_never_swift_redacted() -> None:
    """Property over every upper-case string literal in src/."""
    assert len(REPO_VOCAB) > 100  # sanity: the scan found the vocabulary
    hits = [
        word
        for word in REPO_VOCAB
        if REDACTED in sanitizer.sanitize(f"verdict {word}")
        or REDACTED in str(sanitizer.sanitize_dict({"decision": word, "type": word}))
    ]
    assert hits == []


@settings(max_examples=500, deadline=None)
@given(
    word=st.from_regex(r"[A-Z]{8}|[A-Z]{11}", fullmatch=True),
    prefix=st.sampled_from(["", "verdict ", "status: ", "Decision=", "route via "]),
)
def test_unlabelled_upper_case_words_are_never_redacted(word: str, prefix: str) -> None:
    assert REDACTED not in sanitizer.sanitize(f"{prefix}{word}")


@settings(max_examples=300, deadline=None)
@given(
    bank=st.from_regex(r"[A-Z]{4}", fullmatch=True),
    country=st.sampled_from(sorted(_ISO_3166_ALPHA2)),
    location=st.from_regex(r"[A-Z0-9]{2}", fullmatch=True),
    branch=st.one_of(st.just(""), st.from_regex(r"[A-Z0-9]{3}", fullmatch=True)),
)
def test_every_structurally_valid_labelled_bic_is_redacted(
    bank: str, country: str, location: str, branch: str
) -> None:
    bic = f"{bank}{country}{location}{branch}"
    assert sanitizer.sanitize(f"SWIFT: {bic}") == f"SWIFT: {REDACTED}"
    assert sanitizer.sanitize_dict({"bic": bic}) == {"bic": REDACTED}


def test_repeated_swift_labels_do_not_backtrack_quadratically() -> None:
    """Issue #405: 'swift ' * n without a trailing BIC must scan in linear time."""
    import time

    payload = "swift " * 5000
    t0 = time.perf_counter()
    result = sanitizer.sanitize(payload)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    assert result == payload
    assert elapsed_ms < 250.0, f"_BIC_LABELLED took {elapsed_ms:.1f} ms on 30 KB input"

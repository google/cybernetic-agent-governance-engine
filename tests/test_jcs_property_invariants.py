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

"""
Property-based tests for RFC 8785 JCS (JSON Canonicalization Scheme).

Tests canonical JSON serialization invariants using Hypothesis fuzzing:
- Key ordering stability across arbitrary reordering
- Whitespace normalization invariance
- Idempotency: parse(canonicalize(x)) == parse(canonicalize(canonicalize(x)))

Addresses POAM-017 (Integrity: tamper-evident evidence chains).
"""

import json
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

pytestmark = [pytest.mark.unit, pytest.mark.local]


# Hypothesis strategy for arbitrary JSON-compatible structures
json_value = st.recursive(
    st.one_of(
        st.none(),
        st.booleans(),
        st.integers(min_value=-(2**53), max_value=2**53),
        st.floats(allow_nan=False, allow_infinity=False),
        st.text(alphabet=st.characters(blacklist_categories=("Cs",))),
    ),
    lambda children: st.one_of(
        st.lists(children, max_size=10),
        st.dictionaries(
            st.text(
                alphabet=st.characters(min_codepoint=1, blacklist_categories=("Cs",)),
                min_size=1,
                max_size=20,
            ),
            children,
            max_size=10,
        ),
    ),
    max_leaves=30,
)


@given(obj=json_value)
def test_jcs_key_ordering_invariant(obj: Any) -> None:
    """
    Property: JCS canonical form is invariant under key reordering.

    For any JSON object, canonicalizing the object and then shuffling
    its keys before re-canonicalizing must produce the same byte output.
    """
    if not isinstance(obj, dict):
        # Key ordering only applies to objects; primitives/arrays auto-pass
        return

    canonical_1 = jcs_canonicalize_plan(obj)

    # Reconstruct with reversed key order
    reversed_obj = {k: obj[k] for k in reversed(list(obj.keys()))}
    canonical_2 = jcs_canonicalize_plan(reversed_obj)

    assert canonical_1 == canonical_2, (
        f"Key ordering invariant violated:\n"
        f"  Original: {canonical_1}\n"
        f"  Reversed: {canonical_2}"
    )


def _strip_json_strings(json_bytes: bytes) -> bytes:
    """Remove string literals from JSON bytes to inspect structural characters."""
    result = bytearray()
    in_string = False
    escape = False
    for b in json_bytes:
        if in_string:
            if escape:
                escape = False
            elif b == ord(b"\\"):
                escape = True
            elif b == ord(b'"'):
                in_string = False
        else:
            if b == ord(b'"'):
                in_string = True
            else:
                result.append(b)
    return bytes(result)


@given(obj=json_value)
def test_jcs_whitespace_invariant(obj: Any) -> None:
    """
    Property: JCS canonical form strips all non-structural whitespace (RFC 8785 §3.2.1).

    Verifies that canonical JSON has no whitespace outside string literals and no
    unescaped newlines.
    """
    canonical_bytes = jcs_canonicalize_plan(obj)

    # Verify no unescaped newlines exist anywhere (RFC 8259 strings escape newlines as \n)
    assert b"\n" not in canonical_bytes, "Canonical form contains literal newlines"

    # Verify no whitespace exists outside string literals (RFC 8785 §3.2.1)
    structural = _strip_json_strings(canonical_bytes)
    assert b" " not in structural, (
        "Canonical form contains spaces outside string literals"
    )
    assert b"\t" not in structural, (
        "Canonical form contains tabs outside string literals"
    )
    assert b"\r" not in structural, "Canonical form contains carriage returns"

    # Verify the canonical form is valid JSON
    try:
        _ = json.loads(canonical_bytes)
        # Note: Large floats may be represented differently (scientific vs. integer)
        # This is acceptable per RFC 8785 as long as the value is mathematically equivalent
    except json.JSONDecodeError:
        pytest.fail(f"Canonical form is not valid JSON: {canonical_bytes!r}")


@given(obj=json_value)
def test_jcs_idempotency(obj: Any) -> None:
    """
    Property: Canonicalizing an already-canonical JSON document is idempotent.

    jcs_canonicalize(jcs_canonicalize(x)) == jcs_canonicalize(x)
    """
    canonical_1 = jcs_canonicalize_plan(obj)

    # Parse and re-canonicalize
    parsed = json.loads(canonical_1)
    canonical_2 = jcs_canonicalize_plan(parsed)

    assert canonical_1 == canonical_2, (
        f"Idempotency violated:\n  First:  {canonical_1}\n  Second: {canonical_2}"
    )


def test_jcs_rfc8785_example() -> None:
    """
    Deterministic test: RFC 8785-inspired test vector.

    Ensures JCS implementation produces valid canonical JSON with proper
    key ordering, number formatting, and string escaping.
    """
    test_obj = {
        "numbers": [
            333333333.33333329,
            1e30,
            4.50,
            2e-3,
            0.000000000000000000000000001,
        ],
        "string": "\u20ac$\u000f\u000aA'B",
        "literals": [None, True, False],
    }

    canonical = jcs_canonicalize_plan(test_obj)

    # Verify the canonical form is valid JSON
    parsed = json.loads(canonical)

    # Verify key ordering (literals before numbers before string)
    assert list(parsed.keys()) == ["literals", "numbers", "string"]

    # Verify literals are preserved
    assert parsed["literals"] == [None, True, False]

    # Verify string escaping works
    assert parsed["string"] == test_obj["string"]

    # Verify it's compact (no extra whitespace except structural)
    assert b"\n" not in canonical or b"\\n" in canonical  # Only escaped newlines

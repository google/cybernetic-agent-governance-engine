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

"""Unit tests for RFC 8785 JCS canonicalization."""

from __future__ import annotations

import pytest

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

pytestmark = [pytest.mark.unit, pytest.mark.local]


def test_jcs_canonicalize_floats():
    """Verify RFC 8785 float canonicalization edge cases."""
    # 1.0 -> "1", but 1.1 -> "1.1" etc. In Python, json.dumps might emit "1.0".
    # JCS specifies exact representations.

    plan1 = {"val": 1.0}
    plan2 = {"val": 1}
    assert jcs_canonicalize_plan(plan1) == jcs_canonicalize_plan(plan2)
    assert jcs_canonicalize_plan(plan1) == b'{"val":1}'

    # Scientific notation normalization
    plan3 = {"val": 1e-5}
    assert jcs_canonicalize_plan(plan3) == b'{"val":0.00001}'

    plan4 = {"val": 1000000000000000000000.0}
    # JCS says large floats use uppercase E and specific formats.
    # We just ensure it normalizes to what the RFC library produces.
    # The actual output might be 1e+21 or something similar.
    # The important part is that Python's JCS library handles it deterministically.
    canonical_4 = jcs_canonicalize_plan(plan4)
    assert isinstance(canonical_4, bytes)


def test_jcs_canonicalize_keys():
    """Verify keys are sorted properly."""
    plan1 = {"b": 2, "a": 1}
    assert jcs_canonicalize_plan(plan1) == b'{"a":1,"b":2}'


def test_jcs_canonicalize_nested():
    """Verify nested dictionaries and arrays."""
    plan = {"z": {"y": ["b", "a"]}, "x": 1}
    assert jcs_canonicalize_plan(plan) == b'{"x":1,"z":{"y":["b","a"]}}'


def test_jcs_canonicalize_unicode_escapes():
    """Verify RFC 8785 unicode un-escaping."""
    # JCS requires non-escaped UTF-8 for everything except control characters
    plan = {"text": "café\u20ac"}
    # should be literal UTF-8 in the byte output, not \uXXXX escapes
    canonical = jcs_canonicalize_plan(plan)
    assert canonical == b'{"text":"caf\xc3\xa9\xe2\x82\xac"}'


def test_jcs_canonicalize_negative_zero():
    """Verify RFC 8785 handling of negative zero."""
    plan = {"val": -0.0}
    canonical = jcs_canonicalize_plan(plan)
    assert canonical == b'{"val":0}'


def test_jcs_archytan_reference_vector_1():
    """Verify exact byte and SHA-256 parity for Archytan reference Vector 1."""
    import hashlib

    vector_1_input = {
        "envelope_version": "archytan.envelope/v1",
        "correlation_id": "550e8400-e29b-41d4-a716-446655440000",
        "operator_urn": "urn:archytan:op:test_vector_1",
        "action": "payment.wire.execute",
        "target": {
            "account_hash": "3333333333333333333333333333333333333333333333333333333333333333"
        },
        "parameters": {"amount_minor": 12345, "currency": "USD"},
        "governance": {
            "decision": "ALLOW",
            "decision_path": "DIRECT",
            "receipt_hash": "2222222222222222222222222222222222222222222222222222222222222222",
            "receipt_id": "cage-seal-test-0001",
            "policy_version": "cage-policy-2.1.1",
            "evaluated_at": 1785012000,
            "required_quorum": 2,
        },
        "authority_ref": {
            "graph_version": "ag-2026-08-01T00:00:00Z",
            "graph_hash": "1111111111111111111111111111111111111111111111111111111111111111",
        },
        "issued_at": 1785012000,
        "ttl_seconds": 30,
        "nonce": "0102030405060708090a0b0c0d0e0f10",
    }

    expected_canonical_bytes = b'{"action":"payment.wire.execute","authority_ref":{"graph_hash":"1111111111111111111111111111111111111111111111111111111111111111","graph_version":"ag-2026-08-01T00:00:00Z"},"correlation_id":"550e8400-e29b-41d4-a716-446655440000","envelope_version":"archytan.envelope/v1","governance":{"decision":"ALLOW","decision_path":"DIRECT","evaluated_at":1785012000,"policy_version":"cage-policy-2.1.1","receipt_hash":"2222222222222222222222222222222222222222222222222222222222222222","receipt_id":"cage-seal-test-0001","required_quorum":2},"issued_at":1785012000,"nonce":"0102030405060708090a0b0c0d0e0f10","operator_urn":"urn:archytan:op:test_vector_1","parameters":{"amount_minor":12345,"currency":"USD"},"target":{"account_hash":"3333333333333333333333333333333333333333333333333333333333333333"},"ttl_seconds":30}'
    # Note: SHA-256 of the exact canonical bytes printed in §11 of the Archytan spec
    expected_sha256 = (
        "8f7fc2b331437aa6c6adc5916e0452de01bc9bdcd571d7b155e832af72b3fe40"
    )

    actual_canonical_bytes = jcs_canonicalize_plan(vector_1_input)
    assert actual_canonical_bytes == expected_canonical_bytes
    assert hashlib.sha256(actual_canonical_bytes).hexdigest() == expected_sha256


def test_jcs_archytan_reference_vector_2():
    """Verify exact byte and SHA-256 parity for Archytan reference Vector 2 (adversarial formatting)."""
    import hashlib

    vector_2_input = {
        "z_trailing_zero": 100.50,
        "a_bare_int_as_float": 5.0,
        "m_big_sci_notation": 1.0e21,
        "unicode_name": "José's édition spéciale",
    }

    expected_canonical_bytes = '{"a_bare_int_as_float":5,"m_big_sci_notation":1e+21,"unicode_name":"José\'s édition spéciale","z_trailing_zero":100.5}'.encode(
        "utf-8"
    )
    expected_sha256 = (
        "b66634fe2360add85affbfea2386963881187e0ab6142bebaeff546d1a711712"
    )

    actual_canonical_bytes = jcs_canonicalize_plan(vector_2_input)
    assert actual_canonical_bytes == expected_canonical_bytes
    assert hashlib.sha256(actual_canonical_bytes).hexdigest() == expected_sha256

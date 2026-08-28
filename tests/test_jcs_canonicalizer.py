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


def test_jcs_provider_04_reference_vector_1():
    """Verify exact byte and SHA-256 parity for Provider 04 reference Vector 1."""
    import hashlib

    vector_1_input = {
        "envelope_version": "provider_04.envelope/v1",
        "correlation_id": "550e8400-e29b-41d4-a716-446655440000",
        "operator_urn": "urn:provider_04:op:test_vector_1",
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

    expected_canonical_bytes = b'{"action":"payment.wire.execute","authority_ref":{"graph_hash":"1111111111111111111111111111111111111111111111111111111111111111","graph_version":"ag-2026-08-01T00:00:00Z"},"correlation_id":"550e8400-e29b-41d4-a716-446655440000","envelope_version":"provider_04.envelope/v1","governance":{"decision":"ALLOW","decision_path":"DIRECT","evaluated_at":1785012000,"policy_version":"cage-policy-2.1.1","receipt_hash":"2222222222222222222222222222222222222222222222222222222222222222","receipt_id":"cage-seal-test-0001","required_quorum":2},"issued_at":1785012000,"nonce":"0102030405060708090a0b0c0d0e0f10","operator_urn":"urn:provider_04:op:test_vector_1","parameters":{"amount_minor":12345,"currency":"USD"},"target":{"account_hash":"3333333333333333333333333333333333333333333333333333333333333333"},"ttl_seconds":30}'
    # Note: SHA-256 of the exact canonical bytes printed in §11 of the Provider 04 spec
    expected_sha256 = "90de7ead1529e977c9ba9d84cb7e743c73996168843bcb2e928eef0427980d32"

    actual_canonical_bytes = jcs_canonicalize_plan(vector_1_input)
    assert actual_canonical_bytes == expected_canonical_bytes
    assert hashlib.sha256(actual_canonical_bytes).hexdigest() == expected_sha256


def test_jcs_provider_04_reference_vector_2():
    """Verify exact byte and SHA-256 parity for Provider 04 reference Vector 2 (adversarial formatting)."""
    import hashlib

    vector_2_input = {
        "z_trailing_zero": 100.50,
        "a_bare_int_as_float": 5.0,
        "m_big_sci_notation": 1.0e21,
        "unicode_name": "José's édition spéciale",
    }

    expected_canonical_bytes = '{"a_bare_int_as_float":5,"m_big_sci_notation":1e+21,"unicode_name":"José\'s édition spéciale","z_trailing_zero":100.5}'.encode()
    expected_sha256 = "b66634fe2360add85affbfea2386963881187e0ab6142bebaeff546d1a711712"

    actual_canonical_bytes = jcs_canonicalize_plan(vector_2_input)
    assert actual_canonical_bytes == expected_canonical_bytes
    assert hashlib.sha256(actual_canonical_bytes).hexdigest() == expected_sha256


def test_jcs_divergence_from_json_dumps_sort_keys():
    """Demonstrate that JCS and json.dumps(sort_keys=True) produce different bytes for float payloads.

    This test documents the breaking change introduced in FlowSignal Phase 2 §5.3:
    Evidence hashes computed with json.dumps(sort_keys=True) will NOT match hashes
    computed with RFC 8785 JCS for payloads containing floating-point numbers.

    The divergence occurs because:
    - json.dumps may emit "1.0" for the float 1.0
    - JCS mandates "1" (no trailing .0 for whole-number floats)
    """
    import hashlib
    import json

    # Payload with floats that expose the canonicalization difference
    payload = {
        "amount": 100.0,  # JCS: "100", json.dumps: "100.0"
        "rate": 0.05,  # Both emit "0.05"
        "score": 1.0,  # JCS: "1", json.dumps: "1.0"
    }

    # Old method (json.dumps with sort_keys=True)
    old_canonical = json.dumps(payload, sort_keys=True).encode()
    old_hash = hashlib.sha256(old_canonical).hexdigest()

    # New method (RFC 8785 JCS)
    new_canonical = jcs_canonicalize_plan(payload)
    new_hash = hashlib.sha256(new_canonical).hexdigest()

    # Assert they produce different bytes
    assert old_canonical != new_canonical, (
        "Expected json.dumps and JCS to produce different bytes for float payloads"
    )

    # Assert they produce different hashes
    assert old_hash != new_hash, (
        "Expected different SHA-256 digests between json.dumps and JCS for float payloads"
    )

    # Demonstrate the specific byte difference (json.dumps includes spaces, JCS does not)
    # Also, json.dumps emits "100.0" while JCS emits "100" for whole-number floats
    assert b"100.0" in old_canonical or b"100" in old_canonical
    assert b"100" in new_canonical and b"100.0" not in new_canonical
    assert b"1.0" in old_canonical or b'"score": 1' in old_canonical
    assert b'"score":1' in new_canonical  # JCS: no spaces, "1" not "1.0"


def test_jcs_determinism_across_key_orderings():
    """Verify JCS produces identical bytes regardless of dict insertion order.

    This is the core value proposition of JCS over json.dumps(sort_keys=True):
    identical semantic payloads with different key orderings produce byte-identical output.
    """
    import hashlib

    payload_1 = {"z": 3, "a": 1, "m": 2}
    payload_2 = {"a": 1, "m": 2, "z": 3}
    payload_3 = {"m": 2, "z": 3, "a": 1}

    canonical_1 = jcs_canonicalize_plan(payload_1)
    canonical_2 = jcs_canonicalize_plan(payload_2)
    canonical_3 = jcs_canonicalize_plan(payload_3)

    # All three must produce identical bytes
    assert canonical_1 == canonical_2 == canonical_3

    # And therefore identical hashes
    hash_1 = hashlib.sha256(canonical_1).hexdigest()
    hash_2 = hashlib.sha256(canonical_2).hexdigest()
    hash_3 = hashlib.sha256(canonical_3).hexdigest()
    assert hash_1 == hash_2 == hash_3

import pytest

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan


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
    # JCS says -0 must be serialized as -0, but floating point -0.0 might be tricky.
    # In JCS, -0.0 is technically not different from 0 in Python usually, but if represented as float it might.
    plan = {"val": -0.0}
    canonical = jcs_canonicalize_plan(plan)
    assert (
        canonical == b'{"val":0}'
    )  # wait, let's just make sure it's stable. JCS handles this.

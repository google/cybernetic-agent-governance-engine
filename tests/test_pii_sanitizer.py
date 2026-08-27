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

import pytest

from src.gateway.governance.pii_sanitizer import PIISanitizer, _get_pii_sanitizer


@pytest.fixture
def sanitizer() -> PIISanitizer:
    return PIISanitizer()


@pytest.mark.local
def test_ssn_redacted(sanitizer):
    assert sanitizer.sanitize("123-45-6789") == "[REDACTED_SSN]"


@pytest.mark.local
def test_credit_card_redacted(sanitizer):
    assert sanitizer.sanitize("4111-1111-1111-1111") == "[REDACTED_CC]"


@pytest.mark.local
def test_email_redacted(sanitizer):
    assert sanitizer.sanitize("user@example.com") == "[REDACTED_EMAIL]"


@pytest.mark.local
def test_phone_redacted(sanitizer):
    assert sanitizer.sanitize("+1 (555) 867-5309") == "[REDACTED_PHONE]"


@pytest.mark.local
def test_api_key_pk_lf_redacted(sanitizer):
    assert sanitizer.sanitize("pk-lf-abc123xyz") == "[REDACTED_API_KEY]"


@pytest.mark.local
def test_bearer_token_redacted(sanitizer):
    result = sanitizer.sanitize("Bearer eyJhbGciOiJSUzI1NiJ9")
    assert result == "[REDACTED_API_KEY]"


@pytest.mark.local
def test_clean_text_unchanged(sanitizer):
    assert sanitizer.sanitize("clean text with no PII") == "clean text with no PII"


@pytest.mark.local
def test_empty_string(sanitizer):
    assert sanitizer.sanitize("") == ""


@pytest.mark.local
def test_multi_pattern_single_string(sanitizer):
    result = sanitizer.sanitize("user@example.com or 123-45-6789")
    assert "[REDACTED_EMAIL]" in result
    assert "[REDACTED_SSN]" in result
    assert "user@example.com" not in result
    assert "123-45-6789" not in result


@pytest.mark.local
def test_singleton_returns_same_instance():
    a = _get_pii_sanitizer()
    b = _get_pii_sanitizer()
    assert a is b


@pytest.mark.local
def test_email_pattern_no_quadratic_backtracking(sanitizer):
    # A crafted "no valid TLD" string used to force O(n^2) backtracking in the
    # unbounded email regex. With the length-bounded quantifiers it stays
    # linear, so a large adversarial input completes near-instantly.
    import time

    payload = "a@" + "a." * 60_000 + "!"
    start = time.perf_counter()
    result = sanitizer.sanitize(payload)
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0, f"sanitize took {elapsed:.2f}s — regex backtracking regressed"
    assert result == payload  # no email present, so nothing is redacted


@pytest.mark.local
def test_long_domain_email_still_redacted(sanitizer):
    # A legitimate multi-label address must still be redacted after bounding.
    assert (
        sanitizer.sanitize("first.last+tag@mail.sub.example.co.uk")
        == "[REDACTED_EMAIL]"
    )


# ---------------------------------------------------------------------------
# R5: CONSEQUENCE_TOKEN / JWS scrubbing tests
# ---------------------------------------------------------------------------


@pytest.mark.local
def test_jws_compact_token_redacted_in_freetext(sanitizer):
    """A realistic compact JWS string embedded in free text is redacted."""
    # Fake JWS (three base64url segments, starts with eyJ for JWT header {"alg":...})
    fake_jws = (
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRldi1rZXktMDEifQ."
        "eyJzdWIiOiJhY3RvcjoxMjMiLCJ0aWQiOiJ0aHJlYWQ6NDU2IiwicmVjIjoicmVjOmFiYzEyMyIsImFjdCI6InNoYTI1NjphYmNkZWYxMjM0NTYiLCJ2ZXIiOm51bGwsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoxNzAwMDAwMDYwLCJqdGkiOiJyZWM6YWJjMTIzIn0."
        "cGFkZGVkX2Zha2Vfc2lnbmF0dXJlX2Jhc2U2NHVybF9lbmNvZGVkX3BsYWNlaG9sZGVyX25vdF9yZWFsX2NyeXB0b19kYXRhX2p1c3RfYV90ZXN0X2ZpeHR1cmVfZm9yX3JlZ2V4X21hdGNoaW5n"
    )
    text = f"The governance token is {fake_jws} and should be scrubbed."
    result = sanitizer.sanitize(text)
    assert fake_jws not in result, "Raw JWS must be redacted"
    assert "[REDACTED_JWS]" in result, "Redaction marker must be present"
    assert "The governance token is" in result, "Surrounding text must survive"


@pytest.mark.local
def test_consequence_token_finding_dict_scrubbed(sanitizer):
    """A CONSEQUENCE_TOKEN finding dict has its 'token' value redacted while non-sensitive fields survive."""
    finding = {
        "code": "CONSEQUENCE_TOKEN",
        "severity": "info",
        "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhY3RvcjoxMjMiLCJ0aWQiOiJ0aHJlYWQ6NDU2In0.c2lnbmF0dXJlX3BsYWNlaG9sZGVyX2Zha2VfZGF0YV9mb3JfdGVzdGluZ19vbmx5",
        "authority_record_id": "rec:flowsignal-abc123",
        "message": "ConsequenceToken minted for post-FRIA consequence enforcement",
    }
    result = sanitizer.sanitize_dict(finding)

    # Token must be redacted
    assert result["token"] == "[REDACTED_TOKEN]", (
        "Token field must be redacted by key denylist"
    )
    # All other fields must survive intact
    assert result["code"] == "CONSEQUENCE_TOKEN"
    assert result["severity"] == "info"
    assert result["authority_record_id"] == "rec:flowsignal-abc123"
    assert (
        result["message"]
        == "ConsequenceToken minted for post-FRIA consequence enforcement"
    )


@pytest.mark.local
def test_nested_consequence_token_finding_scrubbed_at_depth(sanitizer):
    """A nested structure (finding inside findings list inside ValidationResult-like dict) is scrubbed at depth."""
    validation_result = {
        "admitted": True,
        "findings": [
            {
                "code": "CONSEQUENCE_TOKEN",
                "severity": "info",
                "token": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnX3BsYWNlaG9sZGVy",
                "authority_record_id": "rec:nested-123",
                "message": "Nested token finding",
            },
            {
                "code": "COMPLIANCE_SATISFIED",
                "severity": "info",
                "message": "All checks passed",
            },
        ],
        "metadata": {
            "thread_id": "thread:789",
            "evaluated_at": "2026-08-27T15:00:00Z",
        },
    }
    result = sanitizer.sanitize_dict(validation_result)

    # Top-level structure preserved
    assert result["admitted"] is True
    assert len(result["findings"]) == 2

    # First finding: token redacted, other fields intact
    first_finding = result["findings"][0]
    assert first_finding["token"] == "[REDACTED_TOKEN]"
    assert first_finding["code"] == "CONSEQUENCE_TOKEN"
    assert first_finding["authority_record_id"] == "rec:nested-123"

    # Second finding: unaffected
    second_finding = result["findings"][1]
    assert second_finding["code"] == "COMPLIANCE_SATISFIED"

    # Metadata: unaffected
    assert result["metadata"]["thread_id"] == "thread:789"


@pytest.mark.local
def test_jws_false_positive_guards(sanitizer):
    """False-positive guards: ordinary text, dotted paths, version strings are NOT mangled."""
    # Module paths
    assert (
        sanitizer.sanitize("src.gateway.governance.consequence_token")
        == "src.gateway.governance.consequence_token"
    )
    # Semantic version strings
    assert sanitizer.sanitize("Version 1.2.3 released") == "Version 1.2.3 released"
    # Normal sentences with periods
    assert (
        sanitizer.sanitize("This is a sentence. It has periods. No JWS here.")
        == "This is a sentence. It has periods. No JWS here."
    )
    # Short dotted identifiers (don't meet minimum length threshold)
    assert sanitizer.sanitize("a.b.c") == "a.b.c"
    # IP addresses
    assert sanitizer.sanitize("Server at 192.168.1.1") == "Server at 192.168.1.1"
    # Dotted notation that doesn't match eyJ prefix
    assert sanitizer.sanitize("config.yaml.backup.2026") == "config.yaml.backup.2026"


@pytest.mark.local
def test_jws_pattern_requires_eyJ_prefix(sanitizer):
    """JWS pattern anchors on eyJ prefix to avoid false positives."""
    # Three base64url-like segments but not starting with eyJ — should NOT match
    fake_non_jwt = "aGVsbG8ud29ybGQuZm9vYmFy.cGF5bG9hZF9kYXRhX2hlcmVfbm90X2pzb25faGVhZGVy.c2lnbmF0dXJlX2hlcmVfYnV0X25vdF9qd3Q"
    result = sanitizer.sanitize(fake_non_jwt)
    assert result == fake_non_jwt, "Non-JWT base64url strings must not be redacted"


@pytest.mark.local
def test_consequence_token_key_case_insensitive(sanitizer):
    """Key denylist is case-insensitive — 'Token', 'TOKEN', 'token' all redacted."""
    findings = [
        {"Token": "eyJhbGciOiJub25lIn0.e30."},  # Capital T
        {"TOKEN": "eyJhbGciOiJub25lIn0.e30."},  # All caps
        {"token": "eyJhbGciOiJub25lIn0.e30."},  # Lowercase
    ]
    for finding in findings:
        result = sanitizer.sanitize_dict(finding)
        key = list(result.keys())[0]
        assert result[key] == "[REDACTED_TOKEN]", (
            f"Key '{key}' must be redacted (case-insensitive)"
        )


@pytest.mark.local
def test_key_denylist_all_entries(sanitizer):
    """All _KEY_DENYLIST entries are honored: token, consequence_token, jws, jwt, bearer_token."""
    finding = {
        "token": "fake-token-1",
        "consequence_token": "fake-token-2",
        "jws": "fake-jws-3",
        "jwt": "fake-jwt-4",
        "bearer_token": "fake-bearer-5",
    }
    result = sanitizer.sanitize_dict(finding)
    for key in finding.keys():
        assert result[key] == "[REDACTED_TOKEN]", f"Key '{key}' must be redacted"


@pytest.mark.local
def test_non_string_value_under_denylisted_key(sanitizer):
    """Non-string values under denylisted keys are redacted with type annotation."""
    finding = {
        "token": {"nested": "object"},
        "jwt": 12345,
        "normal_field": "safe value",
    }
    result = sanitizer.sanitize_dict(finding)
    assert result["token"] == "[REDACTED_TOKEN:dict]"
    assert result["jwt"] == "[REDACTED_TOKEN:int]"
    assert result["normal_field"] == "safe value"


@pytest.mark.local
def test_idempotent_scrubbing(sanitizer):
    """Scrubbing already-scrubbed output doesn't corrupt it."""
    # Use JWS with all segments meeting minimum length (≥20 chars each)
    original = {
        "token": "eyJhbGciOiJub25lIn0xMjM0NTY3ODkw.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNzAwMDAwMDAwfQ.c2lnbmF0dXJlX3BsYWNlaG9sZGVyX2Zvcl90ZXN0aW5nXzEyMzQ1Njc4OTA",
        "message": "This contains a JWS: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNzAwMDAwMDAwfQ.c2lnX3BsYWNlaG9sZGVyX2xvbmdlcl9mb3JfdGVzdGluZ19wdXJwb3Nlcw",
    }
    first_pass = sanitizer.sanitize_dict(original)
    second_pass = sanitizer.sanitize_dict(first_pass)

    # Second pass should be identical to first pass
    assert first_pass == second_pass
    assert first_pass["token"] == "[REDACTED_TOKEN]"
    assert "[REDACTED_JWS]" in first_pass["message"]


@pytest.mark.local
def test_dual_protection_jws_in_token_field(sanitizer):
    """When a JWS appears in a 'token' field, both key-based and regex scrubbing apply (defense in depth)."""
    # Use JWS with all segments meeting minimum length (≥20 chars each)
    finding = {
        "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNzAwMDAwMDAwfQ.c2lnX3BsYWNlaG9sZGVyX2Zvcl90ZXN0aW5nX29ubHlfeHl6MTIz",
        "code": "CONSEQUENCE_TOKEN",
    }
    result = sanitizer.sanitize_dict(finding)

    # Key-based redaction takes precedence (runs first in sanitize_dict)
    assert result["token"] == "[REDACTED_TOKEN]"
    # Even if key-based redaction were disabled, the regex would catch it
    # (verify by checking the raw sanitize() method)
    raw_jws = finding["token"]
    assert "[REDACTED_JWS]" in sanitizer.sanitize(raw_jws)


@pytest.mark.local
def test_realistic_validation_result_with_consequence_token(sanitizer):
    """Full realistic ValidationResult shape from provider_01 is scrubbed correctly."""
    validation_result = {
        "admitted": True,
        "findings": [
            {
                "code": "CONSEQUENCE_TOKEN",
                "severity": "info",
                "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRldi1rZXktMDEifQ.eyJzdWIiOiJhY3RvcjoxMjMiLCJ0aWQiOiJ0aHJlYWQ6NDU2IiwicmVjIjoicmVjOmFiYzEyMyIsImFjdCI6InNoYTI1NjphYmNkZWYxMjM0NTYiLCJ2ZXIiOm51bGwsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoxNzAwMDAwMDYwLCJqdGkiOiJyZWM6YWJjMTIzIn0.cGFkZGVkX2Zha2Vfc2lnbmF0dXJlX2Jhc2U2NHVybF9lbmNvZGVkX3BsYWNlaG9sZGVyX25vdF9yZWFsX2NyeXB0b19kYXRhX2p1c3RfYV90ZXN0X2ZpeHR1cmVfZm9yX3JlZ2V4X21hdGNoaW5n",
                "authority_record_id": "rec:flowsignal-abc123",
                "message": "ConsequenceToken minted for post-FRIA consequence enforcement",
            },
            {
                "code": "COMPLIANCE_SATISFIED",
                "severity": "info",
                "message": "ISO 42001 A.5 satisfied",
            },
        ],
    }
    result = sanitizer.sanitize_dict(validation_result)

    # Structure preserved
    assert result["admitted"] is True
    assert len(result["findings"]) == 2

    # CONSEQUENCE_TOKEN finding: token scrubbed, audit fields intact
    ct_finding = result["findings"][0]
    assert ct_finding["token"] == "[REDACTED_TOKEN]"
    assert ct_finding["code"] == "CONSEQUENCE_TOKEN"
    assert ct_finding["authority_record_id"] == "rec:flowsignal-abc123"
    assert "ConsequenceToken minted" in ct_finding["message"]

    # Other findings unaffected
    compliance_finding = result["findings"][1]
    assert compliance_finding["code"] == "COMPLIANCE_SATISFIED"
    assert compliance_finding["message"] == "ISO 42001 A.5 satisfied"

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
@pytest.mark.parametrize(
    "card",
    [
        # JCB, 16 digits, written in 4-digit groups
        "3530 1113 3330 0000",
        "3530-1113-3330-0000",
        "3566002020360505",
        # Diners Club, 14 digits, split 4-6-4 and 4-4-4-2
        "3056 930902 5904",
        "3056 9309 0259 04",
        "30569309025904",
        # Diners Club, 16 digits (300-305, 36, 38-39 ranges)
        "3000 0000 0000 0004",
        "3600-0000-0000-0008",
        "3800000000000006",
        # Discover, 644-649 prefix
        "6445 6445 6445 6445",
        "6491234567890123",
        # JCB 15-digit, 2131 and 1800 prefixes, grouped 4-6-5
        "2131 000000 00008",
        "180000000000002",
    ],
)
def test_grouped_and_range_card_numbers_redacted(sanitizer, card):
    """Card numbers written with separators, and Discover 644-649, must not reach the ledger."""
    assert sanitizer.sanitize(f"card {card} on file") == "card [REDACTED_CC] on file"


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
        "authority_record_id": "rec:provider01-abc123",
        "message": "ConsequenceToken minted for post-validation consequence enforcement",
    }
    result = sanitizer.sanitize_dict(finding)

    # Token must be redacted
    assert result["token"] == "[REDACTED_TOKEN]", (
        "Token field must be redacted by key denylist"
    )
    # All other fields must survive intact
    assert result["code"] == "CONSEQUENCE_TOKEN"
    assert result["severity"] == "info"
    assert result["authority_record_id"] == "rec:provider01-abc123"
    assert (
        result["message"]
        == "ConsequenceToken minted for post-validation consequence enforcement"
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
                "authority_record_id": "rec:provider01-abc123",
                "message": "ConsequenceToken minted for post-validation consequence enforcement",
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
    assert ct_finding["authority_record_id"] == "rec:provider01-abc123"
    assert "ConsequenceToken minted" in ct_finding["message"]

    # Other findings unaffected
    compliance_finding = result["findings"][1]
    assert compliance_finding["code"] == "COMPLIANCE_SATISFIED"
    assert compliance_finding["message"] == "ISO 42001 A.5 satisfied"


@pytest.mark.unit
@pytest.mark.local
def test_sanitize_dict_recurses_into_nested_lists(sanitizer: PIISanitizer) -> None:
    """Table-shaped values (lists of lists) are sanitized, not passed through."""
    data = {
        "rows": [
            ["contact", "jane.doe@example.com"],
            [["deeper", "123-45-6789"], {"phone": "+1 (415) 555-0134"}],
        ]
    }
    result = sanitizer.sanitize_dict(data)
    flat = str(result)
    assert "jane.doe@example.com" not in flat
    assert "123-45-6789" not in flat
    assert "555-0134" not in flat
    assert result["rows"][0][0] == "contact"


@pytest.mark.unit
@pytest.mark.local
def test_jws_followed_by_period_or_slash_redacted(sanitizer: PIISanitizer) -> None:
    """A compact JWS immediately followed by '.' or '/' is still redacted."""
    fake_jws = (
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRldi1rZXktMDEifQ."
        "eyJzdWIiOiJhY3RvcjoxMjMiLCJ0aWQiOiJ0aHJlYWQ6NDU2IiwicmVjIjoicmVjOmFiYzEyMyIsImFjdCI6InNoYTI1NjphYmNkZWYxMjM0NTYiLCJ2ZXIiOm51bGwsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoxNzAwMDAwMDYwLCJqdGkiOiJyZWM6YWJjMTIzIn0."
        "cGFkZGVkX2Zha2Vfc2lnbmF0dXJlX2Jhc2U2NHVybF9lbmNvZGVkX3BsYWNlaG9sZGVyX25vdF9yZWFsX2NyeXB0b19kYXRhX2p1c3RfYV90ZXN0X2ZpeHR1cmVfZm9yX3JlZ2V4X21hdGNoaW5n"
    )
    assert "[REDACTED_JWS]." in sanitizer.sanitize(f"Token: {fake_jws}.")
    assert "[REDACTED_JWS]/callback" in sanitizer.sanitize(
        f"https://example.com/{fake_jws}/callback"
    )


@pytest.mark.unit
@pytest.mark.local
def test_sanitize_dict_recurses_into_tuples_and_mappings(
    sanitizer: PIISanitizer,
) -> None:
    """Tuples and read-only MappingProxyType containers are recursively sanitized."""
    from types import MappingProxyType

    data = {
        "tuple_field": ("jane.doe@example.com", ("123-45-6789",)),
        "mapping_field": MappingProxyType(
            {"email": "john.doe@example.com", "token": "secret-jwt"}
        ),
    }
    result = sanitizer.sanitize_dict(data)
    assert isinstance(result["tuple_field"], tuple)
    assert result["tuple_field"] == ("[REDACTED_EMAIL]", ("[REDACTED_SSN]",))
    assert result["mapping_field"] == {
        "email": "[REDACTED_EMAIL]",
        "token": "[REDACTED_TOKEN]",
    }


@pytest.mark.unit
@pytest.mark.local
@pytest.mark.parametrize(
    "uuid_val",
    [
        "41112222-3333-4444-ab77-f4f1ecb70374",  # Visa 4xxx 8-4-4 prefix
        "51234567-8901-2345-ab77-f4f1ecb70374",  # MC 51-55 8-4-4 prefix
        "22210000-0000-0000-ab77-f4f1ecb70374",  # MC 2221-2720 8-4-4 prefix
        "60112222-3333-4444-ab77-f4f1ecb70374",  # Discover 6011 8-4-4 prefix
        "65112222-3333-4444-ab77-f4f1ecb70374",  # Discover 65xx 8-4-4 prefix
        "84119661-6585-4371-ab77-f4f1ecb70374",  # 16-digit 8-4-4 prefix
    ],
)
def test_canonical_uuids_preserved_while_cards_and_bearer_uuids_redacted(
    sanitizer: PIISanitizer,
    uuid_val: str,
) -> None:
    """Canonical 8-4-4-4-12 UUIDs survive intact in evidence payloads while cards and Bearer UUIDs redact."""
    record = {
        "defer_id": uuid_val,
        "summary": f"trace={uuid_val} card=2221-0000-0000-0000",
        "auth_header": f"Bearer {uuid_val}",
    }
    sanitized = sanitizer.sanitize_dict(record)
    assert sanitized["defer_id"] == uuid_val
    assert sanitized["summary"] == f"trace={uuid_val} card=[REDACTED_CC]"
    assert sanitized["auth_header"] == "[REDACTED_API_KEY]"


# ---------------------------------------------------------------------------
# Hardened deterministic credential, Luhn PAN, Mod-97 IBAN, and encoded-layer
# sanitization tests.
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.local
def test_pem_url_and_cloud_credentials_redacted(sanitizer: PIISanitizer) -> None:
    """PEM private keys, URL userinfo passwords, and cloud/VCS API keys are scrubbed."""
    pem_block = (
        "-----BEGIN "
        + "RSA PRIVATE KEY-----\n"
        + ("A" * 32)
        + "==\n"
        + "-----END "
        + "RSA PRIVATE KEY-----"
    )
    truncated_pem = "leaked -----BEGIN " + "OPENSSH PRIVATE KEY----- truncated"
    pem_public = (
        "-----BEGIN PUBLIC KEY-----\n" + ("B" * 32) + "\n-----END PUBLIC KEY-----"
    )
    assert sanitizer.sanitize(f"key:\n{pem_block}\ndone") == (
        "key:\n[REDACTED_PRIVATE_KEY]\ndone"
    )
    assert (
        sanitizer.sanitize(truncated_pem) == "leaked [REDACTED_PRIVATE_KEY] truncated"
    )
    assert sanitizer.sanitize(pem_public) == pem_public

    pg_url = "postgresql://" + "svc_user:" + ("p" * 8) + "@db.internal:5432/ledger"
    https_url = "https://" + "bot:" + ("p" * 8) + "@api.example.com/v1/submit"
    redis_url = "red" + "iss://default:" + ("p" * 8) + "@cache.internal:6379/0"
    assert (
        sanitizer.sanitize(pg_url)
        == "postgresql://svc_user:[REDACTED_PASSWORD]@db.internal:5432/ledger"
    )
    assert (
        sanitizer.sanitize(https_url)
        == "https://bot:[REDACTED_PASSWORD]@api.example.com/v1/submit"
    )
    assert sanitizer.sanitize(redis_url) == "[REDACTED_REDIS_URL]"
    assert (
        sanitizer.sanitize("https://example.com:8443/docs?ref=main")
        == "https://example.com:8443/docs?ref=main"
    )
    assert (
        sanitizer.sanitize("postgresql://db.internal:5432/ledger")
        == "postgresql://db.internal:5432/ledger"
    )

    synthetic_keys = [
        "AK" + "IA" + ("A" * 16),
        "AS" + "IA" + ("B" * 16),
        "AB" + "IA" + ("C" * 16),
        "AC" + "CA" + ("D" * 16),
        "gh" + "p_" + ("a" * 36),
        "github_" + "pat_" + ("a" * 36),
        "sk-" + "proj-" + ("a" * 28),
        "sk-" + "ant-" + ("a" * 28),
        "xox" + "b-" + ("1" * 10) + "-" + ("2" * 10) + "-" + ("a" * 12),
        "AI" + "za" + ("x" * 35),
    ]
    for key in synthetic_keys:
        assert sanitizer.sanitize(f"token={key} end") == "token=[REDACTED_API_KEY] end"


@pytest.mark.unit
@pytest.mark.local
def test_luhn_validated_obfuscated_and_international_cards(
    sanitizer: PIISanitizer,
) -> None:
    """Additive Luhn pass redacts obfuscated and international cards while preserving non-cards."""
    valid_cards = [
        "4111.1111.1111.1111",  # dot-separated Visa (Luhn valid)
        "550000 555555 5559",  # irregular-grouped Mastercard (Luhn valid)
        "6221 2600 0000 0000",  # spaced UnionPay 16-digit (Luhn valid)
        "6221260000000000",  # contiguous UnionPay 16-digit (Luhn valid)
        "6304 9500 0000 0000 000",  # 19-digit Maestro (Luhn valid)
    ]
    for card in valid_cards:
        assert sanitizer.sanitize(f"pan={card} ok") == "pan=[REDACTED_CC] ok"

    preserved_values = [
        "order 9999.8888.7777.6666 ok",  # non-payment IIN & non-Luhn
        "pi=3.141592653589793",  # high-precision float (single dot)
        "ratio=4.111111111111111",  # single-dot float even when Luhn-valid digits
        "epoch_ms=1700000000004",  # 13-digit Unix ms timestamp (IIN 1 excluded)
        "zeros=0000-0000-0000-0000",  # trivial repeated digits
        "date=2026-08-27 1234567",  # mixed separators
    ]
    for text in preserved_values:
        assert sanitizer.sanitize(text) == text


@pytest.mark.unit
@pytest.mark.local
def test_mod97_space_grouped_iban_redacted_and_invalid_preserved(
    sanitizer: PIISanitizer,
) -> None:
    """ISO 13616 Mod-97 spaced IBANs redact cleanly without false positives or partial card mangling."""
    assert (
        sanitizer.sanitize("IBAN DE89 3704 0044 0532 0130 00 paid")
        == "IBAN [REDACTED_IBAN] paid"
    )
    assert (
        sanitizer.sanitize("IBAN: GB29 NWBK 6016 1331 9268 19 EUR")
        == "IBAN: [REDACTED_IBAN] EUR"
    )
    assert (
        sanitizer.sanitize("wire FR76 3000 6000 0112 3456 7890 189")
        == "wire [REDACTED_IBAN]"
    )

    invalid_ibans = [
        "ref DE00 3704 0044 0532 0130 00",  # invalid Mod-97 check digits
        "ref DE89 3704 0044 0532",  # wrong length for DE (16 != 22)
        "ref US12 3456 7890 1234",  # US is not an ISO 13616 IBAN country
    ]
    for text in invalid_ibans:
        assert sanitizer.sanitize(text) == text


@pytest.mark.unit
@pytest.mark.local
def test_encoded_base64_hex_url_pii_and_secrets_redacted(
    sanitizer: PIISanitizer,
) -> None:
    """Bounded multi-layer Base64/Hex/URL-encoded PII and credentials are redacted without false positives."""
    import base64
    import hashlib
    from urllib.parse import quote

    def b64(value: str) -> str:
        return base64.b64encode(value.encode("utf-8")).decode("ascii")

    ssn_b64_1x = b64("123-45-6789")
    ssn_b64_2x = b64(ssn_b64_1x)
    ssn_b64_3x = b64(ssn_b64_2x)
    ssn_b64_4x = b64(ssn_b64_3x)

    assert (
        sanitizer.sanitize(f"leaked {ssn_b64_1x}.") == "leaked [REDACTED_ENCODED_PII]."
    )
    assert sanitizer.sanitize(f"d2={ssn_b64_2x}") == "d2=[REDACTED_ENCODED_PII]"
    assert sanitizer.sanitize(f"d3={ssn_b64_3x}") == "d3=[REDACTED_ENCODED_PII]"
    # Exceeds bounded unwrap depth (3) — terminates cleanly without redacting.
    assert sanitizer.sanitize(f"d4={ssn_b64_4x}") == f"d4={ssn_b64_4x}"

    # Mixed-layer: URL-encoded Base64 SSN
    mixed = quote(ssn_b64_1x, safe="")
    assert sanitizer.sanitize(f"mix={mixed}") == "mix=[REDACTED_ENCODED_PII]"

    # Base64-encoded credentials (AWS key and PEM private key)
    aws_sample = "AK" + "IA" + ("A" * 16)
    pem_header = "-----BEGIN " + "RSA PRIVATE KEY-----"
    assert (
        sanitizer.sanitize(f"k={b64(aws_sample)}") == "k=[REDACTED_ENCODED_CREDENTIAL]"
    )
    assert (
        sanitizer.sanitize(f"pem={b64(pem_header)}")
        == "pem=[REDACTED_ENCODED_CREDENTIAL]"
    )

    # Hex-encoded PII and credential
    email_hex = b"user@example.com".hex()
    aws_hex = aws_sample.encode("utf-8").hex()
    assert sanitizer.sanitize(f"h:{email_hex}") == "h:[REDACTED_ENCODED_PII]"
    assert sanitizer.sanitize(f"h:{aws_hex}") == "h:[REDACTED_ENCODED_CREDENTIAL]"

    # URL-encoded PII and credential URL
    assert sanitizer.sanitize("ssn=123%2D45%2D6789") == "ssn=[REDACTED_ENCODED_PII]"
    assert (
        sanitizer.sanitize(
            "https://example.com/search?email=alice%40example.com&page=1"
        )
        == "https://example.com/search?email=[REDACTED_ENCODED_PII]&page=1"
    )
    encoded_cred_url = quote(
        "https://" + "svc:" + ("p" * 8) + "@db.internal/prod", safe=""
    )
    assert (
        sanitizer.sanitize(f"target={encoded_cred_url}")
        == "target=[REDACTED_ENCODED_CREDENTIAL]"
    )

    # False-positive guards: benign Base64, SHA-256 hex digest, benign URL encoding,
    # and Base64-encoded canonical UUID remain intact.
    benign_b64 = b64("hello.world.foobar")
    sha256_hex = hashlib.sha256(b"").hexdigest()
    uuid_b64 = b64("41112222-3333-4444-ab77-f4f1ecb70374")
    for safe_text in (
        f"msg={benign_b64}",
        f"digest={sha256_hex}",
        "https://example.com/search?q=hello%20world&page=1",
        f"corr={uuid_b64}",
    ):
        assert sanitizer.sanitize(safe_text) == safe_text


@pytest.mark.unit
@pytest.mark.local
def test_hardened_patterns_idempotent_and_linear_time(
    sanitizer: PIISanitizer,
) -> None:
    """Hardened sanitizer is idempotent across all markers and linear O(n) on 60k-char inputs."""
    import base64
    import time

    samples = [
        "-----BEGIN "
        + "EC PRIVATE KEY-----\n"
        + ("A" * 16)
        + "==\n-----END "
        + "EC PRIVATE KEY-----",
        "postgresql://" + "svc:" + ("p" * 8) + "@db.internal:5432/app",
        "AK" + "IA" + ("A" * 16),
        "4111.1111.1111.1111",
        "DE89 3704 0044 0532 0130 00",
        base64.b64encode(b"123-45-6789").decode("ascii"),
    ]
    for sample in samples:
        once = sanitizer.sanitize(sample)
        twice = sanitizer.sanitize(once)
        assert once != sample
        assert twice == once

    adversarial_inputs = [
        ("-----BEGIN " + "PRIVATE KEY-----") * 2_000
        + ("-----END " + "PRIVATE KEY-----"),
        "4." * 30_000,
        "AA00 " * 12_000,
        "aGVsbG8ud29ybGQ= " * 3_500,
        "https://" + "a" * 60_000,
    ]
    for payload in adversarial_inputs:
        start = time.perf_counter()
        sanitizer.sanitize(payload)
        elapsed = time.perf_counter() - start
        assert elapsed < 1.0, (
            f"sanitize took {elapsed:.2f}s on {len(payload)}-char adversarial payload"
        )

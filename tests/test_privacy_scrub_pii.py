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

import time

import pytest

from src.gateway.infrastructure.privacy import scrub_pii


@pytest.mark.local
def test_email_redacted():
    assert "[REDACTED-EMAIL-UCA-3]" in scrub_pii("reach me at user@example.com")


@pytest.mark.local
def test_multi_label_email_redacted():
    assert "[REDACTED-EMAIL-UCA-3]" in scrub_pii(
        "first.last+tag@mail.sub.example.co.uk"
    )


@pytest.mark.local
def test_clean_text_unchanged():
    assert scrub_pii("no pii in this line") == "no pii in this line"


@pytest.mark.local
def test_email_pattern_no_quadratic_backtracking():
    # "a@a.a.a.…!" has no valid TLD and used to trigger O(n^2) backtracking in
    # the unbounded email regex. scrub_pii runs inline on unauthenticated
    # /v1/chat/completions message content, so this is a pre-auth stall vector.
    # With length-bounded quantifiers the scan is linear.
    payload = "a@" + "a." * 60_000 + "!"
    start = time.perf_counter()
    result = scrub_pii(payload)
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0, (
        f"scrub_pii took {elapsed:.2f}s — regex backtracking regressed"
    )
    assert result == payload  # no email present, nothing redacted


@pytest.mark.local
def test_canonical_uuid_with_16_digit_prefix_or_suffix_is_not_corrupted_as_credit_card():
    # Regression for 84119661-6585-4371-ab77-f4f1ecb70374: an 8-4-4 all-digit
    # UUID prefix has 16 decimal digits before '-ab77-...' and previously matched
    # PII_PATTERNS['CREDIT_CARD'] via the '-' word boundary, corrupting defer_id.
    payload = (
        '{"deferred_id": "84119661-6585-4371-ab77-f4f1ecb70374", '
        '"oscal_uuid": "00000000-0000-4000-8000-000000000001", '
        '"card": "4111-1111-1111-1111"}'
    )
    scrubbed = scrub_pii(payload)
    assert '"deferred_id": "84119661-6585-4371-ab77-f4f1ecb70374"' in scrubbed
    assert '"oscal_uuid": "00000000-0000-4000-8000-000000000001"' in scrubbed
    assert '"card": "[REDACTED-CREDIT_CARD-UCA-3]"' in scrubbed
    # Malformed hyphen-concatenated card+UUID must NOT bypass redaction:
    joined = scrub_pii("4111-1111-1111-1111-84119661-6585-4371-ab77-f4f1ecb70374")
    assert "[REDACTED-CREDIT_CARD-UCA-3]" in joined


@pytest.mark.unit
@pytest.mark.local
def test_privacy_shares_single_canonical_patterns_with_pii_sanitizer() -> None:
    """privacy.py and pii_sanitizer.py must share one set of compiled regex objects."""
    from src.gateway.governance import pii_sanitizer
    from src.gateway.infrastructure import privacy

    assert privacy._CANONICAL_UUID_RE is pii_sanitizer.CANONICAL_UUID_RE
    assert privacy._COMPILED_PII_PATTERNS["SSN"] is pii_sanitizer.SSN_PATTERN
    assert (
        privacy._COMPILED_PII_PATTERNS["CREDIT_CARD"]
        is pii_sanitizer.CREDIT_CARD_PATTERN
    )
    assert privacy._COMPILED_PII_PATTERNS["EMAIL"] is pii_sanitizer.EMAIL_PATTERN
    assert privacy._COMPILED_PII_PATTERNS["PHONE"] is pii_sanitizer.PHONE_PATTERN

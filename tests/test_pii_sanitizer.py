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

# tests/test_pii_sanitizer.py
# Unit tests for PIISanitizer redaction pipeline.
# Marker: @pytest.mark.local — CI-gated, no external dependencies.
# Run: uv run pytest tests/test_pii_sanitizer.py -m local -v

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

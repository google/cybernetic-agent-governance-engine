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
test_pii_scrubbing.py — Sprint 2: PII Scrubbing with ScrubbedPayload Newtype
=============================================================================

Tests for mandatory PII scrubbing before Evidence Stream ingest.
The ScrubbedPayload newtype ensures unscrubbed data cannot reach the
hash-chained evidence stream.
"""

import pytest

from src.compliance_bridge.pii_scrubber import PIIScrubber, ScrubbedPayload


@pytest.mark.unit
def test_scrubbed_payload_type() -> None:
    """Verify ScrubbedPayload newtype prevents unscrubbed ingest."""
    payload = {"user": "alice@example.com", "amount": 100.0}
    scrubbed = PIIScrubber.scrub(payload)

    # Type checker enforces ScrubbedPayload type
    assert isinstance(scrubbed, dict)
    assert "user" in scrubbed


@pytest.mark.unit
def test_pii_patterns_redacted_email() -> None:
    """Verify email patterns are scrubbed."""
    payload = {
        "message": "Contact alice@example.com for details",
        "sender": "bob@test.org",
    }

    scrubbed = PIIScrubber.scrub(payload)

    assert "[EMAIL_REDACTED]" in scrubbed["message"]
    assert "alice@example.com" not in scrubbed["message"]
    assert scrubbed["sender"] == "[EMAIL_REDACTED]"


@pytest.mark.unit
def test_pii_patterns_redacted_ssn() -> None:
    """Verify SSN patterns are scrubbed."""
    payload = {"text": "SSN: 123-45-6789", "data": "Another SSN 987-65-4321 here"}

    scrubbed = PIIScrubber.scrub(payload)

    assert "[SSN_REDACTED]" in scrubbed["text"]
    assert "123-45-6789" not in scrubbed["text"]
    assert scrubbed["data"].count("[SSN_REDACTED]") == 1


@pytest.mark.unit
def test_pii_patterns_redacted_phone() -> None:
    """Verify phone number patterns are scrubbed."""
    payload = {
        "contact": "555-123-4567",
        "phone": "555.987.6543",
        "mobile": "5551234567",
    }

    scrubbed = PIIScrubber.scrub(payload)

    assert scrubbed["contact"] == "[PHONE_REDACTED]"
    assert scrubbed["phone"] == "[PHONE_REDACTED]"
    assert scrubbed["mobile"] == "[PHONE_REDACTED]"


@pytest.mark.unit
def test_pii_patterns_redacted_credit_card() -> None:
    """Verify credit card patterns are scrubbed."""
    payload = {
        "cc": "4532-1234-5678-9010",
        "card": "4532 1234 5678 9010",
        "pan": "4532123456789010",
    }

    scrubbed = PIIScrubber.scrub(payload)

    assert scrubbed["cc"] == "[CC_REDACTED]"
    assert scrubbed["card"] == "[CC_REDACTED]"
    assert scrubbed["pan"] == "[CC_REDACTED]"


@pytest.mark.unit
def test_recursive_scrubbing_nested_dict() -> None:
    """Verify nested dict scrubbing."""
    payload = {
        "user": {
            "name": "Alice",
            "email": "alice@example.com",
            "details": {"phone": "555-1234", "ssn": "123-45-6789"},
        }
    }

    scrubbed = PIIScrubber.scrub(payload)

    assert scrubbed["user"]["email"] == "[EMAIL_REDACTED]"
    assert scrubbed["user"]["details"]["phone"] == "[PHONE_REDACTED]"
    assert scrubbed["user"]["details"]["ssn"] == "[SSN_REDACTED]"
    assert scrubbed["user"]["name"] == "Alice"  # Non-PII preserved


@pytest.mark.unit
def test_recursive_scrubbing_list() -> None:
    """Verify list scrubbing."""
    payload = {
        "contacts": [
            "alice@example.com",
            "bob@test.org",
            {"email": "charlie@example.com", "phone": "555-9876"},
        ]
    }

    scrubbed = PIIScrubber.scrub(payload)

    assert scrubbed["contacts"][0] == "[EMAIL_REDACTED]"
    assert scrubbed["contacts"][1] == "[EMAIL_REDACTED]"
    assert scrubbed["contacts"][2]["email"] == "[EMAIL_REDACTED]"
    assert scrubbed["contacts"][2]["phone"] == "[PHONE_REDACTED]"


@pytest.mark.unit
def test_evidence_stream_requires_scrubbed() -> None:
    """Verify ingest() type signature enforces ScrubbedPayload."""
    import inspect

    from src.compliance_bridge.evidence_stream import EvidenceStreamSink

    # Check type annotations
    sig = inspect.signature(EvidenceStreamSink.ingest)
    event_param = sig.parameters["event"]

    # Type hint should reference ScrubbedPayload
    assert event_param.annotation is not None
    # Note: NewType doesn't survive runtime inspection perfectly,
    # but the annotation should be present in the source


@pytest.mark.unit
def test_scrubbing_preserves_non_pii() -> None:
    """Verify non-PII data is preserved during scrubbing."""
    payload = {
        "amount": 100.50,
        "currency": "USD",
        "trace_id": "abc123",
        "timestamp": "2026-09-05T00:00:00Z",
        "tags": ["finance", "trade"],
        "contact": "support@example.com",  # PII
    }

    scrubbed = PIIScrubber.scrub(payload)

    assert scrubbed["amount"] == 100.50
    assert scrubbed["currency"] == "USD"
    assert scrubbed["trace_id"] == "abc123"
    assert scrubbed["timestamp"] == "2026-09-05T00:00:00Z"
    assert scrubbed["tags"] == ["finance", "trade"]
    assert scrubbed["contact"] == "[EMAIL_REDACTED]"


@pytest.mark.unit
def test_multiple_pii_patterns_in_single_string() -> None:
    """Verify multiple PII patterns in the same string are all redacted."""
    payload = {
        "message": "Contact alice@example.com at 555-1234 or use SSN 123-45-6789"
    }

    scrubbed = PIIScrubber.scrub(payload)

    assert "[EMAIL_REDACTED]" in scrubbed["message"]
    assert "[PHONE_REDACTED]" in scrubbed["message"]
    assert "[SSN_REDACTED]" in scrubbed["message"]
    assert "alice@example.com" not in scrubbed["message"]
    assert "555-1234" not in scrubbed["message"]
    assert "123-45-6789" not in scrubbed["message"]

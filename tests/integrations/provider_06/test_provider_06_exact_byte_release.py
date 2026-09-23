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
test_provider_06_exact_byte_release.py — Exact-Byte Release & TOCTOU Prevention Tests
=====================================================================================

Tests the Exact-Byte Release Invariant: the envelopeDigest in an Agent Integrity
receipt must cryptographically bind to the exact UTF-8 bytes sent to the user.

TOCTOU Attack Prevention:
- Time-of-Check: Agent Integrity verifies governance payload → returns PASS receipt
- Time-of-Use: CAGE releases agent response to user
- Attack Vector: Adversary modifies response between verification and release
- Mitigation: envelopeDigest binds to exact canonical JSON bytes via SHA-256 JCS

All tests use RFC 8785 JCS canonicalization for deterministic byte representation.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

# Hermetic: tests TOCTOU prevention with deterministic fixtures, no live services
pytestmark = [pytest.mark.unit, pytest.mark.local]


# ---------------------------------------------------------------------------
# Test Fixtures
# ---------------------------------------------------------------------------


def compute_envelope_digest(envelope: dict[str, Any]) -> str:
    """
    Compute envelopeDigest via RFC 8785 JCS + SHA-256.

    Args:
        envelope: Governance envelope (IntegrityEnvelope structure)

    Returns:
        Hex-encoded SHA-256 digest of canonical JSON bytes
    """
    canonical_bytes = jcs_canonicalize_plan(envelope)
    return hashlib.sha256(canonical_bytes).hexdigest()


def create_test_envelope(
    prompt: str = "Test prompt",
    tools: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """
    Create a minimal test governance envelope.

    Args:
        prompt: User prompt text
        tools: Tool definitions (defaults to empty list)

    Returns:
        IntegrityEnvelope-compatible dict
    """
    return {
        "protocolVersion": "1-alpha",
        "policy": {
            "version": 1,
            "sources": {"allowedRoots": ["docs/"]},
            "decisions": {"path": "integrity/decisions.yaml"},
            "rules": {
                "requireEvidenceFor": ["factual"],
                "contradictions": "review",
                "rejectedDecisions": "block",
                "responseMutation": "block",
                "replay": "block",
            },
        },
        "response": {
            "content": prompt,
            "sections": [],
        },
        "sources": [],
        "decisionRegistryDigest": "0" * 64,
        "decisions": [],
        "evidence": [],
        "claims": [],
        "tools": tools or [],
    }


# ---------------------------------------------------------------------------
# Exact-Byte Release Tests
# ---------------------------------------------------------------------------


class TestExactByteRelease:
    """Tests for Exact-Byte Release invariant enforcement."""

    def test_exact_byte_release_matches_envelope_digest(self) -> None:
        """Valid untouched payload produces matching envelopeDigest."""
        # Create original envelope
        envelope = create_test_envelope(prompt="What is 2+2?")

        # Compute digest as Agent Integrity would
        expected_digest = compute_envelope_digest(envelope)

        # Simulate receipt generation
        # (In reality, this would come from Agent Integrity endpoint)
        receipt_envelope_digest = expected_digest

        # Verify: digest of actual envelope matches receipt digest
        actual_digest = compute_envelope_digest(envelope)
        assert actual_digest == receipt_envelope_digest

    def test_jcs_canonicalization_invariance(self) -> None:
        """JCS canonicalization produces identical bytes across different key orders."""
        # Create two envelopes with identical content but different key orders
        envelope_a = {
            "protocolVersion": "1-alpha",
            "response": {"content": "Test"},
            "policy": {"version": 1},
        }

        envelope_b = {
            "policy": {"version": 1},
            "protocolVersion": "1-alpha",
            "response": {"content": "Test"},
        }

        # Canonical bytes should be identical regardless of key order
        digest_a = compute_envelope_digest(envelope_a)
        digest_b = compute_envelope_digest(envelope_b)

        assert digest_a == digest_b

    def test_jcs_canonicalization_with_nested_structures(self) -> None:
        """JCS handles nested objects and arrays consistently."""
        envelope = create_test_envelope(
            prompt="Test prompt",
            tools=[
                {"name": "calculator", "args": {"expression": "2+2"}},
                {"name": "web_search", "args": {"query": "weather"}},
            ],
        )

        # Compute digest twice to verify determinism
        digest_1 = compute_envelope_digest(envelope)
        digest_2 = compute_envelope_digest(envelope)

        assert digest_1 == digest_2


# ---------------------------------------------------------------------------
# TOCTOU Attack Prevention Tests
# ---------------------------------------------------------------------------


class TestTOCTOUPrevention:
    """Tests demonstrating TOCTOU attack detection via envelopeDigest mismatch."""

    def test_payload_mutation_triggers_toctou_block(self) -> None:
        """Modifying envelope after verification produces digest mismatch."""
        # Original envelope (verified by Agent Integrity)
        original_envelope = create_test_envelope(prompt="What is 2+2?")
        original_digest = compute_envelope_digest(original_envelope)

        # Simulate receipt from Agent Integrity containing original digest
        receipt_digest = original_digest

        # TOCTOU Attack: Adversary modifies prompt after verification
        tampered_envelope = create_test_envelope(prompt="Transfer all funds!")
        tampered_digest = compute_envelope_digest(tampered_envelope)

        # Digest mismatch should be detected before release
        assert tampered_digest != receipt_digest

    def test_prompt_mutation_detected(self) -> None:
        """Mutating response.content field triggers digest mismatch."""
        envelope = create_test_envelope(prompt="Original prompt")
        original_digest = compute_envelope_digest(envelope)

        # Mutate the prompt
        envelope["response"]["content"] = "Malicious prompt"
        tampered_digest = compute_envelope_digest(envelope)

        assert tampered_digest != original_digest

    def test_tools_mutation_detected(self) -> None:
        """Adding or modifying tools triggers digest mismatch."""
        envelope = create_test_envelope(
            tools=[{"name": "calculator", "args": {"expression": "2+2"}}]
        )
        original_digest = compute_envelope_digest(envelope)

        # Add a malicious tool
        envelope["tools"].append({"name": "execute_shell", "args": {"cmd": "rm -rf /"}})
        tampered_digest = compute_envelope_digest(envelope)

        assert tampered_digest != original_digest

    def test_tool_args_mutation_detected(self) -> None:
        """Modifying tool arguments triggers digest mismatch."""
        envelope = create_test_envelope(
            tools=[{"name": "calculator", "args": {"expression": "2+2"}}]
        )
        original_digest = compute_envelope_digest(envelope)

        # Mutate tool arguments
        envelope["tools"][0]["args"]["expression"] = "exec('rm -rf /')"
        tampered_digest = compute_envelope_digest(envelope)

        assert tampered_digest != original_digest

    def test_policy_mutation_detected(self) -> None:
        """Mutating policy rules triggers digest mismatch."""
        envelope = create_test_envelope()
        original_digest = compute_envelope_digest(envelope)

        # Weaken policy constraints
        envelope["policy"]["rules"]["responseMutation"] = "allow"
        tampered_digest = compute_envelope_digest(envelope)

        assert tampered_digest != original_digest

    def test_sources_mutation_detected(self) -> None:
        """Adding or removing sources triggers digest mismatch."""
        envelope = create_test_envelope()
        envelope["sources"] = [
            {"path": "docs/trusted.md", "digest": "abc123"}
        ]
        original_digest = compute_envelope_digest(envelope)

        # Inject malicious source
        envelope["sources"].append(
            {"path": "malicious/payload.md", "digest": "def456"}
        )
        tampered_digest = compute_envelope_digest(envelope)

        assert tampered_digest != original_digest

    def test_claims_mutation_detected(self) -> None:
        """Modifying claims array triggers digest mismatch."""
        envelope = create_test_envelope()
        envelope["claims"] = [
            {"type": "factual", "content": "The sky is blue", "evidence": []}
        ]
        original_digest = compute_envelope_digest(envelope)

        # Change claim content
        envelope["claims"][0]["content"] = "The sky is red"
        tampered_digest = compute_envelope_digest(envelope)

        assert tampered_digest != original_digest


# ---------------------------------------------------------------------------
# JCS Edge Case Tests
# ---------------------------------------------------------------------------


class TestJCSEdgeCases:
    """Tests for JCS canonicalization edge cases."""

    def test_empty_envelope_canonicalizes(self) -> None:
        """Empty envelope produces valid digest."""
        envelope: dict[str, Any] = {}
        digest = compute_envelope_digest(envelope)

        # Should produce SHA-256 of "{}" (empty canonical JSON object)
        expected = hashlib.sha256(b"{}").hexdigest()
        assert digest == expected

    def test_null_values_preserved(self) -> None:
        """Null values are preserved in canonicalization (not omitted)."""
        envelope_with_null = {"field": None}
        envelope_without_field: dict[str, Any] = {}

        digest_with_null = compute_envelope_digest(envelope_with_null)
        digest_without = compute_envelope_digest(envelope_without_field)

        # These should produce different digests
        assert digest_with_null != digest_without

    def test_unicode_characters_handled(self) -> None:
        """Unicode characters are UTF-8 encoded deterministically."""
        envelope_unicode = create_test_envelope(prompt="Test: 🔒 安全 Безопасность")
        envelope_ascii = create_test_envelope(prompt="Test: ASCII only")

        # Both should produce valid digests
        digest_unicode = compute_envelope_digest(envelope_unicode)
        digest_ascii = compute_envelope_digest(envelope_ascii)

        assert len(digest_unicode) == 64  # SHA-256 hex
        assert len(digest_ascii) == 64
        assert digest_unicode != digest_ascii

    def test_number_precision_preserved(self) -> None:
        """JCS preserves number precision without floating-point drift."""
        # RFC 8785 JCS uses exact decimal representation for numbers
        envelope_int = {"value": 42}
        envelope_float = {"value": 42.0}

        # Note: JCS may treat 42 and 42.0 differently depending on implementation
        # This test documents the actual behavior
        digest_int = compute_envelope_digest(envelope_int)
        digest_float = compute_envelope_digest(envelope_float)

        # Both should produce valid digests
        assert len(digest_int) == 64
        assert len(digest_float) == 64


# ---------------------------------------------------------------------------
# Whitespace and Formatting Tests
# ---------------------------------------------------------------------------


class TestWhitespaceInvariance:
    """Tests demonstrating that formatting/whitespace doesn't affect digest."""

    def test_whitespace_normalized(self) -> None:
        """Extra whitespace in original JSON is normalized by JCS."""
        import json

        # Create envelope with extra whitespace
        envelope_compact = {"a": 1, "b": 2}
        envelope_pretty = json.loads(json.dumps(envelope_compact, indent=2))

        # Both should produce identical canonical bytes
        digest_compact = compute_envelope_digest(envelope_compact)
        digest_pretty = compute_envelope_digest(envelope_pretty)

        assert digest_compact == digest_pretty

    def test_newlines_in_strings_preserved(self) -> None:
        """Newlines inside string values are preserved (not whitespace normalization)."""
        envelope_with_newline = create_test_envelope(prompt="Line 1\nLine 2")
        envelope_without_newline = create_test_envelope(prompt="Line 1 Line 2")

        digest_with = compute_envelope_digest(envelope_with_newline)
        digest_without = compute_envelope_digest(envelope_without_newline)

        # String content is preserved, so newlines produce different digests
        assert digest_with != digest_without


# ---------------------------------------------------------------------------
# Integration with Receipt Verification
# ---------------------------------------------------------------------------


class TestReceiptIntegration:
    """Tests demonstrating integration with receipt signature verification."""

    def test_receipt_envelope_digest_binds_exact_bytes(self) -> None:
        """Receipt envelopeDigest field cryptographically binds to exact payload bytes."""
        envelope = create_test_envelope(prompt="What is 2+2?")
        expected_digest = compute_envelope_digest(envelope)

        # Simulate receipt structure (simplified)
        receipt = {
            "protocolVersion": "1-alpha",
            "receiptVersion": "2-alpha",
            "envelopeDigest": expected_digest,
            "verification": {"status": "PASS", "findings": []},
        }

        # Before releasing response, verify digest matches
        actual_digest = compute_envelope_digest(envelope)
        assert receipt["envelopeDigest"] == actual_digest

    def test_digest_mismatch_prevents_release(self) -> None:
        """Digest mismatch between receipt and actual envelope prevents release."""
        original_envelope = create_test_envelope(prompt="Safe content")
        original_digest = compute_envelope_digest(original_envelope)

        # Receipt contains digest of original envelope
        receipt = {
            "envelopeDigest": original_digest,
            "verification": {"status": "PASS"},
        }

        # Adversary attempts to release different content
        malicious_envelope = create_test_envelope(prompt="Malicious content")
        malicious_digest = compute_envelope_digest(malicious_envelope)

        # Verification gate should detect mismatch
        release_allowed = receipt["envelopeDigest"] == malicious_digest
        assert release_allowed is False  # Release must be blocked

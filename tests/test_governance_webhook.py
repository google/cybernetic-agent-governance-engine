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

"""Tests for src/compliance_bridge/governance_webhook.py — registration, dispatch, HMAC, region guard."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import unittest.mock as mock

import pytest

from src.compliance_bridge.governance_webhook import WebhookRegistry

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_registry(region: str = "US_FED") -> WebhookRegistry:
    """Create a fresh WebhookRegistry with the given region."""
    registry = WebhookRegistry()
    registry._region = region
    registry._registrations = {}
    return registry


def _make_event(event_type: str = "CBF_VIOLATION") -> dict:
    return {
        "type": event_type,
        "traceId": "trace-abc123",
        "controlId": "A.9.2",
        "result": "FAIL",
        "safetyRate": 0.87,
        "auditId": "audit-uuid-001",
        "timestamp": "2026-07-18T01:00:00Z",
    }


# ---------------------------------------------------------------------------
# Registration tests
# ---------------------------------------------------------------------------


class TestWebhookRegistration:
    def test_register_returns_webhook_id(self):
        registry = _make_registry()
        webhook_id = asyncio.run(
            registry.register(
                endpoint_url="https://governance.example.com/events",
                event_types=["CBF_VIOLATION"],
                secret="test-secret",
            )
        )
        assert webhook_id is not None
        assert len(webhook_id) > 0

    def test_register_stores_registration(self):
        registry = _make_registry()
        webhook_id = asyncio.run(
            registry.register(
                endpoint_url="https://governance.example.com/events",
                event_types=["CBF_VIOLATION"],
                secret="test-secret",
            )
        )
        assert webhook_id in registry._registrations

    def test_register_multiple_event_types(self):
        registry = _make_registry()
        webhook_id = asyncio.run(
            registry.register(
                endpoint_url="https://governance.example.com/events",
                event_types=["CBF_VIOLATION", "OPA_DENY", "HITL_INTERRUPT"],
                secret="test-secret",
            )
        )
        reg = registry._registrations[webhook_id]
        assert "CBF_VIOLATION" in reg.event_types
        assert "OPA_DENY" in reg.event_types
        assert "HITL_INTERRUPT" in reg.event_types

    def test_register_invalid_event_type_raises(self):
        registry = _make_registry()
        with pytest.raises(ValueError, match="unknown event types"):
            asyncio.run(
                registry.register(
                    endpoint_url="https://governance.example.com/events",
                    event_types=["INVALID_EVENT_TYPE"],
                    secret="test-secret",
                )
            )

    def test_deregister_removes_registration(self):
        registry = _make_registry()
        webhook_id = asyncio.run(
            registry.register(
                endpoint_url="https://governance.example.com/events",
                event_types=["CBF_VIOLATION"],
                secret="test-secret",
            )
        )
        removed = asyncio.run(
            registry.deregister(webhook_id)
        )
        assert removed is True
        assert webhook_id not in registry._registrations

    def test_deregister_nonexistent_returns_false(self):
        registry = _make_registry()
        removed = asyncio.run(
            registry.deregister("nonexistent-id")
        )
        assert removed is False

    def test_list_registrations_returns_all(self):
        registry = _make_registry()
        asyncio.run(
            registry.register(
                endpoint_url="https://governance.example.com/events",
                event_types=["CBF_VIOLATION"],
                secret="test-secret",
            )
        )
        asyncio.run(
            registry.register(
                endpoint_url="https://other.example.com/events",
                event_types=["OPA_DENY"],
                secret="other-secret",
            )
        )
        registrations = asyncio.run(
            registry.list_registrations()
        )
        assert len(registrations) == 2

    def test_list_registrations_does_not_include_secret(self):
        registry = _make_registry()
        asyncio.run(
            registry.register(
                endpoint_url="https://governance.example.com/events",
                event_types=["CBF_VIOLATION"],
                secret="super-secret-value",
            )
        )
        registrations = asyncio.run(
            registry.list_registrations()
        )
        for reg in registrations:
            assert "secret" not in reg
            assert "super-secret-value" not in str(reg)


# ---------------------------------------------------------------------------
# HMAC signature tests
# ---------------------------------------------------------------------------


class TestHMACSignature:
    def test_sign_payload_produces_hex_string(self):
        payload = b'{"type": "CBF_VIOLATION"}'
        sig = WebhookRegistry._sign_payload(payload, "test-secret")
        assert isinstance(sig, str)
        assert len(sig) == 64  # SHA-256 hex digest is 64 chars

    def test_sign_payload_is_verifiable(self):
        payload = b'{"type": "CBF_VIOLATION", "traceId": "abc"}'
        secret = "my-signing-secret"
        sig = WebhookRegistry._sign_payload(payload, secret)
        expected = hmac.new(
            secret.encode("utf-8"),
            payload,
            hashlib.sha256,
        ).hexdigest()
        assert sig == expected

    def test_different_secrets_produce_different_signatures(self):
        payload = b'{"type": "CBF_VIOLATION"}'
        sig1 = WebhookRegistry._sign_payload(payload, "secret-1")
        sig2 = WebhookRegistry._sign_payload(payload, "secret-2")
        assert sig1 != sig2

    def test_different_payloads_produce_different_signatures(self):
        secret = "test-secret"
        sig1 = WebhookRegistry._sign_payload(b'{"type": "CBF_VIOLATION"}', secret)
        sig2 = WebhookRegistry._sign_payload(b'{"type": "OPA_DENY"}', secret)
        assert sig1 != sig2


# ---------------------------------------------------------------------------
# Dispatch tests
# ---------------------------------------------------------------------------


class TestWebhookDispatch:
    def test_dispatch_cbf_violation_calls_deliver(self):
        registry = _make_registry()
        asyncio.run(
            registry.register(
                endpoint_url="https://governance.example.com/events",
                event_types=["CBF_VIOLATION"],
                secret="test-secret",
            )
        )

        delivered_payloads = []

        async def mock_deliver(registration, payload):
            delivered_payloads.append(payload)
            return True

        with mock.patch.object(registry, "_deliver", side_effect=mock_deliver):
            asyncio.run(
                registry.dispatch(_make_event("CBF_VIOLATION"))
            )

        assert len(delivered_payloads) == 1
        assert delivered_payloads[0]["type"] == "CBF_VIOLATION"

    def test_dispatch_adds_webhook_id_to_payload(self):
        registry = _make_registry()
        webhook_id = asyncio.run(
            registry.register(
                endpoint_url="https://governance.example.com/events",
                event_types=["CBF_VIOLATION"],
                secret="test-secret",
            )
        )

        delivered_payloads = []

        async def mock_deliver(registration, payload):
            delivered_payloads.append(payload)
            return True

        with mock.patch.object(registry, "_deliver", side_effect=mock_deliver):
            asyncio.run(
                registry.dispatch(_make_event("CBF_VIOLATION"))
            )

        assert delivered_payloads[0]["webhook_id"] == webhook_id

    def test_dispatch_unregistered_event_type_not_dispatched(self):
        registry = _make_registry()
        asyncio.run(
            registry.register(
                endpoint_url="https://governance.example.com/events",
                event_types=["CBF_VIOLATION"],  # Only CBF_VIOLATION registered
                secret="test-secret",
            )
        )

        delivered_payloads = []

        async def mock_deliver(registration, payload):
            delivered_payloads.append(payload)
            return True

        with mock.patch.object(registry, "_deliver", side_effect=mock_deliver):
            asyncio.run(
                registry.dispatch(_make_event("OPA_DENY"))  # Different event type
            )

        assert len(delivered_payloads) == 0

    def test_dispatch_no_registrations_does_not_raise(self):
        registry = _make_registry()
        # Should not raise even with no registrations
        asyncio.run(
            registry.dispatch(_make_event("CBF_VIOLATION"))
        )

    def test_dispatch_unknown_event_type_skipped(self):
        registry = _make_registry()
        # Should not raise for non-webhook event types
        asyncio.run(
            registry.dispatch({"type": "AUDIT_FINDING", "traceId": "x"})
        )

    def test_dispatch_missing_type_field_logs_warning(self):
        registry = _make_registry()
        # Should not raise for events without type field
        asyncio.run(registry.dispatch({"traceId": "x"}))

    def test_dispatch_to_multiple_webhooks(self):
        registry = _make_registry()
        asyncio.run(
            registry.register(
                endpoint_url="https://governance-1.example.com/events",
                event_types=["CBF_VIOLATION"],
                secret="secret-1",
            )
        )
        asyncio.run(
            registry.register(
                endpoint_url="https://governance-2.example.com/events",
                event_types=["CBF_VIOLATION"],
                secret="secret-2",
            )
        )

        delivered_payloads = []

        async def mock_deliver(registration, payload):
            delivered_payloads.append(payload)
            return True

        with mock.patch.object(registry, "_deliver", side_effect=mock_deliver):
            asyncio.run(
                registry.dispatch(_make_event("CBF_VIOLATION"))
            )

        assert len(delivered_payloads) == 2


# ---------------------------------------------------------------------------
# Region guard tests
# ---------------------------------------------------------------------------


class TestRegionGuard:
    def test_eu_ecb_cross_region_endpoint_raises(self):
        registry = _make_registry(region="EU_ECB")
        with pytest.raises(ValueError, match="region guard"):
            asyncio.run(
                registry.register(
                    endpoint_url="https://us-central1.example.com/events",
                    event_types=["CBF_VIOLATION"],
                    secret="test-secret",
                )
            )

    def test_us_fed_allows_any_endpoint(self):
        registry = _make_registry(region="US_FED")
        # US_FED has no geographic restriction
        webhook_id = asyncio.run(
            registry.register(
                endpoint_url="https://any-region.example.com/events",
                event_types=["CBF_VIOLATION"],
                secret="test-secret",
            )
        )
        assert webhook_id is not None

    def test_eu_ecb_allows_europe_west1_endpoint(self):
        registry = _make_registry(region="EU_ECB")
        # europe-west1 endpoints should be allowed
        webhook_id = asyncio.run(
            registry.register(
                endpoint_url="https://europe-west1.example.com/events",
                event_types=["CBF_VIOLATION"],
                secret="test-secret",
            )
        )
        assert webhook_id is not None

    def test_eu_ecb_allows_localhost_for_testing(self):
        registry = _make_registry(region="EU_ECB")
        webhook_id = asyncio.run(
            registry.register(
                endpoint_url="http://localhost:8080/events",
                event_types=["CBF_VIOLATION"],
                secret="test-secret",
            )
        )
        assert webhook_id is not None

    def test_apac_mas_cross_region_endpoint_raises(self):
        registry = _make_registry(region="APAC_MAS")
        with pytest.raises(ValueError, match="region guard"):
            asyncio.run(
                registry.register(
                    endpoint_url="https://europe-west1.example.com/events",
                    event_types=["CBF_VIOLATION"],
                    secret="test-secret",
                )
            )

    def test_apac_mas_allows_asia_southeast1_endpoint(self):
        registry = _make_registry(region="APAC_MAS")
        webhook_id = asyncio.run(
            registry.register(
                endpoint_url="https://asia-southeast1.example.com/events",
                event_types=["CBF_VIOLATION"],
                secret="test-secret",
            )
        )
        assert webhook_id is not None

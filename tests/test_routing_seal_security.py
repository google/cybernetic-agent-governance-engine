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
Security tests for routing_seal modules.

Covers both:
  - src/gateway/governance/routing_seal.py  (gateway issuer)
  - src/governed_financial_advisor/utils/routing_seal.py  (GFA verifier mirror)

Test cases:
  1. is_default_salt() — gateway version
  2. assert_custom_salt_in_production() — gateway version
  3. is_default_salt() — GFA utils version
  4. assert_custom_salt_in_production() — GFA utils version
  5. Seal round-trip: generate + verify with custom salt
  6. verify_seal() rejects expired seal
  7. verify_seal() rejects wrong action
"""

import datetime
import os
import time
from unittest.mock import patch

import pytest
from freezegun import freeze_time

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def disable_seal_strict_mode(monkeypatch):
    """Disable strict mode for all tests in this module.

    Strict mode rejects HMAC seals in production environments.
    Tests use HMAC seals for unit testing, so we disable strict mode.
    """
    monkeypatch.setenv("CAGE_SEAL_STRICT_MODE", "false")


# ---------------------------------------------------------------------------
# NOTE on module-level state
# ---------------------------------------------------------------------------
# Both routing_seal modules compute _USING_DEFAULT_SALT and _HMAC_KEY at
# import time from os.getenv("GOVERNANCE_SALT"). Because Python caches modules,
# we cannot simply re-import to pick up a different env var value.
#
# Strategy: patch the module-level _USING_DEFAULT_SALT flag directly for
# is_default_salt() tests, and patch os.getenv for assert_custom_salt_in_production()
# tests (which reads CAGE_ENV at call time, not import time).
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# 1. is_default_salt() — gateway version
# ---------------------------------------------------------------------------


def test_gateway_is_default_salt_true_when_using_default():
    """is_default_salt() returns True when _USING_DEFAULT_SALT is True (no custom GOVERNANCE_SALT)."""
    import src.gateway.governance.routing_seal as gw_seal

    with patch.object(gw_seal, "_USING_DEFAULT_SALT", True):
        assert gw_seal.is_default_salt() is True


def test_gateway_is_default_salt_false_when_custom_salt_set():
    """is_default_salt() returns False when _USING_DEFAULT_SALT is False (custom GOVERNANCE_SALT in use)."""
    import src.gateway.governance.routing_seal as gw_seal

    with patch.object(gw_seal, "_USING_DEFAULT_SALT", False):
        assert gw_seal.is_default_salt() is False


# ---------------------------------------------------------------------------
# 2. assert_custom_salt_in_production() — gateway version
# ---------------------------------------------------------------------------


def test_gateway_assert_custom_salt_does_not_raise_in_development():
    """assert_custom_salt_in_production() does NOT raise when CAGE_ENV=development, even with default salt."""
    import src.gateway.governance.routing_seal as gw_seal

    with (
        patch.object(gw_seal, "_USING_DEFAULT_SALT", True),
        patch.dict(os.environ, {"CAGE_ENV": "development"}, clear=False),
    ):
        # Should not raise
        gw_seal.assert_custom_salt_in_production()


def test_gateway_assert_custom_salt_does_not_raise_in_test_env():
    """assert_custom_salt_in_production() does NOT raise when CAGE_ENV=test, even with default salt."""
    import src.gateway.governance.routing_seal as gw_seal

    with (
        patch.object(gw_seal, "_USING_DEFAULT_SALT", True),
        patch.dict(os.environ, {"CAGE_ENV": "test"}, clear=False),
    ):
        gw_seal.assert_custom_salt_in_production()


def test_gateway_assert_custom_salt_does_not_raise_in_ci_env():
    """assert_custom_salt_in_production() does NOT raise when CAGE_ENV=ci, even with default salt."""
    import src.gateway.governance.routing_seal as gw_seal

    with (
        patch.object(gw_seal, "_USING_DEFAULT_SALT", True),
        patch.dict(os.environ, {"CAGE_ENV": "ci"}, clear=False),
    ):
        gw_seal.assert_custom_salt_in_production()


def test_gateway_assert_custom_salt_raises_in_production_with_default_salt():
    """assert_custom_salt_in_production() raises RuntimeError when CAGE_ENV=production and default salt is in use."""
    import src.gateway.governance.routing_seal as gw_seal

    env = {k: v for k, v in os.environ.items() if k not in ("CAGE_ENV", "ENVIRONMENT")}
    env["CAGE_ENV"] = "production"

    with (
        patch.object(gw_seal, "_USING_DEFAULT_SALT", True),
        patch.dict(os.environ, env, clear=True),
    ):
        with pytest.raises(RuntimeError, match="REDACTED_SALT"):
            gw_seal.assert_custom_salt_in_production()


def test_gateway_assert_custom_salt_does_not_raise_in_production_with_custom_salt():
    """assert_custom_salt_in_production() does NOT raise when CAGE_ENV=production and a custom salt is set."""
    import src.gateway.governance.routing_seal as gw_seal

    env = {k: v for k, v in os.environ.items() if k not in ("CAGE_ENV", "ENVIRONMENT")}
    env["CAGE_ENV"] = "production"

    with (
        patch.object(gw_seal, "_USING_DEFAULT_SALT", False),
        patch.dict(os.environ, env, clear=True),
    ):
        # Should not raise
        gw_seal.assert_custom_salt_in_production()


def test_gateway_assert_custom_salt_raises_uses_environment_fallback():
    """assert_custom_salt_in_production() uses ENVIRONMENT var when CAGE_ENV is not set."""
    import src.gateway.governance.routing_seal as gw_seal

    env = {k: v for k, v in os.environ.items() if k not in ("CAGE_ENV", "ENVIRONMENT")}
    env["ENVIRONMENT"] = "production"

    with (
        patch.object(gw_seal, "_USING_DEFAULT_SALT", True),
        patch.dict(os.environ, env, clear=True),
    ):
        with pytest.raises(RuntimeError):
            gw_seal.assert_custom_salt_in_production()


# ---------------------------------------------------------------------------
# 3. is_default_salt() — GFA utils version
# ---------------------------------------------------------------------------


def test_gateway_generate_and_gfa_verify_round_trip():
    """generate_seal() + GFA verify_seal() round-trip succeeds with the test salt."""
    from src.gateway.governance.routing_seal import generate_seal
    from src.governed_financial_advisor.utils.routing_seal import (
        verify_seal as gfa_verify,
    )

    params = {"symbol": "AAPL", "amount": 5000.0, "currency": "USD"}
    seal = generate_seal("execute_trade", params)
    assert gfa_verify(seal, "execute_trade", params) is True


def test_gateway_generate_and_gateway_verify_round_trip():
    """generate_seal() + gateway verify_seal() round-trip succeeds."""
    from src.gateway.governance.routing_seal import generate_seal, verify_seal

    params = {"symbol": "TSLA", "amount": 10000.0, "confidence": 0.97}
    seal = generate_seal("execute_trade", params)
    assert verify_seal(seal, "execute_trade", params) is True


def test_round_trip_with_nested_params_coerced_to_string():
    """generate_seal() + verify_seal() round-trip succeeds when params contain non-primitive values (coerced to str)."""
    from src.gateway.governance.routing_seal import generate_seal, verify_seal

    # Non-primitive values are coerced to str in _canonical_payload
    params = {"symbol": "GOOG", "amount": 1000.0, "metadata": {"key": "value"}}
    seal = generate_seal("execute_trade", params)
    assert verify_seal(seal, "execute_trade", params) is True


# ---------------------------------------------------------------------------
# 6. verify_seal() rejects expired seal
# ---------------------------------------------------------------------------


def test_gateway_verify_seal_rejects_expired_seal():
    """verify_seal() raises SymbolicGovernorViolation for a seal generated with ttl_s=-10 (already expired)."""
    from src.gateway.governance.routing_seal import (
        SymbolicGovernorViolation,
        generate_seal,
        verify_seal,
    )

    params = {"symbol": "AAPL", "amount": 1000.0}
    # ttl_s=-10 generates an already-expired seal (both for JWT exp claim and HMAC timestamp)
    seal = generate_seal("execute_trade", params, ttl_s=-10)
    with pytest.raises(SymbolicGovernorViolation):
        verify_seal(seal, "execute_trade", params)


# ---------------------------------------------------------------------------
# 7. verify_seal() rejects wrong action
# ---------------------------------------------------------------------------


def test_gateway_verify_seal_rejects_wrong_action():
    """verify_seal() raises SymbolicGovernorViolation when the action does not match the seal's action slug."""
    from src.gateway.governance.routing_seal import (
        SymbolicGovernorViolation,
        generate_seal,
        verify_seal,
    )

    params = {"symbol": "AAPL", "amount": 1000.0}
    seal = generate_seal("execute_trade", params)
    with pytest.raises(SymbolicGovernorViolation):
        verify_seal(seal, "cancel_trade", params)


def test_gateway_verify_seal_rejects_tampered_hmac():
    """verify_seal() raises SymbolicGovernorViolation when the HMAC component is tampered."""
    from src.gateway.governance.routing_seal import (
        SymbolicGovernorViolation,
        generate_seal,
        verify_seal,
    )

    params = {"symbol": "AAPL", "amount": 1000.0}
    seal = generate_seal("execute_trade", params)
    parts = seal.split(".")
    # v2 format: HMAC is at index 3 (4th component)
    parts[3] = parts[3][:-1] + ("a" if parts[3][-1] != "a" else "b")
    tampered = ".".join(parts)
    with pytest.raises(SymbolicGovernorViolation):
        verify_seal(tampered, "execute_trade", params)


def test_gateway_verify_seal_rejects_tampered_record_hash():
    """verify_seal() raises SymbolicGovernorViolation when the record_hash is tampered."""
    from src.gateway.governance.routing_seal import (
        SymbolicGovernorViolation,
        generate_seal,
        verify_seal,
    )

    params = {"symbol": "AAPL", "amount": 1000.0}
    seal = generate_seal("execute_trade", params, record_hash="original_hash_value")
    parts = seal.split(".")
    # v2 format: record_hash is at index 2 (3rd component)
    parts[2] = "tampered_hash_value"
    tampered = ".".join(parts)
    with pytest.raises(SymbolicGovernorViolation):
        verify_seal(tampered, "execute_trade", params)


def test_gateway_verify_seal_rejects_malformed_seal():
    """verify_seal() raises SymbolicGovernorViolation for a malformed seal string (v2 expects 4 parts)."""
    from src.gateway.governance.routing_seal import (
        SymbolicGovernorViolation,
        verify_seal,
    )

    # Too many parts
    with pytest.raises(SymbolicGovernorViolation):
        verify_seal("a.b.c.d.e.f", "execute_trade", {})
    # Too few parts (v1 format with 3 parts is now invalid)
    with pytest.raises(SymbolicGovernorViolation):
        verify_seal("abc.def.ghi", "execute_trade", {})
    # Only 2 parts
    with pytest.raises(SymbolicGovernorViolation):
        verify_seal("only-two.parts", "execute_trade", {})
    # Empty
    with pytest.raises(SymbolicGovernorViolation):
        verify_seal("", "execute_trade", {})


@pytest.mark.asyncio
async def test_gateway_verify_and_consume_seal_prevents_replay():
    """verify_and_consume_seal() burns the seal in Redis; a second attempt raises SymbolicGovernorViolation."""
    import fakeredis.aioredis as fakeredis

    from src.gateway.governance.routing_seal import (
        SymbolicGovernorViolation,
        generate_seal,
        verify_and_consume_seal,
    )

    redis = fakeredis.FakeRedis()
    params = {"symbol": "AAPL", "amount": 100.0}
    seal = generate_seal("execute_trade", params)

    # First consumption succeeds
    assert (
        await verify_and_consume_seal(seal, "execute_trade", params, redis_client=redis)
        is True
    )

    # Second consumption within TTL must fail with replay violation
    with pytest.raises(SymbolicGovernorViolation) as exc_info:
        await verify_and_consume_seal(seal, "execute_trade", params, redis_client=redis)

    assert "already consumed" in str(exc_info.value) or "Replay" in str(exc_info.value)


# ---------------------------------------------------------------------------
# P0 Hardening: Evidence Binding Enforcement tests
# ---------------------------------------------------------------------------


class TestEvidenceBindingEnforcement:
    """P0 security hardening tests for CAGE_REQUIRE_EVIDENCE_BINDING=true behavior.

    When evidence binding is required, seals with record_hash="no-evidence-binding"
    (or empty/none variants) are rejected. This ensures all financial actions are
    cryptographically bound to evidence records in the compliance evidence stream.
    """

    def test_gateway_rejects_no_evidence_binding_in_strict_mode(self):
        """P0: Gateway verify_seal() rejects 'no-evidence-binding' when enforcement is enabled."""
        import src.gateway.governance.routing_seal as gw_seal

        params = {"symbol": "MSFT", "amount": 500.0}
        # Generate a seal without evidence binding
        seal = gw_seal.generate_seal("execute_trade", params, record_hash=None)

        with (
            patch.object(gw_seal, "_REQUIRE_EVIDENCE_BINDING", True),
        ):
            with pytest.raises(gw_seal.SymbolicGovernorViolation) as exc_info:
                gw_seal.verify_seal(seal, "execute_trade", params)

            assert "Evidence sufficiency violation" in str(exc_info.value)

    def test_gateway_accepts_no_evidence_binding_when_enforcement_disabled(self):
        """P0: Gateway verify_seal() accepts 'no-evidence-binding' when enforcement is disabled."""
        import src.gateway.governance.routing_seal as gw_seal

        params = {"symbol": "MSFT", "amount": 500.0}
        seal = gw_seal.generate_seal("execute_trade", params, record_hash=None)

        with (
            patch.object(gw_seal, "_REQUIRE_EVIDENCE_BINDING", False),
        ):
            # Should not raise
            result = gw_seal.verify_seal(seal, "execute_trade", params)
            assert result is True

    def test_gateway_accepts_valid_evidence_binding_in_strict_mode(self):
        """P0: Gateway verify_seal() accepts seals with valid evidence hash."""
        import src.gateway.governance.routing_seal as gw_seal

        params = {"symbol": "MSFT", "amount": 500.0}
        valid_record_hash = (
            "abc123def456789012345678901234567890abcdef123456789012345678901234"
        )
        seal = gw_seal.generate_seal(
            "execute_trade", params, record_hash=valid_record_hash
        )

        with (
            patch.object(gw_seal, "_REQUIRE_EVIDENCE_BINDING", True),
        ):
            result = gw_seal.verify_seal(seal, "execute_trade", params)
            assert result is True

    def test_gateway_rejects_empty_record_hash_in_strict_mode(self):
        """P0: Gateway verify_seal() rejects empty record_hash when enforcement is enabled."""
        import src.gateway.governance.routing_seal as gw_seal

        params = {"symbol": "TSLA", "amount": 100.0}
        # Manually craft a seal with empty record_hash
        seal = gw_seal.generate_seal("execute_trade", params, record_hash="")

        with (
            patch.object(gw_seal, "_REQUIRE_EVIDENCE_BINDING", True),
        ):
            with pytest.raises(gw_seal.SymbolicGovernorViolation) as exc_info:
                gw_seal.verify_seal(seal, "execute_trade", params)

            assert "Evidence sufficiency violation" in str(exc_info.value)

    def test_gateway_rejects_none_string_record_hash_in_strict_mode(self):
        """P0: Gateway verify_seal() rejects 'none' as record_hash."""
        import src.gateway.governance.routing_seal as gw_seal

        params = {"symbol": "NVDA", "amount": 200.0}
        seal = gw_seal.generate_seal("execute_trade", params, record_hash="none")

        with (
            patch.object(gw_seal, "_REQUIRE_EVIDENCE_BINDING", True),
        ):
            with pytest.raises(gw_seal.SymbolicGovernorViolation) as exc_info:
                gw_seal.verify_seal(seal, "execute_trade", params)

            assert "Evidence sufficiency violation" in str(exc_info.value)


@pytest.mark.asyncio
async def test_gfa_verify_and_consume_seal_prevents_replay():
    """GFA verify_and_consume_seal() burns the seal in Redis and rejects replays."""
    import fakeredis.aioredis as fakeredis

    from src.gateway.governance.routing_seal import generate_seal
    from src.governed_financial_advisor.utils.routing_seal import (
        SymbolicGovernorViolation as GFASymbolicGovernorViolation,
    )
    from src.governed_financial_advisor.utils.routing_seal import (
        verify_and_consume_seal as gfa_verify_and_consume,
    )

    redis = fakeredis.FakeRedis()
    params = {"symbol": "GOOGL", "amount": 250.0}
    seal = generate_seal("execute_trade", params)

    # First consumption succeeds
    assert (
        await gfa_verify_and_consume(seal, "execute_trade", params, redis_client=redis)
        is True
    )

    # Replay attempt fails
    with pytest.raises(GFASymbolicGovernorViolation) as exc_info:
        await gfa_verify_and_consume(seal, "execute_trade", params, redis_client=redis)

    assert "already consumed" in str(exc_info.value) or "Replay" in str(exc_info.value)


def test_gateway_rejects_hmac_in_production():
    """verify_seal() rejects v2 HMAC seals when running in production."""
    import src.gateway.governance.routing_seal as gw_seal

    params = {"symbol": "AAPL", "amount": 1000.0}
    seal = gw_seal.generate_seal("execute_trade", params)

    # Patch environment to simulate production (runtime check via _is_production_env)
    # Clear both CAGE_ENV and ENVIRONMENT to ensure production detection
    env = {k: v for k, v in os.environ.items() if k not in ("CAGE_ENV", "ENVIRONMENT")}
    env["CAGE_ENV"] = "production"
    with patch.dict(os.environ, env, clear=True):
        with pytest.raises(gw_seal.SymbolicGovernorViolation) as exc_info:
            gw_seal.verify_seal(seal, "execute_trade", params)

        assert "HMAC seals are not accepted" in str(exc_info.value)

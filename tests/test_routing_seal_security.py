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


def test_gfa_is_default_salt_true_when_using_default():
    """GFA is_default_salt() returns True when _USING_DEFAULT_SALT is True."""
    import src.governed_financial_advisor.utils.routing_seal as gfa_seal

    with patch.object(gfa_seal, "_USING_DEFAULT_SALT", True):
        assert gfa_seal.is_default_salt() is True


def test_gfa_is_default_salt_false_when_custom_salt_set():
    """GFA is_default_salt() returns False when _USING_DEFAULT_SALT is False."""
    import src.governed_financial_advisor.utils.routing_seal as gfa_seal

    with patch.object(gfa_seal, "_USING_DEFAULT_SALT", False):
        assert gfa_seal.is_default_salt() is False


# ---------------------------------------------------------------------------
# 4. assert_custom_salt_in_production() — GFA utils version
# ---------------------------------------------------------------------------


def test_gfa_assert_custom_salt_does_not_raise_in_development():
    """GFA assert_custom_salt_in_production() does NOT raise when CAGE_ENV=development, even with default salt."""
    import src.governed_financial_advisor.utils.routing_seal as gfa_seal

    with (
        patch.object(gfa_seal, "_USING_DEFAULT_SALT", True),
        patch.dict(os.environ, {"CAGE_ENV": "development"}, clear=False),
    ):
        gfa_seal.assert_custom_salt_in_production()


def test_gfa_assert_custom_salt_does_not_raise_in_test_env():
    """GFA assert_custom_salt_in_production() does NOT raise when CAGE_ENV=test, even with default salt."""
    import src.governed_financial_advisor.utils.routing_seal as gfa_seal

    with (
        patch.object(gfa_seal, "_USING_DEFAULT_SALT", True),
        patch.dict(os.environ, {"CAGE_ENV": "test"}, clear=False),
    ):
        gfa_seal.assert_custom_salt_in_production()


def test_gfa_assert_custom_salt_does_not_raise_in_ci_env():
    """GFA assert_custom_salt_in_production() does NOT raise when CAGE_ENV=ci, even with default salt."""
    import src.governed_financial_advisor.utils.routing_seal as gfa_seal

    with (
        patch.object(gfa_seal, "_USING_DEFAULT_SALT", True),
        patch.dict(os.environ, {"CAGE_ENV": "ci"}, clear=False),
    ):
        gfa_seal.assert_custom_salt_in_production()


def test_gfa_assert_custom_salt_raises_in_production_with_default_salt():
    """GFA assert_custom_salt_in_production() raises RuntimeError when CAGE_ENV=production and default salt is in use."""
    import src.governed_financial_advisor.utils.routing_seal as gfa_seal

    env = {k: v for k, v in os.environ.items() if k not in ("CAGE_ENV", "ENVIRONMENT")}
    env["CAGE_ENV"] = "production"

    with (
        patch.object(gfa_seal, "_USING_DEFAULT_SALT", True),
        patch.dict(os.environ, env, clear=True),
    ):
        with pytest.raises(RuntimeError, match="REDACTED_SALT"):
            gfa_seal.assert_custom_salt_in_production()


def test_gfa_assert_custom_salt_does_not_raise_in_production_with_custom_salt():
    """GFA assert_custom_salt_in_production() does NOT raise when CAGE_ENV=production and a custom salt is set."""
    import src.governed_financial_advisor.utils.routing_seal as gfa_seal

    env = {k: v for k, v in os.environ.items() if k not in ("CAGE_ENV", "ENVIRONMENT")}
    env["CAGE_ENV"] = "production"

    with (
        patch.object(gfa_seal, "_USING_DEFAULT_SALT", False),
        patch.dict(os.environ, env, clear=True),
    ):
        gfa_seal.assert_custom_salt_in_production()


def test_gfa_assert_custom_salt_raises_uses_environment_fallback():
    """GFA assert_custom_salt_in_production() uses ENVIRONMENT var when CAGE_ENV is not set."""
    import src.governed_financial_advisor.utils.routing_seal as gfa_seal

    env = {k: v for k, v in os.environ.items() if k not in ("CAGE_ENV", "ENVIRONMENT")}
    env["ENVIRONMENT"] = "production"

    with (
        patch.object(gfa_seal, "_USING_DEFAULT_SALT", True),
        patch.dict(os.environ, env, clear=True),
    ):
        with pytest.raises(RuntimeError):
            gfa_seal.assert_custom_salt_in_production()


# ---------------------------------------------------------------------------
# 5. Seal round-trip: generate_seal() + verify_seal() with custom salt
# ---------------------------------------------------------------------------
# These tests use the already-imported modules (which have the test salt from
# conftest.py: "CYBERNETIC_GOVERNANCE_TEST_SALT_32C!"). The HMAC key is
# consistent within the test session, so round-trips work correctly.


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
    """verify_seal() raises SymbolicGovernorViolation for a seal generated with ttl_s=0 (immediately expired)."""
    from src.gateway.governance.routing_seal import (
        SymbolicGovernorViolation,
        generate_seal,
        verify_seal,
    )

    params = {"symbol": "AAPL", "amount": 1000.0}
    # ttl_s=0 means expire_ts = now; freeze time 2 s ahead to ensure past expiry
    now = time.time()
    seal = generate_seal("execute_trade", params, ttl_s=0)
    frozen_dt = datetime.datetime.fromtimestamp(now + 2, tz=datetime.timezone.utc)
    with freeze_time(frozen_dt):
        with pytest.raises(SymbolicGovernorViolation):
            verify_seal(seal, "execute_trade", params)


def test_gfa_verify_seal_rejects_expired_seal():
    """GFA verify_seal() raises SymbolicGovernorViolation for an expired seal."""
    from src.gateway.governance.routing_seal import generate_seal
    from src.governed_financial_advisor.utils.routing_seal import (
        SymbolicGovernorViolation as GFASymbolicGovernorViolation,
    )
    from src.governed_financial_advisor.utils.routing_seal import (
        verify_seal as gfa_verify,
    )

    params = {"symbol": "AAPL", "amount": 1000.0}
    now = time.time()
    seal = generate_seal("execute_trade", params, ttl_s=0)
    frozen_dt = datetime.datetime.fromtimestamp(now + 2, tz=datetime.timezone.utc)
    with freeze_time(frozen_dt):
        with pytest.raises(GFASymbolicGovernorViolation):
            gfa_verify(seal, "execute_trade", params)


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


def test_gfa_verify_seal_rejects_wrong_action():
    """GFA verify_seal() raises SymbolicGovernorViolation when the action does not match the seal's action slug."""
    from src.gateway.governance.routing_seal import generate_seal
    from src.governed_financial_advisor.utils.routing_seal import (
        SymbolicGovernorViolation as GFASymbolicGovernorViolation,
    )
    from src.governed_financial_advisor.utils.routing_seal import (
        verify_seal as gfa_verify,
    )

    params = {"symbol": "AAPL", "amount": 1000.0}
    seal = generate_seal("execute_trade", params)
    with pytest.raises(GFASymbolicGovernorViolation):
        gfa_verify(seal, "cancel_trade", params)


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
    # Flip the last character of the HMAC
    parts[2] = parts[2][:-1] + ("a" if parts[2][-1] != "a" else "b")
    tampered = ".".join(parts)
    with pytest.raises(SymbolicGovernorViolation):
        verify_seal(tampered, "execute_trade", params)


def test_gateway_verify_seal_rejects_malformed_seal():
    """verify_seal() raises SymbolicGovernorViolation for a malformed seal string."""
    from src.gateway.governance.routing_seal import (
        SymbolicGovernorViolation,
        verify_seal,
    )

    with pytest.raises(SymbolicGovernorViolation):
        verify_seal("not.a.valid.seal.with.too.many.parts", "execute_trade", {})
    with pytest.raises(SymbolicGovernorViolation):
        verify_seal("only-two-parts", "execute_trade", {})
    with pytest.raises(SymbolicGovernorViolation):
        verify_seal("", "execute_trade", {})


def test_gfa_verify_seal_rejects_malformed_seal():
    """GFA verify_seal() raises SymbolicGovernorViolation for a malformed seal string."""
    from src.governed_financial_advisor.utils.routing_seal import (
        SymbolicGovernorViolation as GFASymbolicGovernorViolation,
    )
    from src.governed_financial_advisor.utils.routing_seal import (
        verify_seal as gfa_verify,
    )

    with pytest.raises(GFASymbolicGovernorViolation):
        gfa_verify("not.a.valid.seal.with.too.many.parts", "execute_trade", {})
    with pytest.raises(GFASymbolicGovernorViolation):
        gfa_verify("only-two-parts", "execute_trade", {})
    with pytest.raises(GFASymbolicGovernorViolation):
        gfa_verify("", "execute_trade", {})


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
        await verify_and_consume_seal(
            seal, "execute_trade", params, redis_client=redis
        )
        is True
    )

    # Second consumption within TTL must fail with replay violation
    with pytest.raises(SymbolicGovernorViolation) as exc_info:
        await verify_and_consume_seal(
            seal, "execute_trade", params, redis_client=redis
        )

    assert "already consumed" in str(exc_info.value) or "Replay" in str(
        exc_info.value
    )


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
        await gfa_verify_and_consume(
            seal, "execute_trade", params, redis_client=redis
        )
        is True
    )

    # Replay attempt fails
    with pytest.raises(GFASymbolicGovernorViolation) as exc_info:
        await gfa_verify_and_consume(
            seal, "execute_trade", params, redis_client=redis
        )

    assert "already consumed" in str(exc_info.value) or "Replay" in str(
        exc_info.value
    )

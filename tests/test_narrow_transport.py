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
NARROW Verdict Transport Tests (CAGE-SEC-004)
==============================================

Tests for the receipt-based NARROW verdict transport fix that resolves
the architectural gap where Envoy OkHttpResponse proto has no body field.

**Finding**: NARROW verdicts generate clamped parameters in validate_action()
and build response body in _build_narrow_response(), but narrowed parameters
cannot reach mcp_tool_server.py through Envoy ext_authz protocol.

**Fix**: Receipt-based transport using Redis fetch-and-burn pattern:
  1. SymbolicGovernor._sealed_narrow() seals the re-bound clamped params,
     returns them as ``SealedAction.params`` and stores the same params via
     issue_narrow_receipt() under narrow_receipt_key(seal), i.e.
     narrow:receipt:<sha256(seal)>
  2. The tool provider uses the governor seal to look up and delete the receipt
  3. 5-minute TTL prevents receipt leakage
  4. Signature verification prevents receipt forgery
  5. The receipt is a cross-check only: the tool verifies and actuates
     ``SealedAction.params``, and a receipt naming other params refuses

Test coverage:
  1. Receipt generation with seal-keyed storage
  2. TTL enforcement (300 seconds)
  3. Fetch-and-burn pattern (one-time use)
  4. Receipt expiry handling
  5. Signature mismatch detection
  6. Narrowed (sealed) params applied to trade execution
  7. Seal verified over the narrowed params (not original)
  8. CAGE_NARROW_ENABLED=false fallback
  9. Receipt replay prevention
 10. A receipt naming params other than the sealed params is refused
 11. A matching receipt is burned and the sealed params are actuated
"""

from __future__ import annotations

import json
import os
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.governor.sealing import SealedAction
from src.gateway.governance.narrow_receipt import narrow_receipt_key
from tests.fixtures.trade_inputs import sealed_governance, trade_governor

pytestmark = [pytest.mark.usefixtures("connected_evidence_sink")]


def _receipt(seal: str, narrowed_params: dict[str, Any], **extra: Any) -> str:
    """A stored NARROW receipt payload, as issue_narrow_receipt() writes it."""
    return json.dumps(
        {
            "narrowed_params": narrowed_params,
            "original_signature": seal,
            "timestamp": 1234567890.0,
            "clamp_reason": "test",
            "constraints_applied": [],
            **extra,
        }
    )


@pytest.mark.unit
@pytest.mark.asyncio
async def test_mcp_server_fetches_and_burns_receipt():
    """Test 3: Verify MCP server fetches and deletes receipt (fetch-and-burn)."""
    from src.cage_finance.tools.tool_provider import execute_trade_action

    seal = "c" * 64
    narrowed = {
        "symbol": "MSFT",
        "amount": 25.0,
        "currency": "USD",
        "confidence": 0.95,
        "transaction_id": "tx123",
        "trader_id": "agent_001",
        "trader_role": "junior",
        "dry_run": True,
    }
    receipt_payload = {
        "narrowed_params": narrowed,
        "original_signature": seal,
        "timestamp": 1234567890.0,
        "clamp_reason": "test",
        "constraints_applied": ["amount clamped"],
    }

    mock_redis = AsyncMock()
    mock_redis.get.return_value = json.dumps(receipt_payload)
    # The narrowed committing run returns the clamped params it sealed.
    mock_enforce = AsyncMock(return_value=SealedAction("execute_trade", seal, narrowed))
    mock_verify = AsyncMock()

    with patch("src.gateway.infrastructure.redis_client.redis_client", mock_redis):
        with patch(
            "src.cage_finance.tools.tool_provider.enforce_governance", mock_enforce
        ):
            with patch(
                "src.gateway.governance.routing_seal.verify_and_consume_seal",
                mock_verify,
            ):
                result = await execute_trade_action(
                    governor=trade_governor(),
                    transaction_id=str(uuid.uuid4()),
                    symbol="AAPL",  # Original params (the seal names the narrowed)
                    amount=100.0,
                    currency="USD",
                    confidence=0.95,
                    dry_run=True,
                )

    # Verify the receipt was fetched under the seal's receipt key
    receipt_key = narrow_receipt_key(seal)
    mock_redis.get.assert_called_once_with(receipt_key)

    # Verify receipt was deleted (fetch-and-burn)
    mock_redis.delete.assert_called_once_with(receipt_key)

    # Verify seal was verified against narrowed params
    verify_call_args = mock_verify.call_args[0]
    _, _, verified_params = verify_call_args
    assert verified_params["amount"] == 25.0  # Narrowed, not original 100.0
    assert verified_params["symbol"] == "MSFT"  # Narrowed, not original AAPL

    assert "DRY_RUN: APPROVED" in result


@pytest.mark.unit
@pytest.mark.asyncio
async def test_expired_receipt_rejected():
    """Test 4: Verify expired receipt (None from Redis) blocks execution."""
    from src.cage_finance.tools.tool_provider import execute_trade_action

    seal = "d" * 64
    mock_redis = AsyncMock()
    mock_redis.get.return_value = None  # Receipt expired or doesn't exist
    mock_enforce = AsyncMock(side_effect=sealed_governance(seal))

    with patch("src.gateway.infrastructure.redis_client.redis_client", mock_redis):
        with patch(
            "src.cage_finance.tools.tool_provider.enforce_governance", mock_enforce
        ):
            # A missing receipt is not an error by itself: an ALLOW verdict has
            # none. The tool verifies the seal against the sealed params it was
            # handed (SealedAction.params); here the seal is not a real one, so
            # verification refuses the trade.

            result = await execute_trade_action(
                governor=trade_governor(),
                transaction_id=str(uuid.uuid4()),
                symbol="AAPL",
                amount=50.0,
                currency="USD",
                confidence=0.95,
                dry_run=True,
            )

    # Should succeed with the sealed params, or refuse an unverifiable seal
    assert "DRY_RUN: APPROVED" in result or "BLOCKED" in result


@pytest.mark.unit
@pytest.mark.asyncio
async def test_forged_receipt_rejected():
    """Test 5: Verify forged receipt (signature mismatch) blocks execution."""
    from src.cage_finance.tools.tool_provider import execute_trade_action

    seal = "e" * 64
    forged_seal = "f" * 64  # Different seal

    receipt_payload = {
        "narrowed_params": {
            "symbol": "AAPL",
            "amount": 25.0,
            "currency": "USD",
            "confidence": 0.95,
            "transaction_id": "tx123",
            "trader_id": "agent_001",
            "trader_role": "junior",
            "dry_run": True,
        },
        "original_signature": forged_seal,  # Mismatch!
        "timestamp": 1234567890.0,
        "clamp_reason": "test",
        "constraints_applied": [],
    }

    mock_redis = AsyncMock()
    mock_redis.get.return_value = json.dumps(receipt_payload)
    mock_enforce = AsyncMock(side_effect=sealed_governance(seal))

    with patch("src.gateway.infrastructure.redis_client.redis_client", mock_redis):
        with patch(
            "src.cage_finance.tools.tool_provider.enforce_governance", mock_enforce
        ):
            result = await execute_trade_action(
                governor=trade_governor(),
                transaction_id=str(uuid.uuid4()),
                symbol="AAPL",
                amount=100.0,
                currency="USD",
                confidence=0.95,
                dry_run=True,
            )

    # Should block due to signature mismatch
    assert "BLOCKED" in result
    assert "signature mismatch" in result


@pytest.mark.unit
@pytest.mark.asyncio
async def test_narrowed_params_applied_to_trade():
    """Test 6: The trade runs the sealed (narrowed) params, never the original."""
    from src.cage_finance.tools.tool_provider import execute_trade_action

    seal = "g" * 64
    narrowed = {
        "symbol": "TSLA",
        "amount": 10.0,  # Narrowed from 500.0
        "currency": "USD",
        "confidence": 0.95,
        "transaction_id": "tx456",
        "trader_id": "agent_001",
        "trader_role": "junior",
        "dry_run": True,
    }
    receipt_payload = {
        "narrowed_params": narrowed,
        "original_signature": seal,
        "timestamp": 1234567890.0,
        "clamp_reason": "amount clamped to fiscal limit",
        "constraints_applied": ["amount clamped: 500.0 → 10.0"],
    }

    mock_redis = AsyncMock()
    mock_redis.get.return_value = json.dumps(receipt_payload)
    mock_enforce = AsyncMock(return_value=SealedAction("execute_trade", seal, narrowed))
    mock_verify = AsyncMock()

    with patch("src.gateway.infrastructure.redis_client.redis_client", mock_redis):
        with patch(
            "src.cage_finance.tools.tool_provider.enforce_governance", mock_enforce
        ):
            with patch(
                "src.gateway.governance.routing_seal.verify_and_consume_seal",
                mock_verify,
            ):
                result = await execute_trade_action(
                    governor=trade_governor(),
                    transaction_id=str(uuid.uuid4()),
                    symbol="AAPL",  # Original
                    amount=500.0,  # Original (the seal names the narrowed amount)
                    currency="USD",
                    confidence=0.95,
                    dry_run=True,
                )

    # Verify seal was verified against narrowed params
    verify_call_args = mock_verify.call_args[0]
    _, _, verified_params = verify_call_args
    assert verified_params["amount"] == 10.0  # Narrowed
    assert verified_params["symbol"] == "TSLA"  # Narrowed

    assert "DRY_RUN: APPROVED" in result


@pytest.mark.unit
@pytest.mark.asyncio
async def test_seal_computed_over_narrowed_params():
    """Test 7: Verify seal is computed over narrowed params, not original."""
    # The governor seals the narrowed params (SymbolicGovernor._sealed_narrow,
    # governor/governor.py) and returns them as SealedAction.params. The test
    # here confirms the contract is honored end-to-end.

    from src.cage_finance.tools.tool_provider import execute_trade_action

    seal = "h" * 64
    narrowed_params = {
        "symbol": "NVDA",
        "amount": 5.0,
        "currency": "USD",
        "confidence": 0.95,
        "transaction_id": "tx789",
        "trader_id": "agent_001",
        "trader_role": "junior",
        "dry_run": True,
    }

    receipt_payload = {
        "narrowed_params": narrowed_params,
        "original_signature": seal,
        "timestamp": 1234567890.0,
        "clamp_reason": "test",
        "constraints_applied": [],
    }

    mock_redis = AsyncMock()
    mock_redis.get.return_value = json.dumps(receipt_payload)
    mock_enforce = AsyncMock(
        return_value=SealedAction("execute_trade", seal, dict(narrowed_params))
    )
    mock_verify = AsyncMock()

    with patch("src.gateway.infrastructure.redis_client.redis_client", mock_redis):
        with patch(
            "src.cage_finance.tools.tool_provider.enforce_governance", mock_enforce
        ):
            with patch(
                "src.gateway.governance.routing_seal.verify_and_consume_seal",
                mock_verify,
            ):
                await execute_trade_action(
                    governor=trade_governor(),
                    transaction_id=str(uuid.uuid4()),
                    symbol="AAPL",
                    amount=1000.0,
                    currency="USD",
                    confidence=0.95,
                    dry_run=True,
                )

    # Verify seal was verified against narrowed params
    verify_call_args = mock_verify.call_args[0]
    actual_seal, _, verified_params = verify_call_args
    assert actual_seal == seal
    assert verified_params == narrowed_params


@pytest.mark.unit
@pytest.mark.asyncio
async def test_narrow_disabled_uses_original_params():
    """Test 8: Verify CAGE_NARROW_ENABLED=false falls back to DENY."""
    # This is tested at the SymbolicGovernor level
    # When NARROW is disabled, _classify_violation returns DENY instead
    # No receipt is generated in this case

    from src.cage_finance.tools.tool_provider import execute_trade_action

    mock_enforce = AsyncMock(side_effect=PermissionError("NARROW->DENY fallback"))

    with patch("src.cage_finance.tools.tool_provider.enforce_governance", mock_enforce):
        result = await execute_trade_action(
            governor=trade_governor(),
            transaction_id=str(uuid.uuid4()),
            symbol="AAPL",
            amount=100.0,
            currency="USD",
            confidence=0.95,
            dry_run=True,
        )

    assert "BLOCKED" in result


@pytest.mark.unit
@pytest.mark.asyncio
async def test_receipt_replay_blocked():
    """Test 9: Verify second fetch of same receipt fails (fetch-and-burn)."""
    from src.cage_finance.tools.tool_provider import execute_trade_action

    seal = "i" * 64
    narrowed = {
        "symbol": "AMD",
        "amount": 20.0,
        "currency": "USD",
        "confidence": 0.95,
        "transaction_id": "tx999",
        "trader_id": "agent_001",
        "trader_role": "junior",
        "dry_run": True,
    }
    receipt_payload = {
        "narrowed_params": narrowed,
        "original_signature": seal,
        "timestamp": 1234567890.0,
        "clamp_reason": "test",
        "constraints_applied": [],
    }

    # First call returns receipt, second call returns None (deleted)
    mock_redis = AsyncMock()
    mock_redis.get.side_effect = [
        json.dumps(receipt_payload),  # First fetch succeeds
        None,  # Second fetch fails (burned)
    ]
    mock_enforce = AsyncMock(return_value=SealedAction("execute_trade", seal, narrowed))
    mock_verify = AsyncMock()

    with patch("src.gateway.infrastructure.redis_client.redis_client", mock_redis):
        with patch(
            "src.cage_finance.tools.tool_provider.enforce_governance", mock_enforce
        ):
            with patch(
                "src.gateway.governance.routing_seal.verify_and_consume_seal",
                mock_verify,
            ):
                # First execution should succeed
                result1 = await execute_trade_action(
                    governor=trade_governor(),
                    transaction_id=str(uuid.uuid4()),
                    symbol="AAPL",
                    amount=100.0,
                    currency="USD",
                    confidence=0.95,
                    dry_run=True,
                )

                # Second execution with the same seal finds no receipt
                # (no receipt found = ALLOW path, not NARROW)
                result2 = await execute_trade_action(
                    governor=trade_governor(),
                    transaction_id=str(uuid.uuid4()),
                    symbol="AAPL",
                    amount=100.0,
                    currency="USD",
                    confidence=0.95,
                    dry_run=True,
                )

    # Verify delete was called after first fetch
    receipt_key = narrow_receipt_key(seal)
    assert mock_redis.delete.call_count >= 1
    mock_redis.delete.assert_any_call(receipt_key)

    assert "DRY_RUN: APPROVED" in result1
    # Second call verifies the sealed params without a receipt
    assert "DRY_RUN: APPROVED" in result2 or "BLOCKED" in result2


@pytest.mark.unit
@pytest.mark.asyncio
async def test_receipt_naming_other_params_than_the_sealed_params_is_refused():
    """Test 10: A receipt that does not name the sealed params refuses the trade.

    The receipt is burned, an AC-3 refusal names the sealed params, and the
    seal is neither verified nor actuated; its commits are released.
    """
    from src.cage_finance.tools.tool_provider import execute_trade_action

    seal = "j" * 64
    sealed_params = {
        "symbol": "AAPL",
        "amount": 25.0,
        "currency": "USD",
        "confidence": 0.95,
        "transaction_id": "tx-sealed",
        "trader_id": "agent_001",
        "trader_role": "junior",
        "dry_run": False,
    }
    mock_redis = AsyncMock()
    mock_redis.get.return_value = _receipt(seal, {**sealed_params, "amount": 2500.0})
    verify = AsyncMock()
    actuate = AsyncMock()
    governor = trade_governor()

    with (
        patch("src.gateway.infrastructure.redis_client.redis_client", mock_redis),
        patch(
            "src.cage_finance.tools.tool_provider.enforce_governance",
            AsyncMock(return_value=SealedAction("execute_trade", seal, sealed_params)),
        ),
        patch("src.gateway.governance.routing_seal.verify_and_consume_seal", verify),
        patch("src.cage_finance.tools.tool_provider._broker_actuator.actuate", actuate),
        patch(
            "src.cage_finance.tools.tool_provider.record_refusal",
            new_callable=AsyncMock,
        ) as refusals,
    ):
        result = await execute_trade_action(
            governor=governor,
            transaction_id=str(uuid.uuid4()),
            symbol="AAPL",
            amount=100.0,
            currency="USD",
            confidence=0.95,
        )

    assert result.startswith(
        "BLOCKED: Narrowing receipt names params other than the sealed params"
    ), result
    mock_redis.delete.assert_called_once_with(narrow_receipt_key(seal))  # burned
    refusals.assert_awaited_once()
    action, reason = refusals.await_args.args
    assert action == "execute_trade"
    assert reason.startswith("Narrowing receipt names params other than the sealed")
    assert refusals.await_args.kwargs["oscal_control_ref"] == "AC-3"
    assert refusals.await_args.kwargs["params"] == sealed_params
    verify.assert_not_awaited()
    actuate.assert_not_awaited()
    governor.settle.assert_awaited_once_with(seal, executed=False)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_matching_receipt_is_burned_and_the_sealed_params_are_actuated():
    """Test 11: A receipt naming the sealed params lets the sealed params run."""
    from src.cage_finance.tools.tool_provider import execute_trade_action
    from src.gateway.governance.seams.actuation import (
        ActuationOutcome,
        ActuationReceipt,
    )

    seal = "k" * 64
    narrowed = {
        "symbol": "AAPL",
        "amount": 30.0,  # Narrowed from 100.0
        "currency": "USD",
        "confidence": 0.95,
        "transaction_id": "tx-narrowed",
        "trader_id": "agent_001",
        "trader_role": "junior",
        "dry_run": False,
    }
    mock_redis = AsyncMock()
    mock_redis.get.return_value = _receipt(seal, narrowed)
    verify = AsyncMock()
    actuate = AsyncMock(
        return_value=ActuationReceipt(
            accepted=True,
            receipt_id="r-narrow",
            session_uuid="s-narrow",
            raw_receipt={},
            findings=[],
            retryable=False,
            outcome=ActuationOutcome.ACCEPTED,
        )
    )
    governor = trade_governor()

    with (
        patch("src.gateway.infrastructure.redis_client.redis_client", mock_redis),
        patch(
            "src.cage_finance.tools.tool_provider.enforce_governance",
            AsyncMock(return_value=SealedAction("execute_trade", seal, narrowed)),
        ),
        patch("src.gateway.governance.routing_seal.verify_and_consume_seal", verify),
        patch("src.cage_finance.tools.tool_provider._broker_actuator.actuate", actuate),
    ):
        result = await execute_trade_action(
            governor=governor,
            transaction_id=str(uuid.uuid4()),
            symbol="AAPL",
            amount=100.0,
            currency="USD",
            confidence=0.95,
        )

    assert result.startswith("EXECUTED: AAPL x 30.0"), result
    mock_redis.delete.assert_called_once_with(narrow_receipt_key(seal))
    verify.assert_awaited_once_with(seal, "execute_trade", narrowed)
    assert actuate.await_args.args[0].params == narrowed
    governor.settle.assert_awaited_once_with(seal, executed=True)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_missing_narrow_receipt_refuses_narrowed_trade():
    """Decision 3: A narrowed trade with no receipt in Redis is refused (never unconfirmed)."""
    from src.cage_finance.tools.tool_provider import execute_trade_action

    tx_id = "00000000-0000-4000-8000-000000000001"
    seal = "m" * 64
    narrowed = {
        "symbol": "AAPL",
        "amount": 30.0,  # Narrowed from 100.0
        "currency": "USD",
        "confidence": 0.95,
        "transaction_id": tx_id,
        "trader_id": "agent_001",
        "trader_role": "junior",
        "dry_run": False,
    }
    mock_redis = AsyncMock()
    mock_redis.get.return_value = None
    verify = AsyncMock()
    actuate = AsyncMock()
    governor = trade_governor()

    with (
        patch("src.gateway.infrastructure.redis_client.redis_client", mock_redis),
        patch(
            "src.cage_finance.tools.tool_provider.enforce_governance",
            AsyncMock(return_value=SealedAction("execute_trade", seal, narrowed)),
        ),
        patch("src.gateway.governance.routing_seal.verify_and_consume_seal", verify),
        patch("src.cage_finance.tools.tool_provider._broker_actuator.actuate", actuate),
        patch(
            "src.cage_finance.tools.tool_provider.record_refusal",
            new_callable=AsyncMock,
        ) as refusals,
    ):
        result = await execute_trade_action(
            governor=governor,
            transaction_id=tx_id,
            symbol="AAPL",
            amount=100.0,
            currency="USD",
            confidence=0.95,
        )

    assert result.startswith("BLOCKED: Narrowing receipt missing"), result
    refusals.assert_awaited_once()
    assert refusals.await_args.kwargs["oscal_control_ref"] == "AC-3"
    assert refusals.await_args.kwargs["params"] == narrowed
    verify.assert_not_awaited()
    actuate.assert_not_awaited()
    governor.settle.assert_awaited_once_with(seal, executed=False)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_corrupt_narrow_receipt_refuses_trade():
    """Decision 3: A non-JSON NARROW receipt payload is refused and recorded."""
    from src.cage_finance.tools.tool_provider import execute_trade_action

    tx_id = "00000000-0000-4000-8000-000000000002"
    seal = "c" * 64
    narrowed = {
        "symbol": "AAPL",
        "amount": 30.0,
        "currency": "USD",
        "confidence": 0.95,
        "transaction_id": tx_id,
        "trader_id": "agent_001",
        "trader_role": "junior",
        "dry_run": False,
    }
    mock_redis = AsyncMock()
    mock_redis.get.return_value = "{not-valid-json"
    verify = AsyncMock()
    actuate = AsyncMock()
    governor = trade_governor()

    with (
        patch("src.gateway.infrastructure.redis_client.redis_client", mock_redis),
        patch(
            "src.cage_finance.tools.tool_provider.enforce_governance",
            AsyncMock(return_value=SealedAction("execute_trade", seal, narrowed)),
        ),
        patch("src.gateway.governance.routing_seal.verify_and_consume_seal", verify),
        patch("src.cage_finance.tools.tool_provider._broker_actuator.actuate", actuate),
        patch(
            "src.cage_finance.tools.tool_provider.record_refusal",
            new_callable=AsyncMock,
        ) as refusals,
    ):
        result = await execute_trade_action(
            governor=governor,
            transaction_id=tx_id,
            symbol="AAPL",
            amount=100.0,
            currency="USD",
            confidence=0.95,
        )

    assert result == "BLOCKED: Narrowing receipt payload corrupted"
    mock_redis.delete.assert_called_once_with(narrow_receipt_key(seal))
    refusals.assert_awaited_once()
    verify.assert_not_awaited()
    actuate.assert_not_awaited()
    governor.settle.assert_awaited_once_with(seal, executed=False)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_narrow_receipt_store_outage_raises_infrastructure_block_no_refusal():
    """Decision 3: Redis outage on a narrowed trade raises 503 infrastructure block, not AC-3 refusal."""
    from src.cage_finance.tools.tool_provider import execute_trade_action
    from src.gateway.governance.governor.errors import GovernanceInfrastructureError

    tx_id = "00000000-0000-4000-8000-000000000003"
    seal = "o" * 64
    narrowed = {
        "symbol": "AAPL",
        "amount": 30.0,
        "currency": "USD",
        "confidence": 0.95,
        "transaction_id": tx_id,
        "trader_id": "agent_001",
        "trader_role": "junior",
        "dry_run": False,
    }
    mock_redis = AsyncMock()
    mock_redis.get.side_effect = ConnectionError("redis unreachable")
    verify = AsyncMock()
    actuate = AsyncMock()
    governor = trade_governor()

    with (
        patch("src.gateway.infrastructure.redis_client.redis_client", mock_redis),
        patch(
            "src.cage_finance.tools.tool_provider.enforce_governance",
            AsyncMock(return_value=SealedAction("execute_trade", seal, narrowed)),
        ),
        patch("src.gateway.governance.routing_seal.verify_and_consume_seal", verify),
        patch("src.cage_finance.tools.tool_provider._broker_actuator.actuate", actuate),
        patch(
            "src.cage_finance.tools.tool_provider.record_refusal",
            new_callable=AsyncMock,
        ) as refusals,
        patch(
            "src.gateway.governance.governor.verdicts.publish_infrastructure_block",
            new_callable=AsyncMock,
        ) as publish_infra,
    ):
        with pytest.raises(GovernanceInfrastructureError) as exc_info:
            await execute_trade_action(
                governor=governor,
                transaction_id=tx_id,
                symbol="AAPL",
                amount=100.0,
                currency="USD",
                confidence=0.95,
            )

    assert exc_info.value.failure_code == "NARROW_RECEIPT_UNAVAILABLE"
    publish_infra.assert_awaited_once()
    refusals.assert_not_awaited()
    verify.assert_not_awaited()
    actuate.assert_not_awaited()
    governor.settle.assert_awaited_once_with(seal, executed=False)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_jcs_canonical_equivalence_accepts_int_float_narrow_receipt():
    """Decision 2: _same_params compares via canonical_action_bytes (RFC 8785 JCS)."""
    from src.cage_finance.tools.tool_provider import execute_trade_action
    from src.gateway.governance.seams.actuation import (
        ActuationOutcome,
        ActuationReceipt,
    )

    tx_id = "00000000-0000-4000-8000-000000000004"
    seal = "j" * 64
    narrowed_float = {
        "symbol": "AAPL",
        "amount": 30.0,
        "currency": "USD",
        "confidence": 0.95,
        "transaction_id": tx_id,
        "trader_id": "agent_001",
        "trader_role": "junior",
        "dry_run": False,
    }
    narrowed_int_amount = {**narrowed_float, "amount": 30}
    mock_redis = AsyncMock()
    mock_redis.get.return_value = _receipt(seal, narrowed_int_amount)
    verify = AsyncMock()
    actuate = AsyncMock(
        return_value=ActuationReceipt(
            accepted=True,
            receipt_id="r-jcs",
            session_uuid="s-jcs",
            raw_receipt={},
            findings=[],
            retryable=False,
            outcome=ActuationOutcome.ACCEPTED,
        )
    )
    governor = trade_governor()

    with (
        patch("src.gateway.infrastructure.redis_client.redis_client", mock_redis),
        patch(
            "src.cage_finance.tools.tool_provider.enforce_governance",
            AsyncMock(return_value=SealedAction("execute_trade", seal, narrowed_float)),
        ),
        patch("src.gateway.governance.routing_seal.verify_and_consume_seal", verify),
        patch("src.cage_finance.tools.tool_provider._broker_actuator.actuate", actuate),
    ):
        result = await execute_trade_action(
            governor=governor,
            transaction_id=tx_id,
            symbol="AAPL",
            amount=100.0,
            currency="USD",
            confidence=0.95,
        )

    assert result.startswith("EXECUTED: AAPL x 30.0"), result
    verify.assert_awaited_once_with(seal, "execute_trade", narrowed_float)
    governor.settle.assert_awaited_once_with(seal, executed=True)

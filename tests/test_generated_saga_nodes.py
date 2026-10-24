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
"""Unit tests for src/gateway/governance/generated_saga_nodes.py.

All tests are marked pytest.mark.local and use only mocks — no live Redis,
OPA, or MCP connections required.
"""

from __future__ import annotations

import asyncio
import hashlib
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.gateway.infrastructure.mcp_client import MCPToolExecutionError

# ---------------------------------------------------------------------------
# Helpers — build minimal AgentState dicts for tests
# ---------------------------------------------------------------------------


def _make_ledger_entry(
    *,
    sequence_id: int = 0,
    uca_ref: str = "UCA-4",
    action: str = "execute_trade",
    status: str = "COMPLETED",
    idempotency_key: str = "key-abc",
    context_data: dict | None = None,
) -> dict[str, Any]:
    return {
        "sequence_id": sequence_id,
        "timestamp": "2026-01-01T00:00:00+00:00",
        "uca_ref": uca_ref,
        "action": action,
        "idempotency_key": idempotency_key,
        "status": status,
        "context_data": context_data or {"transaction_id": "tx-001", "amount": 100},
    }


def _make_state(
    transactions: list[dict] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    base: dict[str, Any] = {
        "completed_transactions": transactions or [],
        "amount": 500,
        "symbol": "AAPL",
        "account_id": "acct-1",
        "trader_role": "retail",
        "approval_token": "tok-xyz",
    }
    base.update(extra)
    return base


# ---------------------------------------------------------------------------
# Import the module under test (after stubs are in place)
# ---------------------------------------------------------------------------


def _import_module():
    """Import generated_saga_nodes with GatewayMCPClient stubbed."""
    mock_client_cls = MagicMock()
    mock_client_cls.return_value = MagicMock()
    with patch.dict(
        "sys.modules",
        {
            "src.gateway.infrastructure.mcp_client": MagicMock(
                GatewayMCPClient=mock_client_cls
            ),
        },
    ):
        import importlib
        import sys

        # Force a fresh import if already loaded (to get our patched version)
        mod_name = "src.cage_finance.stpa.saga_nodes"
        if mod_name in sys.modules:
            return sys.modules[mod_name]
        return importlib.import_module(mod_name)


# Import once at module level — GatewayMCPClient is already lazily initialised
# so we can patch _get_mcp_client instead of intercepting the import.
import src.cage_finance.stpa.saga_nodes as saga  # noqa: E402

# ===========================================================================
# TestDeriveIdempotencyKey
# ===========================================================================


@pytest.mark.local
class TestDeriveIdempotencyKey:
    """Pure-function tests for _derive_idempotency_key."""

    def test_output_is_32_characters(self) -> None:
        key = saga._derive_idempotency_key("tx-001", "reverse_trade")
        assert len(key) == 32

    def test_output_is_deterministic(self) -> None:
        key1 = saga._derive_idempotency_key("tx-abc", "reverse_trade")
        key2 = saga._derive_idempotency_key("tx-abc", "reverse_trade")
        assert key1 == key2

    def test_different_tx_ids_produce_different_keys(self) -> None:
        key1 = saga._derive_idempotency_key("tx-001", "reverse_trade")
        key2 = saga._derive_idempotency_key("tx-002", "reverse_trade")
        assert key1 != key2

    def test_different_actions_produce_different_keys(self) -> None:
        key1 = saga._derive_idempotency_key("tx-001", "reverse_trade")
        key2 = saga._derive_idempotency_key("tx-001", "credit_account")
        assert key1 != key2

    def test_output_matches_manual_sha256(self) -> None:
        raw = "tx-xyz:reverse_trade"
        expected = hashlib.sha256(raw.encode()).hexdigest()[:32]
        assert saga._derive_idempotency_key("tx-xyz", "reverse_trade") == expected

    def test_empty_strings_produce_valid_key(self) -> None:
        key = saga._derive_idempotency_key("", "")
        assert len(key) == 32
        assert isinstance(key, str)


# ===========================================================================
# TestNextSequenceId
# ===========================================================================


@pytest.mark.local
class TestNextSequenceId:
    """Tests for _next_sequence_id helper."""

    def test_empty_state_returns_zero(self) -> None:
        state = _make_state(transactions=[])
        assert saga._next_sequence_id(state) == 0  # type: ignore[arg-type]

    def test_none_transactions_returns_zero(self) -> None:
        state = _make_state(transactions=None)
        assert saga._next_sequence_id(state) == 0  # type: ignore[arg-type]

    def test_single_entry_returns_next(self) -> None:
        state = _make_state(transactions=[_make_ledger_entry(sequence_id=5)])
        assert saga._next_sequence_id(state) == 6  # type: ignore[arg-type]

    def test_multiple_entries_returns_max_plus_one(self) -> None:
        txns = [
            _make_ledger_entry(sequence_id=3),
            _make_ledger_entry(sequence_id=7),
            _make_ledger_entry(sequence_id=1),
        ]
        state = _make_state(transactions=txns)
        assert saga._next_sequence_id(state) == 8  # type: ignore[arg-type]

    def test_sequence_starts_at_zero_when_all_zero(self) -> None:
        state = _make_state(transactions=[_make_ledger_entry(sequence_id=0)])
        assert saga._next_sequence_id(state) == 1  # type: ignore[arg-type]


# ===========================================================================
# TestForwardExecuteTradeNodeUCA4
# ===========================================================================


@pytest.mark.local
class TestForwardExecuteTradeNodeUCA4:
    """Tests for forward_execute_trade_node_uca_4 generator function."""

    _TX_ID = "5f0c6f7e-9d43-4b8e-a1e2-3c4d5e6f7a8b"
    _EXECUTED = "EXECUTED: AAPL x 500 (Receipt ID: r-1)"

    def _trade_state(self, transactions: list[dict] | None = None) -> dict[str, Any]:
        return _make_state(
            transactions=transactions,
            currency="USD",
            side="buy",
            transaction_id=self._TX_ID,
        )

    def _expected_arguments(self) -> dict[str, Any]:
        return {
            "symbol": "AAPL",
            "amount": 500,
            "currency": "USD",
            "side": "buy",
            "transaction_id": self._TX_ID,
        }

    def _run_forward(
        self, state: dict, outcome: str | BaseException = _EXECUTED
    ) -> tuple[dict, dict, AsyncMock]:
        """Drive the generator to completion; return (yielded, returned, call_tool)."""
        call_tool = AsyncMock(side_effect=[outcome])
        client = MagicMock()
        client.call_tool = call_tool

        with (
            patch.object(saga, "_get_mcp_client", return_value=client),
            patch.object(saga, "_run_async", side_effect=asyncio.run),
        ):
            gen = saga.forward_execute_trade_node_uca_4(state)  # type: ignore[arg-type]
            yielded = next(gen)
            try:
                next(gen)
            except StopIteration as exc:
                returned: dict = exc.value
            else:
                pytest.fail("forward node yielded more than the PENDING intent")

        return yielded, returned, call_tool

    def test_first_yield_is_pending_entry(self) -> None:
        yielded, _, _ = self._run_forward(self._trade_state())

        assert "completed_transactions" in yielded
        entries = yielded["completed_transactions"]
        assert len(entries) == 1
        assert entries[0]["status"] == "PENDING"

    def test_pending_entry_has_correct_uca_ref(self) -> None:
        yielded, _, _ = self._run_forward(self._trade_state())

        entry = yielded["completed_transactions"][0]
        assert entry["uca_ref"] == "UCA-4"

    def test_pending_entry_has_correct_action(self) -> None:
        yielded, _, _ = self._run_forward(self._trade_state())

        entry = yielded["completed_transactions"][0]
        assert entry["action"] == "execute_trade"

    def test_pending_entry_has_empty_idempotency_key(self) -> None:
        """The compensation key is set on the COMPLETED entry, not the intent."""
        yielded, _, _ = self._run_forward(self._trade_state())

        entry = yielded["completed_transactions"][0]
        assert entry["idempotency_key"] == ""

    def test_pending_entry_records_the_request(self) -> None:
        """The intent carries what is about to be sent, for reconciliation."""
        yielded, _, _ = self._run_forward(self._trade_state())

        entry = yielded["completed_transactions"][0]
        assert entry["context_data"] == self._expected_arguments()

    def test_only_the_declared_arguments_are_forwarded(self) -> None:
        """approval_token, account_id and any other state field stay behind."""
        _, _, call_tool = self._run_forward(self._trade_state())

        call_tool.assert_awaited_once_with(
            name="execute_trade_action", arguments=self._expected_arguments()
        )

    def test_return_value_is_completed_entry(self) -> None:
        _, returned, _ = self._run_forward(self._trade_state())

        assert "completed_transactions" in returned
        entries = returned["completed_transactions"]
        assert len(entries) == 1
        assert entries[0]["status"] == "COMPLETED"

    def test_completed_entry_key_derives_from_transaction_id(self) -> None:
        _, returned, _ = self._run_forward(self._trade_state())

        entry = returned["completed_transactions"][0]
        expected_key = saga._derive_idempotency_key(self._TX_ID, "reverse_trade")
        assert entry["idempotency_key"] == expected_key

    def test_completed_entry_context_data_records_parsed_outcome(self) -> None:
        _, returned, _ = self._run_forward(self._trade_state())

        entry = returned["completed_transactions"][0]
        assert entry["context_data"] == {
            **self._expected_arguments(),
            "outcome": "EXECUTED",
            "detail": "AAPL x 500 (Receipt ID: r-1)",
        }

    def test_refusal_is_recorded_as_its_outcome(self) -> None:
        _, returned, _ = self._run_forward(
            self._trade_state(), outcome="BLOCKED: governance refused"
        )

        context = returned["completed_transactions"][0]["context_data"]
        assert context["outcome"] == "BLOCKED"
        assert context["detail"] == "governance refused"

    def test_sequence_id_increments_from_existing_transactions(self) -> None:
        existing = [_make_ledger_entry(sequence_id=4)]
        yielded, _, _ = self._run_forward(self._trade_state(transactions=existing))

        pending = yielded["completed_transactions"][0]
        assert pending["sequence_id"] == 5

    def test_sequence_id_is_zero_for_empty_ledger(self) -> None:
        yielded, _, _ = self._run_forward(self._trade_state())

        pending = yielded["completed_transactions"][0]
        assert pending["sequence_id"] == 0

    def test_pending_entry_timestamp_is_iso_format(self) -> None:
        yielded, _, _ = self._run_forward(self._trade_state())

        ts = yielded["completed_transactions"][0]["timestamp"]
        # ISO 8601 strings contain 'T' and '+' or 'Z'
        assert "T" in ts

    def test_unknown_outcome_leaves_entry_pending(self) -> None:
        """An unknown outcome is neither resent nor marked COMPLETED (#514)."""
        unknown = saga.MCPToolOutcomeUnknownError(
            "execute_trade_action", "request sent, no result"
        )
        yielded, returned, call_tool = self._run_forward(
            self._trade_state(), outcome=unknown
        )

        assert call_tool.await_count == 1
        assert returned == {}
        ledger = yielded["completed_transactions"] + returned.get(
            "completed_transactions", []
        )
        assert [e["status"] for e in ledger] == ["PENDING"]
        assert ledger[0]["context_data"]["transaction_id"] == self._TX_ID

        routed = saga.saga_router_node(_make_state(transactions=ledger))  # type: ignore[arg-type]
        assert routed["safety_status"] == "ESCALATED"
        assert routed["next_step"] == "human_review"

    def test_tool_error_propagates_and_leaves_entry_pending(self) -> None:
        """A gateway tool error raises; the yielded PENDING entry persists."""
        call_tool = AsyncMock(
            side_effect=MCPToolExecutionError(
                "execute_trade_action", "Actuation outcome indeterminate"
            )
        )
        client = MagicMock()
        client.call_tool = call_tool

        with (
            patch.object(saga, "_get_mcp_client", return_value=client),
            patch.object(saga, "_run_async", side_effect=asyncio.run),
        ):
            gen = saga.forward_execute_trade_node_uca_4(self._trade_state())  # type: ignore[arg-type]
            yielded = next(gen)
            with pytest.raises(MCPToolExecutionError):
                next(gen)

        assert [e["status"] for e in yielded["completed_transactions"]] == ["PENDING"]
        assert call_tool.await_count == 1

    def test_server_bound_trader_fields_are_never_forwarded(self) -> None:
        """GHSA-w39v-5v7h-fxg9: the gateway binds who trades; a saga never sends it."""
        state = {**self._trade_state(), "trader_role": "senior", "trader_id": "desk-1"}

        _, _, call_tool = self._run_forward(state)

        call_tool.assert_awaited_once_with(
            name="execute_trade_action", arguments=self._expected_arguments()
        )


# ===========================================================================
# TestCompensateReverseTradeNodeUCA4
# ===========================================================================


@pytest.mark.local
class TestCompensateReverseTradeNodeUCA4:
    """Tests for compensate_reverse_trade_node_uca_4."""

    def test_no_completed_entries_returns_escalated(self) -> None:
        state = _make_state(transactions=[])
        result = saga.compensate_reverse_trade_node_uca_4(state)  # type: ignore[arg-type]
        assert result["safety_status"] == "ESCALATED"

    def test_only_pending_entries_returns_escalated(self) -> None:
        txns = [_make_ledger_entry(status="PENDING")]
        state = _make_state(transactions=txns)
        result = saga.compensate_reverse_trade_node_uca_4(state)  # type: ignore[arg-type]
        assert result["safety_status"] == "ESCALATED"

    def test_only_rolled_back_entries_returns_escalated(self) -> None:
        txns = [_make_ledger_entry(status="ROLLED_BACK")]
        state = _make_state(transactions=txns)
        result = saga.compensate_reverse_trade_node_uca_4(state)  # type: ignore[arg-type]
        assert result["safety_status"] == "ESCALATED"

    def test_completed_entry_returns_blocked(self) -> None:
        txns = [_make_ledger_entry(status="COMPLETED")]
        state = _make_state(transactions=txns)
        result = saga.compensate_reverse_trade_node_uca_4(state)  # type: ignore[arg-type]
        assert result["safety_status"] == "BLOCKED"

    def test_completed_entry_produces_rolled_back_ledger_entry(self) -> None:
        txns = [_make_ledger_entry(status="COMPLETED")]
        state = _make_state(transactions=txns)
        result = saga.compensate_reverse_trade_node_uca_4(state)  # type: ignore[arg-type]

        assert "completed_transactions" in result
        entries = result["completed_transactions"]
        assert len(entries) == 1
        assert entries[0]["status"] == "ROLLED_BACK"

    def test_rolled_back_entry_preserves_sequence_id(self) -> None:
        txns = [_make_ledger_entry(status="COMPLETED", sequence_id=7)]
        state = _make_state(transactions=txns)
        result = saga.compensate_reverse_trade_node_uca_4(state)  # type: ignore[arg-type]

        entry = result["completed_transactions"][0]
        assert entry["sequence_id"] == 7

    def test_rolled_back_entry_preserves_uca_ref(self) -> None:
        txns = [_make_ledger_entry(status="COMPLETED", uca_ref="UCA-4")]
        state = _make_state(transactions=txns)
        result = saga.compensate_reverse_trade_node_uca_4(state)  # type: ignore[arg-type]

        entry = result["completed_transactions"][0]
        assert entry["uca_ref"] == "UCA-4"

    def test_uses_most_recent_completed_entry(self) -> None:
        """When multiple COMPLETED entries exist, the most recent (last in list) wins."""
        txns = [
            _make_ledger_entry(
                status="COMPLETED",
                sequence_id=0,
                context_data={"transaction_id": "tx-old", "amount": 100},
            ),
            _make_ledger_entry(
                status="COMPLETED",
                sequence_id=1,
                context_data={"transaction_id": "tx-new", "amount": 200},
            ),
        ]
        state = _make_state(transactions=txns)
        result = saga.compensate_reverse_trade_node_uca_4(state)  # type: ignore[arg-type]

        # The compensating node picks the last COMPLETED in reversed order
        entry = result["completed_transactions"][0]
        assert entry["context_data"]["transaction_id"] == "tx-new"

    def test_rolled_back_timestamp_is_updated(self) -> None:
        """The ROLLED_BACK entry timestamp must differ from the original COMPLETED one."""
        txns = [_make_ledger_entry(status="COMPLETED")]
        state = _make_state(transactions=txns)
        result = saga.compensate_reverse_trade_node_uca_4(state)  # type: ignore[arg-type]

        entry = result["completed_transactions"][0]
        # Original timestamp in helper is 2026-01-01; new should be near now
        assert entry["timestamp"] != "2026-01-01T00:00:00+00:00"

    def test_non_uca4_entries_are_ignored(self) -> None:
        """A COMPLETED entry for a different UCA should be skipped."""
        txns = [
            _make_ledger_entry(
                status="COMPLETED", uca_ref="UCA-9", action="execute_trade"
            )
        ]
        state = _make_state(transactions=txns)
        result = saga.compensate_reverse_trade_node_uca_4(state)  # type: ignore[arg-type]
        assert result["safety_status"] == "ESCALATED"

    def test_non_execute_trade_entries_are_ignored(self) -> None:
        """A COMPLETED UCA-4 entry with a different action should be skipped."""
        txns = [
            _make_ledger_entry(
                status="COMPLETED", uca_ref="UCA-4", action="cancel_order"
            )
        ]
        state = _make_state(transactions=txns)
        result = saga.compensate_reverse_trade_node_uca_4(state)  # type: ignore[arg-type]
        assert result["safety_status"] == "ESCALATED"


# ===========================================================================
# TestSagaRouterNode
# ===========================================================================


@pytest.mark.local
class TestSagaRouterNode:
    """Tests for saga_router_node."""

    def test_empty_transactions_returns_blocked(self) -> None:
        state = _make_state(transactions=[])
        result = saga.saga_router_node(state)  # type: ignore[arg-type]
        assert result["safety_status"] == "BLOCKED"

    def test_none_transactions_returns_blocked(self) -> None:
        state = _make_state(transactions=None)
        result = saga.saga_router_node(state)  # type: ignore[arg-type]
        assert result["safety_status"] == "BLOCKED"

    def test_pending_entry_triggers_ghost_state_escalation(self) -> None:
        txns = [_make_ledger_entry(status="PENDING")]
        state = _make_state(transactions=txns)
        result = saga.saga_router_node(state)  # type: ignore[arg-type]

        assert result["safety_status"] == "ESCALATED"
        assert result["next_step"] == "human_review"

    def test_ghost_state_summary_mentions_pending_count(self) -> None:
        txns = [
            _make_ledger_entry(status="PENDING", sequence_id=0),
            _make_ledger_entry(status="PENDING", sequence_id=1),
        ]
        state = _make_state(transactions=txns)
        result = saga.saga_router_node(state)  # type: ignore[arg-type]

        assert "2" in result.get("governance_summary", "")

    def test_completed_uca4_execute_trade_delegates_to_compensate(self) -> None:
        txns = [
            _make_ledger_entry(
                status="COMPLETED", uca_ref="UCA-4", action="execute_trade"
            )
        ]
        state = _make_state(transactions=txns)
        result = saga.saga_router_node(state)  # type: ignore[arg-type]

        # compensate_reverse_trade_node_uca_4 returns BLOCKED on success
        assert result["safety_status"] == "BLOCKED"
        assert "completed_transactions" in result

    def test_unhandled_uca_escalates(self) -> None:
        txns = [
            _make_ledger_entry(
                status="COMPLETED", uca_ref="UCA-99", action="mystery_action"
            )
        ]
        state = _make_state(transactions=txns)
        result = saga.saga_router_node(state)  # type: ignore[arg-type]

        assert result["safety_status"] == "ESCALATED"
        assert result["next_step"] == "human_review"
        assert "UCA-99" in result.get("governance_summary", "")

    def test_unhandled_uca_includes_action_in_summary(self) -> None:
        txns = [
            _make_ledger_entry(
                status="COMPLETED", uca_ref="UCA-99", action="mystery_action"
            )
        ]
        state = _make_state(transactions=txns)
        result = saga.saga_router_node(state)  # type: ignore[arg-type]

        assert "mystery_action" in result.get("governance_summary", "")

    def test_lifo_ordering_processes_highest_sequence_id_first(self) -> None:
        """LIFO: the entry with the highest sequence_id is rolled back first."""
        txns = [
            _make_ledger_entry(
                status="COMPLETED",
                sequence_id=0,
                uca_ref="UCA-4",
                action="execute_trade",
                context_data={"transaction_id": "tx-old", "amount": 100},
            ),
            _make_ledger_entry(
                status="COMPLETED",
                sequence_id=5,
                uca_ref="UCA-4",
                action="execute_trade",
                context_data={"transaction_id": "tx-new", "amount": 200},
            ),
        ]
        state = _make_state(transactions=txns)
        result = saga.saga_router_node(state)  # type: ignore[arg-type]

        # The highest-sequence entry (tx-new, seq=5) is processed
        assert result["safety_status"] == "BLOCKED"
        rolled_back_entry = result["completed_transactions"][0]
        assert rolled_back_entry["context_data"]["transaction_id"] == "tx-new"

    def test_pending_entry_takes_priority_over_completed(self) -> None:
        """If any PENDING exists alongside COMPLETED, ghost-state path fires first."""
        txns = [
            _make_ledger_entry(status="PENDING", sequence_id=0),
            _make_ledger_entry(
                status="COMPLETED",
                sequence_id=1,
                uca_ref="UCA-4",
                action="execute_trade",
            ),
        ]
        state = _make_state(transactions=txns)
        result = saga.saga_router_node(state)  # type: ignore[arg-type]

        assert result["safety_status"] == "ESCALATED"
        assert result["next_step"] == "human_review"

    def test_all_rolled_back_entries_returns_blocked(self) -> None:
        """No COMPLETED entries left to roll back → BLOCKED."""
        txns = [_make_ledger_entry(status="ROLLED_BACK", sequence_id=0)]
        state = _make_state(transactions=txns)
        result = saga.saga_router_node(state)  # type: ignore[arg-type]

        assert result["safety_status"] == "BLOCKED"

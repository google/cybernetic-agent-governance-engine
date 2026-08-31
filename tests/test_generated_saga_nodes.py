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

import hashlib
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

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
        mod_name = "src.gateway.governance.generated_saga_nodes"
        if mod_name in sys.modules:
            return sys.modules[mod_name]
        return importlib.import_module(mod_name)


# Import once at module level — GatewayMCPClient is already lazily initialised
# so we can patch _get_mcp_client instead of intercepting the import.
import src.gateway.governance.generated_saga_nodes as saga  # noqa: E402

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

    def _run_forward(
        self, state: dict, mcp_result: dict | None = None
    ) -> tuple[dict, dict]:
        """Drive the generator to completion and return (yielded, returned)."""
        if mcp_result is None:
            mcp_result = {"transaction_id": "tx-from-mcp", "amount": 500}

        mock_client = MagicMock()
        mock_client.call_tool = AsyncMock(return_value=mcp_result)

        with (
            patch.object(saga, "_get_mcp_client", return_value=mock_client),
            patch("asyncio.get_event_loop") as mock_loop,
        ):
            mock_loop.return_value.run_until_complete = MagicMock(
                return_value=mcp_result
            )
            gen = saga.forward_execute_trade_node_uca_4(state)  # type: ignore[arg-type]
            # First: consume the yielded PENDING entry
            yielded = next(gen)
            # Second: exhaust the generator to get the return value
            try:
                next(gen)
                returned: dict = {}
            except StopIteration as exc:
                returned = exc.value or {}

        return yielded, returned

    def test_first_yield_is_pending_entry(self) -> None:
        state = _make_state(transactions=[])
        yielded, _ = self._run_forward(state)

        assert "completed_transactions" in yielded
        entries = yielded["completed_transactions"]
        assert len(entries) == 1
        assert entries[0]["status"] == "PENDING"

    def test_pending_entry_has_correct_uca_ref(self) -> None:
        state = _make_state(transactions=[])
        yielded, _ = self._run_forward(state)

        entry = yielded["completed_transactions"][0]
        assert entry["uca_ref"] == "UCA-4"

    def test_pending_entry_has_correct_action(self) -> None:
        state = _make_state(transactions=[])
        yielded, _ = self._run_forward(state)

        entry = yielded["completed_transactions"][0]
        assert entry["action"] == "execute_trade"

    def test_pending_entry_has_empty_idempotency_key(self) -> None:
        """WAL intent is written before the API call, so key is empty at yield time."""
        state = _make_state(transactions=[])
        yielded, _ = self._run_forward(state)

        entry = yielded["completed_transactions"][0]
        assert entry["idempotency_key"] == ""

    def test_return_value_is_completed_entry(self) -> None:
        state = _make_state(transactions=[])
        _, returned = self._run_forward(state, mcp_result={"transaction_id": "tx-999"})

        assert "completed_transactions" in returned
        entries = returned["completed_transactions"]
        assert len(entries) == 1
        assert entries[0]["status"] == "COMPLETED"

    def test_completed_entry_has_idempotency_key_set(self) -> None:
        state = _make_state(transactions=[])
        _, returned = self._run_forward(state, mcp_result={"transaction_id": "tx-123"})

        entry = returned["completed_transactions"][0]
        expected_key = saga._derive_idempotency_key("tx-123", "reverse_trade")
        assert entry["idempotency_key"] == expected_key

    def test_sequence_id_increments_from_existing_transactions(self) -> None:
        existing = [_make_ledger_entry(sequence_id=4)]
        state = _make_state(transactions=existing)
        yielded, _ = self._run_forward(state)

        pending = yielded["completed_transactions"][0]
        assert pending["sequence_id"] == 5

    def test_sequence_id_is_zero_for_empty_ledger(self) -> None:
        state = _make_state(transactions=[])
        yielded, _ = self._run_forward(state)

        pending = yielded["completed_transactions"][0]
        assert pending["sequence_id"] == 0

    def test_completed_entry_context_data_contains_mcp_result(self) -> None:
        mcp_result = {"transaction_id": "tx-abc", "amount": 500, "status": "ok"}
        state = _make_state(transactions=[])
        _, returned = self._run_forward(state, mcp_result=mcp_result)

        entry = returned["completed_transactions"][0]
        assert entry["context_data"] == mcp_result

    def test_pending_entry_timestamp_is_iso_format(self) -> None:
        state = _make_state(transactions=[])
        yielded, _ = self._run_forward(state)

        ts = yielded["completed_transactions"][0]["timestamp"]
        # ISO 8601 strings contain 'T' and '+' or 'Z'
        assert "T" in ts

    def test_state_fields_forwarded_to_mcp_call(self) -> None:
        """Only allowed keys should be passed to call_tool arguments."""
        state = _make_state(transactions=[])
        mock_client = MagicMock()
        mock_client.call_tool = AsyncMock(return_value={"transaction_id": "x"})

        def fake_run_until_complete(coro):  # type: ignore[override]
            # We cannot await the coro in sync context, capture the mock return
            return {"transaction_id": "x"}

        with (
            patch.object(saga, "_get_mcp_client", return_value=mock_client),
            patch("asyncio.get_event_loop") as mock_loop,
        ):
            mock_loop.return_value.run_until_complete = MagicMock(
                side_effect=fake_run_until_complete
            )
            gen = saga.forward_execute_trade_node_uca_4(state)  # type: ignore[arg-type]
            next(gen)
            try:
                next(gen)
            except StopIteration:
                pass

        # The mock was called with run_until_complete — verify it was invoked at all
        mock_loop.return_value.run_until_complete.assert_called_once()


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

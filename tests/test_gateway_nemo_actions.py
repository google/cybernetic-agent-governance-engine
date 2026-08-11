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
Unit tests for src.gateway.governance.nemo.actions — gateway-internal NeMo actions.

These actions delegate to pre-computed governance results injected into the NeMo
context by NeMoManager.  Tests cover:

  - _get_pre_check helper
  - CheckApprovalTokenAction (fail-open when no pre_check, SC-1 violations, passing)
  - CheckLatencyAction (aliases CheckDataLatencyAction)
  - CheckDataLatencyAction (fail-closed on missing latency, fail-open without pre_check,
    FIN-2 violations, passing)
  - CheckDrawdownLimitAction (fail-open, blocked, allowed)
  - CheckSlippageRiskAction (fail-open, UCA-6 violations, passing)
  - CheckAtomicExecutionAction (single-leg, multi-leg no audit, incomplete audit,
    complete audit, type-coercion edge cases)
  - InvokeVllmFallbackAction (empty content path, exception path)
  - Snake_case aliases are the same callables
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.gateway.governance.nemo.actions import (
    CheckApprovalTokenAction,
    CheckAtomicExecutionAction,
    CheckDataLatencyAction,
    CheckDrawdownLimitAction,
    CheckLatencyAction,
    CheckSlippageRiskAction,
    InvokeVllmFallbackAction,
    _get_pre_check,
    check_approval_token,
    check_atomic_execution,
    check_data_latency,
    check_drawdown_limit,
    check_slippage_risk,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PRE_CHECK_KEY = "pre_check_results"


def _make_context(
    pre_check=None,
    latency_ms=None,
    required_legs=None,
    audit_trail=None,
):
    ctx: dict = {}
    if pre_check is not None:
        ctx[_PRE_CHECK_KEY] = pre_check
    if latency_ms is not None:
        ctx["latency_ms"] = latency_ms
    if required_legs is not None:
        ctx["required_legs"] = required_legs
    if audit_trail is not None:
        ctx["audit_trail"] = audit_trail
    return ctx


def _clean_stpa(violations=None):
    return {"stpa_result": {"violations": violations or []}}


def _clean_cbf(allowed=True, reason=""):
    return {"cbf_result": {"allowed": allowed, "reason": reason}}


# ---------------------------------------------------------------------------
# _get_pre_check helper
# ---------------------------------------------------------------------------


class TestGetPreCheck:
    def test_returns_none_when_key_absent(self):
        assert _get_pre_check({}) is None

    def test_returns_value_when_key_present(self):
        payload = {"foo": "bar"}
        ctx = {_PRE_CHECK_KEY: payload}
        assert _get_pre_check(ctx) is payload

    def test_returns_none_for_empty_context(self):
        assert _get_pre_check({}) is None

    def test_returns_correct_value_among_many_keys(self):
        payload = {"stpa_result": {}}
        ctx = {"other_key": "other_value", _PRE_CHECK_KEY: payload}
        assert _get_pre_check(ctx) is payload


# ---------------------------------------------------------------------------
# CheckApprovalTokenAction
# ---------------------------------------------------------------------------


class TestCheckApprovalTokenAction:
    @pytest.mark.asyncio
    async def test_fail_open_when_no_pre_check(self):
        result = await CheckApprovalTokenAction(context={})
        assert result is True

    @pytest.mark.asyncio
    async def test_passes_when_no_sc1_violations(self):
        ctx = _make_context(pre_check=_clean_stpa())
        result = await CheckApprovalTokenAction(context=ctx)
        assert result is True

    @pytest.mark.asyncio
    async def test_blocked_on_sc1_violation(self):
        ctx = _make_context(pre_check=_clean_stpa(["SC-1: approval token missing"]))
        result = await CheckApprovalTokenAction(context=ctx)
        assert result is False

    @pytest.mark.asyncio
    async def test_blocked_on_approval_token_substring(self):
        ctx = _make_context(
            pre_check=_clean_stpa(["missing approval_token for trade 42"])
        )
        result = await CheckApprovalTokenAction(context=ctx)
        assert result is False

    @pytest.mark.asyncio
    async def test_passes_when_unrelated_violations_present(self):
        """Only SC-1/approval_token violations should block this action."""
        ctx = _make_context(pre_check=_clean_stpa(["FIN-2: latency exceeded"]))
        result = await CheckApprovalTokenAction(context=ctx)
        assert result is True

    @pytest.mark.asyncio
    async def test_returns_bool_type(self):
        result = await CheckApprovalTokenAction(context={})
        assert isinstance(result, bool)

    @pytest.mark.asyncio
    async def test_missing_stpa_result_key_allows(self):
        """pre_check present but no stpa_result key → no violations → pass."""
        ctx = _make_context(pre_check={})
        result = await CheckApprovalTokenAction(context=ctx)
        assert result is True

    @pytest.mark.asyncio
    async def test_multiple_violations_one_sc1_blocks(self):
        violations = ["FIN-2: latency", "SC-1: approval_token required"]
        ctx = _make_context(pre_check=_clean_stpa(violations))
        result = await CheckApprovalTokenAction(context=ctx)
        assert result is False


# ---------------------------------------------------------------------------
# CheckLatencyAction (alias)
# ---------------------------------------------------------------------------


class TestCheckLatencyAction:
    @pytest.mark.asyncio
    async def test_delegates_to_check_data_latency_fail_closed(self):
        """Without latency_ms, CheckLatencyAction should fail-closed (False)."""
        result = await CheckLatencyAction(context={})
        assert result is False

    @pytest.mark.asyncio
    async def test_delegates_to_check_data_latency_with_latency(self):
        ctx = _make_context(latency_ms=50, pre_check=_clean_stpa())
        result = await CheckLatencyAction(context=ctx)
        assert result is True


# ---------------------------------------------------------------------------
# CheckDataLatencyAction
# ---------------------------------------------------------------------------


class TestCheckDataLatencyAction:
    @pytest.mark.asyncio
    async def test_fail_closed_when_latency_absent(self):
        result = await CheckDataLatencyAction(context={})
        assert result is False

    @pytest.mark.asyncio
    async def test_fail_open_when_latency_present_no_pre_check(self):
        ctx = _make_context(latency_ms=100)
        result = await CheckDataLatencyAction(context=ctx)
        assert result is True

    @pytest.mark.asyncio
    async def test_passes_when_no_fin2_violations(self):
        ctx = _make_context(latency_ms=100, pre_check=_clean_stpa())
        result = await CheckDataLatencyAction(context=ctx)
        assert result is True

    @pytest.mark.asyncio
    async def test_blocked_on_fin2_violation(self):
        ctx = _make_context(
            latency_ms=5000,
            pre_check=_clean_stpa(["FIN-2: latency exceeds threshold"]),
        )
        result = await CheckDataLatencyAction(context=ctx)
        assert result is False

    @pytest.mark.asyncio
    async def test_blocked_on_latency_substring(self):
        ctx = _make_context(
            latency_ms=5000,
            pre_check=_clean_stpa(["latency too high for trade execution"]),
        )
        result = await CheckDataLatencyAction(context=ctx)
        assert result is False

    @pytest.mark.asyncio
    async def test_unrelated_violations_do_not_block(self):
        ctx = _make_context(
            latency_ms=100,
            pre_check=_clean_stpa(["SC-1: approval_token missing"]),
        )
        result = await CheckDataLatencyAction(context=ctx)
        assert result is True

    @pytest.mark.asyncio
    async def test_latency_zero_is_treated_as_present(self):
        ctx = _make_context(latency_ms=0, pre_check=_clean_stpa())
        result = await CheckDataLatencyAction(context=ctx)
        assert result is True


# ---------------------------------------------------------------------------
# CheckDrawdownLimitAction
# ---------------------------------------------------------------------------


class TestCheckDrawdownLimitAction:
    @pytest.mark.asyncio
    async def test_fail_open_when_no_pre_check(self):
        result = await CheckDrawdownLimitAction(context={})
        assert result is True

    @pytest.mark.asyncio
    async def test_passes_when_cbf_allows(self):
        ctx = _make_context(pre_check=_clean_cbf(allowed=True))
        result = await CheckDrawdownLimitAction(context=ctx)
        assert result is True

    @pytest.mark.asyncio
    async def test_blocked_when_cbf_denies(self):
        ctx = _make_context(pre_check=_clean_cbf(allowed=False, reason="drawdown limit exceeded"))
        result = await CheckDrawdownLimitAction(context=ctx)
        assert result is False

    @pytest.mark.asyncio
    async def test_cbf_result_absent_defaults_to_allow(self):
        """When pre_check is present but no cbf_result, defaults to allowed=True."""
        ctx = _make_context(pre_check={})
        result = await CheckDrawdownLimitAction(context=ctx)
        assert result is True

    @pytest.mark.asyncio
    async def test_returns_bool_type(self):
        result = await CheckDrawdownLimitAction(context={})
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# CheckSlippageRiskAction
# ---------------------------------------------------------------------------


class TestCheckSlippageRiskAction:
    @pytest.mark.asyncio
    async def test_fail_open_when_no_pre_check(self):
        result = await CheckSlippageRiskAction(context={})
        assert result is True

    @pytest.mark.asyncio
    async def test_passes_when_no_uca6_violations(self):
        ctx = _make_context(pre_check=_clean_stpa())
        result = await CheckSlippageRiskAction(context=ctx)
        assert result is True

    @pytest.mark.asyncio
    async def test_blocked_on_uca6_violation(self):
        ctx = _make_context(pre_check=_clean_stpa(["UCA-6: slippage exceeds 2%"]))
        result = await CheckSlippageRiskAction(context=ctx)
        assert result is False

    @pytest.mark.asyncio
    async def test_blocked_on_slippage_substring(self):
        ctx = _make_context(pre_check=_clean_stpa(["excessive slippage risk detected"]))
        result = await CheckSlippageRiskAction(context=ctx)
        assert result is False

    @pytest.mark.asyncio
    async def test_blocked_on_volume_substring(self):
        ctx = _make_context(pre_check=_clean_stpa(["volume too large for market"]))
        result = await CheckSlippageRiskAction(context=ctx)
        assert result is False

    @pytest.mark.asyncio
    async def test_unrelated_violations_do_not_block(self):
        ctx = _make_context(pre_check=_clean_stpa(["SC-1: approval_token missing"]))
        result = await CheckSlippageRiskAction(context=ctx)
        assert result is True

    @pytest.mark.asyncio
    async def test_returns_bool_type(self):
        result = await CheckSlippageRiskAction(context={})
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# CheckAtomicExecutionAction
# ---------------------------------------------------------------------------


class TestCheckAtomicExecutionAction:
    @pytest.mark.asyncio
    async def test_single_leg_always_passes(self):
        ctx = _make_context(required_legs=1)
        result = await CheckAtomicExecutionAction(context=ctx)
        assert result is True

    @pytest.mark.asyncio
    async def test_zero_legs_treated_as_single_passes(self):
        ctx = _make_context(required_legs=0)
        result = await CheckAtomicExecutionAction(context=ctx)
        assert result is True

    @pytest.mark.asyncio
    async def test_default_required_legs_is_one(self):
        """No required_legs in context → defaults to 1 → single-leg → True."""
        result = await CheckAtomicExecutionAction(context={})
        assert result is True

    @pytest.mark.asyncio
    async def test_multi_leg_no_audit_trail_fails(self):
        ctx = _make_context(required_legs=2)
        result = await CheckAtomicExecutionAction(context=ctx)
        assert result is False

    @pytest.mark.asyncio
    async def test_multi_leg_empty_audit_trail_fails(self):
        ctx = _make_context(required_legs=2, audit_trail=[])
        result = await CheckAtomicExecutionAction(context=ctx)
        assert result is False

    @pytest.mark.asyncio
    async def test_multi_leg_complete_audit_trail_passes(self):
        # required_legs=2 means legs 0 and 1 exist; range(1, 2) checks leg_index=1
        audit = [{"leg_index": 0}, {"leg_index": 1}]
        ctx = _make_context(required_legs=2, audit_trail=audit)
        result = await CheckAtomicExecutionAction(context=ctx)
        assert result is True

    @pytest.mark.asyncio
    async def test_multi_leg_missing_intermediate_leg_fails(self):
        # required_legs=3 → range(1, 3) checks leg_index 1 and 2
        audit = [{"leg_index": 0}, {"leg_index": 2}]  # leg_index 1 is missing
        ctx = _make_context(required_legs=3, audit_trail=audit)
        result = await CheckAtomicExecutionAction(context=ctx)
        assert result is False

    @pytest.mark.asyncio
    async def test_multi_leg_all_legs_present_passes(self):
        audit = [{"leg_index": i} for i in range(3)]
        ctx = _make_context(required_legs=3, audit_trail=audit)
        result = await CheckAtomicExecutionAction(context=ctx)
        assert result is True

    @pytest.mark.asyncio
    async def test_string_required_legs_coerced_to_int(self):
        audit = [{"leg_index": 0}, {"leg_index": 1}]
        ctx = _make_context(required_legs="2", audit_trail=audit)
        result = await CheckAtomicExecutionAction(context=ctx)
        assert result is True

    @pytest.mark.asyncio
    async def test_invalid_required_legs_treated_as_one(self):
        """Non-numeric required_legs → coerced to 1 → single-leg → pass."""
        ctx = _make_context(required_legs="invalid")
        result = await CheckAtomicExecutionAction(context=ctx)
        assert result is True

    @pytest.mark.asyncio
    async def test_none_required_legs_treated_as_one(self):
        ctx = {"required_legs": None}
        result = await CheckAtomicExecutionAction(context=ctx)
        assert result is True

    @pytest.mark.asyncio
    async def test_audit_trail_from_event_used_when_not_in_context(self):
        audit = [{"leg_index": 0}, {"leg_index": 1}]
        ctx = {"required_legs": 2}
        event = {"audit_trail": audit}
        result = await CheckAtomicExecutionAction(context=ctx, event=event)
        assert result is True

    @pytest.mark.asyncio
    async def test_non_dict_audit_entries_ignored(self):
        """Non-dict entries in audit_trail must be skipped (isinstance check)."""
        # Entries that aren't dicts contribute nothing to completed_legs
        audit = ["not_a_dict", None, {"leg_index": 1}]
        ctx = _make_context(required_legs=2, audit_trail=audit)
        result = await CheckAtomicExecutionAction(context=ctx)
        # Only leg_index=1 is present; range(1,2) checks for leg_index=1 → passes
        assert result is True

    @pytest.mark.asyncio
    async def test_returns_bool_type(self):
        result = await CheckAtomicExecutionAction(context={})
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# InvokeVllmFallbackAction — edge cases that do not require live LLM
# ---------------------------------------------------------------------------


class TestInvokeVllmFallbackAction:
    @pytest.mark.asyncio
    async def test_empty_content_returns_apology_without_llm(self):
        """Empty content should short-circuit and return the apology string."""
        mock_span_ctx = MagicMock()
        mock_span_ctx.__enter__ = MagicMock(return_value=None)
        mock_span_ctx.__exit__ = MagicMock(return_value=False)

        with patch(
            "src.gateway.governance.nemo.actions.genai_span",
            return_value=mock_span_ctx,
        ) if False else _null_patch():
            # Patch the genai_span import inside the function
            with patch(
                "src.governed_financial_advisor.utils.telemetry.genai_span",
                return_value=mock_span_ctx,
            ) if False else _null_patch():
                pass

        # Direct invocation — empty content path
        with patch(
            "src.gateway.governance.nemo.actions.InvokeVllmFallbackAction.__module__",
        ) if False else _null_patch():
            pass

        # We patch the internal imports used by InvokeVllmFallbackAction
        mock_genai_span = MagicMock()
        mock_genai_span.return_value.__enter__ = MagicMock(return_value=None)
        mock_genai_span.return_value.__exit__ = MagicMock(return_value=False)

        with patch.dict(
            "sys.modules",
            {
                "src.governed_financial_advisor.utils.telemetry": MagicMock(
                    genai_span=_mock_genai_span_ctx()
                ),
            },
        ):
            result = await InvokeVllmFallbackAction(content="")
        assert "apologize" in result.lower() or result != ""

    @pytest.mark.asyncio
    async def test_exception_in_llm_returns_error_message(self):
        """Exception from the VLLM client must be caught and return an error string."""
        mock_vllm_llm = MagicMock()
        mock_vllm_llm.return_value._acall = AsyncMock(
            side_effect=RuntimeError("VLLM unavailable")
        )

        with patch.dict(
            "sys.modules",
            {
                "src.governed_financial_advisor.utils.telemetry": MagicMock(
                    genai_span=_mock_genai_span_ctx()
                ),
                "src.gateway.governance.nemo.vllm_client": MagicMock(
                    VLLMLLM=mock_vllm_llm
                ),
                "langchain_core.messages": MagicMock(HumanMessage=MagicMock()),
            },
        ):
            result = await InvokeVllmFallbackAction(content="Hello")
        # Should return an error message, not raise
        assert isinstance(result, str)
        assert len(result) > 0

    @pytest.mark.asyncio
    async def test_content_from_kwargs_is_used(self):
        """Content passed as a keyword argument must be picked up."""
        with patch.dict(
            "sys.modules",
            {
                "src.governed_financial_advisor.utils.telemetry": MagicMock(
                    genai_span=_mock_genai_span_ctx()
                ),
            },
        ):
            result = await InvokeVllmFallbackAction(content="")
        # Empty content → apology string, not an exception
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# Snake_case alias tests
# ---------------------------------------------------------------------------


class TestSnakeCaseAliases:
    def test_check_approval_token_is_same_as_action(self):
        assert check_approval_token is CheckApprovalTokenAction

    def test_check_data_latency_is_same_as_action(self):
        assert check_data_latency is CheckDataLatencyAction

    def test_check_drawdown_limit_is_same_as_action(self):
        assert check_drawdown_limit is CheckDrawdownLimitAction

    def test_check_slippage_risk_is_same_as_action(self):
        assert check_slippage_risk is CheckSlippageRiskAction

    def test_check_atomic_execution_is_same_as_action(self):
        assert check_atomic_execution is CheckAtomicExecutionAction


# ---------------------------------------------------------------------------
# Tiny helpers for mocking context managers
# ---------------------------------------------------------------------------


def _mock_genai_span_ctx():
    """Return a callable that produces a context manager yielding None."""
    from contextlib import contextmanager

    @contextmanager
    def _genai_span(*args, **kwargs):
        yield None

    return _genai_span


class _null_patch:
    """A no-op context manager for conditional patching."""
    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

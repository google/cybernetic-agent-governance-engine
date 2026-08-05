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
5-Tier Governance Pipeline Latency Test Suite.

Measures per-tier wall-clock latency for the CAGE governance pipeline:

  Tier 1 — NeMo input guardrail  (create_nemo_guardrail_node)
  Tier 2 — OPA policy check      (create_opa_safety_node)
  Tier 3 — Safety/STPA node      (safety_check_node from safety_node.py)
  Tier 4 — Agent/LLM execution   (network-bound; excluded from cumulative test)
  Tier 5 — NeMo output rail      (create_nemo_output_rail_node)

All external I/O (NeMo server, OPA server, LLM) is mocked via
unittest.mock.AsyncMock / patch.  No real network calls are made.

Latency budgets are defined as module-level constants for easy tuning.
"""

from __future__ import annotations

import os
import statistics
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.gateway.governance.langgraph_harness import (
    NemoNodeConfig,
    OpaNodeConfig,
    create_nemo_guardrail_node,
    create_nemo_output_rail_node,
    create_opa_safety_node,
)

pytestmark = pytest.mark.unit

# ---------------------------------------------------------------------------
# Latency budgets (milliseconds) — tune here without touching test logic
# ---------------------------------------------------------------------------

TIER1_NEMO_INPUT_BUDGET_MS: float = 50.0  # NeMo input guardrail
TIER2_OPA_BUDGET_MS: float = 30.0  # OPA policy check
TIER3_SAFETY_BUDGET_MS: float = 20.0  # Safety/STPA validation (pure Python)
TIER4_AGENT_BUDGET_MS: float = 2000.0  # LLM call (network-bound, generous budget)
TIER5_NEMO_OUTPUT_BUDGET_MS: float = 50.0  # NeMo output rail
PIPELINE_TOTAL_BUDGET_MS: float = 2200.0  # End-to-end budget (ex. Tier 4 LLM)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


class _FakeMessage:
    """Minimal stand-in for langchain BaseMessage."""

    def __init__(self, content: str, id: str = "msg-1") -> None:
        self.content = content
        self.id = id


def _input_state(text: str = "What is the current AAPL price?") -> dict[str, Any]:
    """Minimal valid state dict for input-rail tests."""
    return {
        "messages": [_FakeMessage(text)],
        "guardrail_blocked": False,
        "guardrail_reason": "",
    }


def _output_state(text: str = "AAPL is trading at $195.") -> dict[str, Any]:
    """Minimal valid state dict for output-rail tests."""
    return {
        "messages": [_FakeMessage(text, id="msg-out-1")],
    }


def _opa_state() -> dict[str, Any]:
    """Minimal valid state dict for OPA / safety-node tests."""
    return {
        "execution_plan_output": {
            "action": "execute_trade",
            "amount": 1000,
            "symbol": "AAPL",
            "currency": "USD",
            "trader_role": "junior",
        },
        "thread_id": "latency-test-thread",
        "user_id": "test-user",
        "risk_attitude": "neutral",
    }


def _trade_extractor(state: dict[str, Any]) -> dict[str, Any]:
    """Minimal OPA payload extractor for latency tests."""
    plan = state.get("execution_plan_output") or {}
    return {
        "action": plan.get("action", "unknown"),
        "amount": plan.get("amount", 0),
        "symbol": plan.get("symbol", "UNKNOWN"),
        "currency": plan.get("currency", "USD"),
        "trader_role": plan.get("trader_role", "junior"),
        "user_id": state.get("user_id", "anonymous"),
        "risk_profile": state.get("risk_attitude", "neutral"),
        "confidence": 1.0,
        "latency_ms": 0.0,
    }


def _make_opa_config(**overrides) -> OpaNodeConfig:
    """Build a minimal OpaNodeConfig for latency tests."""
    defaults: dict[str, Any] = {
        "policy_action_name": "execute_trade",
        "payload_extractor": _trade_extractor,
        "plan_state_key": "execution_plan_output",
        "status_state_key": "safety_status",
        "error_state_key": "error",
        "iso_control": "A.10.1",
        "iso_tier": 2,
    }
    defaults.update(overrides)
    return OpaNodeConfig(**defaults)


def _elapsed_ms(start: float, end: float) -> float:
    """Convert perf_counter interval to milliseconds."""
    return (end - start) * 1_000.0


def _format_report(
    t1_ms: float,
    t2_ms: float,
    t3_ms: float,
    t5_ms: float,
    total_ms: float,
) -> str:
    """Return a human-readable latency report string."""

    def _status(elapsed: float, budget: float) -> str:
        return "PASS" if elapsed < budget else "FAIL"

    lines = [
        "=== CAGE 5-Tier Governance Pipeline Latency Report ===",
        f"Tier 1 (NeMo Input):    {t1_ms:.1f}ms  / {TIER1_NEMO_INPUT_BUDGET_MS:.0f}ms   [{_status(t1_ms, TIER1_NEMO_INPUT_BUDGET_MS)}]",
        f"Tier 2 (OPA):           {t2_ms:.1f}ms  / {TIER2_OPA_BUDGET_MS:.0f}ms   [{_status(t2_ms, TIER2_OPA_BUDGET_MS)}]",
        f"Tier 3 (Safety):        {t3_ms:.1f}ms  / {TIER3_SAFETY_BUDGET_MS:.0f}ms   [{_status(t3_ms, TIER3_SAFETY_BUDGET_MS)}]",
        f"Tier 5 (NeMo Output):   {t5_ms:.1f}ms  / {TIER5_NEMO_OUTPUT_BUDGET_MS:.0f}ms   [{_status(t5_ms, TIER5_NEMO_OUTPUT_BUDGET_MS)}]",
        "\u2500" * 53,
        f"Total (ex. LLM):        {total_ms:.1f}ms  / {PIPELINE_TOTAL_BUDGET_MS:.0f}ms [{_status(total_ms, PIPELINE_TOTAL_BUDGET_MS)}]",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Context managers for patching all external I/O
# ---------------------------------------------------------------------------


def _nemo_input_patches(safe: bool = True):
    """Return a list of patch context managers for the NeMo input rail."""
    return [
        patch(
            "src.gateway.governance.langgraph_harness.nemo_node_factory.get_nemo_rails",
            return_value=MagicMock(),
        ),
        patch(
            "src.gateway.governance.langgraph_harness.nemo_node_factory.validate_with_nemo",
            new_callable=AsyncMock,
            return_value=(safe, "", False),
        ),
        patch(
            "src.gateway.governance.langgraph_harness.nemo_node_factory._get_symbolic_governor",
            return_value=None,
        ),
    ]


def _nemo_output_patches():
    """Return a list of patch context managers for the NeMo output rail."""
    return [
        patch(
            "src.gateway.governance.langgraph_harness.nemo_node_factory.get_nemo_rails",
            return_value=MagicMock(),
        ),
        patch(
            "src.gateway.governance.langgraph_harness.nemo_node_factory.verify_and_mask_output",
            new_callable=AsyncMock,
            return_value="AAPL is trading at $195.",
        ),
        patch(
            "src.gateway.governance.langgraph_harness.nemo_node_factory.validate_output_semantics",
            new_callable=AsyncMock,
            return_value=(True, ""),
        ),
    ]


def _opa_patches():
    """Return a list of patch context managers for the OPA safety node."""
    mock_gov = AsyncMock()
    mock_gov.govern = AsyncMock(return_value=None)
    return [
        patch(
            "src.gateway.governance.langgraph_harness.opa_node_factory.symbolic_governor",
            mock_gov,
        ),
        patch(
            "src.gateway.governance.langgraph_harness.opa_node_factory.symbolic_governor",
            mock_gov,
        ),
    ]


# ---------------------------------------------------------------------------
# Tier 1 — NeMo input guardrail latency
# ---------------------------------------------------------------------------


class TestTier1NemoInputGuardrailLatency:
    """Latency tests for Tier 1: NeMo input guardrail node."""

    @pytest.mark.skipif(
        not os.getenv("CI"),
        reason="Latency budget tests only enforced in CI environment",
    )
    @pytest.mark.asyncio
    async def test_tier1_nemo_input_guardrail_latency(self):
        """Tier 1 node call must complete within TIER1_NEMO_INPUT_BUDGET_MS."""
        node = create_nemo_guardrail_node(NemoNodeConfig())
        state = _input_state()

        patches = _nemo_input_patches(safe=True)
        with patches[0], patches[1], patches[2]:
            t_start = time.perf_counter()
            result = await node(state)
            t_end = time.perf_counter()

        elapsed_ms = _elapsed_ms(t_start, t_end)
        print(
            f"\n[Tier 1] NeMo input guardrail: {elapsed_ms:.2f}ms "
            f"(budget: {TIER1_NEMO_INPUT_BUDGET_MS}ms)"
        )

        assert result["guardrail_blocked"] is False, (
            f"Expected guardrail_blocked=False, got: {result}"
        )
        assert elapsed_ms < TIER1_NEMO_INPUT_BUDGET_MS, (
            f"Tier 1 latency {elapsed_ms:.2f}ms exceeded budget "
            f"{TIER1_NEMO_INPUT_BUDGET_MS}ms"
        )


# ---------------------------------------------------------------------------
# Tier 2 — OPA policy check latency
# ---------------------------------------------------------------------------


class TestTier2OpaPolicyCheckLatency:
    """Latency tests for Tier 2: OPA policy check node."""

    @pytest.mark.skipif(
        not os.getenv("CI"),
        reason="Latency budget tests only enforced in CI environment",
    )
    @pytest.mark.asyncio
    async def test_tier2_opa_policy_check_latency(self):
        """Tier 2 node call must complete within TIER2_OPA_BUDGET_MS."""
        config = _make_opa_config()
        node = create_opa_safety_node(config)
        state = _opa_state()

        patches = _opa_patches()
        with patches[0], patches[1]:
            t_start = time.perf_counter()
            result = await node(state)
            t_end = time.perf_counter()

        elapsed_ms = _elapsed_ms(t_start, t_end)
        print(
            f"\n[Tier 2] OPA policy check: {elapsed_ms:.2f}ms "
            f"(budget: {TIER2_OPA_BUDGET_MS}ms)"
        )

        assert result["safety_status"] == "APPROVED", (
            f"Expected APPROVED, got: {result}"
        )
        assert elapsed_ms < TIER2_OPA_BUDGET_MS, (
            f"Tier 2 latency {elapsed_ms:.2f}ms exceeded budget {TIER2_OPA_BUDGET_MS}ms"
        )


# ---------------------------------------------------------------------------
# Tier 3 — Safety/STPA node latency
# ---------------------------------------------------------------------------


class TestTier3SafetyNodeLatency:
    """Latency tests for Tier 3: Safety/STPA validation node."""

    @pytest.mark.skipif(
        not os.getenv("CI"),
        reason="Latency budget tests only enforced in CI environment",
    )
    @pytest.mark.asyncio
    async def test_tier3_safety_node_latency(self):
        """Tier 3 safety_check_node call must complete within TIER3_SAFETY_BUDGET_MS.

        safety_check_node is the module-level OPA node produced by
        create_opa_safety_node(_opa_config) in safety_node.py.  It is
        functionally identical to Tier 2 but represents the domain-specific
        financial advisor safety gate (STPA/OPA combined).
        """
        from src.governed_financial_advisor.graph.nodes.safety_node import (
            safety_check_node,
        )

        state = _opa_state()

        patches = _opa_patches()
        with patches[0], patches[1]:
            t_start = time.perf_counter()
            result = await safety_check_node(state)
            t_end = time.perf_counter()

        elapsed_ms = _elapsed_ms(t_start, t_end)
        print(
            f"\n[Tier 3] Safety/STPA node: {elapsed_ms:.2f}ms "
            f"(budget: {TIER3_SAFETY_BUDGET_MS}ms)"
        )

        assert result["safety_status"] in ("APPROVED", "SKIPPED"), (
            f"Expected APPROVED or SKIPPED, got: {result}"
        )
        assert elapsed_ms < TIER3_SAFETY_BUDGET_MS, (
            f"Tier 3 latency {elapsed_ms:.2f}ms exceeded budget "
            f"{TIER3_SAFETY_BUDGET_MS}ms"
        )


# ---------------------------------------------------------------------------
# Tier 5 — NeMo output rail latency
# ---------------------------------------------------------------------------


class TestTier5NemoOutputRailLatency:
    """Latency tests for Tier 5: NeMo output rail node."""

    @pytest.mark.asyncio
    async def test_tier5_nemo_output_rail_latency(self):
        """Tier 5 node call must complete within TIER5_NEMO_OUTPUT_BUDGET_MS."""
        node = create_nemo_output_rail_node(NemoNodeConfig())
        state = _output_state()

        patches = _nemo_output_patches()
        with patches[0], patches[1], patches[2]:
            t_start = time.perf_counter()
            result = await node(state)
            t_end = time.perf_counter()

        elapsed_ms = _elapsed_ms(t_start, t_end)
        print(
            f"\n[Tier 5] NeMo output rail: {elapsed_ms:.2f}ms "
            f"(budget: {TIER5_NEMO_OUTPUT_BUDGET_MS}ms)"
        )

        assert result["output_rail_applied"] is True, (
            f"Expected output_rail_applied=True, got: {result}"
        )
        assert elapsed_ms < TIER5_NEMO_OUTPUT_BUDGET_MS, (
            f"Tier 5 latency {elapsed_ms:.2f}ms exceeded budget "
            f"{TIER5_NEMO_OUTPUT_BUDGET_MS}ms"
        )


# ---------------------------------------------------------------------------
# Pipeline cumulative latency (Tiers 1, 2, 3, 5 — Tier 4 excluded)
# ---------------------------------------------------------------------------


class TestPipelineCumulativeLatency:
    """End-to-end cumulative latency test for the 4 non-LLM tiers."""

    @pytest.mark.skipif(
        not os.getenv("CI"),
        reason="Latency budget tests only enforced in CI environment",
    )
    @pytest.mark.asyncio
    async def test_pipeline_cumulative_latency(self):
        """Run Tiers 1, 2, 3, 5 in sequence and assert total < PIPELINE_TOTAL_BUDGET_MS.

        Tier 4 (LLM/agent execution) is excluded because it is network-bound
        and would make the test flaky.  The budget constant PIPELINE_TOTAL_BUDGET_MS
        already accounts for Tier 4 being excluded from this measurement.
        """
        from src.governed_financial_advisor.graph.nodes.safety_node import (
            safety_check_node,
        )

        # --- Tier 1: NeMo input guardrail ---
        tier1_node = create_nemo_guardrail_node(NemoNodeConfig())
        input_state = _input_state()

        nemo_in_patches = _nemo_input_patches(safe=True)
        with nemo_in_patches[0], nemo_in_patches[1], nemo_in_patches[2]:
            t1_start = time.perf_counter()
            await tier1_node(input_state)
            t1_end = time.perf_counter()

        t1_ms = _elapsed_ms(t1_start, t1_end)

        # --- Tier 2: OPA policy check ---
        tier2_node = create_opa_safety_node(_make_opa_config())
        opa_state = _opa_state()

        opa_patches = _opa_patches()
        with opa_patches[0], opa_patches[1]:
            t2_start = time.perf_counter()
            await tier2_node(opa_state)
            t2_end = time.perf_counter()

        t2_ms = _elapsed_ms(t2_start, t2_end)

        # --- Tier 3: Safety/STPA node ---
        safety_state = _opa_state()

        opa_patches2 = _opa_patches()
        with opa_patches2[0], opa_patches2[1]:
            t3_start = time.perf_counter()
            await safety_check_node(safety_state)
            t3_end = time.perf_counter()

        t3_ms = _elapsed_ms(t3_start, t3_end)

        # --- Tier 5: NeMo output rail ---
        tier5_node = create_nemo_output_rail_node(NemoNodeConfig())
        out_state = _output_state()

        nemo_out_patches = _nemo_output_patches()
        with nemo_out_patches[0], nemo_out_patches[1], nemo_out_patches[2]:
            t5_start = time.perf_counter()
            await tier5_node(out_state)
            t5_end = time.perf_counter()

        t5_ms = _elapsed_ms(t5_start, t5_end)

        total_ms = t1_ms + t2_ms + t3_ms + t5_ms

        # Print the human-readable latency report
        report = _format_report(t1_ms, t2_ms, t3_ms, t5_ms, total_ms)
        print(f"\n{report}")

        # Per-tier assertions
        assert t1_ms < TIER1_NEMO_INPUT_BUDGET_MS, (
            f"Tier 1 latency {t1_ms:.2f}ms exceeded budget {TIER1_NEMO_INPUT_BUDGET_MS}ms"
        )
        assert t2_ms < TIER2_OPA_BUDGET_MS, (
            f"Tier 2 latency {t2_ms:.2f}ms exceeded budget {TIER2_OPA_BUDGET_MS}ms"
        )
        assert t3_ms < TIER3_SAFETY_BUDGET_MS, (
            f"Tier 3 latency {t3_ms:.2f}ms exceeded budget {TIER3_SAFETY_BUDGET_MS}ms"
        )
        assert t5_ms < TIER5_NEMO_OUTPUT_BUDGET_MS, (
            f"Tier 5 latency {t5_ms:.2f}ms exceeded budget {TIER5_NEMO_OUTPUT_BUDGET_MS}ms"
        )
        assert total_ms < PIPELINE_TOTAL_BUDGET_MS, (
            f"Pipeline total latency {total_ms:.2f}ms exceeded budget "
            f"{PIPELINE_TOTAL_BUDGET_MS}ms"
        )


# ---------------------------------------------------------------------------
# Latency report printed to stdout (capsys verification)
# ---------------------------------------------------------------------------


class TestLatencyReportPrinted:
    """Verify that the pipeline test emits a human-readable latency report."""

    @pytest.mark.asyncio
    async def test_latency_report_printed(self, capsys):
        """Run the pipeline and verify a formatted latency report is printed to stdout."""
        from src.governed_financial_advisor.graph.nodes.safety_node import (
            safety_check_node,
        )

        # --- Tier 1 ---
        tier1_node = create_nemo_guardrail_node(NemoNodeConfig())
        nemo_in_patches = _nemo_input_patches(safe=True)
        with nemo_in_patches[0], nemo_in_patches[1], nemo_in_patches[2]:
            t1_start = time.perf_counter()
            await tier1_node(_input_state())
            t1_end = time.perf_counter()
        t1_ms = _elapsed_ms(t1_start, t1_end)

        # --- Tier 2 ---
        tier2_node = create_opa_safety_node(_make_opa_config())
        opa_patches = _opa_patches()
        with opa_patches[0], opa_patches[1]:
            t2_start = time.perf_counter()
            await tier2_node(_opa_state())
            t2_end = time.perf_counter()
        t2_ms = _elapsed_ms(t2_start, t2_end)

        # --- Tier 3 ---
        opa_patches2 = _opa_patches()
        with opa_patches2[0], opa_patches2[1]:
            t3_start = time.perf_counter()
            await safety_check_node(_opa_state())
            t3_end = time.perf_counter()
        t3_ms = _elapsed_ms(t3_start, t3_end)

        # --- Tier 5 ---
        tier5_node = create_nemo_output_rail_node(NemoNodeConfig())
        nemo_out_patches = _nemo_output_patches()
        with nemo_out_patches[0], nemo_out_patches[1], nemo_out_patches[2]:
            t5_start = time.perf_counter()
            await tier5_node(_output_state())
            t5_end = time.perf_counter()
        t5_ms = _elapsed_ms(t5_start, t5_end)

        total_ms = t1_ms + t2_ms + t3_ms + t5_ms

        # Emit the report
        report = _format_report(t1_ms, t2_ms, t3_ms, t5_ms, total_ms)
        print(report)

        # Capture and verify
        captured = capsys.readouterr()
        assert "CAGE 5-Tier Governance Pipeline Latency Report" in captured.out
        assert "Tier 1 (NeMo Input):" in captured.out
        assert "Tier 2 (OPA):" in captured.out
        assert "Tier 3 (Safety):" in captured.out
        assert "Tier 5 (NeMo Output):" in captured.out
        assert "Total (ex. LLM):" in captured.out
        # At least one tier should show PASS (all mocked, so all should be fast)
        assert "PASS" in captured.out


# ---------------------------------------------------------------------------
# Parametrized p95 latency test for Tier 1
# ---------------------------------------------------------------------------


class TestTier1LatencyP95:
    """P95 latency test for Tier 1 NeMo input guardrail over N runs."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("n_runs", [20])
    async def test_tier1_latency_p95(self, n_runs: int):
        """Run Tier 1 node n_runs times and assert p95 < TIER1_NEMO_INPUT_BUDGET_MS * 2.

        The 2x multiplier provides headroom for p95 tail latency under
        test-environment jitter while still catching pathological regressions.
        """
        node = create_nemo_guardrail_node(NemoNodeConfig())
        state = _input_state()
        elapsed_samples: list[float] = []

        patches = _nemo_input_patches(safe=True)
        with patches[0], patches[1], patches[2]:
            for _ in range(n_runs):
                t_start = time.perf_counter()
                await node(state)
                t_end = time.perf_counter()
                elapsed_samples.append(_elapsed_ms(t_start, t_end))

        p95_ms = statistics.quantiles(elapsed_samples, n=100)[94]  # 95th percentile
        mean_ms = statistics.mean(elapsed_samples)
        max_ms = max(elapsed_samples)
        budget_p95 = TIER1_NEMO_INPUT_BUDGET_MS * 2

        print(
            f"\n[Tier 1 p95] n={n_runs} runs | "
            f"mean={mean_ms:.2f}ms | p95={p95_ms:.2f}ms | "
            f"max={max_ms:.2f}ms | budget_p95={budget_p95:.0f}ms"
        )

        assert p95_ms < budget_p95, (
            f"Tier 1 p95 latency {p95_ms:.2f}ms exceeded 2x budget "
            f"{budget_p95:.0f}ms (mean={mean_ms:.2f}ms, max={max_ms:.2f}ms)"
        )

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

"""Per-tier OTel spans emitted by DomainTierStage, and the paper-metrics span map.

Spans are captured with a local TracerProvider + InMemorySpanExporter that is
patched into each emitting module's ``tracer`` attribute, so the global OTel
provider is never touched.
"""

from __future__ import annotations

import ast
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode

from src.gateway.governance.contracts import (
    CommitReceipt,
    MutatingTier,
    ReadOnlyTier,
    Violation,
    ViolationKind,
)
from src.gateway.governance.governor import governor as governor_module
from src.gateway.governance.governor import verdicts as verdicts_module
from src.gateway.governance.governor.pipeline import Profile, StageContext
from src.gateway.governance.governor.stages import confidence as confidence_module
from src.gateway.governance.governor.stages import domain_tiers as domain_tiers_module
from src.gateway.governance.governor.stages import ftra as ftra_module
from src.gateway.governance.governor.stages import stpa as stpa_module
from src.gateway.governance.governor.stages.domain_tiers import DomainTierStage

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO_ROOT = Path(__file__).resolve().parents[3]
_METRICS_SCRIPT = _REPO_ROOT / "scripts" / "measure_paper_metrics.py"

# Fixed-name spans emitted by Layer 1 kernel code (not by DomainTierStage).
KERNEL_SPAN_NAMES = frozenset(
    {
        "cage.ftra_boundary_gate",  # governor/stages/ftra.py
        "cage.stpa_check",  # governor/stages/stpa.py
        "cage.confidence_check",  # governor/stages/confidence.py
        "governance.opa_check",  # gateway/core/policy.py (real OPAClient only)
        "cage.validate_action",  # governor/governor.py
        "symbolic_governor.govern",
        "symbolic_governor.revalidate_post_hitl",
        "symbolic_governor.verify",
    }
)

_TRACED_MODULES = (
    domain_tiers_module,
    governor_module,
    verdicts_module,
    stpa_module,
    confidence_module,
    ftra_module,
)


@pytest.fixture
def exporter(monkeypatch: pytest.MonkeyPatch) -> InMemorySpanExporter:
    exp = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exp))
    for module in _TRACED_MODULES:
        monkeypatch.setattr(module, "tracer", provider.get_tracer(module.__name__))
    return exp


@pytest.fixture
def ctx() -> StageContext:
    return StageContext(action="execute_trade", params={"amount": 100}, profile=Profile.FULL)


def _tier(name: str, phase: int) -> MagicMock:
    """Spec mock of a ReadOnlyTier (phase 1) or a MutatingTier (phase 2)."""
    tier = MagicMock(spec=ReadOnlyTier if phase == 1 else MutatingTier)
    tier.tier_name = name
    tier.phase = phase
    tier.order = 10
    tier.claims_action.return_value = True
    tier.evaluate = AsyncMock(return_value=[])
    if phase == 2:
        tier.commit = AsyncMock(return_value=([], CommitReceipt(tier=name, magnitude=100.0)))
        tier.rollback = AsyncMock()
        tier.confirm = AsyncMock()
    return tier


def _only_span(exporter: InMemorySpanExporter, name: str):
    spans = [s for s in exporter.get_finished_spans() if s.name == name]
    assert len(spans) == 1, [s.name for s in exporter.get_finished_spans()]
    return spans[0]


def _load_tier_span_map() -> dict[str, str]:
    """Read TIER_SPAN_MAP from the script without executing it.

    Importing the script mutates process state (os.environ defaults,
    logging.basicConfig), which would leak into other tests on the worker.
    """
    tree = ast.parse(_METRICS_SCRIPT.read_text())
    for node in tree.body:
        if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", None) == "TIER_SPAN_MAP":
            return ast.literal_eval(node.value)
    raise AssertionError("TIER_SPAN_MAP not found in measure_paper_metrics.py")


# ---------------------------------------------------------------------------
# DomainTierStage span shape
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_evaluate_emits_tier_span(exporter, ctx):
    tier = _tier("alpha", phase=1)
    tier.evaluate.return_value = [
        Violation(tier="alpha", code="A", message="a", kind=ViolationKind.DEFERRABLE),
        Violation(tier="alpha", code="B", message="b", kind=ViolationKind.DEFERRABLE),
    ]

    violations = await DomainTierStage(tier).run(ctx)

    assert len(violations) == 2
    span = _only_span(exporter, "cage.tier.alpha")
    assert span.attributes["cage.tier.phase"] == 1
    assert span.attributes["cage.tier.hook"] == "evaluate"
    assert span.attributes["cage.tier.violation_count"] == 2
    assert "cage.tier.exception" not in span.attributes


@pytest.mark.asyncio
async def test_commit_emits_tier_span(exporter, ctx):
    tier = _tier("beta", phase=2)

    violations, receipt = await DomainTierStage(tier).commit(ctx)
    assert violations == []
    assert receipt == CommitReceipt(tier="beta", magnitude=100.0)

    tier.commit.assert_awaited_once()
    span = _only_span(exporter, "cage.tier.beta")
    assert span.attributes["cage.tier.phase"] == 2
    assert span.attributes["cage.tier.hook"] == "commit"
    assert span.attributes["cage.tier.violation_count"] == 0
    assert "cage.tier.exception" not in span.attributes


@pytest.mark.asyncio
async def test_preview_emits_tier_span(exporter, ctx):
    tier = _tier("beta", phase=2)

    await DomainTierStage(tier).preview(ctx)

    tier.commit.assert_not_awaited()
    span = _only_span(exporter, "cage.tier.beta")
    assert span.attributes["cage.tier.hook"] == "preview"
    assert span.attributes["cage.tier.violation_count"] == 0


@pytest.mark.asyncio
async def test_rollback_emits_tier_span(exporter, ctx):
    tier = _tier("beta", phase=2)
    receipt = CommitReceipt(tier="beta", magnitude=100.0)

    await DomainTierStage(tier).rollback(ctx, receipt)

    span = _only_span(exporter, "cage.tier.beta")
    assert span.attributes["cage.tier.hook"] == "rollback"
    assert span.attributes["cage.tier.violation_count"] == 0


@pytest.mark.asyncio
async def test_confirm_emits_tier_span(exporter, ctx):
    tier = _tier("beta", phase=2)
    receipt = CommitReceipt(tier="beta", magnitude=100.0)

    await DomainTierStage(tier).confirm(ctx, receipt)

    tier.confirm.assert_awaited_once_with("execute_trade", {"amount": 100}, receipt)
    span = _only_span(exporter, "cage.tier.beta")
    assert span.attributes["cage.tier.hook"] == "confirm"
    assert span.attributes["cage.tier.violation_count"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("hook", ["rollback", "confirm"])
async def test_read_only_settle_refuses_and_emits_no_span(exporter, ctx, hook):
    tier = _tier("alpha", phase=1)
    receipt = CommitReceipt(tier="alpha", magnitude=100.0)

    with pytest.raises(TypeError, match="holds no reservation"):
        await getattr(DomainTierStage(tier), hook)(ctx, receipt)

    assert exporter.get_finished_spans() == ()


# ---------------------------------------------------------------------------
# Fail-closed paths: the span still ends and records the exception type
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_raising_commit_ends_span_with_exception_and_fails_closed(exporter, ctx):
    tier = _tier("beta", phase=2)
    tier.commit.side_effect = RuntimeError("backend down")

    violations, receipt = await DomainTierStage(tier).commit(ctx)

    assert receipt is None
    assert [v.code for v in violations] == ["TIER_EXCEPTION"]
    assert violations[0].kind == ViolationKind.HARD
    span = _only_span(exporter, "cage.tier.beta")
    assert span.end_time is not None
    assert span.attributes["cage.tier.exception"] == "RuntimeError"
    assert span.attributes["cage.tier.violation_count"] == 1


@pytest.mark.asyncio
async def test_raising_evaluate_ends_span_with_exception(exporter, ctx):
    tier = _tier("alpha", phase=1)
    tier.evaluate.side_effect = KeyError("missing")

    violations = await DomainTierStage(tier).run(ctx)

    assert violations[0].code == "TIER_EXCEPTION"
    span = _only_span(exporter, "cage.tier.alpha")
    assert span.end_time is not None
    assert span.attributes["cage.tier.exception"] == "KeyError"


@pytest.mark.asyncio
async def test_malformed_commit_result_span_records_violation_count(exporter, ctx):
    tier = _tier("beta", phase=2)
    tier.commit.return_value = []  # missing CommitReceipt tuple

    violations, receipt = await DomainTierStage(tier).commit(ctx)

    assert receipt is None
    assert violations[0].code == "TIER_EXCEPTION"
    span = _only_span(exporter, "cage.tier.beta")
    assert span.attributes["cage.tier.hook"] == "commit"
    assert span.attributes["cage.tier.violation_count"] == 1


@pytest.mark.asyncio
async def test_raising_rollback_propagates_and_ends_span(exporter, ctx):
    tier = _tier("beta", phase=2)
    tier.rollback.side_effect = RuntimeError("undo failed")
    receipt = CommitReceipt(tier="beta", magnitude=100.0)

    with pytest.raises(RuntimeError, match="undo failed"):
        await DomainTierStage(tier).rollback(ctx, receipt)

    span = _only_span(exporter, "cage.tier.beta")
    assert span.end_time is not None
    assert span.attributes["cage.tier.hook"] == "rollback"
    assert span.attributes["cage.tier.exception"] == "RuntimeError"
    assert span.status.status_code == StatusCode.ERROR


@pytest.mark.asyncio
async def test_cancelled_commit_propagates_and_ends_span(exporter, ctx):
    tier = _tier("beta", phase=2)
    tier.commit.side_effect = asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await DomainTierStage(tier).commit(ctx)

    span = _only_span(exporter, "cage.tier.beta")
    assert span.end_time is not None
    assert span.attributes["cage.tier.exception"] == "CancelledError"
    assert "cage.tier.violation_count" not in span.attributes


# ---------------------------------------------------------------------------
# Paper-metrics span map must only name spans that are actually emitted
# ---------------------------------------------------------------------------


def test_tier_span_map_has_no_stale_names():
    span_map = _load_tier_span_map()
    stale = {"cage.cbf_check", "cage.fiscal_limit_reserve", "cage.consensus_gate", "cage.fria_check"}
    assert stale.isdisjoint(span_map.values())


@pytest.mark.asyncio
async def test_tier_span_map_values_are_emitted(exporter):
    from tests.governor.golden.fixtures import SCENARIOS, build_governor_for_scenario

    happy = next(s for s in SCENARIOS if s.id == "01_happy_path_allow")
    governor, _ = build_governor_for_scenario(happy)

    # Seal issuance needs Redis/KMS; stub it the same way the golden harness does.
    with patch(
        "src.gateway.governance.routing_seal.generate_seal_with_evidence",
        new_callable=AsyncMock,
        return_value="mock-seal-" + "a" * 32,
    ):
        await governor.govern(happy.action, dict(happy.params))

    emitted = {s.name for s in exporter.get_finished_spans()}
    span_map = _load_tier_span_map()
    for label, span_name in span_map.items():
        if span_name.startswith("cage.tier."):
            # Domain tier spans must come out of a real governor run.
            assert span_name in emitted, f"{label}: {span_name} not emitted; got {sorted(emitted)}"
        else:
            assert span_name in KERNEL_SPAN_NAMES, f"{label}: {span_name} is not a known kernel span"

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

"""Per-tier OTel spans emitted by DomainTierStage.

Spans are captured with a local TracerProvider + InMemorySpanExporter that is
patched into each emitting module's ``tracer`` attribute, so the global OTel
provider is never touched.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

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
    return StageContext(
        action="execute_trade", params={"amount": 100}, profile=Profile.FULL
    )


def _tier(name: str, phase: int) -> MagicMock:
    """Spec mock of a ReadOnlyTier (phase 1) or a MutatingTier (phase 2)."""
    tier = MagicMock(spec=ReadOnlyTier if phase == 1 else MutatingTier)
    tier.tier_name = name
    tier.phase = phase
    tier.order = 10
    tier.claims_action.return_value = True
    tier.evaluate = AsyncMock(return_value=[])
    if phase == 2:
        tier.commit = AsyncMock(
            return_value=([], CommitReceipt(tier=name, magnitude=100.0))
        )
        tier.rollback = AsyncMock()
        tier.confirm = AsyncMock()
    return tier


def _only_span(exporter: InMemorySpanExporter, name: str):
    spans = [s for s in exporter.get_finished_spans() if s.name == name]
    assert len(spans) == 1, [s.name for s in exporter.get_finished_spans()]
    return spans[0]


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

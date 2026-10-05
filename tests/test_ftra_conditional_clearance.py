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

"""Phase 1 FTRA: provenance codes, conditional clearance, envelope integrity.

Every fail-closed path here is observed failing closed: unregistered,
invalid and unreadable registries; unknown, zero, over-ceiling and
non-finite magnitudes; low confidence; a raising extractor; a missing
extractor; an unsigned or tampered envelope.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from src.gateway.governance.consensus.engine import extract_field_magnitude
from src.gateway.governance.contracts import ViolationKind
from src.gateway.governance.ftra import classifier as classifier_module
from src.gateway.governance.ftra.autonomy import (
    AutonomousEnvelope,
    conditional_clear_reason,
    safe_magnitude,
)
from src.gateway.governance.ftra.classifier import (
    IrreversibilityClassifier,
    _load_registry_document,
    registry_digest,
    rehash_registry,
)
from src.gateway.governance.ftra.graph_analyzer import PlanGraphAnalyzer
from src.gateway.governance.ftra.models import (
    FTRA_REGISTERED_EXTERNALLY_REVERSIBLE,
    FTRA_REGISTERED_IRREVERSIBLE,
    FTRA_REGISTRY_ENTRY_INVALID,
    FTRA_REGISTRY_UNAVAILABLE,
    FTRA_UNREGISTERED_ACTION,
    ExecutionPlan,
    FtraBoundaryResult,
    FTRAVerdict,
    PlanStep,
    RegistryState,
    TerminalClassification,
)
from src.gateway.governance.governor.pipeline import Profile, StageContext, StageOutput
from src.gateway.governance.governor.stages.ftra import FtraStage
from src.gateway.governance.schemas.thresholds import get_agent_confidence_threshold

pytestmark = [pytest.mark.unit, pytest.mark.local]

_IRR = TerminalClassification.IRREVERSIBLE_TERMINAL
_EXT = TerminalClassification.EXTERNALLY_REVERSIBLE
_CEILING = 100.0
_HIGH = 0.99  # above the agent confidence threshold
_magnitude = extract_field_magnitude("amount")


# ── helpers ──────────────────────────────────────────────────────────────────


def _write_registry(
    path: Path, *, envelope: dict[str, Any] | None = None, sign: bool = True
) -> Path:
    doc: dict[str, Any] = {
        "terminals": {
            "move_funds": "IRREVERSIBLE_TERMINAL",
            "refund": "EXTERNALLY_REVERSIBLE",
            "peek": "READ_ONLY",
            "weird": "NOT_A_CLASSIFICATION",
        }
    }
    if envelope is not None:
        doc["autonomous_envelope"] = envelope
    path.write_text(json.dumps(doc))
    if sign:
        rehash_registry(path)
    return path


@pytest.fixture
def registry(tmp_path: Path) -> Path:
    return _write_registry(
        tmp_path / "terminal_registry.json",
        envelope={"move_funds": {"max_magnitude": _CEILING}},
    )


def _clear(**overrides: Any) -> str | None:
    kwargs: dict[str, Any] = {
        "classification": _IRR,
        "registry_state": RegistryState.REGISTERED,
        "envelope": AutonomousEnvelope(_CEILING),
        "magnitude": 50.0,
        "confidence": _HIGH,
        "confidence_floor": 0.95,
    }
    kwargs.update(overrides)
    return conditional_clear_reason(**kwargs)


def _stage(
    registry_path: Path, extractor: Any = _magnitude
) -> tuple[FtraStage, MagicMock]:
    metrics = MagicMock()
    stage = FtraStage(metrics=metrics, magnitude_extractor=extractor)
    stage._ftra_classifier = IrreversibilityClassifier(registry_path)
    return stage, metrics


async def _output(stage: FtraStage, action: str, **params: Any) -> StageOutput:
    return await stage.run(
        StageContext(action=action, params=params, profile=Profile.FULL)
    )


async def _run(stage: FtraStage, action: str, **params: Any) -> list[Any]:
    return list((await _output(stage, action, **params)).violations)


# ── provenance codes ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("classification", "state", "code", "kind"),
    [
        (
            _IRR,
            RegistryState.REGISTERED,
            FTRA_REGISTERED_IRREVERSIBLE,
            ViolationKind.HITL,
        ),
        (
            _EXT,
            RegistryState.REGISTERED,
            FTRA_REGISTERED_EXTERNALLY_REVERSIBLE,
            ViolationKind.HITL,
        ),
        (
            _IRR,
            RegistryState.UNREGISTERED,
            FTRA_UNREGISTERED_ACTION,
            ViolationKind.HITL,
        ),
        (
            _IRR,
            RegistryState.INVALID_ENTRY,
            FTRA_REGISTRY_ENTRY_INVALID,
            ViolationKind.HITL,
        ),
        (
            _IRR,
            RegistryState.UNAVAILABLE,
            FTRA_REGISTRY_UNAVAILABLE,
            ViolationKind.HARD,
        ),
    ],
)
def test_each_provenance_has_its_own_code(classification, state, code, kind) -> None:
    result = FtraBoundaryResult.from_classification(
        classification, "a", registry_state=state
    )
    assert [(v.code, v.kind) for v in result.violations] == [(code, kind)]
    assert result.requires_hitl and not result.auto_cleared


@pytest.mark.parametrize(
    "state",
    [
        RegistryState.UNREGISTERED,
        RegistryState.INVALID_ENTRY,
        RegistryState.UNAVAILABLE,
    ],
)
def test_clear_reason_on_non_registered_raises(state) -> None:
    with pytest.raises(ValueError, match="only a registered terminal"):
        FtraBoundaryResult.from_classification(
            _IRR, "a", registry_state=state, clear_reason="x"
        )


def test_clear_reason_on_registered_non_terminal_raises() -> None:
    with pytest.raises(ValueError, match="only a registered terminal"):
        FtraBoundaryResult.from_classification(
            TerminalClassification.READ_ONLY,
            "a",
            registry_state=RegistryState.REGISTERED,
            clear_reason="x",
        )


def test_registered_terminal_with_clear_reason_carries_no_violation() -> None:
    result = FtraBoundaryResult.from_classification(
        _IRR,
        "a",
        registry_state=RegistryState.REGISTERED,
        bypassed_ftra_node=True,
        clear_reason="inside envelope",
    )
    assert result.violations == [] and result.auto_cleared and result.is_safe
    assert result.bypassed_ftra_node is False


def test_classifier_reports_provenance(registry: Path) -> None:
    c = IrreversibilityClassifier(registry)
    assert (
        c.classify_with_provenance("move_funds").registry_state
        is RegistryState.REGISTERED
    )
    assert c.classify_with_provenance("move_funds").envelope == AutonomousEnvelope(
        _CEILING
    )
    assert c.classify_with_provenance("refund").envelope is None
    unknown = c.classify_with_provenance("nope")
    assert (unknown.classification, unknown.registry_state) == (
        _IRR,
        RegistryState.UNREGISTERED,
    )
    invalid = c.classify_with_provenance("weird")
    assert (invalid.classification, invalid.registry_state) == (
        _IRR,
        RegistryState.INVALID_ENTRY,
    )


def test_unreadable_registry_is_unavailable(tmp_path: Path) -> None:
    c = IrreversibilityClassifier(tmp_path / "missing.json")
    p = c.classify_with_provenance("move_funds")
    assert (p.classification, p.registry_state, p.envelope) == (
        _IRR,
        RegistryState.UNAVAILABLE,
        None,
    )


# ── the conditional-clear predicate ──────────────────────────────────────────


def test_clears_inside_envelope() -> None:
    assert _clear() is not None
    assert _clear(magnitude=_CEILING) is not None  # ceiling is inclusive
    assert _clear(classification=_EXT) is not None


@pytest.mark.parametrize(
    "overrides",
    [
        {"magnitude": _CEILING + 0.01},
        {"magnitude": 0.0},
        {"magnitude": -5.0},
        {"magnitude": None},
        {"magnitude": math.nan},
        {"magnitude": math.inf},
        {"confidence": 0.94},
        {"envelope": None},
        {"classification": TerminalClassification.REVERSIBLE},
        {"classification": TerminalClassification.READ_ONLY},
        {"registry_state": RegistryState.UNREGISTERED},
        {"registry_state": RegistryState.INVALID_ENTRY},
        {"registry_state": RegistryState.UNAVAILABLE},
    ],
)
def test_never_clears_outside_its_conditions(overrides) -> None:
    assert _clear(**overrides) is None


@pytest.mark.parametrize("bad", [0, -1.0, math.nan, math.inf, True, "100"])
def test_envelope_rejects_bad_ceilings(bad) -> None:
    with pytest.raises(ValueError):
        AutonomousEnvelope(bad)


def test_safe_magnitude_reads_unknown_as_none() -> None:
    def boom(_: Any) -> float:
        raise ValueError("malformed")

    assert safe_magnitude(None, {"amount": 5}) is None
    assert safe_magnitude(boom, {"amount": 5}) is None
    assert safe_magnitude(lambda _: True, {}) is None
    assert safe_magnitude(lambda _: "5", {}) is None
    assert safe_magnitude(_magnitude, {"amount": 5}) == 5.0


# ── envelope integrity (digest covers the ceiling) ──────────────────────────


def test_digest_covers_the_envelope(registry: Path) -> None:
    raw = json.loads(registry.read_text())
    raw["autonomous_envelope"]["move_funds"]["max_magnitude"] = 1e9
    registry.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="integrity check FAILED"):
        _load_registry_document(registry)


def test_digest_without_envelope_hashes_terminals_alone(tmp_path: Path) -> None:
    path = _write_registry(tmp_path / "r.json")
    raw = json.loads(path.read_text())
    assert raw["manifest_sha256"] == registry_digest({"terminals": raw["terminals"]})
    assert registry_digest(raw) != registry_digest(
        {**raw, "autonomous_envelope": {"move_funds": {"max_magnitude": 1.0}}}
    )


def test_unsigned_envelope_is_rejected(tmp_path: Path) -> None:
    path = _write_registry(
        tmp_path / "r.json", envelope={"move_funds": {"max_magnitude": 1.0}}, sign=False
    )
    with pytest.raises(ValueError, match="unsigned envelope"):
        _load_registry_document(path)


@pytest.mark.parametrize(
    ("envelope", "match"),
    [
        ({"nope": {"max_magnitude": 1.0}}, "not in 'terminals'"),
        ({"peek": {"max_magnitude": 1.0}}, "only terminal classifications"),
        ({"weird": {"max_magnitude": 1.0}}, "not recognised"),
        ({"move_funds": {"max_magnitude": 1.0, "extra": 2}}, "must be exactly"),
        ({"move_funds": 5}, "must be exactly"),
        ({"move_funds": {"max_magnitude": -1.0}}, "finite and > 0"),
        ([], "must be an object"),
    ],
)
def test_invalid_envelope_specs_refuse_to_load(tmp_path: Path, envelope, match) -> None:
    path = tmp_path / "r.json"
    doc = {
        "terminals": json.loads(_write_registry(path, sign=False).read_text())[
            "terminals"
        ]
    }
    doc["autonomous_envelope"] = envelope
    doc["manifest_sha256"] = registry_digest(doc)
    path.write_text(json.dumps(doc))
    with pytest.raises(ValueError, match=match):
        _load_registry_document(path)


def test_rehash_cli_round_trips(tmp_path: Path, capsys) -> None:
    path = _write_registry(
        tmp_path / "r.json", envelope={"move_funds": {"max_magnitude": 7.0}}, sign=False
    )
    assert classifier_module.main(["--rehash", str(path)]) == 0
    assert "manifest_sha256" in capsys.readouterr().out
    loaded = _load_registry_document(path)
    assert loaded.autonomous_envelope["move_funds"] == AutonomousEnvelope(7.0)


@pytest.mark.parametrize(
    "path",
    [
        Path("config/ftra/terminal_registry.json"),
        Path("src/cage_healthcare/config/ftra/terminal_registry.json"),
    ],
)
def test_shipped_registries_verify(path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    _load_registry_document(root / path)  # raises on a stale or unsigned envelope


def test_finance_envelope_is_the_10k_ceiling() -> None:
    root = Path(__file__).resolve().parents[1]
    doc = _load_registry_document(root / "config/ftra/terminal_registry.json")
    assert dict(doc.autonomous_envelope) == {
        "execute_trade": AutonomousEnvelope(10_000.0),
        "execute_trade_bounded": AutonomousEnvelope(10_000.0),
    }
    assert "release_wire" not in doc.terminals


# ── the boundary stage ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_stage_clears_inside_envelope(registry: Path) -> None:
    stage, metrics = _stage(registry)
    out = await _output(stage, "move_funds", amount=50.0, confidence=_HIGH)
    assert out.violations == ()
    assert out.ftra is not None and out.ftra.auto_cleared
    assert out.ftra.registry_state is RegistryState.REGISTERED
    metrics.ftra_boundary_check.assert_called_once_with("conditional_clear")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "params",
    [
        {"amount": _CEILING * 2, "confidence": _HIGH},
        {"amount": 0.0, "confidence": _HIGH},
        {"confidence": _HIGH},  # missing magnitude reads 0.0
        {"amount": 50.0, "confidence": 0.5},
        {"amount": 50.0, "confidence": True},  # bool confidence reads 0.0
    ],
)
async def test_stage_escalates_outside_envelope(registry: Path, params) -> None:
    stage, metrics = _stage(registry)
    violations = await _run(stage, "move_funds", **params)
    assert [(v.code, v.kind) for v in violations] == [
        (FTRA_REGISTERED_IRREVERSIBLE, ViolationKind.HITL)
    ]
    metrics.ftra_boundary_check.assert_called_once_with("hitl_required")


@pytest.mark.asyncio
async def test_stage_without_extractor_clears_nothing(registry: Path) -> None:
    stage, _ = _stage(registry, extractor=None)
    violations = await _run(stage, "move_funds", amount=1.0, confidence=_HIGH)
    assert [v.code for v in violations] == [FTRA_REGISTERED_IRREVERSIBLE]


@pytest.mark.asyncio
async def test_stage_with_raising_extractor_clears_nothing(registry: Path) -> None:
    def boom(_: Any) -> float:
        raise RuntimeError("malformed")

    stage, _ = _stage(registry, extractor=boom)
    violations = await _run(stage, "move_funds", amount=1.0, confidence=_HIGH)
    assert [v.code for v in violations] == [FTRA_REGISTERED_IRREVERSIBLE]


@pytest.mark.asyncio
async def test_stage_never_clears_unregistered(registry: Path) -> None:
    stage, _ = _stage(registry)
    violations = await _run(stage, "nope", amount=1.0, confidence=_HIGH)
    assert [(v.code, v.kind) for v in violations] == [
        (FTRA_UNREGISTERED_ACTION, ViolationKind.HITL)
    ]


@pytest.mark.asyncio
async def test_stage_unavailable_registry_is_hard(tmp_path: Path) -> None:
    stage, metrics = _stage(tmp_path / "missing.json")
    violations = await _run(stage, "move_funds", amount=1.0, confidence=_HIGH)
    assert [(v.code, v.kind) for v in violations] == [
        (FTRA_REGISTRY_UNAVAILABLE, ViolationKind.HARD)
    ]
    metrics.ftra_boundary_check.assert_called_once_with("error")


# ── the plan graph analyzer ──────────────────────────────────────────────────


def _plan(*steps: tuple[str, dict[str, Any]]) -> ExecutionPlan:
    return ExecutionPlan(
        plan_id="p",
        rationale="r",
        steps=[
            PlanStep(id=f"s{i}", action=a, description=a, parameters=p)
            for i, (a, p) in enumerate(steps)
        ],
    )


def test_analyzer_clears_terminal_inside_envelope(registry: Path) -> None:
    analyzer = PlanGraphAnalyzer(IrreversibilityClassifier(registry), _magnitude)
    result = analyzer.analyze(
        _plan(("peek", {}), ("move_funds", {"amount": 10.0})), _HIGH
    )
    assert result.verdict is FTRAVerdict.CLEAR
    assert result.auto_cleared_terminals == ["s1"]


def test_analyzer_never_clears_unregistered_step(registry: Path) -> None:
    analyzer = PlanGraphAnalyzer(IrreversibilityClassifier(registry), _magnitude)
    result = analyzer.analyze(
        _plan(("move_funds", {"amount": 10.0}), ("nope", {"amount": 1.0})), _HIGH
    )
    assert result.verdict is not FTRAVerdict.CLEAR


def test_analyzer_over_ceiling_is_not_clear(registry: Path) -> None:
    analyzer = PlanGraphAnalyzer(IrreversibilityClassifier(registry), _magnitude)
    result = analyzer.analyze(
        _plan(
            ("move_funds", {"amount": _CEILING * 10}),
        ),
        _HIGH,
    )
    assert result.verdict is not FTRAVerdict.CLEAR


def test_analyzer_without_extractor_is_unchanged(registry: Path) -> None:
    analyzer = PlanGraphAnalyzer(IrreversibilityClassifier(registry))
    result = analyzer.analyze(
        _plan(
            ("move_funds", {"amount": 10.0}),
        ),
        _HIGH,
    )
    assert result.verdict is not FTRAVerdict.CLEAR
    assert result.auto_cleared_terminals == []


def test_confidence_allow_floor_is_the_clearance_floor() -> None:
    """The predicate's floor in production is the band's ALLOW floor."""
    assert _HIGH >= get_agent_confidence_threshold()

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

"""FTRA's one shape check — the envelope magnitude — fails closed.

FTRA validates no parameter values (docs/governance/FTRA_SCOPE.md). The only
input shape it depends on is the magnitude its autonomous envelope compares.
For an enveloped, registered terminal, every malformed magnitude must keep
the human in the loop: ``FTRA_REGISTERED_IRREVERSIBLE`` (HITL) stays and
``auto_cleared`` is False. Exercised through ``FtraStage.run`` with both the
production extractor (``extract_field_magnitude``) and a raw extractor that
hands the param through unchecked, so the stage's own guard is observed and
not just the extractor's.
"""

from __future__ import annotations

import json
import math
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from src.gateway.governance.consensus.engine import extract_field_magnitude
from src.gateway.governance.contracts import ViolationKind
from src.gateway.governance.ftra.classifier import (
    IrreversibilityClassifier,
    rehash_registry,
)
from src.gateway.governance.ftra.models import FTRA_REGISTERED_IRREVERSIBLE
from src.gateway.governance.governor.pipeline import Profile, StageContext, StageOutput
from src.gateway.governance.governor.stages.ftra import FtraStage

pytestmark = [pytest.mark.unit, pytest.mark.local]

_CEILING = 100.0
_HIGH = 0.99  # above the agent confidence threshold


def _raw(params: Mapping[str, Any]) -> Any:
    """Hands ``amount`` through unchecked (a careless domain extractor)."""
    return params["amount"]


_EXTRACTORS: dict[str, Callable[[Mapping[str, Any]], Any]] = {
    "production": extract_field_magnitude("amount"),
    "raw": _raw,
}

_MALFORMED: dict[str, dict[str, Any]] = {
    "missing": {},
    "none": {"amount": None},
    "string": {"amount": "fifty"},
    "bool_true": {"amount": True},
    "bool_false": {"amount": False},
    "nan": {"amount": math.nan},
    "inf": {"amount": math.inf},
    "neg_inf": {"amount": -math.inf},
    "negative": {"amount": -5.0},
    "zero": {"amount": 0},
    "list": {"amount": [50.0]},
    "dict": {"amount": {"value": 50.0}},
}


@pytest.fixture
def registry(tmp_path: Path) -> Path:
    path = tmp_path / "terminal_registry.json"
    path.write_text(
        json.dumps(
            {
                "terminals": {"move_funds": "IRREVERSIBLE_TERMINAL"},
                "autonomous_envelope": {"move_funds": {"max_magnitude": _CEILING}},
            }
        )
    )
    rehash_registry(path)
    return path


async def _run(registry: Path, extractor: Any, params: dict[str, Any]) -> StageOutput:
    stage = FtraStage(metrics=MagicMock(), magnitude_extractor=extractor)
    stage._ftra_classifier = IrreversibilityClassifier(registry)
    ctx = StageContext(
        action="move_funds",
        params={**params, "confidence": _HIGH},
        profile=Profile.FULL,
    )
    return await stage.run(ctx)


@pytest.mark.asyncio
@pytest.mark.parametrize("extractor_id", sorted(_EXTRACTORS))
@pytest.mark.parametrize("case", sorted(_MALFORMED))
async def test_malformed_magnitude_never_auto_clears(
    registry: Path, extractor_id: str, case: str
) -> None:
    out = await _run(registry, _EXTRACTORS[extractor_id], _MALFORMED[case])

    assert [(v.code, v.kind) for v in out.violations] == [
        (FTRA_REGISTERED_IRREVERSIBLE, ViolationKind.HITL)
    ]
    assert out.ftra is not None
    assert out.ftra.auto_cleared is False
    assert out.ftra.clear_reason is None
    assert out.ftra.requires_hitl is True


@pytest.mark.asyncio
@pytest.mark.parametrize("extractor_id", sorted(_EXTRACTORS))
async def test_well_formed_magnitude_inside_envelope_clears(
    registry: Path, extractor_id: str
) -> None:
    """Control: the same harness does clear a well-formed in-envelope magnitude,
    so the refusals above are the shape check, not a broken fixture."""
    out = await _run(registry, _EXTRACTORS[extractor_id], {"amount": 50.0})

    assert out.violations == ()
    assert out.ftra is not None and out.ftra.auto_cleared is True

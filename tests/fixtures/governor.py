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

"""Test helpers for building a :class:`SymbolicGovernor` from explicit parts.

Production code assembles governors only through
``governor.assembly.assemble_governor``. Unit tests that need a governor over
hand-picked mocks use :func:`make_governor`, which builds the same immutable
:class:`GovernorComponents` directly. The ``governor_factory`` fixture in
``tests/conftest.py`` exposes it to tests.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from src.gateway.governance.classification_engine import ClassificationEngine
from src.gateway.governance.env_posture import DeploymentPosture
from src.gateway.governance.governor.assembly import GovernorComponents, kernel_stages
from src.gateway.governance.governor.governor import SymbolicGovernor
from src.gateway.governance.narrower import NarrowerRegistry


def default_classifier(**overrides: Any) -> ClassificationEngine:
    """The classifier configuration the unit suite has always used."""
    kwargs: dict[str, Any] = {
        "narrower_registry": NarrowerRegistry(),
        "confidence_threshold": 0.70,
        "defer_enabled": True,
        "narrow_enabled": False,
        "pause_enabled": False,
    }
    kwargs.update(overrides)
    return ClassificationEngine(**kwargs)


def allow_opa() -> AsyncMock:
    """An OPA client mock that allows every request."""
    opa = AsyncMock()
    opa.evaluate_policy.return_value = "ALLOW"
    return opa


def clean_stpa() -> MagicMock:
    """An STPA validator mock that reports no unsafe control actions."""
    stpa = MagicMock()
    stpa.validate.return_value = []
    return stpa


def make_governor(
    *,
    opa: Any = None,
    stpa_validator: Any = None,
    classifier: ClassificationEngine | None = None,
    domain_tiers: Sequence[Any] = (),
    core_stages: Sequence[Any] | None = None,
    safety_filter: Any = None,
    consensus: Any = None,
    standing_projector: Any = None,
    invariants: Sequence[Any] = (),
    posture: DeploymentPosture = DeploymentPosture.DEV,
) -> SymbolicGovernor:
    """Build a governor from explicit parts; unspecified parts are permissive mocks.

    ``core_stages`` replaces the kernel stages outright (for tests that swap a
    stage); otherwise they are built from ``opa`` and ``stpa_validator``.
    Unset ``safety_filter`` / ``consensus`` keep the deny-by-default nulls.
    """
    opa = opa if opa is not None else allow_opa()
    stpa_validator = stpa_validator if stpa_validator is not None else clean_stpa()
    extra: dict[str, Any] = {}
    if safety_filter is not None:
        extra["safety_filter"] = safety_filter
    if consensus is not None:
        extra["consensus"] = consensus
    if standing_projector is not None:
        extra["standing_projector"] = standing_projector
    components = GovernorComponents(
        opa=opa,
        core_stages=tuple(core_stages) if core_stages is not None else kernel_stages(opa, stpa_validator),
        classifier=classifier if classifier is not None else default_classifier(),
        domain_tiers=tuple(domain_tiers),
        invariants=tuple(invariants),
        posture=posture,
        **extra,
    )
    return SymbolicGovernor(components)

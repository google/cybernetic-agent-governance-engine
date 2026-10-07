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

import asyncio
from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from src.gateway.governance.classification_engine import ClassificationEngine
from src.gateway.governance.env_posture import DeploymentPosture
from src.gateway.governance.governor.assembly import GovernorComponents, kernel_stages
from src.gateway.governance.governor.governor import SymbolicGovernor
from src.gateway.governance.narrower import NarrowerRegistry
from src.gateway.governance.warrant import Warrant

#: The evaluation instant the warrant fixtures are issued around.
WARRANT_TEST_NOW = datetime(2026, 8, 22, 12, 0, tzinfo=timezone.utc)

#: The governing_version the EU_ECB binding and the v0.1 vectors carry.
WARRANT_TEST_GOVERNING_VERSION = "cage-policy-2.1.0"


def issue_test_warrant(**overrides: Any) -> Warrant:
    """An ACTIVE EU_ECB warrant for the trade-confidence norm, digest declared.

    Mirrors the VEIP v0.1 shared vector; ``overrides`` replace individual
    fields before the digest is computed (so the result is still intact).
    """
    fields: dict[str, Any] = {
        "warrant_id": "warrant-test-001",
        "norm_id": "confidence.min_trade_confidence",
        "issuing_authority": "Risk Oversight Committee (EU_ECB)",
        "authority_basis": "Test instrument",
        "scope": {
            "actions": ["execute_trade", "execute_trade_bounded"],
            "actors": ["*"],
            "systems": ["*"],
            "jurisdictions": ["EU_ECB"],
        },
        "valid_from": "2026-08-01T00:00:00Z",
        "valid_until": "2026-12-31T23:59:59Z",
        "governing_version": WARRANT_TEST_GOVERNING_VERSION,
        "status": "ACTIVE",
        "revocation_ref": None,
        "residual_risk_ref": None,
    }
    fields.update(overrides)
    return Warrant.issue(**fields)


class StaticWarrantSource:
    """Hermetic :class:`WarrantSource`: serves fixed warrants by ``norm_id``.

    ``error`` makes every fetch raise it; ``hang`` makes every fetch block
    until cancelled (to exercise the stage timeout). ``calls`` records the
    requested norm ids in order.
    """

    provider_name = "static_test_source"

    def __init__(
        self,
        warrants: dict[str, Warrant] | None = None,
        *,
        error: BaseException | None = None,
        hang: bool = False,
    ) -> None:
        self._warrants = dict(warrants or {})
        self._error = error
        self._hang = hang
        self.calls: list[str] = []

    @classmethod
    def eligible(cls) -> StaticWarrantSource:
        """A source holding an intact, in-scope, current trade-confidence warrant."""
        warrant = issue_test_warrant()
        return cls({warrant.norm_id: warrant})

    def put(self, warrant: Warrant) -> None:
        """Replace the served warrant for its norm (e.g. with a revoked one)."""
        self._warrants[warrant.norm_id] = warrant

    async def fetch(self, norm_id: str) -> Warrant | None:
        self.calls.append(norm_id)
        if self._error is not None:
            raise self._error
        if self._hang:
            await asyncio.Event().wait()
        return self._warrants.get(norm_id)


def default_classifier(**overrides: Any) -> ClassificationEngine:
    """The classifier configuration the unit suite has always used."""
    kwargs: dict[str, Any] = {
        "narrower_registry": NarrowerRegistry(),
        "confidence_threshold": 0.70,
        "defer_enabled": True,
        "narrow_enabled": False,
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
    invariants: Sequence[Any] = (),
    posture: DeploymentPosture = DeploymentPosture.DEV,
    magnitude_extractor: Any = None,
) -> SymbolicGovernor:
    """Build a governor from explicit parts; unspecified parts are permissive mocks.

    ``core_stages`` replaces the kernel stages outright (for tests that swap a
    stage); otherwise they are built from ``opa``, ``stpa_validator`` and
    ``magnitude_extractor`` (conditional FTRA; ``None`` clears nothing).
    Unset ``safety_filter`` / ``consensus`` keep the deny-by-default nulls.
    """
    opa = opa if opa is not None else allow_opa()
    stpa_validator = stpa_validator if stpa_validator is not None else clean_stpa()
    extra: dict[str, Any] = {}
    if safety_filter is not None:
        extra["safety_filter"] = safety_filter
    if consensus is not None:
        extra["consensus"] = consensus
    components = GovernorComponents(
        opa=opa,
        core_stages=(
            tuple(core_stages)
            if core_stages is not None
            else kernel_stages(
                opa, stpa_validator, magnitude_extractor=magnitude_extractor
            )
        ),
        classifier=classifier if classifier is not None else default_classifier(),
        domain_tiers=tuple(domain_tiers),
        invariants=tuple(invariants),
        posture=posture,
        **extra,
    )
    return SymbolicGovernor(components)

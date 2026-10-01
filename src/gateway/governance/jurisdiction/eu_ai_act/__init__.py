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

"""EU AI Act (Regulation (EU) 2024/1689) obligations for the ``EU_ECB`` region.

:func:`contribution` builds the ``fria`` tier (Art. 27) over the deployment's
``NormativeProvider`` and the posture requirement that an enforcing posture
never runs it on the development stub.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from src.gateway.governance.jurisdiction.contribution import (
    JurisdictionContribution,
    PostureRequirement,
)
from src.gateway.governance.jurisdiction.eu_ai_act.fria_tier import (
    ActionClaim,
    AssessmentLookup,
    FriaTier,
)
from src.gateway.governance.seams.normative import NormativeProvider

REGION = "EU_ECB"

_REPO_ROOT = Path(__file__).resolve().parents[5]
#: Regional thresholds carrying ``fria.fria_reassessment_interval_days``.
THRESHOLDS_PATH = _REPO_ROOT / "config" / "thresholds" / f"{REGION}_BASELINE.json"
GATE_TIMEOUT_ENV = "CAGE_NORMATIVE_GATE_TIMEOUT_SECONDS"
_DEFAULT_GATE_TIMEOUT_SECONDS = 5.0


def load_reassessment_interval_days(path: Path = THRESHOLDS_PATH) -> float:
    """``fria.fria_reassessment_interval_days`` from the EU thresholds baseline.

    Raises:
        RuntimeError: The file or the key is missing or not a number — the
            tier cannot judge currency without it, so the EU posture does
            not start.
    """
    try:
        raw = json.loads(path.read_text())
        value = raw["fria"]["fria_reassessment_interval_days"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise RuntimeError(
            f"cannot read fria.fria_reassessment_interval_days from {path}: {exc}"
        ) from exc
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RuntimeError(f"fria.fria_reassessment_interval_days in {path} is not a number: {value!r}")
    return float(value)


def registry_assessment_lookup(action: str) -> Mapping[str, Any] | None:
    """The FRIA artefact for ``action`` from the loaded regional baseline.

    Artefacts live under ``CTRL_FRIA_006.assessments`` in the baseline the
    ``NormativeProviderDaemon`` fetches (``fetch_baseline``) and loads into
    ``ControlRegistry``, so the hot path never touches the network. A
    registry for another region has no ``CTRL_FRIA_006``: every lookup is
    then None (stale, fail closed).
    """
    from src.gateway.governance.constants import ControlRegistry, GovernanceControl

    mapping = ControlRegistry().get_mapping_safe(GovernanceControl.FRIA_ASSESSMENT) or {}
    assessments = mapping.get("assessments") or {}
    artefact = assessments.get(action) if isinstance(assessments, Mapping) else None
    return artefact if isinstance(artefact, Mapping) else None


def gate_timeout_seconds() -> float:
    raw = os.environ.get(GATE_TIMEOUT_ENV)
    if raw is None:
        return _DEFAULT_GATE_TIMEOUT_SECONDS
    try:
        return float(raw)
    except ValueError as exc:
        raise RuntimeError(f"{GATE_TIMEOUT_ENV}={raw!r} is not a number") from exc


def require_real_provider(provider: NormativeProvider) -> None:
    """Posture requirement: the FRIA tier is not backed by the stub.

    The stub admits every ``validate_fria()`` call, which would make
    ``CTRL_FRIA_006`` pass unconditionally.
    """
    from src.gateway.governance.normative_provider import is_stub_provider

    if is_stub_provider(provider):
        raise RuntimeError(
            "the fria tier (CTRL_FRIA_006, EU AI Act Art. 27) is backed by the stub "
            "NormativeProvider, which admits every assessment; set "
            "CAGE_NORMATIVE_PROVIDER to a real provider for an enforcing EU posture"
        )


def contribution(
    *,
    provider: NormativeProvider | None = None,
    assessment_lookup: AssessmentLookup = registry_assessment_lookup,
    claims: ActionClaim | None = None,
) -> JurisdictionContribution:
    """The EU contribution: one ``fria`` tier plus its posture requirement.

    ``provider`` defaults to ``get_normative_provider()`` (``CAGE_NORMATIVE_PROVIDER``).
    """
    if provider is None:
        from src.gateway.governance.normative_provider import get_normative_provider

        provider = get_normative_provider()
    tier = FriaTier(
        provider,
        region=REGION,
        assessment_lookup=assessment_lookup,
        reassessment_interval_days=load_reassessment_interval_days(),
        gate_timeout_seconds=gate_timeout_seconds(),
        claims=claims,
    )
    return JurisdictionContribution(
        region=REGION,
        tiers=(tier,),
        runtime_requirements=(
            PostureRequirement("fria_normative_provider", lambda: require_real_provider(provider)),
        ),
    )


__all__ = [
    "REGION",
    "FriaTier",
    "contribution",
    "load_reassessment_interval_days",
    "registry_assessment_lookup",
    "require_real_provider",
]

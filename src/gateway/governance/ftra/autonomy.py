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

"""Conditional FTRA: when a registered terminal may proceed without a human.

A domain's FTRA registry may grant a terminal action an *autonomous envelope*
(``"autonomous_envelope": {"execute_trade": {"max_magnitude": 10000.0}}``).
Inside it the action clears FTRA on its own; outside it, a human approves.

The envelope is authority, so the registry digest covers it
(``classifier.registry_digest``) and the decision is one pure predicate,
:func:`conditional_clear_reason`, shared by the boundary stage and the plan
graph analyzer. The predicate is closed by construction: anything it cannot
establish (unregistered action, unreadable registry, unknown magnitude) keeps
the human in the loop.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from src.gateway.governance.ftra.models import RegistryState, TerminalClassification

#: A domain-supplied reader of an action's magnitude (e.g. trade amount, dose)
#: from its params. It raises on malformed input; the caller treats a raise as
#: "magnitude unknown", which never clears.
MagnitudeExtractor = Callable[[Mapping[str, Any]], float]

#: Classifications an envelope may clear. READ_ONLY / REVERSIBLE never need one.
ENVELOPE_CLASSIFICATIONS: frozenset[TerminalClassification] = frozenset(
    {
        TerminalClassification.IRREVERSIBLE_TERMINAL,
        TerminalClassification.EXTERNALLY_REVERSIBLE,
    }
)


@dataclass(frozen=True)
class AutonomousEnvelope:
    """The magnitude ceiling under which a registered terminal clears FTRA."""

    max_magnitude: float

    def __post_init__(self) -> None:
        value = self.max_magnitude
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"max_magnitude must be a number, got {value!r}")
        if not math.isfinite(value) or value <= 0:
            raise ValueError(f"max_magnitude must be finite and > 0, got {value!r}")


def conditional_clear_reason(
    *,
    classification: TerminalClassification,
    registry_state: RegistryState,
    envelope: AutonomousEnvelope | None,
    magnitude: float | None,
    confidence: float,
    confidence_floor: float,
) -> str | None:
    """Why the terminal clears FTRA autonomously, or ``None`` if a human must approve.

    Clears iff every condition holds:

    * the action is **registered** (an unregistered, invalid or unreadable
      entry never clears — ``UNREGISTERED_NEVER_AUTO_CLEARS``);
    * its classification is a terminal one (``ENVELOPE_CLASSIFICATIONS``);
    * the registry grants it an envelope;
    * its magnitude is known and ``0 < magnitude <= max_magnitude``;
    * the agent's confidence is at least ``confidence_floor`` (FRIA zone_allow).
    """
    if registry_state is not RegistryState.REGISTERED:
        return None
    if classification not in ENVELOPE_CLASSIFICATIONS or envelope is None:
        return None
    if magnitude is None or not math.isfinite(magnitude):
        return None
    if not 0.0 < magnitude <= envelope.max_magnitude:
        return None
    if confidence < confidence_floor:
        return None
    return (
        f"magnitude {magnitude:g} <= autonomous ceiling {envelope.max_magnitude:g} "
        f"at confidence {confidence:.2f} >= {confidence_floor:.2f}"
    )


def safe_magnitude(
    extractor: MagnitudeExtractor | None, params: Mapping[str, Any]
) -> float | None:
    """``extractor(params)``, or ``None`` when there is no extractor or it raises.

    ``None`` means "magnitude unknown", which :func:`conditional_clear_reason`
    never clears.
    """
    if extractor is None:
        return None
    try:
        value = extractor(params)
    except Exception:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)

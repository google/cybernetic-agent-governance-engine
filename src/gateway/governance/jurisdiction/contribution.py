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

"""What a jurisdiction hands the composition root: tiers + startup requirements."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from src.gateway.governance.consequence_magnitude import ConsequenceMagnitudes
from src.gateway.governance.contracts import ReadOnlyTier


@dataclass(frozen=True)
class PostureRequirement:
    """A startup condition a jurisdiction imposes on an enforcing posture.

    ``check`` raises (any exception) when the requirement is unmet;
    ``assert_production_posture`` refuses an enforcing posture on it and logs
    it at CRITICAL under a permissive one, like every other posture check.
    """

    name: str
    check: Callable[[], None]


@dataclass(frozen=True)
class JurisdictionContribution:
    """The obligations one deployment region adds to every domain.

    ``tiers`` are merged after the domain tiers and sorted with them by
    ``(phase, order, tier_name)``. They must be :class:`ReadOnlyTier` (phase 1):
    a jurisdiction obligation is an assessment, never a barrier that reserves
    state. They must also declare ``revalidated_after_approval``: the
    assessment is an external authority's, which can be revoked or expire
    while a human reviews the request, so POST_HITL re-runs every
    jurisdiction tier before an approved request is sealed
    (``proof/model.py`` claim 10, ``post_hitl_rechecks_jurisdiction``).

    ``consequence_magnitudes`` is the declared consequence-magnitude policy
    the region's tiers check, or ``None`` when they check none (or were
    built without one, which refuses every action they claim).
    ``assemble_governor()`` refuses a contribution whose policy is not the
    one the domain contributions declare.

    Raises:
        TypeError: A contributed tier is not a ``ReadOnlyTier``, or
            ``consequence_magnitudes`` is neither ``None`` nor a
            ``ConsequenceMagnitudes``.
        ValueError: A contributed tier is not ``revalidated_after_approval``.
    """

    region: str
    tiers: tuple[ReadOnlyTier, ...] = ()
    runtime_requirements: tuple[PostureRequirement, ...] = ()
    consequence_magnitudes: ConsequenceMagnitudes | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "tiers", tuple(self.tiers))
        object.__setattr__(
            self, "runtime_requirements", tuple(self.runtime_requirements)
        )
        if self.consequence_magnitudes is not None and not isinstance(
            self.consequence_magnitudes, ConsequenceMagnitudes
        ):
            raise TypeError(
                f"jurisdiction {self.region!r}: consequence_magnitudes must be a "
                "ConsequenceMagnitudes or None"
            )
        for tier in self.tiers:
            if not isinstance(tier, ReadOnlyTier):
                raise TypeError(
                    f"jurisdiction {self.region!r}: tier {getattr(tier, 'tier_name', tier)!r} "
                    "is not a ReadOnlyTier; jurisdiction tiers must be read-only (phase 1)"
                )
            if tier.revalidated_after_approval is not True:
                raise ValueError(
                    f"jurisdiction {self.region!r}: tier {tier.tier_name!r} is not "
                    "revalidated_after_approval; a jurisdiction assessment can change "
                    "while a human reviews the request, so it must be re-run after "
                    "approval"
                )

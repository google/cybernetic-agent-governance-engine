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
    ``(phase, order, tier_name)``. They must be :class:`ReadOnlyTier` (phase 1): a
    jurisdiction obligation is an assessment, never a barrier that reserves
    state, so it can never change what POST_HITL re-runs (``proof/model.py``
    asserts this for every entry of ``JURISDICTION_TIERS``).

    Raises:
        TypeError: A contributed tier is not a ``ReadOnlyTier``.
    """

    region: str
    tiers: tuple[ReadOnlyTier, ...] = ()
    runtime_requirements: tuple[PostureRequirement, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "tiers", tuple(self.tiers))
        object.__setattr__(
            self, "runtime_requirements", tuple(self.runtime_requirements)
        )
        for tier in self.tiers:
            if not isinstance(tier, ReadOnlyTier):
                raise TypeError(
                    f"jurisdiction {self.region!r}: tier {getattr(tier, 'tier_name', tier)!r} "
                    "is not a ReadOnlyTier; jurisdiction tiers must be read-only (phase 1)"
                )

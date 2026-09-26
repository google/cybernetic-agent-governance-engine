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

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping, Protocol

from proof.model import TIERS
from src.gateway.governance.contracts import GovernanceTierFailure, Violation
from src.gateway.governance.ftra.models import FtraBoundaryResult


class Profile(StrEnum):
    FULL = "FULL"
    POST_HITL = "POST_HITL"
    DRY_RUN = "DRY_RUN"


class OpaVerdict(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    MANUAL_REVIEW = "MANUAL_REVIEW"


@dataclass(frozen=True)
class StageContext:
    action: str
    params: Mapping[str, Any]
    profile: Profile
    opa_verdict: OpaVerdict | None = None


class Stage(Protocol):
    name: str
    mutating: bool

    async def run(self, ctx: StageContext) -> list[Violation]: ...
    
    async def rollback(self, ctx: StageContext) -> None: ...  # no-op default for read-only stages


@dataclass(frozen=True)
class PipelineResult:
    violations: tuple[Violation, ...]
    tier_failures: tuple[GovernanceTierFailure, ...]
    opa_verdict: OpaVerdict | None
    ftra: FtraBoundaryResult | None
    committed_stages: tuple[str, ...]


# Stage names must be members of proof/model.py TIERS
PROFILE_STAGES: Mapping[Profile, frozenset[str]] = {
    Profile.FULL: frozenset(TIERS),
    Profile.DRY_RUN: frozenset(TIERS),
    Profile.POST_HITL: frozenset({"opa", "cbf"}),
}

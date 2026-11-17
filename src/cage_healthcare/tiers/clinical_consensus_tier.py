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

from pathlib import Path
from typing import Any

from src.cage_healthcare.constants import (
    HIGH_STAKES_CLINICAL_ACTIONS,
    REGISTERED_ACTIONS,
)
from src.gateway.governance import consensus as _cs
from src.gateway.governance import contracts as _ct

_CRITICS_PATH = Path(__file__).resolve().parent.parent / "config" / "critics.yaml"
_REJ = "CLINICAL_CONSENSUS_REJECTED"


def load_healthcare_critics(path: Path = _CRITICS_PATH) -> tuple[_ct.CriticSpec, ...]:
    return _cs.load_critic_specs(path)


def build_healthcare_consensus_contribution() -> _ct.ConsensusContribution:
    ext = _cs.extract_field_magnitude("dose_mg")
    return _ct.ConsensusContribution(
        load_healthcare_critics(), 100.0, ext, HIGH_STAKES_CLINICAL_ACTIONS
    )


def build_healthcare_consensus_gate() -> _cs.ConsensusGate:
    return _cs.ConsensusGate.from_contribution(
        build_healthcare_consensus_contribution()
    )


class ClinicalConsensusTier(_ct.ReadOnlyTier):
    tier_name: str = "clinical_consensus"
    order: int = 5

    def __init__(self, consensus_engine: Any = None) -> None:
        e = consensus_engine
        empty = isinstance(e, _cs.ConsensusGate) and not e.critics
        self.consensus_engine = (
            build_healthcare_consensus_gate() if (e is None or empty) else e
        )

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return action in REGISTERED_ACTIONS

    def _reject(
        self, m: str, k: _ct.ViolationKind = _ct.ViolationKind.HARD, c: str = _REJ
    ) -> list[_ct.Violation]:
        return [_ct.Violation(self.tier_name, c, m, k)]

    async def evaluate(
        self, action: str, params: dict[str, Any]
    ) -> list[_ct.Violation]:
        if self.consensus_engine is None:
            return self._reject("Clinical consensus engine is not configured")
        res = await self.consensus_engine.check_consensus(
            action_type=action, params=params
        )
        if not isinstance(res, dict):
            return self._reject("Invalid clinical consensus result payload")
        if _cs.consensus_admits(res):
            return []
        r = str(res.get("reason") or "Multi-critic consensus not achieved")
        k = (
            _ct.ViolationKind.HITL
            if res.get("status") == "ESCALATE"
            else _ct.ViolationKind.HARD
        )
        return self._reject(r, k=k, c=_cs.consensus_violation_code(res, _REJ))

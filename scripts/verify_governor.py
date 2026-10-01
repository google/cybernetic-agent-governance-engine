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

"""Smoke-check the governor's confidence gate through the composition root.

Assembles a governor with :func:`assemble_governor` over a one-tier stub
plugin (mock OPA and STPA, no Redis/KMS), runs the same
:func:`assert_production_posture` every entry point runs, then checks that
a dry-run ``verify()`` passes a confident request and refuses an
under-confident one (dry run: no seal, so no Redis evidence chain needed).
Under an enforcing posture the posture check refuses to start without real
KMS/Redis, which is the intended behaviour; run with ``CAGE_ENV=dev``.

The probe uses the finance registry's READ_ONLY ``check_balance`` action so
the FTRA stage does not fail closed on an unregistered action name.
"""

import asyncio
import os
import sys
from typing import Any
from unittest.mock import AsyncMock, MagicMock

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.gateway.governance.contracts import (
    PluginContribution,
    ReadOnlyTier,
    Violation,
)
from src.gateway.governance.env_posture import resolve_posture
from src.gateway.governance.governor.assembly import assemble_governor
from src.gateway.governance.governor.posture import assert_production_posture

os.environ.setdefault("CAGE_DOMAIN", "finance")

_ACTION = "check_balance"


class _PassTier(ReadOnlyTier):
    """Claims the probe action so the full kernel profile (incl. confidence) runs."""

    tier_name = "verify_probe"
    order = 1

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return action == _ACTION

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        return []


class _ProbePlugin:
    name = "verify_probe"
    api_version = "2.0"
    domain_config = None

    def contribute(self) -> PluginContribution:
        return PluginContribution(domain=self.name, tiers=(_PassTier(),))


async def main() -> int:
    opa = AsyncMock()
    opa.evaluate_policy.return_value = "ALLOW"
    stpa = MagicMock()
    stpa.validate.return_value = []

    posture = resolve_posture()
    governor = assemble_governor([_ProbePlugin()], posture=posture, opa=opa, stpa_validator=stpa)
    assert_production_posture(posture, components=governor.components)

    failures = 0
    for confidence, expect_pass in ((0.99, True), (0.10, False)):
        result = await governor.verify(_ACTION, {"confidence": confidence})
        passed = not result["violations"]
        ok = passed is expect_pass
        failures += not ok
        print(f"{'✅' if ok else '❌'} confidence={confidence}: {'admissible' if passed else 'refused'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

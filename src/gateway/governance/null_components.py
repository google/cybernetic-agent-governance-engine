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

"""Fail-closed null objects for bare-kernel mode.

When no domain plugin is loaded (CAGE_ACTIVE_PLUGINS=""), the kernel uses these
null implementations. They are NOT no-ops: every method returns a denial verdict.

A kernel with no plugin denies everything by intent (G2 gate), not by accident.
"""

from typing import Any


class NullSafetyFilter:
    """Fail-closed SafetyFilter used when no domain plugin is loaded.

    Every method returns a denial verdict. This ensures that a missing plugin
    produces explicit DENY verdicts rather than silent failures or AttributeError
    exceptions that might be caught by CBF_FAIL_OPEN error handlers.
    """

    def verify_action(self, action_name: str, payload: dict) -> str:
        return "UNSAFE: no domain safety filter registered (bare-kernel mode)"

    async def atomic_verify_and_commit(
        self, action_name: str, payload: dict, governance_signature: str = ""
    ) -> tuple[bool, str]:
        """Always denies. Returns (False, reason).

        Critical: This must return (False, ...) NOT raise an exception.
        If it raised, the exception would be caught by broad exception handlers
        in the CBF tier, and with CBF_FAIL_OPEN=true that could produce a
        silent fail-open. Returning False ensures the denial travels the normal
        verdict path.
        """
        return (
            False,
            "UNSAFE: no domain safety filter registered (bare-kernel mode)",
        )

    async def rollback_state(
        self, magnitude: float, governance_signature: str | None = None
    ) -> None:
        """No-op rollback — there was no state to commit in the first place."""
        return None


class NullConsensusProvider:
    """Fail-closed ConsensusProvider used when no domain plugin is loaded.

    Always returns REJECT status.
    """

    async def check_consensus(
        self, action: str, context: dict[str, Any], magnitude: float | None = None
    ) -> dict[str, Any]:
        """Always rejects.

        Returns a properly structured consensus response with REJECT status
        so the denial integrates cleanly with the tier loop.
        """
        return {
            "status": "REJECT",
            "reason": "no consensus provider registered (bare-kernel mode)",
            "agreement_level": 0.0,
            "critics_polled": 0,
            "critics_agreed": 0,
        }

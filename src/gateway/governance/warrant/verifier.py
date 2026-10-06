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

"""
Warrant standing verifier (vendor-neutral kernel mechanism).

Governing Rule:
  A warrant failure removes CAGE's right to rely on that norm. It does not
  itself become an institutional ALLOW or DENY.

Precision:
  CAGE verifies the supplied warrant object is authentic, current, applicable,
  and eligible for reliance; it does not establish the underlying institutional
  truth.

Fail-closed invariant:
  The evaluation context must carry ``action``, ``jurisdiction`` and
  ``governing_version``; absence is UNRESOLVED, never "in scope".
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from src.gateway.governance.warrant.model import (
    REQUIRED_CONTEXT_KEYS,
    SCOPE_DIMENSIONS,
    RelianceStatus,
    StandingVerificationResult,
    Warrant,
    WarrantScope,
    WarrantStatus,
)


class WarrantStandingVerifier:
    """CAGE verifier for checking standing and reliance eligibility of warrants.

    Check order (first failure wins):
      0. Presence: a warrant was supplied (else MISSING).
      1. Context: action, jurisdiction and governing_version are supplied.
      2. Integrity: a digest is declared and equals the recomputed JCS digest.
      3. Status: ACTIVE (REVOKED -> REVOKED; SUSPENDED/unknown -> UNRESOLVED).
      4. Currency: evaluation time within [valid_from, valid_until].
      5. Version: governing_version equals the runtime governing version.
      6. Scope: well-formed four-dimension scope admits the context.
    """

    @classmethod
    def verify_standing(
        cls,
        warrant: Warrant | None,
        context: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> StandingVerificationResult:
        """Evaluate standing and return reliance eligibility."""
        context = context or {}
        current_time = now or datetime.now(timezone.utc)
        evaluated_at = current_time.isoformat()

        if warrant is None:
            return StandingVerificationResult(
                eligible=False,
                reliance_status=RelianceStatus.INELIGIBLE_MISSING,
                reason="Warrant is missing; cannot ground reliance on norm",
                evaluated_at=evaluated_at,
            )

        def _ineligible(
            status: RelianceStatus, reason: str
        ) -> StandingVerificationResult:
            return StandingVerificationResult(
                eligible=False,
                reliance_status=status,
                reason=reason,
                evaluated_at=evaluated_at,
                warrant=warrant,
                warrant_id=warrant.warrant_id,
                warrant_digest=warrant.digest,
            )

        # 1. Context completeness
        missing_keys = [k for k in REQUIRED_CONTEXT_KEYS if not context.get(k)]
        if missing_keys:
            return _ineligible(
                RelianceStatus.INELIGIBLE_UNRESOLVED,
                f"Evaluation context missing required keys: {missing_keys}",
            )

        # 2. Cryptographic integrity
        if not warrant.digest:
            return _ineligible(
                RelianceStatus.INELIGIBLE_UNRESOLVED,
                "Warrant carries no declared digest; integrity cannot be established",
            )
        computed_digest = warrant.compute_digest()
        if warrant.digest != computed_digest:
            return _ineligible(
                RelianceStatus.INELIGIBLE_UNRESOLVED,
                f"Cryptographic digest mismatch: declared {warrant.digest[:16]}... "
                f"vs computed {computed_digest[:16]}...",
            )

        # 3. Status
        if warrant.status == WarrantStatus.REVOKED:
            return _ineligible(
                RelianceStatus.INELIGIBLE_REVOKED,
                f"Warrant revoked: {warrant.revocation_ref or 'revocation basis recorded'}",
            )
        if warrant.status == WarrantStatus.SUSPENDED:
            return _ineligible(
                RelianceStatus.INELIGIBLE_UNRESOLVED,
                f"Warrant suspended: {warrant.revocation_ref or 'suspension active'}",
            )
        if warrant.status != WarrantStatus.ACTIVE:
            return _ineligible(
                RelianceStatus.INELIGIBLE_UNRESOLVED,
                f"Warrant has unrecognised status: {warrant.status}",
            )

        # 4. Currency
        try:
            from_dt = datetime.fromisoformat(warrant.valid_from.replace("Z", "+00:00"))
            until_dt = datetime.fromisoformat(
                warrant.valid_until.replace("Z", "+00:00")
            )
            out_of_window = current_time < from_dt or current_time > until_dt
        except (TypeError, ValueError) as dt_exc:
            return _ineligible(
                RelianceStatus.INELIGIBLE_UNRESOLVED,
                f"Invalid temporal comparison: {dt_exc}",
            )
        if out_of_window:
            return _ineligible(
                RelianceStatus.INELIGIBLE_EXPIRED,
                f"Warrant temporal window invalid: current {evaluated_at} outside "
                f"[{warrant.valid_from}, {warrant.valid_until}]",
            )

        # 5. Version
        expected_version = context["governing_version"]
        if warrant.governing_version != expected_version:
            return _ineligible(
                RelianceStatus.INELIGIBLE_VERSION_MISMATCH,
                f"Governing version mismatch: expected {expected_version} "
                f"vs warrant {warrant.governing_version}",
            )

        # 6. Scope
        if not isinstance(warrant.scope, WarrantScope):
            return _ineligible(
                RelianceStatus.INELIGIBLE_UNRESOLVED,
                f"Warrant scope malformed; all of {list(SCOPE_DIMENSIONS)} are required",
            )
        if not warrant.scope.contains(
            action=context["action"],
            jurisdiction=context["jurisdiction"],
            actor=context.get("actor"),
            system=context.get("system"),
        ):
            return _ineligible(
                RelianceStatus.INELIGIBLE_OUT_OF_SCOPE,
                f"Context ({context}) is outside warrant scope ({warrant.scope.to_dict()})",
            )

        return StandingVerificationResult(
            eligible=True,
            reliance_status=RelianceStatus.ELIGIBLE,
            reason="Warrant standing verified and active; norm eligible for reliance",
            evaluated_at=evaluated_at,
            warrant=warrant,
            warrant_id=warrant.warrant_id,
            warrant_digest=warrant.digest,
        )

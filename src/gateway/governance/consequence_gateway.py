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
consequence_gateway.py — Post-FRIA Consequence Evaluation Gateway

Vendor-agnostic post-FRIA consequence boundary ported from FlowSignal's
production integration candidate. Verifies a ConsequenceToken, re-derives
the action digest, and atomically consumes the authority record before
permitting execution.

6-step evaluation sequence:
  1. JWS signature verification (via ConsequenceToken.verify)
  2. TTL / expiry check
  3. Recompute JCS digest of the action payload
  4. Compare recomputed digest to the `act` claim
  5. Atomic single-use consumption (ConsequenceAuthorityStore)
  6. Emit EXECUTE / HOLD / BLOCK decision with reason code

Steps 1-2 are both handled inside ConsequenceToken.verify(), which raises
ConsequenceTokenError on any failure (bad signature, expired, alg: none,
algorithm confusion, malformed, missing claims).
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from src.gateway.governance.consequence_authority_store import (
    ConsequenceAuthorityStore,
)
from src.gateway.governance.consequence_token import (
    ConsequenceToken,
    ConsequenceTokenError,
)
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

if TYPE_CHECKING:
    from src.gateway.governance.kms_signer import KMSGovernanceSigner

logger = logging.getLogger("Gateway.Governance.ConsequenceGateway")


class ConsequenceDecision(str, Enum):
    """Post-FRIA consequence decision (ported from FlowSignal vendor file)."""

    EXECUTE = "EXECUTE"
    HOLD = "HOLD"
    BLOCK = "BLOCK"


@dataclass
class ConsequenceEvaluation:
    """Result of consequence gateway evaluation.

    Attributes:
        decision: EXECUTE / HOLD / BLOCK verdict.
        reason_code: Machine-readable reason (e.g. TOKEN_INVALID, OK).
        detail: Optional human-readable diagnostic detail.
    """

    decision: ConsequenceDecision
    reason_code: str
    detail: str = ""


class ConsequenceGateway:
    """Vendor-agnostic post-FRIA consequence boundary.

    Preserves FlowSignal's 6-step check sequence while applying CAGE-side
    substitutions (ConsequenceToken instead of vendor's AuthorityRecordBinding,
    ConsequenceAuthorityStore instead of SQLite/in-memory stores).

    The 6 steps:
      1. JWS signature verification (via ConsequenceToken.verify)
      2. TTL / expiry check
      3. Recompute JCS digest of the action payload
      4. Compare recomputed digest to the `act` claim
      5. Atomic single-use consumption (ConsequenceAuthorityStore)
      6. Emit EXECUTE / HOLD / BLOCK decision with reason code

    Steps 1-2 are both handled inside ConsequenceToken.verify(), which raises
    ConsequenceTokenError on any failure (bad signature, expired, alg: none,
    algorithm confusion, malformed, missing claims).
    """

    def __init__(
        self,
        store: ConsequenceAuthorityStore,
        signer: KMSGovernanceSigner,
    ) -> None:
        """Initialize the consequence gateway.

        Args:
            store: ConsequenceAuthorityStore for atomic single-use consumption.
            signer: KMSGovernanceSigner for token verification.
        """
        self._store = store
        self._signer = signer

    async def evaluate(
        self,
        token: str,
        action_payload: dict,
    ) -> ConsequenceEvaluation:
        """Evaluate a consequence authority token against the current action payload.

        Args:
            token: Compact JWS ConsequenceToken string.
            action_payload: Current action payload (will be JCS-canonicalized).

        Returns:
            ConsequenceEvaluation with decision and reason code.
        """
        # Steps 1-2: signature + TTL verification (raises ConsequenceTokenError on failure)
        try:
            claims = ConsequenceToken.verify(token, signer=self._signer)
        except ConsequenceTokenError as exc:
            logger.warning("[ConsequenceGateway] Token verification failed: %s", exc)
            return ConsequenceEvaluation(
                decision=ConsequenceDecision.BLOCK,
                reason_code="TOKEN_INVALID",
                detail=str(exc),
            )

        # Steps 3-4: JCS digest re-verification (closes TOCTOU gap)
        recomputed_digest = hashlib.sha256(
            jcs_canonicalize_plan(action_payload)
        ).hexdigest()

        if recomputed_digest != claims.act:
            logger.warning(
                "[ConsequenceGateway] ACTION_BINDING_MISMATCH rec=%s",
                claims.rec,
            )
            return ConsequenceEvaluation(
                decision=ConsequenceDecision.BLOCK,
                reason_code="ACTION_BINDING_MISMATCH",
            )

        # Step 5: atomic single-use consumption
        # Binding hash combines thread_id, actor_id, action_digest, state_version
        # Mapping: claims.tid→thread_id, claims.sub→actor_id, claims.act→action_digest, claims.ver→state_version
        binding = ConsequenceAuthorityStore.binding_hash(
            thread_id=claims.tid,
            actor_id=claims.sub,
            action_digest=claims.act,
            state_version=claims.ver,
        )

        try:
            consumed = await self._store.consume_once(claims.rec, binding)
        except Exception as exc:
            # Fail-closed: Redis error → BLOCK (never silently EXECUTE on Redis failure)
            logger.error("[ConsequenceGateway] Redis error during consumption: %s", exc)
            return ConsequenceEvaluation(
                decision=ConsequenceDecision.BLOCK,
                reason_code="REDIS_ERROR",
                detail=str(exc),
            )

        if not consumed:
            # Re-read the existing binding to distinguish REPLAY vs SUBSTITUTION
            existing_binding = await self._store.get_binding(claims.rec)
            if existing_binding == binding:
                reason_code = "ALREADY_CONSUMED"
            else:
                reason_code = "AUTHORITY_RECORD_BINDING_MISMATCH"

            logger.warning(
                "[ConsequenceGateway] Consumption rejected: %s rec=%s",
                reason_code,
                claims.rec,
            )
            return ConsequenceEvaluation(
                decision=ConsequenceDecision.BLOCK,
                reason_code=reason_code,
            )

        # Step 6: EXECUTE
        logger.info(
            "[ConsequenceGateway] EXECUTE granted rec=%s",
            claims.rec,
        )
        return ConsequenceEvaluation(
            decision=ConsequenceDecision.EXECUTE,
            reason_code="OK",
        )

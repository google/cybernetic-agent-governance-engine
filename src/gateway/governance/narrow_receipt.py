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

"""NARROW receipts: how a sealed narrowing reaches the tool that executes it.

When the committing run (``SymbolicGovernor.govern``) narrows a request, the
seal it returns covers the *clamped* params, not the ones the caller sent.
The caller learns those params from a single-use receipt stored next to the
seal (CAGE-SEC-004): keyed by the seal's prefix, holding the clamped params
and the full seal, expiring after :data:`NARROW_RECEIPT_TTL_SECONDS`. The
tool fetches and deletes it, then verifies the seal against the clamped
params. A missing receipt fails closed on its own: the seal will not verify
against the original params.
"""

from __future__ import annotations

import json
import time
from typing import Any

from src.gateway.governance.governor.errors import GovernanceError

NARROW_RECEIPT_TTL_SECONDS = 300
_SEAL_PREFIX_CHARS = 32  # 128 bits of the seal


def narrow_receipt_key(seal: str) -> str:
    """Redis key of the receipt that accompanies ``seal``."""
    return f"narrow:receipt:{seal[:_SEAL_PREFIX_CHARS]}"


async def issue_narrow_receipt(
    seal: str,
    narrowed_params: dict[str, Any],
    *,
    constraints_applied: Any,
    narrowing_reason: str,
) -> None:
    """Store the receipt for ``seal``; raise ``GovernanceError`` if it cannot be stored.

    Called by ``run_sealed`` before the run's commits are kept, so a failure
    rolls them back rather than leaving headroom reserved behind a seal the
    caller could never redeem.
    """
    from src.gateway.infrastructure.redis_client import redis_client

    if redis_client is None:
        raise GovernanceError("[NARROW_RECEIPT_UNAVAILABLE] no Redis client for the NARROW receipt")
    payload = json.dumps(
        {
            "narrowed_params": narrowed_params,
            "original_signature": seal,
            "timestamp": time.time(),
            "clamp_reason": narrowing_reason,
            "constraints_applied": constraints_applied,
        },
        default=str,
    )
    try:
        await redis_client.setex(narrow_receipt_key(seal), NARROW_RECEIPT_TTL_SECONDS, payload)
    except Exception as exc:
        raise GovernanceError(
            f"[NARROW_RECEIPT_UNAVAILABLE] could not store the NARROW receipt: {type(exc).__name__}"
        ) from exc

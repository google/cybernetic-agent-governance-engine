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

"""The trade the advisor submits to the gateway, in one place.

The evaluator's dry run (``evaluator_node``) and the pre-trade gate
(``safety_check_node``) must describe a trade to the gateway in the same way.
Otherwise the dry run previews a request the real gate never sends. Both
build it here.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import time
from collections.abc import Mapping
from typing import Any

from src.gateway.governance.decisions import GovernanceDecision

#: The finance domain's registered trade action.
TRADE_ACTION = "execute_trade"

#: Least-privilege RBAC role. The role is never read from model output: a
#: plan that claimed ``senior`` would raise its own OPA trade limit.
DEFAULT_TRADER_ROLE = "junior"

#: Default maximum age (seconds) of a reusable ``ALLOW`` routing verdict.
DEFAULT_ROUTING_VERDICT_TTL_S = 30.0

#: Verdicts after which the graph proceeds. ``REQUIRE_APPROVAL`` proceeds
#: because the human-approval path downstream (FTRA HITL parking, the
#: approval node and the gateway's approval token) is where it is resolved.
#: Anything else stops the trade.
PROCEED_VERDICTS: frozenset[GovernanceDecision] = frozenset(
    {
        GovernanceDecision.ALLOW,
        GovernanceDecision.NARROW,
        GovernanceDecision.REQUIRE_APPROVAL,
    }
)


def _is_trade_action(action: Any) -> bool:
    """Return True when ``action`` denotes a trade step in an execution plan."""
    if not isinstance(action, str):
        return False
    lowered = action.lower()
    return any(k in lowered for k in ("trade", "execute", "buy", "sell"))


def extract_trade_step(plan: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """Extract canonical ``execute_trade`` parameters from an execution plan.

    Supports both flat plan dicts (``{"action": "execute_trade", ...}``) and
    structured ``ExecutionPlan`` dicts (``{"steps": [{"action": ..., "parameters": {...}}]}``).
    Returns ``None`` when the plan is empty or contains no trade step.

    Raises:
        ValueError, TypeError: When a trade step is present but its ``amount``
            is missing, boolean, non-finite, or non-positive.
    """
    if not isinstance(plan, Mapping) or not plan:
        return None
    if plan.get("action") == TRADE_ACTION:
        return trade_params(plan)
    steps = plan.get("steps")
    if isinstance(steps, list):
        for step in steps:
            if isinstance(step, Mapping) and _is_trade_action(step.get("action")):
                raw_params = step.get("parameters")
                source = raw_params if isinstance(raw_params, Mapping) else step
                return trade_params(source)
    return None


def trade_params(source: Mapping[str, Any]) -> dict[str, Any]:
    """Return the canonical ``execute_trade`` parameters for a plan or plan step.

    ``trade_governance.rego`` needs ``trader_role``, ``amount`` and
    ``currency`` to evaluate a trade. A missing role is an explicit DENY.

    Raises:
        ValueError: ``amount`` is missing, boolean, non-finite, or not positive. Callers fail closed.
    """
    raw_amount = source.get("amount")
    if raw_amount is None or isinstance(raw_amount, bool):
        raise ValueError(
            f"Invalid trade amount {raw_amount!r}: must be a positive finite number"
        )
    amount = float(raw_amount)
    if not math.isfinite(amount) or amount <= 0.0:
        raise ValueError(
            f"Invalid trade amount {raw_amount!r}: must be a positive finite number"
        )
    return {
        "action": TRADE_ACTION,
        "symbol": str(source.get("symbol") or "UNKNOWN"),
        "amount": amount,
        "currency": str(source.get("currency") or "USD"),
        "trader_role": DEFAULT_TRADER_ROLE,
        "confidence": source.get("confidence", 1.0),
        "side": str(source.get("side") or "buy").lower(),
    }


def canonical_trade_digest(source: Mapping[str, Any]) -> str:
    """Compute a deterministic SHA-256 digest of the canonical trade parameters.

    Binds the trade identity (``action``, ``symbol``, ``amount``, ``currency``,
    ``trader_role``, ``side``) and validates that ``confidence`` meets the
    minimum admissible threshold (>= 0.95) so an under-confident tool call can
    never reuse a previewed ``ALLOW`` verdict.
    """
    canonical = trade_params(source)
    raw_conf = canonical.get("confidence", 1.0)
    if isinstance(raw_conf, bool):
        raise ValueError(f"Invalid trade confidence {raw_conf!r}")
    conf = float(raw_conf)
    if not math.isfinite(conf) or conf < 0.95:
        raise ValueError(
            f"Trade confidence {conf!r} is below the reuse threshold (0.95)"
        )
    identity = {
        "action": canonical["action"],
        "symbol": canonical["symbol"].upper(),
        "amount": canonical["amount"],
        "currency": canonical["currency"].upper(),
        "trader_role": str(source.get("trader_role") or canonical["trader_role"]),
        "side": canonical["side"],
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def routing_verdict_ttl_s() -> float:
    """Return the configured routing-verdict reuse TTL in seconds."""
    raw = os.environ.get("CAGE_ROUTING_VERDICT_TTL_S")
    if raw is None or not raw.strip():
        return DEFAULT_ROUTING_VERDICT_TTL_S
    try:
        val = float(raw)
    except ValueError:
        return DEFAULT_ROUTING_VERDICT_TTL_S
    if not math.isfinite(val) or val <= 0.0:
        return 0.0
    return val


def build_routing_verdict_cache(
    params: Mapping[str, Any],
    *,
    verdict: str,
    envelope: Mapping[str, Any] | None = None,
    now: float | None = None,
) -> dict[str, Any] | None:
    """Build a ``routing_verdict_cache`` entry for an ``ALLOW`` verdict.

    Only ``ALLOW`` verdicts are cacheable: ``NARROW`` and ``REQUIRE_APPROVAL``
    must always hit ``POST /governance/validate-action`` so narrowed parameters
    or a parked ``deferred_id`` approval token are freshly obtained.
    """
    if verdict != GovernanceDecision.ALLOW.value:
        return None
    try:
        digest = canonical_trade_digest(params)
    except (TypeError, ValueError):
        return None
    ts = time.monotonic() if now is None else float(now)
    env_dict: dict[str, Any] = (
        dict(envelope)
        if isinstance(envelope, Mapping)
        else {"verdict": GovernanceDecision.ALLOW.value, "violations": []}
    )
    env_dict.setdefault("verdict", GovernanceDecision.ALLOW.value)
    return {
        "params_digest": digest,
        "verdict": GovernanceDecision.ALLOW.value,
        "at": ts,
        "envelope": env_dict,
    }


def reusable_allow_verdict(
    cache: Mapping[str, Any] | None,
    params: Mapping[str, Any],
    *,
    now: float | None = None,
    ttl_s: float | None = None,
) -> dict[str, Any] | None:
    """Return the cached ``ALLOW`` envelope if ``cache`` matches ``params`` within TTL."""
    if not isinstance(cache, Mapping):
        return None
    if cache.get("verdict") != GovernanceDecision.ALLOW.value:
        return None
    cached_digest = cache.get("params_digest")
    cached_at = cache.get("at")
    if not isinstance(cached_digest, str) or not isinstance(cached_at, (int, float)):
        return None
    if isinstance(cached_at, bool) or not math.isfinite(float(cached_at)):
        return None
    effective_ttl = routing_verdict_ttl_s() if ttl_s is None else float(ttl_s)
    if effective_ttl <= 0.0:
        return None
    ts = time.monotonic() if now is None else float(now)
    age = ts - float(cached_at)
    if age < 0.0 or age > effective_ttl:
        return None
    try:
        digest = canonical_trade_digest(params)
    except (TypeError, ValueError):
        return None
    if digest != cached_digest:
        return None
    envelope = cache.get("envelope")
    if isinstance(envelope, Mapping):
        out = dict(envelope)
        out["verdict"] = GovernanceDecision.ALLOW.value
        return out
    return {"verdict": GovernanceDecision.ALLOW.value, "violations": []}


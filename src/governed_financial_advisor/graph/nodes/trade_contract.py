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

A plan step is a trade only when its action is exactly one of
:data:`TRADE_STEP_ACTIONS` (case-insensitive). :func:`extract_trade_steps`
returns every trade step of a plan, so both gates judge the whole plan, not
its first trade. A step without a ``confidence`` is previewed at ``0.0``,
the committing tool's default.

A cached ``ALLOW`` routing verdict (``routing_verdict_cache``) may stand in
for a fresh ``POST /governance/validate-action`` call only for the exact order
it approved. :func:`canonical_trade_digest` binds every field of the
canonical payload, including the exact ``confidence``, and refuses a payload
that carries any other field, so a request that differs in a field the
digest cannot see is always re-validated.
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
#: The gateway MCP tool that executes a trade.
TRADE_TOOL = "execute_trade_action"

#: Plan-step actions that denote a trade, matched exactly and case-insensitively.
#: ``execute_trade`` is the planner's only trade action (the "Available
#: Actions" of the ``ExecutionPlan`` prompt in
#: ``agents/execution_analyst/agent.py``); the bare verbs cover a model that
#: names the step after the order. Substring matching made ``buyer_survey`` or
#: ``executed_report`` a trade, which then failed validation and counted
#: toward ``MAX_CONSECUTIVE_DENIALS``.
TRADE_STEP_ACTIONS: frozenset[str] = frozenset(
    {"execute_trade", "trade", "buy", "sell"}
)

#: Least-privilege RBAC role. The role is never read from model output: a
#: plan that claimed ``senior`` would raise its own OPA trade limit.
DEFAULT_TRADER_ROLE = "junior"

#: Confidence previewed for a trade step that omits it. It is the committing
#: tool's default (``execute_trade_action(confidence=0.0)``), so the preview
#: is the request the tool will actually make.
DEFAULT_CONFIDENCE = 0.0

#: Keys of the canonical ``execute_trade`` payload built by :func:`trade_params`.
TRADE_PARAM_KEYS: frozenset[str] = frozenset(
    {"action", "symbol", "amount", "currency", "trader_role", "confidence", "side"}
)

#: Keys ``gateway_tool_guard`` adds to a tool call's arguments. ``tool_name``
#: labels the tool, not the order: the guard submits every call as
#: :data:`TRADE_ACTION`.
_GUARD_PARAM_KEYS: frozenset[str] = frozenset({"tool_name", "action"})

#: Minimum ``confidence`` of a payload whose ``ALLOW`` verdict may be reused.
_REUSE_MIN_CONFIDENCE = 0.95

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


def is_trade_action(action: Any) -> bool:
    """Return True when ``action`` is exactly one of :data:`TRADE_STEP_ACTIONS`.

    Only case is ignored: ``"BUY"`` is a trade; ``"buy_stock"`` and
    ``"buyer_survey"`` are not.
    """
    return isinstance(action, str) and action.lower() in TRADE_STEP_ACTIONS


def extract_trade_steps(plan: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """Return the canonical ``execute_trade`` parameters of every trade step in ``plan``.

    Supports both flat plan dicts (``{"action": "execute_trade", ...}``) and
    structured ``ExecutionPlan`` dicts
    (``{"steps": [{"action": ..., "parameters": {...}}]}``). Trade steps keep
    their plan order. Returns an empty list when the plan is empty or contains
    no trade step.

    Raises:
        ValueError, TypeError: When any trade step has invalid parameters (see
            :func:`trade_params`). One malformed trade step fails the whole
            plan, so a gate never approves a plan it could not fully read.
    """
    if not isinstance(plan, Mapping) or not plan:
        return []
    if is_trade_action(plan.get("action")):
        return [trade_params(plan)]
    steps = plan.get("steps")
    if not isinstance(steps, list):
        return []
    trades: list[dict[str, Any]] = []
    for step in steps:
        if isinstance(step, Mapping) and is_trade_action(step.get("action")):
            raw_params = step.get("parameters")
            source = raw_params if isinstance(raw_params, Mapping) else step
            trades.append(trade_params(source))
    return trades


def _confidence(source: Mapping[str, Any]) -> float:
    """Return the trade's ``confidence``, or :data:`DEFAULT_CONFIDENCE` when absent.

    Raises:
        ValueError: ``confidence`` is present but boolean, non-numeric
            (including ``None``) or non-finite.
    """
    if "confidence" not in source:
        return DEFAULT_CONFIDENCE
    raw = source["confidence"]
    invalid = f"Invalid trade confidence {raw!r}: must be a finite number"
    if isinstance(raw, bool):
        raise ValueError(invalid)
    try:
        value = float(raw)
    except (TypeError, ValueError):
        raise ValueError(invalid) from None
    if not math.isfinite(value):
        raise ValueError(invalid)
    return value


def trade_params(source: Mapping[str, Any]) -> dict[str, Any]:
    """Return the canonical ``execute_trade`` parameters for a plan or plan step.

    ``trade_governance.rego`` needs ``trader_role``, ``amount`` and
    ``currency`` to evaluate a trade. A missing role is an explicit DENY.

    A missing ``confidence`` becomes :data:`DEFAULT_CONFIDENCE` (``0.0``), as
    in the committing tool.

    Raises:
        ValueError: ``amount`` is missing, boolean, non-finite, or not positive,
            or ``confidence`` is boolean, non-numeric or non-finite. Callers
            fail closed.
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
        "confidence": _confidence(source),
        "side": str(source.get("side") or "buy").lower(),
    }


def canonical_trade_digest(source: Mapping[str, Any]) -> str:
    """Compute a deterministic SHA-256 digest of the canonical trade parameters.

    Binds the trade identity (``action``, ``symbol``, ``amount``, ``currency``,
    ``trader_role``, ``side``) and validates that ``confidence`` meets the
    minimum admissible threshold (>= 0.95) so an under-confident tool call can
    never reuse a previewed ``ALLOW`` verdict. The exact ``confidence`` is part
    of the identity as well.

    ``source`` may carry only the keys of the canonical payload
    (:data:`TRADE_PARAM_KEYS`) plus the ``tool_name`` and ``action`` keys
    ``gateway_tool_guard`` adds, and its ``action``, if any, must be
    :data:`TRADE_ACTION`. Any other field (``limit_price``, ``account_id``,
    ``transaction_id``, ...) could change the order without changing the
    digest, so a payload carrying one has no digest.

    Raises:
        ValueError: ``source`` carries a field the digest does not bind, names
            another action, has invalid trade parameters, or its confidence is
            below the reuse threshold.
    """
    unbound = sorted(
        str(key) for key in source if key not in TRADE_PARAM_KEYS | _GUARD_PARAM_KEYS
    )
    if unbound:
        raise ValueError(f"Trade fields {unbound} are not bound by the trade digest")
    if source.get("action", TRADE_ACTION) != TRADE_ACTION:
        raise ValueError(
            f"Action {source.get('action')!r} is not the trade action {TRADE_ACTION!r}"
        )
    canonical = trade_params(source)
    conf = canonical["confidence"]
    if conf < _REUSE_MIN_CONFIDENCE:
        raise ValueError(
            f"Trade confidence {conf!r} is below the reuse threshold "
            f"({_REUSE_MIN_CONFIDENCE})"
        )
    identity = {
        "confidence": conf,
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
    or a parked ``deferred_id`` approval token are freshly obtained. Nothing is
    cached for ``params`` without a :func:`canonical_trade_digest`. One entry
    binds one order, so callers cache only single-trade plans.
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
    """Return the cached ``ALLOW`` envelope if ``cache`` matches ``params`` within TTL.

    ``params`` matches only when its :func:`canonical_trade_digest` equals the
    cached one. A payload carrying a key outside the canonical payload (other
    than the ``tool_name`` / ``action`` keys the tool guard adds) has no digest,
    so it is never served from the cache.
    """
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

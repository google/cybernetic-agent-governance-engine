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

"""Deterministic step-key and UUIDv5 idempotency-key helpers for LangGraph calls.

Matches the CAGE advisor's ``derive_plan_step_key`` and ``derive_transaction_id``
contract cleanly without importing monorepo ``src`` packages so external SDK
installs and retries keep identical idempotency keys across turns and resumes.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable, Mapping, Sequence
from typing import Any

#: Default UUIDv5 namespace for deterministic tool-step idempotency keys.
DEFAULT_IDEMPOTENCY_NAMESPACE = uuid.uuid5(
    uuid.NAMESPACE_URL, "urn:cage:advisor:execute_trade_action:transaction_id"
)

_VOLATILE_ARG_KEYS: frozenset[str] = frozenset(
    {
        "idempotency_key",
        "transaction_id",
        "deferred_id",
        "approval_token",
    }
)


def _is_trade_shaped(mapping: Mapping[str, Any]) -> bool:
    symbol = mapping.get("symbol")
    return isinstance(symbol, str) and bool(symbol.strip())


def _canonical_trade_tuple(args: Any) -> tuple[str, str, str, str]:
    """Extract normalized ``(symbol, currency, side, amount_key)`` from trade args."""
    mapping = args if isinstance(args, Mapping) else {}
    symbol = str(mapping.get("symbol") or "").strip().upper()
    currency = str(mapping.get("currency") or "USD").strip().upper()
    side = str(mapping.get("side") or "buy").strip().lower()
    raw_amount = mapping.get("amount")
    if isinstance(raw_amount, (int, float)) and not isinstance(raw_amount, bool):
        amount_key = f"{float(raw_amount):.8f}"
    else:
        amount_key = str(raw_amount or "").strip()
    return (symbol, currency, side, amount_key)


def _canonical_args_digest(args: Any) -> str:
    """Deterministic SHA-256 prefix for general non-trade tool parameters."""
    mapping = args if isinstance(args, Mapping) else {}
    filtered = {
        str(k): v for k, v in mapping.items() if str(k) not in _VOLATILE_ARG_KEYS
    }
    encoded = json.dumps(filtered, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:24]


def _default_extract_steps(plan: Mapping[str, Any]) -> list[dict[str, Any]]:
    steps = plan.get("steps")
    if not isinstance(steps, list):
        return []
    out: list[dict[str, Any]] = []
    for item in steps:
        if not isinstance(item, Mapping):
            continue
        params = item.get("parameters")
        if isinstance(params, Mapping):
            out.append(dict(params))
        else:
            out.append(dict(item))
    return out


def extract_plan_step_bindings(
    plan_raw: Any,
    *,
    step_extractor: Callable[[Mapping[str, Any]], Sequence[Mapping[str, Any]]]
    | None = None,
) -> tuple[str | None, list[dict[str, Any]]]:
    """Return ``(plan_digest, steps)`` from a dict or JSON-string execution plan."""
    plan_dict: Mapping[str, Any] | None = None
    if isinstance(plan_raw, Mapping):
        plan_dict = plan_raw
    elif isinstance(plan_raw, str) and plan_raw.strip():
        try:
            loaded = json.loads(plan_raw)
            if isinstance(loaded, Mapping):
                plan_dict = loaded
        except json.JSONDecodeError:
            plan_dict = None
    if not plan_dict:
        return None, []

    extractor = step_extractor or _default_extract_steps
    try:
        steps = [dict(s) for s in extractor(plan_dict) if isinstance(s, Mapping)]
    except Exception:
        steps = []

    canonical_plan = json.dumps(
        plan_dict, sort_keys=True, separators=(",", ":"), default=str
    )
    plan_digest = hashlib.sha256(canonical_plan.encode("utf-8")).hexdigest()[:24]
    return plan_digest, steps


def _pad4(parts: tuple[str, ...]) -> tuple[str, str, str, str]:
    padded = (*parts, "", "", "", "")
    return (padded[0], padded[1], padded[2], padded[3])


def derive_plan_step_key(
    args: Any,
    *,
    plan_digest: str | None = None,
    plan_steps: Sequence[Mapping[str, Any]] | None = None,
    used_step_indices: set[int] | None = None,
    occurrence: int = 0,
    canonical_extractor: Callable[[Any], tuple[str, ...]] | None = None,
) -> str:
    """Bind a tool call deterministically to its approved plan step or canonical intent.

    Preserves exact compatibility with finance trade intent tuples
    ``(symbol, currency, side, amount_key)`` when ``symbol`` is present, and
    falls back cleanly to canonical parameter digests for general tools.
    """
    extractor = canonical_extractor or _canonical_trade_tuple
    mapping = args if isinstance(args, Mapping) else {}
    trade_mode = canonical_extractor is not None or _is_trade_shaped(mapping)

    if trade_mode:
        symbol, currency, side, amount_key = _pad4(extractor(mapping))
        if plan_digest is not None and plan_steps:
            taken = used_step_indices if used_step_indices is not None else set()
            for exact in (True, False):
                for idx, step in enumerate(plan_steps):
                    if idx in taken:
                        continue
                    s_sym, s_cur, s_side, s_amt = _pad4(extractor(step))
                    if (s_sym, s_cur, s_side) == (symbol, currency, side) and (
                        not exact or s_amt == amount_key
                    ):
                        taken.add(idx)
                        return f"plan:{plan_digest}|step:{idx}|{s_sym}|{s_cur}|{s_side}|{s_amt}"
            for idx, step in enumerate(plan_steps):
                if idx not in taken:
                    taken.add(idx)
                    s_sym, s_cur, s_side, s_amt = _pad4(extractor(step))
                    return f"plan:{plan_digest}|step:{idx}|{s_sym}|{s_cur}|{s_side}|{s_amt}"
            return f"plan:{plan_digest}|extra:{occurrence}|{symbol}|{currency}|{side}|{amount_key}"
        return f"intent:{symbol}|{amount_key}|{currency}|{side}|occ:{occurrence}"

    args_digest = _canonical_args_digest(mapping)
    if plan_digest is not None and plan_steps:
        taken = used_step_indices if used_step_indices is not None else set()
        for idx, step in enumerate(plan_steps):
            if idx in taken:
                continue
            step_digest = _canonical_args_digest(step)
            if step_digest == args_digest:
                taken.add(idx)
                return f"plan:{plan_digest}|step:{idx}|args:{step_digest}"
        for idx, step in enumerate(plan_steps):
            if idx not in taken:
                taken.add(idx)
                return (
                    f"plan:{plan_digest}|step:{idx}|args:{_canonical_args_digest(step)}"
                )
        return f"plan:{plan_digest}|extra:{occurrence}|args:{args_digest}"
    return f"intent:args:{args_digest}|occ:{occurrence}"


def derive_idempotency_key(
    step_key: str,
    *,
    thread_id: str | None,
    message_id: str | None,
    namespace: uuid.UUID = DEFAULT_IDEMPOTENCY_NAMESPACE,
) -> str:
    """Derive a deterministic UUIDv5 idempotency key for one logical tool step.

    Scoped by LangGraph ``thread_id`` (preserving key identity across retries
    and HITL resumes), falling back to ``message_id`` when no thread exists.
    """
    scope = f"thread:{thread_id}" if thread_id else f"message:{message_id}"
    return str(uuid.uuid5(namespace, f"{scope}|step:{step_key}"))

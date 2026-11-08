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

"""Digest-free deterministic scenario and tool-call dispatch (F-36 / POAM-2026-191).

Subgraphs in ``src/governed_financial_advisor/`` inject dynamic ``timestamp_utc``
strings and per-run correlation identifiers into prompts, and multiple LangGraph
nodes share ``bind_tools`` over MCP tool definitions. Keying a stub on a raw
request SHA-256 breaks immediately when wall-clock time advances.

This module resolves responses purely from:
1. Canonicalized user intent stripped of timestamps, UUIDs (outside explicit
   ``[CAGE_TX_ID:...]`` / ``[CAGE_DEFERRED_ID:...]`` directives), and hex digests.
2. The declared OpenAI ``tools`` / ``tool_choice`` schema on the request.
3. Structured-output schemas (``guided_json`` / ``response_format``).
4. Conversation turn progression (whether a ``role == "tool"`` message has
   already answered the pending tool call since the latest ``role == "user"``
   turn).
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

_STUB_UUID_NS: Final[uuid.UUID] = uuid.UUID("c46e0191-0006-4000-8000-000000000191")

# Volatile patterns stripped before intent resolution (F-36).
_ISO_TS_RE: Final[re.Pattern[str]] = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
)
_EPOCH_FIELD_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(?:timestamp(?:_utc|_ms|_ns)?|created_at|issued_at)\s*[:=]\s*['\"]?[\w.:+-]+['\"]?",
    re.IGNORECASE,
)
_HEX_DIGEST_RE: Final[re.Pattern[str]] = re.compile(r"\b[0-9a-fA-F]{32,128}\b")
_UUID_RE: Final[re.Pattern[str]] = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_WS_RE: Final[re.Pattern[str]] = re.compile(r"\s+")

# Explicit deterministic scenario / directive headers.
_SCENARIO_TAG_RE: Final[re.Pattern[str]] = re.compile(
    r"\[CAGE_SCENARIO:([A-Z0-9_-]+)\]", re.IGNORECASE
)
_TX_ID_TAG_RE: Final[re.Pattern[str]] = re.compile(r"\[CAGE_TX_ID:([0-9a-fA-F-]{36})\]")
_DEFERRED_ID_TAG_RE: Final[re.Pattern[str]] = re.compile(
    r"\[CAGE_DEFERRED_ID:([A-Za-z0-9_.:-]+)\]"
)
_CONFIDENCE_TAG_RE: Final[re.Pattern[str]] = re.compile(
    r"\[CAGE_CONFIDENCE:(0(?:\.\d+)?|1(?:\.0+)?)\]", re.IGNORECASE
)

# Natural-language extraction patterns (deterministic fallbacks when no explicit
# [CAGE_SCENARIO:...] tag is provided).
_KNOWN_SYMBOLS: Final[tuple[str, ...]] = (
    "BTC",
    "ETH",
    "XMR",
    "DOGE",
    "AAPL",
    "MSFT",
    "GOOGL",
    "NVDA",
    "AMZN",
    "SPY",
    "TSLA",
)
_DOLLAR_AMOUNT_RE: Final[re.Pattern[str]] = re.compile(
    r"\$\s*([0-9]{1,3}(?:,[0-9]{3})+|[0-9]+)(?:\.([0-9]{1,4}))?"
)
_AMOUNT_KV_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(?:amount|notional|value|for|worth)\s*(?:of|=|:)?\s*\$?\s*"
    r"([0-9]{1,3}(?:,[0-9]{3})+|[0-9]+)(?:\.([0-9]{1,4}))?\b",
    re.IGNORECASE,
)
_SHARES_QTY_RE: Final[re.Pattern[str]] = re.compile(
    r"\b([0-9]{1,3}(?:,[0-9]{3})+|[0-9]+(?:\.[0-9]+)?)\s+(?:shares?|units?|coins?)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ResolvedScenario:
    """Canonical trade/advisory parameters derived without volatile fields."""

    scenario_id: str
    intent_kind: str  # "trade" | "market_read" | "portfolio_read" | "advisory"
    symbol: str
    side: str  # "buy" | "sell"
    amount: float
    currency: str
    confidence: float
    transaction_id: str
    deferred_id: str | None = None


@dataclass(frozen=True)
class StubTurnDecision:
    """Deterministic stub output before OpenAI JSON/SSE serialization."""

    scenario: ResolvedScenario
    finish_reason: str  # "tool_calls" | "stop"
    content: str | None
    tool_calls: tuple[dict[str, Any], ...] = ()


# Canonical preset table for explicit [CAGE_SCENARIO:<NAME>] tags.
_SCENARIO_PRESETS: Final[dict[str, dict[str, Any]]] = {
    "ALLOW_TRADE": {
        "intent_kind": "trade",
        "symbol": "AAPL",
        "side": "buy",
        "amount": 1500.0,
        "currency": "USD",
        "confidence": 0.98,
    },
    "DENY_RESTRICTED_ASSET": {
        "intent_kind": "trade",
        "symbol": "BTC",
        "side": "buy",
        "amount": 1000.0,
        "currency": "USD",
        "confidence": 0.98,
    },
    "DEFER_HIGH_VALUE": {
        "intent_kind": "trade",
        "symbol": "MSFT",
        "side": "buy",
        "amount": 7500.0,
        "currency": "USD",
        "confidence": 0.98,
    },
    "REDEEM_APPROVED_TRADE": {
        "intent_kind": "trade",
        "symbol": "MSFT",
        "side": "buy",
        "amount": 7500.0,
        "currency": "USD",
        "confidence": 0.98,
    },
    "MARKET_STATUS": {
        "intent_kind": "market_read",
        "symbol": "AAPL",
        "side": "buy",
        "amount": 0.0,
        "currency": "USD",
        "confidence": 0.98,
    },
    "READ_PORTFOLIO": {
        "intent_kind": "portfolio_read",
        "symbol": "AAPL",
        "side": "buy",
        "amount": 0.0,
        "currency": "USD",
        "confidence": 0.98,
    },
}


def _message_text(msg: Mapping[str, Any]) -> str:
    """Extract plain text from an OpenAI string or multi-part content payload."""
    content = msg.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, Sequence) and not isinstance(content, (bytes, bytearray)):
        parts: list[str] = []
        for item in content:
            if isinstance(item, Mapping):
                text = item.get("text")
                if isinstance(text, str):
                    parts.append(text)
            elif isinstance(item, str):
                parts.append(item)
        return " ".join(parts)
    return ""


def normalize_intent_text(raw: str) -> str:
    """Strip volatile timestamps, UUIDs, and hex digests from prompt text."""
    preserved_tags: list[str] = []
    for regex in (
        _SCENARIO_TAG_RE,
        _TX_ID_TAG_RE,
        _DEFERRED_ID_TAG_RE,
        _CONFIDENCE_TAG_RE,
    ):
        for match in regex.finditer(raw):
            preserved_tags.append(match.group(0))

    cleaned = raw
    for tag in preserved_tags:
        cleaned = cleaned.replace(tag, " ")
    cleaned = _ISO_TS_RE.sub(" ", cleaned)
    cleaned = _EPOCH_FIELD_RE.sub(" ", cleaned)
    cleaned = _UUID_RE.sub(" ", cleaned)
    cleaned = _HEX_DIGEST_RE.sub(" ", cleaned)
    if preserved_tags:
        cleaned = " ".join(preserved_tags) + " " + cleaned
    return _WS_RE.sub(" ", cleaned).strip()


def _extract_primary_user_text(messages: Sequence[Mapping[str, Any]]) -> str:
    """Prefer user messages (preserving user scenario tags across agent nodes)."""
    user_texts = [
        _message_text(m)
        for m in messages
        if str(m.get("role", "")).lower() in ("user", "human") and _message_text(m)
    ]
    if user_texts:
        if len(user_texts) == 1:
            return user_texts[0]
        return f"{user_texts[0]}\n{user_texts[-1]}"
    return "\n".join(_message_text(m) for m in messages if _message_text(m))


def _parse_float_match(whole: str, frac: str | None) -> float:
    digits = whole.replace(",", "")
    if frac:
        return float(f"{digits}.{frac}")
    return float(digits)


def _extract_symbol(normalized: str) -> str | None:
    upper = normalized.upper()
    for sym in _KNOWN_SYMBOLS:
        if re.search(rf"\b{re.escape(sym)}\b", upper):
            return sym
    if "BITCOIN" in upper:
        return "BTC"
    if "ETHEREUM" in upper:
        return "ETH"
    return None


def _extract_amount(normalized: str) -> float | None:
    dollar_matches = list(_DOLLAR_AMOUNT_RE.finditer(normalized))
    if dollar_matches:
        return max(_parse_float_match(m.group(1), m.group(2)) for m in dollar_matches)
    kv_match = _AMOUNT_KV_RE.search(normalized)
    if kv_match:
        return _parse_float_match(kv_match.group(1), kv_match.group(2))
    qty_match = _SHARES_QTY_RE.search(normalized)
    if qty_match:
        return float(qty_match.group(1).replace(",", ""))
    return None


def resolve_scenario(messages: Sequence[Mapping[str, Any]]) -> ResolvedScenario:
    """Deterministically resolve the active scenario from conversation messages."""
    all_text = "\n".join(_message_text(m) for m in messages if _message_text(m))
    primary_raw = _extract_primary_user_text(messages)
    normalized = normalize_intent_text(primary_raw)
    normalized_all = normalize_intent_text(all_text)

    tx_match = _TX_ID_TAG_RE.search(normalized_all)
    deferred_match = _DEFERRED_ID_TAG_RE.search(normalized_all)
    conf_match = _CONFIDENCE_TAG_RE.search(normalized_all)
    scenario_match = _SCENARIO_TAG_RE.search(normalized_all)

    explicit_tx_id = tx_match.group(1).lower() if tx_match else None
    explicit_deferred_id = deferred_match.group(1) if deferred_match else None
    explicit_conf = float(conf_match.group(1)) if conf_match else None

    if scenario_match:
        tag = scenario_match.group(1).upper().replace("-", "_")
        preset = dict(_SCENARIO_PRESETS.get(tag, _SCENARIO_PRESETS["ALLOW_TRADE"]))
        tagless = _SCENARIO_TAG_RE.sub(" ", normalized)
        tagless = _TX_ID_TAG_RE.sub(" ", tagless)
        tagless = _DEFERRED_ID_TAG_RE.sub(" ", tagless)
        override_symbol = _extract_symbol(tagless)
        override_amount = _extract_amount(tagless)
        symbol = override_symbol or str(preset["symbol"])
        amount = (
            override_amount
            if override_amount is not None and preset["intent_kind"] == "trade"
            else float(preset["amount"])
        )
        lower_norm = tagless.lower()
        side = "sell" if re.search(r"\bsell\b", lower_norm) else str(preset["side"])
        confidence = (
            explicit_conf if explicit_conf is not None else float(preset["confidence"])
        )
        canonical_seed = (
            f"{tag}:{preset['intent_kind']}:{side}:{symbol}:{amount:.4f}:"
            f"{preset['currency']}:{explicit_deferred_id or ''}"
        )
        tx_id = explicit_tx_id or str(uuid.uuid5(_STUB_UUID_NS, canonical_seed))
        return ResolvedScenario(
            scenario_id=tag.lower(),
            intent_kind=str(preset["intent_kind"]),
            symbol=symbol,
            side=side,
            amount=amount,
            currency=str(preset["currency"]),
            confidence=confidence,
            transaction_id=tx_id,
            deferred_id=explicit_deferred_id,
        )

    lower = normalized.lower()
    symbol = _extract_symbol(normalized) or "AAPL"
    side = "sell" if re.search(r"\bsell\b", lower) else "buy"
    is_trade = bool(
        re.search(r"\b(buy|sell|trade|execute|order|purchase|redeem)\b", lower)
        or explicit_deferred_id
    )
    is_portfolio = bool(re.search(r"\b(portfolio|holdings|balance|positions)\b", lower))
    is_market = bool(
        re.search(r"\b(market|status|quote|price|sentiment|ticker)\b", lower)
    )

    if is_trade:
        intent_kind = "trade"
        parsed_amount = _extract_amount(normalized)
        amount = 100.0 if parsed_amount is None else parsed_amount
        if symbol in ("BTC", "ETH", "XMR", "DOGE"):
            scenario_id = "deny_restricted_asset"
        elif amount > 5000.0:
            scenario_id = (
                "redeem_approved_trade" if explicit_deferred_id else "defer_high_value"
            )
        else:
            scenario_id = "allow_trade"
    elif is_portfolio:
        intent_kind = "portfolio_read"
        amount = 0.0
        scenario_id = "read_portfolio"
    elif is_market:
        intent_kind = "market_read"
        amount = 0.0
        scenario_id = "market_status"
    else:
        intent_kind = "advisory"
        amount = 0.0
        scenario_id = "general_advisory"

    confidence = explicit_conf if explicit_conf is not None else 0.98
    canonical_seed = (
        f"{scenario_id}:{intent_kind}:{side}:{symbol}:{amount:.4f}:USD:"
        f"{explicit_deferred_id or ''}"
    )
    tx_id = explicit_tx_id or str(uuid.uuid5(_STUB_UUID_NS, canonical_seed))
    return ResolvedScenario(
        scenario_id=scenario_id,
        intent_kind=intent_kind,
        symbol=symbol,
        side=side,
        amount=amount,
        currency="USD",
        confidence=confidence,
        transaction_id=tx_id,
        deferred_id=explicit_deferred_id,
    )


def _tool_messages_since_last_user(
    messages: Sequence[Mapping[str, Any]],
) -> list[str]:
    """Return tool result texts after the most recent user message."""
    last_user_idx = -1
    for idx, msg in enumerate(messages):
        if str(msg.get("role", "")).lower() in ("user", "human"):
            last_user_idx = idx
    tool_outputs: list[str] = []
    for msg in messages[last_user_idx + 1 :]:
        if str(msg.get("role", "")).lower() == "tool":
            tool_outputs.append(_message_text(msg))
    return tool_outputs


def _extract_guided_schema(body: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """Extract vLLM ``guided_json`` or OpenAI ``response_format`` JSON schema."""
    direct = body.get("guided_json")
    if isinstance(direct, Mapping):
        return direct
    if isinstance(direct, str):
        try:
            parsed = json.loads(direct)
            if isinstance(parsed, Mapping):
                return parsed
        except json.JSONDecodeError:
            return None
    extra = body.get("extra_body")
    if isinstance(extra, Mapping):
        nested = extra.get("guided_json")
        if isinstance(nested, Mapping):
            return nested
    resp_fmt = body.get("response_format")
    if isinstance(resp_fmt, Mapping):
        fmt_type = resp_fmt.get("type")
        if fmt_type == "json_schema":
            js = resp_fmt.get("json_schema")
            if isinstance(js, Mapping) and isinstance(js.get("schema"), Mapping):
                return js["schema"]
        if fmt_type == "json_object":
            return {"type": "object"}
    return None


def _default_for_property(prop_schema: Any) -> Any:
    if not isinstance(prop_schema, Mapping):
        return ""
    if (
        "enum" in prop_schema
        and isinstance(prop_schema["enum"], Sequence)
        and prop_schema["enum"]
    ):
        return prop_schema["enum"][0]
    prop_type = prop_schema.get("type")
    if prop_type == "number":
        return 0.98
    if prop_type == "integer":
        return 1
    if prop_type == "boolean":
        return True
    if prop_type == "array":
        return []
    if prop_type == "object":
        return {}
    return "stub"


_SCHEMA_ACTION_EXAMPLE_RE: Final[re.Pattern[str]] = re.compile(
    r"e\.g\.,\s*([a-z][a-z0-9_]*)"
)


def _extract_primary_step_action(schema: Mapping[str, Any]) -> str:
    """Resolve the terminal step action identifier from the caller's JSON schema."""
    candidates: list[Mapping[str, Any]] = []
    props = schema.get("properties")
    if isinstance(props, Mapping):
        steps_prop = props.get("steps")
        if isinstance(steps_prop, Mapping):
            items = steps_prop.get("items")
            if isinstance(items, Mapping):
                candidates.append(items)
    defs = schema.get("$defs")
    if isinstance(defs, Mapping):
        for defn in defs.values():
            if isinstance(defn, Mapping):
                candidates.append(defn)

    for item_schema in candidates:
        item_props = item_schema.get("properties")
        if not isinstance(item_props, Mapping):
            continue
        action_prop = item_props.get("action")
        if not isinstance(action_prop, Mapping):
            continue
        enum_vals = action_prop.get("enum")
        if (
            isinstance(enum_vals, Sequence)
            and not isinstance(enum_vals, (str, bytes))
            and enum_vals
            and isinstance(enum_vals[0], str)
        ):
            return enum_vals[0]
        desc = action_prop.get("description")
        if isinstance(desc, str):
            match = _SCHEMA_ACTION_EXAMPLE_RE.search(desc)
            if match is not None:
                return match.group(1)
    return "submit_action"


def _render_guided_json(schema: Mapping[str, Any], scenario: ResolvedScenario) -> str:
    """Render deterministic JSON conforming to structured plan or generic schemas."""
    props = schema.get("properties")
    prop_keys = set(props.keys()) if isinstance(props, Mapping) else set()
    if (
        {"steps", "rationale"} <= prop_keys
        or {"orders", "confidence_score"} <= prop_keys
        or "plan_id" in prop_keys
    ):
        primary_action = _extract_primary_step_action(schema)
        action_params: dict[str, Any] = {
            "symbol": scenario.symbol,
            "side": scenario.side,
            "amount": scenario.amount,
            "currency": scenario.currency,
            "confidence": scenario.confidence,
            "transaction_id": scenario.transaction_id,
        }
        if scenario.deferred_id is not None:
            action_params["deferred_id"] = scenario.deferred_id
        plan_steps: list[dict[str, Any]] = [
            {
                "id": "s1",
                "action": "check_market_status",
                "description": f"Confirm {scenario.symbol} market status before proceeding",
                "parameters": {"symbol": scenario.symbol},
            }
        ]
        if scenario.intent_kind == "trade":
            plan_steps.extend(
                [
                    {
                        "id": "s2",
                        "action": "check_balance",
                        "description": (
                            f"Verify funds for {scenario.amount:.2f} {scenario.currency} "
                            f"{scenario.symbol} order"
                        ),
                        "parameters": {
                            "required_amount": scenario.amount,
                            "currency": scenario.currency,
                        },
                    },
                    {
                        "id": "s3",
                        "action": primary_action,
                        "description": (
                            f"{scenario.side.title()} {scenario.amount:.2f} "
                            f"{scenario.currency} of {scenario.symbol}"
                        ),
                        "parameters": action_params,
                    },
                ]
            )
        plan_payload: dict[str, Any] = {
            "plan_id": f"plan-stub-{scenario.scenario_id}",
            "strategy_name": (
                f"Deterministic Governed {scenario.side.upper()} — {scenario.symbol}"
                if scenario.intent_kind == "trade"
                else f"Deterministic Market Inquiry — {scenario.symbol}"
            ),
            "rationale": (
                f"Deterministic stub execution plan for {scenario.side.upper()} "
                f"{scenario.symbol} ({scenario.amount:.2f} {scenario.currency})."
            ),
            "risk_factors": (
                ["restricted_asset_policy"]
                if scenario.symbol in ("BTC", "ETH", "XMR", "DOGE")
                else (
                    ["notional_exposure_threshold"]
                    if scenario.amount > 5000.0
                    else ["equity_market_volatility"]
                )
            ),
            "steps": plan_steps,
            "user_risk_attitude": "Moderate",
            "user_investment_period": "Medium",
            "orders": (
                [
                    {
                        "ticker": scenario.symbol,
                        "action": scenario.side.upper(),
                        "quantity": max(1, int(round(scenario.amount))),
                        "order_type": "MARKET",
                        "limit_price": None,
                        "time_in_force": "DAY",
                        "execution_algo": "TWAP",
                    }
                ]
                if scenario.intent_kind == "trade"
                else []
            ),
            "risk_assessment": (
                "RESTRICTED_ASSET"
                if scenario.symbol in ("BTC", "ETH", "XMR", "DOGE")
                else ("HIGH_VALUE_HITL" if scenario.amount > 5000.0 else "LOW")
            ),
            "confidence_score": scenario.confidence,
            "compliance_checklist": [
                "gateway_inference_proxy_routed",
                "symbolic_governor_seal_required",
            ],
        }
        if prop_keys:
            filtered = {k: v for k, v in plan_payload.items() if k in prop_keys}
            for req_key in schema.get("required", ()):
                if req_key not in filtered and isinstance(props, Mapping):
                    filtered[req_key] = _default_for_property(props.get(req_key, {}))
            return json.dumps(filtered, sort_keys=True)
        return json.dumps(plan_payload, sort_keys=True)

    result: dict[str, Any] = {}
    if isinstance(props, Mapping):
        for key in sorted(props):
            result[key] = _default_for_property(props[key])
    else:
        result = {
            "scenario_id": scenario.scenario_id,
            "symbol": scenario.symbol,
            "status": "ok",
        }
    return json.dumps(result, sort_keys=True)


def _declared_tools(body: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    """Map tool function name -> JSON parameter schema from ``body['tools']``."""
    raw_tools = body.get("tools")
    if not isinstance(raw_tools, Sequence):
        return {}
    out: dict[str, Mapping[str, Any]] = {}
    for entry in raw_tools:
        if not isinstance(entry, Mapping):
            continue
        fn = entry.get("function")
        if isinstance(fn, Mapping) and isinstance(fn.get("name"), str):
            params = fn.get("parameters")
            out[fn["name"]] = params if isinstance(params, Mapping) else {}
        elif isinstance(entry.get("name"), str):
            params = entry.get("parameters")
            out[str(entry["name"])] = params if isinstance(params, Mapping) else {}
    return out


def _forced_tool_name(body: Mapping[str, Any]) -> str | None:
    choice = body.get("tool_choice")
    if isinstance(choice, Mapping):
        fn = choice.get("function")
        if isinstance(fn, Mapping) and isinstance(fn.get("name"), str):
            return fn["name"]
        if isinstance(choice.get("name"), str):
            return str(choice["name"])
    return None


def _build_tool_args(
    tool_name: str,
    param_schema: Mapping[str, Any],
    scenario: ResolvedScenario,
) -> dict[str, Any]:
    """Construct canonical tool arguments aligned with the declared tool schema."""
    props = param_schema.get("properties")
    prop_names = set(props.keys()) if isinstance(props, Mapping) else set()
    lower_name = tool_name.lower()

    if "trade" in lower_name or "order" in lower_name:
        base_trade: dict[str, Any] = {
            "symbol": scenario.symbol,
            "amount": scenario.amount,
            "currency": scenario.currency,
            "confidence": scenario.confidence,
            "transaction_id": scenario.transaction_id,
            "side": scenario.side,
        }
        if scenario.deferred_id is not None:
            base_trade["deferred_id"] = scenario.deferred_id
        if not prop_names:
            return base_trade
        filtered: dict[str, Any] = {}
        for key, value in base_trade.items():
            if key in prop_names:
                filtered[key] = value
        if "ticker" in prop_names and "symbol" not in filtered:
            filtered["ticker"] = scenario.symbol
        if "quantity" in prop_names and "amount" not in filtered:
            filtered["quantity"] = scenario.amount
        if "action" in prop_names and "side" not in filtered:
            filtered["action"] = scenario.side
        return filtered

    if "portfolio" in lower_name:
        if "portfolio_id" in prop_names:
            return {"portfolio_id": "PORTFOLIO-E2E-001"}
        if "account_id" in prop_names:
            return {"account_id": "ACCT-E2E-001"}
        return {}

    if "symbol" in prop_names or not prop_names:
        return {"symbol": scenario.symbol}
    if "ticker" in prop_names:
        return {"ticker": scenario.symbol}
    return {
        req: _default_for_property(
            props.get(req, {}) if isinstance(props, Mapping) else {}
        )
        for req in sorted(param_schema.get("required", ()))
    }


def _select_tool_name(
    declared: Mapping[str, Mapping[str, Any]],
    forced: str | None,
    scenario: ResolvedScenario,
) -> str | None:
    if forced and forced in declared:
        return forced
    names = list(declared.keys())
    if not names:
        return None

    if scenario.intent_kind == "trade":
        for name in names:
            lower = name.lower()
            if "trade" in lower and lower.endswith("_action"):
                return name
        for name in names:
            lower = name.lower()
            if "trade" in lower or "order" in lower:
                return name
        for name in names:
            lower = name.lower()
            if "market" in lower or "status" in lower:
                return name
        return None

    if scenario.intent_kind == "portfolio_read":
        for preferred in ("get_portfolio", "read_portfolio", "check_market_status"):
            if preferred in declared:
                return preferred
        for name in names:
            if "portfolio" in name.lower() or "market" in name.lower():
                return name
        return None

    if scenario.intent_kind == "market_read":
        for preferred in (
            "check_market_status",
            "get_market_data",
            "get_market_sentiment",
        ):
            if preferred in declared:
                return preferred
        for name in names:
            if "market" in name.lower() or "status" in name.lower():
                return name
        return None

    return None


def _is_supervisor_routing_prompt(messages: Sequence[Mapping[str, Any]]) -> bool:
    combined = "\n".join(_message_text(m) for m in messages)
    return (
        "EXECUTION_ANALYST" in combined
        and "DATA_ANALYST" in combined
        and ("STRATEGY_ADVISOR" in combined or "FINISH" in combined)
    )


def _supervisor_route(
    messages: Sequence[Mapping[str, Any]], scenario: ResolvedScenario
) -> str:
    combined = "\n".join(_message_text(m) for m in messages)
    has_exec_output = bool(
        re.search(r"execution[_\s-]?plan|EXECUTED:|DEFERRED:|BLOCKED:", combined)
    )
    has_data_output = (
        "market_status" in combined.lower() or "current price" in combined.lower()
    )

    if scenario.intent_kind == "trade":
        if has_exec_output:
            return "FINISH\nGovernance trade workflow completed deterministically."
        return (
            f"EXECUTION_ANALYST\nRoute {scenario.side.upper()} {scenario.symbol} "
            f"({scenario.amount:.2f} {scenario.currency}) to governed execution."
        )
    if scenario.intent_kind in ("market_read", "portfolio_read"):
        if has_data_output:
            return "FINISH\nRead-only market inquiry completed deterministically."
        return f"DATA_ANALYST\nGather market telemetry for {scenario.symbol}."
    return "FINISH\nAdvisory inquiry answered deterministically."


def _summarize_tool_results(
    scenario: ResolvedScenario, tool_results: Sequence[str]
) -> str:
    joined = " | ".join(r.strip() for r in tool_results if r.strip())
    upper = joined.upper()
    if "DEFERRED:" in upper or "REQUIRE_APPROVAL" in upper:
        status = "DEFERRED"
    elif "BLOCKED:" in upper or "DENIED" in upper or "REFUSAL" in upper:
        status = "DENIED"
    elif "EXECUTED:" in upper or "APPROVED" in upper:
        status = "EXECUTED"
    else:
        status = "COMPLETED"
    return (
        f"[STUB_SUMMARY status={status} scenario={scenario.scenario_id} "
        f"symbol={scenario.symbol}] {joined}"
    )


def resolve_chat_completion(body: Mapping[str, Any]) -> StubTurnDecision:
    """Deterministically compute the stub completion for an OpenAI chat body."""
    raw_messages = body.get("messages")
    messages: list[Mapping[str, Any]] = (
        [m for m in raw_messages if isinstance(m, Mapping)]
        if isinstance(raw_messages, Sequence)
        else []
    )
    scenario = resolve_scenario(messages)

    tool_results = _tool_messages_since_last_user(messages)
    if tool_results:
        return StubTurnDecision(
            scenario=scenario,
            finish_reason="stop",
            content=_summarize_tool_results(scenario, tool_results),
        )

    guided_schema = _extract_guided_schema(body)
    if guided_schema is not None:
        return StubTurnDecision(
            scenario=scenario,
            finish_reason="stop",
            content=_render_guided_json(guided_schema, scenario),
        )

    tool_choice = body.get("tool_choice")
    tools_suppressed = isinstance(tool_choice, str) and tool_choice.lower() == "none"
    if not tools_suppressed:
        declared = _declared_tools(body)
        forced = _forced_tool_name(body)
        chosen = _select_tool_name(declared, forced, scenario)
        if chosen is not None:
            args = _build_tool_args(chosen, declared[chosen], scenario)
            args_json = json.dumps(args, sort_keys=True, separators=(",", ":"))
            call_seed = (
                f"call:{chosen}:{scenario.scenario_id}:{scenario.transaction_id}"
            )
            call_suffix = uuid.uuid5(_STUB_UUID_NS, call_seed).hex[:12]
            tool_call = {
                "id": f"call_stub_{call_suffix}",
                "type": "function",
                "function": {
                    "name": chosen,
                    "arguments": args_json,
                },
            }
            return StubTurnDecision(
                scenario=scenario,
                finish_reason="tool_calls",
                content=None,
                tool_calls=(tool_call,),
            )

    if _is_supervisor_routing_prompt(messages):
        return StubTurnDecision(
            scenario=scenario,
            finish_reason="stop",
            content=_supervisor_route(messages, scenario),
        )

    return StubTurnDecision(
        scenario=scenario,
        finish_reason="stop",
        content=(
            f"Deterministic stub response for scenario={scenario.scenario_id} "
            f"symbol={scenario.symbol} side={scenario.side} "
            f"amount={scenario.amount:.2f} {scenario.currency}."
        ),
    )

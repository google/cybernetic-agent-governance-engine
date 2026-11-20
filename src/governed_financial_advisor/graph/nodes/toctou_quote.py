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

"""Deterministic ticker, check-time quote, and plan helpers for post-HITL TOCTOU enforcement."""

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any

from src.governed_financial_advisor.graph.nodes.trade_contract import is_trade_action

logger = logging.getLogger(__name__)

#: Valid ticker symbols (equities ``AAPL``, ``BRK.B``, indices ``^GSPC``, FX ``EURUSD=X``, crypto ``BTC-USD``).
_TICKER_RE = re.compile(r"^[A-Z0-9.^=-]{1,12}$")

#: Sentinel strings that must never be treated as tradable ticker symbols.
_INVALID_TICKER_SENTINELS: frozenset[str] = frozenset(
    {"UNKNOWN", "NONE", "NULL", "N/A", "NA", "UNDEFINED"}
)

#: Analyst read-only tools whose arguments carry a ``symbol`` or ``ticker``.
_ANALYST_MARKET_TOOLS: frozenset[str] = frozenset(
    {"get_market_data", "check_market_status", "get_market_sentiment"}
)

_REPORT_HEADER_RE = re.compile(
    r"^#\s*Market Data Report for\s+([A-Za-z0-9.^=-]{1,12})\b",
    re.MULTILINE,
)
_LATEST_CLOSE_RE = re.compile(
    r"\*\*Latest Close:\*\*\s*\$?([0-9]+(?:\.[0-9]+)?)",
)


def normalize_ticker(raw: Any) -> str | None:
    """Return a canonical uppercase ticker symbol, or ``None`` if invalid/sentinel."""
    if not isinstance(raw, str):
        return None
    cleaned = raw.strip().upper()
    if not cleaned or cleaned in _INVALID_TICKER_SENTINELS:
        return None
    if not _TICKER_RE.fullmatch(cleaned):
        return None
    return cleaned


def positive_finite_float(raw: Any) -> float | None:
    """Return ``float(raw)`` when finite and ``> 0.0`` (rejecting booleans), else ``None``."""
    if raw is None or isinstance(raw, bool):
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(value) or value <= 0.0:
        return None
    return value


def non_negative_finite_float(raw: Any) -> float | None:
    """Return ``float(raw)`` when finite and ``>= 0.0`` (rejecting booleans), else ``None``."""
    if raw is None or isinstance(raw, bool):
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(value) or value < 0.0:
        return None
    return value


def parse_slippage_tolerance_pct(
    raw: Any,
    *,
    default: float = 2.0,
) -> float | None:
    """Validate ``max_slippage_pct`` in ``[0.0, 100.0]`` (defaulting only when omitted)."""
    if raw is None:
        return None
    val = non_negative_finite_float(raw)
    if val is None or val > 100.0:
        return None
    return val


def resolve_decision_slippage_pct(
    approval_decision: Mapping[str, Any] | None,
    *,
    default: float = 2.0,
) -> float | None:
    """Extract and validate ``max_slippage_pct`` from ``approval_decision``."""
    if not isinstance(approval_decision, Mapping):
        return default
    if "max_slippage_pct" not in approval_decision:
        return default
    return parse_slippage_tolerance_pct(
        approval_decision.get("max_slippage_pct"),
        default=default,
    )


def serialize_execution_plan(plan_output: Any) -> str:
    """Serialize ``execution_plan_output`` as valid JSON rather than Python ``repr``."""
    if plan_output is None:
        return ""
    if isinstance(plan_output, str):
        return plan_output
    if isinstance(plan_output, Mapping):
        return json.dumps(dict(plan_output))
    try:
        return json.dumps(plan_output)
    except TypeError:
        return str(plan_output)


def _step_symbol_and_price(step: Mapping[str, Any]) -> tuple[str | None, float | None]:
    """Extract ``(ticker, reference_price)`` from a plan step (nested ``parameters`` or flat)."""
    params = step.get("parameters")
    sources: tuple[Mapping[str, Any], ...] = (
        (params, step) if isinstance(params, Mapping) else (step,)
    )

    ticker: str | None = None
    for src in sources:
        ticker = normalize_ticker(src.get("symbol")) or normalize_ticker(
            src.get("ticker")
        )
        if ticker is not None:
            break

    price: float | None = None
    for src in sources:
        price = positive_finite_float(
            src.get("reference_price")
        ) or positive_finite_float(src.get("price"))
        if price is not None:
            break
        amount = positive_finite_float(src.get("amount"))
        quantity = positive_finite_float(src.get("quantity"))
        if amount is not None and quantity is not None:
            implied = amount / quantity
            if math.isfinite(implied) and implied > 0.0:
                price = implied
                break

    return ticker, price


def extract_plan_ticker_and_price(
    plan_raw: Any,
    *,
    preferred_ticker: str | None = None,
) -> tuple[str | None, float | None]:
    """Extract ``(ticker, stale_price)`` from a JSON string or dict ``ExecutionPlan``."""
    target_ticker = normalize_ticker(preferred_ticker)
    plan: Mapping[str, Any] | None = None
    if isinstance(plan_raw, Mapping):
        plan = plan_raw
    elif isinstance(plan_raw, str) and plan_raw.strip():
        try:
            loaded = json.loads(plan_raw)
        except json.JSONDecodeError:
            loaded = None
        if isinstance(loaded, Mapping):
            plan = loaded

    if not plan:
        return target_ticker, None

    steps = plan.get("steps")
    ordered_steps: list[Mapping[str, Any]] = []
    if isinstance(steps, list):
        trade_steps = [
            s
            for s in steps
            if isinstance(s, Mapping) and is_trade_action(s.get("action"))
        ]
        other_steps = [
            s
            for s in steps
            if isinstance(s, Mapping) and not is_trade_action(s.get("action"))
        ]
        ordered_steps = [*trade_steps, *other_steps]

    resolved_ticker: str | None = target_ticker
    resolved_price: float | None = None

    for step in ordered_steps:
        step_ticker, step_price = _step_symbol_and_price(step)
        if (
            target_ticker is not None
            and step_ticker is not None
            and step_ticker != target_ticker
        ):
            continue
        if resolved_ticker is None and step_ticker is not None:
            resolved_ticker = step_ticker
        if resolved_price is None and step_price is not None:
            if (
                resolved_ticker is None
                or step_ticker is None
                or step_ticker == resolved_ticker
            ):
                resolved_price = step_price
        if resolved_ticker is not None and resolved_price is not None:
            return resolved_ticker, resolved_price

    top_ticker, top_price = _step_symbol_and_price(plan)
    if target_ticker is None or top_ticker is None or top_ticker == target_ticker:
        if resolved_ticker is None and top_ticker is not None:
            resolved_ticker = top_ticker
        if resolved_price is None and top_price is not None:
            resolved_price = top_price

    return resolved_ticker, resolved_price


def extract_analyst_quote_and_ticker(
    messages: Sequence[Any] | None,
    *,
    preferred_ticker: str | None = None,
) -> tuple[str | None, float | None]:
    """Extract ``(ticker, latest_close_price)`` from Data Analyst tool calls and outputs."""
    target_ticker = normalize_ticker(preferred_ticker)
    if not messages:
        return target_ticker, None

    call_id_to_ticker: dict[str, str] = {}
    latest_tool_ticker: str | None = None
    for msg in reversed(messages):
        tool_calls = getattr(msg, "tool_calls", None)
        if isinstance(tool_calls, list):
            for call in reversed(tool_calls):
                if not isinstance(call, Mapping):
                    continue
                if call.get("name") not in _ANALYST_MARKET_TOOLS:
                    continue
                args = call.get("args")
                if not isinstance(args, Mapping):
                    continue
                sym = normalize_ticker(args.get("symbol")) or normalize_ticker(
                    args.get("ticker")
                )
                if sym is None:
                    continue
                call_id = call.get("id")
                if isinstance(call_id, str) and call_id:
                    call_id_to_ticker[call_id] = sym
                if latest_tool_ticker is None and (
                    target_ticker is None or sym == target_ticker
                ):
                    latest_tool_ticker = sym

    for msg in reversed(messages):
        content = (
            msg[1]
            if isinstance(msg, tuple) and len(msg) >= 2
            else getattr(msg, "content", None)
        )
        if not isinstance(content, str) or not content:
            continue

        header_match = _REPORT_HEADER_RE.search(content)
        msg_ticker = (
            normalize_ticker(header_match.group(1))
            if header_match is not None
            else None
        )
        if msg_ticker is None:
            tool_call_id = getattr(msg, "tool_call_id", None)
            if isinstance(tool_call_id, str):
                msg_ticker = call_id_to_ticker.get(tool_call_id)

        if target_ticker is not None and msg_ticker != target_ticker:
            continue

        close_match = _LATEST_CLOSE_RE.search(content)
        price = (
            positive_finite_float(close_match.group(1))
            if close_match is not None
            else None
        )
        if msg_ticker is not None and price is not None:
            return msg_ticker, price
        if latest_tool_ticker is None and msg_ticker is not None:
            latest_tool_ticker = msg_ticker

    return target_ticker or latest_tool_ticker, None


def build_hitl_reference_quote(
    ticker: str,
    price: float,
    *,
    source: str,
) -> dict[str, Any]:
    """Construct a normalized ``hitl_reference_quote`` checkpoint payload."""
    return {
        "ticker": ticker,
        "price": price,
        "source": source,
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
    }


def extract_reference_quote_from_state(
    state: Mapping[str, Any],
    *,
    preferred_ticker: str | None = None,
) -> tuple[str | None, float | None, str | None]:
    """Resolve ``(ticker, stale_price, source)`` from state, plan, or message history."""
    plan_raw = (
        state.get("execution_plan")
        if state.get("execution_plan") is not None
        else state.get("execution_plan_output")
    )

    ticker = normalize_ticker(preferred_ticker) or normalize_ticker(
        state.get("data_analyst_ticker")
    )
    plan_ticker, plan_price = extract_plan_ticker_and_price(
        plan_raw,
        preferred_ticker=ticker,
    )
    if ticker is None and plan_ticker is not None:
        ticker = plan_ticker

    ref_quote = state.get("hitl_reference_quote")
    if isinstance(ref_quote, Mapping):
        ref_ticker = normalize_ticker(ref_quote.get("ticker"))
        ref_price = positive_finite_float(ref_quote.get("price"))
        if ticker is None and ref_ticker is not None:
            ticker = ref_ticker
        if ref_price is not None and (
            ticker is None or ref_ticker is None or ref_ticker == ticker
        ):
            source = str(ref_quote.get("source") or "hitl_reference_quote")
            return ticker, ref_price, source

    if plan_price is not None:
        return ticker, plan_price, "execution_plan"

    msg_ticker, msg_price = extract_analyst_quote_and_ticker(
        state.get("messages"),
        preferred_ticker=ticker,
    )
    if ticker is None and msg_ticker is not None:
        ticker = msg_ticker
    if msg_price is not None:
        return ticker, msg_price, "get_market_data"

    return ticker, None, None


def fetch_yfinance_price_sync(sym: str) -> float | None:
    """Synchronously sample ``sym``'s latest quote via ``yfinance``."""
    import yfinance as yf

    ticker_obj = yf.Ticker(sym)
    price: float | None = None
    try:
        fi = ticker_obj.fast_info
        if fi is not None:
            raw = fi.get("last_price") or fi.get("lastPrice")
            price = positive_finite_float(raw)
    except Exception as exc:
        logger.debug("yfinance fast_info lookup failed for %s: %s", sym, exc)

    if price is None:
        hist = ticker_obj.history(period="1d")
        if hist is not None and not hist.empty:
            price = positive_finite_float(hist.iloc[-1]["Close"])
    return price


async def fetch_live_yfinance_price(
    sym: str,
    *,
    timeout_s: float | None = None,
) -> float | None:
    """Sample ``sym``'s live quote off the event loop under ``YFINANCE_TIMEOUT_SECONDS``."""
    yf_timeout = (
        timeout_s
        if timeout_s is not None
        else float(os.environ.get("YFINANCE_TIMEOUT_SECONDS", "5.0"))
    )
    return await asyncio.wait_for(
        asyncio.to_thread(fetch_yfinance_price_sync, sym),
        timeout=yf_timeout,
    )

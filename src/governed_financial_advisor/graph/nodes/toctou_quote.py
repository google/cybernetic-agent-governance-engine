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


#: Maximum age (seconds) for reusing a check-time quote captured earlier in the
#: same turn (e.g. ``data_analyst_node`` immediately preceding ``execution_analyst_node``).
#: Older quotes from prior conversation turns on the same ``thread_id`` are
#: refreshed at check time so pre-turn price movement is not misattributed to HITL review.
DEFAULT_CHECK_TIME_QUOTE_MAX_AGE_S: float = 60.0

#: Mutating trade tool names whose arguments carry ``symbol`` / ``ticker``.
_TRADE_EXECUTION_TOOLS: frozenset[str] = frozenset(
    {"execute_trade_action", "execute_trade"}
)


def build_hitl_reference_quote(
    ticker: str,
    price: float,
    *,
    source: str,
    quotes_by_ticker: Mapping[str, float] | None = None,
    captured_at_utc: str | None = None,
) -> dict[str, Any]:
    """Construct a normalized ``hitl_reference_quote`` checkpoint payload."""
    payload: dict[str, Any] = {
        "ticker": ticker,
        "price": price,
        "source": source,
        "captured_at_utc": captured_at_utc or datetime.now(timezone.utc).isoformat(),
    }
    if quotes_by_ticker:
        cleaned_map = {
            norm: val
            for raw_sym, raw_val in quotes_by_ticker.items()
            if (norm := normalize_ticker(raw_sym)) is not None
            and (val := positive_finite_float(raw_val)) is not None
        }
        if cleaned_map:
            payload["quotes_by_ticker"] = cleaned_map
    return payload


def _lookup_quote_in_ref(ref_quote: Mapping[str, Any], ticker: str) -> float | None:
    """Look up ``ticker`` in ``ref_quote`` (either primary ``ticker`` or ``quotes_by_ticker``)."""
    norm_target = normalize_ticker(ticker)
    if norm_target is None:
        return None
    if normalize_ticker(ref_quote.get("ticker")) == norm_target:
        direct = positive_finite_float(ref_quote.get("price"))
        if direct is not None:
            return direct
    by_ticker = ref_quote.get("quotes_by_ticker")
    if isinstance(by_ticker, Mapping):
        for raw_sym, raw_val in by_ticker.items():
            if normalize_ticker(raw_sym) == norm_target:
                mapped = positive_finite_float(raw_val)
                if mapped is not None:
                    return mapped
    return None


def is_fresh_reference_quote(
    ref_quote: Any,
    *,
    ticker: str,
    max_age_s: float = DEFAULT_CHECK_TIME_QUOTE_MAX_AGE_S,
    now: datetime | None = None,
) -> tuple[float, str] | None:
    """Return ``(price, source)`` if ``ref_quote`` covers ``ticker`` within ``max_age_s``."""
    if not isinstance(ref_quote, Mapping):
        return None
    price = _lookup_quote_in_ref(ref_quote, ticker)
    if price is None:
        return None
    raw_ts = ref_quote.get("captured_at_utc")
    if not isinstance(raw_ts, str) or not raw_ts.strip():
        return None
    try:
        captured = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    if captured.tzinfo is None:
        return None
    ref_now = now if now is not None else datetime.now(timezone.utc)
    age_s = (ref_now - captured.astimezone(timezone.utc)).total_seconds()
    if not math.isfinite(age_s) or age_s < -5.0 or age_s > max_age_s:
        return None
    return price, str(ref_quote.get("source") or "hitl_reference_quote")


def extract_all_plan_tickers(plan_raw: Any) -> list[str]:
    """Return all unique normalized trade symbols in ``plan_raw`` in step order."""
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
        return []

    seen: list[str] = []
    steps = plan.get("steps")
    if isinstance(steps, list):
        for step in steps:
            if isinstance(step, Mapping) and is_trade_action(step.get("action")):
                sym, _ = _step_symbol_and_price(step)
                if sym is not None and sym not in seen:
                    seen.append(sym)
        for step in steps:
            if isinstance(step, Mapping) and not is_trade_action(step.get("action")):
                sym, _ = _step_symbol_and_price(step)
                if sym is not None and sym not in seen:
                    seen.append(sym)
    top_sym, _ = _step_symbol_and_price(plan)
    if top_sym is not None and top_sym not in seen:
        seen.append(top_sym)
    return seen


def extract_pending_trade_tool_ticker(messages: Sequence[Any] | None) -> str | None:
    """Extract the most recent ``execute_trade_action`` tool-call symbol from ``messages``."""
    if not messages:
        return None
    for msg in reversed(messages):
        tool_calls = getattr(msg, "tool_calls", None)
        if not isinstance(tool_calls, list):
            continue
        for call in reversed(tool_calls):
            if not isinstance(call, Mapping):
                continue
            if call.get("name") not in _TRADE_EXECUTION_TOOLS:
                continue
            args = call.get("args")
            if not isinstance(args, Mapping):
                continue
            sym = normalize_ticker(args.get("symbol")) or normalize_ticker(
                args.get("ticker")
            )
            if sym is not None:
                return sym
    return None


async def resolve_check_time_reference_quote(
    state: Mapping[str, Any],
    *,
    ticker: str,
    plan_raw: Any = None,
    max_age_s: float = DEFAULT_CHECK_TIME_QUOTE_MAX_AGE_S,
) -> dict[str, Any] | None:
    """Resolve or sample a fresh check-time ``hitl_reference_quote`` for ``ticker``."""
    norm_ticker = normalize_ticker(ticker)
    if norm_ticker is None:
        return None

    effective_plan = (
        plan_raw
        if plan_raw is not None
        else (
            state.get("execution_plan")
            if state.get("execution_plan") is not None
            else state.get("execution_plan_output")
        )
    )
    _, plan_price = extract_plan_ticker_and_price(
        effective_plan,
        preferred_ticker=norm_ticker,
    )
    if plan_price is not None:
        return build_hitl_reference_quote(
            norm_ticker,
            plan_price,
            source="execution_plan",
        )

    existing_ref = state.get("hitl_reference_quote")
    fresh_existing = is_fresh_reference_quote(
        existing_ref,
        ticker=norm_ticker,
        max_age_s=max_age_s,
    )
    if fresh_existing is not None:
        existing_price, existing_source = fresh_existing
        return build_hitl_reference_quote(
            norm_ticker,
            existing_price,
            source=existing_source,
        )

    try:
        live_price = await fetch_live_yfinance_price(norm_ticker)
    except Exception as exc:
        logger.warning(
            "[TOCTOUQuote] ⚠️ Could not sample live check-time quote for %s: %s",
            norm_ticker,
            exc,
        )
        live_price = None

    if live_price is not None:
        return build_hitl_reference_quote(
            norm_ticker,
            live_price,
            source="yfinance_check_time",
        )

    has_expired_same_symbol = (
        isinstance(existing_ref, Mapping)
        and _lookup_quote_in_ref(existing_ref, norm_ticker) is not None
    )
    if not has_expired_same_symbol:
        _, msg_price = extract_analyst_quote_and_ticker(
            state.get("messages"),
            preferred_ticker=norm_ticker,
        )
        if msg_price is not None:
            return build_hitl_reference_quote(
                norm_ticker,
                msg_price,
                source="get_market_data",
            )

    return None


async def resolve_check_time_plan_quotes(
    state: Mapping[str, Any],
    plan_raw: Any,
    *,
    max_age_s: float = DEFAULT_CHECK_TIME_QUOTE_MAX_AGE_S,
) -> tuple[str | None, dict[str, Any] | None]:
    """Capture check-time quotes for all trade tickers in ``plan_raw``."""
    tickers = extract_all_plan_tickers(plan_raw)
    if not tickers:
        return None, None

    quotes_by_ticker: dict[str, float] = {}
    primary_source = "yfinance_check_time"
    for idx, sym in enumerate(tickers):
        resolved = await resolve_check_time_reference_quote(
            state,
            ticker=sym,
            plan_raw=plan_raw,
            max_age_s=max_age_s,
        )
        if resolved is not None:
            price = positive_finite_float(resolved.get("price"))
            if price is not None:
                quotes_by_ticker[sym] = price
                if idx == 0:
                    primary_source = str(
                        resolved.get("source") or "yfinance_check_time"
                    )

    primary_ticker = tickers[0]
    if not quotes_by_ticker:
        return primary_ticker, None

    chosen_ticker = (
        primary_ticker
        if primary_ticker in quotes_by_ticker
        else next(iter(quotes_by_ticker))
    )
    return primary_ticker, build_hitl_reference_quote(
        chosen_ticker,
        quotes_by_ticker[chosen_ticker],
        source=primary_source,
        quotes_by_ticker=quotes_by_ticker,
    )


def select_reference_quote_for_ticker(
    state: Mapping[str, Any],
    *,
    ticker: str,
    plan_raw: Any = None,
) -> dict[str, Any] | None:
    """Synchronously select an in-memory reference quote for ``ticker`` (zero network I/O)."""
    norm_ticker = normalize_ticker(ticker)
    if norm_ticker is None:
        return None

    ref_quote = state.get("hitl_reference_quote")
    if isinstance(ref_quote, Mapping):
        mapped_price = _lookup_quote_in_ref(ref_quote, norm_ticker)
        if mapped_price is not None:
            existing_map = ref_quote.get("quotes_by_ticker")
            return build_hitl_reference_quote(
                norm_ticker,
                mapped_price,
                source=str(ref_quote.get("source") or "hitl_reference_quote"),
                quotes_by_ticker=existing_map
                if isinstance(existing_map, Mapping)
                else None,
                captured_at_utc=(
                    str(ref_quote["captured_at_utc"])
                    if isinstance(ref_quote.get("captured_at_utc"), str)
                    else None
                ),
            )

    _, resolved_price, resolved_source = extract_reference_quote_from_state(
        {
            **state,
            "execution_plan_output": plan_raw
            if plan_raw is not None
            else state.get("execution_plan_output"),
        },
        preferred_ticker=norm_ticker,
    )
    if resolved_price is not None:
        return build_hitl_reference_quote(
            norm_ticker,
            resolved_price,
            source=resolved_source or "execution_plan",
        )
    return None


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
    if ticker is None:
        ticker = extract_pending_trade_tool_ticker(state.get("messages"))

    ref_quote = state.get("hitl_reference_quote")
    if isinstance(ref_quote, Mapping):
        ref_ticker = normalize_ticker(ref_quote.get("ticker"))
        if ticker is None and ref_ticker is not None:
            ticker = ref_ticker
        if ticker is not None:
            matched_price = _lookup_quote_in_ref(ref_quote, ticker)
            if matched_price is not None:
                source = str(ref_quote.get("source") or "hitl_reference_quote")
                return ticker, matched_price, source
        else:
            ref_price = positive_finite_float(ref_quote.get("price"))
            if ref_price is not None:
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


def fetch_yfinance_price_sync(sym: str, *, timeout_s: float = 5.0) -> float | None:
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
        hist = ticker_obj.history(period="1d", timeout=timeout_s)
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
        asyncio.to_thread(fetch_yfinance_price_sync, sym, timeout_s=yf_timeout),
        timeout=yf_timeout,
    )

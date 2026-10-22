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

"""Langfuse live telemetry provider adapter (Layer 3).

Queries Langfuse for recent traces tagged with governance spans
(iso42001.control_id = A.6.2.8) and extracts empirical world-model validation data.
"""

from __future__ import annotations

import json
import logging
import math
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Any

import pandas as pd

from src.gateway.governance.schemas.thresholds import (
    get_telemetry_max_staleness_seconds,
)
from src.gateway.governance.telemetry_provider import (
    MIN_SAMPLES,
    BaseTelemetryProvider,
    ConfigurationError,
    NullTelemetryProvider,
)

logger = logging.getLogger("cage.integrations.telemetry_langfuse")

# The Langfuse public API caps ``GET /api/public/traces`` at 100 rows a page.
_PAGE_LIMIT = 100
_MAX_CONCURRENT_PAGES = 5


def _as_mapping(value: Any) -> dict[str, Any]:
    """Return a trace ``input`` / ``metadata`` value as a dict, or ``{}``.

    Langfuse stores whatever the instrumented code recorded: a dict, a JSON
    string, or plain text (an LLM prompt). Only mappings can carry the causal
    columns; anything else contributes no row.
    """
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except ValueError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _list_recent_traces(
    client: Any,
    n_samples: int,
    *,
    from_timestamp: datetime | None = None,
    name: str | None = None,
    tags: str | Sequence[str] | None = None,
) -> list[Any]:
    """Return up to ``n_samples`` of the most recent traces, newest first.

    Uses the SDK's generated public-API client (``client.api.trace.list``) with
    server-side filters (`from_timestamp`, optional `name` / `tags`) and fetches
    remaining pages concurrently after page 1.
    """
    if n_samples <= 0:
        return []

    filter_kwargs: dict[str, Any] = {"order_by": "timestamp.desc"}
    if from_timestamp is not None:
        filter_kwargs["from_timestamp"] = from_timestamp
    if name is not None:
        filter_kwargs["name"] = name
    if tags is not None:
        filter_kwargs["tags"] = tags

    first_limit = min(_PAGE_LIMIT, n_samples)
    first_resp = client.api.trace.list(
        page=1,
        limit=first_limit,
        **filter_kwargs,
    )
    traces: list[Any] = list(getattr(first_resp, "data", None) or [])
    if len(traces) < first_limit or len(traces) >= n_samples:
        return traces[:n_samples]

    remaining = n_samples - len(traces)
    additional_pages = math.ceil(remaining / _PAGE_LIMIT)
    page_nums = [idx + 2 for idx in range(additional_pages)]

    def _fetch_page(p_num: int) -> list[Any]:
        resp = client.api.trace.list(
            page=p_num,
            limit=_PAGE_LIMIT,
            **filter_kwargs,
        )
        return list(getattr(resp, "data", None) or [])

    if len(page_nums) == 1:
        traces.extend(_fetch_page(page_nums[0]))
    else:
        max_workers = min(_MAX_CONCURRENT_PAGES, len(page_nums))
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            for batch in pool.map(_fetch_page, page_nums):
                traces.extend(batch)
                if not batch:
                    break

    return traces[:n_samples]


class LangfuseTelemetryProvider(BaseTelemetryProvider):
    """[CTRL_TEL_003] Pull live governance telemetry from Langfuse.

    Queries Langfuse for recent traces tagged with governance spans
    (iso42001.control_id = A.6.2.8) and extracts:
        - market_volatility: from span metadata ("market_volatility" key)
        - trade_amount:      from span input payload ("amount" key)
        - risk_score:        from span scores (score name "risk_score")

    If fewer than MIN_SAMPLES live records are available, falls back to
    the configured fallback provider (defaulting to NullTelemetryProvider)
    and emits a WARNING stamped to the audit log.

    Args:
        langfuse_client:  An initialised ``langfuse.Langfuse`` instance.
        fallback:         Provider to use when live data is insufficient.
                          Defaults to NullTelemetryProvider().
        trace_name:       Optional server-side ``name`` filter passed to
                          ``client.api.trace.list``.
        trace_tags:       Optional server-side ``tags`` filter passed to
                          ``client.api.trace.list``.
    """

    def __init__(
        self,
        langfuse_client: object,
        fallback: BaseTelemetryProvider | None = None,
        *,
        trace_name: str | None = None,
        trace_tags: str | Sequence[str] | None = None,
    ) -> None:
        self._client = langfuse_client
        self._fallback = fallback or NullTelemetryProvider()
        self._trace_name = trace_name
        self._trace_tags = trace_tags

    @classmethod
    def from_credentials(
        cls,
        *,
        host: str,
        public_key: str,
        secret_key: str,
        trace_name: str | None = None,
        trace_tags: str | Sequence[str] | None = None,
    ) -> LangfuseTelemetryProvider:
        """Construct a client from credentials resolved by the kernel factory.

        The adapter reads no environment variables: ``get_telemetry_provider()``
        resolves ``TELEMETRY_HOST`` / ``TELEMETRY_PUBLIC_KEY`` /
        ``TELEMETRY_SECRET_KEY`` and passes them here.

        Raises:
            ConfigurationError: If any credential is empty, or if the langfuse
                package is not installed. Silent fallback to mock data is
                strictly eliminated (AW-8).
        """
        if not (host and public_key and secret_key):
            raise ConfigurationError(
                "[CTRL_TEL_003] LangfuseTelemetryProvider requires host, public_key "
                "and secret_key."
            )

        try:
            from langfuse import Langfuse  # type: ignore[import]
        except ImportError as err:
            raise ConfigurationError(
                "[CTRL_TEL_003] The 'langfuse' package is required when using "
                "LangfuseTelemetryProvider. Install dependencies or set "
                "CAGE_TELEMETRY_PROVIDER=null."
            ) from err

        client = Langfuse(public_key=public_key, secret_key=secret_key, host=host)
        logger.info(
            "[CTRL_TEL_003] LangfuseTelemetryProvider initialised (host=%s).", host
        )
        return cls(
            langfuse_client=client,
            trace_name=trace_name,
            trace_tags=trace_tags,
        )

    def get_latest_data(self, n_samples: int = 500) -> pd.DataFrame:
        """Fetch live trade governance telemetry from Langfuse.

        Queries traces with governance metadata and builds the causal model
        DataFrame (with a ``timestamp`` column for the freshness check). Below
        MIN_SAMPLES the real rows are returned so the gatekeeper reports
        ``insufficient_samples``. Falls back to the configured fallback provider
        (NullTelemetryProvider by default) only when the client is unavailable or
        the fetch fails.
        """
        if self._client is None:
            logger.warning(
                "[CTRL_TEL_003] No Langfuse client — using fallback provider."
            )
            return self._fallback.get_latest_data(n_samples)

        try:
            max_staleness = get_telemetry_max_staleness_seconds()
            cutoff = datetime.now(tz=timezone.utc) - timedelta(
                seconds=max(1, max_staleness)
            )
            traces = _list_recent_traces(
                self._client,
                n_samples,
                from_timestamp=cutoff,
                name=self._trace_name,
                tags=self._trace_tags,
            )

            rows: list[dict] = []
            for trace in traces:
                meta = _as_mapping(getattr(trace, "metadata", None))
                input_data = _as_mapping(getattr(trace, "input", None))
                scores_list = getattr(trace, "scores", []) or []

                # Build score lookup: {name -> value}. The trace list endpoint
                # returns score ids (strings), not score objects; only objects
                # carry a name/value, so ids are skipped and the metadata
                # ``risk_score`` is used instead.
                scores = {
                    getattr(s, "name", ""): getattr(s, "value", None)
                    for s in scores_list
                    if not isinstance(s, str)
                }

                market_vol = meta.get("market_volatility")
                trade_amount = input_data.get("amount")
                risk_score = scores.get("risk_score") or meta.get("risk_score")
                observed_at = getattr(trace, "timestamp", None)

                # Only include rows where all three variables and the trace
                # timestamp are present; the gatekeeper's freshness check
                # needs the timestamp and fails closed without it.
                if (
                    market_vol is not None
                    and trade_amount is not None
                    and risk_score is not None
                    and observed_at is not None
                ):
                    rows.append(
                        {
                            "market_volatility": float(market_vol),
                            "trade_amount": float(trade_amount),
                            "risk_score": float(risk_score),
                            "timestamp": observed_at,
                        }
                    )

            if len(rows) < MIN_SAMPLES:
                # Return the real rows: the gatekeeper is the single decision
                # point and reports insufficient_samples (CAUSAL_INSUFFICIENT_SAMPLES)
                # instead of seeing an empty fallback frame.
                logger.warning(
                    "[CTRL_TEL_003] Only %d live Langfuse samples available "
                    "(minimum %d required); the causal gatekeeper will fail closed.",
                    len(rows),
                    MIN_SAMPLES,
                )
                return pd.DataFrame(
                    rows,
                    columns=[
                        "market_volatility",
                        "trade_amount",
                        "risk_score",
                        "timestamp",
                    ],
                )

            logger.info(
                "[CTRL_TEL_003] LangfuseTelemetryProvider returning %d live samples "
                "for DoWhy causal model.",
                len(rows),
            )
            return pd.DataFrame(rows)

        except Exception as exc:
            logger.error(
                "[CTRL_TEL_003] LangfuseTelemetryProvider fetch failed (%s) — "
                "falling back to %s.",
                exc,
                type(self._fallback).__name__,
            )
            return self._fallback.get_latest_data(n_samples)

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

import logging
import os
from typing import Any

import pandas as pd

from src.gateway.governance.telemetry_provider import (
    BaseTelemetryProvider,
    ConfigurationError,
    MIN_SAMPLES,
    NullTelemetryProvider,
)

logger = logging.getLogger("cage.integrations.telemetry_langfuse")


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
    """

    def __init__(
        self,
        langfuse_client: object,
        fallback: BaseTelemetryProvider | None = None,
    ) -> None:
        self._client = langfuse_client
        self._fallback = fallback or NullTelemetryProvider()

    @classmethod
    def from_env(cls) -> LangfuseTelemetryProvider:
        """Construct from LANGFUSE_* environment variables.

        Required env vars:
            LANGFUSE_PUBLIC_KEY
            LANGFUSE_SECRET_KEY
            LANGFUSE_HOST  (default: https://cloud.langfuse.com)

        Raises:
            ConfigurationError: If LANGFUSE_PUBLIC_KEY or LANGFUSE_SECRET_KEY are
                missing, or if the langfuse package is not installed.
                Silent fallback to mock data is strictly eliminated (AW-8).
        """
        public_key = os.environ.get("LANGFUSE_PUBLIC_KEY", "").strip()
        secret_key = os.environ.get("LANGFUSE_SECRET_KEY", "").strip()
        host = os.environ.get("LANGFUSE_HOST", "https://cloud.langfuse.com").strip()

        if not (public_key and secret_key):
            raise ConfigurationError(
                "[CTRL_TEL_003] LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY must be set "
                "when using LangfuseTelemetryProvider. Set CAGE_TELEMETRY_PROVIDER=null "
                "or explicit CAGE_TELEMETRY_PROVIDER=mock for offline/testing environments."
            )

        try:
            from langfuse import Langfuse  # type: ignore[import]

            client = Langfuse(
                public_key=public_key,
                secret_key=secret_key,
                host=host,
            )
            logger.info(
                "[CTRL_TEL_003] LangfuseTelemetryProvider initialised (host=%s).", host
            )
            return cls(langfuse_client=client)

        except ImportError as err:
            raise ConfigurationError(
                "[CTRL_TEL_003] The 'langfuse' package is required when using "
                "LangfuseTelemetryProvider. Install dependencies or set "
                "CAGE_TELEMETRY_PROVIDER=null."
            ) from err

    def get_latest_data(self, n_samples: int = 500) -> pd.DataFrame:
        """Fetch live trade governance telemetry from Langfuse.

        Queries traces with governance metadata and builds the causal model
        DataFrame. Falls back to configured fallback provider (NullTelemetryProvider
        by default) when live records are below MIN_SAMPLES or client is unavailable.
        """
        if self._client is None:
            logger.warning(
                "[CTRL_TEL_003] No Langfuse client — using fallback provider."
            )
            return self._fallback.get_latest_data(n_samples)

        try:
            # Fetch recent traces from Langfuse (domain-agnostic).
            response = self._client.fetch_traces(  # type: ignore[attr-defined]
                limit=n_samples,
            )
            traces = response.data if hasattr(response, "data") else []

            rows: list[dict] = []
            for trace in traces:
                meta = getattr(trace, "metadata", {}) or {}
                input_data = getattr(trace, "input", {}) or {}
                scores_list = getattr(trace, "scores", []) or []

                # Build score lookup: {name -> value}
                scores = {
                    getattr(s, "name", ""): getattr(s, "value", None)
                    for s in scores_list
                }

                market_vol = meta.get("market_volatility")
                trade_amount = (input_data or {}).get("amount")
                risk_score = scores.get("risk_score") or meta.get("risk_score")

                # Only include rows where all three variables are present.
                if (
                    market_vol is not None
                    and trade_amount is not None
                    and risk_score is not None
                ):
                    rows.append(
                        {
                            "market_volatility": float(market_vol),
                            "trade_amount": float(trade_amount),
                            "risk_score": float(risk_score),
                        }
                    )

            if len(rows) < MIN_SAMPLES:
                logger.warning(
                    "[CTRL_TEL_003] Only %d live Langfuse samples available "
                    "(minimum %d required). Falling back to %s.",
                    len(rows),
                    MIN_SAMPLES,
                    type(self._fallback).__name__,
                )
                return self._fallback.get_latest_data(n_samples)

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

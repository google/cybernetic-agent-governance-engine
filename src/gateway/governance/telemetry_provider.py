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
[CTRL_TEL_003] Live Telemetry Provider for DoWhy Causal Gatekeeper
==================================================================

Provides telemetry data consumed by the CausalGatekeeper for empirical
world-model validation.

Control CTRL_TEL_003 (see config/control_mappings.json) requires that world-model
validation reflect actual runtime conditions, not synthetic data.

Architecture (Wave 1, Task W1.6):
  - BaseTelemetryProvider:       Abstract interface consumed by SymbolicGovernor.
  - NullTelemetryProvider:       Clean fail-closed null provider returning an empty,
                                 correctly-typed DataFrame without fabricating data.
  - LangfuseTelemetryProvider:   Fetches live triples from Langfuse governance spans.
  - MockTelemetryProvider:       Retained for test environments; forbidden in production.
  - get_telemetry_provider:      Factory resolving CAGE_TELEMETRY_PROVIDER env var.

Explicit Provider Selection (AW-8):
  Provider selection is controlled via ``CAGE_TELEMETRY_PROVIDER``:
    - 'langfuse': Pulls live telemetry. Hard failure (ConfigurationError) if credentials missing.
    - 'null': Returns NullTelemetryProvider. Safe for offline / bare-kernel mode.
    - 'mock': Explicitly runs MockTelemetryProvider. Forbidden if CAGE_ENV=prod.
"""

from __future__ import annotations

import logging
import os
from abc import ABC, abstractmethod

import numpy as np
import pandas as pd

logger = logging.getLogger("Gateway.Governance.TelemetryProvider")

# EV-4 Migration: MIN_SAMPLES is sourced from config/governance_thresholds.json
# with environment variable overrides supported (CAUSAL_MIN_SAMPLES or legacy
# CAUSAL_MIN_LIVE_SAMPLES). See schemas/thresholds.py for details.
from src.gateway.governance.schemas.thresholds import get_causal_min_samples

# Minimum number of live samples required before trusting live telemetry.
MIN_SAMPLES: int = get_causal_min_samples()


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ConfigurationError(ValueError):
    """Raised when telemetry provider configuration or credentials are invalid."""


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class BaseTelemetryProvider(ABC):
    """Abstract interface for telemetry data consumed by the causal gatekeeper.

    Concrete providers must return a DataFrame with exactly three columns:
        market_volatility  float  [0, 1]
        trade_amount       float  [0, ∞)
        risk_score         float  [0, 1]
    """

    @abstractmethod
    def get_latest_data(self, n_samples: int = 500) -> pd.DataFrame:
        """Return the most recent n_samples telemetry records.

        The returned DataFrame MUST contain these columns:
            market_volatility, trade_amount, risk_score

        Raises:
            NotImplementedError if the concrete class does not implement this.
        """
        ...  # pragma: no cover


# ---------------------------------------------------------------------------
# Null provider (bare-kernel / offline safe)
# ---------------------------------------------------------------------------


class NullTelemetryProvider(BaseTelemetryProvider):
    """Null telemetry provider returning an empty DataFrame with correct column types.

    Used when:
      - CAGE_TELEMETRY_PROVIDER is set to "null"
      - Running in offline, bare-kernel, or test environments without telemetry
      - Telemetry is explicitly disabled

    Returns an empty DataFrame with the required schema:
        market_volatility: float64
        trade_amount:      float64
        risk_score:        float64

    This allows the causal gatekeeper to cleanly take its documented
    insufficient-samples fail-closed path without fabricating synthetic data.
    """

    def get_latest_data(self, n_samples: int = 500) -> pd.DataFrame:
        """Return an empty typed DataFrame."""
        return pd.DataFrame(
            {
                "market_volatility": pd.Series(dtype="float64"),
                "trade_amount": pd.Series(dtype="float64"),
                "risk_score": pd.Series(dtype="float64"),
            }
        )


# ---------------------------------------------------------------------------
# Mock provider (test / deterministic synthesis)
# ---------------------------------------------------------------------------


class MockTelemetryProvider(BaseTelemetryProvider):
    """Wraps the deterministic synthetic telemetry generator.

    Used in unit and property tests. Forbidden in production (CAGE_ENV=prod).
    The seed is configurable via CAUSAL_MOCK_SEED (default: 42).
    """

    def __init__(self, seed: int = 42) -> None:
        self._seed = seed

    def get_latest_data(self, n_samples: int = 500) -> pd.DataFrame:
        """Generate deterministic synthetic telemetry."""
        np.random.seed(self._seed)
        market_volatility = np.random.uniform(0.1, 0.9, n_samples)
        trade_amount = np.random.normal(5000, 1000, n_samples) - (
            market_volatility * 2000
        )
        trade_amount = np.clip(trade_amount, 100, 10_000)
        risk_score = (
            (market_volatility * 0.5)
            + (trade_amount / 10_000 * 0.5)
            + np.random.normal(0, 0.05, n_samples)
        )
        risk_score = np.clip(risk_score, 0.0, 1.0)
        return pd.DataFrame(
            {
                "market_volatility": market_volatility,
                "trade_amount": trade_amount,
                "risk_score": risk_score,
            }
        )


# ---------------------------------------------------------------------------
# Live Langfuse provider
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Provider factory
# ---------------------------------------------------------------------------


def get_telemetry_provider(
    provider_type: str | None = None,
) -> BaseTelemetryProvider:
    """Return an initialized telemetry provider based on configuration.

    Resolution order:
      1. Explicit ``provider_type`` argument if provided.
      2. ``CAGE_TELEMETRY_PROVIDER`` environment variable ('langfuse', 'null', 'mock').
      3. If unset: defaults to 'langfuse' if LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY
         are configured, otherwise defaults to 'null'.

    Rules:
      - 'mock': forbidden when CAGE_ENV=prod (raises ConfigurationError).
      - 'langfuse': raises ConfigurationError if credentials or SDK are missing.
      - 'null': returns NullTelemetryProvider().
    """
    if provider_type is None:
        provider_type = os.environ.get("CAGE_TELEMETRY_PROVIDER", "").strip().lower()

    if not provider_type:
        has_keys = bool(
            os.environ.get("LANGFUSE_PUBLIC_KEY")
            and os.environ.get("LANGFUSE_SECRET_KEY")
        )
        if has_keys:
            provider_type = "langfuse"
        else:
            provider_type = "null"

    provider_type = provider_type.lower()

    if provider_type == "null":
        return NullTelemetryProvider()

    if provider_type == "mock":
        cage_env = (
            (os.environ.get("CAGE_ENV") or os.environ.get("ENVIRONMENT", ""))
            .strip()
            .lower()
        )
        if cage_env in ("prod", "production"):
            raise ConfigurationError(
                "MockTelemetryProvider is strictly forbidden in production (CAGE_ENV=prod). "
                "Configure live telemetry credentials or select a valid production provider."
            )
        return MockTelemetryProvider()

    if provider_type == "langfuse":
        return LangfuseTelemetryProvider.from_env()

    raise ConfigurationError(
        f"Unknown telemetry provider '{provider_type}'. "
        "Valid choices are: 'langfuse', 'null', 'mock'."
    )

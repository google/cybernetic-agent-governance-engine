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
  - RemoteTelemetryProvider:   Fetches live triples from Langfuse governance spans.
  - MockTelemetryProvider:       Retained for test environments; forbidden in production.
  - get_telemetry_provider:      Factory resolving CAGE_TELEMETRY_PROVIDER env var.

Explicit Provider Selection (AW-8):
  Provider selection is controlled via ``CAGE_TELEMETRY_PROVIDER``:
    - 'remote': Pulls live telemetry. Hard failure (ConfigurationError) if credentials missing.
    - 'null': Returns NullTelemetryProvider. Safe for offline / bare-kernel mode.
    - 'mock': Explicitly runs MockTelemetryProvider. Forbidden if CAGE_ENV=prod.
"""

from __future__ import annotations

import logging
import os
from abc import ABC, abstractmethod
from typing import Any

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
# Lazy-loaded external integrations (Layer 3)
# ---------------------------------------------------------------------------


def __getattr__(name: str) -> Any:
    """Lazy-load Layer 3 integration adapters on attribute access.

    This preserves backward-compatible imports while maintaining strict
    layer boundary separation (Gate G3).
    """
    if name == "RemoteTelemetryProvider":
        from src.integrations.telemetry_langfuse.provider import (
            LangfuseTelemetryProvider as RemoteTelemetryProvider,
        )

        return RemoteTelemetryProvider
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# ---------------------------------------------------------------------------
# Provider factory
# ---------------------------------------------------------------------------


def get_telemetry_provider(
    provider_type: str | None = None,
) -> BaseTelemetryProvider:
    """Return an initialized telemetry provider based on configuration.

    Resolution order:
      1. Explicit ``provider_type`` argument if provided.
      2. ``CAGE_TELEMETRY_PROVIDER`` environment variable ('remote', 'null', 'mock').
      3. If unset: defaults to 'remote' if TELEMETRY_PUBLIC_KEY and TELEMETRY_SECRET_KEY
         are configured, otherwise defaults to 'null'.

    Rules:
      - 'mock': forbidden when CAGE_ENV=prod (raises ConfigurationError).
      - 'remote': raises ConfigurationError if credentials or SDK are missing.
      - 'null': returns NullTelemetryProvider().
    """
    if provider_type is None:
        provider_type = os.environ.get("CAGE_TELEMETRY_PROVIDER", "").strip().lower()

    if not provider_type:
        has_keys = bool(
            os.environ.get("TELEMETRY_PUBLIC_KEY")
            and os.environ.get("TELEMETRY_SECRET_KEY")
        )
        if has_keys:
            provider_type = "remote"
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

    if provider_type == "remote":
        from src.integrations.telemetry_langfuse.provider import (
            LangfuseTelemetryProvider as RemoteTelemetryProvider,
        )

        return RemoteTelemetryProvider.from_env()

    raise ConfigurationError(
        f"Unknown telemetry provider '{provider_type}'. "
        "Valid choices are: 'remote', 'null', 'mock'."
    )


__all__ = [
    "MIN_SAMPLES",
    "BaseTelemetryProvider",
    "ConfigurationError",
    "MockTelemetryProvider",
    "NullTelemetryProvider",
    "get_telemetry_provider",
]

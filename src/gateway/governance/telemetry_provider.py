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
  Under an enforcing posture (``env_posture.is_enforcing()``) the variable must
  be set: the kernel never picks a provider silently there.

Credentials (one name per value, vendor-neutral):
    TELEMETRY_HOST, TELEMETRY_PUBLIC_KEY, TELEMETRY_SECRET_KEY
  The kernel reads them and passes them to the remote adapter, which reads no
  environment variables itself.
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


_PREV_CONFIGURATION_ERROR = globals().get("ConfigurationError")
_PREV_BASE_TELEMETRY_PROVIDER = globals().get("BaseTelemetryProvider")
_PREV_NULL_TELEMETRY_PROVIDER = globals().get("NullTelemetryProvider")
_PREV_MOCK_TELEMETRY_PROVIDER = globals().get("MockTelemetryProvider")


class ConfigurationError(ValueError):
    """Raised when telemetry provider configuration or credentials are invalid."""


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


def _resolve_telemetry_columns() -> tuple[str, str, str]:
    """Resolve (confounder, treatment, outcome) column names from the active domain's causal graph."""
    try:
        from src.gateway.governance.causal.gatekeeper import _causal_config

        cfg = _causal_config()
        common_causes = cfg.get("common_causes") or []
        confounder = str(common_causes[0]) if common_causes else "confounder"
        treatment = str(cfg.get("treatment") or "treatment")
        outcome = str(cfg.get("outcome") or "outcome")
        return (confounder, treatment, outcome)
    except Exception:
        return ("confounder", "treatment", "outcome")


class BaseTelemetryProvider(ABC):
    """Abstract interface for telemetry data consumed by the causal gatekeeper.

    Concrete providers must return a DataFrame with the three columns declared
    by the active domain's causal graph configuration:
        <confounder>   float  [0, 1]
        <treatment>    float  [0, ∞)
        <outcome>      float  [0, 1]
    """

    @abstractmethod
    def get_latest_data(self, n_samples: int = 500) -> pd.DataFrame:
        """Return the most recent n_samples telemetry records.

        The returned DataFrame MUST contain the confounder, treatment, and
        outcome columns declared by the active domain's causal graph.

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

    Returns an empty DataFrame with ``float64`` columns matching the active
    domain's causal graph ``(confounder, treatment, outcome)`` schema.

    This allows the causal gatekeeper to cleanly take its documented
    insufficient-samples fail-closed path without fabricating synthetic data.
    """

    def get_latest_data(self, n_samples: int = 500) -> pd.DataFrame:
        """Return an empty typed DataFrame."""
        confounder_col, treatment_col, outcome_col = _resolve_telemetry_columns()
        return pd.DataFrame(
            {
                confounder_col: pd.Series(dtype="float64"),
                treatment_col: pd.Series(dtype="float64"),
                outcome_col: pd.Series(dtype="float64"),
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
        confounder_col, treatment_col, outcome_col = _resolve_telemetry_columns()
        np.random.seed(self._seed)
        confounder = np.random.uniform(0.1, 0.9, n_samples)
        treatment = np.random.normal(5000, 1000, n_samples) - (confounder * 2000)
        treatment = np.clip(treatment, 100, 10_000)
        outcome = (
            (confounder * 0.5)
            + (treatment / 10_000 * 0.5)
            + np.random.normal(0, 0.05, n_samples)
        )
        outcome = np.clip(outcome, 0.0, 1.0)
        return pd.DataFrame(
            {
                confounder_col: confounder,
                treatment_col: treatment,
                outcome_col: outcome,
            }
        )


if _PREV_CONFIGURATION_ERROR is not None:
    ConfigurationError = _PREV_CONFIGURATION_ERROR  # type: ignore[misc]
if _PREV_BASE_TELEMETRY_PROVIDER is not None:
    BaseTelemetryProvider = _PREV_BASE_TELEMETRY_PROVIDER  # type: ignore[misc]
if _PREV_NULL_TELEMETRY_PROVIDER is not None:
    NullTelemetryProvider = _PREV_NULL_TELEMETRY_PROVIDER  # type: ignore[misc]
if _PREV_MOCK_TELEMETRY_PROVIDER is not None:
    MockTelemetryProvider = _PREV_MOCK_TELEMETRY_PROVIDER  # type: ignore[misc]


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


TELEMETRY_CREDENTIAL_VARS: tuple[str, str, str] = (
    "TELEMETRY_HOST",
    "TELEMETRY_PUBLIC_KEY",
    "TELEMETRY_SECRET_KEY",
)


def _telemetry_credentials() -> tuple[str, str, str]:
    """Return ``(host, public_key, secret_key)`` from ``TELEMETRY_*`` (stripped)."""
    host, public_key, secret_key = (
        os.environ.get(name, "").strip() for name in TELEMETRY_CREDENTIAL_VARS
    )
    return host.rstrip("/"), public_key, secret_key


def get_telemetry_provider(
    provider_type: str | None = None,
) -> BaseTelemetryProvider:
    """Return an initialized telemetry provider based on configuration.

    Resolution order:
      1. Explicit ``provider_type`` argument if provided.
      2. ``CAGE_TELEMETRY_PROVIDER`` environment variable ('remote', 'null', 'mock').
      3. If unset under an enforcing posture: ConfigurationError. Otherwise
         'remote' if all ``TELEMETRY_*`` credentials are set, else 'null'.

    Rules:
      - 'mock': forbidden when CAGE_ENV=prod (raises ConfigurationError).
      - 'remote': raises ConfigurationError if a ``TELEMETRY_*`` credential or
        the adapter's SDK is missing.
      - 'null': returns NullTelemetryProvider().
    """
    from src.gateway.governance.env_posture import is_enforcing

    if provider_type is None:
        provider_type = os.environ.get("CAGE_TELEMETRY_PROVIDER", "").strip().lower()

    host, public_key, secret_key = _telemetry_credentials()

    if not provider_type:
        if is_enforcing():
            raise ConfigurationError(
                "CAGE_TELEMETRY_PROVIDER must be set under an enforcing posture "
                "('remote', or 'null' to run the causal tier without telemetry). "
                "The provider is never selected implicitly outside dev/test/ci."
            )
        provider_type = "remote" if (host and public_key and secret_key) else "null"

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
        missing = [
            name
            for name, value in zip(
                TELEMETRY_CREDENTIAL_VARS, (host, public_key, secret_key), strict=True
            )
            if not value
        ]
        if missing:
            raise ConfigurationError(
                "[CTRL_TEL_003] CAGE_TELEMETRY_PROVIDER=remote requires "
                + ", ".join(missing)
                + ". Set CAGE_TELEMETRY_PROVIDER=null to run without telemetry."
            )
        from src.integrations.telemetry_langfuse.provider import (
            LangfuseTelemetryProvider as RemoteTelemetryProvider,
        )

        return RemoteTelemetryProvider.from_credentials(
            host=host, public_key=public_key, secret_key=secret_key
        )

    raise ConfigurationError(
        f"Unknown telemetry provider '{provider_type}'. "
        "Valid choices are: 'remote', 'null', 'mock'."
    )


__all__ = [
    "MIN_SAMPLES",
    "TELEMETRY_CREDENTIAL_VARS",
    "BaseTelemetryProvider",
    "ConfigurationError",
    "MockTelemetryProvider",
    "NullTelemetryProvider",
    "get_telemetry_provider",
]

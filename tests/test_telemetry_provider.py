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
Unit tests for src.gateway.governance.telemetry_provider.

Covers:
  - BaseTelemetryProvider abstract interface
  - MockTelemetryProvider deterministic data generation
  - RemoteTelemetryProvider with None client (fallback path)
  - RemoteTelemetryProvider.from_credentials() credential-missing and ImportError paths
  - get_telemetry_provider(): TELEMETRY_* resolution and the enforcing-posture rule
  - RemoteTelemetryProvider.get_latest_data() with live data (sufficient samples)
  - RemoteTelemetryProvider.get_latest_data() with too few samples (fallback)
  - RemoteTelemetryProvider.get_latest_data() exception fallback
  - MIN_SAMPLES default value
"""

import datetime
import os
from unittest import mock
from unittest.mock import MagicMock, patch

import numpy as np
import pandas as pd
import pytest

from src.gateway.governance.telemetry_provider import (
    MIN_SAMPLES,
    BaseTelemetryProvider,
    ConfigurationError,
    MockTelemetryProvider,
    NullTelemetryProvider,
    RemoteTelemetryProvider,
    get_telemetry_provider,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_REQUIRED_COLUMNS = {"market_volatility", "trade_amount", "risk_score"}
_TRACE_TS = datetime.datetime(2026, 10, 2, 12, 0, tzinfo=datetime.timezone.utc)


def _make_trace(
    market_vol=0.5, amount=5000.0, risk=0.4, include_all=True, timestamp=_TRACE_TS
):
    """Build a minimal mock Langfuse trace object."""
    trace = MagicMock()
    trace.timestamp = timestamp
    trace.metadata = {"market_volatility": market_vol} if include_all else {}
    trace.input = {"amount": amount} if include_all else {}
    score = MagicMock()
    score.name = "risk_score"
    score.value = risk
    trace.scores = [score] if include_all else []
    return trace


# ---------------------------------------------------------------------------
# BaseTelemetryProvider
# ---------------------------------------------------------------------------


class TestBaseTelemetryProvider:
    """Abstract interface contract."""

    def test_cannot_instantiate_directly(self):
        """BaseTelemetryProvider must be abstract — direct instantiation should fail."""
        with pytest.raises(TypeError):
            BaseTelemetryProvider()  # type: ignore[abstract]

    def test_concrete_subclass_must_implement_get_latest_data(self):
        """Concrete subclass that omits get_latest_data must still raise TypeError."""

        class Incomplete(BaseTelemetryProvider):
            pass

        with pytest.raises(TypeError):
            Incomplete()


# ---------------------------------------------------------------------------
# MockTelemetryProvider
# ---------------------------------------------------------------------------


class TestMockTelemetryProvider:
    """Deterministic synthetic telemetry generation."""

    def test_default_seed_is_42(self):
        provider = MockTelemetryProvider()
        assert provider._seed == 42

    def test_custom_seed_stored(self):
        provider = MockTelemetryProvider(seed=99)
        assert provider._seed == 99

    def test_returns_dataframe(self):
        provider = MockTelemetryProvider()
        df = provider.get_latest_data()
        assert isinstance(df, pd.DataFrame)

    def test_dataframe_has_required_columns(self):
        provider = MockTelemetryProvider()
        df = provider.get_latest_data()
        assert _REQUIRED_COLUMNS.issubset(set(df.columns))

    def test_default_n_samples_is_500(self):
        provider = MockTelemetryProvider()
        df = provider.get_latest_data()
        assert len(df) == 500

    def test_custom_n_samples(self):
        provider = MockTelemetryProvider()
        df = provider.get_latest_data(n_samples=100)
        assert len(df) == 100

    def test_market_volatility_in_range(self):
        provider = MockTelemetryProvider(seed=0)
        df = provider.get_latest_data(n_samples=200)
        assert df["market_volatility"].between(0.0, 1.0).all(), (
            "market_volatility must be in [0, 1]"
        )

    def test_risk_score_in_range(self):
        provider = MockTelemetryProvider(seed=0)
        df = provider.get_latest_data(n_samples=200)
        assert df["risk_score"].between(0.0, 1.0).all(), "risk_score must be in [0, 1]"

    def test_trade_amount_positive(self):
        provider = MockTelemetryProvider(seed=0)
        df = provider.get_latest_data(n_samples=200)
        assert (df["trade_amount"] >= 0).all(), "trade_amount must be non-negative"

    def test_same_seed_produces_same_data(self):
        p1 = MockTelemetryProvider(seed=7)
        p2 = MockTelemetryProvider(seed=7)
        df1 = p1.get_latest_data(n_samples=50)
        df2 = p2.get_latest_data(n_samples=50)
        pd.testing.assert_frame_equal(df1, df2)

    def test_different_seeds_produce_different_data(self):
        p1 = MockTelemetryProvider(seed=1)
        p2 = MockTelemetryProvider(seed=2)
        df1 = p1.get_latest_data(n_samples=50)
        df2 = p2.get_latest_data(n_samples=50)
        # At least one column must differ
        assert not df1["market_volatility"].equals(df2["market_volatility"])

    def test_no_nan_values(self):
        provider = MockTelemetryProvider()
        df = provider.get_latest_data(n_samples=100)
        assert not df.isnull().any().any(), "MockTelemetryProvider must not return NaN"

    def test_small_n_samples(self):
        provider = MockTelemetryProvider()
        df = provider.get_latest_data(n_samples=1)
        assert len(df) == 1

    def test_large_n_samples(self):
        provider = MockTelemetryProvider()
        df = provider.get_latest_data(n_samples=2000)
        assert len(df) == 2000


# ---------------------------------------------------------------------------
# RemoteTelemetryProvider — None-client path (default fallback is NullTelemetryProvider)
# ---------------------------------------------------------------------------


class TestRemoteTelemetryProviderNoneClient:
    """When client=None, all calls fall back to the configured fallback provider."""

    def test_none_client_fallback_returns_dataframe(self):
        provider = RemoteTelemetryProvider(langfuse_client=None)
        df = provider.get_latest_data()
        assert isinstance(df, pd.DataFrame)
        assert _REQUIRED_COLUMNS.issubset(set(df.columns))

    def test_none_client_uses_default_null_fallback(self):
        provider = RemoteTelemetryProvider(langfuse_client=None)
        assert isinstance(provider._fallback, NullTelemetryProvider)

    def test_none_client_custom_fallback_is_used(self):
        custom_fallback = MockTelemetryProvider(seed=123)
        provider = RemoteTelemetryProvider(
            langfuse_client=None, fallback=custom_fallback
        )
        assert provider._fallback is custom_fallback
        df = provider.get_latest_data(n_samples=100)
        assert len(df) == 100

    def test_none_client_default_fallback_data_is_empty(self):
        """Default fallback is NullTelemetryProvider which returns 0 rows (fail-closed)."""
        provider = RemoteTelemetryProvider(langfuse_client=None)
        df = provider.get_latest_data(n_samples=100)
        assert len(df) == 0

    def test_none_client_stores_client_as_none(self):
        provider = RemoteTelemetryProvider(langfuse_client=None)
        assert provider._client is None


# ---------------------------------------------------------------------------
# RemoteTelemetryProvider.from_credentials() — credential / import-error paths (AW-8)
# ---------------------------------------------------------------------------

_CREDS = {
    "host": "https://telemetry.test.example",
    "public_key": "pub-test-1234",
    "secret_key": "sec-test-5678",
}
_CRED_ENV = {
    "TELEMETRY_HOST": _CREDS["host"],
    "TELEMETRY_PUBLIC_KEY": _CREDS["public_key"],
    "TELEMETRY_SECRET_KEY": _CREDS["secret_key"],
}


def _env_without(*names: str) -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k not in names}


class TestRemoteTelemetryProviderFromCredentials:
    """The adapter takes explicit credentials and reads no environment."""

    @pytest.mark.parametrize("empty", ["host", "public_key", "secret_key"])
    def test_empty_credential_raises_configuration_error(self, empty):
        creds = {**_CREDS, empty: ""}
        with pytest.raises(ConfigurationError, match="requires host, public_key"):
            RemoteTelemetryProvider.from_credentials(**creds)

    def test_import_error_raises_configuration_error(self):
        """If the SDK is not installed, construction must fail closed (AW-8)."""
        with patch("builtins.__import__", side_effect=_selective_import_error("langfuse")):
            with pytest.raises(ConfigurationError, match="package is required"):
                RemoteTelemetryProvider.from_credentials(**_CREDS)

    def test_credentials_are_passed_to_the_client(self):
        client_cls = MagicMock()
        with patch.dict("sys.modules", {"langfuse": MagicMock(Langfuse=client_cls)}):
            provider = RemoteTelemetryProvider.from_credentials(**_CREDS)
        client_cls.assert_called_once_with(**_CREDS)
        assert provider._client is client_cls.return_value

    def test_adapter_ignores_vendor_named_env(self):
        """Vendor-named variables are not a second source of the same credential."""
        assert not hasattr(RemoteTelemetryProvider, "from_env")


# ---------------------------------------------------------------------------
# get_telemetry_provider() Factory (AW-8)
# ---------------------------------------------------------------------------


class TestGetTelemetryProviderFactory:
    """Explicit provider selection via CAGE_TELEMETRY_PROVIDER."""

    def test_factory_null_provider(self):
        with patch.dict(os.environ, {"CAGE_TELEMETRY_PROVIDER": "null"}):
            provider = get_telemetry_provider()
        assert isinstance(provider, NullTelemetryProvider)

    def test_factory_mock_provider_non_prod(self):
        with patch.dict(
            os.environ,
            {"CAGE_TELEMETRY_PROVIDER": "mock", "CAGE_ENV": "development"},
        ):
            provider = get_telemetry_provider()
        assert isinstance(provider, MockTelemetryProvider)

    def test_factory_mock_provider_rejected_in_prod(self):
        with patch.dict(
            os.environ,
            {"CAGE_TELEMETRY_PROVIDER": "mock", "CAGE_ENV": "prod"},
        ):
            with pytest.raises(
                ConfigurationError, match="[Mm]ock.*forbidden in production"
            ):
                get_telemetry_provider()

    def test_factory_unknown_provider_rejected(self):
        with patch.dict(os.environ, {"CAGE_TELEMETRY_PROVIDER": "unsupported_vendor"}):
            with pytest.raises(ConfigurationError, match="Unknown telemetry provider"):
                get_telemetry_provider()

    def test_factory_remote_passes_telemetry_credentials(self):
        env = {**_env_without("CAGE_TELEMETRY_PROVIDER"), "CAGE_TELEMETRY_PROVIDER": "remote"}
        env.update({**_CRED_ENV, "TELEMETRY_HOST": _CREDS["host"] + "/"})
        client_cls = MagicMock()
        with patch.dict(os.environ, env, clear=True):
            with patch.dict("sys.modules", {"langfuse": MagicMock(Langfuse=client_cls)}):
                provider = get_telemetry_provider()
        assert isinstance(provider, RemoteTelemetryProvider)
        client_cls.assert_called_once_with(**_CREDS)  # trailing slash stripped

    @pytest.mark.parametrize("missing", list(_CRED_ENV))
    def test_factory_remote_names_each_missing_credential(self, missing):
        env = {**_env_without(*_CRED_ENV), "CAGE_TELEMETRY_PROVIDER": "remote"}
        env.update({k: v for k, v in _CRED_ENV.items() if k != missing})
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ConfigurationError, match=missing):
                get_telemetry_provider()

    def test_factory_remote_ignores_vendor_named_credentials(self):
        env = {**_env_without(*_CRED_ENV), "CAGE_TELEMETRY_PROVIDER": "remote"}
        env.update({"LANGFUSE_PUBLIC_KEY": "x", "LANGFUSE_SECRET_KEY": "y"})
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ConfigurationError, match="TELEMETRY_PUBLIC_KEY"):
                get_telemetry_provider()

    @pytest.mark.parametrize("cage_env", ["staging", "production", "local"])
    def test_factory_unset_under_enforcing_posture_raises(self, cage_env):
        env = {**_env_without("CAGE_TELEMETRY_PROVIDER"), "CAGE_ENV": cage_env, **_CRED_ENV}
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ConfigurationError, match="CAGE_TELEMETRY_PROVIDER must be set"):
                get_telemetry_provider()

    def test_factory_unset_permissive_without_credentials_is_null(self):
        env = {**_env_without("CAGE_TELEMETRY_PROVIDER", *_CRED_ENV), "CAGE_ENV": "test"}
        with patch.dict(os.environ, env, clear=True):
            assert isinstance(get_telemetry_provider(), NullTelemetryProvider)

    def test_factory_unset_permissive_with_credentials_is_remote(self):
        env = {**_env_without("CAGE_TELEMETRY_PROVIDER"), "CAGE_ENV": "dev", **_CRED_ENV}
        with patch.dict(os.environ, env, clear=True):
            with patch.dict("sys.modules", {"langfuse": MagicMock()}):
                assert isinstance(get_telemetry_provider(), RemoteTelemetryProvider)


# ---------------------------------------------------------------------------
# RemoteTelemetryProvider.get_latest_data() — live data paths
# ---------------------------------------------------------------------------


class TestRemoteTelemetryProviderGetLatestData:
    """get_latest_data() with mocked Langfuse client."""

    def _make_provider_with_traces(self, traces, n_samples=500):
        """Build a provider whose mock client returns the given list of traces."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.data = traces
        mock_client.fetch_traces.return_value = mock_response
        fallback = MockTelemetryProvider(seed=42)
        return RemoteTelemetryProvider(langfuse_client=mock_client, fallback=fallback)

    def test_sufficient_live_samples_returns_live_dataframe(self):
        n = MIN_SAMPLES + 10
        traces = [
            _make_trace(market_vol=0.3, amount=4000.0, risk=0.35) for _ in range(n)
        ]
        provider = self._make_provider_with_traces(traces)
        df = provider.get_latest_data(n_samples=n)
        assert isinstance(df, pd.DataFrame)
        assert _REQUIRED_COLUMNS.issubset(set(df.columns))
        assert len(df) == n

    def test_sufficient_live_samples_values_match_traces(self):
        n = MIN_SAMPLES + 5
        traces = [
            _make_trace(market_vol=0.2, amount=3000.0, risk=0.25) for _ in range(n)
        ]
        provider = self._make_provider_with_traces(traces)
        df = provider.get_latest_data(n_samples=n)
        assert all(abs(v - 0.2) < 1e-9 for v in df["market_volatility"])
        assert all(abs(v - 3000.0) < 1e-9 for v in df["trade_amount"])
        assert all(abs(v - 0.25) < 1e-9 for v in df["risk_score"])

    def test_insufficient_live_samples_returns_real_rows(self):
        """Fewer than MIN_SAMPLES traces → the real rows, never the fallback.

        The causal gatekeeper is the single decision point: it must see the
        short frame and report insufficient_samples (WS-C, POAM-2026-088).
        """
        traces = [_make_trace() for _ in range(MIN_SAMPLES - 1)]
        provider = self._make_provider_with_traces(traces)
        df = provider.get_latest_data(n_samples=500)
        assert len(df) == MIN_SAMPLES - 1
        assert (df["timestamp"] == _TRACE_TS).all()

    def test_zero_live_samples_returns_empty_typed_frame(self):
        provider = self._make_provider_with_traces([])
        df = provider.get_latest_data(n_samples=100)
        assert isinstance(df, pd.DataFrame)
        assert len(df) == 0
        assert _REQUIRED_COLUMNS | {"timestamp"} <= set(df.columns)

    def test_traces_without_timestamp_are_excluded(self):
        """A row the freshness check cannot date is dropped, not passed through."""
        good = [_make_trace() for _ in range(MIN_SAMPLES)]
        undated = _make_trace(timestamp=None)
        provider = self._make_provider_with_traces([undated, *good])
        df = provider.get_latest_data(n_samples=len(good) + 1)
        assert len(df) == len(good)
        assert df["timestamp"].notna().all()

    def test_traces_with_missing_fields_are_excluded(self):
        """Traces missing any of the three fields must be dropped."""
        good_traces = [_make_trace() for _ in range(MIN_SAMPLES + 5)]
        bad_trace = _make_trace(include_all=False)
        all_traces = [bad_trace, *good_traces]

        provider = self._make_provider_with_traces(all_traces)
        df = provider.get_latest_data(n_samples=len(all_traces))
        # Only good_traces should appear
        assert len(df) == len(good_traces)

    def test_exception_during_fetch_falls_back_to_mock(self):
        mock_client = MagicMock()
        mock_client.fetch_traces.side_effect = RuntimeError("network error")
        fallback = MockTelemetryProvider(seed=42)
        provider = RemoteTelemetryProvider(
            langfuse_client=mock_client, fallback=fallback
        )
        df = provider.get_latest_data(n_samples=100)
        # Should fall back to mock (100 rows)
        assert isinstance(df, pd.DataFrame)
        assert _REQUIRED_COLUMNS.issubset(set(df.columns))

    def test_response_without_data_attribute_falls_back(self):
        """When response has no .data attribute, treat as empty → fallback."""
        mock_client = MagicMock()
        mock_response = MagicMock(spec=[])  # spec=[] means no attributes
        mock_client.fetch_traces.return_value = mock_response
        fallback = MockTelemetryProvider(seed=42)
        provider = RemoteTelemetryProvider(
            langfuse_client=mock_client, fallback=fallback
        )
        df = provider.get_latest_data(n_samples=100)
        assert isinstance(df, pd.DataFrame)

    def test_risk_score_from_metadata_fallback(self):
        """Risk score should be read from metadata if not in scores list."""
        n = MIN_SAMPLES + 2
        traces = []
        for _ in range(n):
            trace = MagicMock()
            trace.metadata = {"market_volatility": 0.5, "risk_score": 0.6}
            trace.input = {"amount": 1000.0}
            trace.scores = []  # Empty scores — should fall back to meta.risk_score
            traces.append(trace)

        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.data = traces
        mock_client.fetch_traces.return_value = mock_response
        provider = RemoteTelemetryProvider(
            langfuse_client=mock_client, fallback=MockTelemetryProvider()
        )
        df = provider.get_latest_data(n_samples=n)
        assert len(df) == n
        assert all(abs(v - 0.6) < 1e-9 for v in df["risk_score"])

    def test_fetch_traces_called_with_correct_params(self):
        traces = [_make_trace() for _ in range(MIN_SAMPLES + 1)]
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.data = traces
        mock_client.fetch_traces.return_value = mock_response
        provider = RemoteTelemetryProvider(
            langfuse_client=mock_client, fallback=MockTelemetryProvider()
        )
        provider.get_latest_data(n_samples=200)
        mock_client.fetch_traces.assert_called_once_with(limit=200)


# ---------------------------------------------------------------------------
# MIN_SAMPLES constant
# ---------------------------------------------------------------------------


class TestMinSamplesConstant:
    def test_min_samples_is_positive_integer(self):
        assert isinstance(MIN_SAMPLES, int)
        assert MIN_SAMPLES > 0

    def test_min_samples_default_is_50(self):
        """Default MIN_SAMPLES (without env override) is 50."""
        with patch.dict(os.environ, {}, clear=False):
            # Remove override if present, then re-import to check default logic
            env = dict(os.environ)
            env.pop("CAUSAL_MIN_LIVE_SAMPLES", None)
            with patch.dict(os.environ, env, clear=True):
                import importlib

                import src.gateway.governance.telemetry_provider as tp_mod

                importlib.reload(tp_mod)
                assert tp_mod.MIN_SAMPLES == 50


# ---------------------------------------------------------------------------
# Private helper for selective ImportError mocking
# ---------------------------------------------------------------------------


def _selective_import_error(blocked_module: str):
    """Return a builtins.__import__ side-effect that raises ImportError for blocked_module."""
    original_import = (
        __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__
    )

    def _import(name, *args, **kwargs):
        if name == blocked_module or name.startswith(blocked_module + "."):
            raise ImportError(f"Mocked ImportError for {name}")
        return original_import(name, *args, **kwargs)

    return _import


pytestmark = [pytest.mark.unit, pytest.mark.local]

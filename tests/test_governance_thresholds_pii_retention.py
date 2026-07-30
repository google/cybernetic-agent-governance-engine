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

"""Tests for FINDING-07 remediation — jurisdictional PII audit retention.

pii_audit_retention_days / pii_audit_retention_authority previously hardcoded
FISMA AU-11 / 90 days as a universal Pydantic default regardless of
CAGE_DEPLOYMENT_REGION. These tests assert the region-aware resolution
implemented in src/gateway/governance/schemas/thresholds.py.

Ref: docs/compliance/cross-region/JURISDICTIONAL_SEPARATION_ANALYSIS.md#FINDING-07
"""

from src.gateway.governance.schemas.thresholds import (
    GovernanceThresholds,
    _resolve_pii_retention,
)


class TestResolvePiiRetention:
    """_resolve_pii_retention() must key off CAGE_DEPLOYMENT_REGION at call time."""

    def test_us_fed_cites_fisma_au11(self, monkeypatch):
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "US_FED")
        days, authority = _resolve_pii_retention()
        assert days == 90
        assert "FISMA AU-11" in authority

    def test_eu_ecb_cites_gdpr(self, monkeypatch):
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "EU_ECB")
        _days, authority = _resolve_pii_retention()
        assert "GDPR Art. 5" in authority

    def test_apac_mas_cites_notice_655(self, monkeypatch):
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "APAC_MAS")
        _days, authority = _resolve_pii_retention()
        assert "MAS Notice 655" in authority

    def test_unset_region_falls_back_to_iso_42001(self, monkeypatch):
        monkeypatch.delenv("CAGE_DEPLOYMENT_REGION", raising=False)
        _days, authority = _resolve_pii_retention()
        assert "ISO 42001" in authority

    def test_unknown_region_falls_back_to_iso_42001(self, monkeypatch):
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "UNKNOWN_REGION")
        _days, authority = _resolve_pii_retention()
        assert "ISO 42001" in authority


class TestGovernanceThresholdsPiiFieldsRegionAware:
    """GovernanceThresholds model must expose region-derived PII fields
    when not explicitly overridden by governance_thresholds.json."""

    def _build_minimal_kwargs(self) -> dict:
        """Minimal kwargs to satisfy required sub-models (no pii_* overrides)."""
        return {
            "cbf": {"min_cash_balance": 1000.0, "gamma": 0.5},
            "drawdown": {"limit": 0.05},
            "stpa": {
                "uca5_drawdown_threshold_pct": 4.5,
                "uca6_max_order_volume_fraction": 0.01,
                "max_sell_portfolio_fraction": 0.1,
                "max_latency_ms": 200.0,
            },
            "confidence": {"min_trade_confidence": 0.95},
            "consensus": {"threshold_usd": 10000.0},
            "tier1_keywords": ["SYSTEM OVERRIDE"],
        }

    def test_pii_retention_authority_field_exists(self):
        thresholds = GovernanceThresholds(**self._build_minimal_kwargs())
        assert hasattr(thresholds, "pii_audit_retention_authority")
        assert isinstance(thresholds.pii_audit_retention_authority, str)
        assert len(thresholds.pii_audit_retention_authority) > 0

    def test_region_derived_default_reflects_us_fed(self, monkeypatch):
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "US_FED")
        thresholds = GovernanceThresholds(**self._build_minimal_kwargs())
        assert "FISMA AU-11" in thresholds.pii_audit_retention_authority

    def test_region_derived_default_reflects_eu_ecb(self, monkeypatch):
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "EU_ECB")
        thresholds = GovernanceThresholds(**self._build_minimal_kwargs())
        assert "GDPR" in thresholds.pii_audit_retention_authority

    def test_explicit_json_value_overrides_region_default(self, monkeypatch):
        """An explicit value in governance_thresholds.json must win over the
        region-derived default (JSON is the single source of truth)."""
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "US_FED")
        kwargs = self._build_minimal_kwargs()
        kwargs["pii_audit_retention_days"] = 365
        kwargs["pii_audit_retention_authority"] = "Custom Override Citation"
        thresholds = GovernanceThresholds(**kwargs)
        assert thresholds.pii_audit_retention_days == 365
        assert thresholds.pii_audit_retention_authority == "Custom Override Citation"

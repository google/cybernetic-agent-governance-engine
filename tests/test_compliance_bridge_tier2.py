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
tests/test_compliance_bridge_tier2.py

Tier-2 roadmap implementation tests:
  2.1 — Multi-framework control registry (FRAMEWORK_CONTROLS, SUPPORTED_FRAMEWORKS,
         GET /v1/controls?framework=)
  2.2 — SSE REMEDIATION_GENERATED event type
  2.5 — Evidence SLA alerting (sla_monitor.py, EVIDENCE_SLA_SECONDS)
  2.6 — GET /v1/metrics/summary aggregate endpoint
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import asyncio
import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    """TestClient with Langfuse patched and C-07 auth dependency overridden."""
    with patch("src.compliance_bridge.main.Langfuse") as MockLF:
        MockLF.return_value = MagicMock()
        from src.compliance_bridge.main import app
        from src.compliance_bridge.auth import require_internal_token
        from fastapi.testclient import TestClient
        app.dependency_overrides[require_internal_token] = lambda: "test-token"
        try:
            with TestClient(app, raise_server_exceptions=True) as c:
                yield c
        finally:
            app.dependency_overrides.pop(require_internal_token, None)


def _make_metrics(control_id: str, safety_rate: float = 1.0, grace: bool = False,
                  evidence_age: float = 0.0):
    from src.compliance_bridge.types import ComplianceMetrics
    return ComplianceMetrics(
        control_id=control_id,
        safety_rate=safety_rate,
        total_traces=100,
        blocked_traces=int((1 - safety_rate) * 100),
        passed_traces=int(safety_rate * 100),
        window_hours=24.0,
        last_event_utc=datetime.now(tz=timezone.utc).isoformat(),
        evidence_age_seconds=evidence_age,
        startup_grace_active=grace,
        startup_grace_remaining_hours=5.0 if grace else 0.0,
    )


# ---------------------------------------------------------------------------
# 2.1 — Multi-framework control registry
# ---------------------------------------------------------------------------

class TestMultiFrameworkRegistry:
    def test_framework_controls_is_populated(self):
        from src.compliance_bridge.types import FRAMEWORK_CONTROLS
        assert isinstance(FRAMEWORK_CONTROLS, dict)
        assert len(FRAMEWORK_CONTROLS) > 0

    def test_eu_ai_act_controls_present(self):
        from src.compliance_bridge.types import FRAMEWORK_CONTROLS
        assert "eu_ai_act" in FRAMEWORK_CONTROLS
        # EU_ECB jurisdictional controls: Article 12, Article 13 (2 entries after
        # jurisdictional separation refactor — previously mixed with universal controls)
        assert len(FRAMEWORK_CONTROLS["eu_ai_act"]) >= 2

    def test_fedramp_controls_present(self):
        from src.compliance_bridge.types import FRAMEWORK_CONTROLS
        assert "fedramp" in FRAMEWORK_CONTROLS
        assert len(FRAMEWORK_CONTROLS["fedramp"]) >= 4

    def test_nist_ai_rmf_controls_present(self):
        from src.compliance_bridge.types import FRAMEWORK_CONTROLS
        assert "nist_ai_rmf" in FRAMEWORK_CONTROLS

    def test_framework_controls_only_reference_supported_controls(self):
        from src.compliance_bridge.types import FRAMEWORK_CONTROLS, SUPPORTED_CONTROLS
        for fw, cids in FRAMEWORK_CONTROLS.items():
            for cid in cids:
                assert cid in SUPPORTED_CONTROLS, (
                    f"FRAMEWORK_CONTROLS[{fw!r}] contains {cid!r} "
                    f"which is not in SUPPORTED_CONTROLS"
                )

    def test_supported_frameworks_sorted(self):
        from src.compliance_bridge.types import SUPPORTED_FRAMEWORKS
        assert SUPPORTED_FRAMEWORKS == sorted(SUPPORTED_FRAMEWORKS)

    def test_control_meta_has_frameworks_field(self):
        from src.compliance_bridge.types import CONTROL_META
        for cid, meta in CONTROL_META.items():
            assert "frameworks" in meta, f"{cid} missing 'frameworks' key in CONTROL_META"
            assert isinstance(meta["frameworks"], dict)

    def test_evidence_sla_seconds_defined(self):
        from src.compliance_bridge.types import EVIDENCE_SLA_SECONDS, SUPPORTED_CONTROLS
        assert isinstance(EVIDENCE_SLA_SECONDS, dict)
        # Critical controls must have an SLA
        from src.compliance_bridge.types import CRITICAL_CONTROLS
        for cid in CRITICAL_CONTROLS:
            assert cid in EVIDENCE_SLA_SECONDS, (
                f"Critical control {cid!r} must have an EVIDENCE_SLA_SECONDS entry"
            )

    # GET /v1/controls?framework= endpoint tests

    def test_unfiltered_controls_have_frameworks_field(self, client):
        data = client.get("/v1/controls").json()
        for c in data["controls"]:
            assert "frameworks" in c
            assert isinstance(c["frameworks"], dict)

    def test_unfiltered_returns_framework_filter_null(self, client):
        data = client.get("/v1/controls").json()
        assert data["framework_filter"] is None

    def test_eu_ai_act_filter_returns_subset(self, client):
        # eu_ai_act is an EU_ECB-only framework; the endpoint must be called
        # with CAGE_DEPLOYMENT_REGION=EU_ECB to expose those controls.
        with patch.dict(os.environ, {"CAGE_DEPLOYMENT_REGION": "EU_ECB"}):
            all_data = client.get("/v1/controls").json()
            eu_data  = client.get("/v1/controls?framework=eu_ai_act").json()
        assert eu_data["total"] < all_data["total"]
        assert eu_data["framework_filter"] == "eu_ai_act"
        # Every returned control must have eu_ai_act in its frameworks
        for c in eu_data["controls"]:
            assert "eu_ai_act" in c["frameworks"], (
                f"{c['control_id']} returned for eu_ai_act filter "
                f"but has no eu_ai_act framework reference"
            )

    def test_fedramp_filter_returns_subset(self, client):
        # fedramp is a US_FED-only framework; set the region accordingly.
        with patch.dict(os.environ, {"CAGE_DEPLOYMENT_REGION": "US_FED"}):
            data = client.get("/v1/controls?framework=fedramp").json()
        assert data["total"] >= 1
        for c in data["controls"]:
            assert "fedramp" in c["frameworks"]

    def test_unknown_framework_returns_400(self, client):
        resp = client.get("/v1/controls?framework=made_up_framework")
        assert resp.status_code == 400
        assert resp.json()["detail"]["error"] == "UNSUPPORTED_FRAMEWORK"


# ---------------------------------------------------------------------------
# 2.2 — SSE REMEDIATION_GENERATED event type
# ---------------------------------------------------------------------------

class TestRemediationGeneratedEventType:
    def test_remediation_generated_in_governance_event_type(self):
        from src.compliance_bridge.sse_events import GovernanceEventType
        import typing
        args = typing.get_args(GovernanceEventType)
        assert "REMEDIATION_GENERATED" in args

    def test_all_three_event_types_present(self):
        from src.compliance_bridge.sse_events import GovernanceEventType
        import typing
        args = set(typing.get_args(GovernanceEventType))
        # Original contract — these three MUST always be present.
        # CAGE v0.1.0 added AARM primitives (CONTEXT_CHAIN_SEALED, etc.)
        # which are validated separately; use subset check to avoid
        # breaking when new event types are added.
        required = {"AUDIT_FINDING", "GOVERNANCE_VIOLATION", "REMEDIATION_GENERATED"}
        assert required.issubset(args), (
            f"Missing required event types: {required - args}"
        )

    @pytest.mark.asyncio
    async def test_remediation_generated_published_to_event_bus(self):
        """When Step 5 succeeds, REMEDIATION_GENERATED must reach the event bus."""
        from src.compliance_bridge.sse_events import GovernanceEventBus
        bus = GovernanceEventBus()
        published: list[dict] = []

        async def _collect():
            async for event in bus.subscribe():
                published.append(event)
                break  # only need one

        task = asyncio.create_task(_collect())
        await asyncio.sleep(0)  # allow subscriber to register

        await bus.publish({
            "type":      "REMEDIATION_GENERATED",
            "traceId":   None,
            "controlId": "A.9.2",
            "result":    None,
            "safetyRate": None,
            "auditId":   "test-audit-001",
            "modelName": "qwen-test",
            "textLength": 256,
            "traceCount": 3,
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        })

        await asyncio.sleep(0.05)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

        assert len(published) == 1
        assert published[0]["type"] == "REMEDIATION_GENERATED"
        assert published[0]["controlId"] == "A.9.2"
        assert published[0]["modelName"] == "qwen-test"


# ---------------------------------------------------------------------------
# 2.5 — Evidence SLA monitor
# ---------------------------------------------------------------------------

class TestSlaMonitor:
    @pytest.mark.asyncio
    async def test_no_breach_when_within_sla(self):
        from src.compliance_bridge.sla_monitor import _check_sla_once
        from src.compliance_bridge.types import EVIDENCE_SLA_SECONDS

        # All controls return evidence_age well within SLA
        async def _mock_metrics(control_id, window_hours=24):
            return _make_metrics(control_id, safety_rate=1.0, evidence_age=60.0)

        with patch("src.compliance_bridge.sla_monitor.get_compliance_metrics",
                   new=AsyncMock(side_effect=_mock_metrics)):
            breached = await _check_sla_once()

        assert breached == []

    @pytest.mark.asyncio
    async def test_breach_detected_when_evidence_stale(self):
        from src.compliance_bridge.sla_monitor import _check_sla_once
        from src.compliance_bridge.types import EVIDENCE_SLA_SECONDS

        # A.9.2 SLA is 3600s — simulate 7200s age (2x SLA)
        async def _mock_metrics(control_id, window_hours=24):
            if control_id == "A.9.2":
                return _make_metrics(control_id, evidence_age=7_200.0)
            return _make_metrics(control_id, evidence_age=60.0)

        with patch("src.compliance_bridge.sla_monitor.get_compliance_metrics",
                   new=AsyncMock(side_effect=_mock_metrics)):
            breached = await _check_sla_once()

        assert "A.9.2" in breached

    @pytest.mark.asyncio
    async def test_no_breach_during_grace_period(self):
        """Startup grace must suppress SLA alerts even when evidence is stale."""
        from src.compliance_bridge.sla_monitor import _check_sla_once

        async def _mock_metrics(control_id, window_hours=24):
            return _make_metrics(control_id, evidence_age=99_999.0, grace=True)

        with patch("src.compliance_bridge.sla_monitor.get_compliance_metrics",
                   new=AsyncMock(side_effect=_mock_metrics)):
            breached = await _check_sla_once()

        assert breached == []

    @pytest.mark.asyncio
    async def test_sla_monitor_disabled_by_env(self):
        """EVIDENCE_SLA_DISABLED=1 must exit immediately without polling."""
        from src.compliance_bridge.sla_monitor import run_sla_monitor

        fetch_called = False

        async def _mock_fetch(control_id, window_hours=24):
            nonlocal fetch_called
            fetch_called = True
            return _make_metrics(control_id)

        with patch.dict(os.environ, {"EVIDENCE_SLA_DISABLED": "1"}):
            with patch("src.compliance_bridge.sla_monitor.get_compliance_metrics",
                       new=AsyncMock(side_effect=_mock_fetch)):
                await run_sla_monitor()

        assert not fetch_called, "Monitor should not fetch metrics when disabled"

    @pytest.mark.asyncio
    async def test_sla_alert_fires_notifier(self):
        """When a breach is detected, send_critical_alert must be called."""
        from src.compliance_bridge.sla_monitor import _fire_sla_alerts

        mock_notifier = MagicMock()
        mock_notifier.send_critical_alert = AsyncMock()

        async def _mock_metrics(control_id, window_hours=24):
            return _make_metrics("A.9.2", evidence_age=7_200.0)

        with patch("src.compliance_bridge.sla_monitor.get_compliance_metrics",
                   new=AsyncMock(side_effect=_mock_metrics)):
            with patch("src.compliance_bridge.sla_monitor.create_notifier",
                       return_value=mock_notifier):
                await _fire_sla_alerts(["A.9.2"])

        mock_notifier.send_critical_alert.assert_called_once()
        findings, audit_id = mock_notifier.send_critical_alert.call_args[0]
        assert len(findings) == 1
        assert findings[0].control_id == "A.9.2"
        assert findings[0].result == "FAIL"
        assert "SLA breach" in (findings[0].remarks or "")


# ---------------------------------------------------------------------------
# 2.6 — GET /v1/metrics/summary
# ---------------------------------------------------------------------------

class TestMetricsSummaryEndpoint:
    def _mock_metrics_factory(self, failing_controls: list[str] = None):
        """Return an AsyncMock side_effect that marks some controls as failing."""
        failing_controls = failing_controls or []

        async def _side_effect(control_id, window_hours=24):
            sr = 0.85 if control_id in failing_controls else 1.0
            return _make_metrics(control_id, safety_rate=sr, grace=False)

        return _side_effect

    def test_summary_returns_200(self, client):
        with patch("src.compliance_bridge.main.get_compliance_metrics",
                   new=AsyncMock(side_effect=self._mock_metrics_factory())):
            resp = client.get("/v1/metrics/summary")
        assert resp.status_code == 200

    def test_summary_has_required_fields(self, client):
        with patch("src.compliance_bridge.main.get_compliance_metrics",
                   new=AsyncMock(side_effect=self._mock_metrics_factory())):
            data = client.get("/v1/metrics/summary").json()
        required = {
            "overall_pass_rate", "total_controls", "passing_controls",
            "failing_controls", "critical_fails", "window_hours", "controls",
        }
        assert required.issubset(data.keys())

    def test_summary_all_pass(self, client):
        with patch("src.compliance_bridge.main.get_compliance_metrics",
                   new=AsyncMock(side_effect=self._mock_metrics_factory())):
            data = client.get("/v1/metrics/summary").json()
        assert data["overall_pass_rate"] == 1.0
        assert data["failing_controls"] == []
        assert data["critical_fails"] == []
        assert data["passing_controls"] == data["total_controls"]

    def test_summary_with_failing_controls(self, client):
        from src.compliance_bridge.types import SUPPORTED_CONTROLS
        with patch("src.compliance_bridge.main.get_compliance_metrics",
                   new=AsyncMock(side_effect=self._mock_metrics_factory(["A.9.2"]))):
            data = client.get("/v1/metrics/summary").json()
        assert "A.9.2" in data["failing_controls"]
        assert "A.9.2" in data["critical_fails"]
        assert data["passing_controls"] == data["total_controls"] - 1
        assert data["overall_pass_rate"] < 1.0

    def test_summary_controls_dict_has_all_supported(self, client):
        # The summary endpoint returns region-filtered controls via get_control_meta(region).
        # With CAGE_DEPLOYMENT_REGION unset (empty string), only universal ISO 42001
        # controls are returned — jurisdictional controls (SA-11, SC-7, etc.) are
        # correctly excluded.  Use get_control_meta("") to match the endpoint's behaviour.
        from src.compliance_bridge.types import get_control_meta
        expected_controls = list(get_control_meta("").keys())
        with patch("src.compliance_bridge.main.get_compliance_metrics",
                   new=AsyncMock(side_effect=self._mock_metrics_factory())):
            data = client.get("/v1/metrics/summary").json()
        for cid in expected_controls:
            assert cid in data["controls"], f"{cid} missing from summary controls"

    def test_summary_respects_window_hours(self, client):
        call_args: list = []

        async def _track(control_id, window_hours=24):
            call_args.append(window_hours)
            return _make_metrics(control_id)

        with patch("src.compliance_bridge.main.get_compliance_metrics",
                   new=AsyncMock(side_effect=_track)):
            client.get("/v1/metrics/summary?window_hours=48")

        assert all(wh == 48 for wh in call_args), (
            f"Not all metrics calls used window_hours=48: {call_args}"
        )

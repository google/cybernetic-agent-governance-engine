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
tests/test_compliance_bridge_tier2b.py

Tier-2 roadmap tests (part B):
  2.3 — OSCAL Assessment Results exporter (oscal_exporter.py + GET /v1/oscal/assessment-results)
  2.4 — PagerDuty notifier + WebhookNotifier + factory routing
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import respx
import httpx

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(control_id: str, result: str = "PASS", safety_rate: float = 1.0,
                  evidence_age: float = 0.0) -> "OscalFinding":
    from src.compliance_bridge.types import OscalFinding
    return OscalFinding(
        control_id=control_id,
        result=result,  # type: ignore[arg-type]
        finding_id=f"finding-{control_id}",
        safety_rate=safety_rate,
        evidence_age_s=evidence_age,
        remarks=None,
    )


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


# ---------------------------------------------------------------------------
# 2.3 — OSCAL Assessment Results exporter (unit tests for oscal_exporter.py)
# ---------------------------------------------------------------------------

class TestOscalExporterUnit:
    def test_build_returns_assessment_results_root(self):
        from src.compliance_bridge.oscal_exporter import build_oscal_assessment_results
        doc = build_oscal_assessment_results(
            findings=[_make_finding("A.5.2", "PASS"), _make_finding("A.9.2", "FAIL", 0.85)],
            audit_id="unit-test-001",
        )
        assert "assessment-results" in doc

    def test_metadata_present(self):
        from src.compliance_bridge.oscal_exporter import build_oscal_assessment_results
        ar = build_oscal_assessment_results(
            findings=[_make_finding("A.5.2")],
            audit_id="meta-test",
        )["assessment-results"]
        meta = ar["metadata"]
        assert "title" in meta
        assert meta["oscal-version"] == "1.1.2"
        assert len(meta["parties"]) == 1

    def test_finding_state_satisfied(self):
        from src.compliance_bridge.oscal_exporter import build_oscal_assessment_results
        findings = build_oscal_assessment_results(
            findings=[_make_finding("A.5.2", "PASS")],
            audit_id="state-test",
        )["assessment-results"]["results"][0]["findings"]
        assert findings[0]["target"]["status"]["state"] == "satisfied"

    def test_finding_state_not_satisfied(self):
        from src.compliance_bridge.oscal_exporter import build_oscal_assessment_results
        findings = build_oscal_assessment_results(
            findings=[_make_finding("A.9.2", "FAIL", 0.8)],
            audit_id="state-test-fail",
        )["assessment-results"]["results"][0]["findings"]
        assert findings[0]["target"]["status"]["state"] == "not-satisfied"

    def test_finding_state_not_applicable(self):
        from src.compliance_bridge.oscal_exporter import build_oscal_assessment_results
        findings = build_oscal_assessment_results(
            findings=[_make_finding("SC-7", "NOT_APPLICABLE")],
            audit_id="na-test",
        )["assessment-results"]["results"][0]["findings"]
        assert findings[0]["target"]["status"]["state"] == "not-applicable"

    def test_safety_rate_prop_present(self):
        from src.compliance_bridge.oscal_exporter import build_oscal_assessment_results
        findings = build_oscal_assessment_results(
            findings=[_make_finding("A.5.2", safety_rate=0.997)],
            audit_id="prop-test",
        )["assessment-results"]["results"][0]["findings"]
        props = {p["name"]: p["value"] for p in findings[0]["props"]}
        assert "safety_rate" in props
        assert float(props["safety_rate"]) == pytest.approx(0.997)

    def test_evidence_age_prop_present(self):
        from src.compliance_bridge.oscal_exporter import build_oscal_assessment_results
        findings = build_oscal_assessment_results(
            findings=[_make_finding("A.5.2", evidence_age=3600.0)],
            audit_id="age-test",
        )["assessment-results"]["results"][0]["findings"]
        props = {p["name"]: p["value"] for p in findings[0]["props"]}
        assert "evidence_age_seconds" in props
        assert int(props["evidence_age_seconds"]) == 3600

    def test_framework_props_embedded(self):
        from src.compliance_bridge.oscal_exporter import build_oscal_assessment_results
        # A.5.2 maps to iso42001, eu_ai_act, nist_ai_rmf
        findings = build_oscal_assessment_results(
            findings=[_make_finding("A.5.2")],
            audit_id="fw-test",
        )["assessment-results"]["results"][0]["findings"]
        fw_props = [p for p in findings[0]["props"] if p["name"] == "framework"]
        fw_values = {p["value"] for p in fw_props}
        assert "iso42001" in fw_values
        assert "eu_ai_act" in fw_values

    def test_reviewed_controls_contains_all_finding_controls(self):
        from src.compliance_bridge.oscal_exporter import build_oscal_assessment_results
        fs = [_make_finding("A.5.2"), _make_finding("SC-4")]
        doc = build_oscal_assessment_results(findings=fs, audit_id="ctrl-test")
        selections = doc["assessment-results"]["results"][0]["reviewed-controls"]["control-selections"]
        included = {c["control-id"] for cs in selections for c in cs["include-controls"]}
        assert "A.5.2" in included
        assert "SC-4" in included

    def test_uuid_is_deterministic_for_same_audit_id(self):
        from src.compliance_bridge.oscal_exporter import build_oscal_assessment_results
        doc1 = build_oscal_assessment_results(
            findings=[_make_finding("A.5.2")], audit_id="det-test"
        )
        doc2 = build_oscal_assessment_results(
            findings=[_make_finding("A.5.2")], audit_id="det-test"
        )
        assert doc1["assessment-results"]["uuid"] == doc2["assessment-results"]["uuid"]

    def test_findings_from_metrics_dict(self):
        """
        Fetch errors must produce ERROR findings — NOT be silently skipped.

        Rationale (NIST SP 800-53A §3.2 / FedRAMP assessment guide):
          A data-collection failure ("fetch failed") is not the same as
          NOT_APPLICABLE.  Silently dropping the finding hides a potential
          security blind spot from auditors.  The correct behaviour is to
          emit an ERROR finding so the gap is visible in the OSCAL document
          and can be investigated by a human reviewer.
        """
        from src.compliance_bridge.oscal_exporter import findings_from_metrics_dict
        data = {
            "A.5.2": {"safety_rate": 1.0, "evidence_age_seconds": 60.0},
            "A.9.2": {"safety_rate": 0.85, "evidence_age_seconds": 3600.0},
            "SC-4":  {"error": "fetch failed"},   # must emit ERROR, not be skipped
        }
        findings = findings_from_metrics_dict(data, "dict-test")
        # All three controls must produce a finding entry
        assert len(findings) == 3
        cids = {f.control_id for f in findings}
        assert "A.5.2" in cids
        assert "A.9.2" in cids
        assert "SC-4" in cids, (
            "SC-4 fetch error must produce an ERROR finding — "
            "silently skipping it masks a security blind spot (NIST SP 800-53A §3.2)"
        )
        a52 = next(f for f in findings if f.control_id == "A.5.2")
        assert a52.result == "PASS"
        a92 = next(f for f in findings if f.control_id == "A.9.2")
        assert a92.result == "FAIL"
        sc4 = next(f for f in findings if f.control_id == "SC-4")
        assert sc4.result == "ERROR", (
            f"Expected ERROR for fetch-failed SC-4, got {sc4.result!r}"
        )
        assert sc4.safety_rate is None
        assert sc4.evidence_age_s is None
        assert "fetch failed" in (sc4.remarks or "")


# ---------------------------------------------------------------------------
# 2.3 — GET /v1/oscal/assessment-results endpoint
# ---------------------------------------------------------------------------

class TestOscalExporterEndpoint:
    def _mock_metrics_side_effect(self, control_id, window_hours=24):
        return _make_metrics(control_id, safety_rate=1.0)

    def test_endpoint_returns_200(self, client):
        with patch("src.compliance_bridge.main.get_compliance_metrics",
                   new=AsyncMock(side_effect=self._mock_metrics_side_effect)):
            resp = client.get("/v1/oscal/assessment-results")
        assert resp.status_code == 200

    def test_response_has_document_and_audit_id(self, client):
        with patch("src.compliance_bridge.main.get_compliance_metrics",
                   new=AsyncMock(side_effect=self._mock_metrics_side_effect)):
            data = client.get("/v1/oscal/assessment-results").json()
        assert "document" in data
        assert "audit_id" in data

    def test_document_is_oscal_shaped(self, client):
        with patch("src.compliance_bridge.main.get_compliance_metrics",
                   new=AsyncMock(side_effect=self._mock_metrics_side_effect)):
            data = client.get("/v1/oscal/assessment-results").json()
        assert "assessment-results" in data["document"]

    def test_custom_audit_id_echoed(self, client):
        with patch("src.compliance_bridge.main.get_compliance_metrics",
                   new=AsyncMock(side_effect=self._mock_metrics_side_effect)):
            data = client.get("/v1/oscal/assessment-results?audit_id=my-audit-123").json()
        assert data["audit_id"] == "my-audit-123"

    def test_invalid_format_returns_422(self, client):
        resp = client.get("/v1/oscal/assessment-results?format=xml")
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 2.4 — PagerDutyNotifier
# ---------------------------------------------------------------------------

class TestPagerDutyNotifier:
    @pytest.mark.asyncio
    @respx.mock
    async def test_triggers_incident_for_each_critical_fail(self):
        from src.compliance_bridge.notifier import PagerDutyNotifier

        pd_route = respx.post("https://events.pagerduty.com/v2/enqueue").mock(
            return_value=httpx.Response(202, json={"status": "success", "dedup_key": "k"})
        )
        notifier = PagerDutyNotifier("test-routing-key")
        findings = [
            _make_finding("A.9.2", "FAIL", 0.7),
            _make_finding("SC-4", "FAIL", 0.8),
        ]
        await notifier.send_critical_alert(findings, "pd-test-001")
        # One request per failing finding
        assert pd_route.call_count == 2

    @pytest.mark.asyncio
    @respx.mock
    async def test_critical_alert_uses_critical_severity(self):
        from src.compliance_bridge.notifier import PagerDutyNotifier

        calls: list[dict] = []

        def _capture(request: httpx.Request, **kwargs):
            calls.append(request.content)
            return httpx.Response(202, json={"status": "success"})

        respx.post("https://events.pagerduty.com/v2/enqueue").mock(side_effect=_capture)
        notifier = PagerDutyNotifier("test-key")
        await notifier.send_critical_alert([_make_finding("A.9.2", "FAIL")], "sev-test")

        import json
        body = json.loads(calls[0])
        assert body["payload"]["severity"] == "critical"
        assert body["event_action"] == "trigger"

    @pytest.mark.asyncio
    @respx.mock
    async def test_remediation_followup_uses_info_severity(self):
        from src.compliance_bridge.notifier import PagerDutyNotifier

        calls: list[dict] = []

        def _capture(request: httpx.Request, **kwargs):
            calls.append(request.content)
            return httpx.Response(202, json={"status": "success"})

        respx.post("https://events.pagerduty.com/v2/enqueue").mock(side_effect=_capture)
        notifier = PagerDutyNotifier("test-key")
        await notifier.send_remediation_followup(
            "A.9.2", "audit-001", "qwen-test", "Increase data retention", []
        )

        import json
        body = json.loads(calls[0])
        assert body["payload"]["severity"] == "info"

    @pytest.mark.asyncio
    @respx.mock
    async def test_dedup_key_includes_audit_id_and_control(self):
        from src.compliance_bridge.notifier import PagerDutyNotifier

        calls: list[dict] = []

        def _capture(request: httpx.Request, **kwargs):
            calls.append(request.content)
            return httpx.Response(202, json={"status": "success"})

        respx.post("https://events.pagerduty.com/v2/enqueue").mock(side_effect=_capture)
        notifier = PagerDutyNotifier("test-key")
        await notifier.send_critical_alert([_make_finding("A.9.2", "FAIL")], "audit-xyz")

        import json
        body = json.loads(calls[0])
        assert body["dedup_key"] == "cage-audit-xyz-A.9.2"

    @pytest.mark.asyncio
    @respx.mock
    async def test_remediation_text_truncated_to_512(self):
        from src.compliance_bridge.notifier import PagerDutyNotifier

        calls: list[dict] = []

        def _capture(request: httpx.Request, **kwargs):
            calls.append(request.content)
            return httpx.Response(202, json={"status": "success"})

        respx.post("https://events.pagerduty.com/v2/enqueue").mock(side_effect=_capture)
        notifier = PagerDutyNotifier("test-key")
        long_text = "x" * 1000
        await notifier.send_remediation_followup("A.9.2", "a", "m", long_text, [])

        import json
        body = json.loads(calls[0])
        assert len(body["payload"]["custom_details"]["remediation_text"]) == 512


# ---------------------------------------------------------------------------
# 2.4 — WebhookNotifier
# ---------------------------------------------------------------------------

class TestWebhookNotifier:
    @pytest.mark.asyncio
    @respx.mock
    async def test_sends_critical_failure_payload(self):
        from src.compliance_bridge.notifier import WebhookNotifier

        calls: list[dict] = []

        def _capture(request: httpx.Request, **kwargs):
            import json
            calls.append(json.loads(request.content))
            return httpx.Response(200)

        respx.post("https://webhook.example.com/hook").mock(side_effect=_capture)
        notifier = WebhookNotifier("https://webhook.example.com/hook")
        await notifier.send_critical_alert([_make_finding("SC-4", "FAIL")], "wh-test")

        assert len(calls) == 1
        assert calls[0]["alert_type"] == "critical_failure"
        assert calls[0]["source"] == "compliance-bridge"
        assert len(calls[0]["findings"]) == 1
        assert calls[0]["findings"][0]["control_id"] == "SC-4"

    @pytest.mark.asyncio
    @respx.mock
    async def test_sends_remediation_payload(self):
        from src.compliance_bridge.notifier import WebhookNotifier

        calls: list[dict] = []

        def _capture(request: httpx.Request, **kwargs):
            import json
            calls.append(json.loads(request.content))
            return httpx.Response(200)

        respx.post("https://webhook.example.com/hook").mock(side_effect=_capture)
        notifier = WebhookNotifier("https://webhook.example.com/hook")
        await notifier.send_remediation_followup(
            "A.9.2", "audit-002", "qwen", "Do X, Y, Z", ["t1", "t2"]
        )

        assert calls[0]["alert_type"] == "remediation"
        assert calls[0]["control_id"] == "A.9.2"
        assert calls[0]["trace_ids"] == ["t1", "t2"]


# ---------------------------------------------------------------------------
# 2.4 — create_notifier factory routing
# ---------------------------------------------------------------------------

class TestNotifierFactory:
    def test_default_is_console(self):
        from src.compliance_bridge.notifier import create_notifier, ConsoleNotifier
        with patch.dict(os.environ, {}, clear=False):
            if "ALERT_CHANNEL" in os.environ:
                del os.environ["ALERT_CHANNEL"]
            n = create_notifier()
        assert isinstance(n, ConsoleNotifier)

    def test_pagerduty_with_key_returns_pagerduty(self):
        from src.compliance_bridge.notifier import create_notifier, PagerDutyNotifier
        with patch.dict(os.environ, {"ALERT_CHANNEL": "pagerduty", "PAGERDUTY_ROUTING_KEY": "abc123"}):
            n = create_notifier()
        assert isinstance(n, PagerDutyNotifier)

    def test_pagerduty_without_key_falls_back_to_console(self):
        from src.compliance_bridge.notifier import create_notifier, ConsoleNotifier
        env = {"ALERT_CHANNEL": "pagerduty"}
        # Ensure routing key is absent
        with patch.dict(os.environ, env):
            os.environ.pop("PAGERDUTY_ROUTING_KEY", None)
            n = create_notifier()
        assert isinstance(n, ConsoleNotifier)

    def test_webhook_with_url_returns_webhook(self):
        from src.compliance_bridge.notifier import create_notifier, WebhookNotifier
        with patch.dict(os.environ, {
            "ALERT_CHANNEL": "webhook",
            "COMPLIANCE_ALERT_WEBHOOK_URL": "https://example.com/hook",
        }):
            n = create_notifier()
        assert isinstance(n, WebhookNotifier)

    def test_slack_with_url_returns_slack(self):
        from src.compliance_bridge.notifier import create_notifier, SlackNotifier
        with patch.dict(os.environ, {
            "ALERT_CHANNEL": "slack",
            "COMPLIANCE_ALERT_WEBHOOK_URL": "https://hooks.slack.com/xxx",
        }):
            n = create_notifier()
        assert isinstance(n, SlackNotifier)

    def test_mock_requires_testing_env(self):
        from src.compliance_bridge.notifier import create_notifier
        with patch.dict(os.environ, {"ALERT_CHANNEL": "mock", "TESTING": "1"}):
            from src.compliance_bridge.notifier import MockNotifier
            n = create_notifier()
        assert isinstance(n, MockNotifier)

    def test_mock_without_testing_raises(self):
        from src.compliance_bridge.notifier import create_notifier
        env = {"ALERT_CHANNEL": "mock"}
        with patch.dict(os.environ, env):
            os.environ.pop("TESTING", None)
            with pytest.raises(ValueError, match="MockNotifier is not permitted"):
                create_notifier()

    def test_mock_notifier_alert_count(self):
        from src.compliance_bridge.notifier import MockNotifier
        import asyncio
        n = MockNotifier()
        asyncio.get_event_loop().run_until_complete(
            n.send_critical_alert([_make_finding("A.9.2", "FAIL")], "count-test")
        )
        assert n.alert_count == 1

    def test_unknown_channel_falls_back_to_console(self):
        from src.compliance_bridge.notifier import create_notifier, ConsoleNotifier
        with patch.dict(os.environ, {"ALERT_CHANNEL": "telegram"}):
            n = create_notifier()
        assert isinstance(n, ConsoleNotifier)

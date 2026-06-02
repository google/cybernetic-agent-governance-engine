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
tests/test_compliance_bridge.py

Pytest tests for the Python compliance bridge (src/compliance_bridge/).

Covers:
  - OSCAL YAML parsing (valid + invalid inputs)
  - Pydantic model construction (OscalFinding, ComplianceMetrics)
  - FastAPI endpoint behaviour (/health, /v1/metrics/*)
  - Langfuse SDK calls are mocked throughout
"""

from __future__ import annotations

import sys
import os

# Ensure src/ is on the path so `compliance_bridge` is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

pytestmark = pytest.mark.unit

from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# ── types ──
# ---------------------------------------------------------------------------

class TestOscalFindingModel:
    """OscalFinding Pydantic model instantiation and validation."""

    def test_oscal_finding_valid(self):
        from src.compliance_bridge.types import OscalFinding

        f = OscalFinding(
            control_id="A.5.2",
            result="PASS",
            finding_id="uuid-abc-123",
            remarks="All good",
            safety_rate=0.995,
            evidence_age_s=3600.0,
        )
        assert f.control_id == "A.5.2"
        assert f.result == "PASS"
        assert f.safety_rate == 0.995

    def test_oscal_finding_invalid_result(self):
        from src.compliance_bridge.types import OscalFinding
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            OscalFinding(
                control_id="A.5.2",
                result="INVALID_STATUS",  # not in Literal
                finding_id="uuid-abc",
            )

    def test_oscal_finding_safety_rate_bounds(self):
        from src.compliance_bridge.types import OscalFinding
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            OscalFinding(
                control_id="A.5.2",
                result="PASS",
                finding_id="uuid-abc",
                safety_rate=1.5,  # > 1.0
            )

    def test_oscal_finding_optional_fields(self):
        from src.compliance_bridge.types import OscalFinding

        f = OscalFinding(
            control_id="SC-4",
            result="FAIL",
            finding_id="uuid-sc4",
        )
        assert f.remarks is None
        assert f.safety_rate is None
        assert f.evidence_age_s is None


class TestComplianceMetricsModel:
    """ComplianceMetrics Pydantic model instantiation and validation."""

    def test_compliance_metrics_valid(self):
        from src.compliance_bridge.types import ComplianceMetrics

        m = ComplianceMetrics(
            control_id="A.5.3",
            safety_rate=0.99,
            total_traces=150,
            blocked_traces=1,
            passed_traces=149,
            window_hours=24.0,
            last_event_utc="2026-03-03T00:00:00+00:00",
            evidence_age_seconds=1800.0,
            startup_grace_active=False,
            startup_grace_remaining_hours=0.0,
        )
        assert m.control_id == "A.5.3"
        assert m.safety_rate == 0.99
        assert m.total_traces == 150

    def test_compliance_metrics_safety_rate_bounds(self):
        from src.compliance_bridge.types import ComplianceMetrics
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            ComplianceMetrics(
                control_id="A.5.3",
                safety_rate=1.1,  # > 1.0
                total_traces=10,
                blocked_traces=0,
                passed_traces=10,
                window_hours=24.0,
                last_event_utc="2026-03-03T00:00:00+00:00",
                evidence_age_seconds=0.0,
                startup_grace_active=False,
                startup_grace_remaining_hours=0.0,
            )


# ---------------------------------------------------------------------------
# ── OSCAL parser ──
# ---------------------------------------------------------------------------

# Minimal valid OSCAL YAML that matches `lula validate` output
VALID_OSCAL_YAML = """
assessment-results:
  uuid: "test-uuid-001"
  metadata:
    last-modified: "2026-03-01T00:00:00Z"
  results:
    - uuid: "result-uuid-001"
      findings:
        - uuid: "finding-uuid-001"
          title: "A.5.2 validation"
          remarks: "NeMo output rails are active"
          target:
            type: objective-id
            target-id: "A.5.2"
            status:
              state: "satisfied"
          props:
            - name: safety_rate
              value: "0.995"
            - name: evidence_age_seconds
              value: "3600"
        - uuid: "finding-uuid-002"
          title: "A.9.2 validation"
          target:
            type: objective-id
            target-id: "A.9.2"
            status:
              state: "not-satisfied"
"""

INVALID_OSCAL_YAML = """
this: is
  not: valid yaml: because: of: bad: indentation:
  :::
"""

MISSING_RESULTS_YAML = """
assessment-results:
  uuid: "no-results"
  results: []
"""

NO_FINDINGS_YAML = """
assessment-results:
  uuid: "no-findings"
  results:
    - uuid: "result-001"
      findings: []
"""


class TestParseOscalYaml:
    """Tests for src/compliance_bridge/oscal_parser.parse_oscal_yaml()."""

    def test_parse_valid_yaml(self):
        from src.compliance_bridge.oscal_parser import parse_oscal_yaml

        findings = parse_oscal_yaml(VALID_OSCAL_YAML)

        assert isinstance(findings, list)
        assert len(findings) == 2

        a52 = next(f for f in findings if f.control_id == "A.5.2")
        assert a52.result == "PASS"
        assert a52.safety_rate == pytest.approx(0.995)
        assert a52.evidence_age_s == pytest.approx(3600.0)
        assert a52.finding_id == "finding-uuid-001"

        a92 = next(f for f in findings if f.control_id == "A.9.2")
        assert a92.result == "FAIL"

    def test_parse_invalid_yaml_raises(self):
        from src.compliance_bridge.oscal_parser import parse_oscal_yaml

        with pytest.raises(ValueError, match="YAML syntax error|does not match|zero valid"):
            parse_oscal_yaml(INVALID_OSCAL_YAML)

    def test_parse_missing_results_raises(self):
        from src.compliance_bridge.oscal_parser import parse_oscal_yaml

        with pytest.raises(ValueError, match="no result entries"):
            parse_oscal_yaml(MISSING_RESULTS_YAML)

    def test_parse_no_findings_raises(self):
        from src.compliance_bridge.oscal_parser import parse_oscal_yaml

        with pytest.raises(ValueError, match="zero valid findings"):
            parse_oscal_yaml(NO_FINDINGS_YAML)

    def test_state_mapping_not_satisfied(self):
        from src.compliance_bridge.oscal_parser import parse_oscal_yaml

        yaml_str = """
assessment-results:
  uuid: "t"
  results:
    - uuid: "r"
      findings:
        - uuid: "f1"
          target:
            target-id: "SC-4"
            status:
              state: "not-satisfied"
"""
        findings = parse_oscal_yaml(yaml_str)
        assert findings[0].result == "FAIL"

    def test_state_mapping_satisfied(self):
        from src.compliance_bridge.oscal_parser import parse_oscal_yaml

        yaml_str = """
assessment-results:
  uuid: "t"
  results:
    - uuid: "r"
      findings:
        - uuid: "f1"
          target:
            target-id: "A.5.3"
            status:
              state: "satisfied"
"""
        findings = parse_oscal_yaml(yaml_str)
        assert findings[0].result == "PASS"


# ---------------------------------------------------------------------------
# ── FastAPI endpoints ──
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    """
    TestClient for the FastAPI app.
    Langfuse is patched at import time so no real credentials are needed.
    """
    with patch("src.compliance_bridge.main.Langfuse") as MockLangfuse:
        mock_lf = MagicMock()
        MockLangfuse.return_value = mock_lf

        from src.compliance_bridge.main import app
        with TestClient(app, raise_server_exceptions=True) as c:
            yield c


class TestHealthEndpoint:
    def test_health_returns_ok(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["service"] == "compliance-bridge"
        assert data["version"] == "2.0.0"


class TestMetricsEndpoint:
    def test_unsupported_control_returns_400(self, client):
        response = client.get("/v1/metrics/UNKNOWN-CONTROL")
        assert response.status_code == 400
        data = response.json()
        # FastAPI wraps HTTPException detail
        detail = data.get("detail", data)
        if isinstance(detail, dict):
            assert detail.get("error") == "UNSUPPORTED_CONTROL"
        else:
            assert "UNSUPPORTED_CONTROL" in str(data)

    def test_supported_control_calls_get_compliance_metrics(self, client):
        from src.compliance_bridge.types import ComplianceMetrics
        from datetime import datetime, timezone

        mock_metrics = ComplianceMetrics(
            control_id="A.5.2",
            safety_rate=0.99,
            total_traces=200,
            blocked_traces=2,
            passed_traces=198,
            window_hours=24.0,
            last_event_utc=datetime.now(tz=timezone.utc).isoformat(),
            evidence_age_seconds=100.0,
            startup_grace_active=False,
            startup_grace_remaining_hours=0.0,
        )

        with patch(
            "src.compliance_bridge.main.get_compliance_metrics",
            new=AsyncMock(return_value=mock_metrics),
        ):
            response = client.get("/v1/metrics/A.5.2?window_hours=24")

        assert response.status_code == 200
        data = response.json()
        assert data["control_id"] == "A.5.2"
        assert data["safety_rate"] == pytest.approx(0.99)
        assert data["total_traces"] == 200


class TestAuditIngestEndpoint:
    def test_missing_oscal_yaml_returns_400(self, client):
        response = client.post(
            "/v1/audit/ingest",
            json={"oscal_yaml": "  ", "audit_id": "test-001"},
        )
        assert response.status_code == 400

    def test_valid_ingest_calls_workflow(self, client):
        mock_result = {
            "status":           "ok",
            "audit_id":         "test-audit-001",
            "findings_count":   2,
            "artifact_key":     None,
            "ingested":         2,
            "alerted":          False,
            "alert_targets":    [],
            "remediation_sent": False,
            "remediation_text": None,
            "advisor_error":    None,
        }

        with patch(
            "src.compliance_bridge.main.run_audit_workflow",
            new=AsyncMock(return_value=mock_result),
        ):
            response = client.post(
                "/v1/audit/ingest",
                json={"oscal_yaml": VALID_OSCAL_YAML, "audit_id": "test-audit-001"},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["findings_count"] == 2

    def test_invalid_yaml_returns_422(self, client):
        with patch(
            "src.compliance_bridge.main.run_audit_workflow",
            new=AsyncMock(side_effect=ValueError("YAML syntax error: bad yaml")),
        ):
            response = client.post(
                "/v1/audit/ingest",
                json={"oscal_yaml": "definitely: bad: yaml:", "audit_id": "x"},
            )
        assert response.status_code == 422

    def test_background_ingest_schedules_task_and_returns_running(self, client):
        mock_result = {
            "status":           "ok",
            "audit_id":         "test-audit-bg",
            "findings_count":   2,
            "artifact_key":     None,
            "ingested":         2,
            "alerted":          False,
            "alert_targets":    [],
            "remediation_sent": False,
            "remediation_text": None,
            "advisor_error":    None,
        }

        with patch(
            "src.compliance_bridge.main.run_audit_workflow",
            new=AsyncMock(return_value=mock_result),
        ):
            response = client.post(
                "/v1/audit/ingest?background=true",
                json={"oscal_yaml": VALID_OSCAL_YAML, "audit_id": "test-audit-bg"},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["phase"] == "running"
        assert data["status"] == "ok"
        assert data["audit_id"] == "test-audit-bg"


class TestTelemetryHistoryEndpoint:
    def test_get_history_success(self, client):
        class MockTraceMeta:
            page = 1
            total_pages = 2

        class MockTraceData:
            def __init__(self):
                self.id = "trace-123"
                self.name = "lula-audit"
                self.tags = ["compliance"]
                self.metadata = {
                    "iso_42001_control": "A.5.2",
                    "lula_result": "PASS",
                    "safety_rate": "1.0",
                    "audit_id": "audit-abc",
                }
                self.timestamp = "2026-05-21T18:00:00Z"

        class MockTraceListResponse:
            data = [MockTraceData()]
            meta = MockTraceMeta()

        mock_api = MagicMock()
        mock_api.trace.list.return_value = MockTraceListResponse()

        with patch("src.compliance_bridge.main._get_compliance_api", return_value=mock_api):
            response = client.get("/v1/telemetry/history?page=1&limit=20")

        assert response.status_code == 200
        data = response.json()
        assert "telemetry" in data
        assert len(data["telemetry"]) == 1
        item = data["telemetry"][0]
        assert item["traceId"] == "trace-123"
        assert item["auditId"] == "audit-abc"
        assert item["result"] == "PASS"
        assert data["hasMore"] is True


# ---------------------------------------------------------------------------

# ── types constants ──
# ---------------------------------------------------------------------------

class TestTypesConstants:
    def test_supported_controls_contains_expected(self):
        from src.compliance_bridge.types import SUPPORTED_CONTROLS

        assert "A.5.2" in SUPPORTED_CONTROLS
        assert "A.5.3" in SUPPORTED_CONTROLS
        assert "A.9.2" in SUPPORTED_CONTROLS
        assert "SC-4"  in SUPPORTED_CONTROLS

    def test_critical_controls_subset_of_supported(self):
        from src.compliance_bridge.types import CRITICAL_CONTROLS, SUPPORTED_CONTROLS

        for c in CRITICAL_CONTROLS:
            assert c in SUPPORTED_CONTROLS

    def test_iso_control_map_values_are_supported(self):
        from src.compliance_bridge.types import ISO_CONTROL_MAP, SUPPORTED_CONTROLS

        for event_name, control_id in ISO_CONTROL_MAP.items():
            assert control_id in SUPPORTED_CONTROLS, (
                f"ISO_CONTROL_MAP[{event_name!r}]={control_id!r} not in SUPPORTED_CONTROLS"
            )

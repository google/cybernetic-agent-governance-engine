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
Unit tests for src/compliance_bridge/audit_workflow.py

Covers: _ensure_uuid, _step1 (skip when no S3 endpoint), _step2 (parse OSCAL),
_step4 (critical alert), run_audit_workflow full pipeline, and AARM report
generation path. All Langfuse, OpenAI, and GCS calls are mocked.

The module has a startup credential guard that raises RuntimeError in non-dev
environments.  All tests set CAGE_ENV=ci via autouse fixture.
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytestmark = pytest.mark.local


# ---------------------------------------------------------------------------
# Set CAGE_ENV so the module-level credential guard does not block import
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _dev_env(monkeypatch):
    """Force dev environment and dummy Langfuse creds so audit_workflow imports."""
    monkeypatch.setenv("CAGE_ENV", "ci")
    monkeypatch.setenv("LANGFUSE_COMPLIANCE_PUBLIC_KEY", "pk-dummy")
    monkeypatch.setenv("LANGFUSE_COMPLIANCE_SECRET_KEY", "sk-dummy")
    monkeypatch.setenv("LANGFUSE_PUBLIC_KEY", "pk-dummy")
    monkeypatch.setenv("LANGFUSE_SECRET_KEY", "sk-dummy")
    # Clear OSCAL_S3_ENDPOINT so Step 1 is skipped by default
    monkeypatch.delenv("OSCAL_S3_ENDPOINT", raising=False)


# ---------------------------------------------------------------------------
# Minimal OSCAL YAML fixture — matches oscal_parser expectations
# ---------------------------------------------------------------------------

_MINIMAL_OSCAL_YAML = """
assessment-results:
  results:
    - findings:
        - target:
            target-id: "A.5.2"
            status:
              state: "satisfied"
          uuid: "test-finding-001"
          related-observations:
            - observation-uuid: "obs-001"
        - target:
            target-id: "A.6.1"
            status:
              state: "not-satisfied"
          uuid: "test-finding-002"
"""


# ---------------------------------------------------------------------------
# _ensure_uuid
# ---------------------------------------------------------------------------


class TestEnsureUuid:
    """Tests for the _ensure_uuid helper function."""

    def test_valid_uuid_returns_hex(self):
        """A valid UUID string is returned as its hex representation."""
        from src.compliance_bridge.audit_workflow import _ensure_uuid

        test_uuid = "12345678-1234-5678-1234-567812345678"
        result = _ensure_uuid(test_uuid)
        # hex is the UUID without hyphens
        assert result == uuid.UUID(test_uuid).hex
        assert "-" not in result
        assert len(result) == 32

    def test_non_uuid_string_deterministically_converts(self):
        """A non-UUID string is deterministically converted via uuid5."""
        from src.compliance_bridge.audit_workflow import _ensure_uuid

        result1 = _ensure_uuid("my-finding-id")
        result2 = _ensure_uuid("my-finding-id")
        assert result1 == result2
        assert len(result1) == 32
        assert "-" not in result1

    def test_different_strings_produce_different_uuids(self):
        """Different input strings produce different UUIDs (collision resistance)."""
        from src.compliance_bridge.audit_workflow import _ensure_uuid

        r1 = _ensure_uuid("finding-A")
        r2 = _ensure_uuid("finding-B")
        assert r1 != r2

    def test_empty_string_produces_valid_uuid(self):
        """Empty string input still produces a valid UUID hex."""
        from src.compliance_bridge.audit_workflow import _ensure_uuid

        result = _ensure_uuid("")
        assert len(result) == 32


# ---------------------------------------------------------------------------
# _step1 artifact persistence
# ---------------------------------------------------------------------------


class TestStep1ArtifactPersistence:
    """Tests for _step1_persist_artifact."""

    @pytest.mark.asyncio
    async def test_step1_skipped_when_no_s3_endpoint(self, monkeypatch):
        """Step 1 returns None when OSCAL_S3_ENDPOINT is not set."""
        monkeypatch.delenv("OSCAL_S3_ENDPOINT", raising=False)
        from src.compliance_bridge.audit_workflow import _step1_persist_artifact

        result = await _step1_persist_artifact("yaml-content", "audit-001")
        assert result is None

    @pytest.mark.asyncio
    async def test_step1_calls_put_when_endpoint_set(self, monkeypatch):
        """Step 1 calls put_oscal_artifact when OSCAL_S3_ENDPOINT is set."""
        monkeypatch.setenv("OSCAL_S3_ENDPOINT", "http://minio:9000")

        with patch(
            "src.compliance_bridge.audit_workflow.put_oscal_artifact",
            new_callable=AsyncMock,
            return_value="audit-001/oscal.yaml",
        ) as mock_put:
            from src.compliance_bridge.audit_workflow import _step1_persist_artifact

            result = await _step1_persist_artifact("yaml-content", "audit-001")

        assert result == "audit-001/oscal.yaml"
        mock_put.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_step1_returns_none_on_storage_failure(self, monkeypatch):
        """Step 1 returns None (non-fatal) when put_oscal_artifact raises."""
        monkeypatch.setenv("OSCAL_S3_ENDPOINT", "http://minio:9000")

        with patch(
            "src.compliance_bridge.audit_workflow.put_oscal_artifact",
            new_callable=AsyncMock,
            side_effect=RuntimeError("Storage unavailable"),
        ):
            from src.compliance_bridge.audit_workflow import _step1_persist_artifact

            result = await _step1_persist_artifact("yaml-content", "audit-001")

        assert result is None


# ---------------------------------------------------------------------------
# _step4 critical alert
# ---------------------------------------------------------------------------


class TestStep4CriticalAlert:
    """Tests for _step4_alert_on_critical_fail."""

    def _make_finding(self, control_id, result, finding_id="f-001"):
        from src.compliance_bridge.types import OscalFinding

        return OscalFinding(
            control_id=control_id,
            result=result,
            finding_id=finding_id,
            evidence_age_s=10.0,
            remarks="test finding",
        )

    @pytest.mark.asyncio
    async def test_no_alert_when_all_pass(self):
        """No alert is sent when all findings pass."""
        from src.compliance_bridge.audit_workflow import _step4_alert_on_critical_fail
        from src.compliance_bridge.types import CRITICAL_CONTROLS

        # Create passing findings for each critical control
        findings = [
            self._make_finding(cid, "PASS", f"f-{i}")
            for i, cid in enumerate(list(CRITICAL_CONTROLS)[:2])
        ]

        mock_notifier = MagicMock()
        mock_notifier.send_critical_alert = AsyncMock()

        with patch(
            "src.compliance_bridge.audit_workflow.create_notifier",
            return_value=mock_notifier,
        ):
            alerted, targets = await _step4_alert_on_critical_fail(
                findings, "audit-001"
            )

        assert alerted is False
        assert targets == []
        mock_notifier.send_critical_alert.assert_not_called()

    @pytest.mark.asyncio
    async def test_alert_sent_on_critical_fail(self):
        """Alert is sent when a CRITICAL_CONTROLS finding has result=FAIL."""
        from src.compliance_bridge.audit_workflow import _step4_alert_on_critical_fail
        from src.compliance_bridge.types import CRITICAL_CONTROLS

        critical_control = next(iter(CRITICAL_CONTROLS))
        findings = [self._make_finding(critical_control, "FAIL")]

        mock_notifier = MagicMock()
        mock_notifier.send_critical_alert = AsyncMock()

        with patch(
            "src.compliance_bridge.audit_workflow.create_notifier",
            return_value=mock_notifier,
        ):
            alerted, targets = await _step4_alert_on_critical_fail(
                findings, "audit-001"
            )

        assert alerted is True
        assert critical_control in targets
        mock_notifier.send_critical_alert.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_alert_sent_on_critical_error(self):
        """Alert is sent when a CRITICAL_CONTROLS finding has result=ERROR."""
        from src.compliance_bridge.audit_workflow import _step4_alert_on_critical_fail
        from src.compliance_bridge.types import CRITICAL_CONTROLS

        critical_control = next(iter(CRITICAL_CONTROLS))
        findings = [self._make_finding(critical_control, "ERROR")]

        mock_notifier = MagicMock()
        mock_notifier.send_critical_alert = AsyncMock()

        with patch(
            "src.compliance_bridge.audit_workflow.create_notifier",
            return_value=mock_notifier,
        ):
            alerted, _targets = await _step4_alert_on_critical_fail(
                findings, "audit-001"
            )

        assert alerted is True

    @pytest.mark.asyncio
    async def test_no_alert_for_non_critical_fail(self):
        """No alert is sent for a FAIL on a non-critical control."""
        from src.compliance_bridge.audit_workflow import _step4_alert_on_critical_fail

        # Use a control that is definitely not in CRITICAL_CONTROLS
        findings = [self._make_finding("NON_CRITICAL_CONTROL_XYZ", "FAIL")]

        mock_notifier = MagicMock()
        mock_notifier.send_critical_alert = AsyncMock()

        with patch(
            "src.compliance_bridge.audit_workflow.create_notifier",
            return_value=mock_notifier,
        ):
            alerted, _targets = await _step4_alert_on_critical_fail(
                findings, "audit-001"
            )

        assert alerted is False
        mock_notifier.send_critical_alert.assert_not_called()


# ---------------------------------------------------------------------------
# run_audit_workflow — full pipeline (mocked external calls)
# ---------------------------------------------------------------------------


class TestRunAuditWorkflow:
    """Integration-style tests for run_audit_workflow with all externals mocked."""

    def _make_finding(self, control_id="A.5.2", result="PASS"):
        from src.compliance_bridge.types import OscalFinding

        return OscalFinding(
            control_id=control_id,
            result=result,
            finding_id=f"finding-{control_id}",
            evidence_age_s=0.0,
        )

    def _make_accumulator_mock(self):
        """Create a mock ContextAccumulator that passes integrity checks."""
        mock_acc = MagicMock()
        mock_acc.chain_root.return_value = "a" * 64
        mock_acc.length = 1
        mock_acc.verify_integrity.return_value = (True, [])
        mock_acc.export_ndjson.return_value = '{"node": "test"}'
        return mock_acc

    @pytest.mark.asyncio
    async def test_pipeline_returns_ok_status(self):
        """run_audit_workflow returns status='ok' with required keys."""
        findings = [self._make_finding()]
        mock_acc = self._make_accumulator_mock()

        with (
            patch(
                "src.compliance_bridge.audit_workflow._step1_persist_artifact",
                new_callable=AsyncMock,
                return_value=None,
            ),
            patch(
                "src.compliance_bridge.audit_workflow._step2_parse_oscal",
                new_callable=AsyncMock,
                return_value=findings,
            ),
            patch(
                "src.compliance_bridge.audit_workflow.ContextAccumulator",
                return_value=mock_acc,
            ),
            patch(
                "src.compliance_bridge.audit_workflow._step3_ingest_to_langfuse",
                new_callable=AsyncMock,
                return_value=1,
            ),
            patch(
                "src.compliance_bridge.audit_workflow._step4_alert_on_critical_fail",
                new_callable=AsyncMock,
                return_value=(False, []),
            ),
            patch(
                "src.compliance_bridge.audit_workflow.event_bus",
                new=MagicMock(
                    publish=AsyncMock(),
                    subscriber_count=0,
                ),
            ),
            patch("asyncio.create_task"),
            patch(
                "src.compliance_bridge.aarm_mapper.build_aarm_conformance_report",
                side_effect=ImportError("aarm_mapper not available"),
            ),
        ):
            from src.compliance_bridge.audit_workflow import run_audit_workflow

            result = await run_audit_workflow("yaml-content", "test-audit-001")

        assert result["status"] == "ok"
        assert result["audit_id"] == "test-audit-001"
        assert "findings_count" in result
        assert "chain_root" in result
        assert "chain_integrity_valid" in result

    @pytest.mark.asyncio
    async def test_pipeline_reports_findings_count(self):
        """run_audit_workflow correctly reports findings_count."""
        findings = [
            self._make_finding("A.5.2", "PASS"),
            self._make_finding("A.6.1", "FAIL"),
        ]
        mock_acc = self._make_accumulator_mock()
        mock_acc.length = 2

        with (
            patch(
                "src.compliance_bridge.audit_workflow._step1_persist_artifact",
                new_callable=AsyncMock,
                return_value=None,
            ),
            patch(
                "src.compliance_bridge.audit_workflow._step2_parse_oscal",
                new_callable=AsyncMock,
                return_value=findings,
            ),
            patch(
                "src.compliance_bridge.audit_workflow.ContextAccumulator",
                return_value=mock_acc,
            ),
            patch(
                "src.compliance_bridge.audit_workflow._step3_ingest_to_langfuse",
                new_callable=AsyncMock,
                return_value=2,
            ),
            patch(
                "src.compliance_bridge.audit_workflow._step4_alert_on_critical_fail",
                new_callable=AsyncMock,
                return_value=(False, []),
            ),
            patch(
                "src.compliance_bridge.audit_workflow.event_bus",
                new=MagicMock(
                    publish=AsyncMock(),
                    subscriber_count=0,
                ),
            ),
            patch("asyncio.create_task"),
            patch(
                "src.compliance_bridge.aarm_mapper.build_aarm_conformance_report",
                side_effect=ImportError("aarm_mapper"),
            ),
        ):
            from src.compliance_bridge.audit_workflow import run_audit_workflow

            result = await run_audit_workflow("yaml-content", "audit-002")

        assert result["findings_count"] == 2

    @pytest.mark.asyncio
    async def test_chain_integrity_valid_in_response(self):
        """chain_integrity_valid in response reflects Context Accumulator result."""
        findings = [self._make_finding()]
        mock_acc = self._make_accumulator_mock()
        mock_acc.verify_integrity.return_value = (True, [])

        with (
            patch(
                "src.compliance_bridge.audit_workflow._step1_persist_artifact",
                new_callable=AsyncMock,
                return_value=None,
            ),
            patch(
                "src.compliance_bridge.audit_workflow._step2_parse_oscal",
                new_callable=AsyncMock,
                return_value=findings,
            ),
            patch(
                "src.compliance_bridge.audit_workflow.ContextAccumulator",
                return_value=mock_acc,
            ),
            patch(
                "src.compliance_bridge.audit_workflow._step3_ingest_to_langfuse",
                new_callable=AsyncMock,
                return_value=1,
            ),
            patch(
                "src.compliance_bridge.audit_workflow._step4_alert_on_critical_fail",
                new_callable=AsyncMock,
                return_value=(False, []),
            ),
            patch(
                "src.compliance_bridge.audit_workflow.event_bus",
                new=MagicMock(
                    publish=AsyncMock(),
                    subscriber_count=0,
                ),
            ),
            patch("asyncio.create_task"),
            patch(
                "src.compliance_bridge.aarm_mapper.build_aarm_conformance_report",
                side_effect=ImportError("aarm_mapper"),
            ),
        ):
            from src.compliance_bridge.audit_workflow import run_audit_workflow

            result = await run_audit_workflow("yaml", "audit-003")

        assert result["chain_integrity_valid"] is True

    @pytest.mark.asyncio
    async def test_aarm_report_artifact_key_set_in_response(self):
        """aarm_report_artifact is set in the response when AARM mapper succeeds."""
        findings = [self._make_finding()]
        mock_acc = self._make_accumulator_mock()

        mock_aarm_report = MagicMock()
        mock_aarm_report.model_dump_json.return_value = '{"posture": "NEUTRALIZED"}'
        mock_aarm_report.overall_posture = "NEUTRALIZED"
        mock_aarm_report.neutralized = 1
        mock_aarm_report.partial = 0
        mock_aarm_report.exposed = 0

        with (
            patch(
                "src.compliance_bridge.audit_workflow._step1_persist_artifact",
                new_callable=AsyncMock,
                return_value=None,
            ),
            patch(
                "src.compliance_bridge.audit_workflow._step2_parse_oscal",
                new_callable=AsyncMock,
                return_value=findings,
            ),
            patch(
                "src.compliance_bridge.audit_workflow.ContextAccumulator",
                return_value=mock_acc,
            ),
            patch(
                "src.compliance_bridge.audit_workflow._step3_ingest_to_langfuse",
                new_callable=AsyncMock,
                return_value=1,
            ),
            patch(
                "src.compliance_bridge.audit_workflow._step4_alert_on_critical_fail",
                new_callable=AsyncMock,
                return_value=(False, []),
            ),
            patch(
                "src.compliance_bridge.audit_workflow.event_bus",
                new=MagicMock(
                    publish=AsyncMock(),
                    subscriber_count=0,
                ),
            ),
            patch("asyncio.create_task"),
            patch(
                "src.compliance_bridge.aarm_mapper.build_aarm_conformance_report",
                return_value=mock_aarm_report,
            ),
        ):
            from src.compliance_bridge.audit_workflow import run_audit_workflow

            result = await run_audit_workflow("yaml", "audit-004")

        # The aarm_report_artifact is always set when AARM succeeds
        assert result["aarm_report_artifact"] is not None
        assert "audit-004" in result["aarm_report_artifact"]


# ---------------------------------------------------------------------------
# _ensure_uuid — property tests
# ---------------------------------------------------------------------------


class TestEnsureUuidProperties:
    """Property-style tests for _ensure_uuid."""

    def test_output_length_is_always_32(self):
        """All outputs are exactly 32 hex characters (128 bits)."""
        from src.compliance_bridge.audit_workflow import _ensure_uuid

        for s in ["", "a", "abc", "a-b-c", "12345678-1234-5678-1234-567812345678"]:
            assert len(_ensure_uuid(s)) == 32

    def test_output_contains_only_hex_chars(self):
        """All outputs contain only hexadecimal characters."""
        from src.compliance_bridge.audit_workflow import _ensure_uuid

        for s in ["test", "FINDING_001", "uuid-like-but-not"]:
            result = _ensure_uuid(s)
            assert all(c in "0123456789abcdef" for c in result.lower())

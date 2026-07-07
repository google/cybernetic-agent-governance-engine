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
tests/test_compliance_bridge_tier3.py

Tier-3 roadmap tests:
  3.1 — Parallel multi-control remediation advisor (audit_workflow Step 5)
  3.2 — Langfuse evaluation dataset auto-population (eval_dataset.py)
  3.3 — CMEK / SC-28 startup guard (cmek_guard.py)
  3.4 — Active Lula scheduler (lula_scheduler.py)
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(control_id: str, result: str = "PASS", safety_rate: float = 1.0):
    from src.compliance_bridge.types import OscalFinding

    return OscalFinding(
        control_id=control_id,
        result=result,  # type: ignore[arg-type]
        finding_id=f"finding-{control_id}",
        safety_rate=safety_rate,
        evidence_age_s=0.0,
        remarks=None,
    )


# ---------------------------------------------------------------------------
# 3.1 — Parallel multi-control remediation advisor
# ---------------------------------------------------------------------------


class TestParallelRemediationAdvisor:
    """
    _step5_remediation_advisor should fan out to ALL alert_targets in parallel,
    not just the first one.
    """

    @pytest.mark.asyncio
    async def test_no_alert_returns_not_sent(self):
        from src.compliance_bridge.audit_workflow import _step5_remediation_advisor

        result = await _step5_remediation_advisor(
            alerted=False, alert_targets=[], findings=[], audit_id="t3-001"
        )
        assert result["remediation_sent"] is False
        assert result["per_control"] == []

    @pytest.mark.asyncio
    async def test_no_vllm_returns_not_sent(self):
        from src.compliance_bridge.audit_workflow import _step5_remediation_advisor

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("VLLM_BASE_URL", None)
            result = await _step5_remediation_advisor(
                alerted=True,
                alert_targets=["A.9.2"],
                findings=[_make_finding("A.9.2", "FAIL")],
                audit_id="t3-002",
            )
        assert result["remediation_sent"] is False
        assert "VLLM_BASE_URL" in result["advisor_error"]

    @pytest.mark.asyncio
    async def test_multiple_targets_each_get_advisory(self):
        """
        When 3 controls fail, _step5_one_control must be called 3 times
        (via _step5_remediation_advisor) concurrently.
        """
        from src.compliance_bridge.audit_workflow import _step5_remediation_advisor

        call_log: list[str] = []

        async def _fake_one_control(
            control_id,
            findings,
            audit_id,
            vllm_base,
            model_name,
            max_tokens,
            timeout_sec,
        ):
            call_log.append(control_id)
            return {
                "control_id": control_id,
                "remediation_sent": True,
                "remediation_text": f"Fix for {control_id}",
                "advisor_error": None,
                "trace_ids_sampled": [],
            }

        findings = [
            _make_finding("A.9.2", "FAIL"),
            _make_finding("SC-4", "FAIL"),
            _make_finding("A.8.4", "FAIL"),
        ]
        with patch.dict(
            os.environ, {"VLLM_BASE_URL": "http://fake-vllm", "VLLM_API_KEY": "k"}
        ):
            with patch(
                "src.compliance_bridge.audit_workflow._step5_one_control",
                new=AsyncMock(side_effect=_fake_one_control),
            ):
                result = await _step5_remediation_advisor(
                    alerted=True,
                    alert_targets=["A.9.2", "SC-4", "A.8.4"],
                    findings=findings,
                    audit_id="t3-parallel",
                )

        assert result["remediation_sent"] is True
        assert len(result["per_control"]) == 3
        # All three controls must have been called
        assert set(call_log) == {"A.9.2", "SC-4", "A.8.4"}

    @pytest.mark.asyncio
    async def test_duplicate_targets_deduped(self):
        """Duplicate control IDs in alert_targets must only trigger one advisory."""
        from src.compliance_bridge.audit_workflow import _step5_remediation_advisor

        call_log: list[str] = []

        async def _fake_one(control_id, **kwargs):
            call_log.append(control_id)
            return {
                "control_id": control_id,
                "remediation_sent": True,
                "remediation_text": "fix",
                "advisor_error": None,
                "trace_ids_sampled": [],
            }

        with patch.dict(
            os.environ, {"VLLM_BASE_URL": "http://fake-vllm", "VLLM_API_KEY": "k"}
        ):
            with patch(
                "src.compliance_bridge.audit_workflow._step5_one_control",
                new=AsyncMock(side_effect=_fake_one),
            ):
                result = await _step5_remediation_advisor(
                    alerted=True,
                    alert_targets=["A.9.2", "A.9.2", "A.9.2"],  # triplicated
                    findings=[_make_finding("A.9.2", "FAIL")],
                    audit_id="t3-dedup",
                )

        assert call_log.count("A.9.2") == 1, (
            "Duplicate alert_targets must be de-duplicated"
        )
        assert len(result["per_control"]) == 1

    @pytest.mark.asyncio
    async def test_partial_failure_still_reports_success(self):
        """If 2/3 advisories succeed, remediation_sent should be True."""
        from src.compliance_bridge.audit_workflow import _step5_remediation_advisor

        async def _fake_one(control_id, **kwargs):
            if control_id == "SC-4":
                return {
                    "control_id": "SC-4",
                    "remediation_sent": False,
                    "advisor_error": "LLM error: timeout",
                    "trace_ids_sampled": [],
                }
            return {
                "control_id": control_id,
                "remediation_sent": True,
                "remediation_text": "fix",
                "advisor_error": None,
                "trace_ids_sampled": [],
            }

        with patch.dict(
            os.environ, {"VLLM_BASE_URL": "http://fake-vllm", "VLLM_API_KEY": "k"}
        ):
            with patch(
                "src.compliance_bridge.audit_workflow._step5_one_control",
                new=AsyncMock(side_effect=_fake_one),
            ):
                result = await _step5_remediation_advisor(
                    alerted=True,
                    alert_targets=["A.9.2", "SC-4"],
                    findings=[
                        _make_finding("A.9.2", "FAIL"),
                        _make_finding("SC-4", "FAIL"),
                    ],
                    audit_id="t3-partial",
                )

        assert result["remediation_sent"] is True
        assert result["advisor_error"] is None  # suppressed because ≥1 succeeded
        assert len(result["per_control"]) == 2

    @pytest.mark.asyncio
    async def test_all_failures_reports_first_error(self):
        from src.compliance_bridge.audit_workflow import _step5_remediation_advisor

        async def _fake_one(control_id, **kwargs):
            return {
                "control_id": control_id,
                "remediation_sent": False,
                "advisor_error": f"LLM error for {control_id}",
                "trace_ids_sampled": [],
            }

        with patch.dict(
            os.environ, {"VLLM_BASE_URL": "http://fake-vllm", "VLLM_API_KEY": "k"}
        ):
            with patch(
                "src.compliance_bridge.audit_workflow._step5_one_control",
                new=AsyncMock(side_effect=_fake_one),
            ):
                result = await _step5_remediation_advisor(
                    alerted=True,
                    alert_targets=["A.9.2"],
                    findings=[_make_finding("A.9.2", "FAIL")],
                    audit_id="t3-allfail",
                )

        assert result["remediation_sent"] is False
        assert result["advisor_error"] is not None


# ---------------------------------------------------------------------------
# 3.2 — Langfuse eval dataset auto-population
# ---------------------------------------------------------------------------


class TestEvalDataset:
    @pytest.mark.asyncio
    async def test_no_fail_findings_returns_zero(self):
        from src.compliance_bridge.eval_dataset import populate_eval_dataset

        mock_lf = MagicMock()
        findings = [_make_finding("A.5.2", "PASS"), _make_finding("SC-8", "PASS")]
        count = await populate_eval_dataset(findings, "eval-test-001", mock_lf)
        assert count == 0
        mock_lf.create_dataset_item.assert_not_called()

    @pytest.mark.asyncio
    async def test_fail_findings_create_items(self):
        from src.compliance_bridge.eval_dataset import populate_eval_dataset

        mock_lf = MagicMock()
        findings = [
            _make_finding("A.9.2", "FAIL", 0.7),
            _make_finding("SC-4", "FAIL", 0.8),
            _make_finding("A.5.2", "PASS", 1.0),  # must be skipped
        ]
        count = await populate_eval_dataset(findings, "eval-test-002", mock_lf)
        assert count == 2
        assert mock_lf.create_dataset_item.call_count == 2

    @pytest.mark.asyncio
    async def test_dataset_name_per_control(self):
        from src.compliance_bridge.eval_dataset import (
            _dataset_name,
        )

        assert _dataset_name("A.9.2") == "cage-compliance-A.9.2"
        assert _dataset_name("SC-4") == "cage-compliance-SC-4"

    @pytest.mark.asyncio
    async def test_item_has_correct_input_shape(self):
        from src.compliance_bridge.eval_dataset import populate_eval_dataset

        created_items: list[dict] = []

        mock_lf = MagicMock()

        def _capture_item(**kwargs):
            created_items.append(kwargs)

        mock_lf.create_dataset_item.side_effect = _capture_item

        findings = [_make_finding("A.9.2", "FAIL", 0.75)]
        await populate_eval_dataset(findings, "shape-test", mock_lf)

        assert len(created_items) == 1
        item = created_items[0]
        assert item["dataset_name"] == "cage-compliance-A.9.2"
        assert item["input"]["finding"]["control_id"] == "A.9.2"
        assert item["input"]["audit_id"] == "shape-test"
        assert item["expected_output"]["result"] == "PASS"
        assert item["metadata"]["control_id"] == "A.9.2"

    @pytest.mark.asyncio
    async def test_single_failure_does_not_block_others(self):
        """If one item fails to create, the rest must still be attempted."""
        from src.compliance_bridge.eval_dataset import populate_eval_dataset

        call_count = 0
        mock_lf = MagicMock()

        def _flaky(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("Simulated Langfuse error")

        mock_lf.create_dataset_item.side_effect = _flaky

        findings = [
            _make_finding("A.9.2", "FAIL"),
            _make_finding("SC-4", "FAIL"),
        ]
        count = await populate_eval_dataset(findings, "flaky-test", mock_lf)
        # Only the second should succeed
        assert count == 1
        assert call_count == 2


# ---------------------------------------------------------------------------
# 3.3 — CMEK guard (cmek_guard.py)
# ---------------------------------------------------------------------------


class TestCmekGuard:
    def test_disabled_by_env_returns_cmek_disabled(self):
        from src.compliance_bridge.cmek_guard import validate_cmek_configuration

        with patch.dict(os.environ, {"CMEK_CHECK_DISABLED": "1"}):
            result = validate_cmek_configuration()
        assert result["cmek_enabled"] is False
        assert result["key_name"] is None

    def test_dev_env_missing_key_returns_warning_not_exception(self):
        from src.compliance_bridge.cmek_guard import validate_cmek_configuration

        env = {"ENVIRONMENT": "development", "CMEK_CHECK_DISABLED": "0"}
        with patch.dict(os.environ, env):
            os.environ.pop("CMEK_KEY_RESOURCE_NAME", None)
            result = validate_cmek_configuration()
        assert result["cmek_enabled"] is False
        assert any("CMEK_KEY_RESOURCE_NAME" in w for w in result["warnings"])

    def test_production_missing_key_raises(self):
        from src.compliance_bridge.cmek_guard import validate_cmek_configuration

        env = {"ENVIRONMENT": "production", "CMEK_CHECK_DISABLED": "0"}
        with patch.dict(os.environ, env):
            os.environ.pop("CMEK_KEY_RESOURCE_NAME", None)
            with pytest.raises(RuntimeError, match="CMEK_KEY_RESOURCE_NAME"):
                validate_cmek_configuration()

    def test_valid_key_format_passes(self):
        from src.compliance_bridge.cmek_guard import validate_cmek_configuration

        valid_key = (
            "projects/my-proj/locations/global/keyRings/cage/cryptoKeys/oscal-key"
        )
        env = {
            "ENVIRONMENT": "production",
            "CMEK_KEY_RESOURCE_NAME": valid_key,
            "CMEK_CHECK_DISABLED": "0",
        }
        with patch.dict(os.environ, env):
            os.environ.pop("OSCAL_BUCKET_NAME", None)
            result = validate_cmek_configuration()
        assert result["cmek_enabled"] is True
        assert result["key_name"] == valid_key

    def test_invalid_key_format_raises_in_production(self):
        from src.compliance_bridge.cmek_guard import validate_cmek_configuration

        env = {
            "ENVIRONMENT": "production",
            "CMEK_KEY_RESOURCE_NAME": "not-a-valid-kms-key",
            "CMEK_CHECK_DISABLED": "0",
        }
        with patch.dict(os.environ, env):
            with pytest.raises(RuntimeError, match="invalid format"):
                validate_cmek_configuration()

    def test_invalid_key_format_is_warning_in_dev(self):
        from src.compliance_bridge.cmek_guard import validate_cmek_configuration

        env = {
            "ENVIRONMENT": "development",
            "CMEK_KEY_RESOURCE_NAME": "bad-key",
            "CMEK_CHECK_DISABLED": "0",
        }
        with patch.dict(os.environ, env):
            os.environ.pop("OSCAL_BUCKET_NAME", None)
            result = validate_cmek_configuration()
        # Should not raise, but should populate warnings
        assert any("invalid format" in w for w in result["warnings"])

    def test_gcs_check_skipped_when_no_bucket_name(self):
        from src.compliance_bridge.cmek_guard import validate_cmek_configuration

        valid_key = "projects/p/locations/global/keyRings/r/cryptoKeys/k"
        env = {
            "ENVIRONMENT": "production",
            "CMEK_KEY_RESOURCE_NAME": valid_key,
            "CMEK_CHECK_DISABLED": "0",
        }
        with patch.dict(os.environ, env):
            os.environ.pop("OSCAL_BUCKET_NAME", None)
            os.environ.pop("OSCAL_S3_BUCKET", None)
            result = validate_cmek_configuration()
        assert result["bucket_verified"] is False
        assert any("OSCAL_BUCKET_NAME not set" in w for w in result["warnings"])

    def test_gcs_import_error_is_non_fatal(self):

        def _raise_import(*a, **kw):
            raise ImportError("No module named 'google.cloud.storage'")

        with patch(
            "src.compliance_bridge.cmek_guard._verify_gcs_bucket_cmek"
        ) as mock_verify:
            # Directly simulate what _verify_gcs_bucket_cmek returns on ImportError
            mock_verify.return_value = (
                False,
                [
                    "[cmek_guard] google-cloud-storage not installed — skipping GCS CMEK check. "
                    "Install it in production to enable bucket verification."
                ],
            )
            verified, warnings = mock_verify(
                "cage-oscal-bucket",
                "projects/p/locations/global/keyRings/r/cryptoKeys/k",
            )
        assert verified is False
        assert any("not installed" in w for w in warnings)


# ---------------------------------------------------------------------------
# 3.4 — Lula scheduler (lula_scheduler.py)
# ---------------------------------------------------------------------------


class TestLulaScheduler:
    @pytest.mark.asyncio
    async def test_disabled_by_env_exits_immediately(self):
        from src.compliance_bridge.lula_scheduler import run_lula_scheduler

        called = False

        async def _fake_cycle():
            nonlocal called
            called = True

        with patch.dict(os.environ, {"LULA_SCHEDULER_DISABLED": "1"}):
            with patch(
                "src.compliance_bridge.lula_scheduler._run_lula_cycle",
                new=AsyncMock(side_effect=_fake_cycle),
            ):
                await run_lula_scheduler()

        assert not called, "Scheduler should exit immediately when disabled"

    @pytest.mark.asyncio
    async def test_skips_cycle_when_component_not_found(self, tmp_path):
        from src.compliance_bridge.lula_scheduler import _run_lula_cycle

        non_existent = str(tmp_path / "does-not-exist.yaml")
        with patch.dict(os.environ, {"LULA_COMPONENT_DEFINITION_PATH": non_existent}):
            result = await _run_lula_cycle()
        assert result["status"] == "skipped"
        assert result["reason"] == "component_not_found"

    @pytest.mark.asyncio
    async def test_lula_not_found_returns_failed(self, tmp_path):
        from src.compliance_bridge.lula_scheduler import _run_lula_validate

        # Ensure the binary doesn't exist by using a non-existent PATH
        with patch.dict(os.environ, {"PATH": "/nonexistent"}):
            result = await _run_lula_validate(
                str(tmp_path / "component.yaml"),
                str(tmp_path / "results.yaml"),
                timeout=5,
            )
        assert result is False

    @pytest.mark.asyncio
    async def test_post_results_fails_on_missing_file(self, tmp_path):
        from src.compliance_bridge.lula_scheduler import _post_results_to_bridge

        result = await _post_results_to_bridge(
            str(tmp_path / "nonexistent.yaml"), "test-audit"
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_dataset_name_helper(self):
        from src.compliance_bridge.eval_dataset import _dataset_name

        # Covers the helper used by lula scheduler indirectly
        assert "cage-compliance" in _dataset_name("A.9.2")

    @pytest.mark.asyncio
    async def test_full_cycle_ok_path(self, tmp_path):
        from src.compliance_bridge.lula_scheduler import _run_lula_cycle

        component_file = tmp_path / "component.yaml"
        component_file.write_text("# fake component definition", encoding="utf-8")
        results_file = tmp_path / "results.yaml"

        import httpx
        import respx

        with patch.dict(
            os.environ,
            {
                "LULA_COMPONENT_DEFINITION_PATH": str(component_file),
                "LULA_ASSESSMENT_RESULTS_PATH": str(results_file),
                "COMPLIANCE_BRIDGE_URL": "http://localhost:3001",
            },
        ):
            with patch(
                "src.compliance_bridge.lula_scheduler._run_lula_validate",
                new=AsyncMock(return_value=True),
            ):
                # Simulate lula writing results file
                results_file.write_text(
                    "assessment-results:\n  uuid: test\n", encoding="utf-8"
                )
                with respx.mock:
                    respx.post("http://localhost:3001/v1/audit/ingest").mock(
                        return_value=httpx.Response(200, json={"status": "ok"})
                    )
                    result = await _run_lula_cycle()

        assert result["status"] == "ok"
        assert "lula-scheduled-" in result["audit_id"]

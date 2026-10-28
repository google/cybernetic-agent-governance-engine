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

"""The compliance bridge never skips its remediation advisory silently.

Under ``CAGE_INFERENCE_BACKEND=none`` the audit artifact records the advisory
as ``NOT_PERFORMED`` with ``INFERENCE_BACKEND_NONE`` and no model is called. A
required backend with no ``VLLM_BASE_URL`` is recorded as an ``ERROR`` with
``INFERENCE_BACKEND_URL_MISSING``.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.gateway.governance.inference_backend import (
    ENV_VAR,
    INFERENCE_BACKEND_NONE,
    INFERENCE_BACKEND_URL_MISSING,
)
from tests.test_compliance_bridge_tier3 import _make_finding

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.mark.asyncio
async def test_advisory_not_performed_under_none(monkeypatch) -> None:
    from src.compliance_bridge import audit_workflow as aw

    monkeypatch.setenv(ENV_VAR, "none")
    monkeypatch.setenv("VLLM_BASE_URL", "http://would-be-called/v1")
    one_control = AsyncMock()
    with patch.object(aw, "_step5_one_control", one_control):
        result = await aw._step5_remediation_advisor(
            alerted=True,
            alert_targets=["A.9.2"],
            findings=[_make_finding("A.9.2", "FAIL")],
            audit_id="none-001",
        )

    assert result["advisor_status"] == "NOT_PERFORMED"
    assert result["advisor_reason_code"] == INFERENCE_BACKEND_NONE
    assert result["remediation_sent"] is False
    one_control.assert_not_awaited()


@pytest.mark.asyncio
async def test_advisory_without_url_is_an_error(monkeypatch) -> None:
    from src.compliance_bridge import audit_workflow as aw

    monkeypatch.delenv(ENV_VAR, raising=False)
    monkeypatch.delenv("VLLM_BASE_URL", raising=False)
    result = await aw._step5_remediation_advisor(
        alerted=True,
        alert_targets=["A.9.2"],
        findings=[_make_finding("A.9.2", "FAIL")],
        audit_id="url-001",
    )

    assert result["advisor_status"] == "ERROR"
    assert result["advisor_reason_code"] == INFERENCE_BACKEND_URL_MISSING
    assert "VLLM_BASE_URL" in result["advisor_error"]


@pytest.mark.asyncio
async def test_advisory_status_on_every_path(monkeypatch) -> None:
    from src.compliance_bridge import audit_workflow as aw

    monkeypatch.delenv(ENV_VAR, raising=False)
    no_alert = await aw._step5_remediation_advisor(
        alerted=False, alert_targets=[], findings=[], audit_id="na-001"
    )
    assert no_alert["advisor_status"] == "NOT_REQUIRED"

    monkeypatch.setenv("VLLM_BASE_URL", "http://fake-vllm/v1")
    ok = {
        "control_id": "A.9.2",
        "remediation_sent": True,
        "remediation_text": "fix it",
        "advisor_error": None,
        "trace_ids_sampled": [],
    }
    with patch.object(aw, "_step5_one_control", AsyncMock(return_value=ok)):
        performed = await aw._step5_remediation_advisor(
            alerted=True,
            alert_targets=["A.9.2"],
            findings=[_make_finding("A.9.2", "FAIL")],
            audit_id="ok-001",
        )
    assert performed["advisor_status"] == "PERFORMED"


@pytest.mark.asyncio
async def test_audit_response_records_not_performed_under_none(monkeypatch) -> None:
    """The artifact the caller receives says why there is no advisory."""
    from src.compliance_bridge import audit_workflow as aw

    monkeypatch.setenv(ENV_VAR, "none")
    finding = _make_finding("A.9.2", "FAIL")
    step5 = AsyncMock()
    with (
        patch.object(aw, "_step1_persist_artifact", AsyncMock(return_value=None)),
        patch.object(aw, "_step2_parse_oscal", AsyncMock(return_value=[finding])),
        patch.object(aw, "_step3_ingest_to_langfuse", AsyncMock(return_value=1)),
        patch.object(
            aw,
            "_step4_alert_on_critical_fail",
            AsyncMock(return_value=(True, ["A.9.2"])),
        ),
        patch.object(aw, "_step5_remediation_advisor", step5),
        patch.object(aw, "populate_eval_dataset", AsyncMock(return_value=0)),
        patch.object(aw, "_make_compliance_langfuse", MagicMock()),
        patch.object(aw, "event_bus", MagicMock(publish=AsyncMock())),
    ):
        result = await aw.run_audit_workflow("oscal: {}", "none-audit-001")
        for _ in range(3):  # let any scheduled background task start
            await asyncio.sleep(0)

    assert result["advisor_status"] == "NOT_PERFORMED"
    assert result["advisor_reason_code"] == INFERENCE_BACKEND_NONE
    step5.assert_not_called()

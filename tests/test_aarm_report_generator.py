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
tests/test_aarm_report_generator.py — Unit tests for the AARM narrative report generator.
"""

from __future__ import annotations

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.compliance_bridge.aarm_mapper import (
    AARM_THREAT_VECTORS,
    AARMConformanceReport,
    AARMVectorResult,
    build_aarm_conformance_report,
)
from src.compliance_bridge.aarm_report_generator import (
    _build_narrative_prompt,
    _template_narrative,
    enrich_report_with_narratives,
    generate_aarm_narrative,
)
from src.compliance_bridge.types import OscalFinding


def _finding(control_id: str, result: str = "PASS") -> OscalFinding:
    return OscalFinding(
        control_id=control_id,
        result=result,  # type: ignore[arg-type]
        finding_id=f"finding-{control_id}",
        safety_rate=1.0 if result == "PASS" else 0.0,
        evidence_age_s=100.0,
    )


def _all_pass_findings() -> list[OscalFinding]:
    all_controls: set[str] = set()
    for v in AARM_THREAT_VECTORS.values():
        all_controls.update(v.neutralizing_controls)
    return [_finding(cid, "PASS") for cid in all_controls]


@pytest.fixture
def sample_report() -> AARMConformanceReport:
    return build_aarm_conformance_report(
        _all_pass_findings(), audit_id="audit-test-123"
    )


@pytest.fixture
def sample_vector_result(sample_report: AARMConformanceReport) -> AARMVectorResult:
    return sample_report.vectors[0]


@pytest.mark.local
@pytest.mark.unit
def test_template_narrative(sample_vector_result: AARMVectorResult) -> None:
    text = _template_narrative(sample_vector_result)
    assert f"AARM {sample_vector_result.vector_id}" in text
    assert f"Severity: {sample_vector_result.aarm_severity}" in text
    assert sample_vector_result.status in text


@pytest.mark.local
@pytest.mark.unit
def test_build_narrative_prompt(sample_vector_result: AARMVectorResult) -> None:
    prompt = _build_narrative_prompt(sample_vector_result)
    assert sample_vector_result.vector_id in prompt
    assert sample_vector_result.name in prompt
    assert sample_vector_result.aarm_severity in prompt


@pytest.mark.local
@pytest.mark.unit
@pytest.mark.asyncio
async def test_generate_aarm_narrative_success(
    sample_vector_result: AARMVectorResult,
) -> None:
    mock_choice = MagicMock()
    mock_choice.message.content = (
        "Generated narrative prose explaining security controls."
    )
    mock_completion = MagicMock()
    mock_completion.choices = [mock_choice]

    mock_client = MagicMock()
    mock_client.chat.completions.create = AsyncMock(return_value=mock_completion)

    with (
        patch.dict(os.environ, {"VLLM_API_KEY": "test-key"}, clear=False),
        patch("openai.AsyncOpenAI", return_value=mock_client),
    ):
        result = await generate_aarm_narrative(
            sample_vector_result,
            vllm_base="http://localhost:8000/v1",
            model_name="test-model",
        )
        assert result == "Generated narrative prose explaining security controls."


@pytest.mark.local
@pytest.mark.unit
@pytest.mark.asyncio
async def test_generate_aarm_narrative_missing_key_fallback(
    sample_vector_result: AARMVectorResult,
) -> None:
    with patch.dict(os.environ, {"VLLM_API_KEY": ""}, clear=False):
        result = await generate_aarm_narrative(
            sample_vector_result,
            vllm_base="http://localhost:8000/v1",
            model_name="test-model",
        )
        assert f"AARM {sample_vector_result.vector_id}" in result
        assert f"Severity: {sample_vector_result.aarm_severity}" in result


@pytest.mark.local
@pytest.mark.unit
@pytest.mark.asyncio
async def test_generate_aarm_narrative_timeout_fallback(
    sample_vector_result: AARMVectorResult,
) -> None:
    mock_client = MagicMock()
    mock_client.chat.completions.create = AsyncMock(side_effect=asyncio.TimeoutError())

    with (
        patch.dict(os.environ, {"VLLM_API_KEY": "test-key"}, clear=False),
        patch("openai.AsyncOpenAI", return_value=mock_client),
    ):
        result = await generate_aarm_narrative(
            sample_vector_result,
            vllm_base="http://localhost:8000/v1",
            model_name="test-model",
        )
        assert f"AARM {sample_vector_result.vector_id}" in result
        assert f"Severity: {sample_vector_result.aarm_severity}" in result


@pytest.mark.local
@pytest.mark.unit
@pytest.mark.asyncio
async def test_enrich_report_with_narratives_no_vllm_base(
    sample_report: AARMConformanceReport,
) -> None:
    with patch.dict(os.environ, {"VLLM_BASE_URL": ""}, clear=False):
        narratives = await enrich_report_with_narratives(sample_report)
        assert len(narratives) == 11
        for v in sample_report.vectors:
            assert v.vector_id in narratives


@pytest.mark.local
@pytest.mark.unit
@pytest.mark.asyncio
async def test_enrich_report_with_narratives_with_vllm(
    sample_report: AARMConformanceReport,
) -> None:
    with (
        patch.dict(
            os.environ, {"VLLM_BASE_URL": "http://localhost:8000/v1"}, clear=False
        ),
        patch(
            "src.compliance_bridge.aarm_report_generator.generate_aarm_narrative",
            new=AsyncMock(return_value="Narrative prose"),
        ),
    ):
        narratives = await enrich_report_with_narratives(sample_report)
        assert len(narratives) == 11
        assert narratives[sample_report.vectors[0].vector_id] == "Narrative prose"

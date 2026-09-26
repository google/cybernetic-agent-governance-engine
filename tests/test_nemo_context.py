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

import pytest
from unittest.mock import AsyncMock, MagicMock

from src.gateway.governance.nemo_context import (
    INPUT_RAIL_PROBE_ACTION,
    compute_nemo_context,
)
from src.gateway.governance.null_components import NullSafetyFilter

pytestmark = [pytest.mark.unit, pytest.mark.local]

@pytest.fixture
def stpa_validator():
    mock = MagicMock()
    mock.validate.return_value = []
    return mock

@pytest.fixture
def safety_filter():
    mock = AsyncMock()
    mock.verify_action.return_value = "SAFE"
    return mock

@pytest.mark.asyncio
async def test_compute_nemo_context_happy_path(stpa_validator, safety_filter):
    result = await compute_nemo_context(
        stpa_validator, safety_filter, "action", {"foo": "bar"}
    )
    assert result["stpa_result"]["allowed"] is True
    assert result["cbf_result"]["allowed"] is True
    assert result["cbf_result"]["reason"] == "SAFE"

@pytest.mark.asyncio
async def test_compute_nemo_context_stpa_raises(stpa_validator, safety_filter):
    stpa_validator.validate.side_effect = ValueError("STPA failed")
    result = await compute_nemo_context(
        stpa_validator, safety_filter, "action", {"foo": "bar"}
    )
    assert result["stpa_result"]["allowed"] is False
    assert "STPA exception" in result["stpa_result"]["violations"][0]
    
@pytest.mark.asyncio
async def test_compute_nemo_context_cbf_raises(stpa_validator, safety_filter):
    safety_filter.verify_action.side_effect = ValueError("CBF failed")
    result = await compute_nemo_context(
        stpa_validator, safety_filter, "action", {"foo": "bar"}
    )
    assert result["cbf_result"]["allowed"] is False
    assert "CBF unavailable (fail-closed)" in result["cbf_result"]["reason"]

@pytest.mark.asyncio
async def test_compute_nemo_context_cbf_unsafe(stpa_validator, safety_filter):
    safety_filter.verify_action.return_value = "UNSAFE: some reason"
    result = await compute_nemo_context(
        stpa_validator, safety_filter, "action", {"foo": "bar"}
    )
    assert result["cbf_result"]["allowed"] is False
    assert result["cbf_result"]["reason"] == "UNSAFE: some reason"

@pytest.mark.asyncio
async def test_compute_nemo_context_cbf_non_safe_prefix(stpa_validator, safety_filter):
    safety_filter.verify_action.return_value = "[REASON] Not safe"
    result = await compute_nemo_context(
        stpa_validator, safety_filter, "action", {"foo": "bar"}
    )
    assert result["cbf_result"]["allowed"] is False
    assert result["cbf_result"]["reason"] == "[REASON] Not safe"

@pytest.mark.asyncio
async def test_compute_nemo_context_cbf_reconciliation(stpa_validator, safety_filter):
    safety_filter.verify_action.return_value = "RECONCILIATION_UNAVAILABLE: no data"
    result = await compute_nemo_context(
        stpa_validator, safety_filter, "action", {"foo": "bar"}
    )
    assert result["cbf_result"]["allowed"] is False
    assert result["cbf_result"]["reason"] == "RECONCILIATION_UNAVAILABLE: no data"

@pytest.mark.asyncio
async def test_compute_nemo_context_cbf_safe_explanation(stpa_validator, safety_filter):
    safety_filter.verify_action.return_value = "SAFE: some explanation"
    result = await compute_nemo_context(
        stpa_validator, safety_filter, "action", {"foo": "bar"}
    )
    assert result["cbf_result"]["allowed"] is True
    assert result["cbf_result"]["reason"] == "SAFE: some explanation"


@pytest.mark.asyncio
async def test_null_safety_filter_denies_via_verdict_not_exception(stpa_validator):
    """Bare-kernel mode must deny through NullSafetyFilter's explicit verdict.

    If verify_action were sync, awaiting it would raise TypeError and the
    denial would come from the exception path ("CBF unavailable") instead.
    """
    result = await compute_nemo_context(
        stpa_validator, NullSafetyFilter(), INPUT_RAIL_PROBE_ACTION, {}
    )
    assert result["cbf_result"]["allowed"] is False
    assert result["cbf_result"]["reason"].startswith("UNSAFE: no domain safety filter")


def test_input_rail_callers_use_named_probe_action():
    """Both input rails pass the shared constant, not ad-hoc literals or state keys."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    for rel in (
        "src/gateway/server/inference_proxy.py",
        "src/gateway/governance/langgraph_harness/nemo_node_factory.py",
    ):
        src = (root / rel).read_text(encoding="utf-8")
        assert "INPUT_RAIL_PROBE_ACTION," in src, rel
        assert 'state.get("action"' not in src, rel
        assert '"nemo_node"' not in src, rel

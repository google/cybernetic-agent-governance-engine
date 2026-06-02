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

from unittest.mock import MagicMock, patch

import pytest

pytestmark = pytest.mark.unit

from src.governed_financial_advisor.demo.pipeline_manager import submit_governance_pipeline
from src.governed_financial_advisor.demo.state import DemoState, demo_state


@pytest.fixture
def clean_state():
    demo_state.reset()
    return demo_state

@pytest.mark.asyncio
async def test_demo_state_singleton():
    s1 = DemoState()
    s2 = DemoState()
    assert s1 is s2
    s1.simulated_latency = 100.0
    assert s2.simulated_latency == 100.0

@pytest.mark.asyncio
@patch("src.governed_financial_advisor.demo.pipeline_manager.compiler")
async def test_submit_governance_pipeline(mock_compiler, clean_state):
    # Mock KFP compiler
    mock_compiler.Compiler.return_value.compile = MagicMock()

    await submit_governance_pipeline("My Strategy")

    # Verify compilation was called
    mock_compiler.Compiler().compile.assert_called()

    assert clean_state.pipeline_status["status"] == "submitted"
    assert clean_state.pipeline_status["mode"] == "local"
    assert clean_state.latest_trace_id is not None

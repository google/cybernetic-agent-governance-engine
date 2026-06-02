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

from unittest.mock import patch

import pytest

pytestmark = pytest.mark.unit

from src.governed_financial_advisor.governance.structs import ConstraintLogic, ProposedUCA
from src.governed_financial_advisor.governance.transpiler import PolicyTranspiler


@pytest.fixture
def mock_uca():
    return ProposedUCA(
        category="Wrong Action",
        hazard="H-1: Slippage > 1%",
        description="Agent executes trade with high slippage.",
        constraint_logic=ConstraintLogic(
            variable="order_size",
            operator=">",
            threshold="0.01 * daily_volume",
            condition="order_type == MARKET"
        )
    )

def test_transpiler_initialization_llm_flag():
    with patch("src.governed_financial_advisor.governance.transpiler.ChatOpenAI") as MockLLM:
        transpiler = PolicyTranspiler()
        assert transpiler.use_llm is True
        MockLLM.assert_called_once()

def test_generate_nemo_action_calls_llm(mock_uca):
    with patch("src.governed_financial_advisor.governance.transpiler.ChatOpenAI") as MockLLM:
        mock_instance = MockLLM.return_value
        mock_instance.invoke.return_value.content = "def check_test(): return True"

        transpiler = PolicyTranspiler()
        result = transpiler.generate_nemo_action(mock_uca)

        assert "def check_test():" in result
        mock_instance.invoke.assert_called_once()
        # Verify prompt contained UCA details
        args, _ = mock_instance.invoke.call_args
        prompt = args[0]
        assert "H-1: Slippage > 1%" in prompt
        assert "order_size" in prompt
        assert "order_type == MARKET" in prompt

def test_generate_rego_policy_calls_llm(mock_uca):
    with patch("src.governed_financial_advisor.governance.transpiler.ChatOpenAI") as MockLLM:
        mock_instance = MockLLM.return_value
        mock_instance.invoke.return_value.content = "decision = \"DENY\""

        transpiler = PolicyTranspiler()
        result = transpiler.generate_rego_policy(mock_uca)

        assert "decision = \"DENY\"" in result
        mock_instance.invoke.assert_called_once()

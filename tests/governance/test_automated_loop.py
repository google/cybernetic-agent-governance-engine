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

import unittest
import pytest
import os
import sys

# Ensure src is in path
sys.path.append(os.getcwd())

pytestmark = pytest.mark.unit

from src.governed_financial_advisor.agents.risk_analyst.agent import ConstraintLogic, ProposedUCA
from src.governed_financial_advisor.governance.nemo_actions import (
    check_drawdown_limit,
    check_slippage_risk,
)
from src.governed_financial_advisor.governance.transpiler import transpiler


class TestAutomatedLoop(unittest.TestCase):
    def test_transpiler_generation_slippage(self):
        """Test Transpiler for Slippage Rule."""
        logic = ConstraintLogic(
            variable="order_size",
            operator=">",
            threshold="0.01 * daily_volume",
            condition="order_type==MARKET"
        )

        uca = ProposedUCA(
            category="Wrong Order",
            hazard="H-Slippage",
            description="High slippage risk.",
            constraint_logic=logic
        )

        code = transpiler.generate_nemo_action(uca)
        self.assertIn("def check_slippage_risk", code)
        self.assertIn("0.01", code)

    def test_nemo_slippage_block(self):
        """Test NeMo Action: Slippage Block."""
        context = {"order_type": "MARKET", "order_size": 20000, "daily_volume": 1000000}
        # 20k is 2% of 1M -> Should Block (> 1%)
        allowed = check_slippage_risk(context)
        self.assertFalse(allowed)

    def test_nemo_slippage_allow(self):
        """Test NeMo Action: Slippage Allow."""
        context = {"order_type": "MARKET", "order_size": 5000, "daily_volume": 1000000}
        # 5k is 0.5% -> Should Allow
        allowed = check_slippage_risk(context)
        self.assertTrue(allowed)

    def test_nemo_drawdown_block(self):
        """Test NeMo Action: Drawdown Block."""
        context = {"drawdown_pct": 5.0}
        allowed = check_drawdown_limit(context)
        self.assertFalse(allowed)

if __name__ == "__main__":
    unittest.main()

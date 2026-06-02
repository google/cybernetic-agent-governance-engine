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

import os
import unittest

# R-24: AgentBeatsSimulator requires CAGE_SIMULATION_MODE=true to instantiate.
# Set this before importing or instantiating the simulator to enable test mode.
os.environ["CAGE_SIMULATION_MODE"] = "true"

import pytest
pytestmark = pytest.mark.unit

from src.governed_financial_advisor.agents.evaluator.simulator import AgentBeatsSimulator, mock_financial_agent


class TestAgentBeats(unittest.TestCase):
    def test_simulation_run(self):
        """Test that the simulator runs a loop and produces a graded report."""
        sim = AgentBeatsSimulator(mock_financial_agent)

        # Run 2 scenarios
        report = sim.run_simulation(num_scenarios=2, use_red_team=True)

        self.assertEqual(report["total_runs"], 2)
        self.assertIn("pass_rate", report)
        self.assertTrue(0.0 <= report["pass_rate"] <= 1.0)

        # Check details
        for result in report["details"]:
            self.assertIn("score", result)
            self.assertIn("explanation", result)
            # Ensure the Red Agent injected something
            self.assertTrue(len(result["prompt"]) > 0)

if __name__ == "__main__":
    unittest.main()

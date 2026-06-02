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

import json
import os
import unittest

import pytest

pytestmark = pytest.mark.unit

kfp = pytest.importorskip("kfp", reason="kfp not installed; skipping pipeline compilation tests")
compiler = kfp.compiler

try:
    from src.governed_financial_advisor.pipelines.green_stack_pipeline import governance_pipeline
except ImportError:
    governance_pipeline = None


class TestPipelineCompilation(unittest.TestCase):
    def test_pipeline_compiles(self):
        """Verify the KFP pipeline compiles to a valid JSON spec."""
        output_file = "test_pipeline.json"
        try:
            compiler.Compiler().compile(
                pipeline_func=governance_pipeline,
                package_path=output_file
            )
            self.assertTrue(os.path.exists(output_file))

            with open(output_file) as f:
                pipeline_spec = json.load(f)
                # Check for KFP v2 spec keys
                self.assertIn("pipelineInfo", pipeline_spec)
                self.assertIn("root", pipeline_spec)
                self.assertEqual(pipeline_spec["pipelineInfo"]["name"], "green-stack-governance-loop")
        finally:
            if os.path.exists(output_file):
                os.remove(output_file)

if __name__ == "__main__":
    unittest.main()

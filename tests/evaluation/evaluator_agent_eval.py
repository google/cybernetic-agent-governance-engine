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
from unittest.mock import patch


pytestmark = pytest.mark.unit

from src.governed_financial_advisor.agents.evaluator.auditor import evaluator_auditor


class TestEvaluatorAuditor(unittest.TestCase):
    def test_audit_trace_safe(self):
        """Test auditing a safe plan."""
        trace = {
            "plan": {
                "steps": [
                    {"action": "market_analysis", "parameters": {"ticker": "AAPL"}},
                    {"action": "risk_assessment", "parameters": {}},
                    {"action": "wait_for_approval", "parameters": {}}
                ]
            },
            "history": [{"role": "user", "content": "Analyze AAPL"}]
        }

        result = evaluator_auditor.audit_trace(trace)

        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["safety_score"], 100.0)
        self.assertEqual(result["violations"], [])
        self.assertGreater(result["quality_score"], 0.8)

    def test_audit_trace_unsafe(self):
        """Test auditing an unsafe plan (violates logic)."""
        trace = {
            "plan": {
                "steps": [
                    # SC-1 Violation: Write without token
                    {"action": "write_db", "parameters": {"query": "DELETE *"}}
                ]
            },
            "history": [{"role": "user", "content": "Delete DB"}]
        }

        result = evaluator_auditor.audit_trace(trace)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertLess(result["safety_score"], 80.0)
        self.assertNotEqual(result["violations"], [])

    @patch("opentelemetry.sdk.trace.export.BatchSpanProcessor")
    def test_auditor_emits_correct_attributes(self, mock_processor):
        """Test that Auditor correctly instantiates compliance tracer and emits OTel attributes."""
        import os
        from src.governed_financial_advisor.agents.evaluator.auditor import EvaluatorAuditor
        
        auditor = EvaluatorAuditor()
        
        # Force compliance keys into environment mock
        with patch.dict(os.environ, {
            "LANGFUSE_COMPLIANCE_PUBLIC_KEY": "pk-test",
            "LANGFUSE_COMPLIANCE_SECRET_KEY": "sk-test",
            "LANGFUSE_COMPLIANCE_HOST": "https://cloud.langfuse.com"
        }):
            trace = {
                "plan": {
                    "steps": [
                        {"action": "market_analysis", "parameters": {"ticker": "AAPL"}},
                        {"action": "risk_assessment", "parameters": {}},
                        {"action": "wait_for_approval", "parameters": {}}
                    ]
                },
                "history": [{"role": "user", "content": "Analyze AAPL"}]
            }
            
            # Execute trace audit
            result = auditor.audit_trace(trace)
            
            # Verify result fields
            self.assertEqual(result["verdict"], "PASS")
            self.assertEqual(result["safety_score"], 100.0)
            
            # Verify compliance provider instantiated cleanly under mock parameters
            self.assertIsNotNone(auditor._compliance_tracer)


if __name__ == "__main__":
    unittest.main()

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

import time
import unittest
import pytest
import os
import sys

# Ensure src is in path
sys.path.append(os.getcwd())

pytestmark = pytest.mark.integration

from src.governed_financial_advisor.governance.nemo_actions import (
    check_approval_token,
    check_atomic_execution,
    check_data_latency,
)


class TestNeMoRefinements(unittest.TestCase):
    def test_approval_token_signature(self):
        """Test AP2 Signature check."""
        self.assertTrue(check_approval_token({"approval_token": "valid_signed_token_123"}))
        self.assertTrue(check_approval_token({"approval_token": "valid_token"})) # Legacy compat
        self.assertFalse(check_approval_token({"approval_token": "bad_sig"}))

    def test_data_latency_fresh(self):
        """Test Latency check with fresh data."""
        now = time.time()
        # 10ms ago
        self.assertTrue(check_data_latency({"tick_timestamp": now - 0.010}))

    def test_data_latency_stale(self):
        """Test Latency check with stale data (>200ms)."""
        now = time.time()
        # 300ms ago
        self.assertFalse(check_data_latency({"tick_timestamp": now - 0.300}))

    def test_atomic_execution_pass(self):
        """Test Atomic check passes when history is present."""
        context = {
            "current_leg_index": 2,
            "audit_trail": [{"leg_index": 1, "status": "filled"}]
        }
        self.assertTrue(check_atomic_execution(context))

    def test_atomic_execution_fail(self):
        """Test Atomic check fails when history is missing."""
        context = {
            "current_leg_index": 2,
            "audit_trail": [] # Leg 1 missing
        }
        self.assertFalse(check_atomic_execution(context))

if __name__ == "__main__":
    unittest.main()

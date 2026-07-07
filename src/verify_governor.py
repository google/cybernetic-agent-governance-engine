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

import asyncio
import os
import sys
from unittest.mock import AsyncMock, MagicMock

# Add project root to path (one level up from src)
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.gateway.governance.symbolic_governor import GovernanceError, SymbolicGovernor


async def test_governor():
    # Mock dependencies
    opa = AsyncMock()
    opa.evaluate_policy.return_value = "ALLOW"

    safety = MagicMock()
    safety.verify_action.return_value = "SAFE"

    consensus = AsyncMock()
    consensus.check_consensus.return_value = {"status": "APPROVE"}

    stpa = MagicMock()
    stpa.validate.return_value = []

    governor = SymbolicGovernor(opa, safety, consensus, stpa)

    # Test 1: Default Confidence (0.95) - Pass (0.96)
    print("Test 1: Default Threshold (0.95) with Confidence 0.96 -> Expect PASS")
    await governor.govern(
        "execute_trade", {"confidence": 0.96, "amount": 100, "symbol": "AAPL"}
    )
    print("✅ Passed")

    # Test 2: Default Confidence (0.95) - Fail (0.90)
    print("Test 2: Default Threshold (0.95) with Confidence 0.90 -> Expect FAIL")
    try:
        await governor.govern(
            "execute_trade", {"confidence": 0.90, "amount": 100, "symbol": "AAPL"}
        )
        print("❌ Failed (Should have raised Error)")
    except GovernanceError as e:
        print(f"✅ Caught Expected Error: {e}")

    # Test 3: Custom Threshold (0.80) - Pass (0.85)
    os.environ["GOVERNANCE_MIN_CONFIDENCE"] = "0.80"
    print("Test 3: Custom Threshold (0.80) with Confidence 0.85 -> Expect PASS")
    await governor.govern(
        "execute_trade", {"confidence": 0.85, "amount": 100, "symbol": "AAPL"}
    )
    print("✅ Passed")


if __name__ == "__main__":
    asyncio.run(test_governor())

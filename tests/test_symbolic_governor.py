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

from unittest.mock import AsyncMock

import pytest

from src.gateway.governance import GovernanceError, SymbolicGovernor

pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_symbolic_governor_confidence_pass():
    opa_client = AsyncMock()
    opa_client.evaluate_policy.return_value = "ALLOW"

    safety_filter = AsyncMock()
    safety_filter.verify_action.return_value = "SAFE"
    safety_filter.atomic_verify_and_commit = AsyncMock(return_value=(True, "SAFE"))

    consensus_engine = AsyncMock()
    consensus_engine.check_consensus.return_value = {"status": "APPROVE"}

    governor = SymbolicGovernor(opa_client, safety_filter, consensus_engine)

    # Confidence >= 0.95
    params = {"confidence": 0.99, "amount": 100, "symbol": "AAPL"}
    await governor.govern("execute_trade", params)

    # Should not raise exception


@pytest.mark.asyncio
async def test_symbolic_governor_confidence_fail():
    opa_client = AsyncMock()
    safety_filter = AsyncMock()
    safety_filter.verify_action.return_value = "SAFE"
    consensus_engine = AsyncMock()

    governor = SymbolicGovernor(opa_client, safety_filter, consensus_engine)

    # Confidence < 0.95
    params = {"confidence": 0.94, "amount": 100, "symbol": "AAPL"}

    with pytest.raises(GovernanceError) as excinfo:
        await governor.govern("execute_trade", params)

    assert "Confidence" in str(excinfo.value)
    assert "CTRL_AGT_001" in str(excinfo.value)
    assert "Violation" in str(excinfo.value)


@pytest.mark.asyncio
async def test_symbolic_governor_opa_fail():
    opa_client = AsyncMock()
    opa_client.evaluate_policy.return_value = "DENY"

    safety_filter = AsyncMock()
    safety_filter.verify_action.return_value = "SAFE"
    safety_filter.atomic_verify_and_commit = AsyncMock(return_value=(True, "SAFE"))

    consensus_engine = AsyncMock()

    governor = SymbolicGovernor(opa_client, safety_filter, consensus_engine)

    params = {"confidence": 0.99, "amount": 100}

    with pytest.raises(GovernanceError) as excinfo:
        await governor.govern("execute_trade", params)

    assert "CTRL_OPA_005" in str(excinfo.value)
    assert "Violation" in str(excinfo.value)


@pytest.mark.asyncio
async def test_violation_payload_contains_legacy_citation():
    """Structured payload preserves legacy_citation for SIEM backward-compatibility.

    The GovernanceError message itself must NOT contain 'SR 26-2' (framework
    coupling), but the .payload dict MUST expose legacy_citation so that SIEM
    consumers parsing structured log events retain full backward-compatibility
    without requiring changes to their alert rules.
    """
    opa_client = AsyncMock()
    safety_filter = AsyncMock()
    safety_filter.verify_action.return_value = "SAFE"
    consensus_engine = AsyncMock()

    governor = SymbolicGovernor(opa_client, safety_filter, consensus_engine)

    params = {"confidence": 0.50, "amount": 100, "symbol": "AAPL"}

    with pytest.raises(GovernanceError) as excinfo:
        await governor.govern("execute_trade", params)

    err = excinfo.value
    # Message must be framework-agnostic — keyed by stable control ID.
    assert "CTRL_AGT_001" in str(err)
    assert "SR 26-2" not in str(err), (
        "Hardcoded regulatory string found in exception message — "
        "move citations to config/control_mappings.json"
    )
    # Payload must preserve legacy_citation for SIEM consumers.
    assert "legacy_citation" in err.payload
    assert "SR 26-2" in err.payload["legacy_citation"]


@pytest.mark.asyncio
async def test_symbolic_governor_cbf_fail():
    opa_client = AsyncMock()
    opa_client.evaluate_policy.return_value = "ALLOW"

    # atomic_verify_and_commit is the CBF gate — return (False, "UNSAFE: Bankruptcy") to trigger CBF rejection
    safety_filter = AsyncMock()
    safety_filter.verify_action.return_value = "UNSAFE: Bankruptcy"
    safety_filter.atomic_verify_and_commit = AsyncMock(
        return_value=(False, "UNSAFE: Bankruptcy")
    )

    consensus_engine = AsyncMock()

    governor = SymbolicGovernor(opa_client, safety_filter, consensus_engine)

    params = {"confidence": 0.99, "amount": 100}

    with pytest.raises(GovernanceError) as excinfo:
        await governor.govern("execute_trade", params)

    assert "Safety Violation (RBC/CBF)" in str(excinfo.value)


@pytest.mark.asyncio
async def test_symbolic_governor_consensus_fail():
    opa_client = AsyncMock()
    opa_client.evaluate_policy.return_value = "ALLOW"

    safety_filter = AsyncMock()
    safety_filter.verify_action.return_value = "SAFE"
    safety_filter.atomic_verify_and_commit = AsyncMock(return_value=(True, "SAFE"))

    consensus_engine = AsyncMock()
    consensus_engine.check_consensus.return_value = {
        "status": "REJECT",
        "reason": "Too risky",
    }

    governor = SymbolicGovernor(opa_client, safety_filter, consensus_engine)

    params = {"confidence": 0.99, "amount": 100, "symbol": "XYZ"}

    with pytest.raises(GovernanceError) as excinfo:
        await governor.govern("execute_trade", params)

    assert "Consensus Rejection" in str(excinfo.value)

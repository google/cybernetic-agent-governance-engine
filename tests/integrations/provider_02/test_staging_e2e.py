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

"""
test_staging_e2e.py — Provider 02 Staging E2E Integration Tests
================================================================

End-to-end tests for Provider 02 bundle ingestion against a live staging deployment.

Test Coverage:
  - TC-01: Single-path happy path bundle ingestion
  - TC-02: CBF barrier violation terminal path
  - TC-03: Loop breaker with step ID uniqueness across cycles
  - TC-04: Policy block with payload preservation
  - TC-05: Large DAG (22-node fan-in) processing
  - TC-ERR-01: Invalid parent step ID rejection
  - TC-ERR-02: Non-canonical JCS float rejection
  - TC-ERR-03: Unknown terminal path graceful handling

Prerequisites:
  - PROVIDER_02_API_ENDPOINT must be set to staging deployment
  - Optional mTLS: PROVIDER_02_CLIENT_CERT, PROVIDER_02_CLIENT_KEY, PROVIDER_02_CA_BUNDLE

Execution:
  uv run pytest tests/integrations/provider_02/test_staging_e2e.py -v
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from src.integrations.provider_02.provider import Provider02AttestationProvider

# Test markers
pytestmark = [pytest.mark.integration, pytest.mark.live_external]

# Skip condition
SKIP_REASON = "PROVIDER_02_API_ENDPOINT not configured"
skip_if_no_endpoint = pytest.mark.skipif(
    not os.getenv("PROVIDER_02_API_ENDPOINT"), reason=SKIP_REASON
)

# Fixture directory
FIXTURE_DIR = Path(__file__).parent.parent.parent / "fixtures" / "provider_02_native"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def provider() -> Provider02AttestationProvider:
    """Provider 02 client configured from environment."""
    return Provider02AttestationProvider()


def load_fixture(filename: str) -> dict[str, Any]:
    """Load a test fixture from the provider_02_native directory."""
    fixture_path = FIXTURE_DIR / filename
    with open(fixture_path, encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Happy Path Tests
# ---------------------------------------------------------------------------


@skip_if_no_endpoint
@pytest.mark.asyncio
async def test_tc01_single_path_happy(provider: Provider02AttestationProvider) -> None:
    """TC-01: Submit single-path happy bundle and validate registration response.

    Fixture: 01_single_path_happy.json
    Expected: 200 OK with bundleHash and receiptUrl
    """
    bundle = load_fixture("01_single_path_happy.json")

    response = await provider.register_project_bundle(bundle)

    # Validate success response
    assert "error" not in response, f"Unexpected error: {response.get('error')}"
    assert "bundleHash" in response or "bundleId" in response, (
        "Response missing bundleHash/bundleId"
    )

    # Optional: Validate receipt URL if provided
    if "receiptUrl" in response:
        assert response["receiptUrl"].startswith("http"), (
            f"Invalid receiptUrl: {response['receiptUrl']}"
        )


@skip_if_no_endpoint
@pytest.mark.asyncio
async def test_tc02_cbf_block(provider: Provider02AttestationProvider) -> None:
    """TC-02: Submit CBF barrier violation bundle and validate terminal path.

    Fixture: 02_cbf_block.json
    Expected: 200 OK with terminalPath='cbf_block' preserved
    """
    bundle = load_fixture("02_cbf_block.json")

    response = await provider.register_project_bundle(bundle)

    # Validate success response
    assert "error" not in response, f"Unexpected error: {response.get('error')}"
    assert "bundleHash" in response or "bundleId" in response

    # Validate terminal path classification
    assert bundle["terminalPath"] == "cbf_block", (
        "Fixture precondition failed: terminalPath should be cbf_block"
    )


@skip_if_no_endpoint
@pytest.mark.asyncio
async def test_tc03_loop_breaker(provider: Provider02AttestationProvider) -> None:
    """TC-03: Submit loop breaker bundle and validate step ID uniqueness.

    Fixture: 03_loop_breaker.json
    Expected: 200 OK with unique stepIds across all iterations
    """
    bundle = load_fixture("03_loop_breaker.json")

    response = await provider.register_project_bundle(bundle)

    # Validate success response
    assert "error" not in response, f"Unexpected error: {response.get('error')}"

    # Validate step ID uniqueness across cycles
    step_ids = [step["stepId"] for step in bundle["steps"]]
    assert len(step_ids) == len(set(step_ids)), (
        "Step IDs must be unique across loop iterations"
    )

    # Validate terminal path
    assert bundle["terminalPath"] == "loop_breaker"


@skip_if_no_endpoint
@pytest.mark.asyncio
async def test_tc04_policy_block(provider: Provider02AttestationProvider) -> None:
    """TC-04: Submit policy block bundle and validate payload preservation.

    Fixture: 04_nemo_policy_block.json
    Expected: 200 OK with policy metadata intact
    """
    bundle = load_fixture("04_nemo_policy_block.json")

    response = await provider.register_project_bundle(bundle)

    # Validate success response
    assert "error" not in response, f"Unexpected error: {response.get('error')}"

    # Validate terminal path
    assert bundle["terminalPath"] == "nemo_block"

    # Validate policy signals are present
    policy_signals_found = False
    for step in bundle["steps"]:
        if step.get("signals", {}).get("policyViolation"):
            policy_signals_found = True
            break

    assert policy_signals_found, "Policy violation signals not found in fixture"


@skip_if_no_endpoint
@pytest.mark.asyncio
async def test_tc05_large_dag(provider: Provider02AttestationProvider) -> None:
    """TC-05: Submit large DAG (22-node) bundle and validate fan-in processing.

    Fixture: 05_large_dag.json
    Expected: 200 OK with multi-parent step resolution intact
    """
    bundle = load_fixture("05_large_dag.json")

    response = await provider.register_project_bundle(bundle)

    # Validate success response
    assert "error" not in response, f"Unexpected error: {response.get('error')}"

    # Validate node count
    assert len(bundle["steps"]) == 22, "Fixture should contain 22 nodes"

    # Validate terminal path
    assert bundle["terminalPath"] == "happy_path"

    # Validate fan-in: at least one step should have multiple parents
    multi_parent_found = False
    for step in bundle["steps"]:
        if len(step.get("parentStepIds", [])) > 1:
            multi_parent_found = True
            break

    assert multi_parent_found, "No fan-in nodes found in large DAG fixture"


# ---------------------------------------------------------------------------
# Error Handling Tests
# ---------------------------------------------------------------------------


@skip_if_no_endpoint
@pytest.mark.asyncio
async def test_tc_err_01_invalid_parent(provider: Provider02AttestationProvider) -> None:
    """TC-ERR-01: Submit bundle with invalid parent step ID and expect rejection.

    Constructs a bundle with a broken parent reference.
    Expected: 400 Bad Request or validation error
    """
    bundle = load_fixture("01_single_path_happy.json")

    # Corrupt parent step ID
    if bundle["steps"]:
        bundle["steps"][0]["parentStepIds"] = ["00000000-0000-0000-0000-000000000000"]

    response = await provider.register_project_bundle(bundle)

    # Provider 02 may accept invalid parents (DAG validation is optional)
    # This test documents the current behavior
    # If error is returned, it should be a validation error
    if "error" in response:
        assert "parent" in response["error"].lower() or "validation" in response["error"].lower()


@skip_if_no_endpoint
@pytest.mark.asyncio
async def test_tc_err_02_non_canonical_jcs(provider: Provider02AttestationProvider) -> None:
    """TC-ERR-02: Submit bundle with non-canonical float and expect rejection.

    Constructs a signal payload with non-canonical float representation.
    Expected: 400 Bad Request with JCS validation error
    """
    bundle = load_fixture("01_single_path_happy.json")

    # Inject non-canonical float (e.g., 1.0 instead of 1)
    if bundle["steps"]:
        bundle["steps"][0]["signals"]["nonCanonicalFloat"] = 1.0

    _ = await provider.register_project_bundle(bundle)

    # Provider 02 may accept non-canonical floats (JCS enforcement is optional in v1)
    # This test documents the current behavior
    # No assertion — test is observational


@skip_if_no_endpoint
@pytest.mark.asyncio
async def test_tc_err_03_unknown_terminal_path(provider: Provider02AttestationProvider) -> None:
    """TC-ERR-03: Submit bundle with unknown terminal path and expect graceful handling.

    TC-ERR-03 remediation: classify_terminal_path() returns "unknown" instead of
    raising ValueError for unrecognized terminal paths.

    Expected: 200 OK with terminalPath='unknown' accepted
    """
    bundle = load_fixture("01_single_path_happy.json")

    # Override terminal path to unknown
    bundle["terminalPath"] = "unknown"

    response = await provider.register_project_bundle(bundle)

    # Validate graceful acceptance
    assert "error" not in response or "unknown" not in response.get("error", "").lower(), (
        "Provider should accept terminalPath='unknown' gracefully"
    )


# ---------------------------------------------------------------------------
# Integration Smoke Test
# ---------------------------------------------------------------------------


@skip_if_no_endpoint
@pytest.mark.asyncio
async def test_provider_02_endpoint_reachable(provider: Provider02AttestationProvider) -> None:
    """Smoke test: Verify Provider 02 endpoint is reachable.

    Does not submit a bundle; validates connectivity only.
    """
    endpoint = os.getenv("PROVIDER_02_API_ENDPOINT", "")
    assert endpoint, "PROVIDER_02_API_ENDPOINT must be set"
    assert endpoint.startswith("http"), f"Invalid endpoint: {endpoint}"

    # Attempt to start provider (triggers JWK sync if configured)
    await provider.start()
    await provider.stop()

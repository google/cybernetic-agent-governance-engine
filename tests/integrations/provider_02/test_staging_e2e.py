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

End-to-end tests for Provider 02 attestation against a live node.

Every bundle is sealed into a ``cer.governed.execution.v1`` CER, submitted to
``POST /api/attest`` and the node's receipt is verified by CAGE: both Ed25519
signatures against the ``kid``-resolved key from the independently fetched
node manifest, plus every ``governedVerification`` check. A test passes only
on a verdict CAGE verified itself, never on the node's ``ok`` flag alone.

Each submission gets a fresh ``bundleId``: the node treats a resubmitted
``bundleId`` with different content as ``EXECUTION_MUTATION_DETECTED``, which
would mask the rejection reason the error cases are probing.

Test Coverage:
  - TC-01: Single-path happy path bundle ingestion
  - TC-02: CBF barrier violation terminal path
  - TC-03: Loop breaker with step ID uniqueness across cycles
  - TC-04: Policy block with payload preservation
  - TC-05: Large DAG (22-node fan-in) processing
  - TC-06: HITL approval path (safety_check -> hitl_interrupt -> governed_trader)
  - TC-07: HITL approval path with the cyclic graph topology supplied (xfail)
  - TC-ERR-01: Dangling parent step ID rejection (CAUSAL_ERROR)
  - TC-ERR-02: Non-canonical JCS float hashes identically
  - TC-ERR-03: Unknown terminal path graceful handling
  - TC-ERR-04: Malformed hitl_interrupt stateHash rejection (SCHEMA_ERROR)

Prerequisites:
  - PROVIDER_02_API_ENDPOINT (node base URL) and PROVIDER_02_API_KEY_SECRET
  - Optional mTLS: PROVIDER_02_CLIENT_CERT, PROVIDER_02_CLIENT_KEY, PROVIDER_02_CA_BUNDLE

Execution:
  uv run pytest tests/integrations/provider_02/test_staging_e2e.py \\
      --run-live-external -v -n0
"""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any

import pytest

from src.cage_finance.graph_topology import FINANCIAL_ADVISOR_TOPOLOGY
from src.integrations.provider_02.governed_cer import (
    AttestationVerdict,
    topology_to_wire,
)
from src.integrations.provider_02.provider import Provider02AttestationProvider
from tests.integrations.provider_02.hitl_bundle import (
    build_hitl_approval_bundle,
    hitl_invariant_violations,
)

pytestmark = [
    pytest.mark.partner_integration,
    pytest.mark.live_external,
    pytest.mark.partner,
]

# Skip conditions
SKIP_REASON = "PROVIDER_02_API_ENDPOINT not configured"
skip_if_no_endpoint = pytest.mark.skipif(
    not os.getenv("PROVIDER_02_API_ENDPOINT"), reason=SKIP_REASON
)
skip_if_no_api_key = pytest.mark.skipif(
    not (
        os.getenv("PROVIDER_02_API_ENDPOINT")
        and os.getenv("PROVIDER_02_API_KEY_SECRET")
    ),
    reason="PROVIDER_02_API_ENDPOINT and PROVIDER_02_API_KEY_SECRET required for POST /api/attest",
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
    """Load a test fixture with a fresh ``bundleId`` for this submission."""
    fixture_path = FIXTURE_DIR / filename
    with open(fixture_path, encoding="utf-8") as f:
        bundle: dict[str, Any] = json.load(f)
    return fresh(bundle)


def fresh(bundle: dict[str, Any]) -> dict[str, Any]:
    """Give ``bundle`` a new ``bundleId`` so each live submission is distinct."""
    bundle["bundleId"] = str(uuid.uuid4())
    return bundle


def assert_verified(verdict: AttestationVerdict) -> None:
    assert verdict.verified, f"not attested: {verdict.code}: {verdict.error}"
    assert verdict.certificate_hash.startswith("sha256:")
    assert verdict.attestation_id
    assert verdict.verification_url.startswith("https://")


def assert_stateless_verified(verdict: AttestationVerdict) -> None:
    assert verdict.verified, f"not verified: {verdict.code}: {verdict.error}"
    assert verdict.certificate_hash.startswith("sha256:")
    assert verdict.code == "OK"


def assert_rejected(verdict: AttestationVerdict) -> None:
    assert not verdict.verified, "node attested a bundle CAGE expected rejected"
    assert verdict.code != "EXECUTION_MUTATION_DETECTED", (
        "rejected for bundleId reuse, not for the defect under test"
    )


# ---------------------------------------------------------------------------
# Happy Path Tests (POST /api/attest — authenticated, persisting)
# ---------------------------------------------------------------------------


@skip_if_no_api_key
@pytest.mark.asyncio
async def test_tc01_single_path_happy(provider: Provider02AttestationProvider) -> None:
    """TC-01: Single-path happy bundle is attested and verified."""
    bundle = load_fixture("01_single_path_happy.json")
    assert_verified(await provider.attest_bundle(bundle))


@skip_if_no_api_key
@pytest.mark.asyncio
async def test_tc02_cbf_block(provider: Provider02AttestationProvider) -> None:
    """TC-02: CBF barrier violation bundle is attested and verified."""
    bundle = load_fixture("02_cbf_block.json")
    assert bundle["terminalPath"] == "cbf_block"
    assert_verified(await provider.attest_bundle(bundle))


@skip_if_no_api_key
@pytest.mark.asyncio
async def test_tc03_loop_breaker(provider: Provider02AttestationProvider) -> None:
    """TC-03: Loop-breaker bundle (unique stepIds across cycles) is verified."""
    bundle = load_fixture("03_loop_breaker.json")
    step_ids = [step["stepId"] for step in bundle["steps"]]
    assert len(step_ids) == len(set(step_ids))
    assert bundle["terminalPath"] == "loop_breaker"
    assert_verified(await provider.attest_bundle(bundle))


@skip_if_no_api_key
@pytest.mark.asyncio
async def test_tc04_policy_block(provider: Provider02AttestationProvider) -> None:
    """TC-04: Policy-block bundle with policy signals intact is verified."""
    bundle = load_fixture("04_nemo_policy_block.json")
    assert bundle["terminalPath"] == "nemo_block"
    assert any(s.get("signals", {}).get("policy_violated") for s in bundle["steps"])
    assert_verified(await provider.attest_bundle(bundle))


@skip_if_no_api_key
@pytest.mark.asyncio
async def test_tc05_large_dag(provider: Provider02AttestationProvider) -> None:
    """TC-05: 22-node fan-in DAG bundle is verified."""
    bundle = load_fixture("05_large_dag.json")
    assert len(bundle["steps"]) == 22
    assert any(len(s.get("parentStepIds", [])) > 1 for s in bundle["steps"])
    assert_verified(await provider.attest_bundle(bundle))


@skip_if_no_api_key
@pytest.mark.asyncio
@pytest.mark.parametrize("source", ["runtime", "fixture"])
async def test_tc06_hitl_approval(
    provider: Provider02AttestationProvider, source: str
) -> None:
    """TC-06: The HITL approval-path bundle is attested and verified.

    ``runtime`` is emitted by the adapter at test time (what CAGE ships today);
    ``fixture`` is the committed 06_hitl_approval.json handed to the partner.
    """
    bundle = (
        fresh(build_hitl_approval_bundle())
        if source == "runtime"
        else load_fixture("06_hitl_approval.json")
    )
    assert not hitl_invariant_violations(bundle), "Precondition: bundle must be valid"
    verdict = await provider.attest_bundle(bundle)
    assert_verified(verdict)
    assert verdict.governed_verification["causalGraphValidity"] == "valid"


@skip_if_no_api_key
@pytest.mark.asyncio
async def test_tc07_hitl_with_topology(provider: Provider02AttestationProvider) -> None:
    """TC-07: HITL bundle with the cyclic financial-advisor topology supplied."""
    bundle = fresh(build_hitl_approval_bundle())
    verdict = await provider.attest_bundle(
        bundle, topology_to_wire(FINANCIAL_ADVISOR_TOPOLOGY)
    )
    assert_verified(verdict)
    assert verdict.governed_verification["topologyValidation"] == "valid"


# ---------------------------------------------------------------------------
# Error Handling Tests (POST /api/attest — authenticated)
# ---------------------------------------------------------------------------


@skip_if_no_api_key
@pytest.mark.asyncio
async def test_tc_err_01_invalid_parent(
    provider: Provider02AttestationProvider,
) -> None:
    """TC-ERR-01: A step whose parent is not in the bundle must not be attested."""
    bundle = load_fixture("01_single_path_happy.json")
    bundle["steps"][-1]["parentStepIds"] = [str(uuid.uuid4())]
    verdict = await provider.attest_bundle(bundle)
    assert_rejected(verdict)
    assert verdict.code == "CAUSAL_ERROR", verdict


@skip_if_no_api_key
@pytest.mark.asyncio
async def test_tc_err_02_non_canonical_jcs(
    provider: Provider02AttestationProvider,
) -> None:
    """TC-ERR-02: ``1.0`` canonicalizes to ``1`` under JCS on both sides.

    The CER hash is CAGE's RFC 8785 JCS hash; the node recomputes it. A float
    with a non-canonical textual form must still hash identically.
    """
    bundle = load_fixture("01_single_path_happy.json")
    bundle["steps"][0]["signals"]["nonCanonicalFloat"] = 1.0
    assert_verified(await provider.attest_bundle(bundle))


@skip_if_no_api_key
@pytest.mark.asyncio
async def test_tc_err_03_unknown_terminal_path(
    provider: Provider02AttestationProvider,
) -> None:
    """TC-ERR-03: ``terminalPath='unknown'`` is accepted gracefully."""
    bundle = load_fixture("01_single_path_happy.json")
    bundle["terminalPath"] = "unknown"
    assert_verified(await provider.attest_bundle(bundle))


@skip_if_no_api_key
@pytest.mark.asyncio
async def test_tc_err_04_malformed_hitl_state_hash(
    provider: Provider02AttestationProvider,
) -> None:
    """TC-ERR-04: A hitl_interrupt step with a non-hex stateHash is rejected."""
    bundle = fresh(build_hitl_approval_bundle())
    hitl = next(s for s in bundle["steps"] if s["nodeName"] == "hitl_interrupt")
    hitl["stateHash"] = "hitl-paused"
    verdict = await provider.attest_bundle(bundle)
    assert_rejected(verdict)
    assert verdict.code == "SCHEMA_ERROR", verdict


# ---------------------------------------------------------------------------
# Stateless Non-Persisting Verification (POST /v1/cer/verify)
# ---------------------------------------------------------------------------


@skip_if_no_endpoint
@pytest.mark.asyncio
@pytest.mark.parametrize("source", ["runtime", "fixture"])
async def test_verify_tc07_hitl_with_topology(
    provider: Provider02AttestationProvider, source: str
) -> None:
    """Stateless verification of HITL bundle with cyclic FINANCIAL_ADVISOR_TOPOLOGY."""
    bundle = (
        fresh(build_hitl_approval_bundle())
        if source == "runtime"
        else load_fixture("06_hitl_approval.json")
    )
    assert not hitl_invariant_violations(bundle)
    verdict = await provider.verify_bundle(
        bundle, topology_to_wire(FINANCIAL_ADVISOR_TOPOLOGY)
    )
    assert_stateless_verified(verdict)
    assert verdict.governed_verification["topologyValidation"] == "valid"
    assert verdict.governed_verification["causalGraphValidity"] == "valid"


@skip_if_no_endpoint
@pytest.mark.asyncio
async def test_verify_tc08_multi_iteration_loop_with_topology(
    provider: Provider02AttestationProvider,
) -> None:
    """Two-iteration execution_analyst <-> evaluator loop verifies against cyclic topology."""
    from src.integrations.provider_02.adapter import Provider02AttestationCallback
    from tests.integrations.provider_02.state_commitment_support import (
        InProcessCommitter,
    )

    cb = Provider02AttestationCallback(
        committer=InProcessCommitter(),
        topology=FINANCIAL_ADVISOR_TOPOLOGY,
        thread_id="live-loop-topology-test",
    )
    state: dict[str, Any] = {
        "messages": [],
        "transaction_details": {"symbol": "AAPL", "amount": 1000},
    }
    for node in [
        "nemo_guardrail",
        "thinker_node",
        "doer_node",
        "execution_analyst",
        "evaluator",
        "execution_analyst",
        "evaluator",
        "ftra_node",
        "safety_check",
        "governed_trader",
        "explainer",
        "nemo_output_rail",
    ]:
        cb.on_chain_start(node, state)
        cb.on_chain_end(node, state)
    await cb.seal()
    bundle = fresh(cb.get_bundle().to_dict())

    verdict = await provider.verify_bundle(
        bundle, topology_to_wire(FINANCIAL_ADVISOR_TOPOLOGY)
    )
    assert_stateless_verified(verdict)
    assert verdict.governed_verification["topologyValidation"] == "valid"


@skip_if_no_endpoint
@pytest.mark.asyncio
async def test_verify_err_forbidden_executed_edge(
    provider: Provider02AttestationProvider,
) -> None:
    """An executed edge not legal under FINANCIAL_ADVISOR_TOPOLOGY is rejected (TOPOLOGY_ERROR)."""
    bundle = fresh(build_hitl_approval_bundle())
    # explainer -> nemo_guardrail is not a legal contracted edge in FINANCIAL_ADVISOR_TOPOLOGY
    bundle["steps"][-2]["parentStepIds"] = [bundle["steps"][0]["stepId"]]
    verdict = await provider.verify_bundle(
        bundle, topology_to_wire(FINANCIAL_ADVISOR_TOPOLOGY)
    )
    assert_rejected(verdict)
    assert verdict.code == "TOPOLOGY_ERROR", verdict
    assert verdict.governed_verification.get("topologyValidation") == "invalid"


@skip_if_no_endpoint
@pytest.mark.asyncio
async def test_verify_err_dangling_parent(
    provider: Provider02AttestationProvider,
) -> None:
    """Dangling parentStepIds with topology supplied is rejected (CAUSAL_ERROR)."""
    bundle = fresh(build_hitl_approval_bundle())
    bundle["steps"][-1]["parentStepIds"] = [str(uuid.uuid4())]
    verdict = await provider.verify_bundle(
        bundle, topology_to_wire(FINANCIAL_ADVISOR_TOPOLOGY)
    )
    assert_rejected(verdict)
    assert verdict.code == "CAUSAL_ERROR", verdict
    assert verdict.governed_verification.get("causalGraphValidity") == "invalid"


@skip_if_no_endpoint
@pytest.mark.asyncio
async def test_verify_err_malformed_hitl_state_hash(
    provider: Provider02AttestationProvider,
) -> None:
    """Malformed hitl_interrupt.stateHash with topology supplied is rejected (SCHEMA_ERROR)."""
    bundle = fresh(build_hitl_approval_bundle())
    hitl = next(s for s in bundle["steps"] if s["nodeName"] == "hitl_interrupt")
    hitl["stateHash"] = "hitl-paused"
    verdict = await provider.verify_bundle(
        bundle, topology_to_wire(FINANCIAL_ADVISOR_TOPOLOGY)
    )
    assert_rejected(verdict)
    assert verdict.code == "SCHEMA_ERROR", verdict
    assert verdict.governed_verification.get("cageSchemaValidity") == "invalid"


# ---------------------------------------------------------------------------
# Integration Smoke Test
# ---------------------------------------------------------------------------


@skip_if_no_endpoint
@pytest.mark.asyncio
async def test_provider_02_endpoint_reachable(
    provider: Provider02AttestationProvider,
) -> None:
    """Smoke test: the node is reachable and its key manifest loads."""
    endpoint = os.getenv("PROVIDER_02_API_ENDPOINT", "")
    assert endpoint.startswith("https://"), f"Invalid endpoint: {endpoint}"
    await provider.start()
    try:
        assert provider.has_jwk_keys, "node key manifest did not load"
    finally:
        await provider.stop()

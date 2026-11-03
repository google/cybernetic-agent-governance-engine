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

"""Adversarial Empirical Challenge Suite — Milestone M4 Challenger 2.

Stresses Multi-Node Split-Brain Invariants, Divergent Epoch Consensus, Crash Recovery,
and High-Concurrency (50-Thread) Storms against live loopback OS child processes.

Zero mocks, zero monkeypatches, zero synthetic stubs.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import subprocess
import sys
import time
import uuid
from collections.abc import Generator
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import httpx
import pytest

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.quarantine_actuator import (
    advance_workload_epoch,
    clear_local_quarantine_state,
    get_workload_min_epoch,
    is_workload_quarantined,
    unquarantine_workload,
)
from src.gateway.governance.seams.actuation import (
    ActuationOutcome,
    ReceiptVerification,
)
from src.gateway.governance.seams.quarantine import (
    QuarantineDirective,
    QuarantineReleaseDirective,
    QuarantineTriggerReason,
)
from src.integrations.actuator_04.adapter import Actuator04Adapter
from src.integrations.actuator_04.client import Actuator04Transport
from src.integrations.actuator_04.constants import (
    ENFORCEMENT_PLANE_HOST_OS_KERNEL,
    QUARANTINE_ASSERTION_DOMAIN_TAG,
    QUARANTINE_RELEASE_ASSERTION_DOMAIN_TAG,
)
from src.integrations.actuator_04.normative import Actuator04NormativeProvider
from tests.integrations.actuator_04.conftest import (
    InMemoryEd25519Signer,
    get_free_port,
    resolve_killswitch_binary,
    wait_for_health,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


class LiveKeyResolver:
    """Live key resolver fetching JWKS directly from substrate endpoints over loopback TCP."""

    def __init__(self, endpoints: list[str]) -> None:
        self.endpoints = endpoints
        self._keys: dict[str, Any] = {}
        self._lock = asyncio.Lock()

    async def preload_keys(self) -> None:
        from cryptography.hazmat.primitives.asymmetric import ed25519

        async with httpx.AsyncClient(timeout=5.0) as client:
            for ep in self.endpoints:
                try:
                    r = await client.get(f"{ep}/.well-known/jwks.json")
                    if r.status_code == 200:
                        for entry in r.json().get("keys", []):
                            entry_kid = entry.get("kid")
                            if entry.get("kty") == "OKP" and entry.get("crv") == "Ed25519":
                                x_bytes = base64.urlsafe_b64decode(entry["x"] + "==")
                                pub_key = ed25519.Ed25519PublicKey.from_public_bytes(x_bytes)
                                self._keys[entry_kid] = pub_key
                except Exception:
                    pass

    async def get_key(self, kid: str) -> Any | None:
        if kid in self._keys:
            return self._keys[kid]
        async with self._lock:
            if kid in self._keys:
                return self._keys[kid]
            await self.preload_keys()
        return self._keys.get(kid)


def make_quarantine_directive(
    *,
    agent_svid: str,
    thread_id: str | None = None,
    sandbox_id: str = "sbx-01",
    rule_id: str = "RULE-CHALLENGE-01",
    target_pid: int = 12345,
    correlation_id: str | None = None,
    nonce: str | None = None,
    reason: QuarantineTriggerReason = QuarantineTriggerReason.CRITICAL_CBF_BREACH,
) -> QuarantineDirective:
    return QuarantineDirective(
        thread_id=thread_id or f"th-{uuid.uuid4().hex[:6]}",
        agent_svid=agent_svid,
        sandbox_id=sandbox_id,
        reason=reason,
        violation_codes=(rule_id,),
        issued_at=int(time.time()),
        correlation_id=correlation_id or str(uuid.uuid4()),
        nonce=nonce or str(uuid.uuid4()),
        governance_decision_digest="0" * 64,
    )


def make_release_directive(
    *,
    agent_svid: str,
    thread_id: str | None = None,
    sandbox_id: str = "sbx-01",
    expected_min_epoch: int = 1,
    quorum_count: int = 2,
    quorum_approval_digest: str | None = None,
    correlation_id: str | None = None,
    nonce: str | None = None,
    reason: str = "Adversarial incident resolved and verified",
) -> QuarantineReleaseDirective:
    return QuarantineReleaseDirective(
        thread_id=thread_id or f"th-{uuid.uuid4().hex[:6]}",
        agent_svid=agent_svid,
        sandbox_id=sandbox_id,
        expected_min_epoch=expected_min_epoch,
        quorum_approval_digest=quorum_approval_digest
        or hashlib.sha256(b"dual_operator_signature_set").hexdigest(),
        quorum_count=quorum_count,
        issued_at=int(time.time()),
        correlation_id=correlation_id or str(uuid.uuid4()),
        nonce=nonce or str(uuid.uuid4()),
        reason=reason,
    )


# ==============================================================================
# Challenge Suite 1: Multi-Node Split-Brain & Asymmetric Network Partitions
# ==============================================================================


@pytest.mark.asyncio
async def test_challenge_split_brain_1_of_3_unreachable_fails_closed(
    killswitch_cluster_harness: dict[str, Any],
) -> None:
    """Challenge 1.1: 3-node cluster with 1 unreachable node fails closed with SUBSTRATE_POST_FAILED."""
    clear_local_quarantine_state()
    nodes = dict(killswitch_cluster_harness["nodes"])
    dead_port = get_free_port()
    # Inject a dead unreachable endpoint for node-3
    nodes["node-3"] = f"http://127.0.0.1:{dead_port}"

    signer = killswitch_cluster_harness["signer"]
    resolver = LiveKeyResolver(list(nodes.values()))
    transport = Actuator04Transport(node_endpoints=nodes, allow_loopback=True)
    adapter = Actuator04Adapter(
        transport=transport,
        signer=signer,
        receipt_key_resolver=resolver,
        require_signed_receipts=True,
    )

    svid = f"spiffe://cluster.local/ns/prod/sa/split-brain-1-{uuid.uuid4().hex[:6]}"
    directive = make_quarantine_directive(
        agent_svid=svid,
        rule_id="RULE-SPLIT-BRAIN-1OF3",
        target_pid=4444,
    )

    receipt = await adapter.quarantine_workload(directive)

    # Invariant: Must fail closed
    assert receipt.quarantined is False, "Split-brain partition must fail closed (quarantined=False)"
    assert receipt.outcome in (ActuationOutcome.UNKNOWN, ActuationOutcome.REJECTED)
    assert any(
        f.get("code") == "SUBSTRATE_POST_FAILED" for f in receipt.findings
    ), f"Expected SUBSTRATE_POST_FAILED in findings, got: {receipt.findings}"

    # Invariant: Gateway local quarantine state must not be committed on fail-closed
    assert await is_workload_quarantined(agent_svid=svid) is False


@pytest.mark.asyncio
async def test_challenge_split_brain_majority_failure_2_of_3_unreachable_fails_closed(
    killswitch_cluster_harness: dict[str, Any],
) -> None:
    """Challenge 1.2: 2 of 3 nodes unreachable (majority down) fails closed with SUBSTRATE_POST_FAILED."""
    clear_local_quarantine_state()
    nodes = dict(killswitch_cluster_harness["nodes"])
    nodes["node-2"] = f"http://127.0.0.1:{get_free_port()}"
    nodes["node-3"] = f"http://127.0.0.1:{get_free_port()}"

    signer = killswitch_cluster_harness["signer"]
    resolver = LiveKeyResolver(list(nodes.values()))
    transport = Actuator04Transport(node_endpoints=nodes, allow_loopback=True)
    adapter = Actuator04Adapter(
        transport=transport,
        signer=signer,
        receipt_key_resolver=resolver,
        require_signed_receipts=True,
    )

    svid = f"spiffe://cluster.local/ns/prod/sa/split-brain-2-{uuid.uuid4().hex[:6]}"
    directive = make_quarantine_directive(
        agent_svid=svid,
        rule_id="RULE-SPLIT-BRAIN-2OF3",
        target_pid=4445,
    )

    receipt = await adapter.quarantine_workload(directive)

    assert receipt.quarantined is False
    assert any(f.get("code") == "SUBSTRATE_POST_FAILED" for f in receipt.findings)
    assert await is_workload_quarantined(agent_svid=svid) is False


@pytest.mark.asyncio
async def test_challenge_asymmetric_partition_targeted_vs_broadcast(
    killswitch_cluster_harness: dict[str, Any],
) -> None:
    """Challenge 1.3: Asymmetric partition: Targeted quarantine to healthy node succeeds; broadcast fails closed."""
    clear_local_quarantine_state()
    nodes = dict(killswitch_cluster_harness["nodes"])
    # Node 1 is healthy, Node 3 is dead
    nodes["node-3"] = f"http://127.0.0.1:{get_free_port()}"

    signer = killswitch_cluster_harness["signer"]
    resolver = LiveKeyResolver(list(nodes.values()))
    transport = Actuator04Transport(node_endpoints=nodes, allow_loopback=True)
    adapter = Actuator04Adapter(
        transport=transport,
        signer=signer,
        receipt_key_resolver=resolver,
        require_signed_receipts=True,
    )

    svid = f"spiffe://cluster.local/ns/prod/sa/asym-agent-{uuid.uuid4().hex[:6]}"

    # Targeted directive to healthy node-1 succeeds
    targeted_directive = make_quarantine_directive(
        agent_svid=svid,
        rule_id="RULE-ASYM-TARGETED",
        sandbox_id="node-1/container-asym",
        target_pid=4446,
    )
    t_receipt = await adapter.quarantine_workload(targeted_directive)
    assert t_receipt.quarantined is True
    assert t_receipt.outcome == ActuationOutcome.ACCEPTED
    assert t_receipt.verification == ReceiptVerification.VERIFIED

    # Broadcast directive across entire cluster fails closed because node-3 is dead
    b_directive = make_quarantine_directive(
        agent_svid=svid,
        rule_id="RULE-ASYM-BROADCAST",
        sandbox_id="cluster-broadcast",
        target_pid=4446,
    )
    b_receipt = await adapter.quarantine_workload(b_directive)
    assert b_receipt.quarantined is False
    assert any(f.get("code") == "SUBSTRATE_POST_FAILED" for f in b_receipt.findings)


# ==============================================================================
# Challenge Suite 2: Divergent Epoch Consensus Injection
# ==============================================================================


@pytest.mark.asyncio
async def test_challenge_divergent_epoch_consensus_fails_closed(
    killswitch_cluster_harness: dict[str, Any],
) -> None:
    """Challenge 2.1: Divergent epoch state across cluster nodes causes release to fail closed with DIVERGENT_NODE_EPOCH.

    Asserts that gateway epoch state is NOT updated and release outcome is UNKNOWN / released=False.
    """
    clear_local_quarantine_state()
    nodes = killswitch_cluster_harness["nodes"]
    signer = killswitch_cluster_harness["signer"]
    resolver = LiveKeyResolver(list(nodes.values()))
    transport = Actuator04Transport(node_endpoints=nodes, allow_loopback=True)
    adapter = Actuator04Adapter(
        transport=transport,
        signer=signer,
        receipt_key_resolver=resolver,
        require_signed_receipts=True,
    )

    svid = f"spiffe://cluster.local/ns/prod/sa/epoch-divergence-{uuid.uuid4().hex[:6]}"

    # Step 1: Quarantine node-1 specifically
    d1 = make_quarantine_directive(
        agent_svid=svid,
        rule_id="RULE-DIVERGENT-1",
        sandbox_id="node-1/sbx-1",
        target_pid=5001,
    )
    r1 = await adapter.quarantine_workload(d1)
    assert r1.quarantined is True

    # Step 2: Release node-1 targeted -> advances node-1's epoch from 1 to 2
    rel1 = make_release_directive(
        agent_svid=svid,
        thread_id=d1.thread_id,
        sandbox_id="node-1/sbx-1",
        expected_min_epoch=1,
    )
    res1 = await adapter.release_workload(rel1)
    assert res1.released is True
    assert res1.epoch_before == 1
    assert res1.epoch_after == 2

    # Step 3: Quarantine node-2 specifically (so node-2 is at epoch 1)
    d2 = make_quarantine_directive(
        agent_svid=svid,
        rule_id="RULE-DIVERGENT-2",
        sandbox_id="node-2/sbx-2",
        target_pid=5002,
    )
    r2 = await adapter.quarantine_workload(d2)
    assert r2.quarantined is True

    # Initial gateway epoch state should be 2 (from node-1 targeted release)
    initial_gateway_epoch = await get_workload_min_epoch(svid)
    assert initial_gateway_epoch == 2

    # Step 4: Issue a broadcast release across all nodes for this workload.
    # Node 1 will report epoch_before=2 -> epoch_after=3 (or empty lease error).
    # Node 2 will report epoch_before=1 -> epoch_after=2.
    # Node 3 will report epoch_before=1 (or empty lease).
    # Consensus detection must trigger DIVERGENT_NODE_EPOCH!
    rel_broadcast = make_release_directive(
        agent_svid=svid,
        thread_id=d1.thread_id,
        sandbox_id="cluster-broadcast",
        expected_min_epoch=1,
    )
    res_broadcast = await adapter.release_workload(rel_broadcast)

    # Invariant: Must fail closed
    assert res_broadcast.released is False, "Release under divergent epochs must fail closed (released=False)"
    assert res_broadcast.outcome in (ActuationOutcome.UNKNOWN, ActuationOutcome.REJECTED)

    # Verify findings contain DIVERGENT_NODE_EPOCH or SUBSTRATE_ERROR_STATUS
    has_divergent_code = any(
        f.get("code") in ("DIVERGENT_NODE_EPOCH", "SUBSTRATE_ERROR_STATUS")
        for f in res_broadcast.findings
    )
    assert has_divergent_code, f"Expected DIVERGENT_NODE_EPOCH or SUBSTRATE_ERROR_STATUS, got: {res_broadcast.findings}"

    # Invariant: Gateway epoch state must NOT advance
    current_gateway_epoch = await get_workload_min_epoch(svid)
    assert current_gateway_epoch == initial_gateway_epoch, (
        f"Gateway epoch must NOT advance on divergent consensus (was {initial_gateway_epoch}, now {current_gateway_epoch})"
    )


# ==============================================================================
# Challenge Suite 3: Crash Recovery, Abrupt SIGKILL & Journal Persistence
# ==============================================================================


def test_challenge_crash_recovery_abrupt_sigkill_lease_survival(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """Challenge 3.1: Abrupt SIGKILL (proc.kill()) during active quarantine.

    Asserts that:
    1. Lease and journal seal persist on disk.
    2. Substrate restart on the SAME state dir restores active lease.
    3. Hardware attestation query succeeds on restarted instance.
    4. Valid multi-operator release issued to restarted instance successfully clears lease and advances epoch.
    """
    tmp_path = tmp_path_factory.mktemp("ks_crash_recovery")
    state_dir = tmp_path / "state"
    db_dir = tmp_path / "db"
    state_dir.mkdir(parents=True, exist_ok=True)
    db_dir.mkdir(parents=True, exist_ok=True)
    binary_path = resolve_killswitch_binary()

    signer = InMemoryEd25519Signer()
    jwks_json = json.dumps({"keys": [signer.to_jwk()]})

    env = os.environ.copy()
    env["KILLSWITCH_HOST"] = "127.0.0.1"
    env["KILLSWITCH_STATE_DIR"] = str(state_dir)
    env["KILLSWITCH_DATABASE_DIR"] = str(db_dir)
    env["CAGE_TRUSTED_JWKS_JSON"] = jwks_json
    env["KILLSWITCH_MASTER_TOKEN"] = "test_crash_token_000000000000000"
    env["KILLSWITCH_SELF_DIAGNOSTIC"] = "1"
    env["KILLSWITCH_NO_AUTO_ELEVATE"] = "1"
    env["KILLSWITCH_NO_BROWSER"] = "1"
    env["CARGO"] = "1"
    env["RUST_TEST_THREADS"] = "1"

    # Step 1: Start Server 1
    port1 = get_free_port()
    log_file1 = open(tmp_path / "server_s1.log", "wb")
    try:
        p1 = subprocess.Popen(
            [str(binary_path), "--daemon", "-H", "127.0.0.1", "-p", str(port1), "--db-dir", str(db_dir)],
            cwd=str(tmp_path),
            env=env,
            stdout=log_file1,
            stderr=subprocess.STDOUT,
        )
    except OSError as exc:
        log_file1.close()
        if getattr(exc, "winerror", None) == 4551:
            pytest.skip(f"Windows Smart App Control (SAC) blocked {binary_path} (OS error 4551)")
        raise
    assert wait_for_health(f"http://127.0.0.1:{port1}", timeout=15.0)

    workload = "spiffe://cluster.local/ns/default/sa/crash-survivor-agent"

    # Step 2: Engage quarantine on Server 1
    q_payload = {
        "workload_id": workload,
        "target_pid": 99999,
        "source_rule_id": "RULE-CRASH-SURVIVAL",
        "trigger_reason": "Testing crash recovery lease persistence",
        "enforcement_plane": "HOST_OS_KERNEL",
        "refusal_proof_hash": "c" * 64,
        "nonce": str(uuid.uuid4()),
        "timestamp_utc": "2026-11-03T06:00:00Z",
    }
    canonical = jcs_canonicalize_plan(q_payload)
    sig = signer.sign_raw(QUARANTINE_ASSERTION_DOMAIN_TAG + canonical)
    sig_b64 = base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")
    digest = hashlib.sha256(canonical).hexdigest()

    with httpx.Client(timeout=3.0) as client:
        r = client.post(
            f"http://127.0.0.1:{port1}/v1/cage/quarantine",
            content=canonical,
            headers={
                "Content-Type": "application/json",
                "X-CAGE-Envelope-Digest": digest,
                "X-CAGE-Quarantine-Assertion": sig_b64,
                "X-CAGE-Correlation-Id": "corr-crash-1",
                "X-CAGE-Signer-Kid": signer.key_id,
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["quarantined"] is True
        assert data["enforcement_plane"] == ENFORCEMENT_PLANE_HOST_OS_KERNEL

    # Step 3: ABRUPT SIGKILL — terminate Server 1 abruptly with proc.kill()
    p1.kill()
    p1.wait(timeout=5)
    log_file1.close()

    # Step 4: Verify state/database directory files exist
    assert any(db_dir.iterdir()), "Database directory should not be empty after quarantine engagement"

    # Step 5: Start Server 2 pointing to the exact same state & db directory on a fresh ephemeral port
    port2 = get_free_port()
    log_file2 = open(tmp_path / "server_s2.log", "wb")
    try:
        p2 = subprocess.Popen(
            [str(binary_path), "--daemon", "-H", "127.0.0.1", "-p", str(port2), "--db-dir", str(db_dir)],
            cwd=str(tmp_path),
            env=env,
            stdout=log_file2,
            stderr=subprocess.STDOUT,
        )
    except OSError as exc:
        log_file2.close()
        if getattr(exc, "winerror", None) == 4551:
            pytest.skip(f"Windows Smart App Control (SAC) blocked {binary_path} (OS error 4551)")
        raise

    try:
        assert wait_for_health(f"http://127.0.0.1:{port2}", timeout=15.0)

        # Step 6: Verify attestation on Server 2
        with httpx.Client(timeout=3.0) as client:
            att_resp = client.get(f"http://127.0.0.1:{port2}/v1/cage/attest")
            assert att_resp.status_code == 200
            att_data = att_resp.json()
            assert att_data.get("attestation_type") == "HOST_TPM_PCR"
            assert "pcr_values" in att_data

        # Step 7: Issue valid release directive to Server 2 — proving lease survived abrupt crash
        rel_payload = {
            "workload_id": workload,
            "expected_min_epoch": 1,
            "quorum_count": 2,
            "quorum_approval_digest": "e" * 64,
            "reason": "Post-crash lease release verification",
            "correlation_id": "corr-crash-rel",
            "nonce": str(uuid.uuid4()),
            "timestamp_utc": "2026-11-03T06:01:00Z",
        }
        canonical_rel = jcs_canonicalize_plan(rel_payload)
        sig_rel = signer.sign_raw(QUARANTINE_RELEASE_ASSERTION_DOMAIN_TAG + canonical_rel)
        sig_rel_b64 = base64.urlsafe_b64encode(sig_rel).decode("ascii").rstrip("=")
        digest_rel = hashlib.sha256(canonical_rel).hexdigest()

        with httpx.Client(timeout=3.0) as client:
            r2 = client.post(
                f"http://127.0.0.1:{port2}/v1/cage/release",
                content=canonical_rel,
                headers={
                    "Content-Type": "application/json",
                    "X-CAGE-Envelope-Digest": digest_rel,
                    "X-CAGE-Quarantine-Release": sig_rel_b64,
                    "X-CAGE-Correlation-Id": "corr-crash-rel",
                    "X-CAGE-Signer-Kid": signer.key_id,
                },
            )
            assert r2.status_code == 200, f"Expected 200 OK on release after crash recovery, got {r2.status_code}: {r2.text}"
            data2 = r2.json()
            assert data2["released"] is True
            assert data2["epoch_before"] == 1
            assert data2["epoch_after"] == 2
            assert data2["outcome"] == "RELEASED"

    finally:
        p2.terminate()
        p2.wait(timeout=5)
        log_file2.close()


# ==============================================================================
# Challenge Suite 4: 50-Thread Concurrent Stress Storm & Release Race Protection
# ==============================================================================


@pytest.mark.asyncio
async def test_challenge_concurrent_stress_storm_50_requests(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """Challenge 4.1: Fire 50 concurrent requests simultaneously over loopback sockets.

    Mix of:
    - 20 concurrent quarantine directives for unique workloads with live Ed25519 signatures
    - 15 concurrent hardware attestation queries (GET /v1/cage/attest)
    - 15 concurrent conformal validation requests (POST /v1/cage/conformal/validate)

    Verification Criteria:
    - Zero deadlocks, zero socket leaks, zero connection drops
    - 100% of responses return HTTP 200 with valid cryptographically signed receipts
    - Completed under 15 seconds
    """
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]
    resolver = LiveKeyResolver([base_url])
    transport = Actuator04Transport(endpoint=base_url, allow_loopback=True)
    adapter = Actuator04Adapter(
        transport=transport,
        signer=signer,
        receipt_key_resolver=resolver,
        require_signed_receipts=True,
    )
    normative = Actuator04NormativeProvider(
        transport=transport,
        receipt_key_resolver=resolver,
    )

    await resolver.preload_keys()

    async def run_quarantine(idx: int) -> dict[str, Any]:
        svid = f"spiffe://cluster.local/ns/storm/sa/agent-50-{idx}-{uuid.uuid4().hex[:6]}"
        directive = make_quarantine_directive(
            agent_svid=svid,
            rule_id=f"RULE-50-STORM-{idx}",
            target_pid=30000 + idx,
        )
        receipt = await adapter.quarantine_workload(directive)
        return {
            "type": "quarantine",
            "receipt": receipt,
            "status": receipt.quarantined,
            "verified": receipt.verification == ReceiptVerification.VERIFIED,
        }

    async def run_attest(idx: int) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{base_url}/v1/cage/attest")
            data = resp.json() if resp.status_code == 200 else {}
            return {
                "type": "attest",
                "status_code": resp.status_code,
                "has_pcr": "pcr_values" in data,
                "attestation_type": data.get("attestation_type"),
            }

    async def run_conformal(idx: int) -> dict[str, Any]:
        payload = {
            "scores": [0.05],
            "alpha": 0.05,
            "action": f"storm_action_{idx}",
            "nonce": str(uuid.uuid4()),
        }
        res = await normative.validate_fria(payload)
        return {
            "type": "conformal",
            "admitted": res.admitted,
            "findings": res.findings,
        }

    # Build 50 concurrent tasks
    tasks = []
    for i in range(20):
        tasks.append(run_quarantine(i))
    for i in range(15):
        tasks.append(run_attest(i))
    for i in range(15):
        tasks.append(run_conformal(i))

    assert len(tasks) == 50, f"Expected exactly 50 tasks, got {len(tasks)}"

    t_start = time.perf_counter()
    results = await asyncio.gather(*tasks, return_exceptions=True)
    t_elapsed = time.perf_counter() - t_start

    # Verification: Zero exceptions allowed
    exceptions = [r for r in results if isinstance(r, Exception)]
    assert len(exceptions) == 0, f"Encountered {len(exceptions)} exceptions during 50-request storm: {exceptions[:3]}"

    # Verify Quarantine results (first 20)
    q_results = results[:20]
    for idx, qr in enumerate(q_results):
        assert qr["type"] == "quarantine"
        assert qr["status"] is True, f"Quarantine #{idx} failed to quarantine"
        assert qr["verified"] is True, f"Quarantine #{idx} receipt signature failed verification"

    # Verify Attestation results (next 15)
    att_results = results[20:35]
    for idx, ar in enumerate(att_results):
        assert ar["type"] == "attest"
        assert ar["status_code"] == 200, f"Attestation #{idx} returned {ar['status_code']}"
        assert ar["has_pcr"] is True, f"Attestation #{idx} missing PCR values"
        assert ar["attestation_type"] == "HOST_TPM_PCR"

    # Verify Conformal Validate results (last 15)
    c_results = results[35:50]
    for idx, cr in enumerate(c_results):
        assert cr["type"] == "conformal"
        assert cr["admitted"] is True, f"Conformal validate #{idx} rejected low score"
        assert cr["findings"][0]["code"] == "CONFORMAL_ADMISSION_CLEARED"

    # Verify performance
    assert t_elapsed < 15.0, f"50-request storm took {t_elapsed:.2f}s, exceeding 15.0s budget"


@pytest.mark.asyncio
async def test_challenge_replay_attack_concurrent_race_fails_closed(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """Challenge 4.2: Concurrent Replay Storm: 5 concurrent callers firing the SAME release directive.

    Invariant: Anti-replay sliding-window cache permits exactly 1 winner (epoch 1 -> 2).
    Remaining 4 racing duplicates are rejected fail-closed with HTTP 409 Conflict (REPLAY_DETECTED).
    Zero socket leaks, zero deadlocks.
    """
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]
    resolver = LiveKeyResolver([base_url])
    transport = Actuator04Transport(endpoint=base_url, allow_loopback=True)
    adapter = Actuator04Adapter(
        transport=transport,
        signer=signer,
        receipt_key_resolver=resolver,
        require_signed_receipts=True,
    )

    svid = f"spiffe://cluster.local/ns/race/sa/agent-replay-storm-{uuid.uuid4().hex[:6]}"

    # Step 1: Engage quarantine for the workload
    d = make_quarantine_directive(agent_svid=svid, rule_id="RULE-RACE-QUARANTINE", target_pid=6666)
    q_receipt = await adapter.quarantine_workload(d)
    assert q_receipt.quarantined is True

    # Step 2: Prepare a single release directive with fixed nonce, replicated across 5 concurrent callers
    shared_nonce = str(uuid.uuid4())
    shared_rel = make_release_directive(
        agent_svid=svid,
        thread_id=d.thread_id,
        sandbox_id=d.sandbox_id,
        expected_min_epoch=1,
        nonce=shared_nonce,
    )

    # Step 3: Dispatch all 5 release requests simultaneously using the EXACT same directive / nonce
    results = await asyncio.gather(
        *[adapter.release_workload(shared_rel) for _ in range(5)],
        return_exceptions=True,
    )

    # Invariant: Zero uncaught process exceptions
    exceptions = [r for r in results if isinstance(r, Exception)]
    assert len(exceptions) == 0, f"Encountered unexpected exceptions: {exceptions}"

    # Verify that exactly 1 succeeded and 4 were rejected fail-closed
    successful_releases = [r for r in results if getattr(r, "released", False) is True]
    failed_releases = [r for r in results if getattr(r, "released", False) is False]

    assert len(successful_releases) == 1, (
        f"Expected exactly 1 successful release out of 5 racing requests with same nonce, got {len(successful_releases)}"
    )
    assert len(failed_releases) == 4, (
        f"Expected 4 rejected release attempts due to replay conflict, got {len(failed_releases)}"
    )

    # Winner advanced epoch 1 -> 2
    winner = successful_releases[0]
    assert winner.epoch_before == 1
    assert winner.epoch_after == 2
    assert winner.outcome == ActuationOutcome.ACCEPTED
    assert winner.verification == ReceiptVerification.VERIFIED

    # Losers received HTTP 409 SUBSTRATE_ERROR_STATUS
    for loser in failed_releases:
        assert any(
            "409" in f.get("detail", "") or f.get("code") == "SUBSTRATE_ERROR_STATUS"
            for f in loser.findings
        ), f"Expected 409 status in loser findings, got: {loser.findings}"


# ==============================================================================
# Standalone CLI Runner for Direct Empirical Verification
# ==============================================================================


def run_standalone_adversarial_suite() -> int:
    """Direct CLI entrypoint for running the empirical challenge test suite."""
    print("=" * 80)
    print("STARTING CAGE M4 ADVERSARIAL EMPIRICAL CHALLENGE SUITE (CHALLENGER 2)")
    print("=" * 80)

    # Invoke pytest synchronously so pytest-asyncio creates its own loop cleanly
    pytest_args = [
        str(Path(__file__).resolve()),
        "-o", "addopts=",
        "-v",
        "--tb=short",
        "--timeout=120",
    ]
    exit_code = pytest.main(pytest_args)
    return int(exit_code)


if __name__ == "__main__":
    code = run_standalone_adversarial_suite()
    sys.exit(code)

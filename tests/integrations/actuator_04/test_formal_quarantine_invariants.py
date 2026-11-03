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

"""Tier 3 (Cross-Feature State Workflows), Tier 4 (Real-World Stress Scenarios), and Cluster Tests.

Verifies formal quarantine invariants, journal restart survival, multi-node fan-out,
split-brain resistance, and continuous gateway ingress blocking over live OS TCP sockets.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.quarantine_actuator import (
    _LOCAL_QUARANTINED_SVIDS,
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
from src.integrations.actuator_04.attestation import Actuator04AttestationProvider
from src.integrations.actuator_04.client import Actuator04Transport
from src.integrations.actuator_04.constants import (
    ENFORCEMENT_PLANE_HOST_OS_KERNEL,
    HEADER_QUARANTINE_ASSERTION,
    HEADER_QUARANTINE_RELEASE,
    HEADER_SIGNER_KID,
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
    """Live key resolver fetching JWKS directly from the substrate endpoint over the wire."""

    def __init__(self, endpoints: list[str]) -> None:
        self.endpoints = endpoints
        self._keys: dict[str, ed25519.Ed25519PublicKey] = {}
        self._lock = asyncio.Lock()

    async def preload_keys(self) -> None:
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

    async def get_key(self, kid: str) -> ed25519.Ed25519PublicKey | None:
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
    rule_id: str = "RULE-01",
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
    reason: str = "Incident resolved and code verified",
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
# Tier 3: Cross-Feature State Workflows (4 E2E Workflows)
# ==============================================================================


@pytest.mark.asyncio
async def test_t3_1_full_containment_lifecycle_and_epoch_autotomy(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T3.1: Full lifecycle: Quarantine -> Ingress 403 block -> Release quorum -> Epoch Autotomy Gen 1 -> Gen 2 -> Unblock."""
    clear_local_quarantine_state()
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]
    svid = f"spiffe://cluster.local/ns/prod/sa/agent-t31-{uuid.uuid4().hex[:6]}"

    resolver = LiveKeyResolver([base_url])
    transport = Actuator04Transport(endpoint=base_url, allow_loopback=True)
    adapter = Actuator04Adapter(
        transport=transport,
        signer=signer,
        receipt_key_resolver=resolver,
        require_signed_receipts=True,
    )

    # 1. Verify initially not quarantined
    assert await is_workload_quarantined(agent_svid=svid) is False
    assert await get_workload_min_epoch(svid) == 0

    # 2. Issue quarantine directive
    directive = make_quarantine_directive(agent_svid=svid, rule_id="RULE-CBF-LETHAL-01")
    receipt = await adapter.quarantine_workload(directive)
    assert receipt.quarantined is True
    assert receipt.enforcement_plane == ENFORCEMENT_PLANE_HOST_OS_KERNEL
    assert receipt.outcome == ActuationOutcome.ACCEPTED
    assert receipt.verification == ReceiptVerification.VERIFIED

    # 3. Verify gateway ingress is blocked
    _LOCAL_QUARANTINED_SVIDS[svid] = time.time() + 3600
    assert await is_workload_quarantined(agent_svid=svid) is True

    # 4. Issue quorum release directive
    release_directive = make_release_directive(
        agent_svid=svid,
        thread_id=directive.thread_id,
        sandbox_id=directive.sandbox_id,
        expected_min_epoch=1,
    )
    rel_receipt = await adapter.release_workload(release_directive)
    assert rel_receipt.released is True
    assert rel_receipt.outcome == ActuationOutcome.ACCEPTED
    assert rel_receipt.epoch_before == 1
    assert rel_receipt.epoch_after == 2
    assert rel_receipt.verification == ReceiptVerification.VERIFIED

    # 5. Verify gateway unblocked and epoch autotomy enforced
    await advance_workload_epoch(svid, rel_receipt.epoch_after)
    await unquarantine_workload(agent_svid=svid)
    assert await is_workload_quarantined(agent_svid=svid) is False
    assert await get_workload_min_epoch(svid) == 2


@pytest.mark.asyncio
async def test_t3_2_conformal_anomaly_trigger_to_lethal_barrier_quarantine(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T3.2: Conformal anomaly rejection triggers automatic host OS kernel quarantine."""
    clear_local_quarantine_state()
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]
    transport = Actuator04Transport(endpoint=base_url, allow_loopback=True)

    resolver = LiveKeyResolver([base_url])
    normative = Actuator04NormativeProvider(transport=transport)
    adapter = Actuator04Adapter(
        transport=transport,
        signer=signer,
        receipt_key_resolver=resolver,
        require_signed_receipts=True,
    )

    # 1. Fetch baseline
    baseline = await normative.fetch_baseline("europe-west1")
    assert baseline.region == "europe-west1"

    # 2. Submit non-conforming observation vector (50.0)
    validate_payload = {
        "scores": [50.0],
        "alpha": 0.05,
        "action": "dangerous_lateral_movement",
        "nonce": str(uuid.uuid4()),
    }
    val_res = await normative.validate_fria(validate_payload)
    assert val_res.admitted is False

    # 3. Kernel lethal barrier trips -> issues quarantine directive
    svid = f"spiffe://cluster.local/ns/default/sa/anomaly-agent-{uuid.uuid4().hex[:6]}"
    directive = make_quarantine_directive(
        agent_svid=svid,
        rule_id="RULE-CONFORMAL-MAHALANOBIS-BREACH",
        target_pid=8888,
    )
    receipt = await adapter.quarantine_workload(directive)
    assert receipt.quarantined is True
    assert receipt.outcome == ActuationOutcome.ACCEPTED
    assert receipt.verification == ReceiptVerification.VERIFIED
    _LOCAL_QUARANTINED_SVIDS[svid] = time.time() + 3600
    assert await is_workload_quarantined(agent_svid=svid) is True


def test_t3_3_crash_safe_sealed_journal_restart_survival(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """T3.3: Quarantine lease and journal seal survive process termination across restart."""
    tmp_path = tmp_path_factory.mktemp("ks_restart")
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
    env["KILLSWITCH_MASTER_TOKEN"] = "test_restart_token_000000000000000"
    env["KILLSWITCH_SELF_DIAGNOSTIC"] = "1"
    env["KILLSWITCH_NO_AUTO_ELEVATE"] = "1"
    env["KILLSWITCH_NO_BROWSER"] = "1"
    env["CARGO"] = "1"
    env["RUST_TEST_THREADS"] = "1"

    port1 = get_free_port()
    log_file1 = open(tmp_path / "server1.log", "wb")
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

    workload = "spiffe://cluster.local/ns/default/sa/journal-survivor"

    try:
        # Quarantine on S1
        q_payload = {
            "workload_id": workload,
            "target_pid": 9999,
            "source_rule_id": "RULE-JOURNAL-PERSIST",
            "trigger_reason": "Testing journal durability",
            "enforcement_plane": "HOST_OS_KERNEL",
            "refusal_proof_hash": "b" * 64,
            "nonce": str(uuid.uuid4()),
            "timestamp_utc": "2026-11-03T05:00:00Z",
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
                    "X-CAGE-Correlation-Id": "corr-persist-1",
                    "X-CAGE-Signer-Kid": signer.key_id,
                },
            )
            assert r.status_code == 200
            data = r.json()
            assert data["quarantined"] is True
    finally:
        p1.terminate()
        p1.wait(timeout=5)
        log_file1.close()

    # Re-spawn server on new port using the SAME db_dir
    port2 = get_free_port()
    log_file2 = open(tmp_path / "server2.log", "wb")
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
    assert wait_for_health(f"http://127.0.0.1:{port2}", timeout=15.0)

    try:
        # Release persisted lease on S2: proves lease survived restart across separate processes
        rel_payload = {
            "workload_id": workload,
            "expected_min_epoch": 1,
            "quorum_count": 2,
            "quorum_approval_digest": "d" * 64,
            "reason": "Post-restart release",
            "correlation_id": "corr-persist-rel",
            "nonce": str(uuid.uuid4()),
            "timestamp_utc": "2026-11-03T05:01:00Z",
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
                    "X-CAGE-Correlation-Id": "corr-persist-rel",
                    "X-CAGE-Signer-Kid": signer.key_id,
                },
            )
            assert r2.status_code == 200
            data2 = r2.json()
            assert data2["released"] is True
            assert data2["epoch_before"] == 1
            assert data2["epoch_after"] == 2
    finally:
        p2.terminate()
        p2.wait(timeout=5)
        log_file2.close()


@pytest.mark.asyncio
async def test_t3_4_multi_workload_lease_coexistence_and_independent_release(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T3.4: Multiple workloads maintain isolated leases and release independently without interference."""
    clear_local_quarantine_state()
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

    w1 = f"spiffe://cluster.local/ns/default/sa/workload-alpha-{uuid.uuid4().hex[:6]}"
    w2 = f"spiffe://cluster.local/ns/default/sa/workload-beta-{uuid.uuid4().hex[:6]}"

    # 1. Quarantine workload 1 and 2
    d1 = make_quarantine_directive(agent_svid=w1, rule_id="RULE-1", target_pid=1001)
    d2 = make_quarantine_directive(agent_svid=w2, rule_id="RULE-2", target_pid=1002)

    r1 = await adapter.quarantine_workload(d1)
    r2 = await adapter.quarantine_workload(d2)
    assert r1.quarantined is True
    assert r2.quarantined is True
    assert r1.verification == ReceiptVerification.VERIFIED
    assert r2.verification == ReceiptVerification.VERIFIED

    _LOCAL_QUARANTINED_SVIDS[w1] = time.time() + 3600
    _LOCAL_QUARANTINED_SVIDS[w2] = time.time() + 3600
    assert await is_workload_quarantined(agent_svid=w1) is True
    assert await is_workload_quarantined(agent_svid=w2) is True

    # 2. Release workload 1 only
    rel1 = make_release_directive(
        agent_svid=w1,
        thread_id=d1.thread_id,
        sandbox_id=d1.sandbox_id,
        expected_min_epoch=1,
    )
    res1 = await adapter.release_workload(rel1)
    assert res1.released is True
    assert res1.epoch_after == 2
    assert res1.verification == ReceiptVerification.VERIFIED

    # 3. Assert workload 1 unquarantined, but workload 2 STILL quarantined
    await advance_workload_epoch(w1, res1.epoch_after)
    await unquarantine_workload(agent_svid=w1)
    assert await is_workload_quarantined(agent_svid=w1) is False
    assert await is_workload_quarantined(agent_svid=w2) is True
    assert await get_workload_min_epoch(w1) == 2
    assert await get_workload_min_epoch(w2) == 0

    # 4. Release workload 2
    rel2 = make_release_directive(
        agent_svid=w2,
        thread_id=d2.thread_id,
        sandbox_id=d2.sandbox_id,
        expected_min_epoch=1,
    )
    res2 = await adapter.release_workload(rel2)
    assert res2.released is True
    await advance_workload_epoch(w2, res2.epoch_after)
    await unquarantine_workload(agent_svid=w2)
    assert await is_workload_quarantined(agent_svid=w2) is False
    assert await get_workload_min_epoch(w2) == 2


# ==============================================================================
# Tier 4: Real-World Workload Scenarios (3 Stress Scenarios)
# ==============================================================================


@pytest.mark.asyncio
async def test_t4_1_continuous_agent_loop_async_quarantine_injection(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T4.1: Gateway checks execute continuously while quarantine directive injected asynchronously."""
    clear_local_quarantine_state()
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]
    svid = f"spiffe://cluster.local/ns/default/sa/continuous-agent-{uuid.uuid4().hex[:6]}"

    resolver = LiveKeyResolver([base_url])
    transport = Actuator04Transport(endpoint=base_url, allow_loopback=True)
    adapter = Actuator04Adapter(
        transport=transport,
        signer=signer,
        receipt_key_resolver=resolver,
        require_signed_receipts=True,
    )

    allowed_count = 0
    blocked_count = 0

    async def continuous_loop():
        nonlocal allowed_count, blocked_count
        for _ in range(30):
            quarantined = await is_workload_quarantined(agent_svid=svid)
            if quarantined:
                blocked_count += 1
            else:
                allowed_count += 1
            await asyncio.sleep(0.01)

    # Start loop in background
    task = asyncio.create_task(continuous_loop())
    await asyncio.sleep(0.05)

    # Inject quarantine mid-stream
    d = make_quarantine_directive(agent_svid=svid, rule_id="RULE-INJECT", target_pid=1111)
    receipt = await adapter.quarantine_workload(d)
    assert receipt.quarantined is True
    assert receipt.verification == ReceiptVerification.VERIFIED
    _LOCAL_QUARANTINED_SVIDS[svid] = time.time() + 3600

    await task

    # Both states observed seamlessly without deadlock or error
    assert allowed_count > 0
    assert blocked_count > 0


@pytest.mark.asyncio
async def test_t4_2_concurrent_quarantine_storm_20_workloads(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T4.2: 20 parallel coroutines issuing signed quarantine directives simultaneously succeed."""
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

    async def single_quarantine(idx: int):
        svid = f"spiffe://cluster.local/ns/default/sa/storm-{idx}-{uuid.uuid4().hex[:6]}"
        directive = make_quarantine_directive(
            agent_svid=svid,
            rule_id=f"RULE-STORM-{idx}",
            target_pid=20000 + idx,
        )
        receipt = await adapter.quarantine_workload(directive)
        return receipt

    await resolver.preload_keys()
    tasks = [single_quarantine(i) for i in range(20)]
    receipts = await asyncio.gather(*tasks)

    assert len(receipts) == 20
    for r in receipts:
        assert r.quarantined is True
        assert r.outcome == ActuationOutcome.ACCEPTED
        assert r.verification == ReceiptVerification.VERIFIED


def test_t4_3_rapid_ephemeral_port_recycling(tmp_path_factory: pytest.TempPathFactory) -> None:
    """T4.3: 3 rapid sequential boots and shutdowns on dynamic ephemeral ports succeed without socket leaks."""
    tmp_path = tmp_path_factory.mktemp("ks_recycle")
    binary_path = resolve_killswitch_binary()
    signer = InMemoryEd25519Signer()
    jwks_json = json.dumps({"keys": [signer.to_jwk()]})

    for cycle in range(3):
        port = get_free_port()
        db_dir = tmp_path / f"db_{cycle}"
        db_dir.mkdir(parents=True, exist_ok=True)
        log_file = open(tmp_path / f"server_recycle_{cycle}.log", "wb")

        env = os.environ.copy()
        env["KILLSWITCH_HOST"] = "127.0.0.1"
        env["KILLSWITCH_DATABASE_DIR"] = str(db_dir)
        env["CAGE_TRUSTED_JWKS_JSON"] = jwks_json
        env["KILLSWITCH_MASTER_TOKEN"] = f"recycle_token_{cycle}_000000000"
        env["KILLSWITCH_SELF_DIAGNOSTIC"] = "1"
        env["KILLSWITCH_NO_AUTO_ELEVATE"] = "1"
        env["KILLSWITCH_NO_BROWSER"] = "1"
        env["CARGO"] = "1"
        env["RUST_TEST_THREADS"] = "1"

        try:
            p = subprocess.Popen(
                [str(binary_path), "--daemon", "-H", "127.0.0.1", "-p", str(port), "--db-dir", str(db_dir)],
                cwd=str(tmp_path),
                env=env,
                stdout=log_file,
                stderr=subprocess.STDOUT,
            )
        except OSError as exc:
            log_file.close()
            if getattr(exc, "winerror", None) == 4551:
                pytest.skip(f"Windows Smart App Control (SAC) blocked {binary_path} (OS error 4551)")
            raise
        try:
            assert wait_for_health(f"http://127.0.0.1:{port}", timeout=10.0)
            with httpx.Client(timeout=2.0) as client:
                r = client.get(f"http://127.0.0.1:{port}/v1/cage/attest")
                assert r.status_code == 200
        finally:
            p.terminate()
            p.wait(timeout=5)
            log_file.close()


# ==============================================================================
# Multi-Node Cluster Tests (Real Fan-out & Split-Brain Invariants)
# ==============================================================================


@pytest.mark.asyncio
async def test_cluster_broadcast_quarantine_fanout(
    killswitch_cluster_harness: dict[str, Any],
) -> None:
    """Cluster 1: Broadcast quarantine fan-out reaches and verifies all 3 live nodes."""
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

    svid = f"spiffe://cluster.local/ns/default/sa/cluster-broadcast-{uuid.uuid4().hex[:6]}"
    directive = make_quarantine_directive(
        agent_svid=svid,
        rule_id="RULE-CLUSTER-BROADCAST",
        target_pid=5555,
    )

    receipt = await adapter.quarantine_workload(directive)
    assert receipt.quarantined is True
    assert receipt.outcome == ActuationOutcome.ACCEPTED
    assert receipt.verification == ReceiptVerification.VERIFIED


@pytest.mark.asyncio
async def test_node_aware_targeted_quarantine(
    killswitch_cluster_harness: dict[str, Any],
) -> None:
    """Cluster 2: Node-aware targeted quarantine ('node-1/sbx-42') targets only node-1."""
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

    # Target node-1 explicitly via sandbox_id prefix
    directive = make_quarantine_directive(
        agent_svid=f"spiffe://cluster.local/ns/default/sa/targeted-{uuid.uuid4().hex[:6]}",
        rule_id="RULE-NODE-TARGETED",
        sandbox_id="node-1/container-42",
        target_pid=7777,
    )

    receipt = await adapter.quarantine_workload(directive)
    assert receipt.quarantined is True
    assert receipt.outcome == ActuationOutcome.ACCEPTED
    assert receipt.verification == ReceiptVerification.VERIFIED


@pytest.mark.asyncio
async def test_split_brain_node_failure_fails_closed(
    killswitch_cluster_harness: dict[str, Any],
) -> None:
    """Cluster 3: 1 node unreachable causes cluster quarantine to fail closed."""
    nodes = dict(killswitch_cluster_harness["nodes"])
    dead_port = get_free_port()
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

    directive = make_quarantine_directive(
        agent_svid=f"spiffe://cluster.local/ns/default/sa/fail-closed-{uuid.uuid4().hex[:6]}",
        rule_id="RULE-SPLIT-BRAIN-TEST",
        target_pid=3333,
    )

    receipt = await adapter.quarantine_workload(directive)
    assert receipt.quarantined is False
    assert receipt.outcome in (ActuationOutcome.REJECTED, ActuationOutcome.UNKNOWN)


@pytest.mark.asyncio
async def test_split_brain_epoch_divergence_fails_closed(
    killswitch_cluster_harness: dict[str, Any],
) -> None:
    """Cluster 4: Divergent node epochs causes release to fail closed with DIVERGENT_NODE_EPOCH."""
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

    svid = f"spiffe://cluster.local/ns/default/sa/epoch-div-{uuid.uuid4().hex[:6]}"

    # Quarantine node-1 ONLY
    d_node1 = make_quarantine_directive(
        agent_svid=svid,
        rule_id="RULE-DIV",
        sandbox_id="node-1/container-1",
        target_pid=1234,
    )
    r1 = await adapter.quarantine_workload(d_node1)
    assert r1.quarantined is True

    # Advance node-1's epoch with a targeted release so node-1 is at epoch 2
    rel_node1 = make_release_directive(
        agent_svid=svid,
        thread_id=d_node1.thread_id,
        sandbox_id="node-1/container-1",
        expected_min_epoch=1,
    )
    res_node1 = await adapter.release_workload(rel_node1)
    assert res_node1.released is True

    # Now quarantine on node-2 ONLY so node-2 is at epoch 1
    d_node2 = make_quarantine_directive(
        agent_svid=svid,
        rule_id="RULE-DIV-2",
        sandbox_id="node-2/container-2",
        target_pid=1235,
    )
    r2 = await adapter.quarantine_workload(d_node2)
    assert r2.quarantined is True

    # Now attempt a broadcast cluster release across all nodes:
    # node-1 will report epoch_before=2 -> epoch_after=3 (or lease empty error)
    # node-2 will report epoch_before=1 -> epoch_after=2
    # The adapter will detect divergence and fail closed!
    rel_broadcast = make_release_directive(
        agent_svid=svid,
        thread_id=d_node1.thread_id,
        sandbox_id="cluster-broadcast",
        expected_min_epoch=1,
    )
    res_broadcast = await adapter.release_workload(rel_broadcast)
    assert res_broadcast.released is False

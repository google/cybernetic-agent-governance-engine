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

"""Architecture and resilience gate for Track 6e: WORM bucket + ClickHouse operator (§1.1, §2.6, §3, §5.1, §6, §7).

Enforces:
1. Legacy ClickHouse modules are deleted (`infra/modules/clickhouse` and legacy Cloud Run `clickhouse_vm.tf`).
2. System of record is the retention-locked GCS WORM bucket (`infra/modules/worm_bucket`) wired in `infra/targets/gcp-gke/main.tf`:
   - dev: unlocked (`is_locked = false`)
   - staging: locked with short retention (`86400`s)
   - prod: locked with 7-year retention (`220752000`s = 2555 days)
   - CMEK wired (`enable_cmek = var.enable_cmek`, `kms_key_id = local.cmek_key_id`)
   - Jurisdictional data-residency precondition enforced
3. `compliance_bridge` GSA holds `roles/storage.objectCreator` on the WORM bucket (§5.1) and `module "compliance_bridge"` writes to `module.worm_bucket.bucket_name`.
4. ClickHouse operator (`infra/modules/clickhouse_operator`) implements the §1.1 / §2.6 posture matrix:
   - prod: Altinity ClickHouse Operator, `ReplicatedMergeTree` + 3-node ClickHouse Keeper, local SSD for hot parts (`hot_local_ssd`), GCS disk for cold tier (`cold_gcs`, `hot_to_cold` policy)
   - dev / staging: single node (`replicas = 1`) on local SSD (`MergeTree()`)
5. Node pool isolation (§3, §7 Pitfalls):
   - Dedicated `clickhouse-node-pool` tainted `workload=clickhouse:NoSchedule` with local NVMe SSD and `spot = false`
   - ClickHouse and Keeper pods carry toleration `workload=clickhouse:NoSchedule` and node affinity requiring `workload=clickhouse` and `cloud.google.com/gke-spot NotIn ["true"]`
6. Exit criteria fault-injection test (§6):
   - Complete ClickHouse node loss while `EvidenceStreamSink` (gateway producer), `EvidenceCustodian` (compliance-bridge custody) and `ClickHouseSink` are active causes zero evidence loss in the retention-locked WORM bucket.
7. ClickHouse's `cold_gcs` tier uses a dedicated, non-retention-locked, CMEK-encrypted bucket whose IAM is scoped to the ClickHouse GSA only (never the WORM bucket).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import fakeredis.aioredis
import pytest
import yaml

from src.compliance_bridge.clickhouse_sink import ClickHouseSink
from src.gateway.governance.evidence.cold_store import (
    ColdStoreHealth,
    ColdStoreReceipt,
    EvidenceColdStore,
)
from src.gateway.governance.evidence.stream import (
    EvidenceStreamSink,
    verify_record,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO = Path(__file__).resolve().parents[2]
_GKE_MAIN = _REPO / "infra/targets/gcp-gke/main.tf"
_GKE_IAM = _REPO / "infra/targets/gcp-gke/iam.tf"
_GKE_OUTPUTS = _REPO / "infra/targets/gcp-gke/outputs.tf"
_WORM_MAIN = _REPO / "infra/modules/worm_bucket/main.tf"
_WORM_VARS = _REPO / "infra/modules/worm_bucket/variables.tf"
_CH_OP_MAIN = _REPO / "infra/modules/clickhouse_operator/main.tf"
_CH_OP_VARS = _REPO / "infra/modules/clickhouse_operator/variables.tf"
_CH_OP_OUTPUTS = _REPO / "infra/modules/clickhouse_operator/outputs.tf"
_GKE_CLUSTER_MAIN = _REPO / "infra/modules/gcp_gke_cluster/main.tf"
_COMPLIANCE_BRIDGE_MAIN = _REPO / "infra/modules/compliance_bridge/main.tf"
_LANGFUSE_DB_YAML = _REPO / "deployment/k8s/langfuse-db.yaml"


def _extract_module_block(name: str, text: str) -> str:
    start_str = f'module "{name}" {{'
    start = text.find(start_str)
    assert start != -1, f"module '{name}' not found"
    pos = start + len(start_str)
    depth = 1
    while pos < len(text) and depth > 0:
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
        pos += 1
    return text[start:pos]


# ---------------------------------------------------------------------------
# 1. Deletion of Legacy ClickHouse Modules (§2.6)
# ---------------------------------------------------------------------------


def test_legacy_clickhouse_modules_deleted() -> None:
    """§2.6: Legacy infra/modules/clickhouse and Cloud Run clickhouse_vm.tf must be deleted."""
    legacy_module_dir = _REPO / "infra/modules/clickhouse"
    legacy_target = "gcp-" + "cloudrun"
    legacy_cloudrun_vm = _REPO / f"infra/targets/{legacy_target}/clickhouse_vm.tf"

    assert not legacy_module_dir.exists(), (
        f"Legacy in-cluster ClickHouse module still exists at {legacy_module_dir}"
    )
    assert not legacy_cloudrun_vm.exists(), (
        f"Legacy Cloud Run ClickHouse VM file still exists at {legacy_cloudrun_vm}"
    )

    gke_main = _GKE_MAIN.read_text()
    assert 'source = "../../modules/clickhouse"' not in gke_main, (
        "Legacy ../../modules/clickhouse source still referenced in gcp-gke/main.tf"
    )


# ---------------------------------------------------------------------------
# 2. System of Record: WORM Bucket Posture & IAM (§1.1, §2.6, §5.1)
# ---------------------------------------------------------------------------


def test_worm_bucket_configured_as_system_of_record() -> None:
    """§1.1, §2.6: WORM bucket is instantiated in gcp-gke/main.tf with posture matrix lock & CMEK."""
    gke_main = _GKE_MAIN.read_text()
    block = _extract_module_block("worm_bucket", gke_main)

    assert 'source = "../../modules/worm_bucket"' in block
    assert "enable_cmek              = var.enable_cmek" in block
    assert "kms_key_id               = local.cmek_key_id" in block

    # Posture matrix (§1.1):
    # - staging: short retention lock (86400s)
    # - prod: 7yr retention lock (220752000s = 2555 days)
    # - dev: unlocked (is_locked = false)
    assert 'var.environment == "staging" ? 86400 : 220752000' in block
    assert (
        'is_locked                = var.environment == "prod" || var.environment == "staging" || var.enable_nist_compliance'
        in block
    )


def test_worm_bucket_module_enforces_retention_cmek_and_residency() -> None:
    """§2.6: infra/modules/worm_bucket enforces uniform access, retention policy, CMEK, and residency."""
    worm_main = _WORM_MAIN.read_text()
    assert "uniform_bucket_level_access = true" in worm_main
    assert 'public_access_prevention    = "enforced"' in worm_main
    assert "retention_policy {" in worm_main
    assert "retention_period = var.retention_period_seconds" in worm_main
    assert "is_locked        = var.is_locked" in worm_main
    assert "default_kms_key_name = var.kms_key_id" in worm_main

    # Data residency precondition
    assert 'var.cage_deployment_region == "EU_ECB"' in worm_main
    assert 'var.cage_deployment_region == "APAC_MAS"' in worm_main
    assert 'var.cage_deployment_region == "US_FED"' in worm_main


def test_compliance_bridge_wired_to_worm_bucket_and_object_creator_iam() -> None:
    """§2.6, §5.1: compliance-bridge writes to WORM bucket with roles/storage.objectCreator."""
    gke_main = _GKE_MAIN.read_text()
    cb_block = _extract_module_block("compliance_bridge", gke_main)

    assert "oscal_s3_bucket            = module.worm_bucket.bucket_name" in cb_block
    assert 'evidence_cold_store        = "gcs"' in cb_block
    assert "evidence_cold_store_bucket = module.worm_bucket.bucket_name" in cb_block
    assert "clickhouse_host            = module.clickhouse_operator.service_name" in cb_block

    cb_module_main = _COMPLIANCE_BRIDGE_MAIN.read_text()
    assert 'name  = "EVIDENCE_COLD_STORE"' in cb_module_main
    assert 'name  = "EVIDENCE_COLD_STORE_BUCKET"' in cb_module_main
    assert 'name  = "CMEK_KEY_RESOURCE_NAME"' in cb_module_main
    assert 'name  = "CLICKHOUSE_HOST"' in cb_module_main

    iam_text = _GKE_IAM.read_text()
    assert 'resource "google_storage_bucket_iam_member" "compliance_bridge_worm_creator"' in iam_text
    assert "bucket = module.worm_bucket.bucket_name" in iam_text
    assert 'role   = "roles/storage.objectCreator"' in iam_text


# ---------------------------------------------------------------------------
# 3. ClickHouse Operator & Posture Matrix (§1.1, §2.6)
# ---------------------------------------------------------------------------


def test_clickhouse_operator_module_posture_matrix() -> None:
    """§1.1, §2.6: prod uses Operator + ReplicatedMergeTree + 3-node Keeper + GCS cold tier; dev/staging uses 1 node on local SSD."""
    gke_main = _GKE_MAIN.read_text()
    ch_block = _extract_module_block("clickhouse_operator", gke_main)
    assert 'source = "../../modules/clickhouse_operator"' in ch_block
    assert "google_storage_bucket.clickhouse_tiering[0].name" in ch_block
    assert "module.worm_bucket" not in ch_block

    ch_op_main = _CH_OP_MAIN.read_text()
    ch_op_vars = _CH_OP_VARS.read_text()

    # Altinity ClickHouse Operator Helm release for prod/HA
    assert 'resource "helm_release" "clickhouse_operator"' in ch_op_main
    assert 'chart      = "altinity-clickhouse-operator"' in ch_op_main

    # ReplicatedMergeTree in prod/HA vs MergeTree in dev/staging
    assert (
        "ReplicatedMergeTree('/clickhouse/tables/{shard}/evidence_stream', '{replica}')"
        in ch_op_main
    )
    assert '"MergeTree()"' in ch_op_main

    # 3-node Keeper quorum in prod/HA, 0 in dev/staging; 3 ClickHouse replicas in prod/HA, 1 in dev/staging
    assert "replicas        = local.is_ha ? 3 : 1" in ch_op_main
    assert "keeper_replicas = local.is_ha ? 3 : 0" in ch_op_main
    assert 'resource "kubernetes_stateful_set" "clickhouse_keeper"' in ch_op_main

    # Local SSD hot tier + GCS cold tier storage policy
    assert 'default     = "local-ssd"' in ch_op_vars
    assert "<hot_local_ssd>" in ch_op_main
    assert "<cold_gcs>" in ch_op_main
    assert "<hot_to_cold>" in ch_op_main


def _extract_resource_block(rtype: str, name: str, text: str) -> str:
    start_str = f'resource "{rtype}" "{name}" {{'
    start = text.find(start_str)
    assert start != -1, f"resource {rtype}.{name} not found"
    pos = start + len(start_str)
    depth = 1
    while pos < len(text) and depth > 0:
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
        pos += 1
    return text[start:pos]


def test_clickhouse_tiering_bucket_is_dedicated_unlocked_and_cmek() -> None:
    """§2.6: ClickHouse deletes S3-disk objects on merge/TTL, so its cold tier is NOT the WORM bucket."""
    gke_main = _GKE_MAIN.read_text()
    bucket = _extract_resource_block("google_storage_bucket", "clickhouse_tiering", gke_main)
    bucket = "\n".join(line for line in bucket.splitlines() if not line.lstrip().startswith("#"))
    worm = _extract_module_block("worm_bucket", gke_main)

    # Distinct name from the WORM bucket (and a guard precondition).
    assert '"${var.project_id}-clickhouse-tiering-${var.environment}"' in bucket
    assert '"${var.project_id}-evidence-worm-${var.environment}"' in worm
    assert "!= module.worm_bucket.bucket_name" in bucket

    # Not retention-locked: no retention policy and no lock at all.
    assert "retention_policy" not in bucket
    assert "is_locked" not in bucket

    # CMEK-encrypted with the shared symmetric key, private, residency-guarded.
    assert "default_kms_key_name = local.cmek_key_id" in bucket
    assert "uniform_bucket_level_access = true" in bucket
    assert 'public_access_prevention    = "enforced"' in bucket
    assert 'var.cage_deployment_region == "EU_ECB"' in bucket


def test_clickhouse_tiering_bucket_iam_scoped_to_clickhouse_identity_only() -> None:
    """§2.6 / AC-6: only the ClickHouse GSA holds IAM on the tiering bucket; it holds none on WORM."""
    gke_main = _GKE_MAIN.read_text()
    iam_text = _GKE_IAM.read_text()
    combined = gke_main + "\n" + iam_text

    tiering_bindings = [
        m.group(0)
        for m in re.finditer(r'resource "google_storage_bucket_iam_[a-z]+" "\w+" \{[^}]*\}', combined, re.S)
        if "clickhouse_tiering" in m.group(0)
    ]
    assert tiering_bindings, "no IAM binding on the ClickHouse tiering bucket"
    for binding in tiering_bindings:
        assert "google_service_account.clickhouse.email" in binding
        assert 'role   = "roles/storage.objectAdmin"' in binding

    # ClickHouse GSA never touches the WORM bucket.
    for m in re.finditer(r'resource "google_storage_bucket_iam_[a-z]+" "\w+" \{[^}]*\}', combined, re.S):
        if "module.worm_bucket" in m.group(0):
            assert "google_service_account.clickhouse" not in m.group(0)

    # No project-wide storage role that would also reach the tiering bucket.
    for m in re.finditer(r'resource "google_project_iam_member" "\w+" \{.*?\n\}', iam_text, re.S):
        assert "roles/storage.object" not in m.group(0) or "condition {" in m.group(0), (
            f"Unconditioned project-wide storage role: {m.group(0)[:80]}"
        )

    # ClickHouse runs as its own KSA bound 1:1 to its own GSA; HMAC key is that GSA's.
    assert 'sa_clickhouse        = "cage-clickhouse"' in iam_text
    assert 'ksa_clickhouse        = "cage-clickhouse-sa"' in iam_text
    assert 'resource "google_service_account_iam_binding" "clickhouse_workload_identity"' in iam_text
    hmac = _extract_resource_block("google_storage_hmac_key", "clickhouse_tiering", gke_main)
    assert "google_service_account.clickhouse.email" in hmac
    ch_block = _extract_module_block("clickhouse_operator", gke_main)
    assert 'kubernetes_service_account.workload["clickhouse"]' in ch_block


def test_clickhouse_cold_tier_credentials_come_from_secret() -> None:
    """cold_gcs uses use_environment_credentials; creds must be secretKeyRef and required when active."""
    ch_op_main = _CH_OP_MAIN.read_text()
    assert "<use_environment_credentials>true</use_environment_credentials>" in ch_op_main
    assert '["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]' in ch_op_main
    assert "name = var.cold_tier_credentials_secret_name" in ch_op_main
    # Fail closed at plan time when the cold tier is on without credentials.
    assert "!local.cold_tier_on || var.cold_tier_credentials_secret_name != \"\"" in ch_op_main


# ---------------------------------------------------------------------------
# 4. Node Pool Isolation Guard (§3, §7 Pitfalls)
# ---------------------------------------------------------------------------


def test_clickhouse_node_pool_and_pod_scheduling_isolation() -> None:
    """§3, §7: ClickHouse node pool is tainted workload=clickhouse:NoSchedule with local SSD; pods require toleration + node affinity and forbid Spot."""
    cluster_main = _GKE_CLUSTER_MAIN.read_text()
    assert 'resource "google_container_node_pool" "clickhouse_nodes"' in cluster_main
    assert "spot = false" in cluster_main
    assert "local_nvme_ssd_block_config" in cluster_main
    assert 'key    = "workload"' in cluster_main
    assert 'value  = "clickhouse"' in cluster_main
    assert 'effect = "NO_SCHEDULE"' in cluster_main

    # Terraform ClickHouse & Keeper pods enforce toleration + node affinity + anti-Spot
    ch_op_main = _CH_OP_MAIN.read_text()
    assert 'key      = "workload"' in ch_op_main
    assert 'value    = "clickhouse"' in ch_op_main
    assert 'effect   = "NoSchedule"' in ch_op_main
    assert 'key      = "cloud.google.com/gke-spot"' in ch_op_main
    assert 'operator = "NotIn"' in ch_op_main

    # Raw K8s manifest (deployment/k8s/langfuse-db.yaml) enforces the same guards
    docs = [d for d in yaml.safe_load_all(_LANGFUSE_DB_YAML.read_text()) if isinstance(d, dict)]
    stateful_sets = [d for d in docs if d.get("kind") == "StatefulSet"]
    assert len(stateful_sets) == 1
    pod_spec = stateful_sets[0]["spec"]["template"]["spec"]

    tolerations = pod_spec.get("tolerations", [])
    assert any(
        t.get("key") == "workload"
        and t.get("value") == "clickhouse"
        and t.get("effect") == "NoSchedule"
        for t in tolerations
    ), f"Missing workload=clickhouse:NoSchedule toleration in langfuse-db.yaml: {tolerations}"

    terms = (
        pod_spec.get("affinity", {})
        .get("nodeAffinity", {})
        .get("requiredDuringSchedulingIgnoredDuringExecution", {})
        .get("nodeSelectorTerms", [])
    )
    expressions = [expr for term in terms for expr in term.get("matchExpressions", [])]
    assert any(
        e.get("key") == "workload"
        and e.get("operator") == "In"
        and "clickhouse" in e.get("values", [])
        for e in expressions
    ), f"Missing workload=clickhouse nodeAffinity in langfuse-db.yaml: {expressions}"
    assert any(
        e.get("key") == "cloud.google.com/gke-spot"
        and e.get("operator") == "NotIn"
        and "true" in e.get("values", [])
        for e in expressions
    ), f"Missing anti-Spot nodeAffinity in langfuse-db.yaml: {expressions}"


# ---------------------------------------------------------------------------
# 5. Exit Criteria Resilience Test (§6):
#    "Evidence reaches the locked bucket; ClickHouse node loss causes no evidence loss"
# ---------------------------------------------------------------------------


class _LockedWormColdStore(EvidenceColdStore):
    """Hermetic retention-locked WORM bucket fake enforcing write-once immutability."""

    def __init__(self, bucket_name: str = "cage-prod-evidence-worm-prod") -> None:
        self._bucket_name = bucket_name
        self.is_locked = True
        self.retention_period_seconds = 220752000
        self.objects: dict[str, bytes] = {}
        self.metadata: dict[str, dict[str, str]] = {}

    @property
    def backend_id(self) -> str:
        return "gcs"

    async def put_batch(
        self,
        key: str,
        content: bytes,
        metadata: Mapping[str, str] | None = None,
    ) -> ColdStoreReceipt:
        if key in self.objects:
            raise PermissionError(f"WORM retention lock violation: cannot overwrite {key}")
        self.objects[key] = content
        self.metadata[key] = dict(metadata or {})
        digest = hashlib.sha256(content).hexdigest()
        return ColdStoreReceipt(
            uri=f"gs://{self._bucket_name}/{key}",
            key=key,
            content_sha256=digest,
            backend_id="gcs",
            written_at=datetime.now(tz=timezone.utc),
        )

    async def exists(self, key: str) -> bool:
        return key in self.objects

    async def put_if_absent(
        self,
        key: str,
        content: bytes,
        metadata: Mapping[str, str] | None = None,
    ) -> tuple[ColdStoreReceipt, bool]:
        digest = hashlib.sha256(content).hexdigest()
        if key in self.objects:
            return (
                ColdStoreReceipt(
                    uri=f"gs://{self._bucket_name}/{key}",
                    key=key,
                    content_sha256=digest,
                    backend_id="gcs",
                    written_at=datetime.now(tz=timezone.utc),
                ),
                False,
            )
        receipt = await self.put_batch(key, content, metadata)
        return receipt, True

    def health(self) -> ColdStoreHealth:
        return ColdStoreHealth(
            available=True,
            backend_id="gcs",
            detail=f"WORM bucket gs://{self._bucket_name} (is_locked={self.is_locked})",
        )


@pytest.mark.asyncio
async def test_clickhouse_node_loss_causes_zero_evidence_loss_in_locked_worm_bucket() -> None:
    """§6 Exit Criteria: Evidence reaches the locked bucket; ClickHouse node loss causes no evidence loss.

    Option A custody: the gateway's EvidenceStreamSink only hash-chains and
    XADDs to the governance Redis stream; the compliance bridge's
    EvidenceCustodian re-verifies the chain and writes the batch to the WORM
    bucket. The ClickHouse query plane is down for the whole run.
    """
    from src.compliance_bridge.evidence_custodian import EvidenceCustodian

    stream_key = "cage:evidence:stream"
    worm_bucket = _LockedWormColdStore()
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)

    # 1. Gateway producer: EvidenceStreamSink appends to the Redis stream only.
    evidence_sink = EvidenceStreamSink(stream_key=stream_key)
    evidence_sink._redis = fake_redis  # type: ignore[assignment]
    async with evidence_sink._chain_lock:
        await evidence_sink._ensure_chain_restored()
    evidence_sink._running = True

    # 2. Simulate complete ClickHouse node loss (query plane down: ConnectionRefusedError)
    ch_sink = ClickHouseSink(
        host="clickhouse-dead-node.governance-stack.svc.cluster.local",
        port=8123,
        batch_size=2,
        flush_seconds=0.05,
    )
    ch_sink._max_retries = 1
    ch_sink._breaker._failure_threshold = 1

    mock_ch_module = MagicMock()
    mock_ch_module.get_client.side_effect = ConnectionRefusedError(
        "ClickHouse query-plane node terminated"
    )

    events = [
        {"type": "STERA_ALLOW", "controlId": "AU-9", "action": "rebalance", "seq": i}
        for i in range(5)
    ]

    with patch.dict("sys.modules", {"clickhouse_connect": mock_ch_module}):
        await ch_sink.start()
        try:
            for ev in events:
                # Commit to the primary evidence stream (gateway -> Redis Streams)
                commit = await evidence_sink.ingest_sync(ev)
                assert commit.success is True

                # Feed query-plane sink while ClickHouse node is completely down
                await ch_sink.ingest(
                    {
                        "schema": "cage-audit/3.0",
                        "chain_id": evidence_sink.chain_id,
                        "sequence": commit.sequence,
                        "timestamp_utc": commit.commit_timestamp.isoformat(),
                        "event_type": ev["type"],
                        "control_id": ev["controlId"],
                        "trace_id": "trace-worm-test",
                        "record_hash": commit.hash,
                        "payload_json": json.dumps(ev),
                    }
                )

            # Force query-plane flush attempt — must fail gracefully and open circuit breaker
            await asyncio.sleep(0.15)
            assert ch_sink._breaker.is_open() is True
        finally:
            await ch_sink.close()

    # 3. Compliance-bridge custodian: one custody cycle Redis stream -> locked WORM bucket
    custodian = EvidenceCustodian(
        redis=fake_redis,
        cold_store=worm_bucket,
        signer=None,
        stream_key=stream_key,
        batch_size=5000,
        require_signature=False,
    )
    outcome = await custodian.flush_once()
    assert outcome.entries == len(events)
    assert outcome.gap is False
    assert outcome.data_key is not None

    # 4. Verify 100% of evidence records reached the locked WORM bucket intact
    assert worm_bucket.is_locked is True
    expected_objects = {outcome.data_key}
    # signer=None (permissive): the attestation is non-evidentiary and segregated.
    assert outcome.evidentiary is False
    assert outcome.attestation_key == (
        outcome.data_key.removesuffix(".ndjson") + ".attestation.unsigned.json"
    )
    expected_objects.add(outcome.attestation_key)
    assert set(worm_bucket.objects) == expected_objects, (
        f"Unexpected objects in locked WORM bucket: {sorted(worm_bucket.objects)}"
    )

    batch_key = outcome.data_key
    batch_bytes = worm_bucket.objects[batch_key]
    assert batch_key.startswith("evidence-stream/")
    assert batch_key.endswith(".ndjson")

    persisted_records = [
        json.loads(line)
        for line in batch_bytes.decode("utf-8").strip().splitlines()
    ]
    assert len(persisted_records) == len(events), (
        f"Expected all {len(events)} records in locked WORM bucket despite ClickHouse loss, "
        f"got {len(persisted_records)}"
    )

    # Verify cryptographic hash chain continuity and RFC 8785 record hashes
    prev_hash = ""
    for expected_seq, record in enumerate(persisted_records):
        assert record.pop("stream_id")
        assert int(record["sequence"]) == expected_seq
        assert record["prev_hash"] == prev_hash
        verification = verify_record(record, prev_hash)
        assert verification.valid is True, f"Hash verification failed at seq {expected_seq}: {verification.error}"
        prev_hash = record["record_hash"]

    # 5. Durable cursor lives in "<stream_key>:custody"; a second cycle writes nothing new.
    assert await fake_redis.hgetall(f"{stream_key}:custody")
    again = await custodian.flush_once()
    assert again.entries == 0
    assert set(worm_bucket.objects) == expected_objects

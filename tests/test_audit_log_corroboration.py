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

"""Unit & Terraform contract tests for AS-6 Cloud Audit Log corroboration.

Covers:
1. Bidirectional 1-to-1 corroboration across ``gateway-seal`` (both 3-part
   compact JWS and JCS seal payloads), ``compliance-evidence`` (real
   ``EvidenceCustodian`` ``cage-evidence-batch/1`` attestations), and
   ``reconciler-snapshot`` (``ReconciliationResult.to_redis_payload()`` and
   ``RECONCILIATION_DISCREPANCY_FENCE``) using realistic non-empty base64
   Cloud KMS ``protoPayload.request.digest.sha256`` preimage digests.
2. Fail-closed rejection when the base64 KMS preimage digest differs from the
   artifact's JCS/JWS signing preimage digest (proving ``content_sha256`` hex or
   tampered preimages never match).
3. ``EvidenceCustodian`` ``created_at_utc`` stamping, crash-retry equivalence
   across wall-clock ticks in ``_same_attestation_body``, and fail-closed
   rejection when ``abs(created_at_utc - kms_timestamp) > max_skew_seconds``.
4. Caller service-account per-key isolation (``UNEXPECTED_SIGNER_PRINCIPAL``)
   and failed KMS calls (``FAILED_KMS_SIGN_EVENT``).
5. Control-plane & ``POAM-2026-192`` GKE ``k8s.io`` ``governance-stack``
   workload/Secret/ConfigMap/RBAC mutation detection.
6. CLI execution for ``cage-conformance verify-audit-corroboration`` and
   ``scripts/verify_audit_corroboration.py`` (offline + mocked live APIs).
7. Terraform IaC alignment with ``module.evidence_domain`` (zero duplicate
   buckets, static ``for_each`` keys, zero unescaped ``${...}`` in variable
   descriptions).
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch

import fakeredis.aioredis
import pytest

_REPO_ROOT_BOOTSTRAP = Path(__file__).resolve().parents[1]
_CONFORMANCE_SRC = _REPO_ROOT_BOOTSTRAP / "packages" / "cage-conformance" / "src"
if str(_CONFORMANCE_SRC) not in sys.path:
    sys.path.insert(0, str(_CONFORMANCE_SRC))

from cage_conformance import (
    COMPLIANCE_EVIDENCE_KEY,
    GATEWAY_SEAL_KEY,
    RECONCILER_SNAPSHOT_KEY,
    compute_kms_preimage_digest_b64,
    extract_signed_artifacts,
    verify_audit_corroboration,
)
from cage_conformance.cli import main as conformance_main
from cage_conformance.stream_invariants import jcs_bytes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

from scripts import verify_audit_corroboration as live_corroborator
from src.compliance_bridge.evidence_custodian import (
    CustodyStatus,
    EvidenceCustodian,
    _same_attestation_body,
)
from src.gateway.governance.evidence.cold_store import ColdStoreReceipt
from src.gateway.governance.evidence.stream import append_evidence_record_sync
from src.gateway.governance.kms_signer import (
    BaseKMSProvider,
    KMSGovernanceSigner,
)
from src.gateway.governance.reconciliation.daemon import ReconciliationResult
from src.gateway.governance.reconciliation.trust import snapshot_signing_payload

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parent.parent
PROJECT_ID = "cage-staging-proj"
KEYRING = f"projects/{PROJECT_ID}/locations/us-central1/keyRings/cage-signing-staging"
GATEWAY_KEY_V1 = f"{KEYRING}/cryptoKeys/gateway-seal/cryptoKeyVersions/1"
EVIDENCE_KEY_V1 = f"{KEYRING}/cryptoKeys/compliance-evidence/cryptoKeyVersions/1"
RECONCILER_KEY_V1 = f"{KEYRING}/cryptoKeys/reconciler-snapshot/cryptoKeyVersions/1"

GATEWAY_SA = f"cage-gateway@{PROJECT_ID}.iam.gserviceaccount.com"
BRIDGE_SA = f"cage-compliance-bridge@{PROJECT_ID}.iam.gserviceaccount.com"
RECONCILER_SA = f"cage-reconciler@{PROJECT_ID}.iam.gserviceaccount.com"
DEPLOYER_SA = f"sa-cage-deployer@{PROJECT_ID}.iam.gserviceaccount.com"


class _CapturingECDSAKMSProvider(BaseKMSProvider):
    """Real ECDSA P-256 KMS provider capturing exact SHA-256 digests sent to KMS."""

    def __init__(self, key_id: str) -> None:
        self._key_id = key_id
        self._priv = ec.generate_private_key(ec.SECP256R1())
        self.captured_digests_b64: list[str] = []

    @property
    def provider_name(self) -> str:
        return "GCP_CLOUD_KMS_TEST"

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign_digest(self, digest: bytes) -> bytes:
        self.captured_digests_b64.append(base64.b64encode(digest).decode("ascii"))
        return self._priv.sign(digest, ec.ECDSA(asym_utils.Prehashed(hashes.SHA256())))

    def sign_raw(self, message: bytes) -> bytes:
        raise NotImplementedError

    def get_public_key_pem(self) -> bytes:
        return self._priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )


class _MemoryColdStore:
    backend_id = "gcs"

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    async def put_if_absent(
        self, key: str, content: bytes, metadata: dict[str, str] | None = None
    ) -> tuple[ColdStoreReceipt, bool]:
        created = key not in self.objects
        if created:
            self.objects[key] = bytes(content)
        stored = self.objects[key]
        return (
            ColdStoreReceipt(
                uri=f"gs://test-worm/{key}",
                key=key,
                content_sha256=hashlib.sha256(stored).hexdigest(),
                backend_id="gcs",
                written_at=datetime.now(timezone.utc),
            ),
            created,
        )

    async def get(self, key: str) -> bytes:
        return self.objects[key]

    async def list_keys(self, prefix: str = "") -> list[str]:
        return sorted(k for k in self.objects if k.startswith(prefix))


def _sha256_b64(preimage: bytes) -> str:
    return base64.b64encode(hashlib.sha256(preimage).digest()).decode("ascii")


def _make_compact_jws(
    kid: str,
    *,
    nonce: str = "seal-nonce-001",
    iat: int = 1775500000,
) -> tuple[str, str]:
    header = {"alg": "ES256", "typ": "JWT", "kid": kid}
    payload = {
        "action_hash": "a" * 64,
        "canon": "RFC8785-JCS",
        "record_hash": "b" * 64,
        "nonce": nonce,
        "iat": iat,
        "exp": iat + 60,
        "iss": "cage-gateway",
        "aud": "cage-actuator:execute_trade",
    }
    b64_hdr = (
        base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    )
    b64_pay = (
        base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    )
    signing_input = f"{b64_hdr}.{b64_pay}".encode("ascii")
    b64_sig = base64.urlsafe_b64encode(b"r" * 32 + b"s" * 32).rstrip(b"=").decode()
    return f"{b64_hdr}.{b64_pay}.{b64_sig}", _sha256_b64(signing_input)


def _kms_sign_log(
    *,
    insert_id: str,
    resource_name: str,
    principal: str,
    timestamp: str,
    digest_b64: str,
    status_code: int = 0,
) -> dict[str, Any]:
    return {
        "insertId": insert_id,
        "logName": f"projects/{PROJECT_ID}/logs/cloudaudit.googleapis.com%2Fdata_access",
        "timestamp": timestamp,
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "serviceName": "cloudkms.googleapis.com",
            "methodName": "AsymmetricSign",
            "resourceName": resource_name,
            "authenticationInfo": {"principalEmail": principal},
            "status": {"code": status_code},
            "request": {"digest": {"sha256": digest_b64}},
        },
    }


def _admin_activity_log(
    *,
    insert_id: str,
    service_name: str,
    method_name: str,
    resource_name: str,
    principal: str,
    timestamp: str = "2026-04-06T18:27:00Z",
) -> dict[str, Any]:
    return {
        "insertId": insert_id,
        "logName": f"projects/{PROJECT_ID}/logs/cloudaudit.googleapis.com%2Factivity",
        "timestamp": timestamp,
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "serviceName": service_name,
            "methodName": method_name,
            "resourceName": resource_name,
            "authenticationInfo": {"principalEmail": principal},
            "status": {"code": 0},
        },
    }


class TestPreimageDigestAndBidirectionalCorroboration:
    """Verify exact base64 SHA-256 KMS signing preimage matching across all 3 keys."""

    def test_valid_nonempty_base64_preimage_digests_pass_across_all_three_keys(
        self,
    ) -> None:
        compact_jws, expected_jws_digest_b64 = _make_compact_jws(
            GATEWAY_KEY_V1, nonce="seal-jws-001", iat=1775500000
        )
        seal_record = {"decision_id": "dec-001", "routing_seal": compact_jws}

        attestation_body = {
            "schema": "cage-evidence-batch/1",
            "created_at_utc": "2026-04-06T18:26:50Z",
            "chain_id": "chain-alpha",
            "stream_key": "cage:evidence:stream",
            "first_sequence": 0,
            "last_sequence": 2,
            "first_stream_id": "1775500010000-0",
            "last_stream_id": "1775500010002-0",
            "first_prev_hash": "0" * 64,
            "last_record_hash": "c" * 64,
            "entries_count": 3,
            "content_sha256": "d" * 64,  # hex .ndjson hash — NOT what KMS signs!
            "data_key": "evidence-stream/2026/04/06/chain-alpha/000000000000-000000000002.ndjson",
            "gap": {"detected": False},
            "signature_status": "SIGNED",
            "evidentiary": True,
        }
        expected_batch_digest_b64 = _sha256_b64(jcs_bytes(attestation_body))
        batch_attestation = {
            **attestation_body,
            "signature": {
                "algorithm": "ECDSA_P256_SHA256",
                "key_id": EVIDENCE_KEY_V1,
                "value": "MEUCIQ...",
            },
        }

        reconciler_res = ReconciliationResult(
            source="custodian-sim",
            state_scalar=125000.5,
            verified_at=1775500020.0,
            signature="MEYCIQ...",
            sequence=7,
            invariant_id="finance.cash_balance",
            kms_key_id=RECONCILER_KEY_V1,
            signing_algorithm="ECDSA_P256_SHA256",
            settled_through=1775500015.0,
        )
        snapshot_redis_doc = json.loads(reconciler_res.to_redis_payload())
        expected_snapshot_digest_b64 = _sha256_b64(
            jcs_bytes(snapshot_signing_payload(reconciler_res))
        )

        # Sanity-check our preimage helper matches each real signing path byte-for-byte
        assert (
            compute_kms_preimage_digest_b64(seal_record, GATEWAY_SEAL_KEY)
            == expected_jws_digest_b64
        )
        assert (
            compute_kms_preimage_digest_b64(batch_attestation, COMPLIANCE_EVIDENCE_KEY)
            == expected_batch_digest_b64
        )
        assert (
            compute_kms_preimage_digest_b64(snapshot_redis_doc, RECONCILER_SNAPSHOT_KEY)
            == expected_snapshot_digest_b64
        )

        artifacts = (
            extract_signed_artifacts([seal_record], GATEWAY_SEAL_KEY)
            + extract_signed_artifacts([batch_attestation], COMPLIANCE_EVIDENCE_KEY)
            + extract_signed_artifacts([snapshot_redis_doc], RECONCILER_SNAPSHOT_KEY)
        )
        logs = [
            _kms_sign_log(
                insert_id="kms-1",
                resource_name=GATEWAY_KEY_V1,
                principal=GATEWAY_SA,
                timestamp="2026-04-06T18:26:41Z",
                digest_b64=expected_jws_digest_b64,
            ),
            _kms_sign_log(
                insert_id="kms-2",
                resource_name=EVIDENCE_KEY_V1,
                principal=BRIDGE_SA,
                timestamp="2026-04-06T18:26:51Z",
                digest_b64=expected_batch_digest_b64,
            ),
            _kms_sign_log(
                insert_id="kms-3",
                resource_name=RECONCILER_KEY_V1,
                principal=RECONCILER_SA,
                timestamp="2026-04-06T18:27:01Z",
                digest_b64=expected_snapshot_digest_b64,
            ),
            _admin_activity_log(
                insert_id="adm-1",
                service_name="cloudkms.googleapis.com",
                method_name="SetIamPolicy",
                resource_name=GATEWAY_KEY_V1,
                principal=DEPLOYER_SA,
            ),
        ]

        report = verify_audit_corroboration(
            logs,
            signed_artifacts=artifacts,
            trusted_deployer_principals=[DEPLOYER_SA],
        )
        assert report.corroborated is True, report.findings
        assert report.checked_artifacts == 3
        assert report.checked_kms_events == 3
        assert report.matched_pairs == 3
        assert report.findings == ()

    def test_mismatched_base64_kms_digest_fails_closed(self) -> None:
        """If KMS logged a different preimage digest (or ndjson content_sha256), fail closed."""
        attestation_body = {
            "schema": "cage-evidence-batch/1",
            "created_at_utc": "2026-04-06T18:26:50Z",
            "chain_id": "chain-beta",
            "stream_key": "cage:evidence:stream",
            "first_sequence": 0,
            "last_sequence": 0,
            "first_stream_id": "1775500010000-0",
            "last_stream_id": "1775500010000-0",
            "first_prev_hash": "0" * 64,
            "last_record_hash": "e" * 64,
            "entries_count": 1,
            "content_sha256": hashlib.sha256(b"raw-ndjson-bytes").hexdigest(),
            "data_key": "evidence-stream/2026/04/06/chain-beta/000000000000-000000000000.ndjson",
            "gap": {"detected": False},
            "signature_status": "SIGNED",
            "evidentiary": True,
        }
        batch_attestation = {
            **attestation_body,
            "signature": {
                "algorithm": "ECDSA_P256_SHA256",
                "key_id": EVIDENCE_KEY_V1,
                "value": "MEUCIQ...",
            },
        }
        # Wrong digest: base64 of raw .ndjson bytes instead of JCS(attestation_body)
        wrong_digest_b64 = _sha256_b64(b"raw-ndjson-bytes")

        report = verify_audit_corroboration(
            [
                _kms_sign_log(
                    insert_id="kms-wrong-digest",
                    resource_name=EVIDENCE_KEY_V1,
                    principal=BRIDGE_SA,
                    timestamp="2026-04-06T18:26:50Z",
                    digest_b64=wrong_digest_b64,
                )
            ],
            signed_artifacts=extract_signed_artifacts(
                [batch_attestation], COMPLIANCE_EVIDENCE_KEY
            ),
        )
        assert report.corroborated is False
        codes = {f.code for f in report.findings}
        assert "MISSING_KMS_SIGN_EVENT" in codes
        assert "UNMATCHED_KMS_SIGN_EVENT" in codes

    def test_reconciliation_discrepancy_fence_preimage_corroborates(self) -> None:
        fence_signed_body = {
            "type": "RECONCILIATION_DISCREPANCY_FENCE",
            "event_type": "RECONCILIATION_DISCREPANCY_FENCE",
            "schema_version": 1,
            "fence_epoch": 2,
            "fence_id": "finance.cash_balance:epoch:2",
            "invariant_id": "finance.cash_balance",
            "source": "custodian-sim",
            "sequence": 4,
            "state_scalar": 900.0,
            "signed_at": 1775500025.0,
        }
        expected_b64 = _sha256_b64(jcs_bytes(fence_signed_body))
        fence_record = {
            **fence_signed_body,
            "signature": "MEUCIQ...",
            "kms_key_id": RECONCILER_KEY_V1,
            "signing_algorithm": "ECDSA_P256_SHA256",
        }
        report = verify_audit_corroboration(
            [
                _kms_sign_log(
                    insert_id="kms-fence-1",
                    resource_name=RECONCILER_KEY_V1,
                    principal=RECONCILER_SA,
                    timestamp="2026-04-06T18:27:05Z",
                    digest_b64=expected_b64,
                )
            ],
            signed_artifacts=extract_signed_artifacts(
                [fence_record], RECONCILER_SNAPSHOT_KEY
            ),
        )
        assert report.corroborated is True, report.findings


class TestEvidenceCustodianTimestampAndClockSkew:
    """Verify EvidenceCustodian stamps created_at_utc, preserves retry idempotency, and enforces skew."""

    @pytest.mark.asyncio
    async def test_custodian_stamps_created_at_utc_and_enforces_clock_skew_window(
        self,
    ) -> None:
        sync_redis_server = fakeredis.FakeServer()
        sync_redis = fakeredis.FakeStrictRedis(
            server=sync_redis_server, decode_responses=True
        )
        async_redis = fakeredis.aioredis.FakeRedis(
            server=sync_redis_server, decode_responses=True
        )
        append_evidence_record_sync(
            sync_redis,
            {"type": "GOVERNANCE_DECISION", "action": "get_balance"},
            stream_key="cage:evidence:stream",
        )

        provider = _CapturingECDSAKMSProvider(key_id=EVIDENCE_KEY_V1)
        signer = KMSGovernanceSigner(provider=provider)
        cold_store = _MemoryColdStore()
        custodian = EvidenceCustodian(
            async_redis,
            cold_store,
            signer,
            stream_key="cage:evidence:stream",
            require_signature=True,
        )
        outcome = await custodian.flush_once()
        assert outcome.status == CustodyStatus.WRITTEN
        assert len(provider.captured_digests_b64) == 1

        att_bytes = await cold_store.get(outcome.attestation_key)
        att_doc = json.loads(att_bytes.decode("utf-8"))
        assert isinstance(att_doc.get("created_at_utc"), str)
        assert att_doc["created_at_utc"].endswith("Z")

        # Exact JCS preimage digest of the real EvidenceCustodian output MUST match
        # the exact 32-byte digest passed into BaseKMSProvider.sign_digest()!
        real_digest_b64 = compute_kms_preimage_digest_b64(
            att_doc, COMPLIANCE_EVIDENCE_KEY
        )
        assert real_digest_b64 == provider.captured_digests_b64[0]
        created_epoch = datetime.fromisoformat(
            att_doc["created_at_utc"].replace("Z", "+00:00")
        ).timestamp()

        # 1. Within 300s skew window -> PASS
        in_window_ts = (
            datetime.fromtimestamp(created_epoch + 12.0, tz=timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )
        ok_report = verify_audit_corroboration(
            [
                _kms_sign_log(
                    insert_id="kms-real-ok",
                    resource_name=EVIDENCE_KEY_V1,
                    principal=BRIDGE_SA,
                    timestamp=in_window_ts,
                    digest_b64=real_digest_b64,
                )
            ],
            signed_artifacts=extract_signed_artifacts(
                [att_doc], COMPLIANCE_EVIDENCE_KEY
            ),
            max_skew_seconds=300.0,
        )
        assert ok_report.corroborated is True, ok_report.findings

        # 2. Outside 300s skew window (e.g. +900s) -> FAIL CLOSED
        out_of_window_ts = (
            datetime.fromtimestamp(created_epoch + 900.0, tz=timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )
        skew_report = verify_audit_corroboration(
            [
                _kms_sign_log(
                    insert_id="kms-real-skew",
                    resource_name=EVIDENCE_KEY_V1,
                    principal=BRIDGE_SA,
                    timestamp=out_of_window_ts,
                    digest_b64=real_digest_b64,
                )
            ],
            signed_artifacts=extract_signed_artifacts(
                [att_doc], COMPLIANCE_EVIDENCE_KEY
            ),
            max_skew_seconds=300.0,
        )
        assert skew_report.corroborated is False
        assert {f.code for f in skew_report.findings} == {
            "MISSING_KMS_SIGN_EVENT",
            "UNMATCHED_KMS_SIGN_EVENT",
        }

    def test_same_attestation_body_ignores_created_at_utc_and_signature_on_crash_retry(
        self,
    ) -> None:
        first = json.dumps(
            {
                "schema": "cage-evidence-batch/1",
                "created_at_utc": "2026-04-06T18:26:50.100000Z",
                "chain_id": "c1",
                "content_sha256": "a" * 64,
                "signature": {"key_id": EVIDENCE_KEY_V1, "value": "sig-1"},
            }
        ).encode("utf-8")
        retry_one_second_later = json.dumps(
            {
                "schema": "cage-evidence-batch/1",
                "created_at_utc": "2026-04-06T18:26:51.900000Z",
                "chain_id": "c1",
                "content_sha256": "a" * 64,
                "signature": {"key_id": EVIDENCE_KEY_V1, "value": "sig-2"},
            }
        ).encode("utf-8")
        tampered = json.dumps(
            {
                "schema": "cage-evidence-batch/1",
                "created_at_utc": "2026-04-06T18:26:51.900000Z",
                "chain_id": "c1",
                "content_sha256": "b" * 64,
                "signature": {"key_id": EVIDENCE_KEY_V1, "value": "sig-2"},
            }
        ).encode("utf-8")
        assert _same_attestation_body(first, retry_one_second_later) is True
        assert _same_attestation_body(first, tampered) is False


class TestCallerIsolationAndControlPlaneMutations:
    """Verify caller SA isolation and POAM-2026-192 Kubernetes + GCP mutation detection."""

    def test_wrong_caller_sa_and_failed_kms_status_fail_closed(self) -> None:
        compact_jws, jws_digest = _make_compact_jws(GATEWAY_KEY_V1)
        report = verify_audit_corroboration(
            [
                _kms_sign_log(
                    insert_id="kms-wrong-sa",
                    resource_name=GATEWAY_KEY_V1,
                    principal=f"cage-advisor@{PROJECT_ID}.iam.gserviceaccount.com",
                    timestamp="2026-04-06T18:26:41Z",
                    digest_b64=jws_digest,
                ),
                _kms_sign_log(
                    insert_id="kms-denied",
                    resource_name=EVIDENCE_KEY_V1,
                    principal=BRIDGE_SA,
                    timestamp="2026-04-06T18:26:42Z",
                    digest_b64=jws_digest,
                    status_code=7,
                ),
            ],
            signed_artifacts=extract_signed_artifacts(
                [{"decision_id": "d1", "routing_seal": compact_jws}],
                GATEWAY_SEAL_KEY,
            ),
        )
        assert report.corroborated is False
        codes = {f.code for f in report.findings}
        assert "UNEXPECTED_SIGNER_PRINCIPAL" in codes
        assert "FAILED_KMS_SIGN_EVENT" in codes
        assert "MISSING_KMS_SIGN_EVENT" in codes

    @pytest.mark.parametrize(
        ("service_name", "method_name", "resource_name"),
        [
            (
                "k8s.io",
                "io.k8s.apps.v1.deployments.create",
                "apps/v1/namespaces/governance-stack/deployments/agentsight",
            ),
            (
                "k8s.io",
                "io.k8s.core.v1.secrets.patch",
                "core/v1/namespaces/governance-stack/secrets/gateway-secrets",
            ),
            (
                "k8s.io",
                "io.k8s.core.v1.configmaps.update",
                "core/v1/namespaces/governance-stack/configmaps/opa-policies",
            ),
            (
                "k8s.io",
                "io.k8s.rbac.authorization.k8s.io.v1.rolebindings.create",
                "rbac.authorization.k8s.io/v1/namespaces/governance-stack/rolebindings/rogue-admin",
            ),
            (
                "k8s.io",
                "io.k8s.rbac.authorization.k8s.io.v1.clusterrolebindings.create",
                "rbac.authorization.k8s.io/v1/clusterrolebindings/rogue-cluster-admin",
            ),
            (
                "k8s.io",
                "io.k8s.core.v1.namespaces.patch",
                "core/v1/namespaces/governance-stack",
            ),
            (
                "storage.googleapis.com",
                "storage.buckets.delete",
                f"projects/_/buckets/{PROJECT_ID}-audit-logs-worm-staging",
            ),
            (
                "logging.googleapis.com",
                "google.logging.v2.ConfigServiceV2.DeleteSink",
                f"projects/{PROJECT_ID}/sinks/cage-kms-signing-audit-staging",
            ),
            (
                "iam.googleapis.com",
                "google.iam.admin.v1.CreateServiceAccountKey",
                f"projects/{PROJECT_ID}/serviceAccounts/{GATEWAY_SA}",
            ),
        ],
    )
    def test_unauthorized_gcp_and_k8s_governance_stack_mutations_fail_closed(
        self,
        service_name: str,
        method_name: str,
        resource_name: str,
    ) -> None:
        report = verify_audit_corroboration(
            [
                _admin_activity_log(
                    insert_id="mut-1",
                    service_name=service_name,
                    method_name=method_name,
                    resource_name=resource_name,
                    principal="attacker@example.com",
                )
            ],
            trusted_deployer_principals=[DEPLOYER_SA],
        )
        assert report.corroborated is False
        assert len(report.findings) == 1
        assert report.findings[0].code == "UNAUTHORIZED_CONTROL_PLANE_MUTATION"

    def test_k8s_system_controllers_and_status_updates_do_not_false_positive(
        self,
    ) -> None:
        logs = [
            _admin_activity_log(
                insert_id="sys-1",
                service_name="k8s.io",
                method_name="io.k8s.coordination.v1.leases.update",
                resource_name="coordination.k8s.io/v1/namespaces/governance-stack/leases/leader",
                principal="system:serviceaccount:governance-stack:gateway",
            ),
            _admin_activity_log(
                insert_id="sys-2",
                service_name="k8s.io",
                method_name="io.k8s.apps.v1.deployments.status.patch",
                resource_name="apps/v1/namespaces/governance-stack/deployments/gateway/status",
                principal="system:kube-controller-manager",
            ),
            _admin_activity_log(
                insert_id="sys-3",
                service_name="k8s.io",
                method_name="io.k8s.batch.v1.jobs.create",
                resource_name="batch/v1/namespaces/governance-stack/jobs/lula-gate-w",
                principal=DEPLOYER_SA,
            ),
        ]
        report = verify_audit_corroboration(
            logs,
            trusted_deployer_principals=[DEPLOYER_SA],
        )
        assert report.corroborated is True, report.findings


class TestCliAndLiveRunner:
    """Verify cage-conformance CLI and scripts/verify_audit_corroboration.py."""

    def test_cage_conformance_cli_verify_audit_corroboration_subcommand(
        self, tmp_path: Path
    ) -> None:
        compact_jws, jws_digest = _make_compact_jws(GATEWAY_KEY_V1)
        seals_file = tmp_path / "seals.jsonl"
        seals_file.write_text(
            json.dumps({"decision_id": "d1", "routing_seal": compact_jws}) + "\n",
            encoding="utf-8",
        )
        logs_file = tmp_path / "audit.jsonl"
        logs_file.write_text(
            json.dumps(
                _kms_sign_log(
                    insert_id="cli-1",
                    resource_name=GATEWAY_KEY_V1,
                    principal=GATEWAY_SA,
                    timestamp="2026-04-06T18:26:41Z",
                    digest_b64=jws_digest,
                )
            )
            + "\n",
            encoding="utf-8",
        )
        out_report = tmp_path / "report.json"

        rc1 = conformance_main(
            [
                "verify-audit-corroboration",
                "--audit-logs",
                str(logs_file),
                "--seals",
                str(seals_file),
                "--project-id",
                PROJECT_ID,
                "--output",
                str(out_report),
            ]
        )
        assert rc1 == 0
        parsed = json.loads(out_report.read_text(encoding="utf-8"))
        assert parsed["corroborated"] is True
        assert parsed["matched_pairs"] == 1

        mismatch_logs_file = tmp_path / "audit-mismatch.jsonl"
        mismatch_logs_file.write_text(
            json.dumps(
                _kms_sign_log(
                    insert_id="cli-bad",
                    resource_name=GATEWAY_KEY_V1,
                    principal=BRIDGE_SA,
                    timestamp="2026-04-06T18:26:41Z",
                    digest_b64=jws_digest,
                )
            )
            + "\n",
            encoding="utf-8",
        )
        rc2 = conformance_main(
            [
                "verify-audit-corroboration",
                "--audit-logs",
                str(mismatch_logs_file),
                "--seals",
                str(seals_file),
                "--project-id",
                PROJECT_ID,
                "--json",
            ]
        )
        assert rc2 == 1

    def test_verify_audit_corroboration_script_live_mode_corroborates_and_fails_on_empty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        in_window_iso = (
            (datetime.now(timezone.utc) - timedelta(minutes=5))
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
        att_body = {
            "schema": "cage-evidence-batch/1",
            "created_at_utc": in_window_iso,
            "chain_id": "live-chain",
            "stream_key": "cage:evidence:stream",
            "first_sequence": 0,
            "last_sequence": 1,
            "first_stream_id": "1775500010000-0",
            "last_stream_id": "1775500010001-0",
            "first_prev_hash": "0" * 64,
            "last_record_hash": "f" * 64,
            "entries_count": 2,
            "content_sha256": "1" * 64,
            "data_key": "evidence-stream/2026/04/06/live-chain/000000000000-000000000001.ndjson",
            "gap": {"detected": False},
            "signature_status": "SIGNED",
            "evidentiary": True,
        }
        digest_b64 = _sha256_b64(jcs_bytes(att_body))
        att_doc = {
            **att_body,
            "signature": {
                "algorithm": "ECDSA_P256_SHA256",
                "key_id": EVIDENCE_KEY_V1,
                "value": "MEUCIQ...",
            },
        }
        # Include both a gateway-seal sign call (checked for caller SA isolation!)
        # and the compliance-evidence sign call (checked for 1-to-1 batch preimage!).
        mock_logs = [
            _kms_sign_log(
                insert_id="live-gw-1",
                resource_name=GATEWAY_KEY_V1,
                principal=GATEWAY_SA,
                timestamp=in_window_iso,
                digest_b64=digest_b64,
            ),
            _kms_sign_log(
                insert_id="live-ev-1",
                resource_name=EVIDENCE_KEY_V1,
                principal=BRIDGE_SA,
                timestamp=in_window_iso,
                digest_b64=digest_b64,
            ),
        ]

        monkeypatch.setenv("CAGE_GCP_ACCESS_TOKEN", "test-bearer-token")
        with (
            patch.object(
                live_corroborator, "fetch_audit_log_entries", return_value=mock_logs
            ),
            patch.object(
                live_corroborator,
                "fetch_signed_attestations",
                return_value=[att_doc],
            ),
        ):
            rc = live_corroborator.main(["--project", PROJECT_ID])
            assert rc == 0

        # Empty WORM archive in live mode must fail closed unless --allow-empty-evidence
        with (
            patch.object(live_corroborator, "fetch_audit_log_entries", return_value=[]),
            patch.object(
                live_corroborator, "fetch_signed_attestations", return_value=[]
            ),
        ):
            assert live_corroborator.main(["--project", PROJECT_ID]) == 1
            assert (
                live_corroborator.main(
                    ["--project", PROJECT_ID, "--allow-empty-evidence"]
                )
                == 0
            )

    def test_live_gcp_hex_digest_cainjector_and_gke_lro_completion_corroborate(
        self,
    ) -> None:
        import base64

        compact_jws, jws_digest_b64 = _make_compact_jws(GATEWAY_KEY_V1)
        jws_digest_hex = base64.b64decode(jws_digest_b64).hex()
        deployer = f"sa-cage-deployer@{PROJECT_ID}.iam.gserviceaccount.com"

        entries = [
            _kms_sign_log(
                insert_id="kms-hex-1",
                resource_name=GATEWAY_KEY_V1,
                principal=GATEWAY_SA,
                timestamp="2026-04-06T18:26:41Z",
                digest_b64=jws_digest_hex,
            ),
            {
                "insertId": "cainjector-webhook",
                "timestamp": "2026-04-06T18:26:42Z",
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "serviceName": "k8s.io",
                    "methodName": "io.k8s.admissionregistration.v1.validatingwebhookconfigurations.patch",
                    "resourceName": "admissionregistration.k8s.io/v1/validatingwebhookconfigurations/linkerd-policy-validator-k8s-io",
                    "authenticationInfo": {
                        "principalEmail": "system:serviceaccount:cert-manager:cert-manager-cainjector"
                    },
                },
            },
            {
                "insertId": "gke-lro-first",
                "timestamp": "2026-04-06T18:20:00Z",
                "operation": {"id": "operation-123", "first": True},
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "serviceName": "container.googleapis.com",
                    "methodName": "google.container.v1.ClusterManager.CreateCluster",
                    "resourceName": f"projects/{PROJECT_ID}/zones/us-central1-a/clusters/cage-staging",
                    "authenticationInfo": {"principalEmail": deployer},
                },
            },
            {
                "insertId": "gke-lro-last",
                "timestamp": "2026-04-06T18:25:00Z",
                "operation": {"id": "operation-123", "last": True},
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "serviceName": "container.googleapis.com",
                    "methodName": "google.container.v1.ClusterManager.CreateCluster",
                    "resourceName": f"projects/{PROJECT_ID}/zones/us-central1-a/clusters/cage-staging",
                    "authenticationInfo": {"principalEmail": ""},
                },
            },
        ]
        report = verify_audit_corroboration(
            entries,
            signed_artifacts=extract_signed_artifacts(
                [{"decision_id": "d-hex", "routing_seal": compact_jws}],
                GATEWAY_SEAL_KEY,
            ),
            trusted_deployer_principals=frozenset({deployer}),
        )
        assert report.corroborated is True
        assert report.matched_pairs == 1
        assert report.findings == ()

        # Non-webhook mutation by cert-manager-cainjector must still fail closed
        rogue_cainjector = [
            *entries,
            {
                "insertId": "cainjector-secret",
                "timestamp": "2026-04-06T18:26:43Z",
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "serviceName": "k8s.io",
                    "methodName": "io.k8s.core.v1.secrets.patch",
                    "resourceName": "core/v1/namespaces/governance-stack/secrets/gateway-secrets",
                    "authenticationInfo": {
                        "principalEmail": "system:serviceaccount:cert-manager:cert-manager-cainjector"
                    },
                },
            },
        ]
        rogue_report = verify_audit_corroboration(
            rogue_cainjector,
            signed_artifacts=extract_signed_artifacts(
                [{"decision_id": "d-hex", "routing_seal": compact_jws}],
                GATEWAY_SEAL_KEY,
            ),
            trusted_deployer_principals=frozenset({deployer}),
        )
        assert rogue_report.corroborated is False
        assert any(
            f.code == "UNAUTHORIZED_CONTROL_PLANE_MUTATION"
            for f in rogue_report.findings
        )

    def test_fresh_project_gcp_service_agent_bootstrap_corroborates_and_escalation_fails_closed(
        self,
    ) -> None:
        compact_jws, jws_digest_b64 = _make_compact_jws(GATEWAY_KEY_V1)
        deployer = f"sa-cage-deployer@{PROJECT_ID}.iam.gserviceaccount.com"
        base_entries: list[dict[str, Any]] = [
            _kms_sign_log(
                insert_id="kms-p4sa-1",
                resource_name=GATEWAY_KEY_V1,
                principal=GATEWAY_SA,
                timestamp="2026-04-06T18:26:42Z",
                digest_b64=jws_digest_b64,
            ),
            {
                "insertId": "p4sa-add-memorystore",
                "timestamp": "2026-04-06T18:20:00Z",
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "serviceName": "cloudresourcemanager.googleapis.com",
                    "methodName": "SetIamPolicy",
                    "resourceName": f"projects/{PROJECT_ID}",
                    "authenticationInfo": {
                        "principalEmail": "service-agent-manager@system.gserviceaccount.com"
                    },
                    "status": {},
                    "serviceData": {
                        "policyDelta": {
                            "bindingDeltas": [
                                {
                                    "action": "ADD",
                                    "member": "serviceAccount:service-123456789012@gcp-sa-memorystore.iam.gserviceaccount.com",
                                    "role": "roles/memorystore.serviceAgent",
                                },
                                {
                                    "action": "ADD",
                                    "member": "serviceAccount:service-123456789012@gcp-sa-gkenode.iam.gserviceaccount.com",
                                    "role": "roles/container.defaultNodeServiceAgent",
                                },
                            ]
                        }
                    },
                },
            },
            {
                "insertId": "p4sa-retry-aborted",
                "timestamp": "2026-04-06T18:20:01Z",
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "serviceName": "cloudresourcemanager.googleapis.com",
                    "methodName": "SetIamPolicy",
                    "resourceName": f"projects/{PROJECT_ID}",
                    "authenticationInfo": {
                        "principalEmail": "service-agent-manager@system.gserviceaccount.com"
                    },
                    "status": {"code": 10, "message": "ABORTED"},
                    "serviceData": None,
                },
            },
            {
                "insertId": "p4sa-retry-invalid-arg",
                "timestamp": "2026-04-06T18:20:02Z",
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "serviceName": "cloudresourcemanager.googleapis.com",
                    "methodName": "SetIamPolicy",
                    "resourceName": f"projects/{PROJECT_ID}",
                    "authenticationInfo": {
                        "principalEmail": "service-agent-manager@system.gserviceaccount.com"
                    },
                    "status": {"code": 3, "message": "INVALID_ARGUMENT"},
                    "serviceData": None,
                },
            },
        ]
        artifacts = extract_signed_artifacts(
            [{"decision_id": "d-p4sa", "routing_seal": compact_jws}],
            GATEWAY_SEAL_KEY,
        )
        ok_report = verify_audit_corroboration(
            base_entries,
            signed_artifacts=artifacts,
            trusted_deployer_principals=frozenset({deployer}),
        )
        assert ok_report.corroborated is True
        assert ok_report.findings == ()

        bad_cases: list[dict[str, Any]] = [
            # 1. Privilege escalation role (roles/owner)
            {
                "insertId": "p4sa-owner-role",
                "timestamp": "2026-04-06T18:21:00Z",
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "serviceName": "cloudresourcemanager.googleapis.com",
                    "methodName": "SetIamPolicy",
                    "resourceName": f"projects/{PROJECT_ID}",
                    "authenticationInfo": {
                        "principalEmail": "service-agent-manager@system.gserviceaccount.com"
                    },
                    "status": {},
                    "serviceData": {
                        "policyDelta": {
                            "bindingDeltas": [
                                {
                                    "action": "ADD",
                                    "member": "serviceAccount:service-123456789012@gcp-sa-memorystore.iam.gserviceaccount.com",
                                    "role": "roles/owner",
                                }
                            ]
                        }
                    },
                },
            },
            # 2. Non-P4SA member bound to a ServiceAgent role
            {
                "insertId": "p4sa-non-p4sa-member",
                "timestamp": "2026-04-06T18:21:01Z",
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "serviceName": "cloudresourcemanager.googleapis.com",
                    "methodName": "SetIamPolicy",
                    "resourceName": f"projects/{PROJECT_ID}",
                    "authenticationInfo": {
                        "principalEmail": "service-agent-manager@system.gserviceaccount.com"
                    },
                    "status": {},
                    "serviceData": {
                        "policyDelta": {
                            "bindingDeltas": [
                                {
                                    "action": "ADD",
                                    "member": f"serviceAccount:cage-gateway@{PROJECT_ID}.iam.gserviceaccount.com",
                                    "role": "roles/memorystore.serviceAgent",
                                }
                            ]
                        }
                    },
                },
            },
            # 3. Audit-config tampering (auditConfigDeltas non-empty)
            {
                "insertId": "p4sa-audit-config-tamper",
                "timestamp": "2026-04-06T18:21:02Z",
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "serviceName": "cloudresourcemanager.googleapis.com",
                    "methodName": "SetIamPolicy",
                    "resourceName": f"projects/{PROJECT_ID}",
                    "authenticationInfo": {
                        "principalEmail": "service-agent-manager@system.gserviceaccount.com"
                    },
                    "status": {},
                    "serviceData": {
                        "policyDelta": {
                            "auditConfigDeltas": [
                                {
                                    "action": "REMOVE",
                                    "service": "cloudkms.googleapis.com",
                                }
                            ],
                            "bindingDeltas": [
                                {
                                    "action": "ADD",
                                    "member": "serviceAccount:service-123456789012@gcp-sa-memorystore.iam.gserviceaccount.com",
                                    "role": "roles/memorystore.serviceAgent",
                                }
                            ],
                        }
                    },
                },
            },
            # 4. PERMISSION_DENIED (status.code == 7) must not be silently dropped
            {
                "insertId": "p4sa-perm-denied",
                "timestamp": "2026-04-06T18:21:03Z",
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "serviceName": "cloudresourcemanager.googleapis.com",
                    "methodName": "SetIamPolicy",
                    "resourceName": f"projects/{PROJECT_ID}",
                    "authenticationInfo": {
                        "principalEmail": "service-agent-manager@system.gserviceaccount.com"
                    },
                    "status": {"code": 7, "message": "PERMISSION_DENIED"},
                    "serviceData": None,
                },
            },
        ]
        for bad_entry in bad_cases:
            bad_report = verify_audit_corroboration(
                [*base_entries, bad_entry],
                signed_artifacts=artifacts,
                trusted_deployer_principals=frozenset({deployer}),
            )
            assert bad_report.corroborated is False, bad_entry["insertId"]
            assert any(
                f.code == "UNAUTHORIZED_CONTROL_PLANE_MUTATION"
                and f.subject == bad_entry["insertId"]
                for f in bad_report.findings
            )


class TestTerraformAuditLogSinkAlignment:
    """Verify kms_signing.tf routes directly into module.evidence_domain without collisions."""

    def test_kms_signing_tf_uses_evidence_domain_bucket_and_static_sink_keys(
        self,
    ) -> None:
        kms_tf = (
            REPO_ROOT / "infra" / "targets" / "gcp-gke" / "kms_signing.tf"
        ).read_text(encoding="utf-8")
        main_tf = (REPO_ROOT / "infra" / "targets" / "gcp-gke" / "main.tf").read_text(
            encoding="utf-8"
        )
        vars_tf = (
            REPO_ROOT / "infra" / "targets" / "gcp-gke" / "variables.tf"
        ).read_text(encoding="utf-8")

        assert (
            'resource "google_project_iam_audit_config" "kms_signing_audit"' in kms_tf
        )
        assert 'log_type = "DATA_READ"' in kms_tf
        assert 'resource "google_logging_project_sink" "kms_asymmetric_sign"' in kms_tf
        assert 'resource "google_logging_project_sink" "admin_activity"' in kms_tf
        assert (
            'destination            = "storage.googleapis.com/${module.evidence_domain.audit_logs_worm_bucket_name}"'
            in kms_tf
        )
        # Must NOT create duplicate audit_log_archive bucket or computed toset IAM in kms_signing.tf
        assert 'resource "google_storage_bucket" "audit_log_archive"' not in kms_tf
        assert "toset([" not in kms_tf
        assert "local.managed_audit_log_sink_writer_identities" in main_tf

        # Variable descriptions must contain zero unescaped ${...} interpolations
        for block in vars_tf.split("variable "):
            if "description" in block:
                desc_section = block.split("\n\n", 1)[0]
                assert "${var." not in desc_section

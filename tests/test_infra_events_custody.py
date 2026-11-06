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

"""Tests for INFRA event mesh custody & audit ingest auth (F-85 / R-3 / §11a).

Verifies all five F-85 controls before any live INFRA producer is turned on:
1. Verified Linkerd mesh identity on ``POST /v1/infra/events`` AND
   ``POST /v1/audit/ingest`` (refusing shared bearer tokens, loopback peers
   without LT-1 opt-in, external peers, duplicate/malformed ``l5d-client-id``
   headers, and untrusted workloads such as ``cage-advisor-sa``), plus server
   derivation of ``source``/``namespace``/``pod_name`` and HTTP 403 rejection of
   caller-asserted mismatches or unverified ``pod_name`` claims.
2. Server-side ``received_at_utc`` receipt stamping while preserving caller
   ``timestamp_utc`` strictly as unverified ``producer_timestamp_utc``.
3. Deterministic RFC 8785 JCS / canonical JSON full-payload ``record_hash``
   covering ``summary``, ``received_at_utc``, mesh-derived identity fields, and
   all claim fields (zero ``time.monotonic()``; zero nil ``chain_id``), linked
   by ``prev_hash`` + ``sequence`` in a real ``INFRA`` Redis Stream custodied by
   ``EvidenceCustodian`` (``compliance-evidence`` attestation signature) and
   verified end-to-end by ``CustodyVerifier``.
4. Fail-closed HTTP 503 whenever durable Redis Stream or inline WORM cold-store
   persistence raises or reports failure (defaulting inline flush to ``true``
   under enforcing postures on both ``/v1/infra/events`` and ``/v1/audit/ingest``)
   — never HTTP 200 ``INGESTED``.
5. Per-producer ``Idempotency-Key`` safe retries (returning the original receipt
   without duplicating chain records), partial-failure sink completion on retry,
   cross-producer key isolation, and HTTP 409 on payload mutation.
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.datastructures import Headers

from src.compliance_bridge import main as bridge_main
from src.compliance_bridge.auth import (
    TRUSTED_AUDIT_PRODUCERS_ENV,
    TRUSTED_INFRA_PRODUCERS_ENV,
    require_audit_ingest_producer,
    require_infra_event_producer,
)
from src.compliance_bridge.evidence_custodian import EvidenceCustodian
from src.compliance_bridge.evidence_verifier import (
    CustodyVerifier,
    build_attestation_verifier,
)
from src.compliance_bridge.infra_custody import (
    DEFAULT_INFRA_STREAM_KEY,
    INFRA_INLINE_FLUSH_ENV,
    InfraEvidenceChain,
    canonical_payload_json,
    compute_infra_record_hash,
)
from src.compliance_bridge.main import app
from src.gateway.governance.evidence.cold_store import ColdStoreError, ColdStoreReceipt
from src.gateway.governance.evidence.null_cold_store import NullColdStore
from src.gateway.governance.evidence.stream import (
    EvidenceStreamSink,
    _link_hash,
    verify_record,
)
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.kms_signer import (
    KMSGovernanceSigner,
    SoftwareEd25519Provider,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

POD_IP = "10.24.1.7"
PROXY_PEER = (POD_IP, 50000)
BASE_URL = f"http://{POD_IP}:3001"
OTHER_POD_PEER = ("10.112.3.7", 51000)
LOOPBACK_PEER = ("127.0.0.1", 52000)

AGENTSIGHT_L5D = (
    "agentsight-daemon.governance-stack.serviceaccount.identity.linkerd.cluster.local"
)
AGENTSIGHT_SVID = "spiffe://cluster.local/ns/governance-stack/sa/agentsight-daemon"
CILIUM_L5D = (
    "cilium-monitor-exporter.kube-system.serviceaccount.identity.linkerd.cluster.local"
)
LULA_L5D = "lula-auditor.governance-stack.serviceaccount.identity.linkerd.cluster.local"
ADVISOR_L5D = (
    "cage-advisor-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"
)
BRIDGE_SA_L5D = "cage-compliance-bridge-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"

KID = (
    "projects/p/locations/l/keyRings/r/cryptoKeys/compliance-evidence/"
    "cryptoKeyVersions/1"
)

MINIMAL_OSCAL_YAML = """
assessment-results:
  uuid: "custody-audit-001"
  metadata:
    last-modified: "2026-11-05T00:00:00Z"
  results:
    - uuid: "res-001"
      findings:
        - uuid: "find-001"
          title: "AU-2 check"
          target:
            type: objective-id
            target-id: "A.5.2"
            status:
              state: "satisfied"
"""


class _PodSvidTransportWrapper:
    """ASGI test wrapper simulating a substrate transport pod SVID binding."""

    def __init__(self, inner, pod_svid: object) -> None:
        self._inner = inner
        self._pod_svid = pod_svid

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "http":
            scope = {**scope, "transport_pod_svid": self._pod_svid}
        await self._inner(scope, receive, send)


def _sample_event(**overrides) -> dict:
    body = {
        "event_type": "agentsight_syscall",
        "timestamp_utc": "2026-09-06T20:00:00Z",
        "summary": "execve(/usr/bin/python3)",
        "control_hint": "AU-2",
    }
    body.update(overrides)
    return body


@pytest.fixture(autouse=True)
def _clean_bridge_env_and_state(monkeypatch: pytest.MonkeyPatch):
    for var in (
        "CAGE_ENV",
        "ENVIRONMENT",
        "CAGE_DEPLOYMENT_REGION",
        "CAGE_ALLOW_DEV_LOOPBACK_IDENTITY",
        "CAGE_INTERNAL_TOKEN",
        "COMPLIANCE_BRIDGE_INTERNAL_TOKEN",
        "EVIDENCE_STREAM_ENABLED",
        INFRA_INLINE_FLUSH_ENV,
        TRUSTED_INFRA_PRODUCERS_ENV,
        TRUSTED_AUDIT_PRODUCERS_ENV,
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("CAGE_ENV", "dev")
    monkeypatch.setenv("EVIDENCE_STREAM_ENABLED", "false")
    monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "US_FED")

    for attr in (
        "infra_evidence_chain",
        "infra_evidence_custodian",
        "infra_custody_flusher",
    ):
        if hasattr(app.state, attr):
            delattr(app.state, attr)
    app.dependency_overrides.clear()
    yield
    for attr in (
        "infra_evidence_chain",
        "infra_evidence_custodian",
        "infra_custody_flusher",
    ):
        if hasattr(app.state, attr):
            delattr(app.state, attr)
    app.dependency_overrides.clear()


@pytest.fixture
def fake_server() -> fakeredis.FakeServer:
    return fakeredis.FakeServer()


@pytest.fixture
def redis_client(fake_server: fakeredis.FakeServer):
    return fakeredis.FakeAsyncRedis(server=fake_server, decode_responses=True)


@pytest.fixture
def infra_chain(fake_server: fakeredis.FakeServer) -> InfraEvidenceChain:
    chain = InfraEvidenceChain(
        fakeredis.FakeAsyncRedis(server=fake_server, decode_responses=True),
        stream_key="cage:evidence:infra:test",
    )
    app.state.infra_evidence_chain = chain
    return chain


@pytest.fixture
def mesh_client(infra_chain: InfraEvidenceChain):
    with patch("src.compliance_bridge.main.Langfuse", return_value=MagicMock()):
        with TestClient(
            app,
            client=PROXY_PEER,
            base_url=BASE_URL,
            raise_server_exceptions=False,
        ) as c:
            yield c


# ---------------------------------------------------------------------------
# 1. Producer mesh identity auth & caller-claim spoofing protection
# ---------------------------------------------------------------------------


class TestMeshProducerAuthentication:
    """Verify Linkerd workload identity enforcement on /v1/infra/events and /v1/audit/ingest."""

    def test_missing_l5d_header_returns_401_even_with_valid_internal_token_in_dev(
        self,
        mesh_client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", "dev")
        monkeypatch.setenv("CAGE_INTERNAL_TOKEN", "shared-internal-secret")
        monkeypatch.setenv("COMPLIANCE_BRIDGE_INTERNAL_TOKEN", "shared-internal-secret")
        token_headers = {
            "Authorization": "Bearer shared-internal-secret",
            "X-Cage-Internal-Token": "shared-internal-secret",
        }

        res_infra = mesh_client.post(
            "/v1/infra/events", json=_sample_event(), headers=token_headers
        )
        assert res_infra.status_code == 401

        res_audit = mesh_client.post(
            "/v1/audit/ingest",
            json={"oscal_yaml": MINIMAL_OSCAL_YAML, "audit_id": "tok-rejected"},
            headers=token_headers,
        )
        assert res_audit.status_code == 401

    @pytest.mark.parametrize(
        "loopback_host",
        ["127.0.0.1", "::1", "::ffff:127.0.0.1"],
    )
    def test_loopback_peer_rejected_without_lt1_opt_in(
        self,
        infra_chain: InfraEvidenceChain,
        monkeypatch: pytest.MonkeyPatch,
        loopback_host: str,
    ) -> None:
        """kubectl port-forward / pod-local loopback cannot forge l5d-client-id (POAM-2026-167)."""
        monkeypatch.setenv("CAGE_ENV", "dev")
        with patch("src.compliance_bridge.main.Langfuse", return_value=MagicMock()):
            with TestClient(
                app,
                client=(loopback_host, 53000),
                base_url="http://127.0.0.1:3001",
                raise_server_exceptions=False,
            ) as c:
                r1 = c.post(
                    "/v1/infra/events",
                    json=_sample_event(),
                    headers={"l5d-client-id": AGENTSIGHT_L5D},
                )
                r2 = c.post(
                    "/v1/audit/ingest",
                    json={"oscal_yaml": MINIMAL_OSCAL_YAML},
                    headers={"l5d-client-id": LULA_L5D},
                )
        assert r1.status_code == 401
        assert r2.status_code == 401

    def test_external_pod_peer_bypassing_proxy_rejected_401(
        self, infra_chain: InfraEvidenceChain
    ) -> None:
        with patch("src.compliance_bridge.main.Langfuse", return_value=MagicMock()):
            with TestClient(
                app,
                client=OTHER_POD_PEER,
                base_url=BASE_URL,
                raise_server_exceptions=False,
            ) as c:
                r1 = c.post(
                    "/v1/infra/events",
                    json=_sample_event(),
                    headers={"l5d-client-id": AGENTSIGHT_L5D},
                )
                r2 = c.post(
                    "/v1/audit/ingest",
                    json={"oscal_yaml": MINIMAL_OSCAL_YAML},
                    headers={"l5d-client-id": LULA_L5D},
                )
        assert r1.status_code == 401
        assert r2.status_code == 401

    def test_lt1_dev_loopback_opt_in_admits_loopback_only_in_non_enforcing_dev(
        self,
        infra_chain: InfraEvidenceChain,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", "development")
        monkeypatch.setenv("CAGE_ALLOW_DEV_LOOPBACK_IDENTITY", "true")
        with (
            patch("src.compliance_bridge.main.Langfuse", return_value=MagicMock()),
            patch(
                "src.compliance_bridge.main.run_audit_workflow",
                new=AsyncMock(
                    return_value={
                        "findings_count": 1,
                        "artifact_key": "k",
                        "ingested": 1,
                        "alerted": False,
                        "alert_targets": [],
                        "remediation_sent": False,
                        "remediation_text": None,
                        "advisor_error": None,
                    }
                ),
            ),
        ):
            with TestClient(
                app,
                client=LOOPBACK_PEER,
                base_url="http://127.0.0.1:3001",
                raise_server_exceptions=False,
            ) as c:
                r_infra = c.post(
                    "/v1/infra/events",
                    json=_sample_event(),
                    headers={"l5d-client-id": AGENTSIGHT_L5D},
                )
                r_audit = c.post(
                    "/v1/audit/ingest",
                    json={"oscal_yaml": MINIMAL_OSCAL_YAML, "audit_id": "lt1-audit"},
                    headers={"l5d-client-id": LULA_L5D},
                )
        assert r_infra.status_code == 200
        assert r_infra.json()["source"] == "agentsight-daemon"
        assert r_audit.status_code == 200
        assert r_audit.json()["producer_svid"] == (
            "spiffe://cluster.local/ns/governance-stack/sa/lula-auditor"
        )

    @pytest.mark.asyncio
    async def test_lt1_forbidden_in_enforcing_posture_at_startup_and_request_time(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", "staging")
        monkeypatch.setenv("CAGE_ALLOW_DEV_LOOPBACK_IDENTITY", "true")

        req = SimpleNamespace(
            headers=Headers(raw=[(b"l5d-client-id", AGENTSIGHT_L5D.encode())]),
            attributes=None,
            client=SimpleNamespace(host="127.0.0.1"),
            scope={"client": LOOPBACK_PEER, "server": ("127.0.0.1", 3001)},
        )
        with pytest.raises(HTTPException) as exc_info:
            await require_infra_event_producer(req)  # type: ignore[arg-type]
        assert exc_info.value.status_code == 401

        with patch("src.compliance_bridge.main.Langfuse", return_value=MagicMock()):
            with pytest.raises(RuntimeError, match="CAGE_ALLOW_DEV_LOOPBACK_IDENTITY"):
                with TestClient(app):
                    pass

    @pytest.mark.asyncio
    async def test_enforcing_default_posture_enforces_pod_local_mesh_identity(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("CAGE_ENV", raising=False)
        monkeypatch.setenv("CAGE_INTERNAL_TOKEN", "prod-shared-secret")

        bearer_only = SimpleNamespace(
            headers=Headers(raw=[(b"authorization", b"Bearer prod-shared-secret")]),
            attributes=None,
            client=SimpleNamespace(host=POD_IP),
            scope={"client": PROXY_PEER, "server": (POD_IP, 3001)},
        )
        with pytest.raises(HTTPException) as b_exc:
            await require_infra_event_producer(bearer_only)  # type: ignore[arg-type]
        assert b_exc.value.status_code == 401

        loopback_forged = SimpleNamespace(
            headers=Headers(raw=[(b"l5d-client-id", AGENTSIGHT_L5D.encode())]),
            attributes=None,
            client=SimpleNamespace(host="127.0.0.1"),
            scope={"client": LOOPBACK_PEER, "server": ("127.0.0.1", 3001)},
        )
        with pytest.raises(HTTPException) as lb_exc:
            await require_infra_event_producer(loopback_forged)  # type: ignore[arg-type]
        assert lb_exc.value.status_code == 401

        valid_mesh = SimpleNamespace(
            headers=Headers(raw=[(b"l5d-client-id", LULA_L5D.encode())]),
            attributes=None,
            client=SimpleNamespace(host=POD_IP),
            scope={"client": PROXY_PEER, "server": (POD_IP, 3001)},
        )
        principal = await require_audit_ingest_producer(valid_mesh)  # type: ignore[arg-type]
        assert principal.channel_provenance == "LINKERD_MTLS"
        assert principal.service_account == "lula-auditor"
        assert principal.namespace == "governance-stack"

    def test_audit_ingest_background_records_mesh_producer_provenance(
        self, mesh_client: TestClient
    ) -> None:
        with patch(
            "src.compliance_bridge.main.run_audit_workflow",
            new=AsyncMock(
                return_value={
                    "findings_count": 2,
                    "artifact_key": "audit/bg.json",
                    "ingested": 2,
                    "alerted": False,
                    "alert_targets": [],
                    "remediation_sent": False,
                    "remediation_text": None,
                    "advisor_error": None,
                }
            ),
        ):
            res = mesh_client.post(
                "/v1/audit/ingest?background=true",
                json={"oscal_yaml": MINIMAL_OSCAL_YAML, "audit_id": "bg-mesh-001"},
                headers={"l5d-client-id": LULA_L5D},
            )
        assert res.status_code == 200
        data = res.json()
        assert (
            data["producer_svid"]
            == "spiffe://cluster.local/ns/governance-stack/sa/lula-auditor"
        )
        assert data["producer_source"] == "lula-auditor"
        assert data["producer_namespace"] == "governance-stack"
        stored = bridge_main._audit_status["bg-mesh-001"]
        assert stored["producer_source"] == "lula-auditor"
        assert stored["producer_namespace"] == "governance-stack"

    @pytest.mark.asyncio
    async def test_duplicate_and_malformed_l5d_headers_rejected_401(self) -> None:
        dup_req = SimpleNamespace(
            headers=Headers(
                raw=[
                    (b"l5d-client-id", AGENTSIGHT_L5D.encode()),
                    (b"l5d-client-id", CILIUM_L5D.encode()),
                ]
            ),
            attributes=None,
            client=SimpleNamespace(host=POD_IP),
            scope={"client": PROXY_PEER, "server": (POD_IP, 3001)},
        )
        with pytest.raises(HTTPException) as dup_exc:
            await require_infra_event_producer(dup_req)  # type: ignore[arg-type]
        assert dup_exc.value.status_code == 401
        assert "Multiple" in str(dup_exc.value.detail)

        bad_req = SimpleNamespace(
            headers=Headers(
                raw=[(b"l5d-client-id", b"spiffe://cluster.local/ns/x/sa/y")]
            ),
            attributes=None,
            client=SimpleNamespace(host=POD_IP),
            scope={"client": PROXY_PEER, "server": (POD_IP, 3001)},
        )
        with pytest.raises(HTTPException) as bad_exc:
            await require_audit_ingest_producer(bad_req)  # type: ignore[arg-type]
        assert bad_exc.value.status_code == 401

    def test_untrusted_workloads_and_cross_endpoint_roles_rejected_403(
        self, mesh_client: TestClient
    ) -> None:
        r_adv_infra = mesh_client.post(
            "/v1/infra/events",
            json=_sample_event(),
            headers={"l5d-client-id": ADVISOR_L5D},
        )
        r_adv_audit = mesh_client.post(
            "/v1/audit/ingest",
            json={"oscal_yaml": MINIMAL_OSCAL_YAML},
            headers={"l5d-client-id": ADVISOR_L5D},
        )
        assert r_adv_infra.status_code == 403
        assert r_adv_audit.status_code == 403

        r_lula_infra = mesh_client.post(
            "/v1/infra/events",
            json=_sample_event(),
            headers={"l5d-client-id": LULA_L5D},
        )
        r_agent_audit = mesh_client.post(
            "/v1/audit/ingest",
            json={"oscal_yaml": MINIMAL_OSCAL_YAML},
            headers={"l5d-client-id": AGENTSIGHT_L5D},
        )
        r_self_audit = mesh_client.post(
            "/v1/audit/ingest",
            json={"oscal_yaml": MINIMAL_OSCAL_YAML},
            headers={"l5d-client-id": BRIDGE_SA_L5D},
        )
        assert r_lula_infra.status_code == 403
        assert r_agent_audit.status_code == 403
        assert r_self_audit.status_code == 403

    def test_trusted_producer_env_override_and_malformed_fail_closed(
        self,
        mesh_client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv(TRUSTED_INFRA_PRODUCERS_ENV, "   ")
        assert (
            mesh_client.post(
                "/v1/infra/events",
                json=_sample_event(),
                headers={"l5d-client-id": AGENTSIGHT_L5D},
            ).status_code
            == 403
        )

        monkeypatch.setenv(TRUSTED_INFRA_PRODUCERS_ENV, "not-a-valid-identity!!")
        assert (
            mesh_client.post(
                "/v1/infra/events",
                json=_sample_event(),
                headers={"l5d-client-id": AGENTSIGHT_L5D},
            ).status_code
            == 500
        )

        monkeypatch.setenv(
            TRUSTED_INFRA_PRODUCERS_ENV,
            "spiffe://cluster.local/ns/sec-ops/sa/ebpf-collector",
        )
        custom_l5d = (
            "ebpf-collector.sec-ops.serviceaccount.identity.linkerd.cluster.local"
        )
        res = mesh_client.post(
            "/v1/infra/events",
            json=_sample_event(),
            headers={"l5d-client-id": custom_l5d},
        )
        assert res.status_code == 200
        body = res.json()
        assert body["source"] == "ebpf-collector"
        assert body["namespace"] == "sec-ops"


class TestIdentityDerivationAndSpoofRejection:
    """Verify source/namespace/pod_name come strictly from verified SVIDs, never caller JSON."""

    @pytest.mark.asyncio
    async def test_derives_source_and_namespace_from_mesh_svid_when_omitted(
        self,
        mesh_client: TestClient,
        redis_client,
        infra_chain: InfraEvidenceChain,
    ) -> None:
        res = mesh_client.post(
            "/v1/infra/events",
            json=_sample_event(),
            headers={
                "l5d-client-id": CILIUM_L5D,
                "x-cage-source-principal": "spiffe://evil/ns/default/sa/root",
            },
        )
        assert res.status_code == 200
        data = res.json()
        assert data["source"] == "cilium-monitor-exporter"
        assert data["namespace"] == "kube-system"
        assert data["pod_name"] is None
        assert data["pod_name_verified"] is False
        assert data["control_id"] == "AU-2"

        entries = await redis_client.xrange(infra_chain.stream_key)
        assert len(entries) == 1
        payload = json.loads(entries[0][1]["payload_json"])
        assert payload["source"] == "cilium-monitor-exporter"
        assert payload["namespace"] == "kube-system"
        assert payload["pod_name"] is None
        assert payload["pod_name_verified"] is False
        assert payload["producer_id"] == CILIUM_L5D
        assert (
            payload["producer_svid"]
            == "spiffe://cluster.local/ns/kube-system/sa/cilium-monitor-exporter"
        )

    def test_caller_matching_source_and_namespace_accepted_mismatches_rejected_403(
        self, mesh_client: TestClient
    ) -> None:
        ok = mesh_client.post(
            "/v1/infra/events",
            json=_sample_event(
                source="agentsight-daemon", namespace="governance-stack"
            ),
            headers={"l5d-client-id": AGENTSIGHT_L5D},
        )
        assert ok.status_code == 200

        bad_source = mesh_client.post(
            "/v1/infra/events",
            json=_sample_event(source="cilium-monitor-exporter"),
            headers={"l5d-client-id": AGENTSIGHT_L5D},
        )
        assert bad_source.status_code == 403
        assert bad_source.json()["detail"]["error"] == "PRODUCER_IDENTITY_MISMATCH"

        bad_ns = mesh_client.post(
            "/v1/infra/events",
            json=_sample_event(namespace="kube-system"),
            headers={"l5d-client-id": AGENTSIGHT_L5D},
        )
        assert bad_ns.status_code == 403
        assert bad_ns.json()["detail"]["error"] == "PRODUCER_IDENTITY_MISMATCH"

    def test_unverified_caller_pod_name_rejected_403_without_transport_pod_svid(
        self, mesh_client: TestClient
    ) -> None:
        """SA-scoped Linkerd mTLS cannot verify pod_name; claiming any pod returns 403."""
        for claimed_pod in ("gateway-586cb58877-4vhs6", "agentsight-daemon-abc12"):
            res = mesh_client.post(
                "/v1/infra/events",
                json=_sample_event(pod_name=claimed_pod),
                headers={"l5d-client-id": AGENTSIGHT_L5D},
            )
            assert res.status_code == 403
            assert res.json()["detail"]["error"] == "UNVERIFIED_POD_CLAIM"

    def test_transport_pod_svid_binds_pod_name_and_rejects_mismatches(
        self, infra_chain: InfraEvidenceChain
    ) -> None:
        valid_pod_svid = (
            "spiffe://cluster.local/ns/governance-stack/sa/agentsight-daemon/"
            "pod/agentsight-daemon-x7k2p"
        )
        wrapped = _PodSvidTransportWrapper(app, valid_pod_svid)
        with patch("src.compliance_bridge.main.Langfuse", return_value=MagicMock()):
            with TestClient(
                wrapped,
                client=PROXY_PEER,
                base_url=BASE_URL,
                raise_server_exceptions=False,
            ) as c:
                r_derived = c.post(
                    "/v1/infra/events",
                    json=_sample_event(),
                    headers={"l5d-client-id": AGENTSIGHT_L5D},
                )
                assert r_derived.status_code == 200
                assert r_derived.json()["pod_name"] == "agentsight-daemon-x7k2p"
                assert r_derived.json()["pod_name_verified"] is True

                r_match = c.post(
                    "/v1/infra/events",
                    json=_sample_event(pod_name="agentsight-daemon-x7k2p"),
                    headers={"l5d-client-id": AGENTSIGHT_L5D},
                )
                assert r_match.status_code == 200

                r_spoof = c.post(
                    "/v1/infra/events",
                    json=_sample_event(pod_name="gateway-victim-pod-999"),
                    headers={"l5d-client-id": AGENTSIGHT_L5D},
                )
                assert r_spoof.status_code == 403
                assert r_spoof.json()["detail"]["error"] == "PRODUCER_IDENTITY_MISMATCH"

        mismatched_svid = (
            "spiffe://cluster.local/ns/kube-system/sa/cilium-monitor-exporter/"
            "pod/cilium-9z"
        )
        with patch("src.compliance_bridge.main.Langfuse", return_value=MagicMock()):
            with TestClient(
                _PodSvidTransportWrapper(app, mismatched_svid),
                client=PROXY_PEER,
                base_url=BASE_URL,
                raise_server_exceptions=False,
            ) as c_bad:
                r_disagree = c_bad.post(
                    "/v1/infra/events",
                    json=_sample_event(),
                    headers={"l5d-client-id": AGENTSIGHT_L5D},
                )
                assert r_disagree.status_code == 403

    @pytest.mark.asyncio
    async def test_sa_scoped_transport_attribute_accepted_without_pod_claim(
        self,
    ) -> None:
        req = SimpleNamespace(
            headers=Headers(raw=[(b"l5d-client-id", AGENTSIGHT_L5D.encode())]),
            attributes=SimpleNamespace(source={"principal": AGENTSIGHT_SVID}),
            client=SimpleNamespace(host=POD_IP),
            scope={"client": PROXY_PEER, "server": (POD_IP, 3001)},
        )
        principal = await require_infra_event_producer(req)  # type: ignore[arg-type]
        assert principal.service_account == "agentsight-daemon"
        assert principal.namespace == "governance-stack"
        assert principal.verified_pod_name is None

    @pytest.mark.parametrize(
        "bad_payload",
        [
            _sample_event(unexpected_field="injected"),
            _sample_event(timestamp_utc="2026-09-06T20:00:00"),
            _sample_event(timestamp_utc="not-a-timestamp"),
            _sample_event(summary="bad\x00nullbyte"),
            _sample_event(summary="bad\nnewline"),
            _sample_event(control_hint="AU-2\x1f"),
        ],
    )
    def test_strict_schema_and_control_char_rejection_422(
        self, mesh_client: TestClient, bad_payload: dict
    ) -> None:
        res = mesh_client.post(
            "/v1/infra/events",
            json=bad_payload,
            headers={"l5d-client-id": AGENTSIGHT_L5D},
        )
        assert res.status_code == 422


# ---------------------------------------------------------------------------
# 2. Server-side receipt timestamp vs unverified producer timestamp
# ---------------------------------------------------------------------------


class TestServerReceiptTimestamp:
    @pytest.mark.asyncio
    async def test_stamps_server_received_at_utc_and_isolates_producer_timestamp(
        self,
        mesh_client: TestClient,
        redis_client,
        infra_chain: InfraEvidenceChain,
    ) -> None:
        unverified_claim = "1999-12-31T23:59:59Z"
        before = datetime.now(tz=timezone.utc)
        res = mesh_client.post(
            "/v1/infra/events",
            json=_sample_event(timestamp_utc=unverified_claim),
            headers={"l5d-client-id": AGENTSIGHT_L5D},
        )
        after = datetime.now(tz=timezone.utc)
        assert res.status_code == 200
        body = res.json()

        assert body["producer_timestamp_utc"] == unverified_claim
        assert body["received_at_utc"] != unverified_claim
        stamped = datetime.fromisoformat(body["received_at_utc"].replace("Z", "+00:00"))
        assert (
            (before.timestamp() - 0.002)
            <= stamped.timestamp()
            <= (after.timestamp() + 0.002)
        )

        entries = await redis_client.xrange(infra_chain.stream_key)
        _, fields = entries[0]
        assert fields["timestamp_utc"] == body["received_at_utc"]
        payload = json.loads(fields["payload_json"])
        assert payload["received_at_utc"] == body["received_at_utc"]
        assert payload["producer_timestamp_utc"] == unverified_claim
        assert "timestamp_utc" not in payload


# ---------------------------------------------------------------------------
# 3. Deterministic full-payload hash & INFRA hash chain + custodian round-trip
# ---------------------------------------------------------------------------


class TestDeterministicHashAndCustodyChain:
    def test_no_time_monotonic_or_nil_uuid_in_infra_custody_paths(self) -> None:
        main_src = inspect.getsource(bridge_main.ingest_infra_event)
        custody_src = (
            Path(__file__).resolve().parents[1]
            / "src/compliance_bridge/infra_custody.py"
        ).read_text(encoding="utf-8")
        for source in (main_src, custody_src):
            tree = ast.parse(source)
            attrs = {
                node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
            }
            assert "monotonic" not in attrs

        assert "00000000-0000-0000-0000-000000000000" not in main_src

    @pytest.mark.asyncio
    async def test_record_hash_reproducible_offline_from_canonical_json(
        self,
        mesh_client: TestClient,
        redis_client,
        infra_chain: InfraEvidenceChain,
    ) -> None:
        res = mesh_client.post(
            "/v1/infra/events",
            json=_sample_event(
                summary="connect with Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 ok"
            ),
            headers={"l5d-client-id": AGENTSIGHT_L5D},
        )
        assert res.status_code == 200
        body = res.json()
        assert body["event_id"] == body["record_hash"]

        entries = await redis_client.xrange(infra_chain.stream_key)
        assert len(entries) == 1
        stream_id, fields = entries[0]
        assert stream_id == body["stream_id"]

        payload_json = fields["payload_json"]
        decoded = json.loads(payload_json)
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in payload_json
        assert "[REDACTED]" in decoded["summary"]
        re_encoded_stdlib = json.dumps(
            decoded, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        re_encoded_jcs = jcs_canonicalize_plan(decoded).decode("utf-8")
        assert payload_json == re_encoded_stdlib == re_encoded_jcs

        header_bytes = jcs_canonicalize_plan(
            {
                "canonicalization": "RFC8785",
                "chain_id": fields["chain_id"],
                "control_id": fields["control_id"],
                "event_type": fields["event_type"],
                "hash_algorithm": "SHA-256",
                "schema": "cage-audit/3.0",
                "sequence": int(fields["sequence"]),
                "trace_id": fields["trace_id"],
            }
        )
        manual_sha = hashlib.sha256(
            fields["prev_hash"].encode("ascii")
            + header_bytes
            + payload_json.encode("utf-8")
        ).hexdigest()
        helper_hash = compute_infra_record_hash(
            prev_hash=fields["prev_hash"],
            sequence=int(fields["sequence"]),
            event_type=fields["event_type"],
            control_id=fields["control_id"],
            payload_json=payload_json,
            chain_id=fields["chain_id"],
            trace_id=fields["trace_id"],
        )
        stream_link = _link_hash(
            prev_hash=fields["prev_hash"],
            sequence=int(fields["sequence"]),
            event_type=fields["event_type"],
            control_id=fields["control_id"],
            payload_json=payload_json,
            chain_id=fields["chain_id"],
            trace_id=fields["trace_id"],
        )
        assert manual_sha == helper_hash == stream_link == body["record_hash"]
        verdict = verify_record(fields, prev_hash="")
        assert verdict.valid, verdict.error

    @pytest.mark.asyncio
    async def test_identical_inputs_yield_identical_hash_and_every_field_mutates_hash(
        self,
    ) -> None:
        base_kwargs = {
            "event_type": "agentsight_fim",
            "control_id": "SI-7",
            "control_hint": "SI-7",
            "scrubbed_summary": "openat(/etc/passwd, O_WRONLY) denied",
            "producer_timestamp_utc": "2026-11-05T12:00:00Z",
            "received_at_utc": "2026-11-05T12:00:01.250Z",
            "producer_id": AGENTSIGHT_L5D,
            "producer_svid": AGENTSIGHT_SVID,
            "source": "agentsight-daemon",
            "namespace": "governance-stack",
            "pod_name": "agentsight-daemon-p1",
            "pod_name_verified": True,
        }
        fixed_cid = "4f6e2d10-8e34-4a2b-9f11-2a3b4c5d6e7f"
        fixed_tid = "a" * 32

        async def _seal_once(**overrides) -> str:
            srv = fakeredis.FakeServer()
            chain = InfraEvidenceChain(
                fakeredis.FakeAsyncRedis(server=srv, decode_responses=True),
                chain_id_factory=lambda: fixed_cid,
                trace_id_factory=lambda: fixed_tid,
            )
            params = {**base_kwargs, **overrides}
            rec = await chain.append_durable(**params)
            return rec.record_hash

        h1 = await _seal_once()
        h2 = await _seal_once()
        assert h1 == h2, "Deterministic inputs must yield identical record_hash"

        mutations = [
            {"scrubbed_summary": "openat(/etc/shadow, O_WRONLY) denied"},
            {"control_hint": "AU-2"},
            {"control_id": "AU-2"},
            {"event_type": "agentsight_syscall"},
            {"received_at_utc": "2026-11-05T12:00:02.250Z"},
            {"producer_timestamp_utc": "2026-11-05T12:00:09Z"},
            {"source": "cilium-monitor-exporter"},
            {"namespace": "kube-system"},
            {"pod_name": "agentsight-daemon-p2"},
            {"pod_name": None, "pod_name_verified": False},
            {"idempotency_key": "idem-xyz"},
        ]
        for mutation in mutations:
            mutated_hash = await _seal_once(**mutation)
            assert mutated_hash != h1, (
                f"Mutation {mutation!r} did not alter record_hash!"
            )

    @pytest.mark.asyncio
    async def test_hash_chain_links_prev_hash_recovers_after_restart_and_passes_custody_verifier(
        self,
        fake_server: fakeredis.FakeServer,
        mesh_client: TestClient,
        infra_chain: InfraEvidenceChain,
    ) -> None:
        receipts = []
        producers = [
            (AGENTSIGHT_L5D, "agentsight_syscall", "AU-2"),
            (AGENTSIGHT_L5D, "agentsight_fim", "SI-7"),
            (CILIUM_L5D, "cilium_l7_flow", "SC-7"),
        ]
        for idx, (l5d, etype, hint) in enumerate(producers):
            r = mesh_client.post(
                "/v1/infra/events",
                json=_sample_event(
                    event_type=etype,
                    control_hint=hint,
                    summary=f"event-{idx}:{etype}",
                ),
                headers={"l5d-client-id": l5d},
            )
            assert r.status_code == 200
            receipts.append(r.json())

        restarted_chain = InfraEvidenceChain(
            fakeredis.FakeAsyncRedis(server=fake_server, decode_responses=True),
            stream_key=infra_chain.stream_key,
        )
        app.state.infra_evidence_chain = restarted_chain
        r3 = mesh_client.post(
            "/v1/infra/events",
            json=_sample_event(summary="post-restart-event-3"),
            headers={"l5d-client-id": AGENTSIGHT_L5D},
        )
        assert r3.status_code == 200
        receipts.append(r3.json())

        chain_uuid = uuid.UUID(receipts[0]["chain_id"])
        assert chain_uuid.version == 4
        assert str(chain_uuid) != "00000000-0000-0000-0000-000000000000"

        prev = ""
        for expected_seq, item in enumerate(receipts):
            assert item["chain_id"] == receipts[0]["chain_id"]
            assert item["sequence"] == expected_seq
            assert item["prev_hash"] == prev
            prev = item["record_hash"]

        provider = SoftwareEd25519Provider(key_id=KID)
        signer = KMSGovernanceSigner(provider=provider)
        cold_store = NullColdStore()

        gov_sink = EvidenceStreamSink(stream_key="cage:evidence:gov:test")
        gov_sink._redis = fakeredis.FakeAsyncRedis(
            server=fake_server, decode_responses=True
        )
        await gov_sink.ingest({"type": "GOVERNANCE_DECISION", "controlId": "AU-9"})
        await gov_sink.ingest({"type": "GOVERNANCE_DECISION", "controlId": "AC-3"})

        gov_custodian = EvidenceCustodian(
            fakeredis.FakeAsyncRedis(server=fake_server, decode_responses=True),
            cold_store,
            signer,
            stream_key="cage:evidence:gov:test",
            require_signature=True,
        )
        infra_custodian = EvidenceCustodian(
            fakeredis.FakeAsyncRedis(server=fake_server, decode_responses=True),
            cold_store,
            signer,
            stream_key=infra_chain.stream_key,
            require_signature=True,
        )
        gov_out = await gov_custodian.flush_once()
        infra_out = await infra_custodian.flush_once()
        assert gov_out.entries == 2
        assert gov_out.evidentiary is True
        assert infra_out.entries == 4
        assert infra_out.evidentiary is True

        verifier = CustodyVerifier(
            cold_store,
            build_attestation_verifier({KID: provider.get_public_key_pem()}),
        )
        report = await verifier.verify_for_citation()
        assert report.ok is True
        assert report.citable is True
        assert len(report.verified) == 2
        assert sum(b.entries for b in report.verified) == 6
        by_chain = {b.chain_id: b for b in report.verified}
        assert receipts[0]["chain_id"] in by_chain
        infra_batch = by_chain[receipts[0]["chain_id"]]
        assert infra_batch.first_sequence == 0
        assert infra_batch.last_sequence == 3
        assert infra_batch.entries == 4
        assert infra_batch.last_record_hash == receipts[-1]["record_hash"]
        assert infra_batch.key_id == KID


# ---------------------------------------------------------------------------
# 4. Fail-closed HTTP 503 persistence & Idempotency-Key deduplication
# ---------------------------------------------------------------------------


class TestFailClosedPersistenceAndIdempotency:
    def test_returns_503_when_infra_chain_missing(self) -> None:
        app.state.infra_evidence_chain = None
        with patch("src.compliance_bridge.main.Langfuse", return_value=MagicMock()):
            with TestClient(
                app,
                client=PROXY_PEER,
                base_url=BASE_URL,
                raise_server_exceptions=False,
            ) as c:
                res = c.post(
                    "/v1/infra/events",
                    json=_sample_event(),
                    headers={"l5d-client-id": AGENTSIGHT_L5D},
                )
        assert res.status_code == 503
        assert res.json().get("status") != "INGESTED"
        assert res.json()["detail"]["error"] == "INFRA_CUSTODY_UNAVAILABLE"

    def test_returns_503_when_redis_read_or_append_fails(
        self, mesh_client: TestClient
    ) -> None:
        broken_redis = MagicMock()
        broken_redis.xrevrange = AsyncMock(
            side_effect=ConnectionError("Redis connection refused")
        )
        app.state.infra_evidence_chain = InfraEvidenceChain(broken_redis)
        res = mesh_client.post(
            "/v1/infra/events",
            json=_sample_event(),
            headers={"l5d-client-id": AGENTSIGHT_L5D},
        )
        assert res.status_code == 503
        assert res.json().get("status") != "INGESTED"
        assert res.json()["detail"]["error"] == "INFRA_CUSTODY_UNAVAILABLE"

    @pytest.mark.asyncio
    async def test_returns_503_when_stream_head_corrupted_or_truncated(
        self,
        mesh_client: TestClient,
        redis_client,
        infra_chain: InfraEvidenceChain,
    ) -> None:
        r0 = mesh_client.post(
            "/v1/infra/events",
            json=_sample_event(summary="valid-genesis"),
            headers={"l5d-client-id": AGENTSIGHT_L5D},
        )
        assert r0.status_code == 200

        await redis_client.delete(infra_chain.stream_key)
        infra_chain._chain_restored = False
        r_trunc = mesh_client.post(
            "/v1/infra/events",
            json=_sample_event(summary="after-truncation"),
            headers={"l5d-client-id": AGENTSIGHT_L5D},
        )
        assert r_trunc.status_code == 503
        assert r_trunc.json().get("status") != "INGESTED"

        await redis_client.xadd(
            "cage:evidence:infra:tampered",
            {
                "schema": "cage-audit/3.0",
                "chain_id": str(uuid.uuid4()),
                "sequence": "0",
                "timestamp_utc": "2026-11-05T00:00:00Z",
                "event_type": "agentsight_syscall",
                "control_id": "AU-2",
                "trace_id": "b" * 32,
                "hash_algorithm": "SHA-256",
                "canonicalization": "RFC8785",
                "evidence_class": "INFRA",
                "prev_hash": "",
                "record_hash": "f" * 64,
                "payload_json": canonical_payload_json({"summary": "forged"}),
            },
        )
        app.state.infra_evidence_chain = InfraEvidenceChain(
            redis_client, stream_key="cage:evidence:infra:tampered"
        )
        r_tamper = mesh_client.post(
            "/v1/infra/events",
            json=_sample_event(),
            headers={"l5d-client-id": AGENTSIGHT_L5D},
        )
        assert r_tamper.status_code == 503

    @pytest.mark.asyncio
    async def test_inline_worm_flush_succeeds_and_returns_503_when_cold_store_fails(
        self,
        fake_server: fakeredis.FakeServer,
        mesh_client: TestClient,
        infra_chain: InfraEvidenceChain,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv(INFRA_INLINE_FLUSH_ENV, "true")

        provider = SoftwareEd25519Provider(key_id=KID)
        signer = KMSGovernanceSigner(provider=provider)
        ok_store = NullColdStore()
        app.state.infra_evidence_custodian = EvidenceCustodian(
            fakeredis.FakeAsyncRedis(server=fake_server, decode_responses=True),
            ok_store,
            signer,
            stream_key=infra_chain.stream_key,
            require_signature=True,
        )
        r_ok = mesh_client.post(
            "/v1/infra/events",
            json=_sample_event(summary="inline-worm-custodied"),
            headers={"l5d-client-id": AGENTSIGHT_L5D},
        )
        assert r_ok.status_code == 200
        ver = CustodyVerifier(
            ok_store,
            build_attestation_verifier({KID: provider.get_public_key_pem()}),
        )
        rep = await ver.verify_for_citation()
        assert rep.citable is True
        assert rep.verified[0].last_record_hash == r_ok.json()["record_hash"]

        app.state.infra_evidence_custodian = None
        r_missing = mesh_client.post(
            "/v1/infra/events",
            json=_sample_event(summary="missing-custodian"),
            headers={"l5d-client-id": AGENTSIGHT_L5D},
        )
        assert r_missing.status_code == 503
        failing_store = MagicMock()
        failing_store.backend_id = "gcs"
        failing_store.list_keys = AsyncMock(return_value=[])
        failing_store.put_if_absent = AsyncMock(
            side_effect=ColdStoreError("GCS WORM bucket unreachable", backend_id="gcs")
        )
        app.state.infra_evidence_custodian = EvidenceCustodian(
            fakeredis.FakeAsyncRedis(server=fake_server, decode_responses=True),
            failing_store,
            signer,
            stream_key=infra_chain.stream_key,
            require_signature=True,
        )
        r_worm_err = mesh_client.post(
            "/v1/infra/events",
            json=_sample_event(summary="worm-failure"),
            headers={"l5d-client-id": AGENTSIGHT_L5D},
        )
        assert r_worm_err.status_code == 503
        assert r_worm_err.json().get("status") != "INGESTED"
        assert r_worm_err.json()["detail"]["error"] == "INFRA_CUSTODY_UNAVAILABLE"

    @pytest.mark.asyncio
    async def test_idempotency_key_deduplicates_retries_isolates_producers_and_rejects_conflicts(
        self,
        mesh_client: TestClient,
        redis_client,
        infra_chain: InfraEvidenceChain,
    ) -> None:
        r1 = mesh_client.post(
            "/v1/infra/events",
            json=_sample_event(summary="syscall-evt-1"),
            headers={
                "l5d-client-id": AGENTSIGHT_L5D,
                "Idempotency-Key": "agentsight-seq-0001",
            },
        )
        assert r1.status_code == 200
        b1 = r1.json()
        assert b1["idempotent_replay"] is False
        assert b1["sequence"] == 0

        r2 = mesh_client.post(
            "/v1/infra/events",
            json=_sample_event(
                summary="syscall-evt-1", idempotency_key="agentsight-seq-0001"
            ),
            headers={
                "l5d-client-id": AGENTSIGHT_L5D,
                "Idempotency-Key": "agentsight-seq-0001",
            },
        )
        assert r2.status_code == 200
        b2 = r2.json()
        assert b2["idempotent_replay"] is True
        assert b2["record_hash"] == b1["record_hash"]
        assert b2["sequence"] == 0
        assert b2["received_at_utc"] == b1["received_at_utc"]
        assert await redis_client.xlen(infra_chain.stream_key) == 1

        r_conflict = mesh_client.post(
            "/v1/infra/events",
            json=_sample_event(summary="TAMPERED-syscall-evt-1"),
            headers={
                "l5d-client-id": AGENTSIGHT_L5D,
                "Idempotency-Key": "agentsight-seq-0001",
            },
        )
        assert r_conflict.status_code == 409
        assert r_conflict.json()["detail"]["error"] == "IDEMPOTENCY_KEY_CONFLICT"
        assert await redis_client.xlen(infra_chain.stream_key) == 1

        r_other = mesh_client.post(
            "/v1/infra/events",
            json=_sample_event(summary="syscall-evt-1"),
            headers={
                "l5d-client-id": CILIUM_L5D,
                "Idempotency-Key": "agentsight-seq-0001",
            },
        )
        assert r_other.status_code == 200
        b_other = r_other.json()
        assert b_other["idempotent_replay"] is False
        assert b_other["sequence"] == 1
        assert b_other["prev_hash"] == b1["record_hash"]
        assert b_other["source"] == "cilium-monitor-exporter"
        assert await redis_client.xlen(infra_chain.stream_key) == 2

        r_mismatch = mesh_client.post(
            "/v1/infra/events",
            json=_sample_event(idempotency_key="key-b"),
            headers={"l5d-client-id": AGENTSIGHT_L5D, "Idempotency-Key": "key-a"},
        )
        assert r_mismatch.status_code == 400
        assert r_mismatch.json()["detail"]["error"] == "IDEMPOTENCY_KEY_MISMATCH"

        r_bad_key = mesh_client.post(
            "/v1/infra/events",
            json=_sample_event(),
            headers={"l5d-client-id": AGENTSIGHT_L5D, "Idempotency-Key": "bad key/.."},
        )
        assert r_bad_key.status_code == 400
        assert r_bad_key.json()["detail"]["error"] == "INVALID_IDEMPOTENCY_KEY"

    @pytest.mark.asyncio
    async def test_idempotency_retry_recovers_failed_custody_flusher_without_duplicate_stream_entry(
        self,
        mesh_client: TestClient,
        redis_client,
        infra_chain: InfraEvidenceChain,
    ) -> None:
        flaky_flusher = AsyncMock(
            side_effect=[RuntimeError("transient WORM outage"), True]
        )
        app.state.infra_custody_flusher = flaky_flusher

        r1 = mesh_client.post(
            "/v1/infra/events",
            json=_sample_event(summary="retry-me-safely"),
            headers={
                "l5d-client-id": AGENTSIGHT_L5D,
                "Idempotency-Key": "recover-001",
            },
        )
        assert r1.status_code == 503
        assert await redis_client.xlen(infra_chain.stream_key) == 1

        r2 = mesh_client.post(
            "/v1/infra/events",
            json=_sample_event(summary="retry-me-safely"),
            headers={
                "l5d-client-id": AGENTSIGHT_L5D,
                "Idempotency-Key": "recover-001",
            },
        )
        assert r2.status_code == 200
        b2 = r2.json()
        assert b2["sequence"] == 0
        assert b2["idempotent_replay"] is True
        assert await redis_client.xlen(infra_chain.stream_key) == 1
        assert flaky_flusher.await_count == 2

        r3 = mesh_client.post(
            "/v1/infra/events",
            json=_sample_event(summary="retry-me-safely"),
            headers={
                "l5d-client-id": AGENTSIGHT_L5D,
                "Idempotency-Key": "recover-001",
            },
        )
        assert r3.status_code == 200
        assert flaky_flusher.await_count == 2

    @pytest.mark.asyncio
    async def test_concurrent_flush_once_serializes_non_overlapping_contiguous_batches(
        self,
        fake_server: fakeredis.FakeServer,
    ) -> None:
        import asyncio
        import itertools

        stream_key = "cage:evidence:infra:concurrent-flush"
        chain = InfraEvidenceChain(
            fakeredis.FakeAsyncRedis(server=fake_server, decode_responses=True),
            stream_key=stream_key,
        )

        class _SlowInMemoryWormStore:
            backend_id = "gcs"

            def __init__(self) -> None:
                self._objects: dict[str, bytes] = {}

            async def put_if_absent(
                self, key: str, content: bytes, metadata: dict[str, str] | None = None
            ) -> tuple[ColdStoreReceipt, bool]:
                await asyncio.sleep(0.025)
                created = key not in self._objects
                if created:
                    self._objects[key] = bytes(content)
                stored = self._objects[key]
                receipt = ColdStoreReceipt(
                    uri=f"gs://test-worm/{key}",
                    key=key,
                    content_sha256=hashlib.sha256(stored).hexdigest(),
                    backend_id=self.backend_id,
                    written_at=datetime.now(timezone.utc),
                )
                return receipt, created

            async def get(self, key: str) -> bytes:
                if key not in self._objects:
                    raise ColdStoreError(f"missing {key}", backend_id="gcs")
                return self._objects[key]

            async def list_keys(self, prefix: str = "") -> list[str]:
                return sorted(k for k in self._objects if k.startswith(prefix))

        for idx in range(5):
            await chain.append_durable(
                event_type="agentsight_syscall",
                control_id="AU-2",
                control_hint="AU-2",
                scrubbed_summary=f"pre-batch-{idx}",
                producer_timestamp_utc="2026-11-05T10:00:00Z",
                received_at_utc=f"2026-11-05T10:00:0{idx}.000Z",
                producer_id=AGENTSIGHT_L5D,
                producer_svid=AGENTSIGHT_SVID,
                source="agentsight-daemon",
                namespace="governance-stack",
                pod_name=None,
                pod_name_verified=False,
            )

        provider = SoftwareEd25519Provider(key_id=KID)
        signer = KMSGovernanceSigner(provider=provider)
        slow_store = _SlowInMemoryWormStore()
        custodian = EvidenceCustodian(
            fakeredis.FakeAsyncRedis(server=fake_server, decode_responses=True),
            slow_store,  # type: ignore[arg-type]
            signer,
            stream_key=stream_key,
            batch_size=3,
            require_signature=True,
        )

        async def _append_mid_flight() -> None:
            await asyncio.sleep(0.01)
            for idx in range(5, 8):
                await chain.append_durable(
                    event_type="agentsight_fim",
                    control_id="SI-7",
                    control_hint="SI-7",
                    scrubbed_summary=f"mid-flight-{idx}",
                    producer_timestamp_utc="2026-11-05T10:01:00Z",
                    received_at_utc=f"2026-11-05T10:01:0{idx}.000Z",
                    producer_id=AGENTSIGHT_L5D,
                    producer_svid=AGENTSIGHT_SVID,
                    source="agentsight-daemon",
                    namespace="governance-stack",
                    pod_name=None,
                    pod_name_verified=False,
                )

        outcomes = await asyncio.gather(
            custodian.flush_once(),
            custodian.flush_once(),
            custodian.flush_once(),
            custodian.flush_once(),
            _append_mid_flight(),
        )
        # Drain any tail records appended after the concurrent gather
        tail_outcome = await custodian.flush_once()
        written = [
            o for o in (*outcomes[:4], tail_outcome) if o is not None and o.entries > 0
        ]
        assert len(written) >= 3

        spans = [(o.first_sequence, o.last_sequence) for o in written]
        assert spans[0][0] == 0
        for prev_span, next_span in itertools.pairwise(spans):
            assert prev_span[1] is not None and next_span[0] is not None
            assert next_span[0] == prev_span[1] + 1, (
                f"Expected strictly contiguous non-overlapping batches, got {spans}"
            )
        assert spans[-1][1] == 7

        verifier = CustodyVerifier(
            slow_store,  # type: ignore[arg-type]
            build_attestation_verifier({KID: provider.get_public_key_pem()}),
        )
        report = await verifier.verify_for_citation()
        assert report.ok is True
        assert report.citable is True
        assert sum(b.entries for b in report.verified) == 8

    @pytest.mark.asyncio
    async def test_enforcing_posture_defaults_inline_flush_true_and_fails_closed_503_on_infra_and_audit_ingest(
        self,
        fake_server: fakeredis.FakeServer,
        infra_chain: InfraEvidenceChain,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", "staging")
        monkeypatch.setenv(
            "CAGE_TRUSTED_OPERATOR_IDENTITIES", "operator:auditor@example.org"
        )
        monkeypatch.delenv(INFRA_INLINE_FLUSH_ENV, raising=False)

        class _InMemoryGcsWormStore:
            backend_id = "gcs"

            def __init__(self) -> None:
                self._objects: dict[str, bytes] = {}

            async def put_if_absent(
                self, key: str, content: bytes, metadata: dict[str, str] | None = None
            ) -> tuple[ColdStoreReceipt, bool]:
                created = key not in self._objects
                if created:
                    self._objects[key] = bytes(content)
                stored = self._objects[key]
                receipt = ColdStoreReceipt(
                    uri=f"gs://test-worm/{key}",
                    key=key,
                    content_sha256=hashlib.sha256(stored).hexdigest(),
                    backend_id=self.backend_id,
                    written_at=datetime.now(timezone.utc),
                )
                return receipt, created

            async def get(self, key: str) -> bytes:
                return self._objects[key]

            async def list_keys(self, prefix: str = "") -> list[str]:
                return sorted(k for k in self._objects if k.startswith(prefix))

        class _HsmStubEd25519Provider(SoftwareEd25519Provider):
            @property
            def provider_name(self) -> str:
                return "GCP_KMS"

            @property
            def is_software_fallback(self) -> bool:
                return False

        provider = _HsmStubEd25519Provider(key_id=KID)
        signer = KMSGovernanceSigner(
            provider=provider, public_key_pem=provider.get_public_key_pem()
        )
        worm_store = _InMemoryGcsWormStore()

        stub_verifier = MagicMock()
        stub_verifier.run_forever = AsyncMock(return_value=None)

        # 1. Custodian unavailable in enforcing posture -> 503 on BOTH endpoints
        stub_bg_custodian = MagicMock()
        stub_bg_custodian.run_forever = AsyncMock(return_value=None)
        stub_bg_custodian.aclose = AsyncMock(return_value=None)

        monkeypatch.setenv("EVIDENCE_STREAM_ENABLED", "true")
        with (
            patch("src.compliance_bridge.main.Langfuse", return_value=MagicMock()),
            patch(
                "src.compliance_bridge.evidence_custodian.EvidenceCustodian.from_env",
                return_value=stub_bg_custodian,
            ),
            patch(
                "src.compliance_bridge.evidence_verifier.CustodyVerifier.from_env",
                return_value=stub_verifier,
            ),
            patch(
                "src.compliance_bridge.main.run_audit_workflow",
                new=AsyncMock(
                    return_value={
                        "findings_count": 1,
                        "artifact_key": "audit/staging.json",
                        "ingested": 1,
                        "alerted": False,
                        "alert_targets": [],
                        "remediation_sent": False,
                        "remediation_text": None,
                        "advisor_error": None,
                    }
                ),
            ),
        ):
            with TestClient(
                app,
                client=PROXY_PEER,
                base_url=BASE_URL,
                raise_server_exceptions=False,
            ) as enf_client:
                # Explicitly clear custodian to prove 503 when unavailable
                app.state.infra_evidence_custodian = None
                monkeypatch.setenv(INFRA_INLINE_FLUSH_ENV, "false")
                r_infra_no_cust = enf_client.post(
                    "/v1/infra/events",
                    json=_sample_event(summary="enforcing-no-custodian"),
                    headers={"l5d-client-id": AGENTSIGHT_L5D},
                )
                r_audit_no_cust = enf_client.post(
                    "/v1/audit/ingest?background=true",
                    json={"oscal_yaml": MINIMAL_OSCAL_YAML, "audit_id": "enf-001"},
                    headers={"l5d-client-id": LULA_L5D},
                )
                assert r_infra_no_cust.status_code == 503
                assert r_audit_no_cust.status_code == 503

                # 2. Failing WORM cold store -> 503 on BOTH endpoints (never 200)
                monkeypatch.delenv(INFRA_INLINE_FLUSH_ENV, raising=False)
                failing_worm = MagicMock()
                failing_worm.backend_id = "gcs"
                failing_worm.list_keys = AsyncMock(return_value=[])
                failing_worm.put_if_absent = AsyncMock(
                    side_effect=ColdStoreError("WORM bucket offline", backend_id="gcs")
                )
                app.state.infra_evidence_custodian = EvidenceCustodian(
                    fakeredis.FakeAsyncRedis(server=fake_server, decode_responses=True),
                    failing_worm,
                    signer,
                    stream_key=infra_chain.stream_key,
                    require_signature=True,
                )
                r_infra_worm_err = enf_client.post(
                    "/v1/infra/events",
                    json=_sample_event(summary="enforcing-worm-down"),
                    headers={"l5d-client-id": AGENTSIGHT_L5D},
                )
                r_audit_worm_err = enf_client.post(
                    "/v1/audit/ingest",
                    json={"oscal_yaml": MINIMAL_OSCAL_YAML, "audit_id": "enf-002"},
                    headers={"l5d-client-id": LULA_L5D},
                )
                assert r_infra_worm_err.status_code == 503
                assert r_infra_worm_err.json().get("status") != "INGESTED"
                assert r_audit_worm_err.status_code == 503

                # 3. Healthy WORM custodian -> 200 and verified WORM custody on BOTH
                app.state.infra_evidence_custodian = EvidenceCustodian(
                    fakeredis.FakeAsyncRedis(server=fake_server, decode_responses=True),
                    worm_store,  # type: ignore[arg-type]
                    signer,
                    stream_key=infra_chain.stream_key,
                    require_signature=True,
                )
                r_infra_ok = enf_client.post(
                    "/v1/infra/events",
                    json=_sample_event(summary="enforcing-ok"),
                    headers={"l5d-client-id": AGENTSIGHT_L5D},
                )
                r_audit_ok = enf_client.post(
                    "/v1/audit/ingest",
                    json={"oscal_yaml": MINIMAL_OSCAL_YAML, "audit_id": "enf-003"},
                    headers={"l5d-client-id": LULA_L5D},
                )
                assert r_infra_ok.status_code == 200
                assert r_audit_ok.status_code == 200

        verifier = CustodyVerifier(
            worm_store,  # type: ignore[arg-type]
            build_attestation_verifier({KID: provider.get_public_key_pem()}),
        )
        rep = await verifier.verify_for_citation()
        assert rep.ok is True
        assert rep.citable is True

    def test_evidence_custodian_from_env_accepts_infra_stream_key_override(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", "dev")
        monkeypatch.setenv("EVIDENCE_STREAM_REDIS_URL", "redis://localhost:6379")
        custodian = EvidenceCustodian.from_env(stream_key=DEFAULT_INFRA_STREAM_KEY)
        assert custodian._stream_key == DEFAULT_INFRA_STREAM_KEY
        assert custodian._cursor_key == f"{DEFAULT_INFRA_STREAM_KEY}:custody"

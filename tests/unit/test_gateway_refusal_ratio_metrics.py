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

"""Unit tests for gated gateway request outcome counters and sustained refusal-ratio alerting.

Verifies the telemetry and alerting contract closing the silent-100%-refusal blind spot:
  1. ``GovernorMetrics`` pre-initializes ``cage_gateway_gated_requests_total`` for both
     ``outcome="blocked"`` and ``outcome="permitted"`` at ``0.0`` on registry binding,
     and never registers collectors at import time.
  2. ``WorkloadIdentityMiddleware`` excludes ``OPEN_EXACT_PATHS`` (``/health``, ``/healthz``,
     ``/governance/jwks``, ``/governance/.well-known/jwks.json``) so kubelet liveness and
     readiness probes never dilute the denominator during a 100% refusal outage.
  3. Every non-open HTTP and WebSocket request increments ``cage_gateway_gated_requests_total``
     at most once and at least once (strict conservation: ``blocked + permitted == total``),
     classifying ingress ``403``s, downstream ``4xx``/``5xx`` responses (so ``404``/``400``
     floods cannot inflate ``permitted``), unhandled exceptions, and HTTP ``200`` responses
     carrying in-band governance refusals (``refusal_decided``, ``policy-precheck`` ``DENY``,
     ``verify_content_safety`` ``BLOCKED``, ``evaluate_policy`` ``DENIED``) as ``blocked``.
  4. ``infra/targets/gcp-gke/metrics_alerting.tf`` provisions
     ``google_monitoring_alert_policy.gateway_sustained_refusal_ratio`` paging
     ``var.lula_alert_owner`` when blocked-over-total over ``[5m]`` meets ``>= 0.95`` with a
     minimum volume floor (``>= 5``) sustained for ``180s``.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
from prometheus_client import CollectorRegistry
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route, WebSocketRoute
from starlette.testclient import TestClient
from starlette.websockets import WebSocket, WebSocketDisconnect

from src.gateway.governance.governor.metrics import governor_metrics
from src.gateway.server.workload_identity import (
    CLIENT_IDENTITY_HEADER,
    OPEN_EXACT_PATHS,
    IdentityPolicy,
    WorkloadIdentityMiddleware,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO_ROOT = Path(__file__).resolve().parents[2]
_METRICS_ALERTING_TF = (
    _REPO_ROOT / "infra" / "targets" / "gcp-gke" / "metrics_alerting.tf"
)

ADVISOR = (
    "cage-advisor-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"
)
UNTRUSTED = (
    "cage-vllm-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"
)
POD_IP = "10.112.0.43"
PROXY_PEER = (POD_IP, 50000)
POLICY = IdentityPolicy(trusted=frozenset({ADVISOR}))


def _counter_value(registry: CollectorRegistry, outcome: str) -> float:
    val = registry.get_sample_value(
        "cage_gateway_gated_requests_total",
        {"outcome": outcome},
    )
    assert val is not None, (
        f"Expected cage_gateway_gated_requests_total{{outcome={outcome!r}}} "
        "to be registered on CollectorRegistry"
    )
    return float(val)


def _build_test_client(registry: CollectorRegistry) -> TestClient:
    metrics = governor_metrics(registry)

    async def ok_route(_request: Request) -> PlainTextResponse:
        return PlainTextResponse("ok", status_code=200)

    async def denied_403_route(_request: Request) -> JSONResponse:
        # Simulates validate-action calling refusal_decided AND returning HTTP 403;
        # must count as exactly 1 blocked request (never double-counted).
        metrics.refusal_decided("OPA_POLICY")
        return JSONResponse({"verdict": "DENIED"}, status_code=403)

    async def dependency_503_route(_request: Request) -> JSONResponse:
        return JSONResponse({"error": "evidence_chain_unavailable"}, status_code=503)

    async def not_found_404_route(_request: Request) -> JSONResponse:
        return JSONResponse({"detail": "not found"}, status_code=404)

    async def protocol_200_refusal_route(_request: Request) -> JSONResponse:
        # Simulates MCP JSON-RPC tools/call or /tools/execute where SymbolicGovernor
        # refuses via refusal_decided() while the transport returns HTTP 200.
        metrics.refusal_decided("CBF")
        return JSONResponse(
            {"jsonrpc": "2.0", "result": {"isError": True}}, status_code=200
        )

    async def crashing_route(_request: Request) -> PlainTextResponse:
        raise RuntimeError("unhandled downstream failure")

    async def ws_accept_route(ws: WebSocket) -> None:
        await ws.accept()
        await ws.send_text("ok")
        await ws.close()

    async def ws_reject_route(ws: WebSocket) -> None:
        await ws.close(code=1008)

    inner = Starlette(
        routes=[
            Route("/health", ok_route, methods=["GET"]),
            Route("/healthz", ok_route, methods=["GET"]),
            Route("/governance/jwks", ok_route, methods=["GET"]),
            Route("/governance/.well-known/jwks.json", ok_route, methods=["GET"]),
            Route("/governance/validate-action", ok_route, methods=["POST"]),
            Route("/governance/deny-403", denied_403_route, methods=["POST"]),
            Route("/governance/fail-503", dependency_503_route, methods=["POST"]),
            Route("/governance/missing", not_found_404_route, methods=["GET"]),
            Route("/mcp/refusal-200", protocol_200_refusal_route, methods=["POST"]),
            Route("/governance/crash", crashing_route, methods=["POST"]),
            WebSocketRoute("/ws/ok", ws_accept_route),
            WebSocketRoute("/ws/reject", ws_reject_route),
        ]
    )
    app = WorkloadIdentityMiddleware(inner, POLICY, metrics=metrics)
    return TestClient(
        app,
        client=PROXY_PEER,
        base_url=f"http://{POD_IP}:8080",
        raise_server_exceptions=False,
    )


class TestGovernorGatedRequestMetrics:
    """Verify startup series initialization and request-outcome conservation."""

    def test_preinitializes_blocked_and_permitted_series_at_zero(self) -> None:
        registry = CollectorRegistry()
        governor_metrics(registry)
        assert _counter_value(registry, "blocked") == 0.0
        assert _counter_value(registry, "permitted") == 0.0

    def test_open_paths_never_increment_gated_request_counters(self) -> None:
        registry = CollectorRegistry()
        client = _build_test_client(registry)

        for path in sorted(OPEN_EXACT_PATHS):
            for _ in range(25):
                resp = client.get(path)
                assert resp.status_code == 200

        assert _counter_value(registry, "blocked") == 0.0
        assert _counter_value(registry, "permitted") == 0.0

    def test_kubelet_health_probes_do_not_dilute_100_percent_refusal_outage(
        self,
    ) -> None:
        """Core outage scenario: /healthz returns 200 200x while every gated call 403s."""
        registry = CollectorRegistry()
        client = _build_test_client(registry)

        for _ in range(200):
            assert client.get("/healthz").status_code == 200

        # 6 ingress 403s (missing/untrusted identity) + 6 downstream 403s (quarantine/policy)
        for _ in range(6):
            assert client.post("/governance/validate-action").status_code == 403
            assert (
                client.post(
                    "/governance/deny-403",
                    headers={CLIENT_IDENTITY_HEADER: ADVISOR},
                ).status_code
                == 403
            )

        blocked = _counter_value(registry, "blocked")
        permitted = _counter_value(registry, "permitted")
        assert blocked == 12.0
        assert permitted == 0.0
        assert blocked / (blocked + permitted) == 1.0

    def test_conservation_and_non_dilution_across_http_and_protocol_outcomes(
        self,
    ) -> None:
        registry = CollectorRegistry()
        client = _build_test_client(registry)
        auth = {CLIENT_IDENTITY_HEADER: ADVISOR}

        # 3 permitted requests
        for _ in range(3):
            assert (
                client.post("/governance/validate-action", headers=auth).status_code
                == 200
            )

        # 1 ingress untrusted identity -> 403 (blocked)
        assert (
            client.post(
                "/governance/validate-action",
                headers={CLIENT_IDENTITY_HEADER: UNTRUSTED},
            ).status_code
            == 403
        )
        # 1 downstream 403 + refusal_decided -> must count once, not twice
        assert client.post("/governance/deny-403", headers=auth).status_code == 403
        # 1 downstream 503 -> blocked
        assert client.post("/governance/fail-503", headers=auth).status_code == 503
        # 1 downstream 404 -> blocked (cannot inflate permitted to mask an attack)
        assert client.get("/governance/missing", headers=auth).status_code == 404
        # 1 HTTP 200 carrying protocol-wrapped governor refusal -> blocked
        assert client.post("/mcp/refusal-200", headers=auth).status_code == 200
        # 1 unhandled downstream exception -> blocked
        assert client.post("/governance/crash", headers=auth).status_code == 500

        assert _counter_value(registry, "permitted") == 3.0
        assert _counter_value(registry, "blocked") == 6.0

    def test_websocket_gated_outcomes_recorded(self) -> None:
        registry = CollectorRegistry()
        client = _build_test_client(registry)

        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(f"ws://{POD_IP}:8080/ws/ok") as ws:
                ws.receive_text()

        with client.websocket_connect(
            f"ws://{POD_IP}:8080/ws/ok", headers={CLIENT_IDENTITY_HEADER: ADVISOR}
        ) as ws:
            assert ws.receive_text() == "ok"

        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(
                f"ws://{POD_IP}:8080/ws/reject",
                headers={CLIENT_IDENTITY_HEADER: ADVISOR},
            ) as ws:
                ws.receive_text()

        assert _counter_value(registry, "permitted") == 1.0
        assert _counter_value(registry, "blocked") == 2.0


class TestInBandHttp200RefusalHooks:
    """Verify HTTP 200 endpoints that carry refusal verdicts mark the request refused."""

    @pytest.mark.asyncio
    async def test_policy_precheck_deny_marks_request_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from types import SimpleNamespace

        from src.gateway.governance.governor.metrics import (
            track_gated_request,
            was_request_refused,
        )
        from src.gateway.server import governance_middleware as gm

        class _BrokenOpa:
            async def evaluate_policy(self, _payload: dict[str, Any]) -> str:
                raise ConnectionError("OPA UDS unreachable")

        fake_gov = SimpleNamespace(
            bind_server_inputs=self._async_identity_bind,
            components=SimpleNamespace(opa=_BrokenOpa()),
        )
        monkeypatch.setattr(gm, "governor_of", lambda _app: fake_gov)
        monkeypatch.setattr(
            gm,
            "_check_validate_action_rate_limit",
            self._allow_rate_limit,
        )

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/policy-precheck",
            "headers": [],
            "app": SimpleNamespace(state=SimpleNamespace()),
        }
        req = Request(scope)
        body = gm.PolicyPrecheckRequest(action="governed_action", params={"amount": 10})

        with track_gated_request():
            resp = await gm.policy_precheck_endpoint(req, body)
            assert resp.status_code == 200
            assert was_request_refused() is True

    @pytest.mark.asyncio
    async def test_verify_content_safety_blocked_marks_request_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from src.gateway.governance.governor.metrics import (
            track_gated_request,
            was_request_refused,
        )
        from src.gateway.server import mcp_tool_server

        monkeypatch.setattr(
            mcp_tool_server.app.state, "nemo_rails", None, raising=False
        )
        monkeypatch.setenv("CAGE_INFERENCE_BACKEND", "vllm")
        monkeypatch.setenv("CAGE_NEMO_ENABLED", "true")

        with track_gated_request():
            verdict = await mcp_tool_server.verify_content_safety("probe")
            assert verdict.startswith("BLOCKED:")
            assert was_request_refused() is True

    @pytest.mark.asyncio
    async def test_evaluate_policy_denied_marks_request_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from types import SimpleNamespace

        from src.gateway.governance.governor.metrics import (
            track_gated_request,
            was_request_refused,
        )
        from src.gateway.server import mcp_tool_server

        class _DenyingOpa:
            async def evaluate_policy(self, _payload: dict[str, Any]) -> str:
                return "DENY"

        fake_gov = SimpleNamespace(components=SimpleNamespace(opa=_DenyingOpa()))
        monkeypatch.setattr(mcp_tool_server, "governor_of", lambda _app: fake_gov)

        with track_gated_request():
            out = await mcp_tool_server._evaluate_policy_internal(
                action="governed_action",
                subject_role="analyst",
                amount=500.0,
            )
            assert out.startswith("DENIED:")
            assert was_request_refused() is True

    @pytest.mark.asyncio
    async def test_tools_execute_unhandled_tool_error_marks_request_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from types import SimpleNamespace

        from src.gateway.governance.governor.metrics import (
            track_gated_request,
            was_request_refused,
        )
        from src.gateway.server import mcp_tool_server

        monkeypatch.setenv("CAGE_TRUSTED_CLIENT_IDENTITIES", ADVISOR)
        monkeypatch.setattr(
            mcp_tool_server,
            "get_shared_rate_limiter",
            lambda: SimpleNamespace(
                check_request=self._allow_mcp_rate_limit,
            ),
        )

        async def _failing_tool(**_kwargs: Any) -> str:
            raise RuntimeError("Redis connection refused")

        monkeypatch.setattr(
            mcp_tool_server, "trigger_safety_intervention", _failing_tool
        )
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/tools/execute",
            "headers": [(b"l5d-client-id", ADVISOR.encode("latin-1"))],
            "client": PROXY_PEER,
            "server": (POD_IP, 8080),
        }
        req = Request(scope)
        body = mcp_tool_server.ToolExecutionRequest(
            tool_name="trigger_safety_intervention",
            params={"reason": "test"},
        )

        with track_gated_request():
            result = await mcp_tool_server.execute_tool_endpoint(body, req)
            assert result["status"] == "ERROR"
            assert was_request_refused() is True

    @staticmethod
    async def _allow_mcp_rate_limit(*_args: Any, **_kwargs: Any) -> Any:
        from types import SimpleNamespace

        return SimpleNamespace(
            allowed=True,
            retry_after_seconds=0,
            identity=ADVISOR,
            principal="test",
            scope="principal",
        )

    @staticmethod
    async def _async_identity_bind(
        _action: str, params: dict[str, Any]
    ) -> dict[str, Any]:
        return dict(params)

    @staticmethod
    async def _allow_rate_limit(_request: Request) -> bool:
        return True


class TestSustainedRefusalRatioAlertTerraformContract:
    """Verify the GMP PromQL alert policy contract and threshold semantics."""

    def test_metrics_alerting_tf_defines_sustained_refusal_ratio_policy(self) -> None:
        tf_text = _METRICS_ALERTING_TF.read_text(encoding="utf-8")
        assert (
            'resource "google_monitoring_alert_policy" "gateway_sustained_refusal_ratio"'
            in tf_text
        )
        assert "cage_gateway_gated_requests_total" in tf_text
        assert 'outcome=\\"blocked\\"' in tf_text

        # Extract floor and ratio threshold from locals and evaluate across all 5 regimes.
        min_match = re.search(
            r"gateway_refusal_ratio_min_requests\s*=\s*(\d+)", tf_text
        )
        thresh_match = re.search(
            r'gateway_refusal_ratio_threshold\s*=\s*"?([0-9.]+)"?', tf_text
        )
        assert min_match is not None, (
            "Expected gateway_refusal_ratio_min_requests local"
        )
        assert thresh_match is not None, (
            "Expected gateway_refusal_ratio_threshold local"
        )
        min_requests = int(min_match.group(1))
        threshold = float(thresh_match.group(1))
        assert min_requests >= 5
        assert 0.90 <= threshold < 1.0

        def fires(blocked_5m: float, permitted_5m: float) -> bool:
            total_5m = blocked_5m + permitted_5m
            if total_5m < min_requests:
                return False
            return (blocked_5m / total_5m) >= threshold

        # 1. Idle cluster (even with 500 open-path /healthz probes excluded from both): silent on ratio
        assert fires(0.0, 0.0) is False
        # 2. Single/small negative smoke probe below volume floor: silent on ratio
        assert fires(float(min_requests - 1), 0.0) is False
        # 3. Healthy cluster with occasional policy denials: silent on ratio
        assert fires(5.0, 95.0) is False
        # 4. Soft-failed dependency (100% gated requests refused): pages on ratio
        assert fires(float(min_requests), 0.0) is True
        # 5. Sustained attack / near-total refusal (96% blocked): pages on ratio
        assert fires(96.0, 4.0) is True

    def test_zero_permitted_requests_policy_closes_caller_backoff_gap(self) -> None:
        """Verify rate(permitted)==0 over 900s holds paging open when callers back off."""
        tf_text = _METRICS_ALERTING_TF.read_text(encoding="utf-8")
        assert (
            'resource "google_monitoring_alert_policy" "gateway_zero_permitted_requests"'
            in tf_text
        )
        assert (
            'rate(cage_gateway_gated_requests_total{job=\\"gateway-metrics\\"'
            in tf_text
        )
        assert 'outcome=\\"permitted\\"}[5m])) == 0' in tf_text
        assert 'duration                  = "900s"' in tf_text

        # Verify Terraform documents the >= 400 denominator assumption tied to
        # deny-by-default Linkerd mesh ingress so widening ingress triggers re-audit.
        assert ">= 400" in tf_text
        assert "404" in tf_text

        min_match = re.search(
            r"gateway_refusal_ratio_min_requests\s*=\s*(\d+)", tf_text
        )
        thresh_match = re.search(
            r'gateway_refusal_ratio_threshold\s*=\s*"?([0-9.]+)"?', tf_text
        )
        assert min_match is not None
        assert thresh_match is not None
        min_requests = int(min_match.group(1))
        threshold = float(thresh_match.group(1))

        def ratio_fires(
            blocked_5m: float, permitted_5m: float, sustained_s: int
        ) -> bool:
            total_5m = blocked_5m + permitted_5m
            if sustained_s < 180 or total_5m < min_requests:
                return False
            return (blocked_5m / total_5m) >= threshold

        def zero_permitted_fires(permitted_5m: float, sustained_s: int) -> bool:
            rate_permitted_per_s = permitted_5m / 300.0
            return sustained_s >= 900 and rate_permitted_per_s == 0.0

        # Stage 1 (t = 3m): outage begins, callers retry (>= 5 blocked / 5m, 0 permitted).
        # Ratio alarm pages fast; 15m zero-permitted condition not yet at duration.
        assert ratio_fires(20.0, 0.0, sustained_s=180) is True
        assert zero_permitted_fires(0.0, sustained_s=180) is False

        # Stage 2 (t = 15m+): callers give up retrying (only 1 blocked / 5m < floor, 0 permitted).
        # Ratio condition drops below floor, but zero_permitted_requests takes over with no floor.
        assert ratio_fires(1.0, 0.0, sustained_s=900) is False
        assert zero_permitted_fires(0.0, sustained_s=900) is True

        # Recovery: as soon as permitted traffic resumes (> 0), both conditions clear.
        assert ratio_fires(0.0, 1.0, sustained_s=900) is False
        assert zero_permitted_fires(1.0, sustained_s=900) is False


CANARY_ID = "cage-gateway-canary-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"


class TestSyntheticMeshCanaryAndComplianceExclusion:
    """Verify synthetic in-mesh canary lockdown and exclusion from Lula compliance counts."""

    def test_canary_identity_disjoint_and_restricted_to_canary_routes(self) -> None:
        from src.gateway.server.workload_identity import is_canary_request

        # Overlapping trusted and canary identities must fail closed at policy construction.
        with pytest.raises(ValueError, match="disjoint"):
            IdentityPolicy(
                trusted=frozenset({ADVISOR}),
                canary=frozenset({ADVISOR}),
            )

        policy = IdentityPolicy(
            trusted=frozenset({ADVISOR}),
            canary=frozenset({CANARY_ID}),
        )
        registry = CollectorRegistry()
        metrics = governor_metrics(registry)
        observed_canary_flags: list[bool] = []

        async def _probe_handler(_request: Request) -> JSONResponse:
            observed_canary_flags.append(is_canary_request())
            return JSONResponse({"decision": "ALLOW"}, status_code=200)

        inner = Starlette(
            routes=[
                Route(
                    "/governance/validate-action",
                    _probe_handler,
                    methods=["POST", "GET"],
                ),
                Route("/governance/policy-precheck", _probe_handler, methods=["POST"]),
                Route("/tools/execute", _probe_handler, methods=["POST"]),
                Route("/mcp/", _probe_handler, methods=["POST"]),
                Route("/v1/chat/completions", _probe_handler, methods=["POST"]),
            ]
        )
        client = TestClient(
            WorkloadIdentityMiddleware(inner, policy, metrics=metrics),
            client=PROXY_PEER,
            base_url=f"http://{POD_IP}:8080",
        )
        canary_headers = {CLIENT_IDENTITY_HEADER: CANARY_ID}
        advisor_headers = {CLIENT_IDENTITY_HEADER: ADVISOR}

        # Canary identity is permitted ONLY on POST /governance/validate-action and
        # POST /governance/policy-precheck, with is_canary_request() == True.
        assert (
            client.post(
                "/governance/validate-action", headers=canary_headers
            ).status_code
            == 200
        )
        assert (
            client.post(
                "/governance/policy-precheck", headers=canary_headers
            ).status_code
            == 200
        )
        # Advisor identity on the same route has is_canary_request() == False.
        assert (
            client.post(
                "/governance/validate-action", headers=advisor_headers
            ).status_code
            == 200
        )
        assert observed_canary_flags == [True, True, False]

        # Canary identity MUST be refused 403 on GET and on every other gated surface.
        assert (
            client.get(
                "/governance/validate-action", headers=canary_headers
            ).status_code
            == 403
        )
        assert client.post("/tools/execute", headers=canary_headers).status_code == 403
        assert client.post("/mcp/", headers=canary_headers).status_code == 403
        assert (
            client.post("/v1/chat/completions", headers=canary_headers).status_code
            == 403
        )

        assert _counter_value(registry, "permitted") == 3.0
        assert _counter_value(registry, "blocked") == 4.0

    def test_evidence_sink_stamps_canary_and_strips_spoofed_canary_flag(self) -> None:
        import json

        from src.gateway.governance.evidence.stream import EvidenceStreamSink
        from src.gateway.server.workload_identity import _serving

        sink = EvidenceStreamSink()

        # 1. Under verified canary identity, _prepare_item stamps "canary": true.
        with _serving(CANARY_ID, canary=True):
            canary_item = sink._prepare_item(
                {
                    "type": "GOVERNANCE_TRACE",
                    "controlId": "A.5.3",
                    "verdict": "ALLOW",
                },
                future=None,
            )
        canary_payload = json.loads(canary_item.payload_json)
        assert canary_payload["canary"] is True

        # 2. Under non-canary identity, a spoofed top-level "canary": True is stripped!
        with _serving(ADVISOR, canary=False):
            spoofed_item = sink._prepare_item(
                {
                    "type": "GOVERNANCE_REFUSAL",
                    "controlId": "A.5.3",
                    "verdict": "DENY",
                    "canary": True,
                },
                future=None,
            )
        spoofed_payload = json.loads(spoofed_item.payload_json)
        assert "canary" not in spoofed_payload

    def test_compliance_bridge_excludes_canary_records_from_lula_volume_thresholds(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """150 canary probes must yield total_traces == 0 and safety_rate is None on idle cluster."""
        import json
        from datetime import datetime, timezone

        from src.compliance_bridge import metrics as cb_metrics

        now_iso = datetime.now(tz=timezone.utc).isoformat()
        synthetic_stream: list[tuple[str, dict[str, str]]] = []

        # Seed 150 canary records across A.5.3, A.5.2, and A.9.2 (> 101 trace threshold).
        for idx in range(150):
            ctrl = ("A.5.3", "A.5.2", "A.9.2")[idx % 3]
            payload = {
                "type": "GOVERNANCE_DECISION",
                "controlId": ctrl,
                "verdict": "ALLOW",
                "canary": True,
                "timestamp_utc": now_iso,
            }
            synthetic_stream.append(
                (
                    f"1700000000{idx:03d}-0",
                    {
                        "chain_id": "test-chain",
                        "sequence": str(idx),
                        "timestamp_utc": now_iso,
                        "event_type": "GOVERNANCE_DECISION",
                        "control_id": ctrl,
                        "payload_json": json.dumps(payload),
                    },
                )
            )

        class _FakeRedis:
            def xrevrange(
                self, _key: str, _max: str, _min: str, count: int = 1000
            ) -> list[tuple[str, dict[str, str]]]:
                if _key != "cage:evidence:stream":
                    return []
                return list(reversed(synthetic_stream))[:count]

            def close(self) -> None:
                pass

        monkeypatch.setenv("EVIDENCE_STREAM_REDIS_URL", "redis://localhost:6379/1")
        monkeypatch.delenv("EVIDENCE_COLD_STORE", raising=False)
        monkeypatch.delenv("EVIDENCE_ARCHIVE_BUCKET", raising=False)
        monkeypatch.setattr(
            cb_metrics, "_build_evidence_sync_redis", lambda *_a, **_kw: _FakeRedis()
        )
        cb_metrics._metrics_cache.clear()
        with cb_metrics._raw_custody_lock:
            cb_metrics._raw_custody_cache.clear()

        for ctrl in ("A.5.3", "A.5.2", "A.9.2"):
            res = cb_metrics._fetch_from_evidence_stream_sync(ctrl, window_hours=24)
            assert res.total_traces == 0, f"{ctrl} counted synthetic canary traces"
            assert res.safety_rate is None, f"{ctrl} fabricated safety_rate from canary"

        # Now append 1 real passing trace and 1 real failing trace attempting to
        # smuggle nested params={"canary": True}: both MUST be counted!
        for seq_offset, (verdict, event_type) in enumerate(
            [("ALLOW", "GOVERNANCE_DECISION"), ("FAIL", "GOVERNANCE_VIOLATION")],
            start=200,
        ):
            real_payload = {
                "type": event_type,
                "controlId": "A.5.3",
                "verdict": verdict,
                "params": {"canary": True},
                "timestamp_utc": now_iso,
            }
            synthetic_stream.append(
                (
                    f"1700000000{seq_offset:03d}-0",
                    {
                        "chain_id": "test-chain",
                        "sequence": str(seq_offset),
                        "timestamp_utc": now_iso,
                        "event_type": event_type,
                        "control_id": "A.5.3",
                        "payload_json": json.dumps(real_payload),
                    },
                )
            )

        with cb_metrics._raw_custody_lock:
            cb_metrics._raw_custody_cache.clear()

        mixed = cb_metrics._fetch_from_evidence_stream_sync("A.5.3", window_hours=24)
        assert mixed.total_traces == 2
        assert mixed.passed_traces == 1
        assert mixed.blocked_traces == 1
        assert mixed.safety_rate == 0.5

    @pytest.mark.asyncio
    async def test_canary_probe_runner_handles_domain_probes_and_failures(self) -> None:
        import httpx

        from src.gateway.canary import run_canary_probe_once
        from src.gateway.governance.plugin_loader import load_domain_plugin

        finance_probe = load_domain_plugin("finance").domain_config.canary_probe
        healthcare_probe = load_domain_plugin("healthcare").domain_config.canary_probe
        assert finance_probe is not None
        assert healthcare_probe is not None
        assert finance_probe.route == "/governance/validate-action"
        assert healthcare_probe.route == "/governance/policy-precheck"

        def _healthy_handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/governance/validate-action":
                return httpx.Response(
                    200,
                    json={"payload": {"governance": {"verdict": "ALLOW"}}},
                )
            return httpx.Response(
                200,
                json={"decision": "ALLOW", "dry_run": True},
            )

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(_healthy_handler)
        ) as client:
            assert (
                await run_canary_probe_once(
                    client, "http://gateway.local:8080", finance_probe
                )
                is True
            )
            assert (
                await run_canary_probe_once(
                    client, "http://gateway.local:8080", healthcare_probe
                )
                is True
            )

        def _broken_opa_handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"decision": "DENY", "dry_run": True})

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(_broken_opa_handler)
        ) as client:
            assert (
                await run_canary_probe_once(
                    client, "http://gateway.local:8080", healthcare_probe
                )
                is False
            )

    def test_canary_probe_scope_rejects_non_probe_actions(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from src.gateway.server.governance_middleware import _enforce_canary_probe_scope
        from src.gateway.server.workload_identity import _serving

        monkeypatch.setenv("CAGE_DOMAIN", "finance")
        with _serving(CANARY_ID, canary=True):
            # Finance canary probe is POST /governance/validate-action with action="market_analysis".
            assert (
                _enforce_canary_probe_scope(
                    "/governance/validate-action", "market_analysis"
                )
                is None
            )
            # Mutating action on the allowed route must be refused 403.
            blocked_mutating = _enforce_canary_probe_scope(
                "/governance/validate-action", "execute_trade"
            )
            assert blocked_mutating is not None and blocked_mutating.status_code == 403
            # Wrong route for finance canary must also be refused 403.
            blocked_route = _enforce_canary_probe_scope(
                "/governance/policy-precheck", "market_analysis"
            )
            assert blocked_route is not None and blocked_route.status_code == 403

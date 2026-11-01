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

"""Unit tests for PR A4: shared workload-identity + principal GCRA rate limiter
and GatewayClient bounded retry behavior.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis.aioredis
import httpx
import pytest
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.governance_envelope import GovernanceEnvelopeBuilder
from src.gateway.server.rate_limit import (
    SharedRateLimiter,
    extract_rate_limit_keys,
    rate_limit_backend_errors_total,
    rate_limit_hits_total,
    sanitize_principal,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

_TRUSTED_SPIFFE = "gfa.governance-stack.serviceaccount.identity.linkerd.cluster.local"


class TestPrincipalSanitizationAndHeaderTrust:
    """Verify principal header sanitization and Linkerd workload-identity trust."""

    def test_sanitize_principal_normalizes_and_caps(self) -> None:
        assert sanitize_principal(None) == "anonymous"
        assert sanitize_principal("") == "anonymous"
        assert sanitize_principal("   ") == "anonymous"
        assert sanitize_principal("user:alice@example.com") == "user:alice@example.com"
        assert sanitize_principal("bad\nheader\x00value!") == "bad_header_value"
        long_val = "a" * 120
        assert len(sanitize_principal(long_val)) == 64

    def test_extract_rate_limit_keys_trusts_principal_only_with_linkerd_id(
        self,
    ) -> None:
        # Request with verified Linkerd workload identity trusts x-cage-principal.
        # The pod's Linkerd proxy connects from the pod's own address.
        trusted_scope = {
            "type": "http",
            "headers": [
                (b"l5d-client-id", _TRUSTED_SPIFFE.encode("latin-1")),
                (b"x-cage-principal", b"trader-42"),
            ],
            "client": ("10.244.0.10", 54321),
            "server": ("10.244.0.10", 8080),
        }
        req_trusted = Request(trusted_scope)
        identity, principal = extract_rate_limit_keys(req_trusted)
        assert identity == _TRUSTED_SPIFFE
        assert principal == "trader-42"

        # Request WITHOUT Linkerd workload identity ignores x-cage-principal
        untrusted_scope = {
            "type": "http",
            "headers": [
                (b"x-cage-principal", b"spoofed-principal-99"),
            ],
            "client": ("198.51.100.7", 54321),
        }
        req_untrusted = Request(untrusted_scope)
        u_id, u_principal = extract_rate_limit_keys(req_untrusted)
        assert u_id == "untrusted:198.51.100.7"
        assert u_principal == "untrusted:198.51.100.7"
        assert "spoofed" not in u_principal

        # A Linkerd identity sent by another pod, not written by this pod's
        # proxy, is not a verified identity either (POAM-2026-167).
        forged_scope = {
            "type": "http",
            "headers": [
                (b"l5d-client-id", _TRUSTED_SPIFFE.encode("latin-1")),
                (b"x-cage-principal", b"spoofed-principal-99"),
            ],
            "client": ("10.244.3.7", 54321),
            "server": ("10.244.0.10", 8080),
        }
        f_id, f_principal = extract_rate_limit_keys(Request(forged_scope))
        assert f_id == "untrusted:10.244.3.7"
        assert "spoofed" not in f_principal

    @pytest.mark.asyncio
    async def test_mcp_tool_server_honors_cage_rate_limit_env_vars(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from src.gateway.server import mcp_tool_server

        monkeypatch.setenv("CAGE_RATE_LIMIT_PRINCIPAL_PER_MIN", "2")
        monkeypatch.setenv("CAGE_RATE_LIMIT_WINDOW_SECONDS", "60")
        mcp_tool_server.get_shared_rate_limiter().clear()
        try:
            assert (
                await mcp_tool_server._check_rate_limit("env-override-caller") is True
            )
            assert (
                await mcp_tool_server._check_rate_limit("env-override-caller") is True
            )
            assert (
                await mcp_tool_server._check_rate_limit("env-override-caller") is False
            )
        finally:
            mcp_tool_server.get_shared_rate_limiter().clear()


class TestSharedGCRADualBucket:
    """Verify Redis Lua dual-bucket GCRA behavior and cross-replica budget sharing."""

    @pytest.mark.asyncio
    async def test_gcra_principal_and_identity_buckets_in_redis(self) -> None:
        fake_redis = fakeredis.aioredis.FakeRedis()
        limiter = SharedRateLimiter(
            fake_redis,
            principal_per_min=2,
            identity_per_min=3,
            window_seconds=60.0,
        )

        # Principal A: 2 calls allowed at t=1000ms
        v1 = await limiter.check(
            "validate-action",
            identity=_TRUSTED_SPIFFE,
            principal="user-a",
            now_ms=1000,
        )
        v2 = await limiter.check(
            "validate-action",
            identity=_TRUSTED_SPIFFE,
            principal="user-a",
            now_ms=1000,
        )
        assert v1.allowed is True
        assert v2.allowed is True

        # 3rd call from Principal A at t=1000ms exceeds principal_per_min=2
        v3 = await limiter.check(
            "validate-action",
            identity=_TRUSTED_SPIFFE,
            principal="user-a",
            now_ms=1000,
        )
        assert v3.allowed is False
        assert v3.scope == "principal"
        assert v3.retry_after_seconds >= 1

        # Principal B on the same workload identity still gets 1 call (3rd for identity)
        v4 = await limiter.check(
            "validate-action",
            identity=_TRUSTED_SPIFFE,
            principal="user-b",
            now_ms=1000,
        )
        assert v4.allowed is True

        # 2nd call from Principal B hits the identity fleet cap (identity_per_min=3)
        v5 = await limiter.check(
            "validate-action",
            identity=_TRUSTED_SPIFFE,
            principal="user-b",
            now_ms=1000,
        )
        assert v5.allowed is False
        assert v5.scope == "identity"
        assert v5.retry_after_seconds >= 1

        # After 30 seconds (one principal emission interval T=30000ms), both recover
        v6 = await limiter.check(
            "validate-action",
            identity=_TRUSTED_SPIFFE,
            principal="user-a",
            now_ms=31_000,
        )
        assert v6.allowed is True
        await fake_redis.aclose()

    @pytest.mark.asyncio
    async def test_two_gateway_replicas_share_single_redis_budget(self) -> None:
        shared_redis = fakeredis.aioredis.FakeRedis()
        replica_1_limiter = SharedRateLimiter(
            shared_redis,
            principal_per_min=3,
            identity_per_min=10,
            window_seconds=60.0,
        )
        replica_2_limiter = SharedRateLimiter(
            shared_redis,
            principal_per_min=3,
            identity_per_min=10,
            window_seconds=60.0,
        )

        def _make_replica_app(limiter: SharedRateLimiter) -> FastAPI:
            app = FastAPI()
            app.state.rate_limit_redis = shared_redis

            @app.post("/governance/validate-action")
            async def _handler(request: Request) -> Any:
                verdict = await limiter.check_request(request, "validate-action")
                if not verdict.allowed:
                    from fastapi.responses import JSONResponse

                    return JSONResponse(
                        status_code=429,
                        headers={"Retry-After": str(verdict.retry_after_seconds)},
                        content={
                            "error": "rate_limit_exceeded",
                            "scope": verdict.scope,
                            "retry_after_seconds": verdict.retry_after_seconds,
                        },
                    )
                return {"ok": True}

            return app

        app1 = _make_replica_app(replica_1_limiter)
        app2 = _make_replica_app(replica_2_limiter)
        headers = {
            "l5d-client-id": _TRUSTED_SPIFFE,
            "x-cage-principal": "shared-session-1",
        }

        async with (
            AsyncClient(
                transport=ASGITransport(app=app1), base_url="http://replica1"
            ) as c1,
            AsyncClient(
                transport=ASGITransport(app=app2), base_url="http://replica2"
            ) as c2,
        ):
            r1 = await c1.post("/governance/validate-action", headers=headers)
            r2 = await c2.post("/governance/validate-action", headers=headers)
            r3 = await c1.post("/governance/validate-action", headers=headers)
            r4 = await c2.post("/governance/validate-action", headers=headers)

        assert r1.status_code == 200
        assert r2.status_code == 200
        assert r3.status_code == 200
        assert r4.status_code == 429
        assert r4.headers.get("Retry-After") is not None
        body = r4.json()
        assert body["error"] == "rate_limit_exceeded"
        assert body["scope"] == "principal"
        await shared_redis.aclose()

    @pytest.mark.asyncio
    async def test_redis_error_falls_back_to_local_gcra_and_increments_metric(
        self,
    ) -> None:
        broken_redis = MagicMock()
        broken_redis.register_script = MagicMock(
            side_effect=ConnectionError("redis down")
        )
        broken_redis.eval = AsyncMock(side_effect=ConnectionError("redis down"))

        limiter = SharedRateLimiter(
            broken_redis,
            principal_per_min=2,
            identity_per_min=10,
            window_seconds=60.0,
        )

        with (
            patch.object(rate_limit_backend_errors_total, "labels") as mock_err_labels,
            patch.object(rate_limit_hits_total, "labels") as mock_hit_labels,
        ):
            err_counter = MagicMock()
            hit_counter = MagicMock()
            mock_err_labels.return_value = err_counter
            mock_hit_labels.return_value = hit_counter

            v1 = await limiter.check(
                "validate-action",
                identity=_TRUSTED_SPIFFE,
                principal="fallback-user",
            )
            v2 = await limiter.check(
                "validate-action",
                identity=_TRUSTED_SPIFFE,
                principal="fallback-user",
            )
            v3 = await limiter.check(
                "validate-action",
                identity=_TRUSTED_SPIFFE,
                principal="fallback-user",
            )

        assert v1.allowed is True
        assert v2.allowed is True
        assert v3.allowed is False
        assert v3.scope == "principal"
        assert err_counter.inc.call_count == 3
        mock_err_labels.assert_called_with(route="validate-action")
        mock_hit_labels.assert_called_with(route="validate-action", scope="principal")


class TestGatewayClientPrincipalAndRetries:
    """Verify GatewayClient sends x-cage-principal and retries on 429/503."""

    @pytest.mark.asyncio
    async def test_validate_action_sends_principal_and_retries_429_503(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from src.governed_financial_advisor.infrastructure.gateway_client import (
            GatewayClient,
        )
        from src.governed_financial_advisor.utils.context import user_context

        monkeypatch.setenv("CAGE_GATEWAY_RETRY_BASE_SECONDS", "0.001")
        monkeypatch.setenv("CAGE_GATEWAY_RETRY_CAP_SECONDS", "0.005")

        token = user_context.set("advisor-session-77")
        seen_headers: list[dict[str, str]] = []
        attempts = 0

        envelope = {
            "verdict": GovernanceDecision.ALLOW.value,
            "latency_ms": 1.2,
        }

        def _handler(request: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            seen_headers.append(dict(request.headers))
            if attempts == 1:
                return httpx.Response(
                    429,
                    headers={"Retry-After": "0.001"},
                    json={"error": "rate_limit_exceeded"},
                )
            if attempts == 2:
                return httpx.Response(503, json={"error": "service_unavailable"})
            return httpx.Response(200, json=envelope)

        client = GatewayClient()
        old_http = client._http
        client._http = httpx.AsyncClient(
            transport=httpx.MockTransport(_handler),
            base_url="http://gateway.test",
        )
        try:
            res = await client.validate_action("execute_trade", {"amount": 100.0})
            assert res["verdict"] == GovernanceDecision.ALLOW.value
            assert attempts == 3
            assert seen_headers[0].get("x-cage-principal") == "advisor-session-77"
        finally:
            await client._http.aclose()
            client._http = old_http
            user_context.reset(token)

    @pytest.mark.asyncio
    async def test_execute_tool_retries_on_429_and_raises_when_exhausted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from src.governed_financial_advisor.infrastructure.gateway_client import (
            GatewayClient,
        )

        monkeypatch.setenv("CAGE_GATEWAY_RETRY_BASE_SECONDS", "0.001")
        monkeypatch.setenv("CAGE_GATEWAY_RETRY_CAP_SECONDS", "0.005")

        call_count = 0

        def _always_429(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            return httpx.Response(
                429,
                headers={"Retry-After": "0.001"},
                content=json.dumps({"error": "rate_limit_exceeded"}).encode(),
            )

        client = GatewayClient()
        old_http = client._http
        client._http = httpx.AsyncClient(
            transport=httpx.MockTransport(_always_429),
            base_url="http://gateway.test",
        )
        try:
            with pytest.raises(httpx.HTTPStatusError) as exc_info:
                await client.execute_tool("execute_trade_action", {"symbol": "AAPL"})
            assert exc_info.value.response.status_code == 429
            assert call_count == 3
        finally:
            await client._http.aclose()
            client._http = old_http

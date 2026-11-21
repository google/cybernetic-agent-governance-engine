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

"""Inference proxy quarantine outages fail closed as 503 infrastructure blocks.

``POST /v1/chat/completions`` previously checked ``is_workload_quarantined()``,
which collapsed a Redis outage or missing enforcing-posture Redis client into
``True`` and returned HTTP 403 ``workload_quarantined`` alongside an
``INFERENCE_PROXY_BLOCK`` record (``SC-7``). Under ``POAM-2026-233``, backend
unavailability must instead return HTTP 503 ``quarantine_backend_unavailable``,
record a ``GOVERNANCE_INFRASTRUCTURE_BLOCK`` without stamping ``SC-7 BLOCK`` or
``INFERENCE_PROXY_BLOCK``, while confirmed quarantines keep HTTP 403 across both
``body.thread_id`` and ``x-cage-thread-id`` without shadowing.
"""

from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis.aioredis
import httpx
import pytest

from src.gateway.governance.env_posture import DeploymentPosture
from src.gateway.governance.evidence.stream import EvidenceChainUnavailableError
from src.gateway.governance.quarantine_actuator import (
    QuarantineDirective,
    QuarantineTriggerReason,
    bind_quarantine_redis,
    clear_local_quarantine_state,
    dispatch_quarantine,
    get_quarantine_redis,
)
from src.gateway.server import inference_proxy as ip

pytestmark = [pytest.mark.unit, pytest.mark.local]

_TRUSTED_SVID = "spiffe://cluster.local/ns/default/sa/proxy-quarantine-test"


def _make_directive(
    *, thread_id: str = "", agent_svid: str = ""
) -> QuarantineDirective:
    return QuarantineDirective(
        thread_id=thread_id,
        agent_svid=agent_svid,
        sandbox_id="sbx-proxy-test",
        reason=QuarantineTriggerReason.CRITICAL_CBF_BREACH,
        violation_codes=("CBF_BARRIER_VIOLATED",),
        issued_at=1700000000,
        correlation_id="corr-proxy-test",
        refusal_proof_hash=hashlib.sha256(b"refusal-receipt-proxy-test").hexdigest(),
        nonce="nonce-proxy-test",
        ttl_seconds=300,
    )


@asynccontextmanager
async def _proxy_harness(
    *,
    redis_client: Any = None,
    posture: DeploymentPosture = DeploymentPosture.DEV,
    publish_infra_side_effect: Any = None,
    emit_proxy_side_effect: Any = None,
) -> AsyncIterator[dict[str, Any]]:
    """Mount controlled Redis, posture, telemetry, and evidence doubles on inference_app."""
    prev_app_redis = getattr(ip.inference_app.state, "redis", None)
    prev_default_redis = get_quarantine_redis()
    ip.inference_app.state.redis = redis_client
    bind_quarantine_redis(None)
    clear_local_quarantine_state()

    span = MagicMock()
    span.is_recording.return_value = True
    tracer = MagicMock()
    tracer.start_as_current_span.return_value.__enter__.return_value = span
    tracer.start_as_current_span.return_value.__exit__.return_value = False

    metrics = MagicMock()
    publish_infra = AsyncMock(side_effect=publish_infra_side_effect)
    emit_proxy = AsyncMock(side_effect=emit_proxy_side_effect)
    quota_proxy = MagicMock()
    quota_proxy.check_and_increment = AsyncMock(
        side_effect=AssertionError("token quota must not run after quarantine block")
    )
    http_client = MagicMock()
    http_client.post = AsyncMock(
        side_effect=AssertionError("upstream LLM must not run after quarantine block")
    )

    try:
        with (
            patch(
                "src.gateway.server.workload_identity.extract_client_identity",
                return_value=_TRUSTED_SVID,
            ),
            patch(
                "src.gateway.governance.quarantine_actuator.resolve_posture",
                return_value=posture,
            ),
            patch(
                "src.gateway.governance.governor.metrics.governor_metrics",
                return_value=metrics,
            ),
            patch(
                "src.gateway.governance.governor.verdicts.publish_infrastructure_block",
                new=publish_infra,
            ),
            patch.object(ip, "_emit_proxy_evidence", new=emit_proxy),
            patch.object(ip, "stamp_iso_control") as stamp_iso,
            patch.object(ip, "_get_token_quota_proxy", return_value=quota_proxy),
            patch.object(ip, "_get_http_client", return_value=http_client),
            patch.object(ip.trace, "get_tracer", return_value=tracer),
        ):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=ip.inference_app),
                base_url="http://testserver",
            ) as client:
                yield {
                    "client": client,
                    "span": span,
                    "metrics": metrics,
                    "publish_infra": publish_infra,
                    "emit_proxy": emit_proxy,
                    "stamp_iso": stamp_iso,
                    "quota_proxy": quota_proxy,
                    "http_client": http_client,
                }
    finally:
        ip.inference_app.state.redis = prev_app_redis
        bind_quarantine_redis(prev_default_redis)
        clear_local_quarantine_state()


def _chat_body(**extra: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "model": "fast",
        "messages": [{"role": "user", "content": "hello"}],
    }
    body.update(extra)
    return body


@pytest.mark.asyncio
async def test_redis_error_returns_503_infrastructure_block_not_false_403() -> None:
    broken_redis = MagicMock()
    broken_redis.exists = AsyncMock(side_effect=RuntimeError("redis connection lost"))

    async with _proxy_harness(redis_client=broken_redis) as env:
        resp = await env["client"].post(
            "/v1/chat/completions",
            headers={"x-cage-thread-id": "thread-outage-1"},
            json=_chat_body(),
        )

    assert resp.status_code == 503, resp.text
    payload = resp.json()
    assert payload["error"] == "quarantine_backend_unavailable"
    assert payload["dependency"] == "redis"
    assert payload["failure_code"] == "QUARANTINE_REDIS_UNAVAILABLE"

    env["emit_proxy"].assert_not_awaited()
    env["metrics"].infrastructure_block_decided.assert_called_once_with(
        "redis", "QUARANTINE_REDIS_UNAVAILABLE"
    )
    env["publish_infra"].assert_awaited_once()
    pub_kwargs = env["publish_infra"].await_args.kwargs
    assert pub_kwargs["dependency"] == "redis"
    assert pub_kwargs["failure_code"] == "QUARANTINE_REDIS_UNAVAILABLE"
    assert pub_kwargs["control_id"] == "SC-7"
    assert pub_kwargs["params"] == {"thread_id": "thread-outage-1"}

    # SC-7 BLOCK must never be stamped on a Redis outage; Stage 1 A.5.2 PASS ran earlier.
    sc7_stamps = [
        call
        for call in env["stamp_iso"].call_args_list
        if call.kwargs.get("control") == "SC-7"
    ]
    assert sc7_stamps == []
    env["span"].set_attribute.assert_any_call("cage.verdict", "INFRASTRUCTURE_BLOCK")
    env["span"].set_attribute.assert_any_call("cage.infrastructure.dependency", "redis")
    env["span"].set_attribute.assert_any_call(
        "cage.infrastructure.failure_code", "QUARANTINE_REDIS_UNAVAILABLE"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "posture",
    [DeploymentPosture.STAGING, DeploymentPosture.PRODUCTION],
)
async def test_missing_redis_in_enforcing_posture_returns_503_not_403(
    posture: DeploymentPosture,
) -> None:
    async with _proxy_harness(redis_client=None, posture=posture) as env:
        resp = await env["client"].post("/v1/chat/completions", json=_chat_body())

    assert resp.status_code == 503, resp.text
    assert resp.json()["error"] == "quarantine_backend_unavailable"
    env["emit_proxy"].assert_not_awaited()
    env["publish_infra"].assert_awaited_once()
    env["metrics"].infrastructure_block_decided.assert_called_once_with(
        "redis", "QUARANTINE_REDIS_UNAVAILABLE"
    )


@pytest.mark.asyncio
async def test_concurrent_redis_and_evidence_outage_still_fails_closed_503() -> None:
    broken_redis = MagicMock()
    broken_redis.exists = AsyncMock(side_effect=ConnectionError("redis down"))

    async with _proxy_harness(
        redis_client=broken_redis,
        publish_infra_side_effect=EvidenceChainUnavailableError("evidence redis down"),
    ) as env:
        resp = await env["client"].post("/v1/chat/completions", json=_chat_body())

    assert resp.status_code == 503, resp.text
    assert resp.json()["error"] == "quarantine_backend_unavailable"
    env["emit_proxy"].assert_not_awaited()
    env["publish_infra"].assert_awaited_once()


@pytest.mark.asyncio
async def test_confirmed_svid_quarantine_returns_403_and_emits_proxy_block() -> None:
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    await dispatch_quarantine(
        _make_directive(agent_svid=_TRUSTED_SVID),
        redis_client=redis,
    )

    async with _proxy_harness(
        redis_client=redis, posture=DeploymentPosture.PRODUCTION
    ) as env:
        resp = await env["client"].post(
            "/v1/chat/completions",
            headers={"x-cage-thread-id": "thread-svid-1"},
            json=_chat_body(),
        )

    assert resp.status_code == 403, resp.text
    payload = resp.json()
    assert payload["error"] == "workload_quarantined"
    assert payload["agent_id"] == _TRUSTED_SVID
    assert payload["thread_id"] == "thread-svid-1"
    env["publish_infra"].assert_not_awaited()
    env["emit_proxy"].assert_awaited_once()
    assert env["emit_proxy"].await_args.kwargs["event_type"] == "INFERENCE_PROXY_BLOCK"
    assert env["emit_proxy"].await_args.kwargs["control_id"] == "SC-7"
    sc7_stamps = [
        call
        for call in env["stamp_iso"].call_args_list
        if call.kwargs.get("control") == "SC-7"
    ]
    assert len(sc7_stamps) == 1
    assert sc7_stamps[0].kwargs["outcome"] == "BLOCK"


@pytest.mark.asyncio
async def test_body_thread_id_cannot_shadow_quarantined_header_thread_id() -> None:
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    await dispatch_quarantine(
        _make_directive(thread_id="quarantined-hdr-thread"),
        redis_client=redis,
    )

    async with _proxy_harness(
        redis_client=redis, posture=DeploymentPosture.PRODUCTION
    ) as env:
        resp = await env["client"].post(
            "/v1/chat/completions",
            headers={"x-cage-thread-id": "quarantined-hdr-thread"},
            json=_chat_body(thread_id="clean-body-thread"),
        )

    assert resp.status_code == 403, resp.text
    payload = resp.json()
    assert payload["error"] == "workload_quarantined"
    assert payload["thread_id"] == "quarantined-hdr-thread"
    env["publish_infra"].assert_not_awaited()
    env["emit_proxy"].assert_awaited_once()


@pytest.mark.asyncio
async def test_header_thread_id_cannot_shadow_quarantined_body_thread_id() -> None:
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    await dispatch_quarantine(
        _make_directive(thread_id="quarantined-body-thread"),
        redis_client=redis,
    )

    async with _proxy_harness(
        redis_client=redis, posture=DeploymentPosture.PRODUCTION
    ) as env:
        resp = await env["client"].post(
            "/v1/chat/completions",
            headers={"x-cage-thread-id": "clean-hdr-thread"},
            json=_chat_body(thread_id="quarantined-body-thread"),
        )

    assert resp.status_code == 403, resp.text
    payload = resp.json()
    assert payload["error"] == "workload_quarantined"
    assert payload["thread_id"] == "quarantined-body-thread"
    env["publish_infra"].assert_not_awaited()
    env["emit_proxy"].assert_awaited_once()


@pytest.mark.asyncio
async def test_confirmed_quarantine_fails_closed_503_when_evidence_chain_unavailable() -> (
    None
):
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    await dispatch_quarantine(
        _make_directive(thread_id="quarantined-ev-down"),
        redis_client=redis,
    )

    async with _proxy_harness(
        redis_client=redis,
        posture=DeploymentPosture.PRODUCTION,
        emit_proxy_side_effect=EvidenceChainUnavailableError("evidence sink stopped"),
    ) as env:
        resp = await env["client"].post(
            "/v1/chat/completions",
            headers={"x-cage-thread-id": "quarantined-ev-down"},
            json=_chat_body(),
        )

    assert resp.status_code == 503, resp.text
    assert resp.json()["error"] == "evidence_chain_unavailable"


@pytest.mark.asyncio
async def test_duplicate_thread_id_headers_cannot_shadow_quarantined_thread() -> None:
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    await dispatch_quarantine(
        _make_directive(thread_id="quarantined-second-hdr"),
        redis_client=redis,
    )

    async with _proxy_harness(
        redis_client=redis, posture=DeploymentPosture.PRODUCTION
    ) as env:
        resp = await env["client"].post(
            "/v1/chat/completions",
            headers=[
                ("x-cage-thread-id", "clean-first-hdr"),
                ("x-cage-thread-id", "quarantined-second-hdr"),
            ],
            json=_chat_body(),
        )

    assert resp.status_code == 403, resp.text
    payload = resp.json()
    assert payload["error"] == "workload_quarantined"
    assert payload["thread_id"] == "quarantined-second-hdr"
    env["publish_infra"].assert_not_awaited()
    env["emit_proxy"].assert_awaited_once()

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

"""Hermetic tests for the Provider 06 sidecar probe client.

These pin CAGE's side of the probe contract (``/health/ready`` and
``/health/live``, fail closed). They are not partner conformance tests: the
over-the-wire mandate applies once the upstream sidecar runtime exists.
"""

import httpx
import pytest

from src.integrations.provider_06.lifecycle import (
    LIVE_PATH,
    READY_PATH,
    SidecarHealthCheck,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

BASE = "http://sidecar.test"


def _client(handler) -> SidecarHealthCheck:
    return SidecarHealthCheck(BASE, timeout=1.0, transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_probes_hit_upstream_contract_paths() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(200)

    probe = _client(handler)
    assert await probe.is_ready() is True
    assert await probe.is_live() is True
    assert seen == [READY_PATH, LIVE_PATH] == ["/health/ready", "/health/live"]


@pytest.mark.asyncio
async def test_not_ready_does_not_fall_back_to_legacy_paths() -> None:
    """A 503 on /health/ready is final; /health or /status must not be tried."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(503 if request.url.path == READY_PATH else 200)

    assert await _client(handler).is_ready() is False
    assert seen == [READY_PATH]


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [204, 301, 404, 500, 503])
async def test_non_200_is_not_ready(status: int) -> None:
    assert await _client(lambda _r: httpx.Response(status)).is_ready() is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exc",
    [
        httpx.ConnectError("refused"),
        httpx.ReadTimeout("slow"),
        httpx.RemoteProtocolError("garbled"),
    ],
)
async def test_transport_failures_fail_closed(exc: Exception) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise exc

    probe = _client(handler)
    assert await probe.is_ready() is False
    assert await probe.is_live() is False

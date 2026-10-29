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

"""``CAGE_NEMO_ENABLED=false`` holds on every path, not only at startup.

Before this change two runtime paths could build NeMo rails that startup had
left off. The inference proxy built them on first call because
``app.state.nemo_rails`` was ``None``. The Redis reload subscriber (and the
refinement-approval endpoint) rebuilt them on every broadcast. Each test here
observes one of those paths refusing.

Also covered:

- The three opt-in switches (NeMo, consensus critics, finance causal tier)
  share one parser, so an ambiguous value such as ``yes`` raises on every
  switch instead of raising on one and silently enabling another.
- ``verify_content_safety`` reports "off by configuration"
  (``CONTENT_SAFETY_RAILS_DISABLED``) apart from "enabled but not
  initialised" (``CONTENT_SAFETY_RAILS_UNAVAILABLE``).
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable
from unittest.mock import MagicMock

import fakeredis.aioredis
import httpx
import pytest
from fastapi import FastAPI

from src.cage_finance import is_causal_tier_enabled
from src.gateway.governance import semantic_rail_factory as factory
from src.gateway.governance.content_safety import (
    CONTENT_SAFETY_NO_INFERENCE_BACKEND,
    CONTENT_SAFETY_RAILS_DISABLED,
    CONTENT_SAFETY_RAILS_UNAVAILABLE,
)
from src.gateway.governance.feature_flags import (
    consensus_critics_enabled,
    nemo_rails_enabled,
)
from src.gateway.governance.inference_backend import ENV_VAR as BACKEND_ENV
from src.gateway.governance.langgraph_harness import nemo_node_factory
from src.gateway.governance.semantic_rail_factory import (
    SemanticRailsDisabled,
    semantic_rails_refusal,
)
from src.gateway.governance.telemetry_provider import ConfigurationError

pytestmark = [pytest.mark.unit, pytest.mark.local]

_PROPOSER = (
    "cage-advisor-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"
)
_APPROVER = (
    "compliance-bridge.governance-stack.serviceaccount.identity.linkerd.cluster.local"
)


@pytest.fixture
def rails_off(monkeypatch: pytest.MonkeyPatch) -> None:
    """A model backend exists, but the semantic rails are switched off."""
    monkeypatch.setenv(BACKEND_ENV, "vllm")
    monkeypatch.setenv("CAGE_NEMO_ENABLED", "false")


@pytest.fixture
def rails_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(BACKEND_ENV, "vllm")
    monkeypatch.setenv("CAGE_NEMO_ENABLED", "true")


# ---------------------------------------------------------------------------
# One vocabulary for every opt-in safety switch
# ---------------------------------------------------------------------------

_SWITCHES: list[tuple[str, Callable[[], bool]]] = [
    ("CAGE_NEMO_ENABLED", nemo_rails_enabled),
    ("CAGE_CONSENSUS_CRITICS_ENABLED", consensus_critics_enabled),
    ("CAGE_CAUSAL_TIER_ENABLED", is_causal_tier_enabled),
]
_SWITCH_IDS = ["nemo", "critics", "causal"]


@pytest.mark.parametrize(("name", "read"), _SWITCHES, ids=_SWITCH_IDS)
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("true", True),
        ("TRUE", True),
        (" 1 ", True),
        ("false", False),
        ("False", False),
        ("0", False),
        ("", False),
    ],
)
def test_every_switch_accepts_the_same_values(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    read: Callable[[], bool],
    value: str,
    expected: bool,
) -> None:
    monkeypatch.setenv(name, value)
    assert read() is expected


@pytest.mark.parametrize(("name", "read"), _SWITCHES, ids=_SWITCH_IDS)
def test_every_switch_is_off_when_unset(
    monkeypatch: pytest.MonkeyPatch, name: str, read: Callable[[], bool]
) -> None:
    monkeypatch.delenv(name, raising=False)
    assert read() is False


@pytest.mark.parametrize(("name", "read"), _SWITCHES, ids=_SWITCH_IDS)
@pytest.mark.parametrize("value", ["yes", "no", "on", "off", "enabled", "2"])
def test_every_switch_rejects_an_ambiguous_value(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    read: Callable[[], bool],
    value: str,
) -> None:
    """``yes`` once raised for NeMo but enabled critics and the causal tier."""
    monkeypatch.setenv(name, value)
    with pytest.raises(ConfigurationError, match=f"Invalid {name}"):
        read()


# ---------------------------------------------------------------------------
# One predicate decides whether rails may be built
# ---------------------------------------------------------------------------


def test_refusal_names_the_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(BACKEND_ENV, "none")
    monkeypatch.setenv("CAGE_NEMO_ENABLED", "true")
    assert semantic_rails_refusal()[0] == CONTENT_SAFETY_NO_INFERENCE_BACKEND  # type: ignore[index]

    monkeypatch.setenv(BACKEND_ENV, "vllm")
    monkeypatch.setenv("CAGE_NEMO_ENABLED", "false")
    assert semantic_rails_refusal()[0] == CONTENT_SAFETY_RAILS_DISABLED  # type: ignore[index]

    monkeypatch.setenv("CAGE_NEMO_ENABLED", "true")
    assert semantic_rails_refusal() is None


@pytest.mark.usefixtures("rails_off")
@pytest.mark.parametrize(
    "build", ["initialize_semantic_rails", "create_semantic_rail_manager"]
)
def test_factory_builds_no_rails_when_off(
    monkeypatch: pytest.MonkeyPatch, build: str
) -> None:
    import src.integrations.nemo.manager as nemo_manager

    layer3_init = MagicMock(name="initialize_rails")
    layer3_create = MagicMock(name="create_nemo_manager")
    monkeypatch.setattr(nemo_manager, "initialize_rails", layer3_init)
    monkeypatch.setattr(nemo_manager, "create_nemo_manager", layer3_create)

    with pytest.raises(SemanticRailsDisabled) as err:
        getattr(factory, build)()

    assert err.value.reason_code == CONTENT_SAFETY_RAILS_DISABLED
    assert str(err.value).startswith(CONTENT_SAFETY_RAILS_DISABLED)
    layer3_init.assert_not_called()
    layer3_create.assert_not_called()


@pytest.mark.usefixtures("rails_off")
def test_cached_rails_are_not_handed_out_when_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(nemo_node_factory, "_nemo_rails", MagicMock(name="cached"))
    with pytest.raises(SemanticRailsDisabled):
        nemo_node_factory.get_nemo_rails()


@pytest.mark.usefixtures("rails_off")
@pytest.mark.asyncio
async def test_singleton_reload_refuses_and_keeps_the_old_instance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cached = MagicMock(name="cached")
    rebuild = MagicMock(name="create_nemo_manager")
    monkeypatch.setattr(nemo_node_factory, "_nemo_rails", cached)
    monkeypatch.setattr(nemo_node_factory, "create_nemo_manager", rebuild)

    with pytest.raises(SemanticRailsDisabled):
        await nemo_node_factory.reload_nemo_rails()

    rebuild.assert_not_called()
    assert nemo_node_factory._nemo_rails is cached


# ---------------------------------------------------------------------------
# Hot reload: a broadcast cannot switch the rails back on
# ---------------------------------------------------------------------------


@pytest.fixture
def gateway(monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    """The hybrid gateway module with every sub-app's rails cleared."""
    import src.gateway.server.hybrid_server as gw_srv

    for sub_app in (gw_srv.inference_app, gw_srv.mcp_app):
        monkeypatch.setattr(sub_app.state, "nemo_rails", None, raising=False)
    return gw_srv


def _rails_on_every_app(gw_srv, app: FastAPI) -> list[object]:  # type: ignore[no-untyped-def]
    return [
        getattr(app.state, "nemo_rails", None),
        getattr(gw_srv.inference_app.state, "nemo_rails", None),
        getattr(gw_srv.mcp_app.state, "nemo_rails", None),
    ]


@pytest.mark.usefixtures("rails_off")
def test_reload_subscriber_is_not_started_when_off(gateway) -> None:  # type: ignore[no-untyped-def]
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    assert gateway._start_nemo_reload_subscriber(redis, FastAPI()) is None


@pytest.mark.usefixtures("rails_on")
@pytest.mark.asyncio
async def test_reload_subscriber_is_started_when_on(gateway) -> None:  # type: ignore[no-untyped-def]
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    task = gateway._start_nemo_reload_subscriber(redis, FastAPI())
    assert task is not None
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


@pytest.mark.usefixtures("rails_off")
@pytest.mark.asyncio
async def test_reload_broadcast_does_not_switch_rails_back_on(
    gateway,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The bypass itself: a ``cage:nemo:reload`` message while the rails are off."""
    rebuild = MagicMock(name="create_nemo_manager", return_value=MagicMock())
    monkeypatch.setattr(nemo_node_factory, "create_nemo_manager", rebuild)
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    app = FastAPI()
    app.state.nemo_rails = None

    subscriber = asyncio.create_task(gateway._subscribe_nemo_reload(redis, app))
    await asyncio.sleep(0.05)
    await redis.publish(gateway.NEMO_RELOAD_CHANNEL, '{"proposal_id": "p-1"}')
    await asyncio.sleep(0.1)
    subscriber.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await subscriber

    rebuild.assert_not_called()
    assert _rails_on_every_app(gateway, app) == [None, None, None]


@pytest.mark.usefixtures("rails_off")
@pytest.mark.asyncio
async def test_approving_a_refinement_while_off_is_refused_and_left_staged(
    gateway,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.gateway.server.workload_identity import (
        WorkloadIdentityMiddleware,
        load_identity_policy,
    )

    monkeypatch.setenv("CAGE_TRUSTED_CLIENT_IDENTITIES", f"{_PROPOSER},{_APPROVER}")
    rebuild = MagicMock(name="create_nemo_manager", return_value=MagicMock())
    monkeypatch.setattr(nemo_node_factory, "create_nemo_manager", rebuild)

    replica = FastAPI()
    replica.add_middleware(WorkloadIdentityMiddleware, policy=load_identity_policy())
    for route in gateway.root_app.router.routes:
        if getattr(route, "path", "").startswith("/v1/nemo/"):
            replica.router.routes.append(route)
    replica.state.redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    replica.state.nemo_rails = None

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=replica), base_url="http://replica"
    ) as client:
        staged = await client.post(
            "/v1/nemo/propose-refinement",
            json={"control_id": "AU-6", "verdict": "FAIL: drift", "source": "bridge"},
            headers={"l5d-client-id": _PROPOSER},
        )
        assert staged.status_code == 200
        proposal_id = staged.json()["proposal_id"]

        approved = await client.post(
            f"/v1/nemo/approve-refinement/{proposal_id}",
            json={"approved": True, "reviewer": "risk@example.com", "rationale": "ok"},
            headers={"l5d-client-id": _APPROVER},
        )
        pending = await client.get(
            "/v1/nemo/proposals/pending", headers={"l5d-client-id": _APPROVER}
        )

    assert approved.status_code == 409
    assert approved.json()["detail"]["reason_code"] == CONTENT_SAFETY_RAILS_DISABLED
    assert proposal_id in [p["proposal_id"] for p in pending.json()["pending"]]
    rebuild.assert_not_called()
    assert _rails_on_every_app(gateway, replica) == [None, None, None]


# ---------------------------------------------------------------------------
# verify_content_safety: "off by configuration" is its own fact
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("rails_off")
@pytest.mark.asyncio
async def test_content_safety_reports_disabled_even_with_stale_rails_on_app_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rails left on app.state are not used while the switch is off."""
    import src.gateway.server.mcp_tool_server as mod

    monkeypatch.setattr(mod.app.state, "nemo_rails", MagicMock(), raising=False)
    verdict = await mod.verify_content_safety("hello")
    assert verdict.startswith(f"BLOCKED: {CONTENT_SAFETY_RAILS_DISABLED}")


@pytest.mark.usefixtures("rails_on")
@pytest.mark.asyncio
async def test_content_safety_reports_unavailable_when_on_but_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import src.gateway.server.mcp_tool_server as mod

    monkeypatch.setattr(mod.app.state, "nemo_rails", None, raising=False)
    verdict = await mod.verify_content_safety("hello")
    assert verdict.startswith(f"BLOCKED: {CONTENT_SAFETY_RAILS_UNAVAILABLE}")

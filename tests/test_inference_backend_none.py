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

"""The gateway starts and refuses cleanly with no model (``CAGE_INFERENCE_BACKEND``).

Under ``none`` startup needs no ``VLLM_*`` settings and builds no NeMo rails,
and every model-dependent path refuses with its own reason code. Unset keeps
the behaviour from before the setting existed (a backend is required), and an
unknown value fails startup.
"""

from __future__ import annotations

import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.gateway.governance.content_safety import CONTENT_SAFETY_NO_INFERENCE_BACKEND
from src.gateway.governance.inference_backend import (
    ENV_VAR,
    InferenceBackend,
    InferenceBackendConfigError,
    InferenceBackendUnavailable,
    inference_disabled,
    require_backend_settings,
    resolve_inference_backend,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture
def backend_none(monkeypatch):
    monkeypatch.setenv(ENV_VAR, "none")
    monkeypatch.delenv("VLLM_BASE_URL", raising=False)
    monkeypatch.delenv("VLLM_API_KEY", raising=False)


# ---------------------------------------------------------------------------
# Selector
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("none", InferenceBackend.NONE),
        ("external", InferenceBackend.EXTERNAL),
        ("vllm", InferenceBackend.VLLM),
        (" VLLM ", InferenceBackend.VLLM),
        ("", None),
    ],
)
def test_selector_values(raw: str, expected: InferenceBackend | None) -> None:
    assert resolve_inference_backend({ENV_VAR: raw}) is expected


def test_unset_selector_is_not_none() -> None:
    """``none`` is explicit, never inferred from a missing setting or URL."""
    assert resolve_inference_backend({}) is None
    assert inference_disabled({}) is False


def test_unknown_selector_value_is_a_config_error() -> None:
    with pytest.raises(InferenceBackendConfigError, match="gpu"):
        resolve_inference_backend({ENV_VAR: "gpu"})


def test_required_backend_settings() -> None:
    with pytest.raises(InferenceBackendConfigError, match="VLLM_BASE_URL"):
        require_backend_settings({"VLLM_API_KEY": "k"}.get)
    with pytest.raises(InferenceBackendConfigError, match="VLLM_API_KEY"):
        require_backend_settings({"VLLM_BASE_URL": "http://m/v1"}.get)
    require_backend_settings({"VLLM_BASE_URL": "http://m/v1", "VLLM_API_KEY": "k"}.get)


# ---------------------------------------------------------------------------
# MCP tool server startup
# ---------------------------------------------------------------------------


def _mcp_lifespan_patches(mod, init_rails: MagicMock, config_get=None):
    governor = MagicMock()
    governor.components.opa.close = AsyncMock()
    patches = [
        patch.object(mod, "setup_tracing", MagicMock()),
        patch.object(mod, "load_and_validate_thresholds", MagicMock()),
        patch.object(mod, "_activate_domain", AsyncMock(return_value=governor)),
        patch.object(
            mod, "build_rate_limit_redis_from_env", MagicMock(return_value=None)
        ),
        patch.object(mod, "mcp", MagicMock(session_manager=None)),
        patch(
            "src.gateway.governance.semantic_rail_factory.initialize_semantic_rails",
            init_rails,
        ),
    ]
    if config_get is not None:
        patches.append(patch.object(mod, "config_manager", MagicMock(get=config_get)))
    return patches


async def _run_mcp_lifespan(mod, patches) -> None:
    from contextlib import ExitStack

    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        async with mod.lifespan(mod.app):
            pass


@pytest.mark.asyncio
async def test_mcp_startup_under_none_needs_no_model_and_builds_no_rails(
    backend_none,
) -> None:
    import src.gateway.server.mcp_tool_server as mod

    init_rails = MagicMock(return_value=MagicMock())
    no_settings = MagicMock(return_value=None)
    await _run_mcp_lifespan(mod, _mcp_lifespan_patches(mod, init_rails, no_settings))

    assert mod.app.state.nemo_rails is None
    init_rails.assert_not_called()
    no_settings.assert_not_called()


@pytest.mark.asyncio
async def test_mcp_startup_fails_on_unknown_backend(monkeypatch) -> None:
    import src.gateway.server.mcp_tool_server as mod

    monkeypatch.setenv(ENV_VAR, "gpu")
    init_rails = MagicMock()
    with pytest.raises(InferenceBackendConfigError):
        await _run_mcp_lifespan(mod, _mcp_lifespan_patches(mod, init_rails))
    init_rails.assert_not_called()


@pytest.mark.parametrize("backend", ["vllm", "external", None])
@pytest.mark.asyncio
async def test_mcp_startup_requires_a_url_unless_none(monkeypatch, backend) -> None:
    import src.gateway.server.mcp_tool_server as mod

    if backend is None:
        monkeypatch.delenv(ENV_VAR, raising=False)
    else:
        monkeypatch.setenv(ENV_VAR, backend)
    init_rails = MagicMock()
    with pytest.raises(RuntimeError, match="VLLM_BASE_URL must be set"):
        await _run_mcp_lifespan(
            mod, _mcp_lifespan_patches(mod, init_rails, MagicMock(return_value=None))
        )
    init_rails.assert_not_called()


# ---------------------------------------------------------------------------
# Hybrid gateway startup
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gateway_startup_under_none_builds_no_rails(
    backend_none, monkeypatch
) -> None:
    from tests.test_hybrid_server import _make_hybrid_stubs

    monkeypatch.setenv("CAGE_ENV", "ci")
    monkeypatch.setenv("RECONCILIATION_PROVIDER", "stub")
    monkeypatch.setenv("CAGE_NORMATIVE_PROVIDER", "static")
    init_rails = MagicMock(return_value=MagicMock())

    sys.modules.pop("src.gateway.server.hybrid_server", None)
    with (
        patch.dict("sys.modules", _make_hybrid_stubs()),
        patch(
            "src.gateway.governance.semantic_rail_factory.initialize_semantic_rails",
            init_rails,
        ),
    ):
        from src.gateway.server.hybrid_server import _gateway_lifespan

        app_mock = MagicMock()
        async with _gateway_lifespan(app_mock):
            assert app_mock.state.nemo_rails is None

    init_rails.assert_not_called()


# ---------------------------------------------------------------------------
# NeMo is off under none, never on and partial
# ---------------------------------------------------------------------------


def test_rail_factory_builds_no_rails_under_none(backend_none) -> None:
    from src.gateway.governance import semantic_rail_factory as factory

    for build in (
        factory.initialize_semantic_rails,
        factory.create_semantic_rail_manager,
    ):
        with pytest.raises(InferenceBackendUnavailable) as err:
            build()
        assert err.value.reason_code == CONTENT_SAFETY_NO_INFERENCE_BACKEND


@pytest.mark.asyncio
async def test_verify_content_safety_under_none_is_blocked(backend_none) -> None:
    import src.gateway.server.mcp_tool_server as mod

    saved = getattr(mod.app.state, "nemo_rails", None)
    try:
        for rails in (None, MagicMock()):
            mod.app.state.nemo_rails = rails
            verdict = await mod.verify_content_safety("hello")
            assert verdict.startswith(f"BLOCKED: {CONTENT_SAFETY_NO_INFERENCE_BACKEND}")
    finally:
        mod.app.state.nemo_rails = saved


@pytest.mark.asyncio
async def test_harness_input_rail_blocks_under_none(
    backend_none, monkeypatch: pytest.MonkeyPatch
) -> None:
    from src.gateway.governance.langgraph_harness import nemo_node_factory

    monkeypatch.setenv("CAGE_NEMO_ENABLED", "true")
    with patch.object(nemo_node_factory, "_ensure_presidio_engines", lambda: None):
        node = nemo_node_factory.create_nemo_guardrail_node()
    with (
        patch.object(nemo_node_factory, "_nemo_rails", None),
        patch.object(nemo_node_factory, "_redact_pii", lambda text: (text, [])),
    ):
        update = await node({"messages": [{"role": "user", "content": "hello"}]})

    assert update["guardrail_blocked"] is True
    assert CONTENT_SAFETY_NO_INFERENCE_BACKEND in update["guardrail_reason"]

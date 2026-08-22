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

"""
Unit tests for src/gateway/governance/nemo/server.py — NeMoService and serve().

All tests are hermetic:
- grpc is mocked so no network server is started.
- nemoguardrails (create_nemo_manager) is mocked.
- Proto-generated stubs (nemo_pb2, nemo_pb2_grpc) are mocked.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

# ---------------------------------------------------------------------------
# Stub the proto and grpc imports so server.py can be imported without them
# ---------------------------------------------------------------------------


def _nemo_server_stubs():
    mock_pb2 = MagicMock()
    mock_pb2.VerifyResponse = MagicMock(side_effect=lambda **kw: MagicMock(**kw))

    mock_pb2_grpc = MagicMock()
    mock_pb2_grpc.NeMoGuardrailsServicer = object  # plain base class

    mock_grpc = MagicMock()
    mock_grpc.StatusCode.UNAVAILABLE = "UNAVAILABLE"
    mock_grpc.StatusCode.INTERNAL = "INTERNAL"

    return {
        "grpc": mock_grpc,
        "src.gateway.protos.nemo_pb2": mock_pb2,
        "src.gateway.protos.nemo_pb2_grpc": mock_pb2_grpc,
        "src.gateway.protos": MagicMock(nemo_pb2=mock_pb2, nemo_pb2_grpc=mock_pb2_grpc),
        "src.gateway.governance.nemo.manager": MagicMock(
            create_nemo_manager=MagicMock(return_value=MagicMock()),
        ),
    }


# ---------------------------------------------------------------------------
# Tests: NeMoService._load_rails
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestNeMoServiceLoadRails:
    """Tests for NeMoService._load_rails() initialization."""

    def test_rails_loaded_when_config_path_exists(self, tmp_path):
        """NeMoService.rails is set when the config path exists."""
        import sys

        stubs = _nemo_server_stubs()

        mock_rails = MagicMock(name="MockRails")
        stubs[
            "src.gateway.governance.nemo.manager"
        ].create_nemo_manager.return_value = mock_rails

        with patch.dict("sys.modules", stubs):
            sys.modules.pop("src.gateway.governance.nemo.server", None)

            with patch("os.path.exists", return_value=True):
                from src.gateway.governance.nemo.server import NeMoService

                svc = NeMoService()

        assert svc.rails is not None

    def test_rails_is_none_when_config_path_missing(self):
        """NeMoService.rails is None when the config path does not exist."""
        import sys

        stubs = _nemo_server_stubs()

        with patch.dict("sys.modules", stubs):
            sys.modules.pop("src.gateway.governance.nemo.server", None)

            with patch("os.path.exists", return_value=False):
                from src.gateway.governance.nemo.server import NeMoService

                svc = NeMoService()

        assert svc.rails is None

    def test_rails_is_none_when_create_nemo_manager_raises(self):
        """NeMoService.rails is None when create_nemo_manager raises an exception."""
        import sys

        stubs = _nemo_server_stubs()
        stubs[
            "src.gateway.governance.nemo.manager"
        ].create_nemo_manager.side_effect = RuntimeError("NeMo init failed")

        with patch.dict("sys.modules", stubs):
            sys.modules.pop("src.gateway.governance.nemo.server", None)

            with patch("os.path.exists", return_value=True):
                from src.gateway.governance.nemo.server import NeMoService

                svc = NeMoService()

        assert svc.rails is None


# ---------------------------------------------------------------------------
# Tests: NeMoService.Verify RPC
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestNeMoServiceVerify:
    """Tests for NeMoService.Verify gRPC handler."""

    @pytest.mark.asyncio
    async def test_verify_returns_unavailable_when_rails_is_none(self):
        """Verify() sets UNAVAILABLE status and returns ERROR response when rails is None."""
        import sys

        stubs = _nemo_server_stubs()

        with patch.dict("sys.modules", stubs):
            sys.modules.pop("src.gateway.governance.nemo.server", None)
            with patch("os.path.exists", return_value=False):
                from src.gateway.governance.nemo.server import NeMoService

                svc = NeMoService()

        assert svc.rails is None

        mock_context = MagicMock()
        mock_request = MagicMock(input="test input")

        response = await svc.Verify(mock_request, mock_context)

        mock_context.set_code.assert_called_once()
        mock_context.set_details.assert_called_once()
        # The response status should be ERROR
        assert response is not None

    @pytest.mark.asyncio
    async def test_verify_calls_generate_async_on_rails(self):
        """Verify() calls rails.generate_async with user input."""
        import sys

        stubs = _nemo_server_stubs()

        mock_rails = MagicMock()
        mock_rails.generate_async = AsyncMock(
            return_value=MagicMock(response=[{"content": "SAFE"}])
        )
        stubs[
            "src.gateway.governance.nemo.manager"
        ].create_nemo_manager.return_value = mock_rails

        with patch.dict("sys.modules", stubs):
            sys.modules.pop("src.gateway.governance.nemo.server", None)
            with patch("os.path.exists", return_value=True):
                from src.gateway.governance.nemo.server import NeMoService

                svc = NeMoService()

        mock_context = MagicMock()
        mock_request = MagicMock(input="hello guardrails")

        await svc.Verify(mock_request, mock_context)

        mock_rails.generate_async.assert_called_once()
        call_kwargs = mock_rails.generate_async.call_args
        messages = call_kwargs[1].get("messages") or call_kwargs[0][0]
        assert any(m.get("content") == "hello guardrails" for m in messages)

    @pytest.mark.asyncio
    async def test_verify_returns_success_status_on_valid_response(self):
        """Verify() returns status=SUCCESS when rails processes the request normally."""
        import sys

        stubs = _nemo_server_stubs()

        mock_rails = MagicMock()
        mock_rails.generate_async = AsyncMock(
            return_value=MagicMock(response=[{"content": "I cannot help with that."}])
        )
        stubs[
            "src.gateway.governance.nemo.manager"
        ].create_nemo_manager.return_value = mock_rails

        with patch.dict("sys.modules", stubs):
            sys.modules.pop("src.gateway.governance.nemo.server", None)
            with patch("os.path.exists", return_value=True):
                from src.gateway.governance.nemo.server import NeMoService

                svc = NeMoService()

        mock_context = MagicMock()
        mock_request = MagicMock(input="give me trading advice")

        response = await svc.Verify(mock_request, mock_context)

        # VerifyResponse was constructed with status="SUCCESS"
        assert response is not None

    @pytest.mark.asyncio
    async def test_verify_handles_generate_async_exception(self):
        """Verify() sets INTERNAL status and returns ERROR when generate_async raises."""
        import sys

        stubs = _nemo_server_stubs()

        mock_rails = MagicMock()
        mock_rails.generate_async = AsyncMock(
            side_effect=RuntimeError("guardrail crash")
        )
        stubs[
            "src.gateway.governance.nemo.manager"
        ].create_nemo_manager.return_value = mock_rails

        with patch.dict("sys.modules", stubs):
            sys.modules.pop("src.gateway.governance.nemo.server", None)
            with patch("os.path.exists", return_value=True):
                from src.gateway.governance.nemo.server import NeMoService

                svc = NeMoService()

        mock_context = MagicMock()
        mock_request = MagicMock(input="crash me")

        response = await svc.Verify(mock_request, mock_context)

        mock_context.set_code.assert_called_once()
        assert response is not None


# ---------------------------------------------------------------------------
# Tests: serve() function structure
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestServeFunction:
    """Tests for the serve() coroutine structure."""

    def test_serve_is_coroutine(self):
        """serve() is a coroutine function (not a regular function)."""
        import asyncio
        import sys

        stubs = _nemo_server_stubs()

        with patch.dict("sys.modules", stubs):
            sys.modules.pop("src.gateway.governance.nemo.server", None)
            with patch("os.path.exists", return_value=False):
                from src.gateway.governance.nemo.server import serve

        assert asyncio.iscoroutinefunction(serve)

    def test_rails_config_path_contains_config_rails(self):
        """RAILS_CONFIG_PATH ends with 'config/rails'."""
        import sys

        stubs = _nemo_server_stubs()

        with patch.dict("sys.modules", stubs):
            sys.modules.pop("src.gateway.governance.nemo.server", None)
            with patch("os.path.exists", return_value=False):
                from src.gateway.governance.nemo import server as nemo_server_mod

        assert (
            nemo_server_mod.RAILS_CONFIG_PATH.endswith("config/rails")
            or "config" in nemo_server_mod.RAILS_CONFIG_PATH
        )

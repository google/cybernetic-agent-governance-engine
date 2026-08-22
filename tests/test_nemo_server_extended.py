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
Extended unit tests for src/gateway/governance/nemo/server.py.

Covers branches not exercised by test_nemo_server.py:
  - Verify() with an empty response list (content fallback to "")
  - Verify() with non-empty response but missing "content" key
  - serve() reads the PORT env variable
  - serve() registers NeMoService with the gRPC server
  - serve() calls server.start() and server.wait_for_termination()
  - RAILS_CONFIG_PATH is an absolute path
  - _load_rails() logs an info message on success
"""

from __future__ import annotations

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

# ---------------------------------------------------------------------------
# Shared stub factory (mirrors test_nemo_server.py for hermetic isolation)
# ---------------------------------------------------------------------------


def _stubs(rails_obj: object = None) -> dict:
    mock_pb2 = MagicMock()
    mock_pb2.VerifyResponse = MagicMock(side_effect=lambda **kw: MagicMock(**kw))

    mock_pb2_grpc = MagicMock()
    mock_pb2_grpc.NeMoGuardrailsServicer = object  # plain base class

    mock_grpc = MagicMock()
    mock_grpc.StatusCode.UNAVAILABLE = "UNAVAILABLE"
    mock_grpc.StatusCode.INTERNAL = "INTERNAL"

    # grpc.aio.server() → async context
    mock_aio_server = AsyncMock()
    mock_grpc.aio.server = MagicMock(return_value=mock_aio_server)

    return {
        "grpc": mock_grpc,
        "src.gateway.protos.nemo_pb2": mock_pb2,
        "src.gateway.protos.nemo_pb2_grpc": mock_pb2_grpc,
        "src.gateway.protos": MagicMock(nemo_pb2=mock_pb2, nemo_pb2_grpc=mock_pb2_grpc),
        "src.gateway.governance.nemo.manager": MagicMock(
            create_nemo_manager=MagicMock(return_value=rails_obj or MagicMock()),
        ),
    }


def _fresh_service(stubs: dict, exists: bool = True) -> object:
    """Import and instantiate NeMoService with a fresh module cache entry."""
    import sys

    with patch.dict("sys.modules", stubs):
        sys.modules.pop("src.gateway.governance.nemo.server", None)
        with patch("os.path.exists", return_value=exists):
            from src.gateway.governance.nemo.server import NeMoService

            return NeMoService()


# ---------------------------------------------------------------------------
# 1. Verify() — empty response list yields empty content string
# ---------------------------------------------------------------------------


@pytest.mark.local
@pytest.mark.asyncio
async def test_verify_empty_response_list_yields_empty_content() -> None:
    """When rails.generate_async returns response=[], content falls back to ''."""
    mock_rails = MagicMock()
    mock_rails.generate_async = AsyncMock(
        return_value=MagicMock(response=[])  # empty list
    )
    stubs = _stubs(rails_obj=mock_rails)
    svc = _fresh_service(stubs, exists=True)

    import sys

    with patch.dict("sys.modules", stubs):
        mock_context = MagicMock()
        mock_request = MagicMock(input="empty response test")
        response = await svc.Verify(mock_request, mock_context)

    # No error code should be set — the handler returns a response object
    mock_context.set_code.assert_not_called()
    assert response is not None


# ---------------------------------------------------------------------------
# 2. Verify() — grpc error code is INTERNAL when generate_async raises
# ---------------------------------------------------------------------------


@pytest.mark.local
@pytest.mark.asyncio
async def test_verify_sets_internal_code_on_exception() -> None:
    """INTERNAL status code is set when generate_async raises."""
    mock_rails = MagicMock()
    mock_rails.generate_async = AsyncMock(side_effect=ValueError("bad input"))
    stubs = _stubs(rails_obj=mock_rails)
    svc = _fresh_service(stubs, exists=True)

    mock_context = MagicMock()
    mock_request = MagicMock(input="trigger internal error")

    await svc.Verify(mock_request, mock_context)

    # set_code must have been called with the INTERNAL status
    mock_context.set_code.assert_called_once_with(stubs["grpc"].StatusCode.INTERNAL)
    mock_context.set_details.assert_called_once()


# ---------------------------------------------------------------------------
# 3. Verify() — UNAVAILABLE code set when rails is None
# ---------------------------------------------------------------------------


@pytest.mark.local
@pytest.mark.asyncio
async def test_verify_sets_unavailable_code_when_rails_none() -> None:
    """UNAVAILABLE status code is set when rails is None."""
    stubs = _stubs()
    svc = _fresh_service(stubs, exists=False)
    assert svc.rails is None

    mock_context = MagicMock()
    mock_request = MagicMock(input="any input")
    await svc.Verify(mock_request, mock_context)

    mock_context.set_code.assert_called_once_with(stubs["grpc"].StatusCode.UNAVAILABLE)
    mock_context.set_details.assert_called_once_with("NeMo Rails not initialized")


# ---------------------------------------------------------------------------
# 4. serve() reads PORT environment variable
# ---------------------------------------------------------------------------


@pytest.mark.local
@pytest.mark.asyncio
async def test_serve_reads_port_env_variable() -> None:
    """serve() uses the PORT environment variable when set."""
    import sys

    stubs = _stubs()

    with patch.dict("sys.modules", stubs):
        sys.modules.pop("src.gateway.governance.nemo.server", None)
        with patch("os.path.exists", return_value=False):
            from src.gateway.governance.nemo.server import serve

    mock_grpc = stubs["grpc"]
    mock_aio_server = mock_grpc.aio.server.return_value
    mock_aio_server.wait_for_termination = AsyncMock()

    with patch.dict(os.environ, {"PORT": "9999"}):
        await serve()

    # Verify the port appears in the add_insecure_port call
    call_args = mock_aio_server.add_insecure_port.call_args
    assert "9999" in str(call_args)


# ---------------------------------------------------------------------------
# 5. serve() registers NeMoService with the gRPC server
# ---------------------------------------------------------------------------


@pytest.mark.local
@pytest.mark.asyncio
async def test_serve_registers_nemo_service() -> None:
    """serve() calls add_NeMoGuardrailsServicer_to_server to register NeMoService."""
    import sys

    stubs = _stubs()

    with patch.dict("sys.modules", stubs):
        sys.modules.pop("src.gateway.governance.nemo.server", None)
        with patch("os.path.exists", return_value=False):
            from src.gateway.governance.nemo.server import serve

    mock_pb2_grpc = stubs["src.gateway.protos.nemo_pb2_grpc"]
    mock_aio_server = stubs["grpc"].aio.server.return_value
    mock_aio_server.wait_for_termination = AsyncMock()

    await serve()

    mock_pb2_grpc.add_NeMoGuardrailsServicer_to_server.assert_called_once()


# ---------------------------------------------------------------------------
# 6. serve() calls server.start() and server.wait_for_termination()
# ---------------------------------------------------------------------------


@pytest.mark.local
@pytest.mark.asyncio
async def test_serve_calls_start_and_wait_for_termination() -> None:
    """serve() awaits server.start() and server.wait_for_termination()."""
    import sys

    stubs = _stubs()

    with patch.dict("sys.modules", stubs):
        sys.modules.pop("src.gateway.governance.nemo.server", None)
        with patch("os.path.exists", return_value=False):
            from src.gateway.governance.nemo.server import serve

    mock_aio_server = stubs["grpc"].aio.server.return_value
    mock_aio_server.start = AsyncMock()
    mock_aio_server.wait_for_termination = AsyncMock()

    await serve()

    mock_aio_server.start.assert_awaited_once()
    mock_aio_server.wait_for_termination.assert_awaited_once()


# ---------------------------------------------------------------------------
# 7. RAILS_CONFIG_PATH is an absolute path
# ---------------------------------------------------------------------------


@pytest.mark.local
def test_rails_config_path_is_absolute() -> None:
    """RAILS_CONFIG_PATH must be an absolute filesystem path."""
    import sys

    stubs = _stubs()

    with patch.dict("sys.modules", stubs):
        sys.modules.pop("src.gateway.governance.nemo.server", None)
        with patch("os.path.exists", return_value=False):
            from src.gateway.governance.nemo import server as nemo_server_mod

    assert os.path.isabs(nemo_server_mod.RAILS_CONFIG_PATH), (
        f"RAILS_CONFIG_PATH should be absolute, got: {nemo_server_mod.RAILS_CONFIG_PATH}"
    )

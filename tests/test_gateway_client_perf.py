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

import pytest

pytestmark = pytest.mark.unit
from unittest.mock import AsyncMock, MagicMock, patch

from src.governed_financial_advisor.infrastructure.gateway_client import GatewayClient


@pytest.mark.asyncio
async def test_gateway_client_reuses_http_client():
    # We need to reset the singleton for the test
    GatewayClient._instance = None

    with patch("httpx.AsyncClient") as mock_client_cls:
        # Mock the client instance
        mock_client_instance = AsyncMock()
        mock_client_instance.is_closed = False  # Ensure it looks open
        mock_client_cls.return_value = mock_client_instance

        # Mock the response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "choices": [{"message": {"content": "Test Response"}}]
        }
        mock_client_instance.post.return_value = mock_response

        # Instantiate GatewayClient (Lazy initialization)
        client = GatewayClient()

        # Verify AsyncClient was NOT created yet
        mock_client_cls.assert_not_called()

        # Call chat (triggers initialization)
        await client.chat("Hello")

        # Verify AsyncClient was created once
        mock_client_cls.assert_called_once()

        # Call chat again
        await client.chat("World")

        # Verify AsyncClient was NOT created again
        mock_client_cls.assert_called_once()

        # Verify post was called twice on the SAME instance
        assert mock_client_instance.post.call_count == 2

        # Verify close
        await client.close()
        mock_client_instance.aclose.assert_called_once()

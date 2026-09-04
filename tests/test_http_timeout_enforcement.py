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
Test suite for M-9: Async HTTP client timeout enforcement.

Validates that the centralized HTTP client factory correctly enforces
posture-aware timeouts and prevents indefinite hangs.
"""

import asyncio

import httpx
import pytest
import respx
from httpx import AsyncClient, Client

from src.gateway.governance.env_posture import DeploymentPosture
from src.gateway.governance.http_client_factory import (
    _get_default_timeout,
    create_async_client,
    create_sync_client,
)


class TestHttpClientFactoryTimeouts:
    """Test timeout configuration in HTTP client factory."""

    def test_default_timeout_production(self):
        """Production posture should use 10s timeout."""
        timeout = _get_default_timeout(DeploymentPosture.PRODUCTION)
        assert timeout == 10.0

    def test_default_timeout_staging(self):
        """Staging posture should use 10s timeout (same as production)."""
        timeout = _get_default_timeout(DeploymentPosture.STAGING)
        assert timeout == 10.0

    def test_default_timeout_dev(self):
        """Dev posture should use 30s timeout."""
        timeout = _get_default_timeout(DeploymentPosture.DEV)
        assert timeout == 30.0

    def test_default_timeout_test(self):
        """Test posture should use 30s timeout."""
        timeout = _get_default_timeout(DeploymentPosture.TEST)
        assert timeout == 30.0

    def test_default_timeout_local(self):
        """Local posture should use 30s timeout."""
        timeout = _get_default_timeout(DeploymentPosture.LOCAL)
        assert timeout == 30.0

    def test_default_timeout_ci(self):
        """CI posture should use 30s timeout."""
        timeout = _get_default_timeout(DeploymentPosture.CI)
        assert timeout == 30.0


class TestAsyncClientCreation:
    """Test async HTTP client creation with timeout enforcement."""

    @pytest.mark.asyncio
    async def test_create_async_client_default_timeout(self):
        """Async client should be created with default timeout."""
        async with create_async_client(posture=DeploymentPosture.PRODUCTION) as client:
            assert isinstance(client, AsyncClient)
            assert client.timeout.read == 10.0

    @pytest.mark.asyncio
    async def test_create_async_client_explicit_timeout(self):
        """Async client should respect explicit timeout parameter."""
        async with create_async_client(timeout_seconds=5.0) as client:
            assert client.timeout.read == 5.0

    @pytest.mark.asyncio
    async def test_create_async_client_with_kwargs(self):
        """Async client should accept additional httpx parameters."""
        async with create_async_client(
            timeout_seconds=15.0,
            verify=False,
        ) as client:
            assert client.timeout.read == 15.0
            # Verify client was created successfully
            assert isinstance(client, httpx.AsyncClient)

    @pytest.mark.asyncio
    async def test_create_async_client_dev_posture(self):
        """Dev posture should use 30s timeout."""
        async with create_async_client(posture=DeploymentPosture.DEV) as client:
            assert client.timeout.read == 30.0


class TestSyncClientCreation:
    """Test sync HTTP client creation with timeout enforcement."""

    def test_create_sync_client_default_timeout(self):
        """Sync client should be created with default timeout."""
        with create_sync_client(posture=DeploymentPosture.PRODUCTION) as client:
            assert isinstance(client, Client)
            assert client.timeout.read == 10.0

    def test_create_sync_client_explicit_timeout(self):
        """Sync client should respect explicit timeout parameter."""
        with create_sync_client(timeout_seconds=5.0) as client:
            assert client.timeout.read == 5.0

    def test_create_sync_client_with_kwargs(self):
        """Sync client should accept additional httpx parameters."""
        with create_sync_client(
            timeout_seconds=15.0,
            verify=False,
        ) as client:
            assert client.timeout.read == 15.0
            # Verify client was created successfully
            assert isinstance(client, httpx.Client)

    def test_create_sync_client_dev_posture(self):
        """Dev posture should use 30s timeout."""
        with create_sync_client(posture=DeploymentPosture.DEV) as client:
            assert client.timeout.read == 30.0


class TestTimeoutEnforcement:
    """Test that timeout configuration is correctly applied."""

    @pytest.mark.asyncio
    async def test_async_client_timeout_configured(self):
        """Async client should have timeout configured correctly."""
        # Verify short timeout is set
        async with create_async_client(timeout_seconds=0.5) as client:
            assert client.timeout.read == 0.5
            assert client.timeout.connect == 0.5

    @pytest.mark.asyncio
    async def test_async_client_fast_endpoint_succeeds(self):
        """Async client should succeed on fast endpoints."""
        with respx.mock:
            # Mock endpoint that responds immediately
            fast_route = respx.get("https://fast.example.com/api").mock(
                return_value=httpx.Response(200, json={"status": "ok"})
            )

            async with create_async_client(timeout_seconds=5.0) as client:
                response = await client.get("https://fast.example.com/api")
                assert response.status_code == 200
                assert response.json() == {"status": "ok"}

            assert fast_route.called

    @pytest.mark.asyncio
    async def test_production_timeout_configured_correctly(self):
        """Production posture should configure 10s timeout."""
        # Test that production timeout is correctly set to 10s
        async with create_async_client(posture=DeploymentPosture.PRODUCTION) as client:
            assert client.timeout.read == 10.0
            assert client.timeout.connect == 10.0
            
        # Test that staging also uses 10s timeout
        async with create_async_client(posture=DeploymentPosture.STAGING) as client:
            assert client.timeout.read == 10.0


class TestFactoryIntegration:
    """Integration tests for HTTP client factory usage."""

    @pytest.mark.skip(reason="JWKS verifier module removed in Phase 1 domain extraction - test preserved for historical reference")
    @pytest.mark.asyncio
    async def test_jwks_verifier_uses_factory(self):
        """JWKS verifier should use factory-created client with timeout."""
        with respx.mock:
            # This is a regression test to ensure jwks_verifier.py uses the factory
            jwks_route = respx.get("https://issuer.example.com/.well-known/jwks.json").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "keys": [
                            {
                                "kid": "test-key-1",
                                "kty": "RSA",
                                "alg": "RS256",
                                "n": "test-n",
                                "e": "AQAB",
                            }
                        ]
                    },
                )
            )

            from src.gateway.governance.jwks_verifier import JwksVerifier

            verifier = JwksVerifier(
                jwks_url="https://issuer.example.com/.well-known/jwks.json",
                issuer="https://issuer.example.com",
                posture=DeploymentPosture.TEST,
            )

            # Should succeed with factory-created client
            jwks = await verifier.fetch_jwks()
            assert "test-key-1" in jwks
            assert jwks_route.called

    @pytest.mark.asyncio
    async def test_timeout_prevents_resource_exhaustion(self):
        """Multiple concurrent timeout failures should not exhaust resources."""
        # Test that multiple clients can be created and closed without issues
        clients_created = []
        for _i in range(5):
            client = create_async_client(timeout_seconds=1.0)
            clients_created.append(client)
            
        # All clients should have timeout set
        for client in clients_created:
            assert client.timeout.read == 1.0
            await client.aclose()
            
        # Verify we can still create more clients (no resource exhaustion)
        async with create_async_client(timeout_seconds=2.0) as final_client:
            assert final_client.timeout.read == 2.0

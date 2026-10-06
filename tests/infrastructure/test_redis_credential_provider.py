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

"""Unit tests for Memorystore IAM Credential Provider and Factory Seam (Track 6b)."""

from __future__ import annotations

import os
import time
from unittest.mock import MagicMock, patch

import pytest

from src.gateway.infrastructure.redis_credential_factory import (
    get_redis_credential_provider,
    is_redis_iam_auth_enabled,
)
from src.integrations.gcp.redis_credential_provider import (
    GcpRedisIamCredentialProvider,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestGcpRedisIamCredentialProvider:
    """Tests for Layer 3 GCP IAM Credential Provider."""

    def test_explicit_token_override(self) -> None:
        """REDIS_IAM_TOKEN environment variable overrides remote token lookup."""
        with patch.dict(os.environ, {"REDIS_IAM_TOKEN": "test-static-token"}):
            provider = GcpRedisIamCredentialProvider(username="custom-user")
            username, password = provider.get_credentials()
            assert username == "custom-user"
            assert password == "test-static-token"

    @pytest.mark.asyncio
    async def test_async_get_credentials(self) -> None:
        """get_credentials_async returns same tuple as sync."""
        with patch.dict(os.environ, {"REDIS_IAM_TOKEN": "async-test-token"}):
            provider = GcpRedisIamCredentialProvider()
            username, password = await provider.get_credentials_async()
            assert username == "default"
            assert password == "async-test-token"

    def test_metadata_server_fetch_success(self) -> None:
        """Successful fetch from metadata server caches token."""
        provider = GcpRedisIamCredentialProvider()

        # Clear class cache
        GcpRedisIamCredentialProvider._cached_token = None
        GcpRedisIamCredentialProvider._cached_expiry = 0.0

        with patch.dict(os.environ, {}, clear=True):
            with patch.object(
                provider,
                "_fetch_token_from_metadata",
                return_value=("meta-token-123", time.time() + 3600),
            ) as mock_meta:
                username, token = provider.get_credentials()
                assert username == "default"
                assert token == "meta-token-123"
                assert mock_meta.call_count == 1

                # Second call should use cache
                _, token2 = provider.get_credentials()
                assert token2 == "meta-token-123"
                assert mock_meta.call_count == 1

    def test_prod_fails_closed_when_credentials_fail(self) -> None:
        """In production posture, failing credential resolution raises RuntimeError."""
        provider = GcpRedisIamCredentialProvider()
        GcpRedisIamCredentialProvider._cached_token = None
        GcpRedisIamCredentialProvider._cached_expiry = 0.0

        with patch.dict(os.environ, {"CAGE_ENV": "prod"}, clear=True):
            with patch.object(
                provider,
                "_fetch_token_from_metadata",
                side_effect=RuntimeError("Metadata unreachable"),
            ):
                with patch.object(
                    provider,
                    "_fetch_token_from_adc",
                    side_effect=RuntimeError("ADC missing"),
                ):
                    with pytest.raises(
                        RuntimeError, match="Unable to obtain GCP IAM token"
                    ):
                        provider.get_credentials()


class TestRedisCredentialFactory:
    """Tests for Layer 1 Redis Credential Factory seam."""

    def test_disabled_by_default(self) -> None:
        """Without REDIS_AUTH_MODE or REDIS_IAM_AUTH, factory returns None."""
        with patch.dict(os.environ, {}, clear=True):
            assert is_redis_iam_auth_enabled() is False
            assert get_redis_credential_provider() is None

    def test_enabled_via_auth_mode(self) -> None:
        """REDIS_AUTH_MODE=iam triggers provider instantiation."""
        with patch.dict(os.environ, {"REDIS_AUTH_MODE": "iam"}):
            assert is_redis_iam_auth_enabled() is True
            provider = get_redis_credential_provider()
            assert isinstance(provider, GcpRedisIamCredentialProvider)

    def test_enabled_via_iam_auth_flag(self) -> None:
        """REDIS_IAM_AUTH=true triggers provider instantiation."""
        with patch.dict(os.environ, {"REDIS_IAM_AUTH": "true"}):
            assert is_redis_iam_auth_enabled() is True
            provider = get_redis_credential_provider()
            assert isinstance(provider, GcpRedisIamCredentialProvider)

    def test_explicit_argument_precedence(self) -> None:
        """Explicit auth_mode argument overrides environment."""
        with patch.dict(os.environ, {"REDIS_AUTH_MODE": "iam"}):
            assert get_redis_credential_provider(auth_mode="password") is None
            assert get_redis_credential_provider(auth_mode="iam") is not None

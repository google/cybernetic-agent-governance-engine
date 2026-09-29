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

"""Tests for build_async_redis() in src/gateway/infrastructure/redis_client.py.

The evidence stream producer and custodian connect through this builder, so
it must honour REDIS_TLS, certificate verification under enforcing postures,
and the IAM credential provider. No connection is opened: redis-py clients
connect lazily.
"""

from __future__ import annotations

import ssl
from unittest.mock import patch

import pytest

from src.gateway.infrastructure.redis_client import build_async_redis

pytestmark = [pytest.mark.unit, pytest.mark.local]


def _kwargs(client):
    return client.connection_pool.connection_kwargs


@pytest.fixture(autouse=True)
def _no_iam(monkeypatch):
    monkeypatch.delenv("REDIS_TLS", raising=False)
    monkeypatch.delenv("REDIS_CA_CERT_PATH", raising=False)
    monkeypatch.delenv("REDIS_PASSWORD", raising=False)
    with patch(
        "src.gateway.infrastructure.redis_credential_factory.get_redis_credential_provider",
        return_value=None,
    ):
        yield


def test_plain_url_parses_host_port_db_and_password(monkeypatch):
    monkeypatch.setenv("CAGE_ENV", "test")
    client = build_async_redis("redis://:s3cret@10.0.0.5:6380", db=1)
    kw = _kwargs(client)
    assert (kw["host"], kw["port"], kw["db"]) == ("10.0.0.5", 6380, 1)
    assert kw["password"] == "s3cret"


def test_rejects_non_redis_scheme(monkeypatch):
    monkeypatch.setenv("CAGE_ENV", "test")
    with pytest.raises(ValueError, match="scheme"):
        build_async_redis("http://10.0.0.5:6379", db=1)


def test_redis_tls_flag_enables_tls_and_verifies_when_enforcing(monkeypatch):
    monkeypatch.setenv("CAGE_ENV", "production")
    monkeypatch.setenv("REDIS_TLS", "true")
    client = build_async_redis("redis://10.0.0.5:6378", db=1)
    kw = _kwargs(client)
    assert kw["ssl_cert_reqs"] == ssl.CERT_REQUIRED
    assert kw["ssl_ca_certs"]


def test_tls_without_ca_skips_verification_only_when_permissive(monkeypatch):
    monkeypatch.setenv("CAGE_ENV", "dev")
    client = build_async_redis("rediss://10.0.0.5:6378", db=1)
    assert _kwargs(client)["ssl_cert_reqs"] == ssl.CERT_NONE


def test_iam_credential_provider_overrides_url_password(monkeypatch):
    monkeypatch.setenv("CAGE_ENV", "test")
    sentinel = object()
    with patch(
        "src.gateway.infrastructure.redis_credential_factory.get_redis_credential_provider",
        return_value=sentinel,
    ):
        client = build_async_redis("redis://:ignored@10.0.0.5:6379", db=1)
    kw = _kwargs(client)
    assert kw["password"] is None
    assert kw["credential_provider"] is sentinel

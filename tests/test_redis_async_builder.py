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

"""Tests for resolve_redis_tls(), module-level Redis clients, and build_async_redis()
in src/gateway/infrastructure/redis_client.py.

Both the gateway module-level clients (_AsyncRedisClient / _SyncRedisClient) and
build_async_redis() (used by the evidence stream producer and custodian) share
resolve_redis_tls(), enforcing ssl.CERT_REQUIRED under every enforcing posture
(including staging and production) or whenever a readable REDIS_CA_CERT_PATH is
present.
"""

from __future__ import annotations

import asyncio
import datetime
import importlib
import ipaddress
import logging
import socket
import ssl
import threading
from pathlib import Path
from typing import Any, Callable
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import src.gateway.infrastructure.redis_client as redis_client_mod
from src.gateway.infrastructure.redis_client import (
    build_async_redis,
    resolve_redis_tls,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


def _kwargs(client: Any) -> dict[str, Any]:
    return client.connection_pool.connection_kwargs


@pytest.fixture(autouse=True)
def _no_iam(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("REDIS_TLS", raising=False)
    monkeypatch.delenv("REDIS_CA_CERT_PATH", raising=False)
    monkeypatch.delenv("REDIS_PASSWORD", raising=False)
    monkeypatch.delenv("REDIS_URL", raising=False)
    with patch(
        "src.gateway.infrastructure.redis_credential_factory.get_redis_credential_provider",
        return_value=None,
    ):
        yield


@pytest.fixture(params=["build_async_redis", "module_reload"])
def redis_entry_point(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> Callable[[str], dict[str, Any]]:
    """Parametrise over both Redis client entry points so one TLS rule is proven for both."""
    mode = request.param
    reloaded = False
    orig_async_client = redis_client_mod.redis_client
    orig_sync_client = redis_client_mod.sync_redis_client

    def _build(url: str) -> dict[str, Any]:
        nonlocal reloaded
        if mode == "build_async_redis":
            client = build_async_redis(url, db=1)
            return _kwargs(client)

        monkeypatch.setenv("REDIS_URL", url)
        monkeypatch.setenv("REDIS_DB", "1")
        reloaded = True
        importlib.reload(redis_client_mod)
        async_raw = asyncio.run(redis_client_mod.redis_client._get())
        sync_raw = redis_client_mod.sync_redis_client._get()
        async_kw = _kwargs(async_raw)
        sync_kw = _kwargs(sync_raw)
        assert async_kw["ssl_cert_reqs"] == sync_kw["ssl_cert_reqs"]
        assert async_kw["ssl_ca_certs"] == sync_kw["ssl_ca_certs"]
        return async_kw

    yield _build

    if reloaded:
        monkeypatch.undo()
        importlib.reload(redis_client_mod)
        orig_async_client._client = None
        orig_sync_client._client = None
        redis_client_mod.redis_client = orig_async_client
        redis_client_mod.sync_redis_client = orig_sync_client


@pytest.fixture
def local_tls_redis_server(tmp_path: Path):
    """Start a hermetic local TLS socket server with a throwaway self-signed cert."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    cert_path = tmp_path / "redis-server-ca.pem"
    key_path = tmp_path / "redis-server-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )

    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(5)
    port = sock.getsockname()[1]

    def _serve() -> None:
        while True:
            try:
                conn, _ = sock.accept()
            except OSError:
                break
            try:
                with server_ctx.wrap_socket(conn, server_side=True) as tls_conn:
                    while tls_conn.recv(1024):
                        tls_conn.sendall(b"+PONG\r\n")
            except (ssl.SSLError, OSError):
                pass

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    try:
        yield port, cert_path
    finally:
        sock.close()


def test_plain_url_parses_host_port_db_and_password(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("CAGE_ENV", "test")
    client = build_async_redis("redis://:s3cret@10.0.0.5:6380", db=1)
    kw = _kwargs(client)
    assert (kw["host"], kw["port"], kw["db"]) == ("10.0.0.5", 6380, 1)
    assert kw["password"] == "s3cret"


def test_rejects_non_redis_scheme(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("CAGE_ENV", "test")
    with pytest.raises(ValueError, match="scheme"):
        build_async_redis("http://10.0.0.5:6379", db=1)


@pytest.mark.parametrize("posture", ["production", "prod", "staging", "local"])
def test_redis_tls_flag_enables_tls_and_verifies_when_enforcing(
    monkeypatch: pytest.MonkeyPatch,
    redis_entry_point: Callable[[str], dict[str, Any]],
    posture: str,
):
    monkeypatch.setenv("CAGE_ENV", posture)
    monkeypatch.setenv("REDIS_TLS", "true")
    kw = redis_entry_point("redis://10.0.0.5:6378")
    assert kw["ssl_cert_reqs"] == ssl.CERT_REQUIRED
    assert kw["ssl_ca_certs"]


@pytest.mark.parametrize("posture", ["dev", "development", "test", "ci"])
def test_tls_without_ca_skips_verification_only_when_permissive(
    monkeypatch: pytest.MonkeyPatch,
    redis_entry_point: Callable[[str], dict[str, Any]],
    posture: str,
):
    monkeypatch.setenv("CAGE_ENV", posture)
    kw = redis_entry_point("rediss://10.0.0.5:6378")
    assert kw["ssl_cert_reqs"] == ssl.CERT_NONE
    assert kw["ssl_ca_certs"] is None


@pytest.mark.parametrize("posture", ["dev", "test", "ci"])
def test_permissive_posture_with_readable_ca_enforces_verification(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    redis_entry_point: Callable[[str], dict[str, Any]],
    posture: str,
):
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n")
    monkeypatch.setenv("CAGE_ENV", posture)
    monkeypatch.setenv("REDIS_CA_CERT_PATH", str(ca_file))
    kw = redis_entry_point("rediss://10.0.0.5:6378")
    assert kw["ssl_cert_reqs"] == ssl.CERT_REQUIRED
    assert kw["ssl_ca_certs"] == str(ca_file)


def test_resolve_redis_tls_logs_one_line_for_required_and_none(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
):
    assert resolve_redis_tls(False) == (ssl.CERT_NONE, None)

    monkeypatch.setenv("CAGE_ENV", "staging")
    monkeypatch.setenv("REDIS_CA_CERT_PATH", "/etc/cage/tls/redis/ca.pem")
    with caplog.at_level(logging.INFO, logger="Gateway.Infrastructure.Redis"):
        cert_reqs, ca_certs = resolve_redis_tls(True)
    assert cert_reqs == ssl.CERT_REQUIRED
    assert ca_certs == "/etc/cage/tls/redis/ca.pem"
    assert (
        "🔒 Redis TLS: cert_reqs=REQUIRED ca=/etc/cage/tls/redis/ca.pem"
        in caplog.text
    )

    caplog.clear()
    monkeypatch.setenv("CAGE_ENV", "dev")
    monkeypatch.delenv("REDIS_CA_CERT_PATH", raising=False)
    with caplog.at_level(logging.WARNING, logger="Gateway.Infrastructure.Redis"):
        cert_reqs, ca_certs = resolve_redis_tls(True)
    assert (cert_reqs, ca_certs) == (ssl.CERT_NONE, None)
    assert "⚠️ Redis TLS: cert_reqs=NONE (posture=dev)" in caplog.text


def test_iam_credential_provider_overrides_url_password(
    monkeypatch: pytest.MonkeyPatch,
):
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


@pytest.mark.asyncio
async def test_staging_tls_handshake_rejects_unpinned_cert_and_succeeds_with_pinned_ca(
    monkeypatch: pytest.MonkeyPatch,
    local_tls_redis_server: tuple[int, Path],
):
    """Fail-closed verification observed over a live local TLS socket:
    under CAGE_ENV=staging without REDIS_CA_CERT_PATH, connecting to a self-signed
    TLS server raises ssl.SSLCertVerificationError; pinning REDIS_CA_CERT_PATH to
    that server's certificate allows the TLS handshake and PING to succeed."""
    port, cert_path = local_tls_redis_server
    url = f"rediss://127.0.0.1:{port}"

    monkeypatch.setenv("CAGE_ENV", "staging")
    monkeypatch.delenv("REDIS_CA_CERT_PATH", raising=False)

    unpinned_client = build_async_redis(url, db=0)
    conn = unpinned_client.connection_pool.make_connection()
    try:
        with pytest.raises(ssl.SSLCertVerificationError):
            await conn._connect()
    finally:
        await unpinned_client.aclose()

    monkeypatch.setenv("REDIS_CA_CERT_PATH", str(cert_path))
    pinned_client = build_async_redis(url, db=0)
    try:
        assert await pinned_client.ping() is True
    finally:
        await pinned_client.aclose()


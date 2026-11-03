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

"""Secure transport client for actuator_04 with mathematical SSRF guards and fan-out."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import socket
import ssl
from typing import Any
from urllib.parse import urlsplit

import httpx

from src.gateway.governance.env_posture import is_enforcing, resolve_posture
from src.integrations.actuator_04.constants import (
    ENV_CA_PATH,
    ENV_CERT_PATH,
    ENV_ENDPOINT,
    ENV_KEY_PATH,
    ENV_NODE_ENDPOINTS,
)

logger = logging.getLogger("cage.integrations.actuator_04.transport")

_DISALLOWED_IP_NETWORKS = (
    ipaddress.ip_network("169.254.0.0/16"),  # IPv4 Link-local / AWS / GCP Metadata
    ipaddress.ip_network("100.64.0.0/10"),  # Shared Address Space / CGNAT
    ipaddress.ip_network("0.0.0.0/8"),  # Current network
    ipaddress.ip_network("fe80::/10"),  # IPv6 Link-local
    ipaddress.ip_network("::/128"),  # IPv6 Unspecified
    ipaddress.ip_network("::ffff:0:0/96"),  # IPv4-mapped IPv6
)


def _parse_ip_part(p: str) -> int:
    p = p.strip()
    if p.startswith(("0x", "0X")):
        return int(p, 16)
    if p.startswith(("0o", "0O")):
        return int(p, 8)
    if p.startswith(("0b", "0B")):
        return int(p, 2)
    if p.startswith("0") and len(p) > 1 and p.isdigit():
        return int(p, 8)
    return int(p, 10)


def _try_parse_ip_literal(
    hostname: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    # 1. Standard library parser (handles dotted-quad, standard IPv6, ::ffff:x.x.x.x, etc.)
    try:
        return ipaddress.ip_address(hostname)
    except ValueError:
        pass

    # 2. Single integer / octal / hex number (e.g. 2130706433, 017700000001, 0x7f000001)
    try:
        val = _parse_ip_part(hostname)
        if 0 <= val <= 0xFFFFFFFF:
            return ipaddress.IPv4Address(val)
    except (ValueError, TypeError):
        pass

    # 3. Dotted octal or hex IPv4 notation (e.g. 0177.0.0.1, 0x7f.0.0.1, 0251.0376.0251.0376)
    parts = hostname.split(".")
    if len(parts) == 4:
        try:
            nums = [_parse_ip_part(p) for p in parts]
            if all(0 <= n <= 255 for n in nums):
                val = (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]
                return ipaddress.IPv4Address(val)
        except (ValueError, TypeError):
            pass

    return None


def _extract_embedded_ip(
    hostname: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    parts = hostname.split(".")
    if len(parts) >= 4:
        for i in range(len(parts) - 3):
            sub = ".".join(parts[i : i + 4])
            parsed = _try_parse_ip_literal(sub)
            if parsed is not None:
                return parsed
    return None


def _check_single_ip(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    allow_loopback: bool,
    enforcing: bool,
) -> None:
    # If IPv4-mapped IPv6, validate mapped IPv4 as well
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        _check_single_ip(
            ip.ipv4_mapped, allow_loopback=allow_loopback, enforcing=enforcing
        )

    if ip.is_loopback:
        if not allow_loopback or enforcing:
            raise ValueError(f"Loopback IP {ip} forbidden in this posture")
        return

    for net in _DISALLOWED_IP_NETWORKS:
        if ip in net:
            raise ValueError(f"Endpoint IP {ip} falls inside restricted network {net}")

    if enforcing and (
        ip.is_private or ip.is_unspecified or ip.is_reserved or ip.is_link_local
    ):
        raise ValueError(
            f"Private/unspecified/reserved/link-local IP {ip} forbidden in enforcing posture"
        )


def validate_destination_url(url: str, *, allow_loopback: bool = False) -> str:
    """Validate endpoint URL with strict scheme checks and mathematical IP SSRF guards (B310).

    Args:
        url: Absolute target endpoint URL.
        allow_loopback: If True and non-enforcing, permits loopback (127.0.0.1, ::1).

    Returns:
        The validated clean URL string (stripped of trailing slashes).

    Raises:
        ValueError: If URL scheme or destination fails security invariants.
    """
    clean = url.strip()
    if not clean:
        raise ValueError("Endpoint URL cannot be empty")

    parsed = urlsplit(clean)
    scheme = parsed.scheme.lower()
    enforcing = is_enforcing(resolve_posture())

    if enforcing and scheme != "https":
        raise ValueError(
            f"Scheme {scheme!r} forbidden in enforcing posture; https required"
        )

    if not enforcing and scheme not in ("https", "http"):
        raise ValueError(
            f"Unsupported endpoint scheme: {scheme!r}; must be https or http"
        )

    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"No hostname in endpoint URL: {clean!r}")

    # Resolve literal IP (decimal, octal, hex, IPv6, or dotted-quad)
    ip = _try_parse_ip_literal(hostname)
    if ip is not None:
        _check_single_ip(ip, allow_loopback=allow_loopback, enforcing=enforcing)
        return clean.rstrip("/")

    # Hostname string check
    lower_host = hostname.lower()
    if lower_host in ("169.254.169.254", "metadata.google.internal"):
        raise ValueError("Cloud metadata service hostnames are strictly blocked")
    if lower_host in ("localhost", "localhost.localdomain") and (
        enforcing or not allow_loopback
    ):
        raise ValueError("localhost forbidden in this posture")

    embedded_ip = _extract_embedded_ip(hostname)
    if embedded_ip is not None:
        _check_single_ip(
            embedded_ip, allow_loopback=allow_loopback, enforcing=enforcing
        )

    # In enforcing posture, perform DNS resolution via socket.getaddrinfo to defeat DNS rebinding
    if enforcing:
        try:
            infos = socket.getaddrinfo(hostname, None)
        except Exception as exc:
            raise ValueError(
                f"DNS resolution failed for hostname {hostname!r} in enforcing posture: {exc}"
            )
        if not infos:
            raise ValueError(f"No DNS records returned for hostname {hostname!r}")
        for info in infos:
            resolved_ip_str = info[4][0]
            resolved_ip = ipaddress.ip_address(resolved_ip_str)
            _check_single_ip(
                resolved_ip, allow_loopback=allow_loopback, enforcing=enforcing
            )
    else:
        # In non-enforcing posture, check resolved IPs if getaddrinfo succeeds without breaking hermetic tests
        try:
            infos = socket.getaddrinfo(hostname, None)
            for info in infos:
                resolved_ip_str = info[4][0]
                resolved_ip = ipaddress.ip_address(resolved_ip_str)
                _check_single_ip(
                    resolved_ip, allow_loopback=allow_loopback, enforcing=enforcing
                )
        except (socket.gaierror, socket.herror, OSError):
            pass

    return clean.rstrip("/")


class Actuator04Transport:
    """High-assurance transport client managing mTLS sessions and multi-node fan-out."""

    def __init__(
        self,
        *,
        default_endpoint: str = "",
        endpoint: str | None = None,
        node_endpoints: dict[str, str] | None = None,
        http_client: httpx.AsyncClient | None = None,
        timeout_seconds: float = 5.0,
        allow_loopback: bool = True,
    ) -> None:
        if endpoint is not None and not default_endpoint:
            default_endpoint = endpoint
        if not default_endpoint and node_endpoints:
            default_endpoint = next(iter(node_endpoints.values()))
        self._default_endpoint = default_endpoint
        self._node_endpoints = dict(node_endpoints or {})
        self._timeout_seconds = timeout_seconds
        self._allow_loopback = allow_loopback
        self._owns_client = http_client is None
        if http_client is None:
            self._http_client = httpx.AsyncClient(timeout=timeout_seconds)
        else:
            self._http_client = http_client

    @classmethod
    def from_env(cls, *, timeout_seconds: float = 5.0) -> Actuator04Transport:
        """Construct transport from standard environment configuration."""
        enforcing = is_enforcing(resolve_posture())
        raw_endpoint = os.environ.get(ENV_ENDPOINT, "").strip()
        raw_nodes = os.environ.get(ENV_NODE_ENDPOINTS, "").strip()

        if not raw_endpoint and not raw_nodes:
            raise RuntimeError(
                f"[actuator_04] Neither {ENV_ENDPOINT} nor {ENV_NODE_ENDPOINTS} is configured"
            )

        allow_loopback = not enforcing
        default_ep = (
            validate_destination_url(raw_endpoint, allow_loopback=allow_loopback)
            if raw_endpoint
            else ""
        )

        node_map: dict[str, str] = {}
        if raw_nodes:
            if raw_nodes.startswith("{"):
                try:
                    parsed_json = json.loads(raw_nodes)
                    for k, v in parsed_json.items():
                        node_map[str(k).strip()] = validate_destination_url(
                            str(v), allow_loopback=allow_loopback
                        )
                except Exception as exc:
                    raise ValueError(
                        f"Invalid JSON in {ENV_NODE_ENDPOINTS}: {exc}"
                    ) from exc
            else:
                for token in raw_nodes.split(","):
                    token = token.strip()
                    if not token:
                        continue
                    if "=" not in token:
                        raise ValueError(
                            f"Node endpoint must be node=url, got: {token}"
                        )
                    k, v = token.split("=", 1)
                    node_map[k.strip()] = validate_destination_url(
                        v.strip(), allow_loopback=allow_loopback
                    )

        if not default_ep and node_map:
            default_ep = next(iter(node_map.values()))

        cert_path = os.environ.get(ENV_CERT_PATH, "").strip()
        key_path = os.environ.get(ENV_KEY_PATH, "").strip()
        ca_path = os.environ.get(ENV_CA_PATH, "").strip()

        ssl_ctx: ssl.SSLContext | None = None
        if cert_path and key_path:
            ssl_ctx = ssl.create_default_context(cafile=ca_path if ca_path else None)
            ssl_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

        client = httpx.AsyncClient(
            verify=ssl_ctx if ssl_ctx is not None else True,
            timeout=timeout_seconds,
        )

        return cls(
            default_endpoint=default_ep,
            node_endpoints=node_map,
            http_client=client,
            timeout_seconds=timeout_seconds,
        )

    def resolve_target_endpoints(
        self, *, sandbox_id: str | None = None, node_id: str | None = None
    ) -> list[str]:
        """Resolve node affinity from sandbox_id/node_id, or return all nodes for fan-out."""
        if node_id and node_id in self._node_endpoints:
            return [self._node_endpoints[node_id]]

        if sandbox_id and "/" in sandbox_id:
            prefix = sandbox_id.split("/", 1)[0]
            if prefix in self._node_endpoints:
                return [self._node_endpoints[prefix]]

        if self._node_endpoints:
            return list(self._node_endpoints.values())

        if self._default_endpoint:
            return [self._default_endpoint]

        raise RuntimeError("No endpoints available for dispatch")

    async def post_to_endpoints(
        self,
        path: str,
        *,
        content: bytes,
        headers: dict[str, str],
        endpoints: list[str],
    ) -> list[httpx.Response]:
        """Concurrently dispatch payload across all target endpoints with fail-closed semantics."""
        if not endpoints:
            raise ValueError("Cannot dispatch across empty endpoint list")

        client = self._http_client
        if client is None:
            raise RuntimeError("HTTP client is not initialized")

        clean_path = path if path.startswith("/") else f"/{path}"

        async def _single_post(endpoint: str) -> httpx.Response:
            url = f"{endpoint}{clean_path}"
            return await client.post(url, content=content, headers=headers)

        tasks = [_single_post(ep) for ep in endpoints]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        responses: list[httpx.Response] = []
        for ep, res in zip(endpoints, results, strict=True):
            if isinstance(res, BaseException):
                logger.error("Transport POST failed to endpoint %s: %s", ep, res)
                raise res
            if not isinstance(res, httpx.Response):
                raise RuntimeError(f"Unexpected response type from {ep}: {type(res)}")
            responses.append(res)

        return responses

    async def get_from_endpoints(
        self,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        endpoints: list[str],
    ) -> list[httpx.Response]:
        """Concurrently fetch from endpoints with fail-closed semantics."""
        client = self._http_client
        if client is None:
            raise RuntimeError("HTTP client is not initialized")

        clean_path = path if path.startswith("/") else f"/{path}"

        async def _single_get(endpoint: str) -> httpx.Response:
            url = f"{endpoint}{clean_path}"
            return await client.get(url, headers=headers)

        tasks = [_single_get(ep) for ep in endpoints]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        responses: list[httpx.Response] = []
        for ep, res in zip(endpoints, results, strict=True):
            if isinstance(res, BaseException):
                logger.error("Transport GET failed to endpoint %s: %s", ep, res)
                raise res
            responses.append(res)

        return responses

    async def aclose(self) -> None:
        """Close managed HTTP client resources."""
        if self._owns_client and self._http_client is not None:
            await self._http_client.aclose()

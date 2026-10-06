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

"""Gateway ingress authentication by mesh workload identity (POAM-2026-080).

Every request to the gateway must come from a trusted workload identity,
except for a short list of open paths (health, metrics, public keys). This
is deny by default: a path that is not explicitly open requires
an identity, so a new route is protected the moment it is added.

Where the identity comes from
-----------------------------
The Linkerd inbound proxy terminates mTLS in front of the gateway container.
On every inbound HTTP request it either **sets** ``l5d-client-id`` to the
client identity it verified from the peer certificate, or **removes** the
header when the connection carried no verified identity. A caller therefore
cannot forge the header through the proxy.

The identity is Linkerd's DNS-style name, not a ``spiffe://`` URI::

    <service-account>.<namespace>.serviceaccount.identity.linkerd.<trust-domain>

This check is the application half of a two-layer control. The mesh half is
the gateway ``Server`` / ``HTTPRoute`` / ``AuthorizationPolicy`` set, which
refuses unauthorized connections before they reach the container. If that
policy is deleted, or the pod runs without a proxy, this middleware still
refuses the request: no proxy means no header, and no header means 403.

Always enforced
---------------
Trusted identities come from ``CAGE_TRUSTED_CLIENT_IDENTITIES`` (comma
separated). The variable is required in every environment — there is no
development or test off-switch — and startup fails closed if it is unset,
empty, or contains a malformed identity.

This module is domain-agnostic kernel code (Layer 1).
"""

from __future__ import annotations

import json
import logging
import os
import re
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

CLIENT_IDENTITY_HEADER = "l5d-client-id"
TRUSTED_IDENTITIES_ENV = "CAGE_TRUSTED_CLIENT_IDENTITIES"

#: Paths that need no caller identity. Everything else is refused unless the
#: caller presents a trusted identity. Only exact paths can be open: there is
#: no prefix form, so no route family is ever open by accident. Keep in sync
#: with the gateway's open HTTPRoute (deployment/k8s/linkerd-mtls-policy.yaml
#: and infra/modules/gateway/mesh-policy); a test enforces that.
OPEN_EXACT_PATHS: frozenset[str] = frozenset(
    {
        "/health",
        "/healthz",
        "/metrics",
        "/governance/jwks",
        "/governance/.well-known/jwks.json",
    }
)

_LINKERD_IDENTITY = re.compile(
    r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?"  # service account
    r"\.[a-z0-9]([-a-z0-9]*[a-z0-9])?"  # namespace
    r"\.serviceaccount\.identity\.linkerd\."
    r"[a-z0-9]([-a-z0-9.]*[a-z0-9])?$"  # trust domain
)

Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


@dataclass(frozen=True)
class IdentityPolicy:
    """Which caller identities the gateway admits. Always enforced."""

    trusted: frozenset[str]

    def __post_init__(self) -> None:
        if not self.trusted:
            raise ValueError("IdentityPolicy requires at least one trusted identity.")
        malformed = sorted(i for i in self.trusted if not _LINKERD_IDENTITY.match(i))
        if malformed:
            raise ValueError(
                f"IdentityPolicy contains values that are not Linkerd workload "
                f"identities: {malformed}."
            )


def is_open_path(path: str) -> bool:
    """True if ``path`` needs no caller identity.

    Only canonical paths can be open: a path with an empty, ``.`` or ``..``
    segment is never open, so ``//health`` or ``/governance/../mcp`` falls
    through to the identity check instead of matching by accident.
    """
    segments = path.split("/")[1:]
    if not path.startswith("/") or any(s in ("", ".", "..") for s in segments[:-1]):
        return False
    if segments and segments[-1] in (".", ".."):
        return False
    return path in OPEN_EXACT_PATHS


def load_identity_policy() -> IdentityPolicy:
    """Build the policy from the environment. Always fails closed when unset.

    Raises:
        RuntimeError: no identity is configured, or a configured identity is
            not a Linkerd workload identity.
    """
    raw = os.environ.get(TRUSTED_IDENTITIES_ENV, "")
    identities = frozenset(part.strip() for part in raw.split(",") if part.strip())
    malformed = sorted(i for i in identities if not _LINKERD_IDENTITY.match(i))
    if malformed:
        raise RuntimeError(
            f"{TRUSTED_IDENTITIES_ENV} contains values that are not Linkerd workload "
            f"identities: {malformed}. Use '<sa>.<namespace>.serviceaccount.identity."
            "linkerd.<trust-domain>' (the l5d-client-id format), not a spiffe:// URI."
        )
    if not identities:
        raise RuntimeError(
            f"{TRUSTED_IDENTITIES_ENV} must list the workload identities allowed to call "
            "the gateway (POAM-2026-080). There is no permissive bypass."
        )
    return IdentityPolicy(trusted=identities)


def _client_identities(scope: Mapping[str, Any]) -> list[str]:
    name = CLIENT_IDENTITY_HEADER.encode()
    return [
        v.decode("latin-1") for k, v in scope.get("headers", []) if k.lower() == name
    ]


def extract_client_identity(scope: Mapping[str, Any]) -> str:
    """Return the verified Linkerd client identity from an ASGI ``scope``.

    Raises:
        ValueError: if the request does not carry exactly one valid
            ``l5d-client-id`` header.
    """
    presented = _client_identities(scope)
    if len(presented) != 1 or not _LINKERD_IDENTITY.match(presented[0]):
        raise ValueError(
            f"Request must carry exactly one valid {CLIENT_IDENTITY_HEADER} header "
            f"(got {len(presented)})."
        )
    return presented[0]


class WorkloadIdentityMiddleware:
    """ASGI middleware: refuse any non-open request without a trusted identity."""

    def __init__(self, app: ASGIApp, policy: IdentityPolicy) -> None:
        self.app = app
        self.policy = policy

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if is_open_path(path):
            await self.app(scope, receive, send)
            return
        presented = _client_identities(scope)
        # Exactly one header, and it must be trusted. Several headers mean
        # something other than the proxy wrote one of them.
        if len(presented) == 1 and presented[0] in self.policy.trusted:
            await self.app(scope, receive, send)
            return
        logger.warning(
            "INGRESS_IDENTITY_REFUSED path=%s identity=%s",
            path,
            presented[0] if len(presented) == 1 else f"<{len(presented)} headers>",
        )
        await _refuse(scope, send)


async def _refuse(scope: Scope, send: Send) -> None:
    if scope["type"] == "websocket":
        await send({"type": "websocket.close", "code": 1008})
        return
    body = json.dumps(
        {
            "detail": "Forbidden: caller workload identity is not authorized for this route."
        }
    ).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 403,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})

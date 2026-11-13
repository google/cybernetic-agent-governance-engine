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

"""A signing gateway stub for tests that drive the advisor's ``GatewayClient``.

The advisor verifies every ``POST /governance/validate-action`` answer with the
installed ``cage-client`` wheel: it resolves the signing key by ``kid`` from
``GET /governance/.well-known/jwks.json`` and checks the envelope's signature,
``expires_at`` freshness and ``subject.action_hash`` binding before it routes
on the verdict. :class:`SignedGatewayStub` plays the gateway's signing role
behind an ``httpx.MockTransport``: it serves an Ed25519 JWKS and turns the
verdict payload a test handler returns into a signed v3.0 envelope bound to
the request it answers.
"""

from __future__ import annotations

import base64
import json
import uuid
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from cage_client._jcs import canonicalize
from cage_client.crypto import compute_expected_action_hash
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

Handler = Callable[[httpx.Request], httpx.Response]

JWKS_PATH = "/governance/.well-known/jwks.json"
VALIDATE_ACTION_PATH = "/governance/validate-action"


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _rfc3339(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


class SignedGatewayStub:
    """Signs validate-action verdicts with an Ed25519 key published as a JWKS."""

    def __init__(self, kid: str = "advisor-test-gateway-ed25519") -> None:
        self.kid = kid
        self._key = ed25519.Ed25519PrivateKey.generate()
        public = self._key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.jwks: dict[str, Any] = {
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "alg": "EdDSA",
                    "use": "sig",
                    "kid": kid,
                    "x": _b64u(public),
                }
            ]
        }
        #: Every envelope this stub signed, in the order it signed them.
        self.issued: list[dict[str, Any]] = []

    def envelope(
        self,
        action: str,
        params: Mapping[str, Any],
        payload: Mapping[str, Any],
        *,
        envelope_id: str | None = None,
    ) -> dict[str, Any]:
        """Return a signed v3.0 envelope carrying ``payload`` for ``action``/``params``."""
        now = datetime.now(timezone.utc).replace(microsecond=0)
        unsigned: dict[str, Any] = {
            "envelope_version": "3.0",
            "envelope_type": "cage_governance_decision",
            "envelope_id": envelope_id or f"env-{uuid.uuid4()}",
            "issued_at": _rfc3339(now),
            "expires_at": _rfc3339(now + timedelta(minutes=5)),
            "issuer": {
                "service": "cage-gateway",
                "instance_id": "test-gateway",
                "region": "US_FED",
            },
            "subject": {
                "action": action,
                "action_hash": compute_expected_action_hash(action, dict(params)),
            },
            "governance_context": {
                "policy_version": "sha256:test-policy",
                "tiers_passed": ["stpa"],
            },
            "payload": dict(payload),
            "external_attestations": [],
        }
        signature = self._key.sign(canonicalize(unsigned))
        signed = {
            **unsigned,
            "signature": {
                "algorithm": "EdDSA",
                "kid": self.kid,
                "value": _b64u(signature),
            },
        }
        self.issued.append(signed)
        return signed

    def signature_values(self) -> list[str]:
        """The ``signature.value`` of every envelope signed so far, in order."""
        return [str(envelope["signature"]["value"]) for envelope in self.issued]

    def transport_handler(self, handler: Handler) -> Handler:
        """Wrap a ``MockTransport`` handler with the gateway's signing role.

        JWKS requests are answered here and never reach ``handler``. A 200
        answer to ``/governance/validate-action`` whose body is a verdict
        payload (or a v3.0-shaped body without a signature block) is replaced
        by a signed envelope bound to the request's ``action`` and ``params``;
        an ``envelope_id`` in the body is kept. A body that already carries a
        signature block (a deliberately forged or tampered envelope), any
        other status, and any other path pass through unchanged.
        """

        def signing(request: httpx.Request) -> httpx.Response:
            if request.url.path == JWKS_PATH:
                return httpx.Response(200, json=self.jwks)
            response = handler(request)
            if request.url.path != VALIDATE_ACTION_PATH or response.status_code != 200:
                return response
            try:
                body = response.json()
            except ValueError:
                return response
            if not isinstance(body, dict) or isinstance(body.get("signature"), dict):
                return response
            payload = body["payload"] if isinstance(body.get("payload"), dict) else body
            envelope_id = body.get("envelope_id")
            sent = json.loads(request.content)
            return httpx.Response(
                200,
                json=self.envelope(
                    sent["action"],
                    sent["params"],
                    payload,
                    envelope_id=envelope_id if isinstance(envelope_id, str) else None,
                ),
            )

        return signing

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

"""Wire contract for the end-user principal the advisor resolves (issues #516, #520).

The advisor resolves an end-user principal into a :class:`PrincipalIdentity`
(``user_id``, ``verified``, ``kid``):

* When an out-of-band ``kid``-resolved user OIDC JWT is presented
  (``X-CAGE-User-Token``, ``X-GEAP-User-Assertion``, or ``Authorization: Bearer <jwt>``
  when ``CAGE_USER_OIDC_ISSUER`` is configured), the advisor verifies the token
  against its out-of-band trust anchor manifest, checks that any caller-supplied
  ``QueryRequest.user_id`` matches the verified subject claim, and marks
  ``verified=True``.
* Without a verified user OIDC token, an enforcing posture (or any posture with
  ``CAGE_USER_OIDC_ISSUER`` / ``CAGE_REQUIRE_VERIFIED_PRINCIPAL`` set, unless
  ``CAGE_ALLOW_ASSERTED_PRINCIPAL=true``) refuses the request with HTTP 401.
  Permissive postures (``dev``/``test``/``ci``) carry ``QueryRequest.user_id``
  forward with ``verified=False``.

The advisor forwards the resolved principal to the gateway as ``x-cage-principal``,
``x-cage-principal-verified`` (``"true"`` or ``"false"``), and, on GEAP Agent
Runtime, as ``x-geap-user-id``.

The charset and length cap mirror the gateway's ``x-cage-principal`` sanitizer
(``sanitize_principal`` in ``src/gateway/server/rate_limit.py``), so a value
that ``QueryRequest`` accepts reaches the gateway unchanged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

PRINCIPAL_MAX_LEN: Final[int] = 64
"""Maximum principal length; the gateway truncates ``x-cage-principal`` here."""

_PRINCIPAL_CHARSET: Final[str] = "A-Za-z0-9._:@/-"

PRINCIPAL_PATTERN: Final[str] = rf"^[{_PRINCIPAL_CHARSET}]+$"
"""Anchored allow-pattern for a principal accepted from a caller."""

_DISALLOWED_RUN: Final[re.Pattern[str]] = re.compile(rf"[^{_PRINCIPAL_CHARSET}]+")


@dataclass(frozen=True)
class PrincipalIdentity:
    """Resolved end-user principal and whether its identity was cryptographically verified."""

    user_id: str
    verified: bool = False
    issuer: str = ""
    kid: str = ""


def principal_header_value(raw: str | None) -> str | None:
    """Return ``raw`` in the gateway's principal charset, capped at 64 characters.

    Applies the gateway's ``x-cage-principal`` sanitization: runs of
    disallowed characters collapse to ``_``, the result is truncated to
    :data:`PRINCIPAL_MAX_LEN`, and leading or trailing underscores are
    stripped. Returns ``None`` where the gateway would fall back to
    ``anonymous``, so the caller omits the header rather than sending an
    empty or placeholder value.
    """
    if not raw:
        return None
    cleaned = _DISALLOWED_RUN.sub("_", raw.strip())[:PRINCIPAL_MAX_LEN].strip("_")
    return cleaned or None

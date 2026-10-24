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

"""Wire contract for the end-user principal the advisor asserts.

The advisor takes an end-user principal from its caller (``QueryRequest.user_id``)
and forwards it to the gateway as ``x-cage-principal`` and, on GEAP Agent
Runtime, as ``x-geap-user-id``. Nothing authenticates that value: ``CAGE_API_KEY``
authenticates the calling client, not a user, and the gateway authenticates only
the advisor's workload identity. The principal is an attribution and
rate-limit key, never an authorization input.

The charset and length cap mirror the gateway's ``x-cage-principal`` sanitizer
(``sanitize_principal`` in ``src/gateway/server/rate_limit.py``), so a value
that ``QueryRequest`` accepts reaches the gateway unchanged.
"""

from __future__ import annotations

import re
from typing import Final

PRINCIPAL_MAX_LEN: Final[int] = 64
"""Maximum principal length; the gateway truncates ``x-cage-principal`` here."""

_PRINCIPAL_CHARSET: Final[str] = "A-Za-z0-9._:@/-"

PRINCIPAL_PATTERN: Final[str] = rf"^[{_PRINCIPAL_CHARSET}]+$"
"""Anchored allow-pattern for a principal accepted from a caller."""

_DISALLOWED_RUN: Final[re.Pattern[str]] = re.compile(rf"[^{_PRINCIPAL_CHARSET}]+")


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

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

"""Hardened TLS context factory for NIST SP 800-52 Rev. 2 compliance (SC-8).

POAM-2026-011 remediation: This module provides a canonical SSL/TLS context
factory that enforces TLS 1.2 as the protocol floor and explicitly disables
legacy TLS 1.0/1.1 protocols, regardless of host OpenSSL default configuration.

All production code creating SSL contexts for HTTPS connections SHOULD use
create_hardened_client_context() instead of ssl.create_default_context()
directly to ensure consistent NIST SP 800-52 Rev. 2 posture.
"""

from __future__ import annotations

import ssl
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ssl import SSLContext


def create_hardened_client_context(
    purpose: ssl.Purpose = ssl.Purpose.SERVER_AUTH,
) -> SSLContext:
    """Create a hardened SSLContext enforcing NIST SP 800-52 Rev. 2 (TLS 1.2+).

    This factory wraps ssl.create_default_context and applies additional
    hardening to ensure TLS 1.2 minimum version and explicit disablement of
    TLS 1.0/1.1, independent of the host system's OpenSSL configuration.

    NIST SP 800-52 Rev. 2 control SC-8 mandate: TLS 1.0 and 1.1 MUST NOT be
    enabled. TLS 1.2 is the minimum acceptable version; TLS 1.3 is preferred.

    Args:
        purpose: The purpose of this SSL context (default: SERVER_AUTH for
            client-side HTTPS connections).

    Returns:
        An SSLContext configured with:
        - minimum_version = TLSVersion.TLSv1_2 (enforces protocol floor)
        - OP_NO_TLSv1 and OP_NO_TLSv1_1 options set (defense-in-depth)
        - All other ssl.create_default_context() hardening (cert validation,
          secure cipher suites, etc.)

    Example:
        >>> import ssl
        >>> from src.gateway.infrastructure.tls_context import create_hardened_client_context
        >>> ctx = create_hardened_client_context()
        >>> assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
        >>> # Use with httpx:
        >>> import httpx
        >>> client = httpx.AsyncClient(verify=ctx)

    References:
        - NIST SP 800-52 Rev. 2: Guidelines for TLS Implementations
        - POAM-2026-011: TLS 1.0/1.1 deprecation tracking
        - SC-8: Transmission Confidentiality and Integrity
    """
    # Start with Python's hardened default context (cert verification, secure
    # cipher suites, etc.)
    ctx = ssl.create_default_context(purpose)

    # Explicitly enforce TLS 1.2 as the protocol floor. This overrides any
    # host OpenSSL configuration that may leave minimum_version at
    # MINIMUM_SUPPORTED (dynamic value, often TLS 1.0 or unspecified).
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    # Defense-in-depth: Explicitly set the legacy protocol disablement flags.
    # These are redundant when minimum_version >= TLSv1_2, but provide an
    # additional layer of protection if minimum_version were ever accidentally
    # lowered or if the OpenSSL build has unexpected defaults.
    ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

    return ctx

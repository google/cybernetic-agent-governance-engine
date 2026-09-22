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
Credential Broker Seam — Vendor-Neutral Outbound Tool Credential Dispatch.

This module defines the protocol boundary for retrieving authenticated credentials
at the outbound tool dispatch edge. Autonomous agents MUST never handle raw API
credentials; CAGE brokers tokens right before tool invocation.

Architecture Invariants:
    - Layer 1 Kernel (Gate G3 compliant): No vendor SDK imports.
    - FORBIDDEN: Imports from src/cage_* (Layer 2), src/integrations/ (Layer 3).
    - Protocol-only: This file defines contracts, not implementations.

Security Model:
    - SVID-based authorization: Agent identity must be authenticated via SPIFFE SVID.
    - Least-privilege scoping: Credentials are scoped to specific tool names.
    - Fail-closed: Unauthorized access raises CredentialAccessDenied.
"""

from __future__ import annotations

from typing import Protocol


class CredentialBrokerError(Exception):
    """Base exception for all credential broker failures."""

    pass


class CredentialNotFound(CredentialBrokerError):
    """Raised when no matching credential exists for the requested tool."""

    pass


class CredentialAccessDenied(CredentialBrokerError):
    """Raised when the SVID is not authorized to access the requested credential."""

    pass


class CredentialBrokerAdapter(Protocol):
    """
    Vendor-neutral protocol for retrieving outbound tool credentials.

    Implementations must enforce SVID-based authorization and return authenticated
    headers suitable for downstream HTTP requests. Credentials are never logged
    or cached beyond the immediate dispatch context.

    Thread-safety: Implementations must be safe for concurrent access.
    """

    async def fetch_credential(
        self,
        agent_svid: str,
        tool_name: str,
        scope: str | None = None,
    ) -> dict[str, str]:
        """
        Retrieve authenticated headers for downstream outbound tool dispatch.

        Args:
            agent_svid: SPIFFE SVID identifying the requesting agent.
            tool_name: Canonical name of the tool requiring credentials (e.g. 'github_api').
            scope: Optional scope restriction (e.g. 'read:repo', 'write:issues').

        Returns:
            Dictionary of HTTP headers to inject (e.g. {'Authorization': 'Bearer ...'}).

        Raises:
            CredentialAccessDenied: If the SVID is not authorized for the tool.
            CredentialNotFound: If no matching secret exists.
            CredentialBrokerError: For transient failures (e.g. network, vault unavailable).

        Security Notes:
            - Never log or cache the returned dictionary beyond the immediate dispatch.
            - Implementations MUST validate SVID signatures before issuing credentials.
            - Fail-closed: Authorization failures must raise, not return empty headers.
        """
        ...

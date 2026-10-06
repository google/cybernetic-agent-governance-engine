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
Warrant Source Seam — Vendor-Neutral Warrant Supply Interface.

This module defines the contract between CAGE's governance kernel and external
warrant issuers. An issuer adapter (Layer 3, ``src/integrations/``) supplies the
current warrant for a norm; the kernel (``src.gateway.governance.warrant``)
owns verification, so an adapter can never decide reliance eligibility itself.

Fail-closed contract:
    ``fetch`` returns ``None`` whenever no warrant can be produced: unknown
    norm, unconfigured or unimplemented transport, or a fetch failure. The
    kernel verifier maps ``None`` to ``RelianceStatus.INELIGIBLE_MISSING``. An
    adapter must never synthesize, back-fill or re-digest a warrant.

Architectural Invariant:
    This module must NEVER import from the rest of the kernel at runtime. The
    ``Warrant`` type is referenced for static typing only.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from src.gateway.governance.warrant.model import Warrant


@runtime_checkable
class WarrantSource(Protocol):
    """Supplies the issuer's current warrant for a norm."""

    @property
    def provider_name(self) -> str:
        """Stable source identifier recorded in warrant evidence attestations."""
        ...  # pragma: no cover

    async def fetch(self, norm_id: str) -> Warrant | None:
        """Return the current warrant governing ``norm_id``, or ``None`` (MISSING).

        The returned warrant is passed to the kernel verifier unmodified,
        including its issuer-declared digest.
        """
        ...  # pragma: no cover

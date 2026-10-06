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
Provider 05 (Veraxis Execution Integrity Protocol — VEIP) warrant source.

Implements the kernel ``WarrantSource`` seam
(``src.gateway.governance.seams.warrant``) for VEIP-issued institutional
warrants under the CAGE x VEIP Warrant Contract v0.1. The warrant model,
standing verifier and evidence binding live in the kernel
(``src.gateway.governance.warrant``); this adapter only supplies warrants.

Status: seeded / synthetic. Warrants are served from an in-memory store
populated through ``seed()``. The HTTP path is unimplemented: a norm with no
seeded warrant yields ``None`` (``INELIGIBLE_MISSING`` at the verifier) even
when ``PROVIDER_05_ATTESTATION_ENDPOINT`` is configured, which is the
fail-closed direction.
"""

from __future__ import annotations

import logging
import os

from src.gateway.governance.warrant import Warrant

logger = logging.getLogger("cage.integrations.provider_05.warrant_source")

PROVIDER_NAME = "provider_05_warrant"


class Provider05WarrantSource:
    """Seeded VEIP warrant source implementing the kernel ``WarrantSource`` seam."""

    def __init__(self, endpoint: str = "") -> None:
        self._endpoint = (
            endpoint or os.environ.get("PROVIDER_05_ATTESTATION_ENDPOINT", "")
        ).rstrip("/")
        self._warrants: dict[str, Warrant] = {}

    @property
    def provider_name(self) -> str:
        return PROVIDER_NAME

    def seed(self, warrant: Warrant) -> None:
        """Seed the issuer's current warrant for its ``norm_id``.

        The warrant is stored exactly as issued, including its declared digest;
        a later seed for the same norm replaces it (e.g. a revocation).
        """
        self._warrants[warrant.norm_id] = warrant

    async def fetch(self, norm_id: str) -> Warrant | None:
        """Return the seeded warrant for ``norm_id``, or ``None`` (MISSING)."""
        warrant = self._warrants.get(norm_id)
        if warrant is not None:
            return warrant
        if self._endpoint:
            logger.warning(
                "VEIP warrant HTTP path is unimplemented; norm %r has no seeded "
                "warrant and resolves as MISSING",
                norm_id,
            )
        return None

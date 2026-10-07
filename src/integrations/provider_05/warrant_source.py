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

Fault injection (AGENTS.md: a posture-completing data source needs
deterministic fault injection for every fail-closed path). ``inject_fault()``
takes a kernel :class:`~src.gateway.governance.seams.ground_truth.FaultMode`;
each supported mode drives one fail-closed path of the warrant gate:

* ``TIMEOUT`` raises ``TimeoutError`` (what the cache's fetch timeout
  raises), ``CONNECTION_ERROR`` raises ``ConnectionError``: a source fault,
  so the norm is ``INELIGIBLE_UNRESOLVED`` (nothing observed yet) or
  ``INELIGIBLE_STALE`` (the cached state is past the freshness window).
* ``MALFORMED_PAYLOAD`` returns the raw payload (a ``dict``) instead of a
  parsed ``Warrant``: the kernel cache refuses it as a source fault.
* ``UNVERIFIED_SOURCE`` returns the warrant with ``issuing_authority``
  rewritten in transit but the declared digest kept: the verifier's digest
  check makes it ``INELIGIBLE_UNRESOLVED``.

Any other mode is refused at injection (``ValueError``) rather than silently
ignored.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from src.gateway.governance.seams.ground_truth import FaultMode
from src.gateway.governance.warrant import Warrant

logger = logging.getLogger("cage.integrations.provider_05.warrant_source")

PROVIDER_NAME = "provider_05_warrant"

#: The fault modes that map onto a warrant-gate fail-closed path.
SUPPORTED_FAULTS: frozenset[FaultMode] = frozenset(
    {
        FaultMode.NONE,
        FaultMode.TIMEOUT,
        FaultMode.CONNECTION_ERROR,
        FaultMode.MALFORMED_PAYLOAD,
        FaultMode.UNVERIFIED_SOURCE,
    }
)


class Provider05WarrantSource:
    """Seeded VEIP warrant source implementing the kernel ``WarrantSource`` seam."""

    def __init__(self, endpoint: str = "") -> None:
        self._endpoint = (
            endpoint or os.environ.get("PROVIDER_05_ATTESTATION_ENDPOINT", "")
        ).rstrip("/")
        self._warrants: dict[str, Warrant] = {}
        self._fault = FaultMode.NONE

    @property
    def provider_name(self) -> str:
        return PROVIDER_NAME

    def seed(self, warrant: Warrant) -> None:
        """Seed the issuer's current warrant for its ``norm_id``.

        The warrant is stored exactly as issued, including its declared digest;
        a later seed for the same norm replaces it (e.g. a revocation).
        """
        self._warrants[warrant.norm_id] = warrant

    @property
    def fault_mode(self) -> FaultMode:
        return self._fault

    def inject_fault(self, mode: FaultMode | str) -> None:
        """Make every later ``fetch()`` fail in ``mode`` until cleared.

        Raises:
            ValueError: ``mode`` is not a FaultMode, or has no warrant
                meaning (see ``SUPPORTED_FAULTS``).
        """
        fault = FaultMode(mode)
        if fault not in SUPPORTED_FAULTS:
            raise ValueError(
                f"fault mode {fault.value!r} has no warrant-source meaning; "
                f"supported: {sorted(f.value for f in SUPPORTED_FAULTS)}"
            )
        self._fault = fault

    def clear_fault(self) -> None:
        self._fault = FaultMode.NONE

    async def fetch(self, norm_id: str) -> Any:
        """Return the seeded warrant for ``norm_id``, or ``None`` (MISSING).

        Under an injected fault the answer is the fault's (see module
        docstring), which is why the return type is not narrowed to
        ``Warrant | None``.
        """
        fault = self._fault
        if fault is FaultMode.TIMEOUT:
            raise TimeoutError("simulated VEIP warrant fetch timeout")
        if fault is FaultMode.CONNECTION_ERROR:
            raise ConnectionError("simulated VEIP warrant connection error")
        warrant = self._warrants.get(norm_id)
        if warrant is not None:
            if fault is FaultMode.MALFORMED_PAYLOAD:
                return warrant.to_dict()
            if fault is FaultMode.UNVERIFIED_SOURCE:
                return Warrant(
                    **{
                        **warrant.to_dict(),
                        "issuing_authority": "rewritten in transit",
                    }
                )
            return warrant
        if self._endpoint:
            logger.warning(
                "VEIP warrant HTTP path is unimplemented; norm %r has no seeded "
                "warrant and resolves as MISSING",
                norm_id,
            )
        return None

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

"""signer.py — Vendor-Decoupled Evidence Signer Protocol (Layer 1)

Provides the vendor-neutral protocol for asynchronous background signing.

Layer Invariant (Layer 1 Kernel):
    This module defines the abstract seam only. It contains ZERO vendor imports
    (no google-cloud-kms or aws-kms). Concrete adapters live strictly in Layer 3
    integrations.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class EvidenceSigner(Protocol):
    """Protocol for asynchronous background evidence signing."""

    def enqueue(
        self,
        record_hash: str,
        payload: dict[str, Any],
        callback: Callable[[str, str], None] | None = None,
    ) -> None:
        """Enqueue a record for background signing."""
        ...

    async def start(self) -> None:
        """Start the background signing task."""
        ...

    async def stop(self) -> None:
        """Stop the background worker."""
        ...

    async def drain(self) -> int:
        """Flush all pending records synchronously."""
        ...

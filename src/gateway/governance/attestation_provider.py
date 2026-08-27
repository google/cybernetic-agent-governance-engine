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
Generic Attestation Provider Protocol.

Defines the abstract base class that all external attestation providers
(e.g., Provider 05, Provider 04, or future vendors) must implement to integrate
with the GovernanceEnvelope's ``external_attestations[]`` field.

Providers fetch, cache, and verify attestation records from external
trust services.  They are polled at boot and on a configurable interval;
cached attestations are embedded into GovernanceEnvelopes without
per-transaction network calls.
"""

from __future__ import annotations

import abc
from typing import Any

from src.gateway.governance.governance_envelope import ExternalAttestation


class AttestationProvider(abc.ABC):
    """Protocol for external attestation providers.

    Implementations fetch, cache, and verify attestation records from
    external trust services.  The provider is polled at boot and on a
    configurable interval; cached attestations are embedded into
    GovernanceEnvelopes without per-transaction network calls.

    To integrate a new attestation source:

    1. Create a new module in ``src/integrations/<vendor>/``.
    2. Subclass ``AttestationProvider``.
    3. Implement ``fetch_attestations()`` and ``provider_name``.
    4. Register the provider with ``AttestationAggregator.register()``.
    """

    @abc.abstractmethod
    async def fetch_attestations(
        self, context: dict[str, Any]
    ) -> list[ExternalAttestation]:
        """Fetch current attestations for the given governance context.

        Args:
            context: A dictionary of contextual information that the
                provider can use to scope its attestation query (e.g.,
                action name, deployment region, agent identity).

        Returns:
            A list of ExternalAttestation entries to embed in the
            GovernanceEnvelope.
        """

    @property
    @abc.abstractmethod
    def provider_name(self) -> str:
        """Unique provider identifier for telemetry and logging."""

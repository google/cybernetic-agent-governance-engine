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
Attestation Provider Seam — External Trust Service Integration.

This module defines the contract between CAGE's governance envelope builder and
external attestation providers (Provider 05, Provider 04, etc.).

Attestation providers fetch, cache, and verify attestation records from external
trust services. They are polled at boot and on a configurable interval; cached
attestations are embedded into GovernanceEnvelopes without per-transaction network calls.

Architectural Invariant:
    This module must NEVER import from src.gateway.governance or any other kernel
    module. It defines pure data contracts and protocols only.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AttestationStatus(str, Enum):
    """Status of an external attestation entry.

    Mirrors the OSCAL four-state finding vocabulary to prevent
    vocabulary drift across attestation providers (c.f. decisions.py).

    Extended with UNVERIFIED to represent "resolved and well-formed,
    but signature not yet checked" — a state the OSCAL vocabulary
    does not express. This is a deliberate extension for fail-closed
    attestation handling.
    """

    VERIFIED = "VERIFIED"
    DENIED = "DENIED"
    STALE = "STALE"
    DRIFT_DETECTED = "DRIFT_DETECTED"
    ERROR = "ERROR"
    UNVERIFIED = "UNVERIFIED"


@dataclass
class ExternalAttestation:
    """An external attestation entry embedded in a governance envelope.

    Generic container for third-party attestation data (e.g.,
    risk-acceptance proofs, identity admissibility grants, substrate
    integrity checks). The ``attestation_type`` and ``metadata`` fields
    are provider-defined; the remaining fields are standardized.

    The ``metadata`` dict is flattened into the serialized output alongside
    the standard fields so that provider-specific keys (e.g.
    ``threshold_id``, ``ca_fingerprint``, ``node_id``) appear at the top
    level of each attestation entry in the envelope JSON.
    """

    attestation_type: str  # e.g. "BLUEPRINT", "KEY", "PHYSICS"
    status: str  # AttestationStatus value
    receipt_id: str  # Provider-issued receipt ID
    attested_at: str  # ISO 8601 UTC timestamp
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict.  Provider metadata is flattened to top level."""
        result: dict[str, Any] = {
            "type": self.attestation_type,
            "status": self.status,
            "receipt_id": self.receipt_id,
            "attested_at": self.attested_at,
        }
        result.update(self.metadata)
        return result


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

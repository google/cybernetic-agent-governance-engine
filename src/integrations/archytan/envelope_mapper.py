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
Archytan Envelope Mapper.

Bidirectional mapping between CAGE's generic ``GovernanceEnvelope`` and
Archytan's wire format.  Translates CAGE's envelope into Archytan's
expected schema and vice versa, handling any Archytan-specific field
naming, nesting, or protocol conventions.

This mapper is used when:
  - Dispatching a signed GovernanceEnvelope to an Archytan downstream
    execution layer.
  - Ingesting an Archytan-produced envelope back into CAGE for audit
    or verification.
"""

from __future__ import annotations

import logging
from typing import Any

from src.gateway.governance.governance_envelope import (
    ExternalAttestation,
    GovernanceEnvelope,
    GovernanceEnvelopeBuilder,
)

logger = logging.getLogger("cage.integrations.archytan.envelope_mapper")


class ArchytanEnvelopeMapper:
    """Bidirectional mapping between GovernanceEnvelope and Archytan wire format.

    Translates CAGE's generic envelope into Archytan's expected schema
    and vice versa, handling any Archytan-specific field naming, nesting,
    or protocol conventions.
    """

    def __init__(self) -> None:
        self._builder = GovernanceEnvelopeBuilder()

    def to_archytan_format(self, envelope: GovernanceEnvelope) -> dict[str, Any]:
        """Convert a GovernanceEnvelope to Archytan's wire format.

        The Archytan wire format wraps the CAGE envelope in an outer
        metadata layer containing Archytan-specific routing and
        provenance fields.

        Args:
            envelope: The CAGE GovernanceEnvelope to convert.

        Returns:
            A dictionary in Archytan's expected wire format.
        """
        cage_dict = envelope.to_dict(include_signature=True)

        return {
            "archytan_version": "1.0",
            "cage_envelope": cage_dict,
            "digest": envelope.compute_digest_hex(),
            "metadata": {
                "source_service": cage_dict.get("issuer", {}).get("service", ""),
                "envelope_id": envelope.envelope_id,
                "envelope_version": envelope.envelope_version,
                "attestation_count": len(envelope.external_attestations),
            },
        }

    def from_archytan_format(self, data: dict[str, Any]) -> GovernanceEnvelope:
        """Convert an Archytan wire-format payload back to a GovernanceEnvelope.

        Args:
            data: A dictionary in Archytan's wire format.

        Returns:
            A reconstructed GovernanceEnvelope.

        Raises:
            ValueError: If the data does not contain a valid cage_envelope.
        """
        cage_dict = data.get("cage_envelope")
        if not cage_dict:
            raise ValueError("Archytan payload missing 'cage_envelope' field")

        return self._builder._envelope_from_dict(cage_dict)

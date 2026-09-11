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

BREAKING CHANGE (C0): AttestationProvider and ExternalAttestation have been
moved to src.gateway.governance.seams.attestation to eliminate circular
dependencies with vendor adapters. This module now re-exports them for
backward compatibility, but the re-export will be removed in the same PR
per the C0 specification.
"""

from __future__ import annotations

# Re-export seam contracts for backward compatibility during transition.
# New code should import directly from seams.attestation.
from src.gateway.governance.seams.attestation import (
    AttestationProvider,
    AttestationStatus,
    ExternalAttestation,
)

__all__ = ["AttestationProvider", "AttestationStatus", "ExternalAttestation"]

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
Kernel warrant mechanism (Warrant Contract v0.1).

Vendor-neutral and domain-agnostic. External issuers supply warrants through
the ``WarrantSource`` seam (``src.gateway.governance.seams.warrant``); this
package owns the data model, the standing verifier and the evidence binding,
so a domain plugin cannot redefine, bypass or self-issue warrant state.

Modules:
    model:    ``Warrant``, ``WarrantScope``, ``WarrantStatus``,
              ``RelianceStatus``, ``StandingVerificationResult``
    verifier: ``WarrantStandingVerifier``
    reliance: ``RelianceRecord`` (the per-decision evidence form carried in
              seals, deferrals and refusal receipts, and the single source
              of the envelope ``WARRANT`` attestation)
    cache:    ``WarrantCache`` (the Warrant Contract v0.1 60 s freshness
              window over a ``WarrantSource``)
"""

from __future__ import annotations

from src.gateway.governance.warrant.cache import (
    CONTRACT_MAX_AGE_SECONDS,
    WarrantCache,
    WarrantClock,
    WarrantFreshness,
    WarrantObservation,
)
from src.gateway.governance.warrant.model import (
    REQUIRED_CONTEXT_KEYS,
    SCOPE_DIMENSIONS,
    WARRANT_SCHEMA_VERSION_V02,
    RelianceStatus,
    StandingVerificationResult,
    Warrant,
    WarrantScope,
    WarrantStatus,
)
from src.gateway.governance.warrant.reliance import (
    RELIANCE_VERIFICATION_STATUS,
    WARRANT_ATTESTATION_TYPE,
    WARRANT_CONTRACT_EVIDENCE_FIELDS,
    RelianceRecord,
    reliance_attestations,
    reliance_evidence,
)
from src.gateway.governance.warrant.trust_anchor import (
    MANIFEST_SCHEMA_VERSION_V02,
    KeyManifestVerificationError,
    ManifestKeyEntry,
    VerifiedKeyManifest,
    WarrantTrustAnchor,
)
from src.gateway.governance.warrant.verifier import WarrantStandingVerifier

__all__ = [
    "CONTRACT_MAX_AGE_SECONDS",
    "MANIFEST_SCHEMA_VERSION_V02",
    "RELIANCE_VERIFICATION_STATUS",
    "REQUIRED_CONTEXT_KEYS",
    "SCOPE_DIMENSIONS",
    "WARRANT_ATTESTATION_TYPE",
    "WARRANT_CONTRACT_EVIDENCE_FIELDS",
    "WARRANT_SCHEMA_VERSION_V02",
    "KeyManifestVerificationError",
    "ManifestKeyEntry",
    "RelianceRecord",
    "RelianceStatus",
    "StandingVerificationResult",
    "VerifiedKeyManifest",
    "Warrant",
    "WarrantCache",
    "WarrantClock",
    "WarrantFreshness",
    "WarrantObservation",
    "WarrantScope",
    "WarrantStandingVerifier",
    "WarrantStatus",
    "WarrantTrustAnchor",
    "reliance_attestations",
    "reliance_evidence",
]

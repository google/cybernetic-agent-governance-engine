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
    evidence: ``bind_warrant_to_attestation``
    reliance: ``RelianceRecord`` (the per-decision evidence form carried in
              seals, deferrals and refusal receipts)
"""

from __future__ import annotations

from src.gateway.governance.warrant.evidence import bind_warrant_to_attestation
from src.gateway.governance.warrant.model import (
    REQUIRED_CONTEXT_KEYS,
    SCOPE_DIMENSIONS,
    RelianceStatus,
    StandingVerificationResult,
    Warrant,
    WarrantScope,
    WarrantStatus,
)
from src.gateway.governance.warrant.reliance import (
    RELIANCE_VERIFICATION_STATUS,
    RelianceRecord,
    reliance_attestations,
    reliance_evidence,
)
from src.gateway.governance.warrant.verifier import WarrantStandingVerifier

__all__ = [
    "RELIANCE_VERIFICATION_STATUS",
    "REQUIRED_CONTEXT_KEYS",
    "SCOPE_DIMENSIONS",
    "RelianceRecord",
    "RelianceStatus",
    "StandingVerificationResult",
    "Warrant",
    "WarrantScope",
    "WarrantStandingVerifier",
    "WarrantStatus",
    "bind_warrant_to_attestation",
    "reliance_attestations",
    "reliance_evidence",
]

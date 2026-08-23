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
Provider 05 (Verifiable Execution Evidence Pack) Integration.

Implements the Three Uncomputable Axioms integration:
  - Axiom 1 (Policy Legitimacy / Blueprint) — Provider05BlueprintProvider
  - Axiom 2 (Identity Genesis / Key) — Provider05KeyProvider
  - Axiom 3 (Substrate Integrity / Physics) — Provider05PhysicsProvider
"""

from src.integrations.provider_05.blueprint_provider import Provider05BlueprintProvider
from src.integrations.provider_05.client import (
    AdmissibilityGrant,
    RiskAcceptanceRecord,
    SubstrateAttestation,
    Provider05Client,
)
from src.integrations.provider_05.key_provider import Provider05KeyProvider
from src.integrations.provider_05.physics_provider import Provider05PhysicsProvider
from src.integrations.provider_05.warrant import (
    RelianceStatus,
    StandingVerificationResult,
    Warrant,
    WarrantScope,
    WarrantStandingVerifier,
    WarrantStatus,
    bind_warrant_to_attestation,
)

__all__ = [
    "AdmissibilityGrant",
    "RelianceStatus",
    "RiskAcceptanceRecord",
    "StandingVerificationResult",
    "SubstrateAttestation",
    "Provider05BlueprintProvider",
    "Provider05Client",
    "Provider05KeyProvider",
    "Provider05PhysicsProvider",
    "Warrant",
    "WarrantScope",
    "WarrantStandingVerifier",
    "WarrantStatus",
    "bind_warrant_to_attestation",
]

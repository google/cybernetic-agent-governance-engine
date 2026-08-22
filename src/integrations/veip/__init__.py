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
VEIP (Verifiable Execution Evidence Pack) Integration.

Implements the Three Uncomputable Axioms integration:
  - Axiom 1 (Policy Legitimacy / Blueprint) — VEIPBlueprintProvider
  - Axiom 2 (Identity Genesis / Key) — VEIPKeyProvider
  - Axiom 3 (Substrate Integrity / Physics) — VEIPPhysicsProvider
"""

from src.integrations.veip.blueprint_provider import VEIPBlueprintProvider
from src.integrations.veip.client import (
    AdmissibilityGrant,
    RiskAcceptanceRecord,
    SubstrateAttestation,
    VEIPClient,
)
from src.integrations.veip.key_provider import VEIPKeyProvider
from src.integrations.veip.physics_provider import VEIPPhysicsProvider

__all__ = [
    "AdmissibilityGrant",
    "RiskAcceptanceRecord",
    "SubstrateAttestation",
    "VEIPBlueprintProvider",
    "VEIPClient",
    "VEIPKeyProvider",
    "VEIPPhysicsProvider",
]

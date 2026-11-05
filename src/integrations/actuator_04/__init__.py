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

"""Layer 3 Actuator04 Package — Host OS Kernel Containment & Attestation Seam.

Exposes vendor-anonymized adapters implementing QuarantineActuator,
ExecutionActuator, NormativeProvider, AttestationProvider, and OCSF Ingestor.
"""

from __future__ import annotations

from src.integrations.actuator_04.adapter import Actuator04Adapter
from src.integrations.actuator_04.attestation import Actuator04AttestationProvider
from src.integrations.actuator_04.client import Actuator04Transport
from src.integrations.actuator_04.constants import (
    ACTUATOR_04_ID,
    ENFORCEMENT_PLANE_HOST_OS_KERNEL,
    OCSF_EVENT_DOMAIN_TAG,
    QUARANTINE_ASSERTION_DOMAIN_TAG,
    QUARANTINE_RECEIPT_DOMAIN_TAG,
    QUARANTINE_RELEASE_ASSERTION_DOMAIN_TAG,
    QUARANTINE_RELEASE_RECEIPT_DOMAIN_TAG,
)
from src.integrations.actuator_04.normative import Actuator04NormativeProvider
from src.integrations.actuator_04.ocsf_bridge import Actuator04OcsfIngestor

__all__ = [
    "ACTUATOR_04_ID",
    "ENFORCEMENT_PLANE_HOST_OS_KERNEL",
    "OCSF_EVENT_DOMAIN_TAG",
    "QUARANTINE_ASSERTION_DOMAIN_TAG",
    "QUARANTINE_RECEIPT_DOMAIN_TAG",
    "QUARANTINE_RELEASE_ASSERTION_DOMAIN_TAG",
    "QUARANTINE_RELEASE_RECEIPT_DOMAIN_TAG",
    "Actuator04Adapter",
    "Actuator04AttestationProvider",
    "Actuator04NormativeProvider",
    "Actuator04OcsfIngestor",
    "Actuator04Transport",
]

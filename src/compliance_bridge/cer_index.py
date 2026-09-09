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

"""CERIndex Protocol — compliance_bridge seam to provider_02 CER lookups.

This module defines the Protocol interface that compliance_bridge uses to
request CER URIs and disclosure policies without directly importing
src.integrations.provider_02, preserving Gate G3 layer isolation.

The concrete implementation (Provider02CERIndex) lives in
src/integrations/provider_02/cer_index.py and is injected at runtime by
the FastAPI main.py startup sequence.
"""

from __future__ import annotations

from typing import Protocol

from src.compliance_bridge.disclosure import Disclosure


class CERIndex(Protocol):
    """Protocol for CER URI and disclosure policy lookups.

    Concrete implementations provide:
    - uri_for_control: Maps NIST SP 800-53 / ISO 42001 control IDs to CER URIs
    - disclosure_for_control: Returns the disclosure policy for a control
    """

    def uri_for_control(self, control_id: str) -> str | None:
        """Return the CER URI for the given control ID, or None if not covered.

        Args:
            control_id: NIST SP 800-53 or ISO 42001 control ID (e.g., "SC-4", "A.5.3")

        Returns:
            Full CER URI (e.g., "https://verify.provider-02.example.com/cer/sha256:abc...")
            or None if no CER exists for this control.
        """
        ...

    def disclosure_for_control(self, control_id: str) -> Disclosure:
        """Return the disclosure policy for the given control ID.

        Args:
            control_id: NIST SP 800-53 or ISO 42001 control ID

        Returns:
            Disclosure policy (PUBLIC, REDACTED, PRIVATE, or UNKNOWN)
        """
        ...

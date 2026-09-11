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

"""Provider02CERIndex — concrete CER URI and disclosure policy index.

This module implements the CERIndex Protocol defined in compliance_bridge,
providing the runtime mapping of NIST SP 800-53 / ISO 42001 control IDs to
Provider 02 CER URIs and disclosure policies.

The implementation is injected into compliance_bridge at FastAPI startup,
preserving layer isolation (Gate G3).
"""

from __future__ import annotations

from src.compliance_bridge.disclosure import Disclosure


class Provider02CERIndex:
    """Provider 02 CER URI and disclosure policy index.

    Maps control IDs to CER URIs and disclosure policies. This is the
    concrete implementation of the CERIndex Protocol used by compliance_bridge's
    OSCAL export pipeline.

    Args:
        cer_uris: Mapping of control_id → CER URI
        disclosure_policies: Mapping of control_id → Disclosure policy
        default_disclosure: Default disclosure policy for controls not in the map
    """

    def __init__(
        self,
        cer_uris: dict[str, str] | None = None,
        disclosure_policies: dict[str, Disclosure] | None = None,
        default_disclosure: Disclosure = Disclosure.UNKNOWN,
    ) -> None:
        """Initialize the CER index.

        Args:
            cer_uris: Optional mapping of control_id → CER URI
            disclosure_policies: Optional mapping of control_id → Disclosure
            default_disclosure: Default disclosure for unmapped controls
        """
        self._cer_uris = cer_uris or {}
        self._disclosure_policies = disclosure_policies or {}
        self._default_disclosure = default_disclosure

    def uri_for_control(self, control_id: str) -> str | None:
        """Return the CER URI for the given control ID, or None if not covered.

        Args:
            control_id: NIST SP 800-53 or ISO 42001 control ID

        Returns:
            Full CER URI or None
        """
        return self._cer_uris.get(control_id)

    def disclosure_for_control(self, control_id: str) -> Disclosure:
        """Return the disclosure policy for the given control ID.

        Args:
            control_id: NIST SP 800-53 or ISO 42001 control ID

        Returns:
            Disclosure policy (PUBLIC, REDACTED, PRIVATE, or UNKNOWN)
        """
        return self._disclosure_policies.get(control_id, self._default_disclosure)

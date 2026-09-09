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

"""Disclosure policy for OSCAL evidence links.

This module defines the four-state disclosure policy that governs whether
CER evidence links appear as dereferenceable link[rel="evidence"] entries
in OSCAL Assessment Results or as props-only metadata.

Decision #2 (plans/provider_02_cer_unblocked_work.md:951):
- PUBLIC: Full link + props
- REDACTED: Full link + props + commitment-scheme metadata (confidential-field scheme)
- PRIVATE: Props only, no dereferenceable link
- UNKNOWN: Treated as PRIVATE (fail-closed)

The fail-closed default ensures an auditor dereferencing a link[rel="evidence"]
that 404s cannot distinguish fabricated evidence from evidence they lack
visibility into. Emitting no link, plus a cer-hash prop, states honestly that
evidence exists but is not publicly dereferenceable.
"""

from __future__ import annotations

from enum import Enum


class Disclosure(Enum):
    """Disclosure policy for CER evidence links in OSCAL exports.

    Attributes:
        PUBLIC: Emit link[rel="evidence"] + cer-hash/cer-digest-alg props.
            The CER is publicly dereferenceable without authentication.

        REDACTED: Emit link[rel="evidence"] + props + commitment-scheme metadata.
            The CER uses Provider 02's confidential-field scheme: sensitive
            payload values are replaced with HMAC commitments, leaving non-sensitive
            fields and the signature chain in clear. The receipt verifies end-to-end
            while withholding only the payload. Suppressing its link would discard
            verifiable evidence for no privacy gain.

        PRIVATE: Emit cer-hash/cer-digest-alg props only, no dereferenceable link.
            The CER exists but requires authenticated access or is never published.
            An auditor receives evidence of existence without a public retrieval path.

        UNKNOWN: Treat as PRIVATE (fail-closed). The disclosure policy is unspecified
            or the control is not covered by CER attestation. No link is emitted.
    """

    PUBLIC = "public"
    REDACTED = "redacted"
    PRIVATE = "private"
    UNKNOWN = "unknown"

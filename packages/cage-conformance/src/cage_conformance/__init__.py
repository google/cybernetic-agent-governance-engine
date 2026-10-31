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

"""Standalone conformance verifier for CAGE governance traces and evidence streams.

Standard library only, with no dependency on a CAGE checkout. ``model``,
``trace_conformance`` and ``stream_invariants`` are byte-identical copies of
the repository's ``proof/`` modules; the rest turns their findings into
provenance-stamped reports (``docs/architecture/CONFORMANCE_VERIFIER_SPEC.md``).
Checking an attestation's signature is the one step that needs a third-party
package, ``cryptography``, installed with the ``attest`` extra.
"""

from __future__ import annotations

__version__ = "0.2.0"

from .attestation import (  # noqa: E402
    ATTESTED_SCHEMA_VERSION,
    ISSUERS,
    OIDC_ENV_VAR,
    PARTIES_SCHEMA_VERSION,
    AttestationError,
    AttestedReport,
    KeySet,
    Parties,
    RsaKey,
    UnpinnedPartyError,
    VerifiedIdentity,
    attest,
    attested_posture,
    audience_for,
    default_parties,
    fetch_key_set,
    is_attested,
    key_set_from_jwks,
    parse_parties,
    validate_attested_report,
    verify_token,
)
from .report import (  # noqa: E402
    ATTESTED_POSTURES,
    MODE_PROFILES,
    PROVENANCE_SCHEMA_VERSION,
    REPORT_SCHEMA_VERSION,
    AdapterUnderTest,
    AssertionResult,
    ConformanceReport,
    InputDigest,
    Provenance,
    ReportError,
    RunnerProvenance,
    VerificationPosture,
    build_provenance,
    derive_posture,
    normalize_org,
    validate_report,
)
from .runner import (  # noqa: E402
    INPUT_ASSERTION,
    STREAM_RULES,
    TRACE_RULES,
    iter_stream_records,
    iter_trace_events,
    verify_stream,
    verify_trace,
)

__all__ = [
    "ATTESTED_POSTURES",
    "ATTESTED_SCHEMA_VERSION",
    "INPUT_ASSERTION",
    "ISSUERS",
    "MODE_PROFILES",
    "OIDC_ENV_VAR",
    "PARTIES_SCHEMA_VERSION",
    "PROVENANCE_SCHEMA_VERSION",
    "REPORT_SCHEMA_VERSION",
    "STREAM_RULES",
    "TRACE_RULES",
    "AdapterUnderTest",
    "AssertionResult",
    "AttestationError",
    "AttestedReport",
    "ConformanceReport",
    "InputDigest",
    "KeySet",
    "Parties",
    "Provenance",
    "ReportError",
    "RsaKey",
    "RunnerProvenance",
    "UnpinnedPartyError",
    "VerificationPosture",
    "VerifiedIdentity",
    "__version__",
    "attest",
    "attested_posture",
    "audience_for",
    "build_provenance",
    "default_parties",
    "derive_posture",
    "fetch_key_set",
    "is_attested",
    "iter_stream_records",
    "iter_trace_events",
    "key_set_from_jwks",
    "normalize_org",
    "parse_parties",
    "validate_attested_report",
    "validate_report",
    "verify_stream",
    "verify_token",
    "verify_trace",
]

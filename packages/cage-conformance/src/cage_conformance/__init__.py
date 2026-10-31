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
"""

from __future__ import annotations

__version__ = "0.1.0"

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
    "INPUT_ASSERTION",
    "MODE_PROFILES",
    "PROVENANCE_SCHEMA_VERSION",
    "REPORT_SCHEMA_VERSION",
    "STREAM_RULES",
    "TRACE_RULES",
    "AdapterUnderTest",
    "AssertionResult",
    "ConformanceReport",
    "InputDigest",
    "Provenance",
    "ReportError",
    "RunnerProvenance",
    "VerificationPosture",
    "__version__",
    "build_provenance",
    "derive_posture",
    "iter_stream_records",
    "iter_trace_events",
    "normalize_org",
    "validate_report",
    "verify_stream",
    "verify_trace",
]

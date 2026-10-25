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

"""CAGE Standalone Conformance & Attributable Provenance Package."""

from __future__ import annotations

from .provenance import (
    PROVENANCE_SCHEMA_VERSION,
    REPORT_SCHEMA_VERSION,
    AdapterUnderTest,
    AssertionResult,
    ConformanceReport,
    ConformanceSummary,
    IdentityProofType,
    ProvenanceBlock,
    ProvenanceValidationError,
    RunnerProvenance,
    VerificationPosture,
    build_provenance_block,
    derive_verification_posture,
    inspect_oidc_jwt,
    normalize_org_name,
    validate_conformance_report,
)
from .runner import (
    TRACE_RULES,
    iter_trace_events,
    load_vector_fixture,
    verify_endpoint,
    verify_trace_events,
    verify_trace_file,
)
from .trace_conformance import (
    TRACE_EVENT_TYPE,
    TRACE_SCHEMA_VERSION,
    Finding,
    check_event,
    check_trace,
    project,
)

__all__ = [
    "PROVENANCE_SCHEMA_VERSION",
    "REPORT_SCHEMA_VERSION",
    "TRACE_EVENT_TYPE",
    "TRACE_RULES",
    "TRACE_SCHEMA_VERSION",
    "AdapterUnderTest",
    "AssertionResult",
    "ConformanceReport",
    "ConformanceSummary",
    "Finding",
    "IdentityProofType",
    "ProvenanceBlock",
    "ProvenanceValidationError",
    "RunnerProvenance",
    "VerificationPosture",
    "build_provenance_block",
    "check_event",
    "check_trace",
    "derive_verification_posture",
    "inspect_oidc_jwt",
    "iter_trace_events",
    "load_vector_fixture",
    "normalize_org_name",
    "project",
    "validate_conformance_report",
    "verify_endpoint",
    "verify_trace_events",
    "verify_trace_file",
]

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

"""CAGE Gateway Client SDK (``cage-client``).

Out-of-process Policy Enforcement Point (PEP) client SDK for interacting with
the CAGE governance gateway over TLS/mTLS with fail-closed cryptographic
``GovernanceEnvelope`` verification on every HTTP ``200`` and HTTP ``403``
verdict (out-of-band ``kid`` JWKS/PEM resolution, RFC 8785 JCS
canonicalization, temporal freshness, and ``subject`` action binding). Channel
TLS/mTLS (``sc-8``) protects only the wire transport and does NOT substitute
for end-to-end envelope signature verification.
"""

from .core import CageClient, enforce_verification_posture
from .crypto import compute_expected_action_hash, generate_w3c_traceparent
from .envelope import ExecutionGrant, GovernanceEnvelope
from .exceptions import (
    CageGatewayError,
    CommitOutcomeDecodeError,
    DeferralPending,
    GatewayUnavailableError,
    MissingDeferralTicketError,
    PolicyViolationException,
    RoutingSealVerificationError,
)
from .idempotency import (
    derive_idempotency_key,
    derive_plan_step_key,
    extract_plan_step_bindings,
)
from .jwks import JwksCache, JwksKeyResolver
from .outcomes import (
    COMMIT_OUTCOME_SCHEMA,
    COMPLETED_STATUSES,
    INDETERMINATE_STATUSES,
    NOT_EXECUTED_STATUSES,
    RETRYABLE_REFUSALS,
    ApprovalRedemptionRefusal,
    CommitOutcome,
    CommitStatus,
    GovernanceDecision,
    IndeterminateProvenance,
    PreviewResult,
    is_retryable_refusal,
    verify_commit_outcome_payload,
)
from .transport import create_mtls_transport

__version__ = "0.5.0"

__all__ = [
    "COMMIT_OUTCOME_SCHEMA",
    "COMPLETED_STATUSES",
    "INDETERMINATE_STATUSES",
    "NOT_EXECUTED_STATUSES",
    "RETRYABLE_REFUSALS",
    "ApprovalRedemptionRefusal",
    "CageClient",
    "CageGatewayError",
    "CommitOutcome",
    "CommitOutcomeDecodeError",
    "CommitStatus",
    "DeferralPending",
    "ExecutionGrant",
    "GatewayUnavailableError",
    "GovernanceDecision",
    "GovernanceEnvelope",
    "IndeterminateProvenance",
    "JwksCache",
    "JwksKeyResolver",
    "MissingDeferralTicketError",
    "PolicyViolationException",
    "PreviewResult",
    "RoutingSealVerificationError",
    "__version__",
    "compute_expected_action_hash",
    "create_mtls_transport",
    "derive_idempotency_key",
    "derive_plan_step_key",
    "enforce_verification_posture",
    "extract_plan_step_bindings",
    "generate_w3c_traceparent",
    "is_retryable_refusal",
    "verify_commit_outcome_payload",
]

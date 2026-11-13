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

"""CAGE Gateway Client SDK (``cage-client`` / ``src.gateway.client``).

Out-of-process Policy Enforcement Point (PEP) client SDK for interacting with
the CAGE governance gateway over TLS/mTLS with fail-closed cryptographic
``GovernanceEnvelope`` verification (out-of-band ``kid`` JWKS/PEM resolution,
RFC 8785 JCS canonicalization, temporal freshness, and ``subject`` action
binding). Channel TLS/mTLS (``sc-8``) protects only the wire transport and does
NOT substitute for end-to-end envelope signature verification.
"""

from .adapters.langgraph import cage_guard
from .core import CageClient, enforce_verification_posture
from .crypto import compute_expected_action_hash, generate_w3c_traceparent
from .envelope import ExecutionGrant, GovernanceEnvelope
from .exceptions import (
    CageGatewayError,
    DeferralPending,
    PolicyViolationException,
    RoutingSealVerificationError,
)
from .jwks import JwksCache, JwksKeyResolver
from .transport import create_mtls_transport

__version__ = "0.3.0"

__all__ = [
    "CageClient",
    "CageGatewayError",
    "DeferralPending",
    "ExecutionGrant",
    "GovernanceEnvelope",
    "JwksCache",
    "JwksKeyResolver",
    "PolicyViolationException",
    "RoutingSealVerificationError",
    "__version__",
    "cage_guard",
    "compute_expected_action_hash",
    "create_mtls_transport",
    "enforce_verification_posture",
    "generate_w3c_traceparent",
]

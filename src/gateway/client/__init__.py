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
CAGE Gateway Client SDK (Layer 1).

This package provides the official Python client SDK for interacting with the
CAGE governance gateway. It enables LangGraph-based agents to submit actions
for governance evaluation and receive cryptographically signed decisions.

The client SDK is strictly Layer 1 (kernel) code and adheres to Gate G3 import
boundaries: no imports from Layer 2 (domain plugins), Layer 3 (integrations),
or vendor SDKs.
"""

from src.gateway.client.adapters.langgraph import cage_guard
from src.gateway.client.core import CageClient
from src.gateway.client.crypto import generate_w3c_traceparent
from src.gateway.client.envelope import ExecutionGrant, GovernanceEnvelope
from src.gateway.client.exceptions import (
    CageGatewayError,
    DeferralPending,
    PolicyViolationException,
    RoutingSealVerificationError,
)
from src.gateway.client.transport import create_mtls_transport

__version__ = "0.2.0"

__all__ = [
    "CageClient",
    "CageGatewayError",
    "DeferralPending",
    "ExecutionGrant",
    "GovernanceEnvelope",
    "PolicyViolationException",
    "RoutingSealVerificationError",
    "__version__",
    "cage_guard",
    "create_mtls_transport",
    "generate_w3c_traceparent",
]

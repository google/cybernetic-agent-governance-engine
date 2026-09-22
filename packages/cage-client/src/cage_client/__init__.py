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
CAGE Gateway Client SDK (`cage-client`).

Lightweight Python client SDK for interacting with the CAGE governance gateway.
Enables LangGraph / LangChain agents to submit actions for governance evaluation
and receive cryptographically signed decisions.
"""

from .adapters.langgraph import cage_guard
from .core import CageClient
from .crypto import generate_w3c_traceparent, verify_routing_seal
from .envelope import ExecutionGrant, GovernanceEnvelope
from .exceptions import (
    CageGatewayError,
    DeferralPending,
    PolicyViolationException,
    RoutingSealVerificationError,
)
from .transport import create_mtls_transport

__all__ = [
    "CageClient",
    "CageGatewayError",
    "DeferralPending",
    "ExecutionGrant",
    "GovernanceEnvelope",
    "PolicyViolationException",
    "RoutingSealVerificationError",
    "cage_guard",
    "create_mtls_transport",
    "generate_w3c_traceparent",
    "verify_routing_seal",
]

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
CAGE Client SDK Singleton for LangGraph Nodes.

This module provides a lazy-initialized CageClient instance shared across all
LangGraph node functions. All nodes decorated with @cage_guard must use this
singleton to ensure uniform governance semantics and avoid repeated client
initialization overhead.

Architecture Contract:
    - LangGraph agents are CLIENTS of the CAGE Gateway service
    - Even in-process deployments use localhost HTTP for clean boundaries
    - No direct calls to SymbolicGovernor.govern() or simulate_governance_check()
    - All governance routes through CageClient.validate_action() → Gateway PDP

Environment Variables:
    CAGE_GATEWAY_URL: Gateway HTTP endpoint (required)
        - Local dev: http://localhost:8000
        - GKE staging: http://cage-gateway-service.governance-stack:8000
        - Production: https://cage-gateway-prod.example.com
    
    ROUTING_SEAL_SECRET: HMAC-SHA256 shared secret for routing seal verification
        - Must match Gateway's ROUTING_SEAL_SECRET environment variable
        - Protects against response tampering in transit

Usage:
    from cage_client import cage_guard
    from src.governed_financial_advisor.graph.cage_client_singleton import get_cage_client
    
    @cage_guard(client=get_cage_client(), action="execute_trade")
    async def tool_executor_node(state: dict[str, Any]) -> dict[str, Any]:
        # Node executes only if governance allows
        return {"messages": [...]}
"""

import os

from src.gateway.client.core import CageClient

_client: CageClient | None = None


def get_cage_client() -> CageClient:
    """Lazy-initialized CAGE Gateway client singleton.
    
    Returns:
        CageClient instance configured from environment variables.
    
    Raises:
        RuntimeError: If CAGE_GATEWAY_URL or ROUTING_SEAL_SECRET are not set.
    
    Notes:
        - Thread-safe: Python's GIL ensures atomic assignment
        - Idempotent: Subsequent calls return the same instance
        - Fail-fast: Raises immediately on missing configuration
    """
    global _client
    
    if _client is None:
        # In test mode, provide defaults instead of failing
        cage_env = os.getenv("CAGE_ENV", "production")
        
        gateway_url = os.getenv("CAGE_GATEWAY_URL")
        if not gateway_url:
            if cage_env == "test":
                gateway_url = "http://localhost:8000"
            else:
                raise RuntimeError(
                    "CAGE_GATEWAY_URL must be set. Examples:\n"
                    "  - Local dev: CAGE_GATEWAY_URL=http://localhost:8000\n"
                    "  - GKE staging: CAGE_GATEWAY_URL=http://cage-gateway-service.governance-stack:8000\n"
                    "  - Production: CAGE_GATEWAY_URL=https://cage-gateway-prod.example.com\n"
                    "No in-process fallback — client-server separation is mandatory."
                )
        
        seal_secret = os.getenv("ROUTING_SEAL_SECRET")
        if not seal_secret:
            if cage_env == "test":
                seal_secret = "test-routing-seal-secret-for-unit-tests"
            else:
                raise RuntimeError(
                    "ROUTING_SEAL_SECRET must be set for routing seal verification.\n"
                    "This HMAC-SHA256 shared secret protects against response tampering."
                )
        
        _client = CageClient(
            gateway_url=gateway_url,
            routing_seal_secret=seal_secret,
        )
    
    return _client

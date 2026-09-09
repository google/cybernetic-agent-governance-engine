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
consequence_token_service.py — Kernel Service for ConsequenceToken Minting

Relocated from provider_01 adapter (Layer 3) to the kernel (Layer 1) per
Phase 8 of the layer inversion remediation plan.

Token minting is JCS canonicalization plus KMS signing — Layer 1 work that
must not be duplicated across vendor adapters. Adapters supply the five
claim inputs as plain data; the kernel mints, signs, and returns a finding.

This eliminates the service-locator anti-pattern (adapter calling
get_governance_signer()) and ensures cryptographic operations remain in the
kernel with centralized security controls.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from src.gateway.governance.consequence_token import ConsequenceToken
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.kms_signer import get_governance_signer

logger = logging.getLogger(__name__)

# Finding codes (matching provider_01 contract)
FINDING_CODE_CONSEQUENCE_TOKEN = "CONSEQUENCE_TOKEN"
FINDING_CODE_CONSEQUENCE_TOKEN_MINT_FAILED = "CONSEQUENCE_TOKEN_MINT_FAILED"


def mint_consequence_token_finding(
    *,
    actor_id: str,
    thread_id: str,
    authority_record_id: str,
    action_payload: dict[str, Any],
    authority_state_version: str | None = None,
    ttl_seconds: int = 60,
) -> dict[str, Any]:
    """Mint a ConsequenceToken and return it as a finding dict.

    This is the kernel service for ConsequenceToken minting, relocated from
    provider_01 (Layer 3) to eliminate the service-locator anti-pattern and
    centralize cryptographic signing in the kernel.

    Computes the action digest from the full action_payload (JCS + SHA-256),
    mints a KMS-signed JWS token, and returns a finding dict suitable for
    inclusion in ValidationResult.findings.

    Args:
        actor_id: Subject (actor making the request).
        thread_id: Thread ID (conversation/request identifier).
        authority_record_id: Authority record ID (single-use consumption key).
        action_payload: Full action context for digest computation (JCS-canonicalized).
        authority_state_version: Optional authority state version.
        ttl_seconds: Token time-to-live (default 60s per FlowSignal plan §5.4).

    Returns:
        A finding dict with code=CONSEQUENCE_TOKEN, severity=info, and the JWS
        token in the 'token' field. On mint failure (KMS error, validation),
        returns a fail-closed finding with code=CONSEQUENCE_TOKEN_MINT_FAILED,
        severity=blocked.

    Fail-closed behavior:
        If minting fails (KMS unavailable, missing required fields), returns a
        blocking finding rather than silently allowing execution without a token.

    Example:
        >>> finding = mint_consequence_token_finding(
        ...     actor_id="user-123",
        ...     thread_id="thread-abc",
        ...     authority_record_id="rec-xyz",
        ...     action_payload={"action": "execute_trade", ...},
        ... )
        >>> finding["code"]
        'CONSEQUENCE_TOKEN'
        >>> "token" in finding
        True
    """
    try:
        # Validate required inputs (fail-fast before KMS call)
        if not actor_id:
            raise ValueError("actor_id missing from action_payload")
        if not thread_id:
            raise ValueError("thread_id missing from action_payload")
        if not authority_record_id:
            raise ValueError("authority_record_id missing from FlowSignal response")
        if not action_payload:
            raise ValueError("action_payload is required")

        # Compute action digest: SHA-256 over JCS-canonicalized action_payload
        action_digest = hashlib.sha256(
            jcs_canonicalize_plan(action_payload)
        ).hexdigest()

        # Get kernel signer singleton
        signer = get_governance_signer()

        # Mint the token (60s TTL default per FlowSignal plan §5.4)
        token = ConsequenceToken.mint(
            sub=actor_id,
            tid=thread_id,
            rec=authority_record_id,
            act=action_digest,
            ver=authority_state_version,
            ttl_seconds=ttl_seconds,
            signer=signer,
        )

        # Return as an informational finding (does NOT block; admitted=True in caller)
        # The token travels with the execution plan to the consequence gateway
        return {
            "code": FINDING_CODE_CONSEQUENCE_TOKEN,
            "severity": "info",
            "token": token,
            "authority_record_id": authority_record_id,
            "message": "ConsequenceToken minted for post-FRIA consequence enforcement",
        }

    except Exception as exc:
        # Mint failure: fail-closed (return a blocking finding, not a silent admit)
        logger.error(
            "[consequence_token_service] ConsequenceToken minting failed: %s — fail-closed, blocking execution",
            exc,
        )
        return {
            "code": FINDING_CODE_CONSEQUENCE_TOKEN_MINT_FAILED,
            "severity": "blocked",
            "message": f"ConsequenceToken minting failed: {exc}",
        }

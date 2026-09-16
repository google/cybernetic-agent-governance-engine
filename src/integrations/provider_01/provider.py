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
provider.py — FlowSignal Normative Compliance Provider
======================================================

Production normative provider backed by external cloud API.
Extracted from ``src/gateway/governance/normative_provider.py`` for
vendor isolation.

Implements the 3-endpoint HTTP contract defined in §2.5.2 of
EXTENSIBILITY_ARCHITECTURE.md:
  - GET  /legal-baseline/{region}      → Normative Data Supply
  - POST /cage/validate                → External Validation (Phase 3 v0.2)
  - GET  /evidence-chain/{thread_id}   → Attestation Logging

Phase 3 v0.2 Schema Reconciliation
-----------------------------------
Provider now sends the full 37-field `CageAuthorityDetermineRequest` payload
to the `/cage/validate` endpoint (superseding the legacy 7-field `/validate/fria`).

See: docs/partners/FLOWSIGNAL_PHASE3_V02_SCHEMA.md § 2 for complete schema.

Authentication
--------------
Dual-header authentication supported for Cloud Run DRS ingress:
  - Authorization: Bearer {key} (FlowSignal application API key)
  - X-Serverless-Authorization: Bearer {token} (Google Cloud IAM identity token)

Key sourced from CAGE_NORMATIVE_API_KEY_SECRET (direct value or
Secret Manager path — Secret Manager resolution is deferred to
container init via Workload Identity).
GCP identity token sourced from CAGE_NORMATIVE_GCP_ID_TOKEN.

Environment variables
---------------------
  CAGE_NORMATIVE_ENDPOINT               — Base URL (required)
  CAGE_NORMATIVE_API_KEY_SECRET         — API key or Secret Manager path
  CAGE_NORMATIVE_GCP_ID_TOKEN           — Google IAM identity token for Cloud Run DRS (optional)
  CAGE_NORMATIVE_GATE_TIMEOUT_SECONDS   — Per-request timeout (default: 5)
  CAGE_NORMATIVE_VALIDATE_PATH          — Validation endpoint path (default: /cage/validate)

Status
------
**INTERFACE READY** — HTTP client is fully implemented.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

from src.gateway.governance.seams.normative import (
    EvidenceSeal,
    NormativeBaseline,
    ValidationResult,
)

logger = logging.getLogger("cage.integrations.provider_01")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_ENDPOINT: str = os.environ.get("CAGE_NORMATIVE_ENDPOINT", "").split("#")[0].strip()
_API_KEY_SECRET: str = (
    os.environ.get("CAGE_NORMATIVE_API_KEY_SECRET", "").split("#")[0].strip()
)
_GCP_ID_TOKEN: str = (
    os.environ.get("CAGE_NORMATIVE_GCP_ID_TOKEN", "").split("#")[0].strip()
)
_GATE_TIMEOUT_SECONDS: float = float(
    os.environ.get("CAGE_NORMATIVE_GATE_TIMEOUT_SECONDS", "5").split("#")[0].strip()
    or "5"
)
_VALIDATE_PATH: str = (
    os.environ.get("CAGE_NORMATIVE_VALIDATE_PATH", "/cage/validate")
    .split("#")[0]
    .strip()
)

# ---------------------------------------------------------------------------
# FlowSignal Decision Values (tri-state)
# ---------------------------------------------------------------------------

_FLOWSIGNAL_ALLOW = "ALLOW"
_FLOWSIGNAL_REFUSE = "REFUSE"
_FLOWSIGNAL_ESCALATE = "ESCALATE"

# Finding codes for FlowSignal decision mapping
FINDING_CODE_FLOWSIGNAL_REFUSE = "FLOWSIGNAL_REFUSE"
FINDING_CODE_EXTERNAL_HOLD = "EXTERNAL_HOLD"
FINDING_CODE_PARSE_ERROR = "PARSE_ERROR"


def _map_flowsignal_decision(
    decision: str, data: dict[str, Any], action_payload: dict[str, Any]
) -> tuple[bool, list[dict[str, Any]]]:
    """Map FlowSignal tri-state decision to CAGE (admitted, findings).

    This implements the ESCALATE contract mapping per §3.1 of the FlowSignal
    integration plan, mirroring provider_06's tri-state pattern.

    Phase 2 (ST-4): On ALLOW, mints a ConsequenceToken and attaches it as a
    CONSEQUENCE_TOKEN finding to enable post-FRIA consequence enforcement.

    Mapping logic:
      - ALLOW    → admitted=True, findings=[CONSEQUENCE_TOKEN] (ConsequenceToken JWS)
      - REFUSE   → admitted=False, findings with code=FLOWSIGNAL_REFUSE
      - ESCALATE → admitted=False, findings with code=EXTERNAL_HOLD,
                   needs_human_review=True for DeferQueue parking

    Args:
        decision: The FlowSignal decision value (ALLOW, REFUSE, ESCALATE).
        data: The full response payload (for extracting authority record context).
        action_payload: The original FRIA request payload (for extracting actor/thread
            context and computing the action digest).

    Returns:
        Tuple of (admitted: bool, findings: list[dict]).

    Raises:
        ValueError: If decision is unrecognized (fail-closed).
    """

    decision_upper = decision.upper().strip()

    if decision_upper == _FLOWSIGNAL_ALLOW:
        # ALLOW: admitted=True, with ConsequenceToken finding (Phase 2 ST-4)
        # Delegate to kernel minting service (relocated from this adapter)
        from src.gateway.governance.consequence_token_service import (
            mint_consequence_token_finding,
        )

        consequence_token_finding = mint_consequence_token_finding(
            actor_id=action_payload.get("actor_id", ""),
            thread_id=action_payload.get("thread_id", ""),
            authority_record_id=data.get("authority_record_id", ""),
            action_payload=action_payload,
            authority_state_version=data.get("authority_state_version"),
            ttl_seconds=60,
        )
        return True, [consequence_token_finding]

    if decision_upper == _FLOWSIGNAL_REFUSE:
        # REFUSE: hard deny with blocked severity
        message = data.get("message", "FlowSignal refused the transaction")
        return False, [
            {
                "code": FINDING_CODE_FLOWSIGNAL_REFUSE,
                "severity": "blocked",
                "message": message,
            }
        ]

    if decision_upper == _FLOWSIGNAL_ESCALATE:
        # ESCALATE: soft deny for human review (DeferQueue parking)
        message = data.get("message", "FlowSignal escalated — requires human approval")
        return False, [
            {
                "code": FINDING_CODE_EXTERNAL_HOLD,
                "severity": "review",
                "message": message,
                "needs_human_review": True,  # CAGE-specific extension for DeferQueue
                "hold_ttl_seconds": 300,  # 5-minute hold for FlowSignal escalations
            }
        ]

    # Unrecognized decision value: fail-closed
    raise ValueError(f"Unrecognized FlowSignal decision: {decision!r}")


def _build_cage_authority_request(envelope: dict[str, Any]) -> dict[str, Any]:
    """Build the complete 37-field CageAuthorityDetermineRequest payload.

    Maps CAGE GovernanceEnvelope fields to the FlowSignal Phase 3 v0.2 schema.
    See: docs/partners/FLOWSIGNAL_PHASE3_V02_SCHEMA.md § 2

    Args:
        envelope: The GovernanceEnvelope dict (or dict-like payload with CAGE fields).

    Returns:
        Complete 37-field payload dict ready for POST /cage/validate.
    """
    params = envelope.get("params", {})

    # Extract and format datetime fields (ISO 8601)
    now_iso = datetime.now(timezone.utc).isoformat()

    return {
        # Core Request Identifiers (3 fields)
        "approval_id": envelope.get("approval_id")
        or envelope.get("correlation_id", ""),
        "platform": "GOOGLE-CAGE-REFERENCE",
        "execution_id": envelope.get("correlation_id", ""),
        # Scenario & Action Context (4 fields)
        "scenario_id": envelope.get("thread_id", ""),
        "action": envelope.get("action", ""),
        "target": envelope.get("target", ""),
        "context": params.get("symbol") or params.get("purpose", ""),
        # Actor Identity & Authorization (5 fields)
        "actor_id": envelope.get("operator_urn", ""),
        "actor_type": "autonomous_agent",
        "actor_role": params.get("actor_role", "agent"),
        "actor_authenticated": True,
        "kya_status": "VERIFIED",
        # Principal (Institutional Context) (2 fields)
        "principal_id": params.get("principal_id", "cage-default"),
        "principal_name": params.get("principal_name", "CAGE Platform"),
        # Mandate Boundary & Limits (7 fields)
        "mandate_id": params.get("mandate_id", "DEFAULT-MANDATE"),
        "mandate_status": "ACTIVE",
        "mandate_max_amount": float(params.get("mandate_max_amount", 1000000.0)),
        "mandate_currency": params.get("currency", "USD"),
        "permitted_source_accounts": params.get(
            "permitted_source_accounts", ["DEFAULT"]
        ),
        "permitted_counterparty_class": params.get(
            "permitted_counterparty_class", "UNRESTRICTED"
        ),
        "mandate_valid_until": params.get(
            "mandate_valid_until", "2099-12-31T23:59:59Z"
        ),
        # Proposed Transaction Details (5 fields)
        "magnitude": float(params.get("amount", 0.0)),
        "currency": params.get("currency", "USD"),
        "source_account": params.get("source_account", "DEFAULT"),
        "beneficiary": params.get("beneficiary", "UNKNOWN"),
        "purpose": params.get("purpose", "CAGE transaction"),
        # Runtime State & Risk Context (4 fields)
        "counterparty_status": params.get("counterparty_status", "UNKNOWN"),
        "account_status": params.get("account_status", "ACTIVE"),
        "risk_state": params.get("risk_state", "NORMAL"),
        "approval_required": bool(params.get("approval_required", False)),
        # Mutable Evidence Freshness (4 fields)
        "screening_status": params.get("screening_status", "CLEAR"),
        "screening_captured_at": params.get("screening_captured_at", now_iso),
        "screening_max_age_seconds": int(params.get("screening_max_age_seconds", 3600)),
        "screening_source": params.get("screening_source", "CAGE-INTERNAL"),
        # Execution Timing (1 field)
        "requested_execution_time": params.get("requested_execution_time", now_iso),
        # Optional Fields (2 fields)
        "authority_resolution_path": None,
        "evidence_references": [
            {
                "type": "governance_decision",
                "uri": f"cer://{envelope.get('correlation_id', '')}",
            }
        ],
    }


# ---------------------------------------------------------------------------
# FlowSignal
# ---------------------------------------------------------------------------


class FlowSignalNormativeProvider:
    """Production normative provider backed by external cloud API.

    Implements the 3-endpoint HTTP contract defined in §2.5.2 of
    EXTENSIBILITY_ARCHITECTURE.md:
      - GET  /legal-baseline/{region}      → Normative Data Supply
      - POST /validate/fria                → External Validation
      - GET  /evidence-chain/{thread_id}   → Attestation Logging
    """

    def __init__(
        self,
        endpoint: str = "",
        api_key: str = "",
        timeout: float = _GATE_TIMEOUT_SECONDS,
        gcp_id_token: str = "",
    ) -> None:
        self._endpoint = (endpoint or _ENDPOINT).rstrip("/")
        self._api_key = api_key or _API_KEY_SECRET
        self._gcp_id_token = gcp_id_token or _GCP_ID_TOKEN
        self._timeout = timeout

        if not self._endpoint:
            logger.error(
                "[FlowSignal] CAGE_NORMATIVE_ENDPOINT is required. "
                "Set CAGE_NORMATIVE_PROVIDER=static for dev/test."
            )

        logger.info(
            "[FlowSignal] Initialised: endpoint=%s timeout=%.1fs gcp_iam=%s",
            self._endpoint or "(not set)",
            self._timeout,
            "configured" if self._gcp_id_token else "none",
        )

    def _headers(self) -> dict[str, str]:
        """Construct authorization headers supporting Cloud Run DRS dual-header auth."""
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        if self._gcp_id_token:
            headers["X-Serverless-Authorization"] = f"Bearer {self._gcp_id_token}"
        return headers

    async def fetch_baseline(self, region: str):  # type: ignore[no-untyped-def]
        """Fetch the active legal baseline from provider."""
        import httpx

        url = f"{self._endpoint}/legal-baseline/{quote(region, safe='')}"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(url, headers=self._headers())
                resp.raise_for_status()
                data = resp.json()
                return NormativeBaseline(
                    region=region,
                    profile=data.get("profile", data),
                    etag=resp.headers.get("ETag", ""),
                )
        except httpx.HTTPStatusError as exc:
            logger.error(
                "[FlowSignal] fetch_baseline HTTP error: %s status=%d",
                url,
                exc.response.status_code,
            )
            return NormativeBaseline(
                region=region,
                profile={},
                error=f"HTTP {exc.response.status_code}: {exc.response.text[:200]}",
            )
        except httpx.RequestError as exc:
            logger.error("[FlowSignal] fetch_baseline request error: %s %s", url, exc)
            return NormativeBaseline(region=region, profile={}, error=str(exc))
        except Exception as exc:
            logger.error(
                "[FlowSignal] fetch_baseline unexpected error: %s %s", url, exc
            )
            return NormativeBaseline(region=region, profile={}, error=str(exc))

    async def validate_fria(self, payload: dict[str, Any]):  # type: ignore[no-untyped-def]
        """Submit FRIA validation (synchronous blocking gate).

        Phase 3 v0.2 Schema Reconciliation:
        - Endpoint: POST /cage/validate (cutover from legacy /validate/fria)
        - Payload: Full 37-field CageAuthorityDetermineRequest

        Expects FlowSignal tri-state response: {"decision": "ALLOW|REFUSE|ESCALATE", ...}

        The ``decision`` field is mandatory. Missing or unrecognized values fail closed
        with structured findings (code="cage.endpoint_error" or "FINDING_CODE_PARSE_ERROR").

        Phase 2 (ST-4): On FlowSignal ALLOW, mints a ConsequenceToken and attaches
        it as a CONSEQUENCE_TOKEN finding in the returned ValidationResult.
        """
        import httpx

        # Build full 37-field payload per Phase 3 v0.2 schema
        cage_payload = _build_cage_authority_request(payload)

        url = f"{self._endpoint}{_VALIDATE_PATH}"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    url, json=cage_payload, headers=self._headers()
                )
                resp.raise_for_status()
                data = resp.json()

                # FlowSignal tri-state decision mapping (Phase 1, §3.1; Phase 2 ST-4)
                if "decision" in data:
                    decision = data["decision"]
                    try:
                        admitted, findings = _map_flowsignal_decision(
                            decision, data, payload
                        )
                        # Check if minting failed (fail-closed finding present)
                        from src.gateway.governance.consequence_token_service import (
                            FINDING_CODE_CONSEQUENCE_TOKEN_MINT_FAILED,
                        )

                        mint_failed = any(
                            f.get("code") == FINDING_CODE_CONSEQUENCE_TOKEN_MINT_FAILED
                            for f in findings
                        )
                        if mint_failed:
                            # Mint failure: override admitted=True to False (fail-closed)
                            admitted = False
                        return ValidationResult(admitted=admitted, findings=findings)
                    except ValueError as exc:
                        # Unrecognized decision value: fail-closed
                        logger.warning(
                            "[FlowSignal] FlowSignal decision parse error: %s",
                            exc,
                        )
                        return ValidationResult(
                            admitted=False,
                            error=str(exc),
                            findings=[
                                {
                                    "code": FINDING_CODE_PARSE_ERROR,
                                    "severity": "blocked",
                                    "message": f"Malformed FlowSignal decision: {decision!r}",
                                }
                            ],
                        )

                # Missing decision field: fail closed (BC-03 remediation)
                logger.warning(
                    "[FlowSignal] FlowSignal response missing 'decision' field — failing closed"
                )
                return ValidationResult(
                    admitted=False,
                    error="Missing required 'decision' field in FlowSignal response",
                    findings=[
                        {
                            "code": "cage.endpoint_error",
                            "severity": "blocked",
                            "message": "FlowSignal response missing required 'decision' field",
                        }
                    ],
                )
        except httpx.HTTPStatusError as exc:
            logger.error(
                "[FlowSignal] validate_fria HTTP error: %s status=%d",
                url,
                exc.response.status_code,
            )
            return ValidationResult(
                admitted=False,
                error=f"HTTP {exc.response.status_code}",
                findings=[
                    {
                        "code": "ENDPOINT_ERROR",
                        "severity": "blocked",
                        "message": f"FlowSignal HTTP error: {exc.response.status_code}",
                    }
                ],
            )
        except httpx.RequestError as exc:
            logger.error("[FlowSignal] validate_fria request error: %s %s", url, exc)
            return ValidationResult(
                admitted=False,
                error=str(exc),
                findings=[
                    {
                        "code": "ENDPOINT_ERROR",
                        "severity": "blocked",
                        "message": f"FlowSignal request failed: {exc}",
                    }
                ],
            )
        except Exception as exc:
            logger.error("[FlowSignal] validate_fria unexpected error: %s %s", url, exc)
            return ValidationResult(
                admitted=False,
                error=str(exc),
                findings=[
                    {
                        "code": "ENDPOINT_ERROR",
                        "severity": "blocked",
                        "message": f"FlowSignal unexpected error: {exc}",
                    }
                ],
            )

    async def submit_evidence(self, thread_id: str, evidence_hash: str):  # type: ignore[no-untyped-def]
        """Submit governance evidence hash for external sealing."""
        import httpx

        url = f"{self._endpoint}/evidence-chain/{quote(thread_id, safe='')}"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(
                    url,
                    headers=self._headers(),
                    params={"evidence_hash": evidence_hash},
                )
                resp.raise_for_status()
                data = resp.json()
                return EvidenceSeal(
                    thread_id=thread_id,
                    seal_hash=data.get("seal_hash", ""),
                )
        except httpx.HTTPStatusError as exc:
            logger.error(
                "[FlowSignal] submit_evidence HTTP error: %s status=%d",
                url,
                exc.response.status_code,
            )
            return EvidenceSeal(
                thread_id=thread_id,
                error=f"HTTP {exc.response.status_code}: {exc.response.text[:200]}",
            )
        except httpx.RequestError as exc:
            logger.error("[FlowSignal] submit_evidence request error: %s %s", url, exc)
            return EvidenceSeal(thread_id=thread_id, error=str(exc))
        except Exception as exc:
            logger.error(
                "[FlowSignal] submit_evidence unexpected error: %s %s", url, exc
            )
            return EvidenceSeal(thread_id=thread_id, error=str(exc))

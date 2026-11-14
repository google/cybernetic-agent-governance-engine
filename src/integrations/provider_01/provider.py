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
provider.py — Provider 01 Normative Compliance Provider
=======================================================

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

See: src/integrations/provider_01/README.md for complete schema.

Authentication
--------------
Dual-header authentication supported for Cloud Run DRS ingress:
  - Authorization: Bearer {key} (Provider 01 application API key)
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
  PROVIDER_01_CA_BUNDLE                 — Optional custom CA bundle path for mTLS verification
  PROVIDER_01_CLIENT_CERT               — Optional client certificate path for mTLS authentication
  PROVIDER_01_CLIENT_KEY                — Optional client private key path for mTLS authentication
  PROVIDER_01_CONTRACT_VERSION          — Wire contract mode: "v0.2" (default) or "v0.3" (strict)
  PROVIDER_01_BOUND_TARGET              — Server-configured target route required under "v0.3"

Status
------
**INTERFACE READY** — HTTP client is fully implemented.
"""

from __future__ import annotations

import logging
import math
import os
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from src.gateway.governance.seams.normative import (
    EvidenceSeal,
    NormativeBaseline,
    ValidationResult,
)

if TYPE_CHECKING:
    from src.gateway.governance.consequence_magnitude import ConsequenceMagnitudes

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
_CA_BUNDLE: str = os.environ.get("PROVIDER_01_CA_BUNDLE", "").split("#")[0].strip()
_CLIENT_CERT: str = os.environ.get("PROVIDER_01_CLIENT_CERT", "").split("#")[0].strip()
_CLIENT_KEY: str = os.environ.get("PROVIDER_01_CLIENT_KEY", "").split("#")[0].strip()

# ---------------------------------------------------------------------------
# Provider 01 Decision Values (tri-state)
# ---------------------------------------------------------------------------

_PROVIDER_01_ALLOW = "ALLOW"
_PROVIDER_01_REFUSE = "REFUSE"
_PROVIDER_01_ESCALATE = "ESCALATE"

# Supported wire contract versions (POAM-2026-113, POAM-2026-156 item 2, POAM-2026-218)
_CONTRACT_V02 = "v0.2"
_CONTRACT_V03 = "v0.3"
_SUPPORTED_CONTRACT_VERSIONS: frozenset[str] = frozenset({_CONTRACT_V02, _CONTRACT_V03})

# Finding codes for Provider 01 decision mapping & v0.3 pre-flight verification
FINDING_CODE_PROVIDER_01_REFUSE = "PROVIDER_01_REFUSE"
FINDING_CODE_EXTERNAL_HOLD = "EXTERNAL_HOLD"
FINDING_CODE_PARSE_ERROR = "PARSE_ERROR"
FINDING_CODE_TLS_CONFIG_ERROR = "TLS_CONFIG_ERROR"
FINDING_CODE_PROVIDER_01_UNVERIFIED_CALLER = "PROVIDER_01_UNVERIFIED_CALLER"
FINDING_CODE_PROVIDER_01_MISSING_VERIFIED_FACT = "PROVIDER_01_MISSING_VERIFIED_FACT"

# Explicit verified facts required in params under contract_version == "v0.3"
_REQUIRED_V03_FACT_FIELDS: tuple[str, ...] = (
    "mandate_id",
    "mandate_status",
    "mandate_max_amount",
    "mandate_valid_until",
    "permitted_source_accounts",
    "permitted_counterparty_class",
    "source_account",
    "beneficiary",
    "counterparty_status",
    "account_status",
    "screening_status",
    "screening_captured_at",
    "screening_max_age_seconds",
    "screening_source",
)


class _Provider01V03ValidationError(ValueError):
    """Fail-closed pre-flight validation error under Provider 01 strict v0.3 mode."""

    def __init__(
        self,
        *,
        code: str,
        message: str,
        missing_fields: tuple[str, ...] = (),
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.missing_fields = missing_fields


def _normalize_contract_version(contract_version: str | None) -> str:
    """Resolve and validate Provider 01 contract_version (fail-closed)."""
    if contract_version is None:
        raw = os.environ.get("PROVIDER_01_CONTRACT_VERSION", _CONTRACT_V02)
        normalized = raw.split("#")[0].strip().lower()
    elif isinstance(contract_version, str):
        normalized = contract_version.strip().lower()
    else:
        raise ValueError(
            f"Invalid Provider 01 contract_version: {contract_version!r} "
            f"(expected {_CONTRACT_V02!r} or {_CONTRACT_V03!r})"
        )

    if normalized not in _SUPPORTED_CONTRACT_VERSIONS:
        raise ValueError(
            f"Unsupported Provider 01 contract_version: {normalized!r} "
            f"(expected {_CONTRACT_V02!r} or {_CONTRACT_V03!r})"
        )
    return normalized


def _parse_iso8601_tz_aware(raw_value: Any) -> datetime | None:
    """Parse an ISO-8601 / RFC 3339 timestamp requiring an explicit UTC offset."""
    if not isinstance(raw_value, str):
        return None
    text = raw_value.strip()
    if not text or ("T" not in text and "t" not in text):
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def _parse_receipt_expiry_epoch(raw_value: Any, *, now_epoch: int) -> int | None:
    """Return epoch seconds for a future UTC-offset receipt expiry, else None."""
    parsed = _parse_iso8601_tz_aware(raw_value)
    if parsed is None:
        return None
    epoch = int(parsed.timestamp())
    if epoch <= now_epoch:
        return None
    return epoch


async def _map_provider_01_decision(
    decision: str,
    data: dict[str, Any],
    action_payload: dict[str, Any],
    *,
    magnitudes: ConsequenceMagnitudes | None,
    contract_version: str = _CONTRACT_V02,
) -> tuple[bool, list[dict[str, Any]]]:
    """Map Provider 01 tri-state decision to CAGE (admitted, findings).

    This implements the ESCALATE contract mapping per §3.1 of the Provider 01
    integration plan, mirroring provider_06's tri-state pattern.

    Phase 2 (ST-4): On ALLOW, mints a ConsequenceToken and attaches it as a
    CONSEQUENCE_TOKEN finding to enable post-FRIA consequence enforcement.

    Mapping logic:
      - ALLOW    → admitted=True, findings=[CONSEQUENCE_TOKEN] (ConsequenceToken JWS)
      - REFUSE   → admitted=False, findings with code=PROVIDER_01_REFUSE
      - ESCALATE → admitted=False, findings with code=EXTERNAL_HOLD,
                   needs_human_review=True for DeferQueue parking

    Args:
        decision: The Provider 01 decision value (ALLOW, REFUSE, ESCALATE).
        data: The full response payload (for extracting authority record context).
        action_payload: The original FRIA request payload (for extracting actor/thread
            context and computing the action digest).
        magnitudes: The declared consequence-magnitude policy, handed to the
            kernel mint service, which refuses to mint for magnitudes it
            rejects (and for every payload when it is ``None``). This adapter
            validates no domain magnitudes itself.

    Returns:
        Tuple of (admitted: bool, findings: list[dict]).

    Raises:
        ValueError: If decision is unrecognized (fail-closed).
    """

    decision_upper = decision.upper().strip()

    if decision_upper == _PROVIDER_01_ALLOW:
        # ALLOW: admitted=True, with ConsequenceToken finding (Phase 2 ST-4)
        # Delegate to kernel minting service (relocated from this adapter),
        # which also checks the declared consequence magnitudes.
        from src.gateway.governance.consequence_token_service import (
            FINDING_CODE_CONSEQUENCE_TOKEN_MINT_FAILED,
            mint_consequence_token_finding,
        )

        params = (
            action_payload.get("params", {})
            if isinstance(action_payload.get("params"), dict)
            else {}
        )
        raw_receipt_obj = data.get("authority_receipt")
        receipt_obj: dict[str, Any] = (
            raw_receipt_obj if isinstance(raw_receipt_obj, dict) else {}
        )
        receipt_id = str(
            receipt_obj.get("id") or data.get("authority_receipt_id") or ""
        ).strip()
        record_id = str(data.get("authority_record_id") or "").strip()
        # Single use is keyed per determination: rec is always the partner's
        # receipt id. authority_record_id may name the mandate, so it never
        # keys single use (two payments under one mandate would collide).
        if not receipt_id:
            return False, [
                {
                    "code": FINDING_CODE_CONSEQUENCE_TOKEN_MINT_FAILED,
                    "severity": "blocked",
                    "message": (
                        "Provider 01 ALLOW carries no authority receipt id "
                        "(authority_receipt.id or authority_receipt_id); single "
                        "use is keyed per determination"
                    ),
                }
            ]
        consumption_id = receipt_id

        raw_expiry: Any = None
        for candidate in (
            receipt_obj.get("valid_until"),
            receipt_obj.get("expires_at"),
            data.get("receipt_valid_until"),
        ):
            if candidate is not None and candidate != "":
                raw_expiry = candidate
                break

        now_epoch = int(time.time())
        receipt_expires_at = (
            _parse_receipt_expiry_epoch(raw_expiry, now_epoch=now_epoch)
            if raw_expiry is not None
            else None
        )
        if contract_version == _CONTRACT_V03 and receipt_expires_at is None:
            return False, [
                {
                    "code": FINDING_CODE_CONSEQUENCE_TOKEN_MINT_FAILED,
                    "severity": "blocked",
                    "message": (
                        "Provider 01 v0.3 ALLOW carries no valid receipt expiry "
                        "(authority_receipt.valid_until, authority_receipt.expires_at, "
                        "or receipt_valid_until)"
                    ),
                }
            ]

        actor_id = str(
            action_payload.get("actor_id") or action_payload.get("operator_urn") or ""
        )
        consequence_token_finding = await mint_consequence_token_finding(
            actor_id=actor_id,
            thread_id=action_payload.get("thread_id", ""),
            authority_record_id=consumption_id,
            action_payload=action_payload,
            magnitudes=magnitudes,
            authority_state_version=data.get("authority_state_version"),
            ttl_seconds=60,
            receipt_expires_at=receipt_expires_at,
        )
        consequence_token_finding["authority_receipt_id"] = receipt_id
        # The kernel finding names its single-use key authority_record_id, and
        # here that key is the receipt id. Report the partner's own
        # authority_record_id under that name instead, for audit only.
        if record_id:
            consequence_token_finding["authority_record_id"] = record_id
        else:
            consequence_token_finding.pop("authority_record_id", None)
        mandate_id = str(
            data.get("mandate_id") or params.get("mandate_id") or ""
        ).strip()
        if mandate_id:
            consequence_token_finding["mandate_id"] = mandate_id
        return True, [consequence_token_finding]

    if decision_upper == _PROVIDER_01_REFUSE:
        # REFUSE: hard deny with blocked severity
        message = data.get("message", "Provider 01 refused the transaction")
        return False, [
            {
                "code": FINDING_CODE_PROVIDER_01_REFUSE,
                "severity": "blocked",
                "message": message,
            }
        ]

    if decision_upper == _PROVIDER_01_ESCALATE:
        # ESCALATE: soft deny for human review (DeferQueue parking)
        message = data.get("message", "Provider 01 escalated — requires human approval")
        return False, [
            {
                "code": FINDING_CODE_EXTERNAL_HOLD,
                "severity": "review",
                "message": message,
                "needs_human_review": True,  # CAGE-specific extension for DeferQueue
                "hold_ttl_seconds": 300,  # 5-minute hold for Provider 01 escalations
            }
        ]

    # Unrecognized decision value: fail-closed
    raise ValueError(f"Unrecognized Provider 01 decision: {decision!r}")


def _validate_v03_params_facts(params: dict[str, Any]) -> list[str]:
    """Return missing or invalid verified fact field names under v0.3 strict mode."""
    missing: list[str] = []
    for field_name in _REQUIRED_V03_FACT_FIELDS:
        val = params.get(field_name)
        if field_name == "mandate_max_amount":
            if (
                isinstance(val, bool)
                or not isinstance(val, (int, float))
                or not math.isfinite(float(val))
                or float(val) <= 0.0
            ):
                missing.append(field_name)
        elif field_name == "permitted_source_accounts":
            if (
                not isinstance(val, list)
                or len(val) == 0
                or not all(isinstance(item, str) and bool(item.strip()) for item in val)
            ):
                missing.append(field_name)
        elif field_name in ("mandate_valid_until", "screening_captured_at"):
            if _parse_iso8601_tz_aware(val) is None:
                missing.append(field_name)
        elif field_name == "screening_max_age_seconds":
            if isinstance(val, bool) or not isinstance(val, int) or val <= 0:
                missing.append(field_name)
        else:
            if not isinstance(val, str) or not val.strip():
                missing.append(field_name)
    return missing


def _build_cage_authority_request(
    envelope: dict[str, Any],
    *,
    contract_version: str = _CONTRACT_V02,
    bound_target: str = "",
) -> dict[str, Any]:
    """Build the complete 37-field CageAuthorityDetermineRequest payload.

    Maps CAGE GovernanceEnvelope fields to the Provider 01 Phase 3 v0.2 (default)
    or opt-in strict v0.3 schema.
    See: src/integrations/provider_01/README.md

    Args:
        envelope: The GovernanceEnvelope dict (or dict-like payload with CAGE fields).
        contract_version: Wire contract version ("v0.2" or "v0.3").
        bound_target: Server-configured target route (required under "v0.3";
            never sourced from caller-controlled params["target"]).

    Returns:
        Complete 37-field payload dict ready for POST /cage/validate.
    """
    resolved_version = _normalize_contract_version(contract_version)
    raw_params = envelope.get("params", {})
    params: dict[str, Any] = raw_params if isinstance(raw_params, dict) else {}

    # Extract and format datetime fields (ISO 8601)
    now_iso = datetime.now(timezone.utc).isoformat()

    if resolved_version == _CONTRACT_V03:
        raw_operator_urn = envelope.get("operator_urn")
        raw_actor_id = envelope.get("actor_id")
        operator_urn = (
            raw_operator_urn.strip() if isinstance(raw_operator_urn, str) else ""
        )
        actor_id = raw_actor_id.strip() if isinstance(raw_actor_id, str) else ""
        if operator_urn and actor_id and operator_urn != actor_id:
            raise _Provider01V03ValidationError(
                code=FINDING_CODE_PROVIDER_01_UNVERIFIED_CALLER,
                message=(
                    "Provider 01 v0.3 rejected conflicting operator_urn and actor_id "
                    "in governance envelope"
                ),
            )
        verified_actor = operator_urn or actor_id
        if not verified_actor:
            raise _Provider01V03ValidationError(
                code=FINDING_CODE_PROVIDER_01_UNVERIFIED_CALLER,
                message=(
                    "Provider 01 v0.3 requires a verified server-bound caller identity "
                    "(operator_urn or actor_id)"
                ),
            )

        clean_bound_target = (
            bound_target.strip() if isinstance(bound_target, str) else ""
        )
        missing_fields: list[str] = []
        if not clean_bound_target:
            missing_fields.append("bound_target")
        missing_fields.extend(_validate_v03_params_facts(params))
        if missing_fields:
            missing_tuple = tuple(missing_fields)
            raise _Provider01V03ValidationError(
                code=FINDING_CODE_PROVIDER_01_MISSING_VERIFIED_FACT,
                message=(
                    "Provider 01 v0.3 requires explicit verified facts and server-bound "
                    f"target; missing or invalid: {', '.join(missing_tuple)}"
                ),
                missing_fields=missing_tuple,
            )

        is_verified_caller = bool(verified_actor)
        return {
            # Core Request Identifiers (3 fields)
            "approval_id": str(
                params.get("approval_id") or envelope.get("correlation_id", "")
            ),
            "platform": "GOOGLE-CAGE-REFERENCE",
            "execution_id": str(envelope.get("correlation_id", "")),
            # Scenario & Action Context (4 fields)
            "scenario_id": str(envelope.get("thread_id", "")),
            "action": str(envelope.get("action", "")),
            # Strictly server-configured bound_target; NEVER params["target"] (POAM-2026-113)
            "target": clean_bound_target,
            "context": str(params.get("symbol") or params.get("purpose", "")),
            # Actor Identity & Authorization (5 fields) — derived strictly from verified identity
            "actor_id": verified_actor,
            "actor_type": "autonomous_agent",
            "actor_role": str(params.get("actor_role", "agent")),
            "actor_authenticated": is_verified_caller,
            "kya_status": "VERIFIED" if is_verified_caller else "UNVERIFIED",
            # Principal (Institutional Context) (2 fields)
            "principal_id": str(params.get("principal_id", "cage-default")),
            "principal_name": str(params.get("principal_name", "CAGE Platform")),
            # Mandate Boundary & Limits (7 fields) — explicit verified facts only
            "mandate_id": params["mandate_id"].strip(),
            "mandate_status": params["mandate_status"].strip(),
            "mandate_max_amount": float(params["mandate_max_amount"]),
            "mandate_currency": str(
                params.get("mandate_currency") or params.get("currency", "USD")
            ),
            "permitted_source_accounts": [
                item.strip() for item in params["permitted_source_accounts"]
            ],
            "permitted_counterparty_class": params[
                "permitted_counterparty_class"
            ].strip(),
            "mandate_valid_until": params["mandate_valid_until"].strip(),
            # Proposed Transaction Details (5 fields)
            "magnitude": float(params.get("amount", 0.0)),
            "currency": str(params.get("currency", "USD")),
            "source_account": params["source_account"].strip(),
            "beneficiary": params["beneficiary"].strip(),
            "purpose": str(params.get("purpose", "CAGE transaction")),
            # Runtime State & Risk Context (4 fields) — explicit verified facts only
            "counterparty_status": params["counterparty_status"].strip(),
            "account_status": params["account_status"].strip(),
            "risk_state": str(params.get("risk_state", "NORMAL")),
            "approval_required": bool(params.get("approval_required", False)),
            # Mutable Evidence Freshness (4 fields) — explicit verified facts only
            "screening_status": params["screening_status"].strip(),
            "screening_captured_at": params["screening_captured_at"].strip(),
            "screening_max_age_seconds": int(params["screening_max_age_seconds"]),
            "screening_source": params["screening_source"].strip(),
            # Execution Timing (1 field)
            "requested_execution_time": str(
                params.get("requested_execution_time", now_iso)
            ),
            # Optional Fields (2 fields)
            "authority_resolution_path": None,
            "evidence_references": [
                {
                    "type": "governance_decision",
                    "uri": f"cer://{envelope.get('correlation_id', '')}",
                }
            ],
        }

    return {
        # Core Request Identifiers (3 fields)
        # Caller-supplied action arguments arrive inside envelope["params"]
        # (FriaTier._payload); fall back to correlation_id when absent.
        "approval_id": str(
            params.get("approval_id") or envelope.get("correlation_id", "")
        ),
        "platform": "GOOGLE-CAGE-REFERENCE",
        "execution_id": envelope.get("correlation_id", ""),
        # Scenario & Action Context (4 fields)
        "scenario_id": envelope.get("thread_id", ""),
        "action": envelope.get("action", ""),
        # Sourced from envelope["params"] (never from a top-level envelope key
        # that FriaTier._payload does not emit; see POAM-2026-113 / POAM-2026-157).
        "target": str(params.get("target", "")),
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
# Provider 01
# ---------------------------------------------------------------------------


class Provider01NormativeProvider:
    """Production normative provider backed by external cloud API.

    Implements the 3-endpoint HTTP contract defined in §2.5.2 of
    EXTENSIBILITY_ARCHITECTURE.md:
      - GET  /legal-baseline/{region}      → Normative Data Supply
      - POST /cage/validate                → External Validation (Phase 3 v0.2)
      - GET  /evidence-chain/{thread_id}   → Attestation Logging
    """

    def __init__(
        self,
        endpoint: str = "",
        api_key: str = "",
        timeout: float = _GATE_TIMEOUT_SECONDS,
        gcp_id_token: str = "",
        ca_bundle: str = "",
        client_cert: str = "",
        client_key: str = "",
        *,
        consequence_magnitudes: ConsequenceMagnitudes | None = None,
        contract_version: str | None = None,
        bound_target: str | None = None,
    ) -> None:
        """Configure the adapter.

        ``consequence_magnitudes`` is the domain's declared policy
        (``get_normative_provider(consequence_magnitudes=...)`` passes the
        governor's). The kernel mint service applies it on every ALLOW;
        without it no ConsequenceToken is minted and every ALLOW fails
        closed.

        ``contract_version`` selects ``"v0.2"`` (default compatibility path) or
        ``"v0.3"`` (strict verified-fact and mandatory receipt-expiry mode);
        any other value raises ``ValueError`` fail-closed.
        """
        self._contract_version = _normalize_contract_version(contract_version)
        if bound_target is None:
            resolved_target = (
                os.environ.get("PROVIDER_01_BOUND_TARGET", "").split("#")[0].strip()
            )
        elif isinstance(bound_target, str):
            resolved_target = bound_target.strip()
        else:
            raise ValueError(
                f"Invalid Provider 01 bound_target: {bound_target!r} (expected str)"
            )
        self._bound_target = resolved_target
        self._consequence_magnitudes = consequence_magnitudes
        self._endpoint = (endpoint or _ENDPOINT).rstrip("/")
        self._api_key = api_key or _API_KEY_SECRET
        self._gcp_id_token = gcp_id_token or _GCP_ID_TOKEN
        self._timeout = timeout
        self._ca_bundle = ca_bundle or _CA_BUNDLE
        self._client_cert = client_cert or _CLIENT_CERT
        self._client_key = client_key or _CLIENT_KEY

        if not self._endpoint:
            logger.error(
                "[provider_01] CAGE_NORMATIVE_ENDPOINT is required. "
                "Set CAGE_NORMATIVE_PROVIDER=static for dev/test."
            )

        logger.info(
            "[provider_01] Initialised: endpoint=%s contract=%s timeout=%.1fs gcp_iam=%s mtls=%s",
            self._endpoint or "(not set)",
            self._contract_version,
            self._timeout,
            "configured" if self._gcp_id_token else "none",
            "configured" if (self._client_cert or self._ca_bundle) else "none",
        )

    @property
    def contract_version(self) -> str:
        """Active wire contract version ('v0.2' or 'v0.3')."""
        return self._contract_version

    @property
    def bound_target(self) -> str:
        """Server-configured target route used in strict v0.3 mode."""
        return self._bound_target

    def _validate_tls_config(self) -> str | None:
        """Validate mTLS configuration invariants (fail-closed on incomplete or plain HTTP config).

        Returns:
            None if configuration is valid, or a descriptive error string if invalid.
        """
        if bool(self._client_cert) != bool(self._client_key):
            return (
                "Incomplete mTLS configuration: PROVIDER_01_CLIENT_CERT and "
                "PROVIDER_01_CLIENT_KEY must both be provided together"
            )

        has_tls_material = bool(
            self._ca_bundle or self._client_cert or self._client_key
        )
        if has_tls_material and self._endpoint.lower().startswith("http://"):
            return (
                "Plain HTTP endpoint rejected when mTLS/TLS material is configured; "
                "https:// is required"
            )

        return None

    def _client_kwargs(self) -> dict[str, Any]:
        """Build httpx.AsyncClient keyword arguments including optional mTLS material."""
        kwargs: dict[str, Any] = {"timeout": self._timeout}
        if self._ca_bundle:
            kwargs["verify"] = self._ca_bundle
        if self._client_cert and self._client_key:
            kwargs["cert"] = (self._client_cert, self._client_key)
        return kwargs

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

        tls_error = self._validate_tls_config()
        if tls_error:
            logger.error("[provider_01] fetch_baseline TLS config error: %s", tls_error)
            return NormativeBaseline(region=region, profile={}, error=tls_error)

        url = f"{self._endpoint}/legal-baseline/{quote(region, safe='')}"
        try:
            async with httpx.AsyncClient(**self._client_kwargs()) as client:
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
                "[provider_01] fetch_baseline HTTP error: %s status=%d",
                url,
                exc.response.status_code,
            )
            return NormativeBaseline(
                region=region,
                profile={},
                error=f"HTTP {exc.response.status_code}: {exc.response.text[:200]}",
            )
        except httpx.RequestError as exc:
            logger.error("[provider_01] fetch_baseline request error: %s %s", url, exc)
            return NormativeBaseline(region=region, profile={}, error=str(exc))
        except Exception as exc:
            logger.error(
                "[provider_01] fetch_baseline unexpected error: %s %s", url, exc
            )
            return NormativeBaseline(region=region, profile={}, error=str(exc))

    async def validate_fria(self, payload: dict[str, Any]):  # type: ignore[no-untyped-def]
        """Submit FRIA validation (synchronous blocking gate).

        Phase 3 v0.2 Schema Reconciliation:
        - Endpoint: POST /cage/validate (cutover from legacy /validate/fria)
        - Payload: Full 37-field CageAuthorityDetermineRequest

        Expects Provider 01 tri-state response: {"decision": "ALLOW|REFUSE|ESCALATE", ...}

        The ``decision`` field is mandatory. Missing or unrecognized values fail closed
        with structured findings (code="cage.endpoint_error" or "FINDING_CODE_PARSE_ERROR").

        Phase 2 (ST-4): On Provider 01 ALLOW, mints a ConsequenceToken and attaches
        it as a CONSEQUENCE_TOKEN finding in the returned ValidationResult.
        """
        import httpx

        tls_error = self._validate_tls_config()
        if tls_error:
            logger.error("[provider_01] validate_fria TLS config error: %s", tls_error)
            return ValidationResult(
                admitted=False,
                error=tls_error,
                findings=[
                    {
                        "code": FINDING_CODE_TLS_CONFIG_ERROR,
                        "severity": "blocked",
                        "message": tls_error,
                    }
                ],
            )

        # Pre-flight strict JSON validation. Magnitudes are not validated
        # here: the kernel checks the declared ones before the call (the
        # jurisdiction tier) and again at minting.
        from src.gateway.governance.consequence_token_service import (
            FINDING_CODE_CONSEQUENCE_TOKEN_MINT_FAILED,
        )
        from src.gateway.governance.routing_seal import _strict_json

        try:
            _strict_json(payload, "payload")
        except (TypeError, ValueError) as exc:
            return ValidationResult(
                admitted=False,
                error=str(exc),
                findings=[
                    {
                        "code": FINDING_CODE_CONSEQUENCE_TOKEN_MINT_FAILED,
                        "severity": "blocked",
                        "message": str(exc),
                    }
                ],
            )

        # Build full 37-field payload per active contract_version ("v0.2" or "v0.3").
        # Under "v0.3", unverified callers, missing server-bound target, or missing
        # verified facts fail closed BEFORE opening any HTTP connection.
        try:
            cage_payload = _build_cage_authority_request(
                payload,
                contract_version=self._contract_version,
                bound_target=self._bound_target,
            )
        except _Provider01V03ValidationError as exc:
            finding_entry: dict[str, Any] = {
                "code": exc.code,
                "severity": "blocked",
                "message": exc.message,
            }
            if exc.missing_fields:
                finding_entry["missing_fields"] = list(exc.missing_fields)
            return ValidationResult(
                admitted=False,
                error=exc.message,
                findings=[finding_entry],
            )

        url = f"{self._endpoint}{_VALIDATE_PATH}"
        try:
            async with httpx.AsyncClient(**self._client_kwargs()) as client:
                resp = await client.post(
                    url, json=cage_payload, headers=self._headers()
                )
                resp.raise_for_status()
                data = resp.json()

                # Provider 01 tri-state decision mapping (Phase 1, §3.1; Phase 2 ST-4)
                if "decision" in data:
                    decision = data["decision"]
                    try:
                        admitted, findings = await _map_provider_01_decision(
                            decision,
                            data,
                            payload,
                            magnitudes=self._consequence_magnitudes,
                            contract_version=self._contract_version,
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
                            "[provider_01] Provider 01 decision parse error: %s",
                            exc,
                        )
                        return ValidationResult(
                            admitted=False,
                            error=str(exc),
                            findings=[
                                {
                                    "code": FINDING_CODE_PARSE_ERROR,
                                    "severity": "blocked",
                                    "message": f"Malformed Provider 01 decision: {decision!r}",
                                }
                            ],
                        )

                # Missing decision field: fail closed (BC-03 remediation)
                logger.warning(
                    "[provider_01] Provider 01 response missing 'decision' field — failing closed"
                )
                return ValidationResult(
                    admitted=False,
                    error="Missing required 'decision' field in Provider 01 response",
                    findings=[
                        {
                            "code": "cage.endpoint_error",
                            "severity": "blocked",
                            "message": "Provider 01 response missing required 'decision' field",
                        }
                    ],
                )
        except httpx.HTTPStatusError as exc:
            logger.error(
                "[provider_01] validate_fria HTTP error: %s status=%d",
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
                        "message": f"Provider 01 HTTP error: {exc.response.status_code}",
                    }
                ],
            )
        except httpx.RequestError as exc:
            logger.error("[provider_01] validate_fria request error: %s %s", url, exc)
            return ValidationResult(
                admitted=False,
                error=str(exc),
                findings=[
                    {
                        "code": "ENDPOINT_ERROR",
                        "severity": "blocked",
                        "message": f"Provider 01 request failed: {exc}",
                    }
                ],
            )
        except Exception as exc:
            logger.error(
                "[provider_01] validate_fria unexpected error: %s %s", url, exc
            )
            return ValidationResult(
                admitted=False,
                error=str(exc),
                findings=[
                    {
                        "code": "ENDPOINT_ERROR",
                        "severity": "blocked",
                        "message": f"Provider 01 unexpected error: {exc}",
                    }
                ],
            )

    async def submit_evidence(self, thread_id: str, evidence_hash: str):  # type: ignore[no-untyped-def]
        """Submit governance evidence hash for external sealing."""
        import httpx

        tls_error = self._validate_tls_config()
        if tls_error:
            logger.error(
                "[provider_01] submit_evidence TLS config error: %s", tls_error
            )
            return EvidenceSeal(thread_id=thread_id, error=tls_error)

        url = f"{self._endpoint}/evidence-chain/{quote(thread_id, safe='')}"
        try:
            async with httpx.AsyncClient(**self._client_kwargs()) as client:
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
                "[provider_01] submit_evidence HTTP error: %s status=%d",
                url,
                exc.response.status_code,
            )
            return EvidenceSeal(
                thread_id=thread_id,
                error=f"HTTP {exc.response.status_code}: {exc.response.text[:200]}",
            )
        except httpx.RequestError as exc:
            logger.error("[provider_01] submit_evidence request error: %s %s", url, exc)
            return EvidenceSeal(thread_id=thread_id, error=str(exc))
        except Exception as exc:
            logger.error(
                "[provider_01] submit_evidence unexpected error: %s %s", url, exc
            )
            return EvidenceSeal(thread_id=thread_id, error=str(exc))

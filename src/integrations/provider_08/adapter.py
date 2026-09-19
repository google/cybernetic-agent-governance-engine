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
provider_08 — Verdict Runtime Evidence Normative Provider Adapter
==================================================================

Implements the three-endpoint ``NormativeProvider`` seam against Verdict
(https://verdict.systems/api/cage):

  - GET  /legal-baseline/{region}       → Normative Data Supply
  - POST /validate/fria                 → External Validation (sync gate)
  - GET  /evidence-chain/{thread_id}    → Attestation Logging

Decision mapping (mirrors provider_01 / provider_07 tri-state contract):

  ALLOW     → kernel mints a ConsequenceToken bound to Verdict's
              ``authority_record_id``; mint failure fails closed.
  REFUSE    → admitted=False, finding ``PROVIDER_08_REFUSE`` (blocked).
  ESCALATE  → admitted=False, finding ``EXTERNAL_HOLD`` with
              ``needs_human_review=True`` and Verdict's ``hold_ttl_seconds``
              (default 300) for DeferQueue parking.
  HTTP/timeout error → ``ENDPOINT_ERROR``; malformed body → ``PARSE_ERROR``.

Environment variables (``from_env()``):

  PROVIDER_08_ENDPOINT           — Base URL (falls back to
                                    CAGE_NORMATIVE_ENDPOINT; default
                                    http://localhost:8088 for hermetic tests)
  PROVIDER_08_API_KEY            — Bearer key (falls back to
                                    CAGE_NORMATIVE_API_KEY_SECRET)
  PROVIDER_08_TIMEOUT_SECONDS    — HTTP timeout (default 5.0)
  PROVIDER_08_REQUIRE_ANCHOR     — "true" to fail closed when Verdict reports
                                    the Rekor anchor as deferred (default false)

The adapter never raises across the seam: every failure is captured in the
returned dataclass (``error`` field or a blocking finding).
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Final
from urllib.parse import quote

import httpx
from pydantic import ValidationError

from src.gateway.governance.seams.normative import (
    EvidenceSeal,
    NormativeBaseline,
    ValidationResult,
)

from .schema import (
    VerdictBaselineResponse,
    VerdictEvidenceSealResponse,
    VerdictFriaResponse,
)

logger = logging.getLogger("cage.integrations.provider_08")

FINDING_CODE_ENDPOINT_ERROR: Final[str] = "ENDPOINT_ERROR"
FINDING_CODE_PARSE_ERROR: Final[str] = "PARSE_ERROR"
FINDING_CODE_REFUSE: Final[str] = "PROVIDER_08_REFUSE"
FINDING_CODE_EXTERNAL_HOLD: Final[str] = "EXTERNAL_HOLD"
FINDING_CODE_ANCHOR_DEFERRED: Final[str] = "PROVIDER_08_ANCHOR_DEFERRED"

_DEFAULT_ENDPOINT: Final[str] = "http://localhost:8088"
_DEFAULT_HOLD_TTL_SECONDS: Final[int] = 300
_CONSEQUENCE_TOKEN_TTL_SECONDS: Final[int] = 60


def _env(*names: str, default: str = "") -> str:
    for name in names:
        value = os.environ.get(name, "")
        value = value.split("#")[0].strip()
        if value:
            return value
    return default


def _first_str(payload: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    params = payload.get("params")
    if isinstance(params, dict):
        for key in keys:
            value = params.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


class Provider08NormativeProvider:
    """Verdict Systems runtime-evidence ``NormativeProvider`` (slot ``provider_08``)."""

    def __init__(
        self,
        endpoint: str = "",
        api_key: str = "",
        timeout_seconds: float = 5.0,
        require_anchor: bool = False,
    ) -> None:
        self._endpoint = (endpoint or _DEFAULT_ENDPOINT).rstrip("/")
        self._api_key = api_key
        self._timeout = timeout_seconds
        self._require_anchor = require_anchor
        if not api_key:
            logger.warning(
                "provider_08: no API key configured — keyed Verdict endpoints "
                "answer 401/503 and every gate call will fail closed."
            )

    @classmethod
    def from_env(cls) -> Provider08NormativeProvider:
        """Construct from ``PROVIDER_08_*`` (falling back to ``CAGE_NORMATIVE_*``)."""
        return cls(
            endpoint=_env(
                "PROVIDER_08_ENDPOINT",
                "CAGE_NORMATIVE_ENDPOINT",
                default=_DEFAULT_ENDPOINT,
            ),
            api_key=_env("PROVIDER_08_API_KEY", "CAGE_NORMATIVE_API_KEY_SECRET"),
            timeout_seconds=float(_env("PROVIDER_08_TIMEOUT_SECONDS", default="5.0")),
            require_anchor=_env("PROVIDER_08_REQUIRE_ANCHOR", default="false").lower()
            in {"1", "true", "yes"},
        )

    @property
    def endpoint(self) -> str:
        return self._endpoint

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    # -- GET /legal-baseline/{region} ----------------------------------------

    async def fetch_baseline(self, region: str) -> NormativeBaseline:
        """Fetch the regional control-mapping profile.

        Verdict's strong ETag equals the SHA-256 of the canonical profile, so
        ``NormativeDaemon`` change detection works on either field.
        """
        url = f"{self._endpoint}/legal-baseline/{quote(region, safe='')}"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(url, headers=self._headers())
                resp.raise_for_status()
                parsed = VerdictBaselineResponse(**resp.json())
            etag = resp.headers.get("ETag", "").strip('"') or parsed.profile_sha256
            return NormativeBaseline(
                region=region,
                profile=parsed.profile,
                fetched_at=time.time(),
                etag=etag,
            )
        except httpx.HTTPStatusError as exc:
            msg = f"HTTP {exc.response.status_code}: {exc.response.text[:200]}"
            logger.error("provider_08: fetch_baseline %s → %s", url, msg)
            return NormativeBaseline(region=region, profile={}, error=msg)
        except (httpx.HTTPError, ValidationError, ValueError) as exc:
            logger.error("provider_08: fetch_baseline %s failed: %s", url, exc)
            return NormativeBaseline(region=region, profile={}, error=str(exc))

    # -- POST /validate/fria --------------------------------------------------

    async def validate_fria(self, payload: dict[str, Any]) -> ValidationResult:
        """Submit CAGE's ``action_context`` unchanged for the synchronous gate."""
        url = f"{self._endpoint}/validate/fria"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(url, json=payload, headers=self._headers())
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as exc:
            msg = f"HTTP {exc.response.status_code}: {exc.response.text[:200]}"
            logger.error("provider_08: validate_fria %s → %s", url, msg)
            return self._blocked(FINDING_CODE_ENDPOINT_ERROR, msg)
        except (httpx.HTTPError, ValueError) as exc:
            logger.error("provider_08: validate_fria %s failed: %s", url, exc)
            return self._blocked(FINDING_CODE_ENDPOINT_ERROR, str(exc))

        try:
            parsed = VerdictFriaResponse(**data)
        except (ValidationError, TypeError) as exc:
            logger.warning("provider_08: malformed FRIA response: %s", exc)
            return self._blocked(
                FINDING_CODE_PARSE_ERROR,
                f"Malformed Verdict FRIA response: {exc}",
            )

        provider_findings = [
            {**f.model_dump(exclude_none=True), "provider": "provider_08"}
            for f in parsed.findings
        ]

        if parsed.decision == "ALLOW":
            from src.gateway.governance.consequence_token_service import (
                FINDING_CODE_CONSEQUENCE_TOKEN_MINT_FAILED,
                mint_consequence_token_finding,
            )

            token_finding = mint_consequence_token_finding(
                actor_id=_first_str(
                    payload, "agent_id", "actor_id", "operator_urn", "executor_id"
                ),
                thread_id=_first_str(payload, "thread_id", "correlation_id"),
                authority_record_id=parsed.authority_record_id,
                action_payload=payload,
                authority_state_version=parsed.authority_state_version,
                ttl_seconds=_CONSEQUENCE_TOKEN_TTL_SECONDS,
            )
            admitted = (
                token_finding.get("code") != FINDING_CODE_CONSEQUENCE_TOKEN_MINT_FAILED
            )
            return ValidationResult(
                admitted=admitted, findings=[token_finding, *provider_findings]
            )

        if parsed.decision == "REFUSE":
            return ValidationResult(
                admitted=False,
                findings=[
                    {
                        "code": FINDING_CODE_REFUSE,
                        "status": "fail",
                        "severity": "blocked",
                        "message": parsed.message or "Verdict refused the action",
                        "authority_record_id": parsed.authority_record_id,
                    },
                    *provider_findings,
                ],
            )

        # ESCALATE — park in the DeferQueue for human review.
        return ValidationResult(
            admitted=False,
            findings=[
                {
                    "code": FINDING_CODE_EXTERNAL_HOLD,
                    "status": "fail",
                    "severity": "review",
                    "message": parsed.message or "Verdict escalated — human review",
                    "needs_human_review": True,
                    "hold_ttl_seconds": parsed.hold_ttl_seconds
                    or _DEFAULT_HOLD_TTL_SECONDS,
                    "authority_record_id": parsed.authority_record_id,
                },
                *provider_findings,
            ],
        )

    # -- GET /evidence-chain/{thread_id} --------------------------------------

    async def submit_evidence(self, thread_id: str, evidence_hash: str) -> EvidenceSeal:
        """Seal the local evidence digest into a Verdict record held externally."""
        url = f"{self._endpoint}/evidence-chain/{quote(thread_id, safe='')}"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(
                    url,
                    headers=self._headers(),
                    params={"evidence_hash": evidence_hash},
                )
                resp.raise_for_status()
                parsed = VerdictEvidenceSealResponse(**resp.json())
        except httpx.HTTPStatusError as exc:
            msg = f"HTTP {exc.response.status_code}: {exc.response.text[:200]}"
            logger.error("provider_08: submit_evidence %s → %s", url, msg)
            return EvidenceSeal(thread_id=thread_id, error=msg)
        except (httpx.HTTPError, ValidationError, ValueError) as exc:
            logger.error("provider_08: submit_evidence %s failed: %s", url, exc)
            return EvidenceSeal(thread_id=thread_id, error=str(exc))

        anchor = parsed.transparency_anchor or {}
        if self._require_anchor and anchor.get("status") != "anchored":
            reason = anchor.get("reason", "no transparency anchor")
            logger.warning(
                "provider_08: anchor deferred for thread=%s (%s) — failing closed",
                thread_id,
                reason,
            )
            return EvidenceSeal(
                thread_id=thread_id,
                seal_hash=parsed.seal_hash,
                sealed_at=parsed.timestamp,
                error=f"{FINDING_CODE_ANCHOR_DEFERRED}: {reason}",
            )
        return EvidenceSeal(
            thread_id=thread_id,
            seal_hash=parsed.seal_hash,
            sealed_at=parsed.timestamp,
        )

    # -- helpers ---------------------------------------------------------------

    @staticmethod
    def _blocked(code: str, message: str) -> ValidationResult:
        return ValidationResult(
            admitted=False,
            error=message,
            findings=[
                {
                    "code": code,
                    "status": "error",
                    "severity": "blocked",
                    "message": message,
                }
            ],
        )

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
adapter.py — Agent Integrity NormativeProvider Adapter
=======================================================

Adapts Simran Pabla's Agent Integrity verification system to the CAGE
NormativeProvider protocol. This follows the "Sidecar CLI" deployment
pattern: exchange JSON with an external verifier process/endpoint.

Tri-State Verdict Mapping
-------------------------
Agent Integrity returns three possible statuses:

  IntegrityStatus | ValidationResult.admitted | CAGE Behavior
  ----------------|---------------------------|----------------
  PASS            | True                      | Proceed to CBF
  BLOCKED         | False                     | Fail-closed DENY
  REVIEW          | False (+ defer)           | Park in DeferQueue

REVIEW verdicts are mapped to `admitted=False` at the ValidationResult
layer, but the adapter sets `needs_human_review=True` in the findings
to signal that the request should be parked in DeferQueue with
`DeferReason.EXTERNAL_VALIDATION` rather than hard-denied.

This preserves ValidationResult.admitted as a strict bool (no breaking
change) while supporting Agent Integrity's tri-state semantics.

Protocol Reference
------------------
Agent Integrity types from packages/protocol/src/types.ts:
  - IntegrityStatus: "PASS" | "REVIEW" | "BLOCKED"
  - IntegrityFinding: { code, severity, message, path? }
  - IntegrityResult: { protocolVersion, status, findings }
  - AlphaIntegrityReceipt: { ..., verification: IntegrityResult, ... }

See: third_party/agent-integrity/docs/ARCHITECTURE.md
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal

logger = logging.getLogger("cage.integrations.provider_06")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_ENDPOINT: str = os.environ.get("CAGE_AGENT_INTEGRITY_ENDPOINT", "")
_PROJECT_ROOT: str = os.environ.get("CAGE_AGENT_INTEGRITY_PROJECT_ROOT", "")
_TIMEOUT_SECONDS: float = float(os.environ.get("CAGE_AGENT_INTEGRITY_TIMEOUT", "10"))

# Protocol version from Agent Integrity (packages/protocol/src/types.ts)
PROTOCOL_VERSION = "1-alpha"


# ---------------------------------------------------------------------------
# Agent Integrity Protocol Types (Python equivalents)
# ---------------------------------------------------------------------------


class IntegrityStatus(str, Enum):
    """Tri-state verdict from Agent Integrity verification.

    Mirrors: packages/protocol/src/types.ts → IntegrityStatus
    """

    PASS = "PASS"
    REVIEW = "REVIEW"
    BLOCKED = "BLOCKED"


class FindingSeverity(str, Enum):
    """Severity levels for integrity findings.

    Mirrors: packages/protocol/src/types.ts → FindingSeverity
    """

    REVIEW = "review"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class IntegrityFinding:
    """A single finding from verification.

    Mirrors: packages/protocol/src/types.ts → IntegrityFinding
    """

    code: str
    severity: FindingSeverity
    message: str
    path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible dict."""
        result: dict[str, Any] = {
            "code": self.code,
            "severity": self.severity.value,
            "message": self.message,
        }
        if self.path is not None:
            result["path"] = self.path
        return result


@dataclass(frozen=True)
class IntegrityResult:
    """Complete verification result.

    Mirrors: packages/protocol/src/types.ts → IntegrityResult
    """

    protocol_version: str
    status: IntegrityStatus
    findings: tuple[IntegrityFinding, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible dict."""
        return {
            "protocolVersion": self.protocol_version,
            "status": self.status.value,
            "findings": [f.to_dict() for f in self.findings],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> IntegrityResult:
        """Deserialize from JSON response."""
        findings = tuple(
            IntegrityFinding(
                code=f["code"],
                severity=FindingSeverity(f["severity"]),
                message=f["message"],
                path=f.get("path"),
            )
            for f in data.get("findings", [])
        )
        return cls(
            protocol_version=data.get("protocolVersion", PROTOCOL_VERSION),
            status=IntegrityStatus(data["status"]),
            findings=findings,
        )


# ---------------------------------------------------------------------------
# Finding codes for CAGE-specific adapter findings
# ---------------------------------------------------------------------------

FINDING_CODE_REVIEW_PENDING = "cage.review_pending"
FINDING_CODE_ENDPOINT_ERROR = "cage.endpoint_error"
FINDING_CODE_PARSE_ERROR = "cage.parse_error"


# ---------------------------------------------------------------------------
# Provider 06 Adapter
# ---------------------------------------------------------------------------


class Provider06AgentIntegrityAdapter:
    """Agent Integrity adapter implementing the NormativeProvider protocol.

    This adapter:
    1. Accepts governance payloads from CAGE's normative boundary
    2. Submits them to Agent Integrity for verification
    3. Maps tri-state verdicts (PASS/REVIEW/BLOCKED) to CAGE's binary
       admitted flag + findings for deferred review handling

    The adapter does NOT modify verdict semantics — it faithfully translates
    Agent Integrity's deterministic decisions into CAGE's type system.
    """

    def __init__(
        self,
        endpoint: str = "",
        project_root: str = "",
        timeout: float = _TIMEOUT_SECONDS,
    ) -> None:
        """Initialize the Agent Integrity adapter.

        Args:
            endpoint: Base URL of the Agent Integrity endpoint (mock or CLI wrapper).
                     Falls back to CAGE_AGENT_INTEGRITY_ENDPOINT env var.
            project_root: Path to trusted project root for source verification.
                         Falls back to CAGE_AGENT_INTEGRITY_PROJECT_ROOT env var.
            timeout: Request timeout in seconds.
        """
        self._endpoint = (endpoint or _ENDPOINT).rstrip("/")
        self._project_root = project_root or _PROJECT_ROOT
        self._timeout = timeout

        if not self._endpoint:
            logger.warning(
                "[Provider06] CAGE_AGENT_INTEGRITY_ENDPOINT not set. "
                "Verification requests will fail until endpoint is configured."
            )

        logger.info(
            "[Provider06] Initialised: endpoint=%s project_root=%s timeout=%.1fs",
            self._endpoint or "(not set)",
            self._project_root or "(not set)",
            self._timeout,
        )

    def _headers(self) -> dict[str, str]:
        """Construct request headers."""
        return {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Protocol-Version": PROTOCOL_VERSION,
        }

    async def fetch_baseline(self, region: str):  # type: ignore[no-untyped-def]
        """Fetch the active legal baseline from Agent Integrity.

        Agent Integrity is a verification system, not a normative data source.
        This method returns a minimal baseline that indicates Agent Integrity
        is the active verifier for the region.

        For full normative data, compose with another provider (e.g., provider_01).
        """
        from src.gateway.governance.normative_provider import NormativeBaseline

        # Agent Integrity doesn't provide normative baselines — it verifies
        # agent responses against project-configured policy. Return a minimal
        # baseline indicating the verifier is active.
        return NormativeBaseline(
            region=region,
            profile={
                "verifier": "agent-integrity",
                "protocol_version": PROTOCOL_VERSION,
                "project_root": self._project_root,
            },
        )

    async def validate_fria(self, payload: dict[str, Any]):  # type: ignore[no-untyped-def]
        """Submit payload for Agent Integrity verification.

        This method:
        1. Submits the governance payload to Agent Integrity endpoint
        2. Receives an IntegrityResult with PASS/REVIEW/BLOCKED status
        3. Maps the tri-state to CAGE's ValidationResult:
           - PASS → admitted=True
           - BLOCKED → admitted=False
           - REVIEW → admitted=False + needs_human_review finding

        Returns:
            ValidationResult with admitted flag and findings list.
        """
        import httpx

        from src.gateway.governance.normative_provider import ValidationResult

        if not self._endpoint:
            return ValidationResult(
                admitted=False,
                error="Agent Integrity endpoint not configured",
                findings=[
                    {
                        "code": FINDING_CODE_ENDPOINT_ERROR,
                        "severity": "blocked",
                        "message": "CAGE_AGENT_INTEGRITY_ENDPOINT not configured",
                    }
                ],
            )

        url = f"{self._endpoint}/verify"

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(url, json=payload, headers=self._headers())
                resp.raise_for_status()
                data = resp.json()

            # Parse the Agent Integrity result
            result = IntegrityResult.from_dict(data)

            # Map tri-state verdict to CAGE's binary admitted + findings
            return self._map_integrity_result(result)

        except httpx.HTTPStatusError as exc:
            logger.error(
                "[Provider06] verify failed: %s HTTP %d",
                url,
                exc.response.status_code,
            )
            return ValidationResult(
                admitted=False,
                error=f"HTTP {exc.response.status_code}: {exc.response.text[:200]}",
                findings=[
                    {
                        "code": FINDING_CODE_ENDPOINT_ERROR,
                        "severity": "blocked",
                        "message": f"Agent Integrity HTTP error: {exc.response.status_code}",
                    }
                ],
            )

        except httpx.RequestError as exc:
            logger.error("[Provider06] verify failed: %s %s", url, exc)
            return ValidationResult(
                admitted=False,
                error=str(exc),
                findings=[
                    {
                        "code": FINDING_CODE_ENDPOINT_ERROR,
                        "severity": "blocked",
                        "message": f"Agent Integrity request failed: {exc}",
                    }
                ],
            )

        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            logger.error("[Provider06] parse error: %s", exc)
            return ValidationResult(
                admitted=False,
                error=f"Response parse error: {exc}",
                findings=[
                    {
                        "code": FINDING_CODE_PARSE_ERROR,
                        "severity": "blocked",
                        "message": f"Agent Integrity response parse error: {exc}",
                    }
                ],
            )

    def _map_integrity_result(self, result: IntegrityResult):  # type: ignore[no-untyped-def]
        """Map Agent Integrity tri-state verdict to CAGE ValidationResult.

        Mapping logic:
          - PASS    → admitted=True, pass through any review-severity findings
          - BLOCKED → admitted=False, findings include all blocked-severity items
          - REVIEW  → admitted=False, findings include a special marker that
                      signals the caller (enforce_fria_boundary) to park in
                      DeferQueue with EXTERNAL_VALIDATION reason

        The REVIEW→defer mapping preserves Agent Integrity's semantic intent
        ("hold for human review") within CAGE's existing primitives.
        """
        from src.gateway.governance.normative_provider import ValidationResult

        # Convert IntegrityFindings to dict format
        findings_list = [f.to_dict() for f in result.findings]

        if result.status == IntegrityStatus.PASS:
            return ValidationResult(
                admitted=True,
                findings=findings_list,
            )

        if result.status == IntegrityStatus.BLOCKED:
            return ValidationResult(
                admitted=False,
                findings=findings_list,
            )

        # REVIEW: Mark as not admitted, but add a finding that tells the
        # caller this should be parked for human review rather than hard-denied.
        # The enforce_fria_boundary() function checks for this marker.
        review_findings = [
            {
                "code": FINDING_CODE_REVIEW_PENDING,
                "severity": "review",
                "message": "Agent Integrity returned REVIEW — requires human approval",
                "needs_human_review": True,  # CAGE-specific extension
                "integrity_status": result.status.value,
                "integrity_findings": findings_list,
            }
        ]
        review_findings.extend(findings_list)

        return ValidationResult(
            admitted=False,
            findings=review_findings,
        )

    async def submit_evidence(self, thread_id: str, evidence_hash: str):  # type: ignore[no-untyped-def]
        """Submit governance evidence hash to Agent Integrity for sealing.

        Agent Integrity creates receipts with Ed25519 signatures. This method
        requests a receipt for the evidence hash and returns the sealed
        attestation.
        """
        import httpx

        from src.gateway.governance.normative_provider import EvidenceSeal

        if not self._endpoint:
            return EvidenceSeal(
                thread_id=thread_id,
                error="Agent Integrity endpoint not configured",
            )

        url = f"{self._endpoint}/receipt"

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    url,
                    json={
                        "thread_id": thread_id,
                        "evidence_hash": evidence_hash,
                    },
                    headers=self._headers(),
                )
                resp.raise_for_status()
                data = resp.json()

            # Extract the receipt digest as the seal hash
            return EvidenceSeal(
                thread_id=thread_id,
                seal_hash=data.get("receiptDigest", ""),
            )

        except Exception as exc:
            logger.error(
                "[Provider06] submit_evidence failed: %s %s",
                url,
                exc,
            )
            return EvidenceSeal(thread_id=thread_id, error=str(exc))


# ---------------------------------------------------------------------------
# Helper: Check if ValidationResult indicates REVIEW status
# ---------------------------------------------------------------------------


def is_review_pending(findings: list[dict[str, Any]]) -> bool:
    """Check if findings indicate Agent Integrity REVIEW status.

    This helper is used by enforce_fria_boundary() to detect when a
    ValidationResult.admitted=False should trigger defer-queue parking
    rather than a hard deny.

    Args:
        findings: The findings list from ValidationResult

    Returns:
        True if any finding has needs_human_review=True marker
    """
    return any(f.get("needs_human_review", False) for f in findings)


def extract_integrity_status(
    findings: list[dict[str, Any]],
) -> Literal["PASS", "REVIEW", "BLOCKED"] | None:
    """Extract the original Agent Integrity status from findings.

    Args:
        findings: The findings list from ValidationResult

    Returns:
        The IntegrityStatus string if present, None otherwise
    """
    for finding in findings:
        status = finding.get("integrity_status")
        if status in ("PASS", "REVIEW", "BLOCKED"):
            return status  # type: ignore[return-value]
    return None

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

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import struct
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.seams.normative import (
    EvidenceSeal,
    NormativeBaseline,
    ValidationResult,
)
from src.integrations.provider_06.jwks_client import (
    FileJWKSClient,
    Provider06KeyManifestClient,
)
from src.integrations.provider_06.signature import (
    verify_receipt_digest,
    verify_receipt_signature,
)

logger = logging.getLogger("cage.integrations.provider_06")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_ENDPOINT: str = os.environ.get("CAGE_AGENT_INTEGRITY_ENDPOINT", "")
_SOCKET_PATH: str = os.environ.get("CAGE_AGENT_INTEGRITY_SOCKET_PATH", "")
_PROJECT_ROOT: str = os.environ.get("CAGE_AGENT_INTEGRITY_PROJECT_ROOT", "")
_TIMEOUT_SECONDS: float = float(os.environ.get("CAGE_AGENT_INTEGRITY_TIMEOUT", "10"))
_KEY_MANIFEST_URL: str = os.environ.get("CAGE_AGENT_INTEGRITY_KEY_MANIFEST", "")
_BUNDLE_ID: str = os.environ.get("CAGE_AGENT_INTEGRITY_BUNDLE_ID", "default-bundle")
_CLIENT_ID: str = os.environ.get("CAGE_AGENT_INTEGRITY_CLIENT_ID", "cage-gateway")
_HMAC_KEY_ID: str = os.environ.get("CAGE_AGENT_INTEGRITY_HMAC_KEY_ID", "hmac-key-1")
_HMAC_SECRET_FILE: str = os.environ.get("CAGE_AGENT_INTEGRITY_HMAC_SECRET_FILE", "")

# Protocol versions
PROTOCOL_VERSION = "1-alpha"
SIDECAR_PROTOCOL_VERSION = "1"
VERIFY_RELEASE_PATH = "/v1/verify-release"
SIDECAR_AUTH_DOMAIN = b"agent-integrity-sidecar-auth-v1"
MAX_RELEASED_RESPONSE_BYTES = 4 * 1024 * 1024

SERVICE_ERROR_CODES = frozenset(
    {
        "INVALID_REQUEST",
        "UNSUPPORTED_PROTOCOL",
        "AUTHENTICATION_FAILED",
        "REPLAY_DETECTED",
        "BUNDLE_UNAVAILABLE",
        "BUNDLE_INVALID",
        "IDEMPOTENCY_CONFLICT",
        "PAYLOAD_TOO_LARGE",
        "RESOURCE_LIMIT",
        "RESULT_EXPIRED",
        "STORAGE_UNAVAILABLE",
        "SIGNING_UNAVAILABLE",
        "VERIFIER_FAILURE",
        "SERVICE_UNAVAILABLE",
        "INTERNAL_FAILURE",
    }
)

_SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_CANONICAL_BASE64_RE = re.compile(
    r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
)


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


class VerifyReleaseStatus(str, Enum):
    """Top-level service response status from ``POST /v1/verify-release``."""

    PASS = "PASS"
    REVIEW = "REVIEW"
    BLOCKED = "BLOCKED"
    RELEASE_REFUSED = "RELEASE_REFUSED"


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
        if not isinstance(data, dict):
            raise ValueError("verification must be a JSON object")
        raw_findings = data.get("findings")
        if not isinstance(raw_findings, list):
            raise ValueError("verification.findings must be a list")
        findings = tuple(
            IntegrityFinding(
                code=f["code"],
                severity=FindingSeverity(f["severity"]),
                message=f["message"],
                path=f.get("path"),
            )
            for f in raw_findings
        )
        return cls(
            protocol_version=data.get("protocolVersion", PROTOCOL_VERSION),
            status=IntegrityStatus(data["status"]),
            findings=findings,
        )


@dataclass(frozen=True)
class ReleasedResponsePayload:
    """Verified exact-byte release payload from ``POST /v1/verify-release``."""

    encoding: Literal["base64"]
    sha256: str
    bytes_b64: str
    decoded_bytes: bytes

    @property
    def text(self) -> str:
        """Decode exact released UTF-8 bytes as string."""
        return self.decoded_bytes.decode("utf-8")

    @classmethod
    def from_dict_and_verify(
        cls,
        data: Any,
        *,
        expected_content: str,
        max_bytes: int = MAX_RELEASED_RESPONSE_BYTES,
    ) -> ReleasedResponsePayload:
        """Validate canonical base64, SHA-256 digest, and exact UTF-8 byte equality."""
        if not isinstance(data, dict) or set(data.keys()) != {
            "encoding",
            "sha256",
            "bytes",
        }:
            raise ValueError(
                "releasedResponse must contain exactly encoding, sha256, bytes"
            )
        if data.get("encoding") != "base64":
            raise ValueError("releasedResponse.encoding must be 'base64'")
        sha_hex = data.get("sha256")
        b64_str = data.get("bytes")
        if not isinstance(sha_hex, str) or not _SHA256_RE.fullmatch(sha_hex):
            raise ValueError("releasedResponse.sha256 is invalid")
        if (
            not isinstance(b64_str, str)
            or len(b64_str) % 4 != 0
            or not _CANONICAL_BASE64_RE.fullmatch(b64_str)
        ):
            raise ValueError("releasedResponse.bytes must be canonical base64")
        decoded = base64.b64decode(b64_str, validate=True)
        if base64.b64encode(decoded).decode("ascii") != b64_str:
            raise ValueError("releasedResponse.bytes is not canonical base64")
        if len(decoded) > max_bytes:
            raise ValueError("releasedResponse exceeds maximum allowed byte length")
        computed_sha = hashlib.sha256(decoded).hexdigest()
        if computed_sha != sha_hex:
            raise ValueError(
                f"releasedResponse.sha256 mismatch: expected={sha_hex} got={computed_sha}"
            )
        expected_bytes = expected_content.encode("utf-8")
        if decoded != expected_bytes:
            raise ValueError(
                "releasedResponse bytes do not match envelope.response.content UTF-8 bytes"
            )
        return cls(
            encoding="base64",
            sha256=sha_hex,
            bytes_b64=b64_str,
            decoded_bytes=decoded,
        )


@dataclass(frozen=True)
class ReleaseRefusalDetail:
    """Details of a post-verification release refusal (``RELEASE_REFUSED``)."""

    status: Literal["REVIEW", "BLOCKED"]
    code: str
    retryable: bool

    @classmethod
    def from_dict(cls, data: Any) -> ReleaseRefusalDetail:
        if not isinstance(data, dict) or set(data.keys()) != {
            "status",
            "code",
            "retryable",
        }:
            raise ValueError("release refusal block contains invalid keys")
        status = data.get("status")
        code = data.get("code")
        retryable = data.get("retryable")
        if status not in ("REVIEW", "BLOCKED"):
            raise ValueError("release.status must be REVIEW or BLOCKED")
        if code != "RECEIPT_RECHECK_REFUSED":
            raise ValueError("release.code must be RECEIPT_RECHECK_REFUSED")
        if retryable is not False:
            raise ValueError("release.retryable must be false")
        return cls(status=status, code=code, retryable=False)


@dataclass(frozen=True)
class VerifyReleaseOutcome:
    """Structured result from ``POST /v1/verify-release``."""

    admitted: bool
    status: VerifyReleaseStatus | None
    request_id: str
    verification: IntegrityResult | None = None
    receipt: dict[str, Any] | None = None
    receipt_verified: bool = False
    released_response: ReleasedResponsePayload | None = None
    release_refusal: ReleaseRefusalDetail | None = None
    error_code: str | None = None
    retryable: bool = False
    http_status: int = 200
    findings: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None

    def to_validation_result(self) -> ValidationResult:
        """Convert to CAGE's canonical :class:`ValidationResult`."""
        return ValidationResult(
            admitted=self.admitted,
            findings=list(self.findings),
            error=self.error,
        )


# ---------------------------------------------------------------------------
# Finding codes for CAGE-specific adapter findings
# ---------------------------------------------------------------------------

FINDING_CODE_REVIEW_PENDING = "cage.review_pending"
FINDING_CODE_RELEASE_REFUSED = "cage.release_refused"
FINDING_CODE_ENDPOINT_ERROR = "cage.endpoint_error"
FINDING_CODE_PARSE_ERROR = "cage.parse_error"
FINDING_CODE_UNKNOWN_KEY = "cage.unknown_key"
FINDING_CODE_INVALID_SIGNATURE = "cage.invalid_signature"
FINDING_CODE_INVALID_DIGEST = "cage.invalid_digest"
FINDING_CODE_ENVELOPE_DIGEST_MISMATCH = "cage.envelope_digest_mismatch"
FINDING_CODE_POLICY_DIGEST_MISMATCH = "cage.policy_digest_mismatch"
FINDING_CODE_RECEIPT_EXPIRED = "cage.receipt_expired"
FINDING_CODE_RECEIPT_MISSING = "cage.receipt_missing"
FINDING_CODE_RELEASED_BYTES_MISMATCH = "cage.released_bytes_mismatch"


def encode_sidecar_auth_input(fields: list[str] | tuple[str, ...]) -> bytes:
    """Encode length-prefixed HMAC signing input matching ``packages/sidecar/src/auth.ts``."""
    parts: list[bytes] = [SIDECAR_AUTH_DOMAIN]
    for item in fields:
        encoded = item.encode("utf-8")
        parts.append(struct.pack(">I", len(encoded)))
        parts.append(encoded)
    return b"".join(parts)


def compute_sidecar_auth_headers(
    *,
    method: str,
    path: str,
    service_protocol_version: str,
    client_id: str,
    key_id: str,
    timestamp_ms: int,
    nonce: str,
    body_digest: str,
    secret: bytes,
) -> dict[str, str]:
    """Construct authenticated sidecar request headers with base64url HMAC-SHA256."""
    ts_str = str(timestamp_ms)
    signing_input = encode_sidecar_auth_input(
        [
            method,
            path,
            service_protocol_version,
            client_id,
            key_id,
            ts_str,
            nonce,
            body_digest,
        ]
    )
    digest = hmac.new(secret, signing_input, hashlib.sha256).digest()
    mac_b64url = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Agent-Integrity-Client": client_id,
        "X-Agent-Integrity-Key-Id": key_id,
        "X-Agent-Integrity-Timestamp": ts_str,
        "X-Agent-Integrity-Nonce": nonce,
        "X-Agent-Integrity-Signature": mac_b64url,
    }


def _load_hmac_secret(
    hmac_secret: bytes | str | None,
    hmac_secret_file: str | Path | None,
) -> bytes | None:
    if hmac_secret is not None:
        raw = (
            hmac_secret.encode("utf-8")
            if isinstance(hmac_secret, str)
            else bytes(hmac_secret)
        )
        if len(raw) < 32 or len(raw) > 1024:
            raise ValueError("Sidecar HMAC secret must be between 32 and 1024 bytes")
        return raw
    file_path = str(hmac_secret_file or _HMAC_SECRET_FILE).strip()
    if not file_path:
        return None
    raw = Path(file_path).read_bytes()
    if len(raw) < 32 or len(raw) > 1024:
        raise ValueError("Sidecar HMAC secret file must contain 32..1024 bytes")
    return raw


# ---------------------------------------------------------------------------
# Provider 06 Adapter
# ---------------------------------------------------------------------------


class Provider06AgentIntegrityAdapter:
    """Agent Integrity adapter implementing the NormativeProvider protocol.

    Supports both:
    - Phase 2 finalized sidecar contract: ``POST /v1/verify-release`` over Unix
      Domain Socket (or HTTP transport) with HMAC-SHA256 request signing,
      out-of-band :class:`FileJWKSClient` receipt verification, signed refusal
      preservation (``REVIEW``, ``BLOCKED``, ``RELEASE_REFUSED``), non-200
      technical failure handling, and exact returned-byte verification.
    - Phase 1 HTTP mock endpoint fallback (``POST /verify`` and ``POST /receipt``)
      when no sidecar socket or ``verify_release`` mode is active.
    """

    def __init__(
        self,
        endpoint: str = "",
        project_root: str = "",
        timeout: float = _TIMEOUT_SECONDS,
        key_manifest_url: str = "",
        *,
        socket_path: str | Path | None = None,
        bundle_id: str = "",
        client_id: str = "",
        hmac_key_id: str = "",
        hmac_secret: bytes | str | None = None,
        hmac_secret_file: str | Path | None = None,
        authority_keys: dict[str, Any] | None = None,
        manifest_state_path: str | Path | None = None,
        transport: Any | None = None,
        use_verify_release: bool = False,
    ) -> None:
        self._endpoint = (endpoint or _ENDPOINT).rstrip("/")
        resolved_socket = (
            str(socket_path) if socket_path is not None else _SOCKET_PATH
        ).strip()
        self._socket_path: str | None = resolved_socket or None
        self._project_root = project_root or _PROJECT_ROOT
        self._timeout = timeout
        self._key_manifest_url = key_manifest_url or _KEY_MANIFEST_URL
        self._bundle_id = bundle_id or _BUNDLE_ID
        self._client_id = client_id or _CLIENT_ID
        self._hmac_key_id = hmac_key_id or _HMAC_KEY_ID
        self._hmac_secret = _load_hmac_secret(hmac_secret, hmac_secret_file)
        self._transport = transport
        self._use_verify_release = bool(
            use_verify_release
            or self._socket_path is not None
            or self._hmac_secret is not None
            or self._endpoint.endswith(VERIFY_RELEASE_PATH)
        )

        # Initialize JWKS client if key manifest is configured
        self._jwks_client: FileJWKSClient | None = None
        if self._key_manifest_url:
            self._jwks_client = Provider06KeyManifestClient(
                manifest_url=self._key_manifest_url,
                cache_ttl_seconds=3600,
                timeout_seconds=timeout,
                authority_keys=authority_keys,
                manifest_state_path=manifest_state_path,
            )
            logger.info(
                "[Provider06] JWKS client initialized: manifest=%s",
                self._key_manifest_url,
            )
        else:
            logger.warning(
                "[Provider06] CAGE_AGENT_INTEGRITY_KEY_MANIFEST not set. "
                "Receipt signature verification will fail closed on /v1/verify-release."
            )

        if not self._endpoint and not self._socket_path:
            logger.warning(
                "[Provider06] Neither CAGE_AGENT_INTEGRITY_SOCKET_PATH nor "
                "CAGE_AGENT_INTEGRITY_ENDPOINT is set."
            )

    def _headers(self) -> dict[str, str]:
        """Construct legacy request headers."""
        return {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Protocol-Version": PROTOCOL_VERSION,
        }

    def _build_http_client(self) -> Any:
        import httpx

        transport = self._transport
        if transport is None and self._socket_path:
            transport = httpx.AsyncHTTPTransport(uds=self._socket_path)
        return httpx.AsyncClient(timeout=self._timeout, transport=transport)

    def _verify_release_url(self) -> str:
        base = self._endpoint or ("http://localhost" if self._socket_path else "")
        if base.endswith(VERIFY_RELEASE_PATH):
            return base
        return f"{base}{VERIFY_RELEASE_PATH}"

    async def fetch_baseline(self, region: str) -> NormativeBaseline:
        """Fetch the active baseline metadata for the Agent Integrity verifier."""
        return NormativeBaseline(
            region=region,
            profile={
                "verifier": "agent-integrity",
                "protocol_version": PROTOCOL_VERSION,
                "sidecar_protocol_version": SIDECAR_PROTOCOL_VERSION,
                "project_root": self._project_root,
            },
        )

    async def verify_release(
        self,
        envelope: dict[str, Any],
        *,
        request_id: str | None = None,
        idempotency_key: str | None = None,
        bundle_id: str | None = None,
        nonce: str | None = None,
        timestamp_ms: int | None = None,
    ) -> VerifyReleaseOutcome:
        """Execute ``POST /v1/verify-release`` against the Agent Integrity sidecar.

        Enforces:
        1. Canonical RFC 8785 JCS request serialization and HMAC-SHA256 headers
        2. Phase-safe non-200 ``TechnicalErrorResponse`` handling (fail closed)
        3. Mandatory out-of-band Ed25519 receipt signature & digest verification
           for ``PASS``, ``REVIEW``, ``BLOCKED``, and ``RELEASE_REFUSED``
        4. Exact returned-byte verification (``releasedResponse.bytes`` + ``sha256``)
           on ``PASS``, and absence of ``releasedResponse`` on all refusals.
        """
        import httpx

        req_id = request_id or f"req-{uuid.uuid4().hex}"
        idem_key = idempotency_key or req_id
        b_id = bundle_id or self._bundle_id
        req_nonce = nonce or f"nonce-{uuid.uuid4().hex}"
        ts_ms = timestamp_ms if timestamp_ms is not None else int(time.time() * 1000)

        if not self._endpoint and not self._socket_path:
            return VerifyReleaseOutcome(
                admitted=False,
                status=None,
                request_id=req_id,
                error="Agent Integrity endpoint or socket_path not configured",
                findings=[
                    {
                        "code": FINDING_CODE_ENDPOINT_ERROR,
                        "severity": "blocked",
                        "message": "CAGE_AGENT_INTEGRITY_ENDPOINT / SOCKET_PATH not configured",
                    }
                ],
            )

        if (
            isinstance(envelope, dict)
            and envelope.get("serviceProtocolVersion") == SIDECAR_PROTOCOL_VERSION
            and "envelope" in envelope
        ):
            req_id = str(envelope.get("requestId", req_id))
            idem_key = str(envelope.get("idempotencyKey", idem_key))
            b_id = str(envelope.get("bundleId", b_id))
            actual_envelope = envelope["envelope"]
        else:
            actual_envelope = envelope

        if not isinstance(actual_envelope, dict):
            return VerifyReleaseOutcome(
                admitted=False,
                status=None,
                request_id=req_id,
                error="Envelope must be a JSON object",
                findings=[
                    {
                        "code": FINDING_CODE_PARSE_ERROR,
                        "severity": "blocked",
                        "message": "Envelope must be a JSON object",
                    }
                ],
            )

        service_request = {
            "serviceProtocolVersion": SIDECAR_PROTOCOL_VERSION,
            "requestId": req_id,
            "idempotencyKey": idem_key,
            "bundleId": b_id,
            "envelope": actual_envelope,
        }
        try:
            body_bytes = jcs_canonicalize_plan(service_request)
        except Exception as exc:
            return VerifyReleaseOutcome(
                admitted=False,
                status=None,
                request_id=req_id,
                error=f"Request canonicalization failed: {exc}",
                findings=[
                    {
                        "code": FINDING_CODE_PARSE_ERROR,
                        "severity": "blocked",
                        "message": f"Request canonicalization failed: {exc}",
                    }
                ],
            )

        body_digest = hashlib.sha256(body_bytes).hexdigest()
        if self._hmac_secret is not None:
            headers = compute_sidecar_auth_headers(
                method="POST",
                path=VERIFY_RELEASE_PATH,
                service_protocol_version=SIDECAR_PROTOCOL_VERSION,
                client_id=self._client_id,
                key_id=self._hmac_key_id,
                timestamp_ms=ts_ms,
                nonce=req_nonce,
                body_digest=body_digest,
                secret=self._hmac_secret,
            )
        else:
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
            }

        url = self._verify_release_url()
        try:
            async with self._build_http_client() as client:
                resp = await client.post(url, content=body_bytes, headers=headers)
        except httpx.RequestError as exc:
            logger.error("[Provider06] verify-release transport error: %s", exc)
            return VerifyReleaseOutcome(
                admitted=False,
                status=None,
                request_id=req_id,
                http_status=503,
                retryable=True,
                error=str(exc),
                findings=[
                    {
                        "code": FINDING_CODE_ENDPOINT_ERROR,
                        "severity": "blocked",
                        "message": f"Agent Integrity sidecar request failed: {exc}",
                    }
                ],
            )

        if resp.status_code != 200:
            return self._handle_technical_error_response(resp, req_id)

        try:
            data = resp.json()
        except (json.JSONDecodeError, ValueError) as exc:
            return VerifyReleaseOutcome(
                admitted=False,
                status=None,
                request_id=req_id,
                http_status=resp.status_code,
                error=f"Response parse error: {exc}",
                findings=[
                    {
                        "code": FINDING_CODE_PARSE_ERROR,
                        "severity": "blocked",
                        "message": f"Agent Integrity response parse error: {exc}",
                    }
                ],
            )

        return await self._process_verify_release_response(
            data=data,
            expected_request_id=req_id,
            envelope=actual_envelope,
        )

    def _handle_technical_error_response(
        self,
        resp: Any,
        expected_request_id: str,
    ) -> VerifyReleaseOutcome:
        """Parse non-200 ``TechnicalErrorResponse`` and fail closed without releasing bytes."""
        error_code = "ENDPOINT_ERROR"
        retryable = False
        req_id = expected_request_id
        try:
            payload = resp.json()
            if isinstance(payload, dict):
                if isinstance(payload.get("requestId"), str):
                    req_id = payload["requestId"]
                err_obj = payload.get("error")
                if isinstance(err_obj, dict):
                    raw_code = err_obj.get("code")
                    if isinstance(raw_code, str) and raw_code in SERVICE_ERROR_CODES:
                        error_code = raw_code
                    if isinstance(err_obj.get("retryable"), bool):
                        retryable = err_obj["retryable"]
        except Exception:
            logger.debug(
                "[Provider06] Non-JSON error body on HTTP %d", resp.status_code
            )

        logger.error(
            "[Provider06] verify-release technical failure: HTTP %d code=%s retryable=%s",
            resp.status_code,
            error_code,
            retryable,
        )
        return VerifyReleaseOutcome(
            admitted=False,
            status=None,
            request_id=req_id,
            error_code=error_code,
            retryable=retryable,
            http_status=resp.status_code,
            error=f"HTTP {resp.status_code}: {error_code}",
            findings=[
                {
                    "code": FINDING_CODE_ENDPOINT_ERROR,
                    "severity": "blocked",
                    "message": f"Agent Integrity technical failure: HTTP {resp.status_code} ({error_code})",
                    "sidecar_error_code": error_code,
                    "retryable": retryable,
                    "http_status": resp.status_code,
                }
            ],
        )

    async def _process_verify_release_response(
        self,
        *,
        data: Any,
        expected_request_id: str,
        envelope: dict[str, Any],
    ) -> VerifyReleaseOutcome:
        if not isinstance(data, dict):
            return self._parse_failure_outcome(
                expected_request_id, "Service response must be a JSON object"
            )

        if data.get("serviceProtocolVersion") != SIDECAR_PROTOCOL_VERSION:
            return self._parse_failure_outcome(
                expected_request_id, "Unsupported or missing serviceProtocolVersion"
            )

        if data.get("requestId") != expected_request_id:
            return self._parse_failure_outcome(
                expected_request_id, "Response requestId does not match request"
            )

        raw_status = data.get("status")
        try:
            status = VerifyReleaseStatus(raw_status)
        except ValueError:
            return self._parse_failure_outcome(
                expected_request_id, f"Invalid verify-release status: {raw_status!r}"
            )

        raw_verification = data.get("verification")
        try:
            verification = IntegrityResult.from_dict(raw_verification)
        except (KeyError, ValueError, TypeError) as exc:
            return self._parse_failure_outcome(
                expected_request_id, f"Invalid verification block: {exc}"
            )

        receipt = data.get("receipt")
        if not isinstance(receipt, dict):
            return VerifyReleaseOutcome(
                admitted=False,
                status=status,
                request_id=expected_request_id,
                verification=verification,
                error="Missing signed receipt in verify-release response",
                findings=[
                    {
                        "code": FINDING_CODE_RECEIPT_MISSING,
                        "severity": "blocked",
                        "message": "Agent Integrity response is missing a signed receipt",
                    }
                ],
            )

        # Verify cryptographic receipt and bindings for ALL statuses (PASS and refusals)
        receipt_err, finding_code = await self._verify_v1_receipt(
            receipt=receipt,
            envelope=envelope,
            expected_verification=raw_verification,
        )
        if receipt_err is not None:
            return VerifyReleaseOutcome(
                admitted=False,
                status=status,
                request_id=expected_request_id,
                verification=verification,
                receipt=receipt,
                receipt_verified=False,
                error=receipt_err,
                findings=[
                    {
                        "code": finding_code or FINDING_CODE_INVALID_SIGNATURE,
                        "severity": "blocked",
                        "message": receipt_err,
                    }
                ],
            )

        receipt_digest = str(receipt.get("receiptDigest", ""))
        base_findings = [f.to_dict() for f in verification.findings]

        # Case 1: PASS
        if status == VerifyReleaseStatus.PASS:
            if set(data.keys()) != {
                "serviceProtocolVersion",
                "requestId",
                "status",
                "verification",
                "receipt",
                "releasedResponse",
            }:
                return self._parse_failure_outcome(
                    expected_request_id,
                    "PASS response contains unexpected or missing top-level keys",
                )
            if verification.status != IntegrityStatus.PASS:
                return self._parse_failure_outcome(
                    expected_request_id,
                    "PASS response has non-PASS verification status",
                )
            expected_content = (
                envelope.get("response", {}).get("content")
                if isinstance(envelope.get("response"), dict)
                else None
            )
            if not isinstance(expected_content, str):
                return self._parse_failure_outcome(
                    expected_request_id,
                    "Envelope missing string response.content",
                )
            try:
                released_payload = ReleasedResponsePayload.from_dict_and_verify(
                    data.get("releasedResponse"),
                    expected_content=expected_content,
                )
            except ValueError as exc:
                logger.error("[Provider06] Exact-byte verification FAILED: %s", exc)
                return VerifyReleaseOutcome(
                    admitted=False,
                    status=status,
                    request_id=expected_request_id,
                    verification=verification,
                    receipt=receipt,
                    receipt_verified=True,
                    error=str(exc),
                    findings=[
                        {
                            "code": FINDING_CODE_RELEASED_BYTES_MISMATCH,
                            "severity": "blocked",
                            "message": str(exc),
                        }
                    ],
                )

            return VerifyReleaseOutcome(
                admitted=True,
                status=VerifyReleaseStatus.PASS,
                request_id=expected_request_id,
                verification=verification,
                receipt=receipt,
                receipt_verified=True,
                released_response=released_payload,
                findings=base_findings,
            )

        # Refusal invariant: releasedResponse must NEVER be present on any refusal
        if "releasedResponse" in data:
            return self._parse_failure_outcome(
                expected_request_id,
                "Refusal response illegally contained releasedResponse",
            )

        # Case 2: Direct Refusals (REVIEW or BLOCKED)
        if status in (VerifyReleaseStatus.REVIEW, VerifyReleaseStatus.BLOCKED):
            if set(data.keys()) != {
                "serviceProtocolVersion",
                "requestId",
                "status",
                "verification",
                "receipt",
            }:
                return self._parse_failure_outcome(
                    expected_request_id,
                    f"{status.value} response contains unexpected top-level keys",
                )
            if verification.status.value != status.value:
                return self._parse_failure_outcome(
                    expected_request_id,
                    f"Refusal status {status.value} does not match verification.status",
                )

            if status == VerifyReleaseStatus.REVIEW:
                review_findings: list[dict[str, Any]] = [
                    {
                        "code": FINDING_CODE_REVIEW_PENDING,
                        "severity": "review",
                        "message": "Agent Integrity returned signed REVIEW — requires human approval",
                        "needs_human_review": True,
                        "integrity_status": "REVIEW",
                        "integrity_findings": base_findings,
                        "receipt_digest": receipt_digest,
                        "receipt_verified": True,
                    },
                    *base_findings,
                ]
                return VerifyReleaseOutcome(
                    admitted=False,
                    status=VerifyReleaseStatus.REVIEW,
                    request_id=expected_request_id,
                    verification=verification,
                    receipt=receipt,
                    receipt_verified=True,
                    findings=review_findings,
                )

            blocked_findings = [
                {
                    **f,
                    "receipt_digest": receipt_digest,
                    "receipt_verified": True,
                }
                for f in base_findings
            ] or [
                {
                    "code": "integrity.blocked",
                    "severity": "blocked",
                    "message": "Agent Integrity returned signed BLOCKED refusal",
                    "receipt_digest": receipt_digest,
                    "receipt_verified": True,
                }
            ]
            return VerifyReleaseOutcome(
                admitted=False,
                status=VerifyReleaseStatus.BLOCKED,
                request_id=expected_request_id,
                verification=verification,
                receipt=receipt,
                receipt_verified=True,
                findings=blocked_findings,
            )

        # Case 3: RELEASE_REFUSED (prospective PASS receipt preserved, release gate refused)
        if set(data.keys()) != {
            "serviceProtocolVersion",
            "requestId",
            "status",
            "verification",
            "receipt",
            "release",
        }:
            return self._parse_failure_outcome(
                expected_request_id,
                "RELEASE_REFUSED response contains unexpected or missing keys",
            )
        if verification.status != IntegrityStatus.PASS:
            return self._parse_failure_outcome(
                expected_request_id,
                "RELEASE_REFUSED must preserve prospective PASS verification",
            )
        try:
            refusal_detail = ReleaseRefusalDetail.from_dict(data.get("release"))
        except ValueError as exc:
            return self._parse_failure_outcome(expected_request_id, str(exc))

        release_finding: dict[str, Any] = {
            "code": FINDING_CODE_RELEASE_REFUSED,
            "severity": "review" if refusal_detail.status == "REVIEW" else "blocked",
            "message": (
                f"Agent Integrity refused release after prospective PASS receipt "
                f"({refusal_detail.code}: {refusal_detail.status})"
            ),
            "integrity_status": "RELEASE_REFUSED",
            "release_status": refusal_detail.status,
            "release_code": refusal_detail.code,
            "retryable": refusal_detail.retryable,
            "receipt_digest": receipt_digest,
            "receipt_verified": True,
        }
        findings_out: list[dict[str, Any]] = [release_finding]
        if refusal_detail.status == "REVIEW":
            findings_out.insert(
                0,
                {
                    "code": FINDING_CODE_REVIEW_PENDING,
                    "severity": "review",
                    "message": "Agent Integrity RELEASE_REFUSED with REVIEW status — requires human approval",
                    "needs_human_review": True,
                    "integrity_status": "REVIEW",
                    "integrity_findings": base_findings,
                    "receipt_digest": receipt_digest,
                    "receipt_verified": True,
                },
            )
        findings_out.extend(base_findings)

        return VerifyReleaseOutcome(
            admitted=False,
            status=VerifyReleaseStatus.RELEASE_REFUSED,
            request_id=expected_request_id,
            verification=verification,
            receipt=receipt,
            receipt_verified=True,
            release_refusal=refusal_detail,
            findings=findings_out,
        )

    def _parse_failure_outcome(
        self,
        request_id: str,
        message: str,
    ) -> VerifyReleaseOutcome:
        logger.error("[Provider06] Protocol validation failure: %s", message)
        return VerifyReleaseOutcome(
            admitted=False,
            status=None,
            request_id=request_id,
            error=message,
            findings=[
                {
                    "code": FINDING_CODE_PARSE_ERROR,
                    "severity": "blocked",
                    "message": message,
                }
            ],
        )

    async def _verify_v1_receipt(
        self,
        *,
        receipt: dict[str, Any],
        envelope: dict[str, Any],
        expected_verification: dict[str, Any],
    ) -> tuple[str | None, str | None]:
        """Verify cryptographic receipt, envelope/policy digests, and profile bounds."""
        if self._jwks_client is None:
            return (
                "Out-of-band key manifest (JWKS) is required for /v1/verify-release",
                FINDING_CODE_UNKNOWN_KEY,
            )

        if not verify_receipt_digest(receipt, strict_v2=True):
            return ("Receipt digest verification failed", FINDING_CODE_INVALID_DIGEST)

        signature_block = receipt.get("signature", {})
        key_id = (
            signature_block.get("keyId") if isinstance(signature_block, dict) else None
        )
        if not isinstance(key_id, str) or not key_id:
            return ("Receipt missing signature key ID", FINDING_CODE_UNKNOWN_KEY)

        try:
            public_key = await self._jwks_client.get_key(key_id)
        except Exception as exc:
            logger.error("[Provider06] Key manifest verification failed: %s", exc)
            return (
                f"Key manifest verification failed: {exc}",
                FINDING_CODE_UNKNOWN_KEY,
            )

        if public_key is None:
            return (f"Unknown or revoked key ID: {key_id}", FINDING_CODE_UNKNOWN_KEY)

        if not verify_receipt_signature(receipt, public_key, strict_v2=True):
            return (
                "Receipt signature verification failed",
                FINDING_CODE_INVALID_SIGNATURE,
            )

        # Verify canonical equality between response.verification and receipt.verification
        receipt_verification = receipt.get("verification")
        if not isinstance(receipt_verification, dict) or jcs_canonicalize_plan(
            receipt_verification
        ) != jcs_canonicalize_plan(expected_verification):
            return (
                "Receipt verification block does not match response verification",
                FINDING_CODE_INVALID_DIGEST,
            )

        # Verify envelopeDigest matches sha256(jcs(envelope))
        expected_env_digest = hashlib.sha256(
            jcs_canonicalize_plan(envelope)
        ).hexdigest()
        if receipt.get("envelopeDigest") != expected_env_digest:
            return (
                f"Receipt envelopeDigest mismatch: expected={expected_env_digest} got={receipt.get('envelopeDigest')}",
                FINDING_CODE_ENVELOPE_DIGEST_MISMATCH,
            )

        # Verify policyDigest if policy is present in envelope
        if isinstance(envelope.get("policy"), dict):
            expected_policy_digest = hashlib.sha256(
                jcs_canonicalize_plan(envelope["policy"])
            ).hexdigest()
            if receipt.get("policyDigest") != expected_policy_digest:
                return (
                    "Receipt policyDigest does not match envelope.policy",
                    FINDING_CODE_POLICY_DIGEST_MISMATCH,
                )

        # Verify timestamps and optional manifest receiptProfile constraints
        created_at_str = receipt.get("createdAt")
        expires_at_str = receipt.get("expiresAt")
        if not isinstance(created_at_str, str) or not isinstance(expires_at_str, str):
            return (
                "Receipt missing createdAt or expiresAt",
                FINDING_CODE_RECEIPT_EXPIRED,
            )

        try:
            created_at = datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
            expires_at = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
        except ValueError:
            return ("Invalid receipt timestamp format", FINDING_CODE_RECEIPT_EXPIRED)

        now = datetime.now(timezone.utc)
        if expires_at <= created_at:
            return (
                "Receipt expiresAt must be later than createdAt",
                FINDING_CODE_RECEIPT_EXPIRED,
            )
        if now >= expires_at:
            return (
                f"Receipt expired at {expires_at.isoformat()}",
                FINDING_CODE_RECEIPT_EXPIRED,
            )

        profile = self._jwks_client.receipt_profile
        if profile is not None:
            if receipt.get("issuer") != profile.issuer:
                return ("Receipt issuer mismatch", FINDING_CODE_INVALID_SIGNATURE)
            if receipt.get("audience") != profile.audience:
                return ("Receipt audience mismatch", FINDING_CODE_INVALID_SIGNATURE)
            if receipt.get("purpose") != profile.purpose:
                return ("Receipt purpose mismatch", FINDING_CODE_INVALID_SIGNATURE)
            if receipt.get("engineVersion") != profile.engine_version:
                return (
                    "Receipt engineVersion mismatch",
                    FINDING_CODE_INVALID_SIGNATURE,
                )
            if created_at > now + timedelta(
                seconds=profile.maximum_future_skew_seconds
            ):
                return (
                    "Receipt createdAt exceeds maximum future skew",
                    FINDING_CODE_RECEIPT_EXPIRED,
                )
            if (expires_at - created_at) > timedelta(
                seconds=profile.maximum_receipt_lifetime_seconds
            ):
                return (
                    "Receipt lifetime exceeds profile maximum",
                    FINDING_CODE_RECEIPT_EXPIRED,
                )

        return (None, None)

    async def validate_fria(self, payload: dict[str, Any]):  # type: ignore[no-untyped-def]
        """Submit payload for Agent Integrity verification.

        When configured for the Phase 2 sidecar contract (``use_verify_release=True``,
        ``socket_path`` set, HMAC secret configured, or payload carrying
        ``serviceProtocolVersion == "1"``), dispatches to ``POST /v1/verify-release``
        via :meth:`verify_release`. Otherwise falls back to the Phase 1 HTTP
        ``POST /verify`` endpoint for legacy test compatibility.
        """
        import httpx

        if self._use_verify_release or (
            isinstance(payload, dict)
            and payload.get("serviceProtocolVersion") == SIDECAR_PROTOCOL_VERSION
        ):
            outcome = await self.verify_release(payload)
            return outcome.to_validation_result()

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

            result = IntegrityResult.from_dict(data)
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
        """Map Agent Integrity tri-state verdict to CAGE ValidationResult."""
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

        review_findings = [
            {
                "code": FINDING_CODE_REVIEW_PENDING,
                "severity": "review",
                "message": "Agent Integrity returned REVIEW — requires human approval",
                "needs_human_review": True,
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
        """Submit governance evidence hash to Agent Integrity for sealing."""
        import httpx

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
                receipt = resp.json()

            if self._jwks_client is not None:
                verification_result = await self._verify_receipt(receipt, evidence_hash)
                if verification_result is not None:
                    return EvidenceSeal(
                        thread_id=thread_id,
                        error=verification_result,
                    )

            return EvidenceSeal(
                thread_id=thread_id,
                seal_hash=receipt.get("receiptDigest", ""),
            )

        except Exception as exc:
            logger.error(
                "[Provider06] submit_evidence failed: %s %s",
                url,
                exc,
            )
            return EvidenceSeal(thread_id=thread_id, error=str(exc))

    async def _verify_receipt(
        self,
        receipt: dict[str, Any],
        evidence_hash: str,
    ) -> str | None:
        """Verify cryptographic integrity of Agent Integrity receipt."""
        if not verify_receipt_digest(receipt):
            logger.error("[Provider06] Receipt digest verification FAILED")
            return "Receipt digest verification failed"

        signature_block = receipt.get("signature", {})
        key_id = signature_block.get("keyId")

        if not key_id:
            logger.error("[Provider06] Receipt missing signature.keyId")
            return "Receipt missing signature key ID"

        assert self._jwks_client is not None
        public_key = await self._jwks_client.get_key(key_id)

        if public_key is None:
            logger.error("[Provider06] Unknown key ID: %s", key_id)
            return f"Unknown key ID: {key_id}"

        if not verify_receipt_signature(receipt, public_key):
            logger.error("[Provider06] Receipt signature verification FAILED")
            return "Receipt signature verification failed"

        envelope_digest = receipt.get("envelopeDigest", "")
        if envelope_digest != evidence_hash:
            logger.warning(
                "[Provider06] Envelope digest mismatch: expected=%s got=%s",
                evidence_hash,
                envelope_digest,
            )

        expires_at_str = receipt.get("expiresAt")
        if expires_at_str:
            try:
                expires_at = datetime.fromisoformat(
                    expires_at_str.replace("Z", "+00:00")
                )
                now = datetime.now(timezone.utc)
                if now > expires_at:
                    logger.error(
                        "[Provider06] Receipt expired: now=%s expires_at=%s",
                        now.isoformat(),
                        expires_at.isoformat(),
                    )
                    return f"Receipt expired at {expires_at.isoformat()}"
            except (ValueError, TypeError) as exc:
                logger.warning("[Provider06] Invalid expiresAt format: %s", exc)

        logger.info("[Provider06] Receipt verification SUCCESS (kid=%s)", key_id)
        return None


# ---------------------------------------------------------------------------
# Helper: Check if ValidationResult indicates REVIEW status
# ---------------------------------------------------------------------------


def is_review_pending(findings: list[dict[str, Any]]) -> bool:
    """Check if findings indicate Agent Integrity REVIEW status."""
    return any(f.get("needs_human_review", False) for f in findings)


def extract_integrity_status(
    findings: list[dict[str, Any]],
) -> Literal["PASS", "REVIEW", "BLOCKED", "RELEASE_REFUSED"] | None:
    """Extract the Agent Integrity status from findings."""
    for finding in findings:
        status = finding.get("integrity_status")
        if status in ("PASS", "REVIEW", "BLOCKED", "RELEASE_REFUSED"):
            return status  # type: ignore[return-value]
    return None

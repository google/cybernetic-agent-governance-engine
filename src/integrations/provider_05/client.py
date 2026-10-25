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
Provider 05 (Veraxis Execution Integrity Protocol — VEIP) Client Interface.

Provides structured access to Provider 05 attestation endpoints for the Three Axioms:
  1. Policy Legitimacy (Blueprint) — RiskAcceptanceRecord
  2. Identity Genesis (Key) — AdmissibilityGrant
  3. Substrate Integrity (Physics) — SubstrateAttestation

Supports both seeded synthetic v0.1/v0.3 test instances and live HTTP v0.3
endpoint connections with out-of-band key-manifest and purpose-bound Ed25519
signature verification.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import httpx

from src.gateway.governance.governance_envelope import AttestationStatus
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.warrant.model import WarrantScope
from src.gateway.governance.warrant.trust_anchor import (
    VerifiedKeyManifest,
    WarrantTrustAnchor,
)

logger = logging.getLogger("cage.integrations.provider_05.client")

_ENDPOINT: str = os.environ.get("PROVIDER_05_ATTESTATION_ENDPOINT", "")
_API_KEY_SECRET: str = os.environ.get("PROVIDER_05_API_KEY_SECRET", "")
_TIMEOUT_SECONDS: float = float(os.environ.get("PROVIDER_05_TIMEOUT_SECONDS", "5.0"))

BLUEPRINT_SCHEMA_VERSION_V03 = "veip-riskacceptancerecord/0.3"
KEY_SCHEMA_VERSION_V03 = "veip-admissibilitygrant/0.3"
PHYSICS_SCHEMA_VERSION_V03 = "veip-substrateattestation/0.3"
DEFAULT_V03_MAX_AGE_SECONDS: float = 60.0

_NUMERIC_RE = re.compile(r"[-+]?\d+(?:\.\d+)?")


def _validate_endpoint_scheme(endpoint: str) -> None:
    if not endpoint.startswith(("https://", "http://")):
        raise ValueError(
            f"Unsupported endpoint URL scheme for {endpoint!r}; "
            "must start with 'https://' or 'http://'"
        )


def _parse_numeric_limit(raw: str) -> float | None:
    match = _NUMERIC_RE.search(raw.replace(",", ""))
    if not match:
        return None
    try:
        return float(match.group(0))
    except ValueError:
        return None


def _coerce_scope(
    scope: Mapping[str, Any] | WarrantScope | None,
) -> WarrantScope | None:
    if scope is None:
        return None
    if isinstance(scope, WarrantScope):
        return scope
    if isinstance(scope, Mapping):
        return WarrantScope.from_dict(dict(scope))
    return None


@dataclass
class RiskAcceptanceRecord:
    """Signed risk-acceptance record for a threshold value (Axiom 1: Blueprint).

    Supports both v0.1 synthetic fields and VEIP v0.3 signed schema fields
    (``veip-riskacceptancerecord/0.3``).
    """

    threshold_id: str = ""
    threshold_value: float = 0.0
    ao_name: str = ""
    ao_signature_hash: str = ""
    receipt_id: str = ""
    attested_at: str = ""
    rationale: str = ""
    # VEIP v0.3 fields
    schema_version: str = ""
    environment: str = ""
    artifact_id: str = ""
    issuer: str = ""
    subject_ref: str = ""
    scope: WarrantScope | dict[str, Any] | None = None
    issued_at: str = ""
    valid_from: str = ""
    valid_until: str = ""
    state_as_of: str = ""
    alg: str = ""
    kid: str = ""
    digest: str = ""
    signature: str = ""
    risk_id: str = ""
    accepted_by: str = ""
    risk_limit: str = ""

    def __post_init__(self) -> None:
        self.scope = _coerce_scope(self.scope)
        if not self.threshold_id and self.risk_id:
            self.threshold_id = self.risk_id
        if not self.risk_id and self.threshold_id:
            self.risk_id = self.threshold_id
        if not self.ao_name and self.accepted_by:
            self.ao_name = self.accepted_by
        if not self.accepted_by and self.ao_name:
            self.accepted_by = self.ao_name
        if not self.receipt_id and self.artifact_id:
            self.receipt_id = self.artifact_id
        if not self.artifact_id and self.receipt_id:
            self.artifact_id = self.receipt_id
        if not self.attested_at and self.issued_at:
            self.attested_at = self.issued_at
        if not self.issued_at and self.attested_at:
            self.issued_at = self.attested_at
        if not self.ao_signature_hash and self.digest:
            self.ao_signature_hash = f"sha256:{self.digest}"
        if self.threshold_value == 0.0 and self.risk_limit:
            parsed = _parse_numeric_limit(self.risk_limit)
            if parsed is not None:
                self.threshold_value = parsed

    @property
    def is_v03(self) -> bool:
        return bool(
            self.schema_version == BLUEPRINT_SCHEMA_VERSION_V03
            or self.signature
            or self.kid
        )

    def to_unsigned_v03_dict(self) -> dict[str, Any]:
        scope_obj = _coerce_scope(self.scope)
        return {
            "schema_version": self.schema_version or BLUEPRINT_SCHEMA_VERSION_V03,
            "environment": self.environment or "SANDBOX",
            "artifact_id": self.artifact_id,
            "issuer": self.issuer,
            "subject_ref": self.subject_ref,
            "scope": scope_obj.to_dict() if scope_obj is not None else {},
            "issued_at": self.issued_at,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "state_as_of": self.state_as_of,
            "alg": self.alg or "Ed25519",
            "kid": self.kid,
            "risk_id": self.risk_id,
            "accepted_by": self.accepted_by,
            "risk_limit": self.risk_limit,
        }

    def compute_digest(self) -> str:
        return hashlib.sha256(
            jcs_canonicalize_plan(self.to_unsigned_v03_dict())
        ).hexdigest()

    def to_signed_bytes(self) -> bytes:
        body = self.to_unsigned_v03_dict()
        body["digest"] = self.digest
        return jcs_canonicalize_plan(body)

    def to_v03_dict(self) -> dict[str, Any]:
        body = self.to_unsigned_v03_dict()
        body["digest"] = self.digest
        body["signature"] = self.signature
        return body

    @classmethod
    def from_v03_dict(cls, payload: Mapping[str, Any]) -> RiskAcceptanceRecord:
        return cls(
            schema_version=str(payload.get("schema_version", "")),
            environment=str(payload.get("environment", "")),
            artifact_id=str(payload.get("artifact_id", "")),
            issuer=str(payload.get("issuer", "")),
            subject_ref=str(payload.get("subject_ref", "")),
            scope=payload.get("scope"),
            issued_at=str(payload.get("issued_at", "")),
            valid_from=str(payload.get("valid_from", "")),
            valid_until=str(payload.get("valid_until", "")),
            state_as_of=str(payload.get("state_as_of", "")),
            alg=str(payload.get("alg", "")),
            kid=str(payload.get("kid", "")),
            digest=str(payload.get("digest", "")),
            signature=str(payload.get("signature", "")),
            risk_id=str(payload.get("risk_id", "")),
            accepted_by=str(payload.get("accepted_by", "")),
            risk_limit=str(payload.get("risk_limit", "")),
        )

    def to_canonical_bytes(self) -> bytes:
        if self.is_v03:
            return jcs_canonicalize_plan(self.to_unsigned_v03_dict())
        return jcs_canonicalize_plan(
            {
                "threshold_id": self.threshold_id,
                "threshold_value": self.threshold_value,
                "ao_name": self.ao_name,
                "ao_signature_hash": self.ao_signature_hash,
                "receipt_id": self.receipt_id,
                "attested_at": self.attested_at,
                "rationale": self.rationale,
            }
        )


@dataclass
class AdmissibilityGrant:
    """Identity authority admissibility grant (Axiom 2: Key).

    Supports both v0.1 synthetic fields and VEIP v0.3 signed schema fields
    (``veip-admissibilitygrant/0.3``).
    """

    spiffe_id: str = ""
    consequence_class: str = ""
    ca_fingerprint: str = ""
    receipt_id: str = ""
    attested_at: str = ""
    admitted: bool = True
    # VEIP v0.3 fields
    schema_version: str = ""
    environment: str = ""
    artifact_id: str = ""
    issuer: str = ""
    subject_ref: str = ""
    scope: WarrantScope | dict[str, Any] | None = None
    issued_at: str = ""
    valid_from: str = ""
    valid_until: str = ""
    state_as_of: str = ""
    alg: str = ""
    kid: str = ""
    digest: str = ""
    signature: str = ""
    grant_id: str = ""
    authority_basis_ref: str = ""
    permitted_action: str = ""

    def __post_init__(self) -> None:
        self.scope = _coerce_scope(self.scope)
        if not self.spiffe_id and self.subject_ref:
            self.spiffe_id = self.subject_ref
        if not self.subject_ref and self.spiffe_id:
            self.subject_ref = self.spiffe_id
        if not self.consequence_class and self.permitted_action:
            self.consequence_class = self.permitted_action
        if not self.permitted_action and self.consequence_class:
            self.permitted_action = self.consequence_class
        if not self.ca_fingerprint and self.authority_basis_ref:
            self.ca_fingerprint = self.authority_basis_ref
        if not self.authority_basis_ref and self.ca_fingerprint:
            self.authority_basis_ref = self.ca_fingerprint
        if not self.receipt_id and self.artifact_id:
            self.receipt_id = self.artifact_id
        if not self.artifact_id and self.receipt_id:
            self.artifact_id = self.receipt_id
        if not self.attested_at and self.issued_at:
            self.attested_at = self.issued_at
        if not self.issued_at and self.attested_at:
            self.issued_at = self.attested_at

    @property
    def is_v03(self) -> bool:
        return bool(
            self.schema_version == KEY_SCHEMA_VERSION_V03 or self.signature or self.kid
        )

    def to_unsigned_v03_dict(self) -> dict[str, Any]:
        scope_obj = _coerce_scope(self.scope)
        return {
            "schema_version": self.schema_version or KEY_SCHEMA_VERSION_V03,
            "environment": self.environment or "SANDBOX",
            "artifact_id": self.artifact_id,
            "issuer": self.issuer,
            "subject_ref": self.subject_ref,
            "scope": scope_obj.to_dict() if scope_obj is not None else {},
            "issued_at": self.issued_at,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "state_as_of": self.state_as_of,
            "alg": self.alg or "Ed25519",
            "kid": self.kid,
            "grant_id": self.grant_id,
            "authority_basis_ref": self.authority_basis_ref,
            "permitted_action": self.permitted_action,
        }

    def compute_digest(self) -> str:
        return hashlib.sha256(
            jcs_canonicalize_plan(self.to_unsigned_v03_dict())
        ).hexdigest()

    def to_signed_bytes(self) -> bytes:
        body = self.to_unsigned_v03_dict()
        body["digest"] = self.digest
        return jcs_canonicalize_plan(body)

    def to_v03_dict(self) -> dict[str, Any]:
        body = self.to_unsigned_v03_dict()
        body["digest"] = self.digest
        body["signature"] = self.signature
        return body

    @classmethod
    def from_v03_dict(cls, payload: Mapping[str, Any]) -> AdmissibilityGrant:
        return cls(
            schema_version=str(payload.get("schema_version", "")),
            environment=str(payload.get("environment", "")),
            artifact_id=str(payload.get("artifact_id", "")),
            issuer=str(payload.get("issuer", "")),
            subject_ref=str(payload.get("subject_ref", "")),
            scope=payload.get("scope"),
            issued_at=str(payload.get("issued_at", "")),
            valid_from=str(payload.get("valid_from", "")),
            valid_until=str(payload.get("valid_until", "")),
            state_as_of=str(payload.get("state_as_of", "")),
            alg=str(payload.get("alg", "")),
            kid=str(payload.get("kid", "")),
            digest=str(payload.get("digest", "")),
            signature=str(payload.get("signature", "")),
            grant_id=str(payload.get("grant_id", "")),
            authority_basis_ref=str(payload.get("authority_basis_ref", "")),
            permitted_action=str(payload.get("permitted_action", "")),
        )

    def to_canonical_bytes(self) -> bytes:
        if self.is_v03:
            return jcs_canonicalize_plan(self.to_unsigned_v03_dict())
        return jcs_canonicalize_plan(
            {
                "spiffe_id": self.spiffe_id,
                "consequence_class": self.consequence_class,
                "ca_fingerprint": self.ca_fingerprint,
                "receipt_id": self.receipt_id,
                "attested_at": self.attested_at,
                "admitted": self.admitted,
            }
        )


@dataclass
class SubstrateAttestation:
    """Substrate hardware & hypervisor integrity attestation (Axiom 3: Physics).

    Supports both v0.1 synthetic fields and VEIP v0.3 signed schema fields
    (``veip-substrateattestation/0.3``).
    """

    node_id: str = ""
    vtpm_status: str = "VERIFIED"  # "VERIFIED", "TAMPERED", "UNKNOWN"
    ebpf_anomaly_count: int = 0
    receipt_id: str = ""
    attested_at: str = ""
    freshness_seconds: int = 0
    # VEIP v0.3 fields
    schema_version: str = ""
    environment: str = ""
    artifact_id: str = ""
    issuer: str = ""
    subject_ref: str = ""
    scope: WarrantScope | dict[str, Any] | None = None
    issued_at: str = ""
    valid_from: str = ""
    valid_until: str = ""
    state_as_of: str = ""
    alg: str = ""
    kid: str = ""
    digest: str = ""
    signature: str = ""
    substrate_id: str = ""
    attestation_result: str = ""
    measurement_ref: str = ""

    def __post_init__(self) -> None:
        self.scope = _coerce_scope(self.scope)
        if not self.node_id and self.substrate_id:
            self.node_id = self.substrate_id
        if not self.substrate_id and self.node_id:
            self.substrate_id = self.node_id
        if self.attestation_result == "FAIL":
            self.vtpm_status = "TAMPERED"
        elif self.attestation_result == "PASS" and not self.vtpm_status:
            self.vtpm_status = "VERIFIED"
        if not self.receipt_id and self.artifact_id:
            self.receipt_id = self.artifact_id
        if not self.artifact_id and self.receipt_id:
            self.artifact_id = self.receipt_id
        if not self.attested_at and self.issued_at:
            self.attested_at = self.issued_at
        if not self.issued_at and self.attested_at:
            self.issued_at = self.attested_at

    @property
    def is_v03(self) -> bool:
        return bool(
            self.schema_version == PHYSICS_SCHEMA_VERSION_V03
            or self.signature
            or self.kid
        )

    def to_unsigned_v03_dict(self) -> dict[str, Any]:
        scope_obj = _coerce_scope(self.scope)
        return {
            "schema_version": self.schema_version or PHYSICS_SCHEMA_VERSION_V03,
            "environment": self.environment or "SANDBOX",
            "artifact_id": self.artifact_id,
            "issuer": self.issuer,
            "subject_ref": self.subject_ref,
            "scope": scope_obj.to_dict() if scope_obj is not None else {},
            "issued_at": self.issued_at,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "state_as_of": self.state_as_of,
            "alg": self.alg or "Ed25519",
            "kid": self.kid,
            "substrate_id": self.substrate_id,
            "attestation_result": self.attestation_result or "PASS",
            "measurement_ref": self.measurement_ref,
        }

    def compute_digest(self) -> str:
        return hashlib.sha256(
            jcs_canonicalize_plan(self.to_unsigned_v03_dict())
        ).hexdigest()

    def to_signed_bytes(self) -> bytes:
        body = self.to_unsigned_v03_dict()
        body["digest"] = self.digest
        return jcs_canonicalize_plan(body)

    def to_v03_dict(self) -> dict[str, Any]:
        body = self.to_unsigned_v03_dict()
        body["digest"] = self.digest
        body["signature"] = self.signature
        return body

    @classmethod
    def from_v03_dict(cls, payload: Mapping[str, Any]) -> SubstrateAttestation:
        return cls(
            schema_version=str(payload.get("schema_version", "")),
            environment=str(payload.get("environment", "")),
            artifact_id=str(payload.get("artifact_id", "")),
            issuer=str(payload.get("issuer", "")),
            subject_ref=str(payload.get("subject_ref", "")),
            scope=payload.get("scope"),
            issued_at=str(payload.get("issued_at", "")),
            valid_from=str(payload.get("valid_from", "")),
            valid_until=str(payload.get("valid_until", "")),
            state_as_of=str(payload.get("state_as_of", "")),
            alg=str(payload.get("alg", "")),
            kid=str(payload.get("kid", "")),
            digest=str(payload.get("digest", "")),
            signature=str(payload.get("signature", "")),
            substrate_id=str(payload.get("substrate_id", "")),
            attestation_result=str(payload.get("attestation_result", "")),
            measurement_ref=str(payload.get("measurement_ref", "")),
        )

    def to_canonical_bytes(self) -> bytes:
        if self.is_v03:
            return jcs_canonicalize_plan(self.to_unsigned_v03_dict())
        return jcs_canonicalize_plan(
            {
                "node_id": self.node_id,
                "vtpm_status": self.vtpm_status,
                "ebpf_anomaly_count": self.ebpf_anomaly_count,
                "receipt_id": self.receipt_id,
                "attested_at": self.attested_at,
                "freshness_seconds": self.freshness_seconds,
            }
        )


@dataclass(frozen=True)
class VeipV03VerificationResult:
    """Result of verifying a VEIP v0.3 BLUEPRINT, KEY, or PHYSICS artifact."""

    accepted: bool
    expected_status: str  # "ACCEPT" or "REJECT"
    attestation_status: str  # AttestationStatus value
    reason_code: str
    reason: str
    attested_at: str


def verify_v03_artifact(
    artifact: RiskAcceptanceRecord | AdmissibilityGrant | SubstrateAttestation | None,
    *,
    expected_purpose: str,
    expected_schema_version: str,
    key_manifest: VerifiedKeyManifest | None,
    context: Mapping[str, Any] | None = None,
    now: datetime | None = None,
    max_age_seconds: float | None = None,
) -> VeipV03VerificationResult:
    """Verify a VEIP v0.3 signed artifact against ``key_manifest`` and ``context``.

    Check order (first failure wins):
      1. Presence (else MISSING -> STALE)
      2. Schema version & key manifest availability
      3. Key lookup in verified manifest (else WRONG_KID -> DENIED)
      4. Key purpose binding (else WRONG_PURPOSE -> DENIED)
      5. Key active window, JCS digest, and Ed25519 signature (else BAD_SIGNATURE -> DENIED)
      6. Artifact validity window [valid_from, valid_until] (else EXPIRED -> STALE)
      7. Issuer state freshness [0, max_age_seconds] of state_as_of (else STALE -> STALE)
      8. Four-dimension scope containment when context provides action/jurisdiction (else OUT_OF_SCOPE -> DENIED)
    """
    ctx = dict(context or {})
    raw_now = now or ctx.get("now")
    if isinstance(raw_now, str):
        current_time = datetime.fromisoformat(raw_now.replace("Z", "+00:00"))
    elif isinstance(raw_now, datetime):
        current_time = raw_now
    else:
        current_time = datetime.now(timezone.utc)
    attested_at = current_time.isoformat()

    def _reject(
        status: AttestationStatus, code: str, reason: str
    ) -> VeipV03VerificationResult:
        return VeipV03VerificationResult(
            accepted=False,
            expected_status="REJECT",
            attestation_status=status.value,
            reason_code=code,
            reason=reason,
            attested_at=attested_at,
        )

    if artifact is None:
        return _reject(
            AttestationStatus.STALE,
            "MISSING",
            f"{expected_purpose} artifact not found",
        )

    if artifact.schema_version != expected_schema_version:
        return _reject(
            AttestationStatus.DENIED,
            "SCHEMA_MISMATCH",
            f"Expected schema_version {expected_schema_version!r}, got {artifact.schema_version!r}",
        )

    if key_manifest is None or not isinstance(key_manifest, VerifiedKeyManifest):
        return _reject(
            AttestationStatus.DENIED,
            "BAD_SIGNATURE",
            "No VerifiedKeyManifest available to verify v0.3 artifact signature",
        )

    if not key_manifest.is_valid_at(current_time):
        return _reject(
            AttestationStatus.DENIED,
            "BAD_SIGNATURE",
            f"Key manifest {key_manifest.manifest_id!r} is outside its validity window",
        )

    if not artifact.kid:
        return _reject(
            AttestationStatus.DENIED,
            "WRONG_KID",
            f"{expected_purpose} artifact is missing kid",
        )

    key_entry = key_manifest.resolve_key(artifact.kid)
    if key_entry is None:
        return _reject(
            AttestationStatus.DENIED,
            "WRONG_KID",
            f"UNKNOWN_KID: {artifact.kid!r} not found in verified key manifest",
        )

    if not key_entry.matches_purpose(expected_purpose) or (
        key_entry.purpose != expected_purpose
    ):
        return _reject(
            AttestationStatus.DENIED,
            "WRONG_PURPOSE",
            f"Key {artifact.kid!r} has purpose {key_entry.purpose!r}, expected {expected_purpose!r}",
        )

    if not key_entry.is_active_at(current_time):
        return _reject(
            AttestationStatus.DENIED,
            "BAD_SIGNATURE",
            f"Issuer key {artifact.kid!r} is not active or is outside validity window",
        )

    if artifact.alg != "Ed25519" or not artifact.digest or not artifact.signature:
        return _reject(
            AttestationStatus.DENIED,
            "BAD_SIGNATURE",
            f"Missing or unsupported cryptographic fields on {expected_purpose} artifact",
        )

    computed_digest = artifact.compute_digest()
    if artifact.digest != computed_digest:
        return _reject(
            AttestationStatus.DENIED,
            "BAD_SIGNATURE",
            f"Digest mismatch: declared {artifact.digest} vs computed {computed_digest}",
        )

    if not key_entry.verify_signature(artifact.signature, artifact.to_signed_bytes()):
        return _reject(
            AttestationStatus.DENIED,
            "BAD_SIGNATURE",
            f"Ed25519 signature verification failed for kid {artifact.kid!r}",
        )

    try:
        from_dt = datetime.fromisoformat(artifact.valid_from.replace("Z", "+00:00"))
        until_dt = datetime.fromisoformat(artifact.valid_until.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        return _reject(
            AttestationStatus.STALE,
            "EXPIRED",
            f"Malformed validity timestamps: {exc}",
        )

    if current_time < from_dt or current_time > until_dt:
        return _reject(
            AttestationStatus.STALE,
            "EXPIRED",
            f"Artifact outside validity window [{artifact.valid_from}, {artifact.valid_until}]",
        )

    try:
        state_dt = datetime.fromisoformat(artifact.state_as_of.replace("Z", "+00:00"))
        state_age = (current_time - state_dt).total_seconds()
    except (TypeError, ValueError) as exc:
        return _reject(
            AttestationStatus.STALE,
            "STALE",
            f"Malformed state_as_of timestamp: {exc}",
        )

    raw_limit = (
        max_age_seconds if max_age_seconds is not None else ctx.get("max_age_seconds")
    )
    freshness_limit = (
        DEFAULT_V03_MAX_AGE_SECONDS if raw_limit is None else float(raw_limit)
    )
    if state_age < 0 or state_age > freshness_limit:
        return _reject(
            AttestationStatus.STALE,
            "STALE",
            f"Artifact state_as_of {artifact.state_as_of} is {state_age:.3f}s old (max {freshness_limit:g}s)",
        )

    scope_obj = _coerce_scope(artifact.scope)
    if scope_obj is None:
        return _reject(
            AttestationStatus.DENIED,
            "OUT_OF_SCOPE",
            "Artifact scope is missing or malformed",
        )

    action = ctx.get("action") or ctx.get("consequence_class")
    jurisdiction = ctx.get("jurisdiction")
    actor = ctx.get("actor") or ctx.get("spiffe_id")
    system = ctx.get("system") or ctx.get("node_id")
    if action or jurisdiction or actor or system:
        check_action = str(action or next(iter(scope_obj.actions), ""))
        check_jurisdiction = str(
            jurisdiction or next(iter(scope_obj.jurisdictions), "")
        )
        if not scope_obj.contains(
            action=check_action,
            jurisdiction=check_jurisdiction,
            actor=str(actor) if actor else None,
            system=str(system) if system else None,
        ):
            return _reject(
                AttestationStatus.DENIED,
                "OUT_OF_SCOPE",
                f"Evaluation context outside artifact scope {scope_obj.to_dict()}",
            )

    return VeipV03VerificationResult(
        accepted=True,
        expected_status="ACCEPT",
        attestation_status=AttestationStatus.VERIFIED.value,
        reason_code="VALID",
        reason=f"{expected_purpose} v0.3 artifact verified",
        attested_at=attested_at,
    )


class Provider05Client:
    """Client for querying Provider 05 attestation services (v0.1 seeded & v0.3 signed)."""

    def __init__(
        self,
        endpoint: str = "",
        api_key: str = "",
        timeout: float = _TIMEOUT_SECONDS,
        *,
        key_manifest: VerifiedKeyManifest | None = None,
        trust_anchor: WarrantTrustAnchor | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._endpoint = (endpoint or _ENDPOINT).rstrip("/")
        if self._endpoint:
            _validate_endpoint_scheme(self._endpoint)
        self._api_key = api_key or _API_KEY_SECRET
        self._timeout = timeout
        self._key_manifest = key_manifest
        self._trust_anchor = trust_anchor
        self._http_client = http_client

        # Seeded in-memory store for synthetic testing / local execution
        self._risk_acceptances: dict[str, RiskAcceptanceRecord] = {}
        self._admissibility_grants: dict[tuple[str, str], AdmissibilityGrant] = {}
        self._admissibility_grants_by_id: dict[str, AdmissibilityGrant] = {}
        self._substrate_attestations: dict[str, SubstrateAttestation] = {}

    @property
    def key_manifest(self) -> VerifiedKeyManifest | None:
        return self._key_manifest

    def seed_key_manifest(
        self,
        manifest: Mapping[str, Any] | VerifiedKeyManifest,
        *,
        trust_anchor: WarrantTrustAnchor | None = None,
        now: datetime | None = None,
    ) -> VerifiedKeyManifest:
        """Seed (and verify if raw) a VEIP key manifest for v0.3 artifact verification."""
        if isinstance(manifest, VerifiedKeyManifest):
            self._key_manifest = manifest
            return manifest
        anchor = trust_anchor or self._trust_anchor
        if anchor is None:
            from src.integrations.provider_05.warrant_source import (
                VEIP_SANDBOX_TRUST_ANCHOR,
            )

            anchor = VEIP_SANDBOX_TRUST_ANCHOR
        verified = VerifiedKeyManifest.verify(manifest, anchor, now=now)
        self._key_manifest = verified
        return verified

    async def get_verified_key_manifest(
        self, *, now: datetime | None = None
    ) -> VerifiedKeyManifest | None:
        """Return the seeded or live-fetched VerifiedKeyManifest."""
        if self._key_manifest is not None:
            return self._key_manifest
        if not self._endpoint:
            return None
        url = f"{self._endpoint}/.well-known/veip/key-manifest-v0.3.json"
        raw = await self._http_get_json(url)
        if raw is None:
            return None
        return self.seed_key_manifest(raw, now=now)

    def seed_risk_acceptance(self, record: RiskAcceptanceRecord) -> None:
        """Seed a risk acceptance record for local/synthetic evaluation."""
        if record.threshold_id:
            self._risk_acceptances[record.threshold_id] = record
        if record.artifact_id:
            self._risk_acceptances[record.artifact_id] = record
        if record.risk_id:
            self._risk_acceptances[record.risk_id] = record

    def seed_admissibility_grant(self, grant: AdmissibilityGrant) -> None:
        """Seed an admissibility grant for local/synthetic evaluation."""
        if grant.spiffe_id and grant.consequence_class:
            self._admissibility_grants[(grant.spiffe_id, grant.consequence_class)] = (
                grant
            )
        if grant.artifact_id:
            self._admissibility_grants_by_id[grant.artifact_id] = grant
        if grant.grant_id:
            self._admissibility_grants_by_id[grant.grant_id] = grant

    def seed_substrate_attestation(self, attestation: SubstrateAttestation) -> None:
        """Seed a substrate attestation for local/synthetic evaluation."""
        if attestation.node_id:
            self._substrate_attestations[attestation.node_id] = attestation
        if attestation.artifact_id:
            self._substrate_attestations[attestation.artifact_id] = attestation
        if attestation.substrate_id:
            self._substrate_attestations[attestation.substrate_id] = attestation

    async def get_risk_acceptance(
        self, threshold_id: str
    ) -> RiskAcceptanceRecord | None:
        """Retrieve the risk acceptance record for a given threshold or artifact_id."""
        if threshold_id in self._risk_acceptances:
            return self._risk_acceptances[threshold_id]
        if not self._endpoint:
            return None
        url = f"{self._endpoint}/v0.3/blueprint/{quote(threshold_id, safe='._-')}"
        payload = await self._http_get_json(url)
        if payload is None:
            return None
        return RiskAcceptanceRecord.from_v03_dict(payload)

    async def get_admissibility_grant(
        self,
        spiffe_id: str,
        consequence_class: str,
        *,
        artifact_id: str = "",
    ) -> AdmissibilityGrant | None:
        """Retrieve the admissibility grant for an identity and consequence class."""
        if artifact_id and artifact_id in self._admissibility_grants_by_id:
            return self._admissibility_grants_by_id[artifact_id]
        key = (spiffe_id, consequence_class)
        if key in self._admissibility_grants:
            return self._admissibility_grants[key]
        if spiffe_id in self._admissibility_grants_by_id:
            return self._admissibility_grants_by_id[spiffe_id]
        if not self._endpoint:
            return None
        lookup_id = artifact_id or f"{spiffe_id}:{consequence_class}"
        url = f"{self._endpoint}/v0.3/key/{quote(lookup_id, safe='._-:')}"
        payload = await self._http_get_json(url)
        if payload is None:
            return None
        return AdmissibilityGrant.from_v03_dict(payload)

    async def get_substrate_attestation(
        self, node_id: str
    ) -> SubstrateAttestation | None:
        """Retrieve substrate attestation for a host/node or artifact_id."""
        if node_id in self._substrate_attestations:
            return self._substrate_attestations[node_id]
        if not self._endpoint:
            return None
        url = f"{self._endpoint}/v0.3/physics/{quote(node_id, safe='._-')}"
        payload = await self._http_get_json(url)
        if payload is None:
            return None
        return SubstrateAttestation.from_v03_dict(payload)

    async def _http_get_json(self, url: str) -> dict[str, Any] | None:
        _validate_endpoint_scheme(url)
        headers: dict[str, str] = {}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        try:
            if self._http_client is not None:
                response = await self._http_client.get(
                    url, headers=headers, timeout=self._timeout
                )
            else:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    response = await client.get(url, headers=headers)
        except httpx.TimeoutException as exc:
            raise TimeoutError(
                f"Provider 05 HTTP request timed out for {url}: {exc}"
            ) from exc
        except httpx.HTTPError as exc:
            raise ConnectionError(
                f"Provider 05 HTTP request failed for {url}: {exc}"
            ) from exc

        if response.status_code == 404:
            return None
        if response.status_code != 200:
            raise ConnectionError(
                f"Provider 05 endpoint {url} returned HTTP {response.status_code}"
            )
        body = response.json()
        if not isinstance(body, dict):
            raise ConnectionError(
                f"Provider 05 endpoint {url} returned non-object JSON"
            )
        return body

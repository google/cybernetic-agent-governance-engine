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

"""Attributable provenance and four-posture derivation for CAGE conformance reports.

Makes self-certification, counterparty verification, and independent third-party
verification machine-distinguishable directly from the conformance artifact.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

PROVENANCE_SCHEMA_VERSION = "cage-conformance-provenance/1.0"
REPORT_SCHEMA_VERSION = "cage-conformance-report/1.0"

_CORP_SUFFIXES = frozenset(
    {
        "llc",
        "ltd",
        "limited",
        "inc",
        "incorporated",
        "corp",
        "corporation",
        "plc",
        "gmbh",
        "ag",
    }
)


class ProvenanceValidationError(ValueError):
    """Raised when a conformance report's provenance block is missing or invalid."""


class VerificationPosture(str, Enum):
    """Four-way verification posture derived from runner vs. adapter provenance."""

    AUTHOR_SELF_TEST = "AUTHOR_SELF_TEST"
    """Runner is the author of the integration adapter under test."""

    COUNTERPARTY_VERIFIED = "COUNTERPARTY_VERIFIED"
    """Runner is the counterparty on the other side of the boundary (identity verified)."""

    INDEPENDENT_PARTY_VERIFIED = "INDEPENDENT_PARTY_VERIFIED"
    """Runner is neither adapter author nor counterparty (identity verified)."""

    UNVERIFIED_LOCAL = "UNVERIFIED_LOCAL"
    """No cryptographic/OIDC identity proof attached for non-author runner."""


class IdentityProofType(str, Enum):
    """Cryptographic or workload-identity proof backing the runner identity."""

    NONE = "NONE"
    GITHUB_OIDC = "GITHUB_OIDC"
    GCP_OIDC = "GCP_OIDC"
    SIGSTORE_OIDC = "SIGSTORE_OIDC"


def normalize_org_name(org: str) -> str:
    """Normalize an organization name for deterministic posture comparison.

    Strips punctuation and legal entity suffixes (e.g. ``"Google LLC"`` ->
    ``"google"``, ``"FlowSignal Ltd."`` -> ``"flowsignal"``).
    """
    tokens = [t for t in re.split(r"[^a-z0-9]+", org.lower().strip()) if t]
    while len(tokens) > 1 and tokens[-1] in _CORP_SUFFIXES:
        tokens.pop()
    return "".join(tokens)


class AdapterUnderTest(BaseModel):
    """Provenance metadata identifying the integration or component under test."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    provider_id: str = Field(..., min_length=1)
    adapter_author_org: str = Field(..., min_length=1)
    counterparty_org: str = Field(..., min_length=1)
    adapter_version: str = Field(..., min_length=1)
    adapter_commit: str = Field(..., min_length=7)
    contract_profile: str = Field(..., min_length=1)

    @field_validator(
        "provider_id",
        "adapter_author_org",
        "counterparty_org",
        "adapter_version",
        "adapter_commit",
        "contract_profile",
    )
    @classmethod
    def _non_blank(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("field must not be blank")
        return cleaned


class RunnerProvenance(BaseModel):
    """Provenance metadata identifying who executed the conformance run."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    runner_org: str = Field(..., min_length=1)
    runner_identity: str = Field(..., min_length=1)
    identity_proof: IdentityProofType = IdentityProofType.NONE
    oidc_issuer: str | None = None
    oidc_subject: str | None = None
    oidc_token_sha256: str | None = None
    cage_conformance_version: str = Field(..., min_length=1)
    cage_commit: str = Field(..., min_length=7)
    timestamp_utc: str = Field(..., min_length=1)

    @field_validator(
        "runner_org", "runner_identity", "cage_conformance_version", "cage_commit"
    )
    @classmethod
    def _non_blank(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("field must not be blank")
        return cleaned

    @field_validator("timestamp_utc")
    @classmethod
    def _validate_tz_aware_iso(cls, value: str) -> str:
        cleaned = value.strip()
        iso_candidate = cleaned[:-1] + "+00:00" if cleaned.endswith("Z") else cleaned
        try:
            parsed = datetime.fromisoformat(iso_candidate)
        except ValueError as exc:
            raise ValueError(f"invalid ISO-8601 timestamp: {value!r}") from exc
        if parsed.tzinfo is None or parsed.tzinfo.utcoffset(parsed) is None:
            raise ValueError("timestamp_utc must be timezone-aware")
        return cleaned

    @model_validator(mode="after")
    def _validate_oidc_fields(self) -> RunnerProvenance:
        if self.identity_proof != IdentityProofType.NONE:
            if not self.oidc_issuer or not self.oidc_issuer.strip():
                raise ValueError(
                    f"oidc_issuer is required when identity_proof={self.identity_proof.value}"
                )
            if not self.oidc_subject or not self.oidc_subject.strip():
                raise ValueError(
                    f"oidc_subject is required when identity_proof={self.identity_proof.value}"
                )
            if not self.oidc_token_sha256 or not re.fullmatch(
                r"[0-9a-f]{64}", self.oidc_token_sha256
            ):
                raise ValueError(
                    "oidc_token_sha256 must be a 64-character lowercase hex SHA-256 digest "
                    f"when identity_proof={self.identity_proof.value}"
                )
        return self


def derive_verification_posture(
    adapter: AdapterUnderTest,
    runner: RunnerProvenance,
) -> VerificationPosture:
    """Deterministically derive the four-way verification posture.

    Rules:
    1. If ``runner_org`` matches ``adapter_author_org``, posture is always
       ``AUTHOR_SELF_TEST`` (regardless of whether OIDC is attached).
    2. If ``identity_proof == NONE`` and ``runner_org != adapter_author_org``,
       posture fails closed to ``UNVERIFIED_LOCAL`` (neither counterparty nor
       independent verification can be claimed without identity proof).
    3. With verified OIDC proof:
       - ``runner_org == counterparty_org`` -> ``COUNTERPARTY_VERIFIED``
       - ``runner_org not in {adapter_author_org, counterparty_org}`` ->
         ``INDEPENDENT_PARTY_VERIFIED``.
    """
    author_norm = normalize_org_name(adapter.adapter_author_org)
    counterparty_norm = normalize_org_name(adapter.counterparty_org)
    runner_norm = normalize_org_name(runner.runner_org)

    if not author_norm or not counterparty_norm or not runner_norm:
        raise ProvenanceValidationError(
            "Organization names must contain at least one alphanumeric character"
        )

    if runner_norm == author_norm:
        return VerificationPosture.AUTHOR_SELF_TEST

    if runner.identity_proof == IdentityProofType.NONE:
        return VerificationPosture.UNVERIFIED_LOCAL

    if runner_norm == counterparty_norm:
        return VerificationPosture.COUNTERPARTY_VERIFIED

    return VerificationPosture.INDEPENDENT_PARTY_VERIFIED


class ProvenanceBlock(BaseModel):
    """Mandatory provenance envelope attached to every CAGE conformance report."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = PROVENANCE_SCHEMA_VERSION
    adapter_under_test: AdapterUnderTest
    runner: RunnerProvenance
    verification_posture: VerificationPosture
    independent_of_author: bool
    third_party_independent: bool

    @model_validator(mode="after")
    def _enforce_posture_integrity(self) -> ProvenanceBlock:
        if self.schema_version != PROVENANCE_SCHEMA_VERSION:
            raise ValueError(
                f"Unsupported provenance schema_version {self.schema_version!r}; "
                f"expected {PROVENANCE_SCHEMA_VERSION!r}"
            )
        expected_posture = derive_verification_posture(
            self.adapter_under_test,
            self.runner,
        )
        if self.verification_posture != expected_posture:
            raise ValueError(
                f"Posture mismatch: recorded {self.verification_posture.value!r} "
                f"does not match derived {expected_posture.value!r}"
            )
        expected_ind_author = expected_posture in (
            VerificationPosture.COUNTERPARTY_VERIFIED,
            VerificationPosture.INDEPENDENT_PARTY_VERIFIED,
        )
        if self.independent_of_author != expected_ind_author:
            raise ValueError(
                f"independent_of_author={self.independent_of_author} contradicts "
                f"posture {expected_posture.value}"
            )
        expected_third_party = (
            expected_posture == VerificationPosture.INDEPENDENT_PARTY_VERIFIED
        )
        if self.third_party_independent != expected_third_party:
            raise ValueError(
                f"third_party_independent={self.third_party_independent} contradicts "
                f"posture {expected_posture.value}"
            )
        return self


def build_provenance_block(
    *,
    adapter_under_test: AdapterUnderTest,
    runner: RunnerProvenance,
) -> ProvenanceBlock:
    """Construct a validated ProvenanceBlock with deterministically derived posture."""
    posture = derive_verification_posture(adapter_under_test, runner)
    return ProvenanceBlock(
        schema_version=PROVENANCE_SCHEMA_VERSION,
        adapter_under_test=adapter_under_test,
        runner=runner,
        verification_posture=posture,
        independent_of_author=posture
        in (
            VerificationPosture.COUNTERPARTY_VERIFIED,
            VerificationPosture.INDEPENDENT_PARTY_VERIFIED,
        ),
        third_party_independent=(
            posture == VerificationPosture.INDEPENDENT_PARTY_VERIFIED
        ),
    )


def inspect_oidc_jwt(token: str) -> dict[str, str]:
    """Extract issuer, subject, inferred org, and SHA-256 digest from an OIDC JWT.

    Note: In offline CLI execution, this inspects the signed JWT structure and
    binds the exact token SHA-256 digest into the provenance block so downstream
    verifiers can cross-check against Cloud Run / GitHub Actions audit logs.
    """
    cleaned = token.strip()
    parts = cleaned.split(".")
    if len(parts) != 3 or not all(parts):
        raise ProvenanceValidationError(
            "OIDC token must be a compact 3-part JWS (header.payload.signature)"
        )
    payload_b64 = parts[1]
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    try:
        payload_raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        claims = json.loads(payload_raw.decode("utf-8"))
    except Exception as exc:
        raise ProvenanceValidationError(f"Malformed OIDC JWT payload: {exc}") from exc

    if not isinstance(claims, dict):
        raise ProvenanceValidationError("OIDC JWT payload must be a JSON object")

    issuer = str(claims.get("iss", "")).strip()
    subject = str(claims.get("sub", "")).strip()
    if not issuer or not subject:
        raise ProvenanceValidationError(
            "OIDC JWT must contain non-empty 'iss' and 'sub' claims"
        )

    if "token.actions.githubusercontent.com" in issuer:
        proof_type = IdentityProofType.GITHUB_OIDC.value
        inferred_org = str(claims.get("repository_owner", "")).strip()
    elif "accounts.google.com" in issuer or "googleapis.com" in issuer:
        proof_type = IdentityProofType.GCP_OIDC.value
        inferred_org = str(claims.get("hd", "")).strip()
    else:
        proof_type = IdentityProofType.SIGSTORE_OIDC.value
        inferred_org = str(claims.get("org", "")).strip()

    token_sha256 = hashlib.sha256(cleaned.encode("utf-8")).hexdigest()
    return {
        "identity_proof": proof_type,
        "oidc_issuer": issuer,
        "oidc_subject": subject,
        "oidc_token_sha256": token_sha256,
        "inferred_org": inferred_org,
    }


class AssertionResult(BaseModel):
    """Per-assertion pass/fail result within a conformance report."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    assertion_id: str = Field(..., min_length=1)
    category: str = Field(..., min_length=1)
    title: str = Field(..., min_length=1)
    passed: bool
    detail: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)


class ConformanceSummary(BaseModel):
    """Aggregate pass/fail counts for a conformance report."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    total_assertions: int = Field(..., ge=1)
    passed_assertions: int = Field(..., ge=0)
    failed_assertions: int = Field(..., ge=0)
    conformant: bool

    @model_validator(mode="after")
    def _check_counts(self) -> ConformanceSummary:
        if self.passed_assertions + self.failed_assertions != self.total_assertions:
            raise ValueError(
                "passed_assertions + failed_assertions must equal total_assertions"
            )
        if self.conformant != (self.failed_assertions == 0):
            raise ValueError("conformant must be True iff failed_assertions == 0")
        return self


class ConformanceReport(BaseModel):
    """Top-level machine-readable conformance artifact with mandatory provenance."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = REPORT_SCHEMA_VERSION
    mode: str = Field(..., pattern=r"^(trace|endpoint)$")
    target: str = Field(..., min_length=1)
    provenance: ProvenanceBlock
    summary: ConformanceSummary
    assertions: list[AssertionResult] = Field(..., min_length=1)

    @model_validator(mode="after")
    def _validate_report_consistency(self) -> ConformanceReport:
        if self.schema_version != REPORT_SCHEMA_VERSION:
            raise ValueError(
                f"Unsupported report schema_version {self.schema_version!r}; "
                f"expected {REPORT_SCHEMA_VERSION!r}"
            )
        if len(self.assertions) != self.summary.total_assertions:
            raise ValueError(
                f"summary.total_assertions ({self.summary.total_assertions}) "
                f"does not match len(assertions) ({len(self.assertions)})"
            )
        actual_passed = sum(1 for a in self.assertions if a.passed)
        if actual_passed != self.summary.passed_assertions:
            raise ValueError(
                f"summary.passed_assertions ({self.summary.passed_assertions}) "
                f"does not match actual passed count ({actual_passed})"
            )
        return self


def validate_conformance_report(data: Mapping[str, Any]) -> ConformanceReport:
    """Validate a conformance report dictionary, rejecting missing or mismatched provenance."""
    if not isinstance(data, Mapping):
        raise ProvenanceValidationError("Conformance report must be a JSON object")
    if "provenance" not in data:
        raise ProvenanceValidationError(
            "Malformed conformance report: mandatory 'provenance' block is missing"
        )
    try:
        return ConformanceReport.model_validate(dict(data))
    except Exception as exc:
        raise ProvenanceValidationError(f"Malformed conformance report: {exc}") from exc


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format with 'Z' suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

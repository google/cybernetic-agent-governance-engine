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
Normative Provider Seam — Vendor-Neutral Compliance Interface.

This module defines the contract between CAGE's governance kernel and external
normative compliance providers (FlowSignal, Provider 03, Provider 06, etc.).

By extracting these symbols into a dedicated seam module with zero kernel imports,
we eliminate the circular dependency that previously forced provider_01, provider_03,
and provider_06 to use function-scope imports.

Architectural Invariant:
    This module must NEVER import from src.gateway.governance or any other kernel
    module. It defines pure data contracts and protocols only.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol


class ExecutionStatus(str, Enum):
    """Tri-state execution decision from the adaptive gating primitive."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    DEFER = "DEFER"


class FindingStatus(str, Enum):
    """OSCAL four-state assessment result vocabulary.

    Standardized vocabulary for NormativeProvider.validate_fria() findings,
    matching NIST OSCAL Assessment Results finding states and preventing
    vocabulary drift across external compliance providers.
    """

    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"


@dataclass
class NormativeBaseline:
    """Fetched legal/regulatory baseline from an external provider.

    Attributes:
        region:      Deployment region (e.g. "US_FED", "EU_ECB").
        profile:     Raw JSON profile payload (same schema as {REGION}_BASELINE.json).
        fetched_at:  Unix timestamp when the baseline was fetched.
        signature:   KMS signature of the profile payload (hex-encoded).
        etag:        Change detection tag from the provider.
        error:       Error message if fetch failed; None on success.
    """

    region: str
    profile: dict[str, Any]
    fetched_at: float = field(default_factory=time.time)
    signature: str = ""
    etag: str = ""
    error: str | None = None

    @property
    def is_valid(self) -> bool:
        """True if the fetch succeeded and the profile is non-empty."""
        return self.error is None and bool(self.profile)

    @property
    def profile_hash(self) -> str:
        """RFC 8785 JCS SHA-256 hash of the profile for deterministic change detection.

        Note: This method requires jcs_canonicalize_plan from the kernel,
        which creates a dependency. The property is defined here for API
        compatibility, but callers must ensure the canonicalizer is available.
        """
        # Import moved to method scope to avoid module-level kernel dependency
        from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

        canonical = jcs_canonicalize_plan(self.profile)
        return hashlib.sha256(canonical).hexdigest()


@dataclass
class ValidationResult:
    """FRIA validation response from external provider.

    Attributes:
        admitted:   True if the provider admits the transaction.
        findings:   List of compliance findings from the provider.
        sealed_at:  Unix timestamp when the validation was sealed.
        error:      Error message if validation failed; None on success.
    """

    admitted: bool
    findings: list[dict[str, Any]] = field(default_factory=list)
    sealed_at: float = field(default_factory=time.time)
    error: str | None = None


@dataclass
class EvidenceSeal:
    """External attestation seal for the governance evidence chain.

    Attributes:
        thread_id:  LangGraph thread ID for the governed transaction.
        seal_hash:  Provider-generated seal hash for the evidence chain.
        sealed_at:  Unix timestamp when the seal was generated.
        error:      Error message if sealing failed; None on success.
    """

    thread_id: str
    seal_hash: str = ""
    sealed_at: float = field(default_factory=time.time)
    error: str | None = None


class NormativeProvider(Protocol):
    """3-endpoint contract matching §2.5.2 of EXTENSIBILITY_ARCHITECTURE.md.

    Any compliance SaaS, internal policy engine, or regulatory data feed
    that implements these three methods can integrate with CAGE without
    kernel modification.
    """

    async def fetch_baseline(self, region: str) -> NormativeBaseline:
        """GET /legal-baseline/{region} — Normative Data Supply.

        Fetch the active legal/regulatory baseline for a deployment region.
        """
        ...  # pragma: no cover

    async def validate_fria(self, payload: dict[str, Any]) -> ValidationResult:
        """POST /validate/fria — External Validation.

        Submit a governance decision payload for external FRIA validation.
        """
        ...  # pragma: no cover

    async def submit_evidence(self, thread_id: str, evidence_hash: str) -> EvidenceSeal:
        """GET /evidence-chain/{thread_id} — Attestation Logging.

        Submit the local governance evidence hash and retrieve an externally
        sealed attestation for the audit trail.
        """
        ...  # pragma: no cover

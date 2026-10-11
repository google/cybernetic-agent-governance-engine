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
Kernel warrant mechanism: model, standing verifier and evidence binding.

Vendor- and domain-neutral counterpart of the provider_05 contract suite. The
partner-published v0.1 vectors and their pinned digests stay in
``tests/integrations/provider_05/test_provider_05_veip_vectors.py``.
"""

from __future__ import annotations

import ast
import dataclasses
import hashlib
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.gateway.governance.governance_envelope import (
    AttestationStatus,
    ExternalAttestation,
)
from src.gateway.governance.seams import warrant as warrant_seam
from src.gateway.governance.warrant import (
    RelianceStatus,
    Warrant,
    WarrantScope,
    WarrantStandingVerifier,
    WarrantStatus,
)
from src.gateway.governance.warrant.model import StandingVerificationResult
from src.gateway.governance.warrant.reliance import RelianceRecord

pytestmark = [pytest.mark.unit, pytest.mark.local]

EVAL_TIME = datetime(2026, 8, 22, 12, 0, 0, tzinfo=timezone.utc)
CONTEXT = {
    "action": "example.action",
    "jurisdiction": "REGION_A",
    "governing_version": "policy-1.0.0",
}


@pytest.fixture
def sample_warrant() -> Warrant:
    return Warrant.issue(
        warrant_id="warrant-example-001",
        norm_id="example.norm",
        issuing_authority="Example Oversight Committee",
        authority_basis="Example Instrument #1",
        scope=WarrantScope(
            actions=["example.action", "example.other_action"],
            actors=["*"],
            systems=["cage-gateway"],
            jurisdictions=["REGION_A"],
        ),
        valid_from="2026-08-01T00:00:00Z",
        valid_until="2026-12-31T23:59:59Z",
        governing_version="policy-1.0.0",
        status=WarrantStatus.ACTIVE,
        revocation_ref=None,
        residual_risk_ref="RRR-EXAMPLE-1",
    )


def _reissue(warrant: Warrant, **changes: object) -> Warrant:
    return Warrant.issue(**{**warrant.to_canonical_dict(), **changes})


def test_canonicalization_and_digest(sample_warrant: Warrant) -> None:
    canon_bytes = sample_warrant.to_canonical_bytes()
    digest = sample_warrant.compute_digest()
    assert len(digest) == 64
    assert digest == sample_warrant.digest
    assert hashlib.sha256(canon_bytes).hexdigest() == digest
    canonical = sample_warrant.to_canonical_dict()
    assert len(canonical) == 11
    assert canonical["status"] == "ACTIVE"


def test_active_warrant_is_eligible(sample_warrant: Warrant) -> None:
    result = WarrantStandingVerifier.verify_standing(
        sample_warrant,
        context={**CONTEXT, "actor": "urn:example:op", "system": "cage-gateway"},
        now=EVAL_TIME,
    )
    assert result.eligible is True
    assert result.reliance_status == RelianceStatus.ELIGIBLE
    assert result.warrant_id == sample_warrant.warrant_id
    assert result.warrant_digest == sample_warrant.digest


def test_failure_matrix(sample_warrant: Warrant) -> None:
    """Every failure state removes reliance eligibility."""
    verify = WarrantStandingVerifier.verify_standing
    cases = [
        (verify(None, CONTEXT), RelianceStatus.INELIGIBLE_MISSING),
        (
            verify(
                sample_warrant, CONTEXT, now=datetime(2027, 1, 15, tzinfo=timezone.utc)
            ),
            RelianceStatus.INELIGIBLE_EXPIRED,
        ),
        (
            verify(
                _reissue(sample_warrant, status="REVOKED", revocation_ref="Notice #1"),
                CONTEXT,
                now=EVAL_TIME,
            ),
            RelianceStatus.INELIGIBLE_REVOKED,
        ),
        (
            verify(sample_warrant, {**CONTEXT, "action": "unlisted"}, now=EVAL_TIME),
            RelianceStatus.INELIGIBLE_OUT_OF_SCOPE,
        ),
        (
            verify(
                sample_warrant,
                {**CONTEXT, "governing_version": "policy-9.9.9"},
                now=EVAL_TIME,
            ),
            RelianceStatus.INELIGIBLE_VERSION_MISMATCH,
        ),
        (
            verify(
                Warrant(**{**sample_warrant.to_dict(), "digest": "0" * 64}),
                CONTEXT,
                now=EVAL_TIME,
            ),
            RelianceStatus.INELIGIBLE_UNRESOLVED,
        ),
        (
            verify(
                _reissue(sample_warrant, status="SUSPENDED"), CONTEXT, now=EVAL_TIME
            ),
            RelianceStatus.INELIGIBLE_SUSPENDED,
        ),
    ]
    for result, expected in cases:
        assert result.eligible is False
        assert result.reliance_status == expected, result.reason


def _attest(
    standing: StandingVerificationResult, provider_name: str = "example"
) -> ExternalAttestation | None:
    return RelianceRecord(
        norm_id="example.norm",
        required_governing_version=CONTEXT["governing_version"],
        provider_name=provider_name,
        standing=standing,
    ).attestation()


def test_binding_is_unverified_and_names_the_source(sample_warrant: Warrant) -> None:
    standing = WarrantStandingVerifier.verify_standing(
        sample_warrant, context=CONTEXT, now=EVAL_TIME
    )
    att = _attest(standing, provider_name="example_source")
    assert att is not None
    assert att.attestation_type == "WARRANT"
    assert att.status == AttestationStatus.UNVERIFIED.value
    assert att.provider_name == "example_source"
    assert att.receipt_id == sample_warrant.warrant_id
    assert att.attested_at == EVAL_TIME.isoformat()
    assert att.metadata["warrant_digest"] == sample_warrant.digest
    assert att.metadata["reliance_status"] == "ELIGIBLE"


def test_ineligible_binding_is_never_denied(sample_warrant: Warrant) -> None:
    revoked = _reissue(sample_warrant, status="REVOKED", revocation_ref="Notice #1")
    standing = WarrantStandingVerifier.verify_standing(
        revoked, context=CONTEXT, now=EVAL_TIME
    )
    att = _attest(standing, provider_name="example")
    assert att is not None
    assert att.status == AttestationStatus.UNVERIFIED.value
    assert att.metadata["reliance_status"] == "INELIGIBLE_REVOKED"


def test_binding_refuses_foreign_standing_result(sample_warrant: Warrant) -> None:
    other = _reissue(sample_warrant, warrant_id="other")
    standing = WarrantStandingVerifier.verify_standing(
        other, context=CONTEXT, now=EVAL_TIME
    )
    with pytest.raises(ValueError, match="does not belong"):
        _attest(dataclasses.replace(standing, warrant=sample_warrant))


def test_warrant_seam_has_no_runtime_kernel_import() -> None:
    """The seam may reference the kernel ``Warrant`` type for typing only."""
    source = Path(warrant_seam.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    type_checking_nodes: set[int] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.If)
            and isinstance(node.test, ast.Name)
            and node.test.id == "TYPE_CHECKING"
        ):
            type_checking_nodes.update(id(child) for child in ast.walk(node))
    runtime_kernel_imports = [
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        and (node.module or "").startswith("src.")
        and id(node) not in type_checking_nodes
    ]
    assert runtime_kernel_imports == []

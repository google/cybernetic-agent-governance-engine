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

"""Live over-the-wire tests for FlowSignal (provider_01).

FlowSignal's deployed CAGE contract is the Phase 3 v0.2 wire contract in
``docs/partners/provider_01/FLOWSIGNAL_PARTNER_SPECIFICATION.md``. The service
has three routes: ``GET /health``, ``POST /authority/determine`` (FlowSignal's
native contract) and ``POST /cage/validate`` (CAGE's). Each request needs two
credentials. Cloud Run's Domain Restricted Sharing ingress checks a Google ID
token in ``X-Serverless-Authorization``, and the FlowSignal application checks
its own key in ``Authorization``.

FlowSignal serves no legal-baseline or evidence-chain route, so the adapter's
``fetch_baseline`` and ``submit_evidence`` must fail closed against it. The last
test pins that, so a change on either side of the contract surfaces here.

ConsequenceTokens are minted on CAGE's side of the boundary. This suite signs
them with a run-local Ed25519 key, so its result does not depend on the
runner's KMS configuration. A token minted here is never KMS evidence.

Every variable is required. The partner harness reads the endpoint and the key
from repository secrets and mints the ID token once per run through Workload
Identity Federation (``scripts/partner_harness.py``):

    PROVIDER_01_ENDPOINT      Cloud Run base URL, without a trailing slash
    PROVIDER_01_API_KEY       FlowSignal application key
    PROVIDER_01_GCP_ID_TOKEN  Google ID token whose audience is the endpoint
"""

from __future__ import annotations

import hashlib
import os
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import patch

import httpx
import pytest

from src.gateway.governance.consequence_token import ConsequenceToken
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.kms_signer import (
    KMSGovernanceSigner,
    SoftwareEd25519Provider,
)
from src.gateway.governance.seams.normative import ValidationResult
from src.integrations.provider_01.provider import (
    FlowSignalNormativeProvider,
    _build_cage_authority_request,
)

pytestmark = [
    pytest.mark.eu_ecb,
    pytest.mark.partner,
    pytest.mark.partner_integration,
    pytest.mark.live_external,
]

_REQUIRED = (
    "PROVIDER_01_ENDPOINT",
    "PROVIDER_01_API_KEY",
    "PROVIDER_01_GCP_ID_TOKEN",
)
_TIMEOUT = 15.0
_EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


@dataclass(frozen=True)
class _Credentials:
    endpoint: str
    api_key: str = field(repr=False)
    id_token: str = field(repr=False)

    def headers(self, *, id_token: bool = True, api_key: bool = True) -> dict[str, str]:
        """Request headers carrying the selected credentials."""
        headers = {"Content-Type": "application/json"}
        if id_token:
            headers["X-Serverless-Authorization"] = f"Bearer {self.id_token}"
        if api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers


@pytest.fixture
def credentials() -> _Credentials:
    values = {name: os.environ.get(name, "").strip() for name in _REQUIRED}
    missing = [name for name, value in values.items() if not value]
    if missing:
        pytest.skip(
            "FlowSignal live credentials not configured — missing: "
            + ", ".join(missing)
        )
    return _Credentials(
        endpoint=values["PROVIDER_01_ENDPOINT"].rstrip("/"),
        api_key=values["PROVIDER_01_API_KEY"],
        id_token=values["PROVIDER_01_GCP_ID_TOKEN"],
    )


@pytest.fixture
def provider(credentials: _Credentials) -> FlowSignalNormativeProvider:
    return FlowSignalNormativeProvider(
        endpoint=credentials.endpoint,
        api_key=credentials.api_key,
        gcp_id_token=credentials.id_token,
        timeout=_TIMEOUT,
    )


@pytest.fixture
def signer() -> Iterator[KMSGovernanceSigner]:
    """The run-local Ed25519 signer CAGE mints ConsequenceTokens with."""
    run_signer = KMSGovernanceSigner(
        provider=SoftwareEd25519Provider(key_id="provider-01-live-run")
    )
    with patch(
        "src.gateway.governance.consequence_token_service.get_governance_signer",
        return_value=run_signer,
    ):
        yield run_signer


def _payment(
    case: str, *, action: str = "payment.release", **params: Any
) -> dict[str, Any]:
    """AP-001: a 500,000 GBP treasury payment inside an active mandate.

    This is the vector FlowSignal's Step 1 qualification used
    (``CAGE_FLOWSIGNAL_PHASE3_STEP1_RECORD.json``). The mandate expiry is set
    relative to now so the vector cannot age into a refusal. Keyword arguments
    override single ``params`` fields.
    """
    run = f"{case}-{uuid.uuid4().hex[:12]}"
    mandate_valid_until = datetime.now(timezone.utc) + timedelta(days=365)
    return {
        "thread_id": f"thread-cage-live-{run}",
        "correlation_id": f"exec-cage-live-{run}",
        "approval_id": "APPROVAL-TREASURY-001",
        "action": action,
        "target": "TREASURY_GATEWAY",
        "operator_urn": "agent-treasury-01",
        "actor_id": "agent-treasury-01",
        "params": {
            "purpose": "Invoice 78431",
            "actor_role": "treasury_agent",
            "principal_id": "institution-001",
            "principal_name": "Example Financial Institution",
            "mandate_id": "MANDATE-TREASURY-001",
            "mandate_max_amount": 1000000.0,
            "currency": "GBP",
            "permitted_source_accounts": ["TREASURY-001"],
            "permitted_counterparty_class": "APPROVED_SUPPLIERS",
            "mandate_valid_until": mandate_valid_until.isoformat(timespec="seconds"),
            "amount": 500000.0,
            "source_account": "TREASURY-001",
            "beneficiary": "SUPPLIER-X",
            "counterparty_status": "APPROVED",
            "account_status": "ACTIVE",
            "risk_state": "NORMAL",
            "approval_required": False,
            "screening_status": "CLEAR",
            "screening_max_age_seconds": 3600,
            "screening_source": "SCREENING-SERVICE-01",
            **params,
        },
    }


def _codes(result: ValidationResult) -> list[str]:
    return [str(finding.get("code", "")) for finding in result.findings]


@pytest.mark.asyncio
async def test_live_health_behind_cloud_run_iam(credentials: _Credentials) -> None:
    """/health answers through Cloud Run's ingress on the ID token alone."""
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.get(
            f"{credentials.endpoint}/health",
            headers=credentials.headers(api_key=False),
        )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_live_each_credential_is_enforced(credentials: _Credentials) -> None:
    """Cloud Run refuses a request without the ID token; FlowSignal, one without its key."""
    url = f"{credentials.endpoint}/cage/validate"
    body = _build_cage_authority_request(_payment("credential-gate"))
    wrong_key = {
        **credentials.headers(api_key=False),
        "Authorization": "Bearer not-the-flowsignal-key",
    }
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        no_identity = await client.post(
            url, json=body, headers=credentials.headers(id_token=False)
        )
        no_key = await client.post(
            url, json=body, headers=credentials.headers(api_key=False)
        )
        bad_key = await client.post(url, json=body, headers=wrong_key)
    assert no_identity.status_code in (401, 403), no_identity.status_code
    assert no_key.status_code == 401, no_key.text
    assert bad_key.status_code == 401, bad_key.text


@pytest.mark.asyncio
async def test_live_allow_mints_a_bound_consequence_token(
    provider: FlowSignalNormativeProvider, signer: KMSGovernanceSigner
) -> None:
    """ALLOW admits, and the token binds FlowSignal's authority record to the exact action."""
    payload = _payment("allow")
    result = await provider.validate_fria(payload)
    assert result.admitted is True, result
    (finding,) = result.findings
    assert finding["code"] == "CONSEQUENCE_TOKEN"
    assert finding.get("authority_receipt_id"), "FlowSignal issued no authority receipt"

    claims = ConsequenceToken.verify(finding["token"], signer=signer)
    assert claims.rec
    assert claims.rec == finding["authority_record_id"]
    assert claims.act == hashlib.sha256(jcs_canonicalize_plan(payload)).hexdigest()
    assert (claims.sub, claims.tid) == (payload["actor_id"], payload["thread_id"])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("action", "params"),
    [
        pytest.param("DELETE_ACCOUNT", {}, id="unsupported-action"),
        pytest.param(
            "payment.release",
            {"mandate_valid_until": "2020-01-01T00:00:00Z"},
            id="expired-mandate",
        ),
    ],
)
async def test_live_refuse_admits_nothing(
    provider: FlowSignalNormativeProvider, action: str, params: dict[str, Any]
) -> None:
    """REFUSE is a hard denial: not admitted, and nothing is minted."""
    result = await provider.validate_fria(_payment("refuse", action=action, **params))
    assert result.admitted is False
    assert _codes(result) == ["FLOWSIGNAL_REFUSE"]


@pytest.mark.asyncio
async def test_live_escalate_holds_for_human_review(
    provider: FlowSignalNormativeProvider,
) -> None:
    """Stale screening evidence escalates: held for review, not admitted, nothing minted."""
    captured = datetime.now(timezone.utc) - timedelta(days=3)
    result = await provider.validate_fria(
        _payment(
            "escalate",
            screening_captured_at=captured.isoformat(timespec="seconds"),
            screening_max_age_seconds=60,
        )
    )
    assert result.admitted is False
    assert _codes(result) == ["EXTERNAL_HOLD"]
    assert result.findings[0]["needs_human_review"] is True


@pytest.mark.asyncio
async def test_live_validate_rejects_malformed_and_forged_bodies(
    credentials: _Credentials,
) -> None:
    """A malformed body and one carrying a forged decision both get 422, never a determination."""
    url = f"{credentials.endpoint}/cage/validate"
    forged = {
        **_build_cage_authority_request(_payment("forged")),
        "decision": "ALLOW",
        "authority_record_id": "FORGED-RECORD-999",
    }
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        malformed = await client.post(
            url, json={"malformed_attack_vector": True}, headers=credentials.headers()
        )
        injected = await client.post(url, json=forged, headers=credentials.headers())
    assert malformed.status_code == 422, malformed.text
    assert injected.status_code == 422, injected.text


@pytest.mark.asyncio
async def test_live_unserved_routes_fail_closed(
    provider: FlowSignalNormativeProvider,
) -> None:
    """FlowSignal serves no baseline or evidence-chain route, and the adapter fabricates neither."""
    baseline = await provider.fetch_baseline("EU_ECB")
    assert not baseline.is_valid
    assert baseline.profile == {}
    assert (baseline.error or "").startswith("HTTP 404"), baseline.error

    seal = await provider.submit_evidence("thread-cage-live-unserved", _EMPTY_SHA256)
    assert seal.seal_hash == ""
    assert (seal.error or "").startswith("HTTP 404"), seal.error

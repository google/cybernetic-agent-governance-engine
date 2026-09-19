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
test_provider_08_adapter.py — Provider 08 (Verdict) Adapter Tests
==================================================================

Hermetic tests (respx) for the Verdict runtime-evidence ``NormativeProvider``:

- Baseline fetch, ETag/profile_sha256 propagation, fail-closed on HTTP error
- Tri-state mapping ALLOW / REFUSE / ESCALATE, ConsequenceToken mint gating
- PARSE_ERROR on malformed or unknown decisions, ENDPOINT_ERROR on 5xx/timeout
- Evidence seal propagation and PROVIDER_08_REQUIRE_ANCHOR fail-closed
- Bearer header and ``from_env()`` configuration
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import httpx
import pytest
import respx

from src.gateway.governance.seams.normative import (
    EvidenceSeal,
    NormativeBaseline,
    ValidationResult,
)
from src.integrations.provider_08 import (
    FINDING_CODE_ANCHOR_DEFERRED,
    FINDING_CODE_ENDPOINT_ERROR,
    FINDING_CODE_EXTERNAL_HOLD,
    FINDING_CODE_PARSE_ERROR,
    FINDING_CODE_REFUSE,
    Provider08NormativeProvider,
)

pytestmark = [pytest.mark.unit, pytest.mark.local, pytest.mark.partner]

BASE = "https://verdict.example.test/api/cage"
KEY = "vk_test_0123456789abcdef0123456789abcdef"
CTX: dict[str, Any] = {
    "thread_id": "thread-1",
    "action": "execute_transfer",
    "action_hash": "b" * 64,
    "agent_id": "agent://treasury",
    "policy_version": "v9",
    "consequence_ceiling": "LOW_INFORMATIONAL",
}


def fria(decision: str, **overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "decision": decision,
        "admitted": decision == "ALLOW",
        "message": f"{decision} from test",
        "findings": [
            {
                "code": "RECORD_THREAD_ID",
                "status": "pass",
                "severity": "info",
                "message": "ok",
                "control_id": "CTRL_TEL_003",
            }
        ],
        "region": "EU_ECB",
        "authority_record_id": "vfria_" + "a" * 32,
        "authority_state_version": "EU_ECB:0123456789abcdef",
        "validation_hash": "c" * 64,
        "validated_at": "2026-09-19T00:00:00.000Z",
    }
    body.update(overrides)
    return body


@pytest.fixture
def provider() -> Provider08NormativeProvider:
    return Provider08NormativeProvider(endpoint=BASE, api_key=KEY, timeout_seconds=2.0)


# -- fetch_baseline -----------------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_baseline_propagates_profile_and_etag(
    provider: Provider08NormativeProvider,
) -> None:
    with respx.mock:
        route = respx.get(f"{BASE}/legal-baseline/EU_ECB").mock(
            return_value=httpx.Response(
                200,
                json={
                    "region": "EU_ECB",
                    "profile": {"_region": "EU_ECB", "CTRL_TEL_003": {"scope": "x"}},
                    "profile_sha256": "d" * 64,
                },
                headers={"ETag": '"' + "d" * 64 + '"'},
            )
        )
        baseline = await provider.fetch_baseline("EU_ECB")
    assert isinstance(baseline, NormativeBaseline)
    assert baseline.is_valid
    assert baseline.etag == "d" * 64
    assert baseline.profile["CTRL_TEL_003"] == {"scope": "x"}
    assert route.calls.last.request.headers["Authorization"] == f"Bearer {KEY}"


@pytest.mark.asyncio
async def test_fetch_baseline_fails_closed_on_http_error(
    provider: Provider08NormativeProvider,
) -> None:
    with respx.mock:
        respx.get(f"{BASE}/legal-baseline/MARS").mock(
            return_value=httpx.Response(404, json={"error": "unknown_region"})
        )
        baseline = await provider.fetch_baseline("MARS")
    assert not baseline.is_valid
    assert baseline.error is not None and "404" in baseline.error


# -- validate_fria -------------------------------------------------------------


@pytest.mark.asyncio
async def test_validate_allow_mints_token_and_admits(
    provider: Provider08NormativeProvider,
) -> None:
    token = {"code": "CONSEQUENCE_TOKEN", "severity": "info", "token": "jws"}
    with (
        respx.mock,
        patch(
            "src.gateway.governance.consequence_token_service."
            "mint_consequence_token_finding",
            return_value=token,
        ) as mint,
    ):
        route = respx.post(f"{BASE}/validate/fria").mock(
            return_value=httpx.Response(200, json=fria("ALLOW"))
        )
        result = await provider.validate_fria(CTX)
    assert isinstance(result, ValidationResult)
    assert result.admitted is True
    assert result.findings[0] == token
    assert result.findings[1]["code"] == "RECORD_THREAD_ID"
    assert result.findings[1]["provider"] == "provider_08"
    kwargs = mint.call_args.kwargs
    assert kwargs["actor_id"] == "agent://treasury"
    assert kwargs["thread_id"] == "thread-1"
    assert kwargs["authority_record_id"] == "vfria_" + "a" * 32
    assert kwargs["authority_state_version"] == "EU_ECB:0123456789abcdef"
    assert (
        route.calls.last.request.content
        == httpx.Request("POST", BASE, json=CTX).content
    )


@pytest.mark.asyncio
async def test_validate_allow_without_signer_fails_closed(
    provider: Provider08NormativeProvider,
) -> None:
    """No KMS in the test environment → mint fails → admitted must be False."""
    with respx.mock:
        respx.post(f"{BASE}/validate/fria").mock(
            return_value=httpx.Response(200, json=fria("ALLOW"))
        )
        result = await provider.validate_fria(CTX)
    assert result.admitted is False
    assert result.findings[0]["code"] == "CONSEQUENCE_TOKEN_MINT_FAILED"


@pytest.mark.asyncio
async def test_validate_refuse(provider: Provider08NormativeProvider) -> None:
    with respx.mock:
        respx.post(f"{BASE}/validate/fria").mock(
            return_value=httpx.Response(200, json=fria("REFUSE", admitted=False))
        )
        result = await provider.validate_fria(CTX)
    assert result.admitted is False
    assert result.findings[0]["code"] == FINDING_CODE_REFUSE
    assert result.findings[0]["severity"] == "blocked"


@pytest.mark.asyncio
async def test_validate_escalate_parks_with_hold_ttl(
    provider: Provider08NormativeProvider,
) -> None:
    with respx.mock:
        respx.post(f"{BASE}/validate/fria").mock(
            return_value=httpx.Response(
                200, json=fria("ESCALATE", admitted=False, hold_ttl_seconds=120)
            )
        )
        result = await provider.validate_fria(CTX)
    hold = result.findings[0]
    assert result.admitted is False
    assert hold["code"] == FINDING_CODE_EXTERNAL_HOLD
    assert hold["severity"] == "review"
    assert hold["needs_human_review"] is True
    assert hold["hold_ttl_seconds"] == 120


@pytest.mark.asyncio
@pytest.mark.parametrize("decision", ["MAYBE", "allow ", "", None])
async def test_validate_unknown_decision_is_parse_error(
    provider: Provider08NormativeProvider, decision: Any
) -> None:
    body = fria("ALLOW")
    body["decision"] = decision
    with respx.mock:
        respx.post(f"{BASE}/validate/fria").mock(
            return_value=httpx.Response(200, json=body)
        )
        result = await provider.validate_fria(CTX)
    assert result.admitted is False
    assert result.findings[0]["code"] == FINDING_CODE_PARSE_ERROR


@pytest.mark.asyncio
async def test_validate_missing_decision_field_is_parse_error(
    provider: Provider08NormativeProvider,
) -> None:
    with respx.mock:
        respx.post(f"{BASE}/validate/fria").mock(
            return_value=httpx.Response(200, json={"ok": True})
        )
        result = await provider.validate_fria(CTX)
    assert result.admitted is False
    assert result.findings[0]["code"] == FINDING_CODE_PARSE_ERROR


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 429, 500, 503])
async def test_validate_http_error_is_endpoint_error(
    provider: Provider08NormativeProvider, status: int
) -> None:
    with respx.mock:
        respx.post(f"{BASE}/validate/fria").mock(
            return_value=httpx.Response(status, json={"error": "x"})
        )
        result = await provider.validate_fria(CTX)
    assert result.admitted is False
    assert result.findings[0]["code"] == FINDING_CODE_ENDPOINT_ERROR
    assert result.error is not None and str(status) in result.error


@pytest.mark.asyncio
async def test_validate_timeout_is_endpoint_error(
    provider: Provider08NormativeProvider,
) -> None:
    with respx.mock:
        respx.post(f"{BASE}/validate/fria").mock(
            side_effect=httpx.ReadTimeout("gate timeout")
        )
        result = await provider.validate_fria(CTX)
    assert result.admitted is False
    assert result.findings[0]["code"] == FINDING_CODE_ENDPOINT_ERROR


# -- submit_evidence ------------------------------------------------------------


def seal_body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "thread_id": "thread-1",
        "evidence_hash": "e" * 64,
        "seal_hash": "f" * 64,
        "seal_status": "RECORDED",
        "timestamp": 1_800_000_000.5,
        "evidence_record_id": "ser_" + "1" * 32,
        "transparency_anchor": {"status": "anchored", "rekor_log_index": 42},
    }
    body.update(overrides)
    return body


@pytest.mark.asyncio
async def test_submit_evidence_returns_commitment_as_seal_hash(
    provider: Provider08NormativeProvider,
) -> None:
    with respx.mock:
        route = respx.get(f"{BASE}/evidence-chain/thread-1").mock(
            return_value=httpx.Response(200, json=seal_body())
        )
        seal = await provider.submit_evidence("thread-1", "e" * 64)
    assert isinstance(seal, EvidenceSeal)
    assert seal.error is None
    assert seal.seal_hash == "f" * 64
    assert seal.sealed_at == 1_800_000_000.5
    assert route.calls.last.request.url.params["evidence_hash"] == "e" * 64


@pytest.mark.asyncio
async def test_submit_evidence_require_anchor_fails_closed_on_deferred() -> None:
    strict = Provider08NormativeProvider(
        endpoint=BASE, api_key=KEY, require_anchor=True
    )
    with respx.mock:
        respx.get(f"{BASE}/evidence-chain/thread-1").mock(
            return_value=httpx.Response(
                200,
                json=seal_body(
                    seal_status="RECORDED_ANCHOR_DEFERRED",
                    transparency_anchor={
                        "status": "deferred",
                        "reason": "rekor_http_503",
                    },
                ),
            )
        )
        seal = await strict.submit_evidence("thread-1", "e" * 64)
    assert seal.error is not None
    assert seal.error.startswith(FINDING_CODE_ANCHOR_DEFERRED)
    assert seal.seal_hash == "f" * 64


@pytest.mark.asyncio
async def test_submit_evidence_http_error(
    provider: Provider08NormativeProvider,
) -> None:
    with respx.mock:
        respx.get(f"{BASE}/evidence-chain/thread-1").mock(
            return_value=httpx.Response(502, json={"error": "seal_failed"})
        )
        seal = await provider.submit_evidence("thread-1", "e" * 64)
    assert seal.error is not None and "502" in seal.error
    assert seal.seal_hash == ""


# -- configuration -------------------------------------------------------------


def test_from_env_prefers_provider_08_over_cage_generic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CAGE_NORMATIVE_ENDPOINT", "https://generic.example/cage")
    monkeypatch.setenv("CAGE_NORMATIVE_API_KEY_SECRET", "generic-key-0123456789")
    monkeypatch.setenv("PROVIDER_08_ENDPOINT", "https://verdict.example/api/cage/")
    monkeypatch.setenv("PROVIDER_08_REQUIRE_ANCHOR", "true")
    p = Provider08NormativeProvider.from_env()
    assert p.endpoint == "https://verdict.example/api/cage"
    assert p._headers()["Authorization"] == "Bearer generic-key-0123456789"
    assert p._require_anchor is True


def test_from_env_defaults_are_hermetic(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "PROVIDER_08_ENDPOINT",
        "CAGE_NORMATIVE_ENDPOINT",
        "PROVIDER_08_API_KEY",
        "CAGE_NORMATIVE_API_KEY_SECRET",
    ):
        monkeypatch.delenv(name, raising=False)
    p = Provider08NormativeProvider.from_env()
    assert p.endpoint == "http://localhost:8088"
    assert "Authorization" not in p._headers()

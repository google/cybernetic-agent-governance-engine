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
# Regression & cutover deletion-trigger guard for: POAM-2026-113, POAM-2026-156, POAM-2026-218

"""Provider 01 opt-in strict v0.3 readiness, receipt-validity TTL, and POAM-2026-218 guard."""

from __future__ import annotations

import ast
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch

import fakeredis.aioredis
import httpx
import pytest
import respx
from opentelemetry.sdk.trace import TracerProvider

from src.gateway.governance.consequence_authority_store import ConsequenceAuthorityStore
from src.gateway.governance.consequence_gateway import (
    ConsequenceDecision,
    ConsequenceGateway,
)
from src.gateway.governance.consequence_magnitude import ConsequenceMagnitudes
from src.gateway.governance.consequence_token import ConsequenceToken
from src.gateway.governance.consequence_token_service import (
    FINDING_CODE_CONSEQUENCE_TOKEN,
    FINDING_CODE_CONSEQUENCE_TOKEN_MINT_FAILED,
)
from src.gateway.governance.contracts import ConsequenceMagnitude, MagnitudePath
from src.gateway.governance.jurisdiction.eu_ai_act.fria_tier import FriaTier
from src.gateway.governance.kms_signer import (
    KMSGovernanceSigner,
    SoftwareEd25519Provider,
)
from src.gateway.infrastructure.redis_replication import ReplicationPolicy
from src.integrations.provider_01.provider import (
    FINDING_CODE_PROVIDER_01_MISSING_VERIFIED_FACT,
    FINDING_CODE_PROVIDER_01_UNVERIFIED_CALLER,
    Provider01NormativeProvider,
    _build_cage_authority_request,
)

pytestmark = [
    pytest.mark.unit,
    pytest.mark.local,
    pytest.mark.partner,
    pytest.mark.usefixtures("connected_evidence_sink"),
]

_REPO_ROOT = Path(__file__).resolve().parents[3]
_POAM_PATH = _REPO_ROOT / "docs" / "POAM.md"
_PROVIDER_PATH = _REPO_ROOT / "src" / "integrations" / "provider_01" / "provider.py"
_TRACER = TracerProvider().get_tracer(__name__)

_MAGNITUDES = ConsequenceMagnitudes(
    (ConsequenceMagnitude("payment.release", (MagnitudePath(("amount",), 2),)),)
)

_GUARDED_POAM_IDS: tuple[str, ...] = ("POAM-2026-113", "POAM-2026-218")
_RETIRED_AT_CUTOVER_TOKENS: tuple[str, ...] = (
    "v0.2",
    "PROVIDER_01_CONTRACT_VERSION",
    "DEFAULT-MANDATE",
    "2099-12-31T23:59:59Z",
)


def _collect_docstring_nodes(tree: ast.AST) -> set[int]:
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            if (
                node.body
                and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)
            ):
                ids.add(id(node.body[0].value))
    return ids


def _detect_v02_compatibility_markers(provider_source: str) -> list[str]:
    """Return any v0.2 dual-path or permissive-default markers present in provider_source."""
    try:
        tree = ast.parse(provider_source)
    except SyntaxError as exc:
        return [f"provider.py failed AST parse: {exc}"]

    docstring_ids = _collect_docstring_nodes(tree)
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) in docstring_ids:
                continue
            val = node.value.strip()
            if val.lower() == "v0.2":
                found.add("v0.2")
            for token in _RETIRED_AT_CUTOVER_TOKENS[1:]:
                if token in val:
                    found.add(token)
        elif isinstance(node, ast.Name) and "PROVIDER_01_CONTRACT_VERSION" in node.id:
            found.add("PROVIDER_01_CONTRACT_VERSION")
    return sorted(found)


def _parse_poam_tracking_state(
    poam_text: str,
) -> dict[str, dict[str, Any]]:
    """Extract summary-table placement and detail-section Status for POAM-2026-113 & POAM-2026-218."""
    state: dict[str, dict[str, Any]] = {
        fid: {
            "in_open_table": False,
            "in_accepted_table": False,
            "in_closed_table": False,
            "detail_status": None,
        }
        for fid in _GUARDED_POAM_IDS
    }

    section: str | None = None
    detail_header_re = re.compile(r"^###\s+(POAM-\d{4}-\d+)\b")
    status_line_re = re.compile(r"^(?:\*\*Status:\*\*|Status:)\s*(.+)$", re.IGNORECASE)
    active_detail_id: str | None = None

    for raw_line in poam_text.splitlines():
        stripped = raw_line.strip()
        if re.match(r"^##\s+Open Findings\b", stripped):
            section = "open"
            active_detail_id = None
            continue
        if re.match(r"^##\s+Accepted Risks\b", stripped):
            section = "accepted"
            active_detail_id = None
            continue
        if re.match(r"^##\s+Closed Findings\b", stripped):
            section = "closed"
            active_detail_id = None
            continue

        detail_match = detail_header_re.match(stripped)
        if detail_match:
            section = None
            cand_id = detail_match.group(1)
            active_detail_id = cand_id if cand_id in state else None
            continue

        if stripped.startswith("## "):
            section = None
            active_detail_id = None
            continue
        if stripped.startswith("### ") and active_detail_id is not None:
            active_detail_id = None

        if section in {"open", "accepted", "closed"} and stripped.startswith("|"):
            cells = [c.strip().strip("*` ") for c in stripped.strip("|").split("|")]
            if cells and cells[0] in state:
                state[cells[0]][f"in_{section}_table"] = True

        if active_detail_id is not None:
            st_match = status_line_re.match(stripped)
            if st_match and state[active_detail_id]["detail_status"] is None:
                cleaned = re.sub(r"[*_`]+", "", st_match.group(1)).strip().lower()
                state[active_detail_id]["detail_status"] = cleaned

    return state


def audit_poam_218_v02_retirement_invariant(
    poam_text: str,
    provider_source: str,
) -> list[str]:
    """Enforce POAM-2026-218: POAM-2026-113 and POAM-2026-218 cannot close while v0.2 exists."""
    errors: list[str] = []
    markers = _detect_v02_compatibility_markers(provider_source)
    poam_state = _parse_poam_tracking_state(poam_text)

    for fid in _GUARDED_POAM_IDS:
        info = poam_state[fid]
        detail_status = info["detail_status"]
        if detail_status is None:
            errors.append(f"{fid} is missing a ### {fid} detail section with Status")
            continue
        if not (
            info["in_open_table"]
            or info["in_closed_table"]
            or info["in_accepted_table"]
        ):
            errors.append(f"{fid} is missing from docs/POAM.md summary tables")
            continue

        is_marked_closed = bool(
            info["in_closed_table"] or detail_status.startswith("closed")
        )
        is_accepted_risk = bool(
            info["in_accepted_table"] or detail_status.startswith("accepted")
        )
        if is_accepted_risk:
            errors.append(
                f"{fid} cannot be parked in Accepted Risks to bypass v0.2 retirement"
            )
        if markers and is_marked_closed:
            errors.append(
                f"{fid} is marked Closed while v0.2 compatibility markers still exist "
                f"in provider.py: {', '.join(markers)}"
            )
        if markers and not info["in_open_table"]:
            errors.append(
                f"{fid} must remain in the Open Findings table while v0.2 markers "
                f"exist in provider.py: {', '.join(markers)}"
            )
    return errors


def _verified_v03_params(**overrides: Any) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    base: dict[str, Any] = {
        "approval_id": "APPROVAL-V03-001",
        "amount": 250000.0,
        "currency": "GBP",
        "purpose": "Invoice 99210",
        "actor_role": "treasury_agent",
        "principal_id": "institution-001",
        "principal_name": "Example Institution",
        "mandate_id": "MANDATE-V03-001",
        "mandate_status": "ACTIVE",
        "mandate_max_amount": 500000.0,
        "mandate_valid_until": (now + timedelta(days=30)).isoformat(timespec="seconds"),
        "permitted_source_accounts": ["TREASURY-001"],
        "permitted_counterparty_class": "APPROVED_SUPPLIERS",
        "source_account": "TREASURY-001",
        "beneficiary": "SUPPLIER-ALPHA",
        "counterparty_status": "APPROVED",
        "account_status": "ACTIVE",
        "risk_state": "NORMAL",
        "approval_required": False,
        "screening_status": "CLEAR",
        "screening_captured_at": (now - timedelta(minutes=5)).isoformat(
            timespec="seconds"
        ),
        "screening_max_age_seconds": 3600,
        "screening_source": "SCREENING-SVC-01",
    }
    base.update(overrides)
    return base


def _fria_envelope(
    *,
    caller: str = "spiffe://cage.example/ns/governance/sa/agent-01",
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    tier = FriaTier(
        object(),  # type: ignore[arg-type]
        region="EU_ECB",
        assessment_lookup=lambda _action: None,
        reassessment_interval_days=365,
        gate_timeout_seconds=5.0,
        caller_identity=lambda: caller,
    )
    with _TRACER.start_as_current_span("validate"):
        return tier._payload(
            "payment.release",
            params if params is not None else _verified_v03_params(),
        )


# ---------------------------------------------------------------------------
# 1. POAM-2026-218 Self-Enforcing CI Deletion-Trigger Tests
# ---------------------------------------------------------------------------


def test_poam_218_forbids_closing_poam_113_while_v02_dual_path_exists() -> None:
    """Live repository check: POAM-2026-113 and POAM-2026-218 stay Open while v0.2 exists."""
    poam_text = _POAM_PATH.read_text(encoding="utf-8")
    provider_source = _PROVIDER_PATH.read_text(encoding="utf-8")

    markers = _detect_v02_compatibility_markers(provider_source)
    assert "v0.2" in markers
    assert "PROVIDER_01_CONTRACT_VERSION" in markers

    violations = audit_poam_218_v02_retirement_invariant(poam_text, provider_source)
    assert violations == [], f"POAM-2026-218 invariant violated: {violations}"


@pytest.mark.parametrize("closed_id", ["POAM-2026-113", "POAM-2026-218"])
def test_poam_218_planted_closed_table_row_fails_while_v02_exists(
    closed_id: str,
) -> None:
    """Planted violation: moving POAM-2026-113 or POAM-2026-218 to Closed table fails."""
    other_id = "POAM-2026-218" if closed_id == "POAM-2026-113" else "POAM-2026-113"
    synthetic_poam = f"""
## Open Findings

| ID | Control | Description | Severity | Target Date |
|---|---|---|---|---|
| {other_id} | AC-3 | Still open | Moderate | 2026-12-31 |

## Closed Findings

| ID | Control | Description | Closed |
|---|---|---|---|
| {closed_id} | AC-3 | Prematurely closed | 2026-11-14 |

### POAM-2026-113: Facts

**Status:** Open

### POAM-2026-218: Retire v0.2

**Status:** Open
"""
    synthetic_provider = 'VERSION = "v0.2"\n'
    errors = audit_poam_218_v02_retirement_invariant(synthetic_poam, synthetic_provider)
    assert any(closed_id in err and "v0.2" in err for err in errors)


@pytest.mark.parametrize(
    ("closed_id", "status_line", "provider_snippet"),
    [
        ("POAM-2026-113", "**Status:** Closed (2026-11-14)", 'MODE = "v0.2"'),
        (
            "POAM-2026-113",
            "Status: Closed",
            'os.environ.get("PROVIDER_01_CONTRACT_VERSION", "v0.3")',
        ),
        (
            "POAM-2026-218",
            "**Status:** Closed",
            'os.environ.get("PROVIDER_01_CONTRACT_VERSION", "v0.3")',
        ),
        (
            "POAM-2026-218",
            "**Status:** Closed",
            'FALLBACK = "DEFAULT-MANDATE"',
        ),
    ],
)
def test_poam_218_planted_detail_status_closed_fails_while_dual_path_exists(
    closed_id: str,
    status_line: str,
    provider_snippet: str,
) -> None:
    """Planted violation: Status: Closed in detail section fails if any v0.2 marker remains."""
    s113 = status_line if closed_id == "POAM-2026-113" else "**Status:** Open"
    s218 = status_line if closed_id == "POAM-2026-218" else "**Status:** Open"
    synthetic_poam = f"""
## Open Findings

| ID | Control | Description | Severity | Target Date |
|---|---|---|---|---|
| POAM-2026-113 | AC-3 | Open row | Moderate | 2026-12-31 |
| POAM-2026-218 | CM-7 | Open row | Moderate | 2026-12-31 |

### POAM-2026-113: Facts

{s113}

### POAM-2026-218: Retire v0.2

{s218}
"""
    errors = audit_poam_218_v02_retirement_invariant(synthetic_poam, provider_snippet)
    assert errors, "Expected planted closure violation to fail closed"
    assert any(closed_id in err for err in errors)


def test_poam_218_allows_simultaneous_closure_once_v02_and_fallbacks_removed() -> None:
    """Cutover verification: closing both findings passes ONLY after v0.2 & fallbacks are deleted."""
    cutover_poam = """
## Open Findings

| ID | Control | Description | Severity | Target Date |
|---|---|---|---|---|

## Closed Findings

| ID | Control | Description | Closed |
|---|---|---|---|
| POAM-2026-113 | AC-3 | Verified facts cutover complete | 2026-12-01 |
| POAM-2026-218 | CM-7 | Compatibility branch deleted | 2026-12-01 |

### POAM-2026-113: Facts

**Status:** Closed (2026-12-01)

### POAM-2026-218: Retire v0.2

**Status:** Closed (2026-12-01)
"""
    sole_v03_provider = """
def build_request(envelope: dict, *, bound_target: str) -> dict:
    return {"target": bound_target, "mandate_id": envelope["params"]["mandate_id"]}
"""
    assert (
        audit_poam_218_v02_retirement_invariant(cutover_poam, sole_v03_provider) == []
    )


# ---------------------------------------------------------------------------
# 2. Contract Version Configuration & Fail-Closed Validation
# ---------------------------------------------------------------------------


def test_contract_version_defaults_to_v02_and_accepts_v03(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PROVIDER_01_CONTRACT_VERSION", raising=False)
    monkeypatch.delenv("PROVIDER_01_BOUND_TARGET", raising=False)
    default_provider = Provider01NormativeProvider(
        endpoint="https://provider01.example.com"
    )
    assert default_provider.contract_version == "v0.2"
    assert default_provider.bound_target == ""

    monkeypatch.setenv("PROVIDER_01_CONTRACT_VERSION", " V0.3 # strict ")
    monkeypatch.setenv("PROVIDER_01_BOUND_TARGET", " TREASURY_GATEWAY ")
    env_provider = Provider01NormativeProvider(
        endpoint="https://provider01.example.com"
    )
    assert env_provider.contract_version == "v0.3"
    assert env_provider.bound_target == "TREASURY_GATEWAY"


@pytest.mark.parametrize("bad_version", ["", "v0.1", "v0.4", "v1", "latest", "true"])
def test_invalid_contract_version_raises_value_error_fail_closed(
    bad_version: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValueError, match="contract_version"):
        Provider01NormativeProvider(
            endpoint="https://provider01.example.com",
            contract_version=bad_version,
        )

    monkeypatch.setenv("PROVIDER_01_CONTRACT_VERSION", bad_version)
    with pytest.raises(ValueError, match="contract_version"):
        Provider01NormativeProvider(endpoint="https://provider01.example.com")


# ---------------------------------------------------------------------------
# 3. Strict v0.3 Caller Identity, Server-Bound Target & Verified Facts (POAM-2026-113)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize(
    "bad_identity_envelope",
    [
        {"operator_urn": "", "actor_id": ""},
        {"operator_urn": "   ", "actor_id": "\t"},
        {"operator_urn": "agent-alpha", "actor_id": "agent-beta"},
    ],
)
async def test_v03_unverified_or_conflicting_caller_fails_closed_before_http(
    bad_identity_envelope: dict[str, str],
) -> None:
    route = respx.post("https://provider01.example.com/cage/validate").mock(
        return_value=httpx.Response(200, json={"decision": "ALLOW"})
    )
    provider = Provider01NormativeProvider(
        endpoint="https://provider01.example.com",
        api_key="test-key",
        consequence_magnitudes=_MAGNITUDES,
        contract_version="v0.3",
        bound_target="TREASURY_GATEWAY",
    )
    envelope = {
        **_fria_envelope(),
        **bad_identity_envelope,
    }
    result = await provider.validate_fria(envelope)
    assert result.admitted is False
    assert result.findings[0]["code"] == FINDING_CODE_PROVIDER_01_UNVERIFIED_CALLER
    assert result.findings[0]["severity"] == "blocked"
    assert not route.called, "Unverified caller must fail closed before HTTP"


@pytest.mark.asyncio
@respx.mock
async def test_v03_ignores_caller_target_and_requires_server_bound_target() -> None:
    route = respx.post("https://provider01.example.com/cage/validate").mock(
        return_value=httpx.Response(
            200,
            json={"decision": "REFUSE", "message": "policy check"},
        )
    )
    # 1. Missing server bound_target fails closed even if caller supplies params["target"]
    unconfigured = Provider01NormativeProvider(
        endpoint="https://provider01.example.com",
        api_key="test-key",
        consequence_magnitudes=_MAGNITUDES,
        contract_version="v0.3",
        bound_target="",
    )
    attacker_env = _fria_envelope(params=_verified_v03_params(target="ATTACKER_SINK"))
    res_missing = await unconfigured.validate_fria(attacker_env)
    assert res_missing.admitted is False
    assert (
        res_missing.findings[0]["code"]
        == FINDING_CODE_PROVIDER_01_MISSING_VERIFIED_FACT
    )
    assert "bound_target" in res_missing.findings[0]["missing_fields"]
    assert not route.called

    # 2. Server-configured bound_target strictly overrides caller params["target"]
    configured = Provider01NormativeProvider(
        endpoint="https://provider01.example.com",
        api_key="test-key",
        consequence_magnitudes=_MAGNITUDES,
        contract_version="v0.3",
        bound_target="SERVER_TREASURY_GATEWAY",
    )
    res_bound = await configured.validate_fria(attacker_env)
    assert res_bound.admitted is False
    assert route.called
    sent_body = _build_cage_authority_request(
        attacker_env,
        contract_version="v0.3",
        bound_target="SERVER_TREASURY_GATEWAY",
    )
    assert sent_body["target"] == "SERVER_TREASURY_GATEWAY"
    assert sent_body["actor_authenticated"] is True
    assert sent_body["kya_status"] == "VERIFIED"


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize(
    ("missing_field", "bad_value"),
    [
        ("mandate_id", ""),
        ("mandate_status", None),
        ("mandate_max_amount", None),
        ("mandate_max_amount", True),
        ("mandate_max_amount", 0.0),
        ("mandate_valid_until", "2026-12-31T23:59:59"),  # lacks UTC offset
        ("permitted_source_accounts", []),
        ("permitted_counterparty_class", "   "),
        ("source_account", None),
        ("beneficiary", ""),
        ("counterparty_status", None),
        ("account_status", ""),
        ("screening_status", None),
        ("screening_captured_at", "2026-11-14"),  # lacks time & UTC offset
        ("screening_max_age_seconds", True),
        ("screening_max_age_seconds", 0),
        ("screening_source", ""),
    ],
)
async def test_v03_missing_or_invalid_verified_fact_fails_closed_before_http(
    missing_field: str,
    bad_value: Any,
) -> None:
    route = respx.post("https://provider01.example.com/cage/validate").mock(
        return_value=httpx.Response(200, json={"decision": "ALLOW"})
    )
    provider = Provider01NormativeProvider(
        endpoint="https://provider01.example.com",
        api_key="test-key",
        consequence_magnitudes=_MAGNITUDES,
        contract_version="v0.3",
        bound_target="TREASURY_GATEWAY",
    )
    params = _verified_v03_params()
    if bad_value is None:
        params.pop(missing_field, None)
    else:
        params[missing_field] = bad_value

    result = await provider.validate_fria(_fria_envelope(params=params))
    assert result.admitted is False
    assert result.findings[0]["code"] == FINDING_CODE_PROVIDER_01_MISSING_VERIFIED_FACT
    assert missing_field in result.findings[0]["missing_fields"]
    assert missing_field in result.findings[0]["message"]
    assert not route.called


# ---------------------------------------------------------------------------
# 4. Partner Receipt Validity Enforcement & Single-Use Marker Retention (POAM-2026-156 item 2)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize(
    "bad_receipt",
    [
        {"id": "rcpt-v03-bad-1"},  # absent expiry
        {"id": "rcpt-v03-bad-2", "valid_until": ""},
        {"id": "rcpt-v03-bad-3", "valid_until": "not-an-iso-date"},
        {"id": "rcpt-v03-bad-4", "valid_until": "2026-11-14T22:00:00"},  # no UTC offset
        {"id": "rcpt-v03-bad-5", "valid_until": "2026-11-14"},  # bare date
        {"id": "rcpt-v03-bad-6", "valid_until": "2020-01-01T00:00:00Z"},  # expired
    ],
)
async def test_v03_allow_without_valid_receipt_expiry_fails_closed(
    bad_receipt: dict[str, Any],
) -> None:
    signer = KMSGovernanceSigner(
        provider=SoftwareEd25519Provider(key_id="p01-v03-expiry-guard")
    )
    provider = Provider01NormativeProvider(
        endpoint="https://provider01.example.com",
        api_key="test-key",
        consequence_magnitudes=_MAGNITUDES,
        contract_version="v0.3",
        bound_target="TREASURY_GATEWAY",
    )
    respx.post("https://provider01.example.com/cage/validate").mock(
        return_value=httpx.Response(
            200,
            json={
                "decision": "ALLOW",
                "authority_record_id": "MANDATE-V03-001",
                "authority_receipt": bad_receipt,
                "authority_state_version": "7",
            },
        )
    )
    with patch(
        "src.gateway.governance.consequence_token_service.get_governance_signer",
        return_value=signer,
    ):
        result = await provider.validate_fria(_fria_envelope())

    assert result.admitted is False
    assert result.findings[0]["code"] == FINDING_CODE_CONSEQUENCE_TOKEN_MINT_FAILED
    assert (
        "Provider 01 v0.3 ALLOW carries no valid receipt expiry"
        in result.findings[0]["message"]
    )


@pytest.mark.asyncio
@respx.mock
async def test_v03_end_to_end_600s_receipt_retains_marker_and_blocks_120s_replay() -> (
    None
):
    """POAM-2026-156 Criterion 1: 600s partner receipt -> >=630s marker -> blocks second token at +120s."""
    import time as _time

    t0 = int(_time.time())
    valid_until_dt = datetime.fromtimestamp(t0 + 600, tz=timezone.utc)
    valid_until_iso = valid_until_dt.isoformat().replace("+00:00", "Z")

    signer = KMSGovernanceSigner(
        provider=SoftwareEd25519Provider(key_id="p01-v03-e2e-ttl")
    )
    redis_client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    store = ConsequenceAuthorityStore(
        redis_client=redis_client,
        replication=ReplicationPolicy.standalone(),
        ttl_seconds=90,
    )
    gateway = ConsequenceGateway(store=store, signer=signer, magnitudes=_MAGNITUDES)
    provider = Provider01NormativeProvider(
        endpoint="https://provider01.example.com",
        api_key="test-key",
        consequence_magnitudes=_MAGNITUDES,
        contract_version="v0.3",
        bound_target="TREASURY_GATEWAY",
    )

    respx.post("https://provider01.example.com/cage/validate").mock(
        return_value=httpx.Response(
            200,
            json={
                "decision": "ALLOW",
                "authority_record_id": "MANDATE-V03-001",
                "authority_receipt": {
                    "id": "rcpt-v03-600s-001",
                    "valid_until": valid_until_iso,
                },
                "authority_state_version": "9",
            },
        )
    )

    envelope_1 = _fria_envelope()
    envelope_sub = _fria_envelope(params=_verified_v03_params(amount=100000.0))
    marker_key = "consequence:token:rcpt-v03-600s-001"

    with (
        patch(
            "src.gateway.governance.consequence_token_service.get_governance_signer",
            return_value=signer,
        ),
        patch("time.time", return_value=t0),
    ):
        res_1 = await provider.validate_fria(envelope_1)
        assert res_1.admitted is True
        finding_1 = res_1.findings[0]
        assert finding_1["code"] == FINDING_CODE_CONSEQUENCE_TOKEN
        assert finding_1["receipt_expires_at"] == t0 + 600
        claims_1 = ConsequenceToken.verify(finding_1["token"], signer=signer)
        assert claims_1.rec_exp == t0 + 600

        eval_1 = await gateway.evaluate(finding_1["token"], envelope_1)
        assert eval_1.decision == ConsequenceDecision.EXECUTE

        initial_ttl = await redis_client.ttl(marker_key)
        assert initial_ttl >= 630, f"Expected marker TTL >= 630s, got {initial_ttl}s"

    # Advance global clock by 120s (past the 90s default marker TTL; fakeredis evaluates expiry against time.time())
    t1 = t0 + 120
    with (
        patch(
            "src.gateway.governance.consequence_token_service.get_governance_signer",
            return_value=signer,
        ),
        patch("time.time", return_value=t1),
    ):
        assert await redis_client.ttl(marker_key) >= 505
        # Second token minted 120s later for the same still-valid receipt (replay)
        res_2_replay = await provider.validate_fria(envelope_1)
        assert res_2_replay.admitted is True
        eval_2_replay = await gateway.evaluate(
            res_2_replay.findings[0]["token"], envelope_1
        )
        assert eval_2_replay.decision == ConsequenceDecision.BLOCK
        assert eval_2_replay.reason_code == "ALREADY_CONSUMED"

        # Second token minted 120s later for a different payload under same receipt (substitution)
        res_2_sub = await provider.validate_fria(envelope_sub)
        assert res_2_sub.admitted is True
        eval_2_sub = await gateway.evaluate(
            res_2_sub.findings[0]["token"], envelope_sub
        )
        assert eval_2_sub.decision == ConsequenceDecision.BLOCK
        assert eval_2_sub.reason_code == "AUTHORITY_RECORD_BINDING_MISMATCH"


@pytest.mark.asyncio
@respx.mock
async def test_v02_propagates_receipt_expiry_when_present_and_tolerates_absence() -> (
    None
):
    """Under v0.2 default mode, absent expiry still admits while valid expiry propagates rec_exp."""
    t0 = 1_763_150_000
    valid_until_iso = (
        datetime.fromtimestamp(t0 + 300, tz=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )
    signer = KMSGovernanceSigner(
        provider=SoftwareEd25519Provider(key_id="p01-v02-compat")
    )
    provider = Provider01NormativeProvider(
        endpoint="https://provider01.example.com",
        api_key="test-key",
        consequence_magnitudes=_MAGNITUDES,
    )
    assert provider.contract_version == "v0.2"

    envelope = _fria_envelope()
    with (
        patch(
            "src.gateway.governance.consequence_token_service.get_governance_signer",
            return_value=signer,
        ),
        patch("src.integrations.provider_01.provider.time.time", return_value=t0),
        patch("src.gateway.governance.consequence_token.time.time", return_value=t0),
    ):
        respx.post("https://provider01.example.com/cage/validate").mock(
            return_value=httpx.Response(
                200,
                json={
                    "decision": "ALLOW",
                    "authority_receipt": {
                        "id": "rcpt-v02-with-exp",
                        "expires_at": valid_until_iso,
                    },
                },
            )
        )
        with_exp = await provider.validate_fria(envelope)
        assert with_exp.admitted is True
        claims_with_exp = ConsequenceToken.verify(
            with_exp.findings[0]["token"], signer=signer
        )
        assert claims_with_exp.rec_exp == t0 + 300

        respx.post("https://provider01.example.com/cage/validate").mock(
            return_value=httpx.Response(
                200,
                json={
                    "decision": "ALLOW",
                    "authority_receipt": {"id": "rcpt-v02-no-exp"},
                },
            )
        )
        without_exp = await provider.validate_fria(envelope)
        assert without_exp.admitted is True
        claims_without_exp = ConsequenceToken.verify(
            without_exp.findings[0]["token"], signer=signer
        )
        assert claims_without_exp.rec_exp is None

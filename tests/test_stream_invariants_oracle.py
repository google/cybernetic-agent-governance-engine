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

"""End-to-end and mutation-sensitivity suite for ``proof/stream_invariants.py``.

Verifies:
1. ``proof/`` modules have zero ``src/`` imports (AST purity guard for W4 reuse).
2. Pure-stdlib ``jcs_bytes`` matches the gateway's RFC 8785 canonicalizer byte-for-byte.
3. Startup ``GOVERNANCE_THRESHOLDS_LOADED``, ``GET /governance/policy-version``,
   and ``GOVERNANCE_DECISION`` agree on ``thresholds_digest`` (POAM-2026-151 Option 2).
4. A real ``EvidenceStreamSink`` + ``ControlBarrierFunction`` + ``SymbolicGovernor``
   + ``verify_and_consume_seal`` + ``dispatch_actuation`` + ``governor.settle`` +
   ``governance_middleware`` + ``POST /tools/execute`` workload conforms across all
   five safety invariants with zero findings (and passes ``check_trace_conformance.py --stream``).
5. Sensitivity controls: mutating each invariant (and chain / threshold / loss
   guards) causes ``check_stream`` to report the exact expected rule finding.
"""

from __future__ import annotations

import ast
import json
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import fakeredis
import fakeredis.aioredis
import pytest
import pytest_asyncio

import src.gateway.governance.routing_seal as rs
from proof.stream_invariants import (
    check_stream,
    compute_cage_audit_hash,
    jcs_bytes,
)
from scripts.check_trace_conformance import main as cli_main
from src.cage_finance.invariants import CashBarrier
from src.cage_finance.tiers.cbf_tier import CBFTierPlugin
from src.gateway.governance.classification_engine import ClassificationEngine
from src.gateway.governance.contracts import (
    NarrowingResult,
    ReadOnlyTier,
    Violation,
    ViolationKind,
)
from src.gateway.governance.evidence import stream as es_module
from src.gateway.governance.evidence.stream import EvidenceStreamSink
from src.gateway.governance.execution_actuator import dispatch_actuation
from src.gateway.governance.governor.assembly import kernel_stages
from src.gateway.governance.governor.errors import GovernanceError
from src.gateway.governance.governor.metrics import governor_metrics
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.narrower import NarrowerRegistry
from src.gateway.governance.safety import cbf_engine as cbf_module
from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction
from src.gateway.governance.schemas.thresholds import (
    load_and_validate_thresholds,
    publish_thresholds_loaded,
    thresholds_digest,
)
from src.gateway.governance.seams.actuation import (
    ActuationOutcome,
    ActuationReceipt,
    ActuatorCapability,
    ExecutionClearance,
)
from src.gateway.server import governance_middleware as gm
from tests.fixtures.governor import allow_opa, clean_stpa, make_governor

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO_ROOT = Path(__file__).resolve().parent.parent
_STREAM_KEY = "cage:test:invariant-oracle-stream"
_ACTION = "execute_trade"


# ---------------------------------------------------------------------------
# Helpers & Doubles
# ---------------------------------------------------------------------------


class _SoftCapTier(ReadOnlyTier):
    """Domain read-only tier emitting NARROWABLE above ``soft_cap``."""

    def __init__(self, soft_cap: float = 1_000.0) -> None:
        self._cap = soft_cap

    @property
    def tier_name(self) -> str:
        return "bounding"

    @property
    def order(self) -> int:
        return 1

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return action == _ACTION

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        amount = float(params.get("amount", 0.0))
        if amount > self._cap:
            return [
                Violation(
                    tier=self.tier_name,
                    code="SOFT_CAP_EXCEEDED",
                    message=f"amount {amount} > soft cap {self._cap}",
                    kind=ViolationKind.NARROWABLE,
                )
            ]
        return []


class _AmountNarrower:
    def __init__(self, cap: float = 1_000.0) -> None:
        self._cap = cap

    def can_narrow(
        self, violation: Violation, action: str, params: dict[str, Any]
    ) -> bool:
        return violation.kind == ViolationKind.NARROWABLE

    def narrow(
        self, violation: Violation, action: str, params: dict[str, Any]
    ) -> NarrowingResult:
        return NarrowingResult(
            can_narrow=True,
            narrowed_params={**params, "amount": self._cap},
            constraints_applied=[f"amount<={self._cap}"],
            narrowing_reason="clamped to soft cap",
        )


class _TestActuator:
    """Deterministic ExecutionActuator returning ACCEPTED or REJECTED."""

    actuator_id = "test_broker"

    def __init__(self, *, accept: bool = True) -> None:
        self._accept = accept

    async def health_check(self) -> bool:
        return True

    def get_capabilities(self) -> set[ActuatorCapability]:
        return {ActuatorCapability.FINANCIAL_EXECUTION}

    async def actuate(self, clearance: ExecutionClearance) -> ActuationReceipt:
        if self._accept:
            return ActuationReceipt(
                accepted=True,
                receipt_id=f"rcpt-{uuid.uuid4().hex[:12]}",
                session_uuid=clearance.thread_id,
                raw_receipt={"ok": True},
                findings=[],
                retryable=False,
                timestamp_utc="2026-10-29T12:00:00+00:00",
                outcome=ActuationOutcome.ACCEPTED,
            )
        return ActuationReceipt(
            accepted=False,
            receipt_id=None,
            session_uuid=clearance.thread_id,
            raw_receipt=None,
            findings=[{"code": "BROKER_REJECTED", "detail": "halted symbol"}],
            retryable=False,
            timestamp_utc="2026-10-29T12:00:00+00:00",
            outcome=ActuationOutcome.REJECTED,
        )


def _make_clearance(seal: str, params: dict[str, Any]) -> ExecutionClearance:
    tid = str(uuid.uuid4())
    return ExecutionClearance(
        thread_id=tid,
        decision="ALLOW",
        decision_path="DIRECT",
        action=_ACTION,
        target=str(params.get("symbol", "AAPL")),
        operator_urn="urn:cage:agent:test",
        issued_at=1_760_000_000,
        issued_at_provenance="CONSTRUCTION_TIME",
        correlation_id=tid,
        correlation_id_source="THREAD_DERIVED",
        governance_decision_digest=rs.seal_digest(seal),
        opa_input_digest="a" * 64,
        nonce=uuid.uuid4().hex[:32],
        params=params,
        executor_id="test_broker",
        target_route="local://default",
        consequence_ceiling="HIGH_FINANCIAL",
        routing_seal=seal,
    )


class _FakeRedisWrapper:
    """Minimal async wrapper matching ``gateway.infrastructure.redis_client``."""

    def __init__(self, raw: fakeredis.aioredis.FakeRedis) -> None:
        self._raw = raw

    async def get(self, key: str) -> str | None:
        val = await self._raw.get(key)
        return val.decode("utf-8") if isinstance(val, bytes) else val

    async def set(self, key: str, value: str, *args: Any, **kwargs: Any) -> Any:
        return await self._raw.set(key, value, *args, **kwargs)

    async def setex(self, key: str, ttl: int, value: str) -> Any:
        return await self._raw.setex(key, ttl, value)

    async def delete(self, *keys: str) -> Any:
        return await self._raw.delete(*keys)

    async def get_float(self, key: str, default: float = 0.0) -> float:
        val = await self.get(key)
        return float(val) if val is not None else default

    def _get(self) -> fakeredis.aioredis.FakeRedis:
        return self._raw


def _build_synthetic_chain(
    events: list[dict[str, Any]], *, chain_id: str = "chain-1"
) -> list[dict[str, str]]:
    """Build valid ``cage-audit/3.0`` wire dicts from payload dicts using ``proof`` helpers."""
    out: list[dict[str, str]] = []
    prev_hash = ""
    for seq, event in enumerate(events):
        payload_json = jcs_bytes(event).decode("utf-8")
        event_type = str(event.get("type", "UNKNOWN"))
        control_id = str(event.get("controlId") or event.get("control_id") or "AC-3")
        trace_id = "0123456789abcdef0123456789abcdef"
        record_hash = compute_cage_audit_hash(
            prev_hash=prev_hash,
            sequence=seq,
            event_type=event_type,
            control_id=control_id,
            payload_json=payload_json,
            chain_id=chain_id,
            trace_id=trace_id,
        )
        out.append(
            {
                "schema": "cage-audit/3.0",
                "chain_id": chain_id,
                "sequence": str(seq),
                "timestamp_utc": "2026-10-29T12:00:00+00:00",
                "event_type": event_type,
                "control_id": control_id,
                "trace_id": trace_id,
                "hash_algorithm": "SHA-256",
                "canonicalization": "RFC8785",
                "evidence_class": "GOVERNANCE",
                "prev_hash": prev_hash,
                "record_hash": record_hash,
                "payload_json": payload_json,
            }
        )
        prev_hash = record_hash
    return out


@pytest_asyncio.fixture
async def live_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[SimpleNamespace]:
    """Real ``EvidenceStreamSink`` + ``FakeRedis`` backing strict asymmetric seals, CBF, and receipts."""
    from src.gateway.governance import jwks as jwks_mod
    from src.gateway.governance import kms_signer as ks

    monkeypatch.delenv("CAGE_SEAL_STRICT_MODE", raising=False)
    monkeypatch.setenv("CAGE_ENV", "test")
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    monkeypatch.delenv("CAGE_REQUIRE_EVIDENCE_BINDING", raising=False)
    monkeypatch.setattr(
        ks, "_signer", ks.KMSGovernanceSigner(provider=ks.SoftwareEd25519Provider())
    )
    monkeypatch.setattr(jwks_mod, "_global_jwks", None)

    server = fakeredis.FakeServer()
    stream_redis = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    raw_bytes_redis = fakeredis.aioredis.FakeRedis(
        server=server, decode_responses=False
    )
    wrapped_redis = _FakeRedisWrapper(stream_redis)

    sink = EvidenceStreamSink(
        redis_url="redis://localhost:6379", stream_key=_STREAM_KEY
    )
    sink._redis = stream_redis

    async def _resolve_bytes(_client: Any) -> Any:
        return raw_bytes_redis

    async def _raw_cbf(_wrapper: Any) -> Any:
        return stream_redis

    monkeypatch.setattr(es_module, "is_evidence_chain_blocking", lambda: True)
    monkeypatch.setattr(es_module, "get_evidence_sink", lambda: sink)
    monkeypatch.setattr(rs.es, "is_evidence_chain_blocking", lambda: True)
    monkeypatch.setattr(rs.es, "get_evidence_sink", lambda: sink)
    monkeypatch.setattr(gm, "get_evidence_sink", lambda: sink)
    monkeypatch.setattr(rs, "_resolve_redis", _resolve_bytes)
    monkeypatch.setattr(
        "src.gateway.infrastructure.redis_client.redis_client", wrapped_redis
    )
    monkeypatch.setattr(cbf_module, "redis_client", wrapped_redis)
    monkeypatch.setattr(cbf_module, "_get_raw_redis", _raw_cbf)

    yield SimpleNamespace(
        sink=sink,
        stream_redis=stream_redis,
        wrapped_redis=wrapped_redis,
    )
    await sink.stop()


# ---------------------------------------------------------------------------
# 1. AST Purity & JCS Byte Parity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "rel_path",
    [
        "proof/model.py",
        "proof/trace_conformance.py",
        "proof/stream_invariants.py",
    ],
)
def test_proof_modules_have_zero_src_imports(rel_path: str) -> None:
    tree = ast.parse(
        (_REPO_ROOT / rel_path).read_text(encoding="utf-8"), filename=rel_path
    )
    illegal: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "src" or alias.name.startswith("src."):
                    illegal.append(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            if node.module == "src" or node.module.startswith("src."):
                illegal.append(node.module)
    assert illegal == [], f"{rel_path} imported from src/: {illegal}"


def test_jcs_bytes_matches_gateway_canonicalizer() -> None:
    sample = {
        "zero": 0,
        "neg_zero": -0.0,
        "int_max": 2**53 - 1,
        "small_float": 1e-6,
        "tiny_exp": 1e-7,
        "large_int_float": 1e20,
        "large_exp_float": 1e21,
        "frac": 1.0 / 3.0,
        "escapes": 'line\n\t"quote"\\slash\x00\x1f',
        # UTF-16 code unit order differs from Unicode code point order here:
        # U+E000 (0xE000) sorts AFTER U+10000 (surrogate 0xD800 0xDC00)!
        "\ue000": "bmp_high",
        "\U00010000": "supplementary",
        "nested": [True, False, None, {"b": 2, "a": 1}],
    }
    assert jcs_bytes(sample) == jcs_canonicalize_plan(sample)


# ---------------------------------------------------------------------------
# 2. POAM-2026-151 Option 2: Thresholds Digest on Stream & Policy Endpoint
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_thresholds_loaded_and_policy_version_agree(
    live_stream: SimpleNamespace,
) -> None:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    expected_digest = thresholds_digest()
    assert len(expected_digest) == 64

    # Regional overlay changes the effective digest deterministically
    eu_digest = thresholds_digest(load_and_validate_thresholds(region="EU_ECB"))
    us_digest = thresholds_digest(load_and_validate_thresholds(region="US_FED"))
    assert eu_digest != us_digest

    msg_id = await publish_thresholds_loaded(live_stream.sink)
    assert msg_id is not None

    app = FastAPI()
    app.mount("/governance", gm.governance_app)
    with TestClient(app) as client:
        resp = client.get("/governance/policy-version")
        assert resp.status_code == 200
        assert resp.json()["thresholds_digest"] == expected_digest

    raw_entries = await live_stream.stream_redis.xrange(_STREAM_KEY)
    assert len(raw_entries) == 1
    assert (
        check_stream(
            raw_entries,
            expected_thresholds_digest=expected_digest,
            require_thresholds_loaded=True,
        )
        == []
    )


# ---------------------------------------------------------------------------
# 3. End-to-End Workload Conformance Across All 5 Invariants + CLI
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_end_to_end_stream_conforms_across_all_five_invariants(
    live_stream: SimpleNamespace,
    tmp_path: Path,
) -> None:
    metrics = governor_metrics()
    refusals_before = sum(
        sample.value
        for metric in ([metrics._refusals] if metrics._refusals is not None else [])
        for family in metric.collect()
        for sample in family.samples
        if sample.name.endswith("_total")
    )
    failures_before = sum(
        sample.value
        for metric in (
            [metrics._evidence_publish_failures]
            if metrics._evidence_publish_failures is not None
            else []
        )
        for family in metric.collect()
        for sample in family.samples
        if sample.name.endswith("_total")
    )

    # 0. Startup threshold baseline
    await publish_thresholds_loaded(live_stream.sink)

    # Set up real CBF engine + governor with full kernel stages + soft-cap narrower + CBF barrier
    from unittest.mock import AsyncMock

    def cost_fn(action: str, params: dict[str, Any]) -> float:
        return float(params.get("amount", 0.0)) if action == _ACTION else 0.0

    cbf = ControlBarrierFunction(
        invariant=CashBarrier(gamma=0.5, requires_external_ground_truth=False),
        cost_resolver=cost_fn,
        skip_epoch_seed=True,
    )
    await cbf.setup()
    await live_stream.stream_redis.set(cbf.redis_key, "100000.0")
    cbf._sync_to_replicas = AsyncMock(return_value=(True, 1))  # type: ignore[method-assign]

    cbf_tier = CBFTierPlugin(cbf, cost_resolver=cost_fn)
    soft_cap = _SoftCapTier(soft_cap=1_000.0)
    classifier = ClassificationEngine(
        NarrowerRegistry([_AmountNarrower(cap=1_000.0)]),
        confidence_threshold=0.70,
        defer_enabled=True,
        narrow_enabled=True,
    )
    governor = make_governor(
        core_stages=kernel_stages(
            allow_opa(),
            clean_stpa(),
            magnitude_extractor=lambda params: float(params["amount"]),
        ),
        domain_tiers=(soft_cap, cbf_tier),
        classifier=classifier,
    )

    # 1. ALLOW flow: govern -> verify_and_consume_seal -> dispatch_actuation (ACCEPTED) -> settle(True)
    allow_params = {"symbol": "AAPL", "amount": 500.0, "confidence": 0.95}
    allow_seal = await governor.govern(_ACTION, allow_params)
    assert await rs.verify_and_consume_seal(allow_seal, _ACTION, allow_params) is True
    allow_rcpt = await dispatch_actuation(
        _TestActuator(accept=True), _make_clearance(allow_seal, allow_params)
    )
    assert allow_rcpt.accepted is True
    assert await governor.settle(allow_seal, executed=True) == []

    # 2. NARROW flow: amount=2500 > soft_cap=1000 -> clamped to 1000 -> full rerun -> seal -> consume -> actuate -> settle(True)
    narrow_input = {"symbol": "MSFT", "amount": 2_500.0, "confidence": 0.95}
    clamped_params = {"symbol": "MSFT", "amount": 1_000.0, "confidence": 0.95}
    narrow_seal = await governor.govern(_ACTION, narrow_input)
    assert (
        await rs.verify_and_consume_seal(narrow_seal, _ACTION, clamped_params) is True
    )
    narrow_rcpt = await dispatch_actuation(
        _TestActuator(accept=True), _make_clearance(narrow_seal, clamped_params)
    )
    assert narrow_rcpt.accepted is True
    assert await governor.settle(narrow_seal, executed=True) == []

    # 3. Rollback flow: govern -> consume -> actuator REJECTED -> settle(False) restores exact cost + idempotent NOOP rollback
    reject_params = {"symbol": "NVDA", "amount": 800.0, "confidence": 0.95}
    balance_before_reject = float(await live_stream.stream_redis.get(cbf.redis_key))
    reject_seal = await governor.govern(_ACTION, reject_params)
    assert float(await live_stream.stream_redis.get(cbf.redis_key)) == pytest.approx(
        balance_before_reject - 800.0
    )
    assert await rs.verify_and_consume_seal(reject_seal, _ACTION, reject_params) is True
    reject_rcpt = await dispatch_actuation(
        _TestActuator(accept=False), _make_clearance(reject_seal, reject_params)
    )
    assert reject_rcpt.accepted is False
    assert await governor.settle(reject_seal, executed=False) == []
    assert float(await live_stream.stream_redis.get(cbf.redis_key)) == pytest.approx(
        balance_before_reject
    )

    # Verify idempotent second rollback on the same debit_id emits NOOP with 0 restore
    settlement_entries = [
        json.loads(fields["payload_json"])
        for _id, fields in await live_stream.stream_redis.xrange(_STREAM_KEY)
        if fields["event_type"] == "GOVERNANCE_SETTLEMENT"
    ]
    rolled_back_debit_id = settlement_entries[-1]["debit_ids"][0]
    await cbf.rollback_state(800.0, debit_id=rolled_back_debit_id)
    assert float(await live_stream.stream_redis.get(cbf.redis_key)) == pytest.approx(
        balance_before_reject
    )

    # 4. Denials (governor CBF HARD breach via enforce_governance + middleware/tool record_refusal)
    observed_client_proof_hashes: list[str] = []
    breach_params = {"symbol": "TSLA", "amount": 950.0, "confidence": 0.95}
    # Lower cash right to threshold_value + 100 so 950 breaches safe set (HARD)
    await live_stream.stream_redis.set(cbf.redis_key, str(cbf.threshold_value + 100.0))
    with pytest.raises(gm.GovernanceBlockedError) as blocked_exc:
        await gm.enforce_governance(governor, _ACTION, breach_params)
    assert len(blocked_exc.value.proof_hash) == 64
    observed_client_proof_hashes.append(blocked_exc.value.proof_hash)

    mw_proof_hash = await gm.record_refusal(
        _ACTION,
        "invalid side 'HOLD'",
        oscal_control_ref="SI-10",
        params={"symbol": "AAPL", "side": "HOLD"},
    )
    assert len(mw_proof_hash) == 64
    observed_client_proof_hashes.append(mw_proof_hash)

    refusals_after = sum(
        sample.value
        for metric in ([metrics._refusals] if metrics._refusals is not None else [])
        for family in metric.collect()
        for sample in family.samples
        if sample.name.endswith("_total")
    )
    failures_after = sum(
        sample.value
        for metric in (
            [metrics._evidence_publish_failures]
            if metrics._evidence_publish_failures is not None
            else []
        )
        for family in metric.collect()
        for sample in family.samples
        if sample.name.endswith("_total")
    )
    refusal_delta = int(refusals_after - refusals_before)
    failure_delta = int(failures_after - failures_before)
    assert refusal_delta == 2
    assert failure_delta == 0

    raw_stream = await live_stream.stream_redis.xrange(_STREAM_KEY)
    event_types = {fields["event_type"] for _id, fields in raw_stream}
    assert {
        "GOVERNANCE_THRESHOLDS_LOADED",
        "CBF_COMMIT",
        "CBF_ROLLBACK",
        "GOVERNANCE_DECISION",
        "GOVERNANCE_SEAL_CONSUMED",
        "ACTUATION_RECEIPT",
        "ACTUATION_REFUSAL_RECEIPT",
        "GOVERNANCE_SETTLEMENT",
        "GOVERNANCE_REFUSAL",
        "GOVERNANCE_REFUSAL_RECEIPT",
    } <= event_types

    findings = check_stream(
        raw_stream,
        expected_thresholds_digest=thresholds_digest(),
        expected_refusal_hashes=observed_client_proof_hashes,
        expected_refusal_count=refusal_delta,
        publish_failures=failure_delta,
        require_thresholds_loaded=True,
        require_settled=True,
    )
    assert findings == []

    # Verify CLI --stream mode on exported JSONL
    exported = tmp_path / "stream.jsonl"
    exported.write_text(
        "\n".join(json.dumps(fields) for _id, fields in raw_stream) + "\n",
        encoding="utf-8",
    )
    rc = cli_main(
        [
            "--stream",
            "--expected-thresholds-digest",
            thresholds_digest(),
            "--expected-refusal-hash",
            observed_client_proof_hashes[0],
            "--expected-refusal-hash",
            observed_client_proof_hashes[1],
            "--expected-refusal-count",
            str(refusal_delta),
            "--require-thresholds-loaded",
            "--require-settled",
            str(exported),
        ]
    )
    assert rc == 0


@pytest.mark.asyncio
async def test_mcp_execute_tool_attaches_proof_hash_on_refusal(
    live_stream: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """POST /tools/execute returns structured ``proof_hash`` when a tool refuses."""
    from unittest.mock import MagicMock

    from mcp.server.fastmcp import FastMCP

    import src.gateway.server.mcp_tool_server as mcp_mod
    from src.cage_finance.tools.tool_provider import FinancialToolProvider

    trusted_id = "governed-financial-advisor.governance-stack.serviceaccount.identity.linkerd.cluster.local"
    monkeypatch.setenv("CAGE_TRUSTED_CLIENT_IDENTITIES", trusted_id)
    isolated_mcp = FastMCP("test-mcp-oracle")
    governor = make_governor(core_stages=kernel_stages(allow_opa(), clean_stpa()))
    FinancialToolProvider().register_tools(isolated_mcp, governor)
    monkeypatch.setattr(mcp_mod, "mcp", isolated_mcp)

    async def _allow_rate_limit(_request: Any) -> bool:
        return True

    monkeypatch.setattr(mcp_mod, "_check_rate_limit", _allow_rate_limit)

    req = MagicMock()
    req.scope = {"headers": [(b"l5d-client-id", trusted_id.encode("latin-1"))]}
    req.client = MagicMock(host="127.0.0.1")
    body = await mcp_mod.execute_tool_endpoint(
        mcp_mod.ToolExecutionRequest(
            tool_name="execute_trade_action",
            params={
                "symbol": "AAPL",
                "amount": 100.0,
                "currency": "USD",
                "side": "INVALID_SIDE",
                "transaction_id": "tx-invalid-side",
            },
        ),
        req,
    )
    assert body["status"] == "SUCCESS"
    assert "BLOCKED" in str(body.get("output", ""))
    assert len(body.get("proof_hash", "")) == 64

    raw_stream = await live_stream.stream_redis.xrange(_STREAM_KEY)
    assert (
        check_stream(
            raw_stream,
            expected_refusal_hashes=[body["proof_hash"]],
            expected_refusal_count=1,
        )
        == []
    )


# ---------------------------------------------------------------------------
# 4. Sensitivity / Mutation Controls Across All 5 Invariants (POAM-2026-120)
# ---------------------------------------------------------------------------


def _valid_decision_event(
    *,
    thresholds_hex: str = "a" * 64,
    params_hash: str = "b" * 64,
    **overrides: Any,
) -> dict[str, Any]:
    plan = [["ftra", 1], ["stpa", 1], ["opa", 1], ["confidence", 1], ["cbf", 2]]
    base: dict[str, Any] = {
        "type": "GOVERNANCE_DECISION",
        "schema_version": 2,
        "controlId": "CTRL_SCOPE_001",
        "action": _ACTION,
        "params_hash": params_hash,
        "thresholds_digest": thresholds_hex,
        "timestamp_utc": "2026-10-29T12:00:00+00:00",
        "seal_ttl_s": 30,
        "path": "govern",
        "profile": "FULL",
        "verdict": "ALLOW",
        "phase": "SEAL_ISSUED",
        "seal_present": True,
        "governed": True,
        "narrower_present": False,
        "clamped_params_valid": False,
        "plan": plan,
        "outcomes": [[name, "PASS"] for name, _ in plan],
    }
    return base | overrides


def _rules_of(records: list[dict[str, str]], **kwargs: Any) -> set[str]:
    return {f.rule for f in check_stream(records, **kwargs)}


def test_mutation_chain_tamper_and_gap_caught() -> None:
    chain = _build_synthetic_chain(
        [
            {"type": "GOVERNANCE_THRESHOLDS_LOADED", "thresholds_digest": "a" * 64},
            _valid_decision_event(),
        ]
    )
    # Tamper payload without recomputing record_hash
    tampered = [
        dict(chain[0]),
        {**chain[1], "payload_json": '{"type":"GOVERNANCE_DECISION"}'},
    ]
    assert "chain_hash" in _rules_of(tampered)

    # Gap in sequence / broken prev_hash linkage
    three = _build_synthetic_chain(
        [
            {"type": "GOVERNANCE_THRESHOLDS_LOADED", "thresholds_digest": "a" * 64},
            _valid_decision_event(),
            _valid_decision_event(params_hash="c" * 64),
        ]
    )
    assert "chain_continuity" in _rules_of([three[0], three[2]])


def test_mutation_thresholds_digest_drift_and_missing_loaded_caught() -> None:
    chain = _build_synthetic_chain(
        [
            {"type": "GOVERNANCE_THRESHOLDS_LOADED", "thresholds_digest": "a" * 64},
            _valid_decision_event(thresholds_hex="f" * 64),
        ]
    )
    assert "thresholds" in _rules_of(chain)
    assert "thresholds" in _rules_of(
        _build_synthetic_chain([_valid_decision_event()]),
        require_thresholds_loaded=True,
    )


@pytest.mark.parametrize(
    "actuation_type",
    [
        "ACTUATION_RECEIPT",
        "ACTUATION_REFUSAL_RECEIPT",
        "ACTUATION_INDETERMINATE_RECEIPT",
    ],
)
def test_mutation_inv1_direct_bind_and_replay_caught(actuation_type: str) -> None:
    # Actuation without GOVERNANCE_SEAL_CONSUMED -> no_direct_bind
    direct_actuation = _build_synthetic_chain(
        [
            {
                "type": actuation_type,
                "action": _ACTION,
                "governance_decision_digest": "d" * 64,
            }
        ]
    )
    assert "no_direct_bind" in _rules_of(direct_actuation)

    # Consumed seal with mismatched params_hash -> no_direct_bind
    chain_dec = _build_synthetic_chain([_valid_decision_event(params_hash="b" * 64)])
    dec_hash = chain_dec[0]["record_hash"]
    bad_params = _build_synthetic_chain(
        [
            _valid_decision_event(params_hash="b" * 64),
            {
                "type": "GOVERNANCE_SEAL_CONSUMED",
                "action": _ACTION,
                "params_hash": "e" * 64,
                "phase": "EXECUTED",
                "seal_present": True,
                "seal_ref": "d" * 64,
                "decision_record_hash": dec_hash,
            },
        ]
    )
    assert "no_direct_bind" in _rules_of(bad_params)

    # Replay of same seal_ref -> single_use
    consumed_evt = {
        "type": "GOVERNANCE_SEAL_CONSUMED",
        "action": _ACTION,
        "params_hash": "b" * 64,
        "phase": "EXECUTED",
        "seal_present": True,
        "seal_ref": "d" * 64,
        "decision_record_hash": dec_hash,
    }
    replay_chain = _build_synthetic_chain(
        [_valid_decision_event(params_hash="b" * 64), consumed_evt, consumed_evt]
    )
    assert "single_use" in _rules_of(replay_chain)


def test_mutation_inv2_cbf_safe_set_and_decay_breaches_caught() -> None:
    # Safe-set breach: h_next < 0
    neg_barrier = _build_synthetic_chain(
        [
            {
                "type": "CBF_COMMIT",
                "invariant_id": "cash_reserve",
                "action": _ACTION,
                "debit_id": "deb-1",
                "state_before": 10_000.0,
                "cost": 6_000.0,
                "state_after": 4_000.0,
                "threshold": 5_000.0,
                "gamma": 0.5,
                "h_t": 5_000.0,
                "h_next": -1_000.0,
            }
        ]
    )
    assert "cbf_barrier" in _rules_of(neg_barrier)

    # Decay breach: h_next >= 0, but h_next < (1 - gamma) * h_t (gamma=0.2 => min h_next=8000, actual=5000)
    decay_breach = _build_synthetic_chain(
        [
            {
                "type": "CBF_COMMIT",
                "invariant_id": "cash_reserve",
                "action": _ACTION,
                "debit_id": "deb-2",
                "state_before": 15_000.0,
                "cost": 5_000.0,
                "state_after": 10_000.0,
                "threshold": 5_000.0,
                "gamma": 0.2,
                "h_t": 10_000.0,
                "h_next": 5_000.0,
            }
        ]
    )
    assert "cbf_barrier" in _rules_of(decay_breach)


def test_mutation_inv3_skipped_failed_and_unverified_narrow_stages_caught() -> None:
    # Schema v1 decision (missing stage coverage) -> decision_schema
    v1 = _build_synthetic_chain(
        [
            {
                "type": "GOVERNANCE_DECISION",
                "schema_version": 1,
                "action": _ACTION,
                "params_hash": "b" * 64,
                "thresholds_digest": "a" * 64,
            }
        ]
    )
    assert "decision_schema" in _rules_of(v1)

    # Missing kernel tier ('confidence') -> coverage
    incomplete_plan = [["ftra", 1], ["stpa", 1], ["opa", 1], ["cbf", 2]]
    missing_tier = _build_synthetic_chain(
        [
            _valid_decision_event(
                plan=incomplete_plan,
                outcomes=[[n, "PASS"] for n, _ in incomplete_plan],
            )
        ]
    )
    assert "coverage" in _rules_of(missing_tier)

    # Sealing over a failed stage -> reachable (and consuming it -> no_direct_bind)
    failed_outcomes = [
        ["ftra", "PASS"],
        ["stpa", "PASS"],
        ["opa", "FAIL"],
        ["confidence", "PASS"],
        ["cbf", "PASS"],
    ]
    bad_dec = _valid_decision_event(outcomes=failed_outcomes)
    first = _build_synthetic_chain([bad_dec])
    assert "reachable" in _rules_of(first)
    bad_consumed = _build_synthetic_chain(
        [
            bad_dec,
            {
                "type": "GOVERNANCE_SEAL_CONSUMED",
                "action": _ACTION,
                "params_hash": "b" * 64,
                "phase": "EXECUTED",
                "seal_present": True,
                "seal_ref": "d" * 64,
                "decision_record_hash": first[0]["record_hash"],
            },
        ]
    )
    assert {"reachable", "no_direct_bind"} <= _rules_of(bad_consumed)

    # NARROW decision whose clamped rerun failed a stage -> narrow_reverified
    plan = [["ftra", 1], ["stpa", 1], ["opa", 1], ["confidence", 1], ["cbf", 2]]
    bad_narrow = _build_synthetic_chain(
        [
            _valid_decision_event(
                verdict="NARROW",
                phase="NARROW",
                narrower_present=True,
                clamped_params_valid=True,
                outcomes=[
                    ["ftra", "PASS"],
                    ["stpa", "PASS"],
                    ["opa", "PASS"],
                    ["confidence", "PASS"],
                    ["cbf", "FAIL"],
                ],
                clamped_governed=True,
                clamped_plan=plan,
                clamped_outcomes=[
                    ["ftra", "PASS"],
                    ["stpa", "PASS"],
                    ["opa", "PASS"],
                    ["confidence", "PASS"],
                    ["cbf", "FAIL"],
                ],
            )
        ]
    )
    assert "narrow_reverified" in _rules_of(bad_narrow)


def test_mutation_inv4_rollback_conservation_and_settlement_mismatches_caught() -> None:
    commit_evt = {
        "type": "CBF_COMMIT",
        "invariant_id": "cash_reserve",
        "action": _ACTION,
        "debit_id": "deb-100",
        "state_before": 50_000.0,
        "cost": 500.0,
        "state_after": 49_500.0,
        "threshold": 10_000.0,
        "gamma": 0.5,
        "h_t": 40_000.0,
        "h_next": 39_500.0,
    }
    # Wrong restore amount on ROLLED_BACK -> cbf_rollback
    wrong_restore = _build_synthetic_chain(
        [
            commit_evt,
            {
                "type": "CBF_ROLLBACK",
                "invariant_id": "cash_reserve",
                "debit_id": "deb-100",
                "status": "ROLLED_BACK",
                "state_before": 49_500.0,
                "restore": 400.0,
                "state_after": 49_900.0,
            },
        ]
    )
    assert "cbf_rollback" in _rules_of(wrong_restore)

    # Non-zero restore on ROLLED_BACK_UNLEDGERED -> cbf_rollback
    bad_unledgered = _build_synthetic_chain(
        [
            {
                "type": "CBF_ROLLBACK",
                "invariant_id": "cash_reserve",
                "debit_id": "deb-unledgered",
                "status": "ROLLED_BACK_UNLEDGERED",
                "state_before": 49_500.0,
                "restore": 500.0,
                "state_after": 50_000.0,
            }
        ]
    )
    assert "cbf_rollback" in _rules_of(bad_unledgered)

    # ROLLED_BACK settlement without preceding CBF_ROLLBACK -> settlement
    missing_rb = _build_synthetic_chain(
        [
            commit_evt,
            {
                "type": "GOVERNANCE_SETTLEMENT",
                "seal_ref": "d" * 64,
                "executed": False,
                "status": "ROLLED_BACK",
                "debit_ids": ["deb-100"],
                "failures": [],
            },
        ]
    )
    assert "settlement" in _rules_of(missing_rb)

    # Unsettled commit with require_settled=True -> settlement
    assert "settlement" in _rules_of(
        _build_synthetic_chain([commit_evt]), require_settled=True
    )


@pytest.mark.asyncio
async def test_mutation_inv5_missing_refusal_and_publish_failure_loss_caught(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    empty_chain = _build_synthetic_chain(
        [{"type": "GOVERNANCE_THRESHOLDS_LOADED", "thresholds_digest": "a" * 64}]
    )
    assert "refusal_evidence" in _rules_of(
        empty_chain, expected_refusal_hashes=["9" * 64]
    )
    assert "refusal_evidence" in _rules_of(empty_chain, expected_refusal_count=1)
    assert "evidence_loss" in _rules_of(empty_chain, publish_failures=1)

    # Verify silent-None return from EvidenceStreamSink.ingest increments failure metric
    metrics = governor_metrics()
    before = sum(
        sample.value
        for metric in (
            [metrics._evidence_publish_failures]
            if metrics._evidence_publish_failures is not None
            else []
        )
        for family in metric.collect()
        for sample in family.samples
        if sample.name.endswith("_total")
    )

    class _DroppingSink:
        _redis = object()
        is_running = True

        async def ingest(self, _event: dict[str, Any]) -> None:
            return None

    monkeypatch.setattr(gm, "get_evidence_sink", lambda: _DroppingSink())
    ph = await gm.record_refusal(
        _ACTION, "dropped refusal", oscal_control_ref="AC-3", params={}
    )
    assert len(ph) == 64
    after = sum(
        sample.value
        for metric in (
            [metrics._evidence_publish_failures]
            if metrics._evidence_publish_failures is not None
            else []
        )
        for family in metric.collect()
        for sample in family.samples
        if sample.name.endswith("_total")
    )
    delta = int(after - before)
    assert delta == 1
    assert "evidence_loss" in _rules_of(empty_chain, publish_failures=delta)

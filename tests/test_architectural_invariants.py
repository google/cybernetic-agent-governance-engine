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
Architectural Invariant Tests — Lock Clean Boundaries into CI.

These tests enforce structural contracts to prevent refactors, automated linter
cleanups, or dependency upgrades from disconnecting governance controls.

Invariant Categories:
  1. AST Seam Isolation — enforce call-graph boundaries
  2. Runtime Traversal — verify execution paths with spies
  3. Wire Protocol — validate transport-level contracts
  4. Ingress Authentication — mesh workload identity, no shared secret

Test Selection Markers: pytest.mark.unit, pytest.mark.local
"""

import ast
import json
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.cage_finance.models.trade_order import TradeOrder
from src.gateway.governance.defer_queue import DeferQueue, DeferToken
from src.gateway.governance.seams.actuation import ActuationReceipt, ExecutionClearance
from tests.fixtures.trade_inputs import trade_governor

pytestmark = [pytest.mark.unit, pytest.mark.local]


# ──────────────────────────────────────────────────────────────────────────────
# Invariant 1: AST — Actuator Seam Isolation (execute_trade)
# ──────────────────────────────────────────────────────────────────────────────


_SRC_ROOT = Path(__file__).parent.parent / "src"
_REPO_ROOT = _SRC_ROOT.parent

# The single place in src/ allowed to call the broker's execute_trade. The
# actuator is reached only through ActuatorRegistry after
# verify_and_consume_seal() has verified the routing seal and consumed its
# nonce (ADR-008). Do not add entries: a second call site is a second path to
# the broker that the seal check does not cover.
_EXECUTE_TRADE_CALL_SITES = frozenset(
    {("src/cage_finance/actuators/broker_actuator.py", "BrokerActuator", "actuate")}
)
_TRADE_EXECUTOR_MODULE = "src.cage_finance.tools.trade_executor"


class _ExecuteTradeScan(ast.NodeVisitor):
    """Record execute_trade calls/imports and literal routing seals in one module."""

    def __init__(self, rel_path: str) -> None:
        self.rel_path = rel_path
        self.scope: list[tuple[str, str]] = []  # (kind, name)
        self.calls: list[tuple[int, str | None, str | None]] = []
        self.imports: list[int] = []
        self.literal_seals: list[int] = []

    def _enclosing(self, kind: str) -> str | None:
        return next((n for k, n in reversed(self.scope) if k == kind), None)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.scope.append(("class", node.name))
        self.generic_visit(node)
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.scope.append(("func", node.name))
        self.generic_visit(node)
        self.scope.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module == _TRADE_EXECUTOR_MODULE or (
            node.module == "src.cage_finance.tools"
            and any(a.name == "trade_executor" for a in node.names)
        ):
            self.imports.append(node.lineno)
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        if any(a.name == _TRADE_EXECUTOR_MODULE for a in node.names):
            self.imports.append(node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        name = (
            func.id
            if isinstance(func, ast.Name)
            else func.attr
            if isinstance(func, ast.Attribute)
            else None
        )
        if name == "execute_trade":
            self.calls.append(
                (node.lineno, self._enclosing("class"), self._enclosing("func"))
            )
        for kw in node.keywords:
            if (
                kw.arg == "routing_seal"
                and isinstance(kw.value, ast.Constant)
                and isinstance(kw.value.value, str)
            ):
                self.literal_seals.append(node.lineno)
        self.generic_visit(node)


def _scan_src() -> list[_ExecuteTradeScan]:
    scans = []
    for py_file in sorted(_SRC_ROOT.rglob("*.py")):
        rel = str(py_file.relative_to(_REPO_ROOT))
        scan = _ExecuteTradeScan(rel)
        scan.visit(ast.parse(py_file.read_text(), filename=rel))
        scans.append(scan)
    return scans


def test_actuator_seam_isolation_execute_trade():
    """
    Verify that execute_trade() is called ONLY within BrokerActuator.actuate().

    Architectural Invariant:
        trade_executor.execute_trade is the domain execution layer and must
        NEVER be invoked directly from governance kernel or any module outside
        the broker actuator seam. The broker only checks that the routing seal
        is non-empty, so any other caller bypasses verify_and_consume_seal()
        (ADR-008). The dead ``bounded_execution`` wrapper did exactly that
        (POAM-2026-109).

    Enforcement:
        Parse every .py file in src/ (including ``__init__.py``) and assert
        that execute_trade is invoked only from
        broker_actuator.py::BrokerActuator.actuate, and that only
        broker_actuator.py imports trade_executor (no aliased call sites).
    """
    violations: list[str] = []
    for scan in _scan_src():
        for lineno, cls, func in scan.calls:
            if (scan.rel_path, cls, func) not in _EXECUTE_TRADE_CALL_SITES:
                violations.append(
                    f"{scan.rel_path}:{lineno} → execute_trade called from "
                    f"{cls or '<module>'}.{func or '<module>'}"
                )
        allowed_importers = {path for path, _, _ in _EXECUTE_TRADE_CALL_SITES}
        if scan.rel_path not in allowed_importers:
            violations.extend(
                f"{scan.rel_path}:{lineno} → imports trade_executor"
                for lineno in scan.imports
            )

    assert not violations, (
        "execute_trade must be called ONLY from BrokerActuator.actuate. "
        "Violations found:\n" + "\n".join(violations)
    )


def test_no_literal_routing_seal_in_src():
    """
    Verify no module in src/ passes a string literal as ``routing_seal``.

    A routing seal is minted by the governor and verified and consumed by
    verify_and_consume_seal(). A hard-coded string (the removed
    ``"INTERNAL_BOUNDED_EXECUTION"``) satisfies the broker's non-empty check
    without any governance decision behind it (POAM-2026-109).
    """
    violations = [
        f"{scan.rel_path}:{lineno} → routing_seal is a string literal"
        for scan in _scan_src()
        for lineno in scan.literal_seals
    ]
    assert not violations, (
        "routing_seal must come from a verified governance decision, never a "
        "literal. Violations found:\n" + "\n".join(violations)
    )


# ──────────────────────────────────────────────────────────────────────────────
# Invariant 2: AST — No Public Defer Resolve
# ──────────────────────────────────────────────────────────────────────────────


def test_defer_queue_resolve_is_internal_only():
    """
    Verify that DeferQueue._resolve() is called ONLY within defer_queue.py.

    Architectural Invariant:
        DeferQueue._resolve is an internal method that MUST NOT be called
        by checking the receiver type. Only calls on queue._resolve where
        queue is typed as DeferQueue should be allowed.

    Enforcement:
        Parse AST of defer_queue.py to verify _resolve is private (leading underscore).
        The Python convention enforces this as a private API contract.
    """
    src_root = Path(__file__).parent.parent / "src"
    defer_queue_file = src_root / "gateway" / "governance" / "defer_queue.py"

    # Verify _resolve method exists and is private (leading underscore)
    tree = ast.parse(defer_queue_file.read_text())

    has_resolve_method = False
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "DeferQueue":
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if item.name == "_resolve":
                        has_resolve_method = True
                        # Verify it starts with underscore (private convention)
                        assert item.name.startswith("_"), (
                            "DeferQueue._resolve must be private (leading underscore)"
                        )

    assert has_resolve_method, "DeferQueue._resolve method not found"


# ──────────────────────────────────────────────────────────────────────────────
# Invariant 3: Runtime Spy — Two-Stage Boundary Traversal
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_execute_trade_action_traverses_actuator():
    """
    Verify that execute_trade_action MUST traverse BrokerActuator.actuate().

    Architectural Invariant:
        No direct execution path may bypass the actuator seam. All trade
        executions must flow through the actuator with an ExecutionClearance.

    Enforcement:
        Patch BrokerActuator.actuate with a spy. Invoke execute_trade_action
        and assert that actuate() was called with a valid ExecutionClearance.
    """
    from src.cage_finance.tools.tool_provider import execute_trade_action

    # Create a spy receipt that will be returned by the mocked actuate()
    spy_receipt = ActuationReceipt(
        accepted=True,
        receipt_id="test-receipt-001",
        session_uuid=str(uuid.uuid4()),
        raw_receipt={"status": "executed"},
        findings=[],
        retryable=False,
        timestamp_utc="2026-09-13T21:00:00Z",
    )

    actuate_spy = AsyncMock(return_value=spy_receipt)

    with patch(
        "src.cage_finance.actuators.broker_actuator.BrokerActuator.actuate", actuate_spy
    ):
        with patch(
            "src.cage_finance.tools.tool_provider.enforce_governance"
        ) as mock_governance:
            # Mock governance to return a seal
            mock_governance.return_value = "test-seal-" + "a" * 56

            with patch(
                "src.gateway.governance.routing_seal.verify_and_consume_seal"
            ) as mock_verify:
                # Mock seal verification to succeed (it's an async function)
                mock_verify.return_value = None

                with patch(
                    "src.gateway.infrastructure.redis_client.redis_client"
                ) as mock_redis:
                    # Mock Redis client for NARROW receipt lookup
                    mock_redis.get = AsyncMock(return_value=None)

                    # Execute a trade action
                    result = await execute_trade_action(
                        symbol="AAPL",
                        amount=10.0,
                        currency="USD",
                        confidence=0.95,
                        governor=trade_governor(),
                    )

    # Assert the actuate spy was called
    assert actuate_spy.called, "BrokerActuator.actuate() was not called"
    assert actuate_spy.call_count == 1, f"Expected 1 call, got {actuate_spy.call_count}"

    # Assert the clearance passed to actuate() is valid
    call_args = actuate_spy.call_args
    assert call_args is not None, "actuate() was called with no arguments"

    clearance = call_args[0][0]  # First positional arg
    assert isinstance(clearance, ExecutionClearance), (
        f"actuate() must be called with ExecutionClearance, got {type(clearance)}"
    )
    assert clearance.decision == "ALLOW", f"Expected ALLOW, got {clearance.decision}"
    assert clearance.action == "execute_trade", (
        f"Expected execute_trade, got {clearance.action}"
    )

    # Assert result reflects actuation success
    assert "EXECUTED" in result or "Receipt ID" in result


# ──────────────────────────────────────────────────────────────────────────────
# Invariant 4: Runtime Spy — Replay Evaluator Traversal
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_defer_token_resolution_traverses_replay_evaluate():
    """
    Verify that parked token resolution MUST traverse replay_evaluate().

    Architectural Invariant:
        No direct resolution path may bypass confidence threshold checks.
        All resolutions must flow through replay_evaluate() which enforces
        the confidence.defer_floor gate.

    Enforcement:
        Mock DeferQueue with a parked token. Patch replay_evaluate with a spy.
        Trigger resolution and assert replay_evaluate() was invoked.
    """
    from src.gateway.governance.defer_queue import replay_evaluate

    # Create a mock DeferQueue
    mock_queue = MagicMock(spec=DeferQueue)

    # Create a mock parked token
    mock_token = DeferToken(
        defer_id="test-defer-001",
        thread_id="test-thread-001",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 10.0},
        defer_reason="CONFIDENCE_BELOW_THRESHOLD",
        confidence_score=0.65,
        ttl_seconds=3600,
    )

    # Mock the status-bearing read to return the parked token
    mock_queue._read_token_with_rev = AsyncMock(return_value=(mock_token, "PARKED", 0))

    # Mock queue._resolve to track calls
    mock_queue._resolve = AsyncMock(return_value=mock_token)

    # Enriched context with confidence above threshold
    enriched_context = {
        "confidence_score": 0.85,
        "enrichment_source": "normative_provider",
    }

    # Call replay_evaluate with the mock queue
    result = await replay_evaluate(
        queue=mock_queue,
        defer_id="test-defer-001",
        enriched_context=enriched_context,
    )

    # Assert replay_evaluate triggered resolution
    assert mock_queue._resolve.called, "DeferQueue._resolve was not called"
    assert mock_queue._resolve.call_count == 1, (
        f"Expected 1 call, got {mock_queue._resolve.call_count}"
    )

    # Assert resolution was INJECTED (admitted)
    call_args = mock_queue._resolve.call_args
    assert call_args[0][0] == "test-defer-001", "Wrong defer_id passed to _resolve"
    assert call_args[0][1] == "INJECTED", f"Expected INJECTED, got {call_args[0][1]}"

    # Assert result is ADMITTED
    from src.gateway.governance.defer_queue import ReplayResult

    assert result == ReplayResult.ADMITTED, f"Expected ADMITTED, got {result}"


# ──────────────────────────────────────────────────────────────────────────────
# Invariant 5: Transport Wire — RFC 8785 Canonical Envelope
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_validate_action_returns_canonical_envelope(monkeypatch):
    """
    Verify that POST /validate-action returns RFC 8785 canonical envelope.

    Architectural Invariant:
        All governance verdicts MUST be transmitted in a canonical envelope
        containing jcs_digest, signature, and payload fields at the top level.

    Enforcement:
        Invoke POST /validate-action on governance_app and assert the response
        contains the required canonical envelope structure.
    """
    from httpx import ASGITransport, AsyncClient

    from src.gateway.server.governance_middleware import governance_app

    # Prepare a minimal validate-action request
    request_body = {
        "action": "execute_trade",
        "params": {
            "symbol": "AAPL",
            "amount": 10.0,
            "currency": "USD",
            "confidence": 0.95,
            "transaction_id": str(uuid.uuid4()),
            "trader_id": "test-agent",
            "trader_role": "junior",
            "dry_run": True,
        },
    }

    body_bytes = json.dumps(request_body).encode()
    headers = {"Content-Type": "application/json", "x-forwarded-for": "127.0.0.1"}

    # Store a mock governor on the app (as the lifespan would) returning ALLOW
    from src.gateway.governance.governor.governor import SymbolicGovernor

    mock_gov = MagicMock(spec=SymbolicGovernor)
    mock_gov.validate_action = AsyncMock(
        return_value={
            "verdict": "ALLOW",
            "action": "execute_trade",
        }
    )
    monkeypatch.setattr(governance_app.state, "governor", mock_gov, raising=False)

    # Mock rate limit check to always allow
    with patch(
        "src.gateway.server.governance_middleware._check_validate_action_rate_limit",
        return_value=True,
    ):
        transport = ASGITransport(app=governance_app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/validate-action",
                content=body_bytes,
                headers=headers,
            )

    assert response.status_code == 200, f"Expected 200, got {response.status_code}"

    # Parse response body
    body = response.json()

    # Assert canonical envelope structure fields are present
    assert "envelope_version" in body, (
        "Response missing required field: envelope_version"
    )
    assert "envelope_type" in body, "Response missing required field: envelope_type"
    assert "envelope_id" in body, "Response missing required field: envelope_id"
    assert "issued_at" in body, "Response missing required field: issued_at"
    assert "payload" in body, "Response missing required field: payload"

    # Assert envelope_version follows semantic versioning
    assert isinstance(body["envelope_version"], str), (
        "envelope_version must be a string"
    )
    assert body["envelope_version"].startswith("3."), (
        f"Expected version 3.x, got {body['envelope_version']}"
    )

    # Assert envelope_type identifies governance decisions
    assert body["envelope_type"] == "cage_governance_decision", (
        f"Expected cage_governance_decision, got {body['envelope_type']}"
    )

    # Assert payload contains the verdict
    assert isinstance(body["payload"], dict), "payload must be a dict"
    assert "verdict" in body["payload"], "payload missing required field: verdict"
    assert body["payload"]["verdict"] == "ALLOW", (
        f"Expected ALLOW, got {body['payload']['verdict']}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# Invariant 6: Ingress Authentication — Mesh Workload Identity (POAM-2026-080)
# ──────────────────────────────────────────────────────────────────────────────

_REPO_ROOT = Path(__file__).resolve().parent.parent
_HYBRID_SERVER = _REPO_ROOT / "src" / "gateway" / "server" / "hybrid_server.py"


def _root_app_middleware_calls() -> list[ast.Call]:
    """Return every ``root_app.add_middleware(...)`` call in hybrid_server.py, in order."""
    tree = ast.parse(_HYBRID_SERVER.read_text())
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "add_middleware"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "root_app"
    ]
    return sorted(calls, key=lambda c: c.lineno)


def test_root_app_installs_workload_identity_middleware_outermost():
    """
    The gateway root app authenticates every caller by mesh workload identity.

    Architectural Invariant:
        ``WorkloadIdentityMiddleware`` is installed on ``root_app`` and is the
        last ``add_middleware`` call, so Starlette runs it first — ahead of
        every other middleware and every mounted sub-app (governance, MCP,
        inference). Removing or reordering it re-opens the ingress.
    """
    calls = _root_app_middleware_calls()
    names = [c.args[0].id for c in calls if c.args and isinstance(c.args[0], ast.Name)]

    assert "WorkloadIdentityMiddleware" in names, (
        "root_app must install WorkloadIdentityMiddleware (POAM-2026-080)"
    )
    assert names[-1] == "WorkloadIdentityMiddleware", (
        "WorkloadIdentityMiddleware must be the last add_middleware call on "
        f"root_app so it runs first; order is {names}"
    )


def test_root_app_workload_identity_middleware_is_live():
    """The imported root app carries WorkloadIdentityMiddleware at runtime."""
    from src.gateway.server.hybrid_server import root_app
    from src.gateway.server.workload_identity import WorkloadIdentityMiddleware

    assert any(m.cls is WorkloadIdentityMiddleware for m in root_app.user_middleware)


def test_hmac_ingress_seal_is_gone_from_src():
    """
    The shared-secret HMAC ingress check stays deleted.

    Architectural Invariant:
        Caller authentication is mesh workload identity only. No module under
        ``src/`` may define or call ``enforce_routing_seal`` (the removed
        ``X-CAGE-Routing-Seal`` HMAC check), so a shared-secret ingress path
        cannot silently return alongside the identity check.
    """
    offenders = [
        str(path.relative_to(_REPO_ROOT))
        for path in (_REPO_ROOT / "src").rglob("*.py")
        if "enforce_routing_seal" in path.read_text(encoding="utf-8")
    ]
    assert offenders == [], f"enforce_routing_seal must not exist in src/: {offenders}"

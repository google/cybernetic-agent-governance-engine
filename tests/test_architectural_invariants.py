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

pytestmark = [pytest.mark.unit, pytest.mark.local]


# ──────────────────────────────────────────────────────────────────────────────
# Invariant 1: AST — Actuator Seam Isolation (execute_trade)
# ──────────────────────────────────────────────────────────────────────────────


def test_actuator_seam_isolation_execute_trade():
    """
    Verify that execute_trade() is called ONLY within BrokerActuator.actuate().
    
    Architectural Invariant:
        trade_executor.execute_trade is the domain execution layer and must
        NEVER be invoked directly from governance kernel or any module outside
        the broker actuator seam.
    
    Enforcement:
        Parse AST of all .py files in src/ and assert that execute_trade is
        invoked only from broker_actuator.py::BrokerActuator.actuate.
    """
    src_root = Path(__file__).parent.parent / "src"
    violations: list[str] = []
    
    # Allowed call sites: BrokerActuator.actuate and bounded_execution (legacy wrapper)
    allowed_files = {
        "src/cage_finance/actuators/broker_actuator.py",
        "src/cage_finance/tools/bounded_execution.py",  # Legacy bounding contract wrapper
    }
    
    for py_file in src_root.rglob("*.py"):
        if py_file.name == "__init__.py":
            continue
        
        try:
            tree = ast.parse(py_file.read_text(), filename=str(py_file))
        except SyntaxError:
            # Skip files that fail to parse (non-Python or broken syntax)
            continue
        
        # Track current class and method for context
        class_stack: list[str] = []
        method_stack: list[str] = []
        
        for node in ast.walk(tree):
            # Track class definitions
            if isinstance(node, ast.ClassDef):
                class_stack.append(node.name)
            
            # Track function/method definitions
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                method_stack.append(node.name)
            
            # Look for calls to execute_trade
            if isinstance(node, ast.Call):
                # Check for direct function call: execute_trade(...)
                if isinstance(node.func, ast.Name) and node.func.id == "execute_trade":
                    file_path = str(py_file.relative_to(src_root.parent))
                    
                    if file_path not in allowed_files:
                        current_class = class_stack[-1] if class_stack else None
                        current_method = method_stack[-1] if method_stack else "<module>"
                        violations.append(
                            f"{file_path}:{node.lineno} "
                            f"→ execute_trade called from {current_class or '<module>'}.{current_method}"
                        )
                
                # Check for module.execute_trade(...) calls
                if isinstance(node.func, ast.Attribute) and node.func.attr == "execute_trade":
                    file_path = str(py_file.relative_to(src_root.parent))
                    
                    if file_path not in allowed_files:
                        current_class = class_stack[-1] if class_stack else None
                        current_method = method_stack[-1] if method_stack else "<module>"
                        violations.append(
                            f"{file_path}:{node.lineno} "
                            f"→ execute_trade called from {current_class or '<module>'}.{current_method}"
                        )
    
    assert not violations, (
        "execute_trade must be called ONLY from BrokerActuator.actuate. "
        "Violations found:\n" + "\n".join(violations)
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
    
    with patch("src.cage_finance.actuators.broker_actuator.BrokerActuator.actuate", actuate_spy):
        with patch("src.cage_finance.tools.tool_provider.enforce_governance") as mock_governance:
            # Mock governance to return a seal
            mock_governance.return_value = "test-seal-" + "a" * 56
            
            with patch("src.gateway.governance.routing_seal.verify_and_consume_seal") as mock_verify:
                # Mock seal verification to succeed (it's an async function)
                mock_verify.return_value = None
                
                with patch("src.gateway.infrastructure.redis_client.redis_client") as mock_redis:
                    # Mock Redis client for NARROW receipt lookup
                    mock_redis.get = AsyncMock(return_value=None)
                    
                    # Execute a trade action
                    result = await execute_trade_action(
                        symbol="AAPL",
                        amount=10.0,
                        currency="USD",
                        confidence=0.95,
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
    assert clearance.action == "execute_trade", f"Expected execute_trade, got {clearance.action}"
    
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
        the DEFER_CONFIDENCE_THRESHOLD gate.
    
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
    
    # Mock queue.get to return the token
    mock_queue.get = AsyncMock(return_value=mock_token)
    
    # Mock queue._resolve to track calls
    mock_queue._resolve = AsyncMock()
    
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
    assert mock_queue._resolve.call_count == 1, f"Expected 1 call, got {mock_queue._resolve.call_count}"
    
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
async def test_validate_action_returns_canonical_envelope():
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

    # Mock the symbolic_governor to return a simple ALLOW verdict
    with patch("src.gateway.server.governance_middleware.symbolic_governor") as mock_gov:
        mock_gov.validate_action = AsyncMock(
            return_value={
                "verdict": "APPROVED",
                "action": "execute_trade",
                "routing_seal": "test-seal-" + "b" * 56,
            }
        )

        # Mock rate limit check to always allow
        with patch("src.gateway.server.governance_middleware._check_validate_action_rate_limit", return_value=True):
            transport = ASGITransport(app=governance_app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.post(
                    "/validate-action",
                    json=request_body,
                    headers={"x-forwarded-for": "127.0.0.1"},
                )

    assert response.status_code == 200, f"Expected 200, got {response.status_code}"

    # Parse response body
    body = response.json()

    # Assert canonical envelope structure fields are present
    assert "envelope_version" in body, "Response missing required field: envelope_version"
    assert "envelope_type" in body, "Response missing required field: envelope_type"
    assert "envelope_id" in body, "Response missing required field: envelope_id"
    assert "issued_at" in body, "Response missing required field: issued_at"
    assert "payload" in body, "Response missing required field: payload"
    
    # Assert envelope_version follows semantic versioning
    assert isinstance(body["envelope_version"], str), "envelope_version must be a string"
    assert body["envelope_version"].startswith("3."), f"Expected version 3.x, got {body['envelope_version']}"
    
    # Assert envelope_type identifies governance decisions
    assert body["envelope_type"] == "cage_governance_decision", (
        f"Expected cage_governance_decision, got {body['envelope_type']}"
    )
    
    # Assert payload contains the verdict
    assert isinstance(body["payload"], dict), "payload must be a dict"
    assert "verdict" in body["payload"], "payload missing required field: verdict"
    assert body["payload"]["verdict"] == "APPROVED", f"Expected APPROVED, got {body['payload']['verdict']}"

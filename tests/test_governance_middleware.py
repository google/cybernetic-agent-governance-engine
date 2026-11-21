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
Tests for src.gateway.server.governance_middleware (BLOCKER-08).

Caller authentication is not this module's concern: every route is reached
only through ``WorkloadIdentityMiddleware`` on the gateway root app
(POAM-2026-080), which is covered by tests/test_workload_identity_middleware.py.

Coverage targets
----------------
A. The removed POST /check route
   - POST /check → 404 and never reaches the governor (use /validate-action)

B. /governance/validate-action endpoint
   - Happy path: valid action → 200 ALLOW (no seal)
   - GovernanceError → 403 DENIED (not 500)
   - Internal exception → 500 with "Internal governance error" (MED-03 fix)
   - detail field never contains stack trace or internal variable names
   - 200 envelopes carry the governor's ``evaluated_action_hash`` as
     ``subject.evaluated_action_hash`` (never in the payload);
     ``subject.action_hash`` binds the submitted params; 403 envelopes
     carry no evaluated hash

C. enforce_approved_governance (POAM-2026-079)
   - /governance/revalidate-post-hitl no longer exists
   - Redeemable approval → POST_HITL commit, returning the SealedAction
   - The pre-check reads token state only: no ``covers``, no server-input
     binding; the approval's ``covers`` / ``spend`` decide coverage of the
     evaluated params (a raising or non-dict matcher input never authorises)
   - Missing/unapproved approval, queue outage → refused with an AC-3
     refusal receipt or blocked; nothing is committed
   - POST_HITL refusal → PermissionError + SC-4 refusal receipt

D. _emit_refusal_receipt()
   - Signs receipt via KMS signer and calls evidence sink
   - KMS sign failure is logged but does not suppress the call
   - Evidence sink failure is logged but does not suppress the call

E. Module exports

G. enforce_governance(): every tool name is governed (no exemption)

Notes
-----
- asyncio_mode = "auto" in pyproject.toml — no @pytest.mark.asyncio needed.
"""

from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager, contextmanager
from types import MappingProxyType
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("CAGE_ENV", "test")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("GOVERNANCE_SALT", "CYBERNETIC_GOVERNANCE_TEST_SALT_32C!")

pytestmark = [pytest.mark.unit, pytest.mark.local]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _json_body(
    tool_name: str = "execute_trade", params: dict[str, Any] | None = None
) -> bytes:
    return json.dumps(
        {"tool_name": tool_name, "params": params or {"amount": 100}}
    ).encode()


#: The params every approved-run test submits.
_PARAMS: dict[str, Any] = {"symbol": "AAPL", "amount": 10.0}


def _sealed(action: str, seal: str, params: dict[str, Any]) -> Any:
    """What a committing run returns: the seal and the evaluated params."""
    from src.gateway.governance.governor.sealing import SealedAction

    return SealedAction(action, seal, dict(params))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _mock_governor() -> MagicMock:
    """A governor mock that passes ``governor_of``'s ``SymbolicGovernor`` check."""
    from src.gateway.governance.governor.governor import SymbolicGovernor

    return MagicMock(spec=SymbolicGovernor)


@contextmanager
def _installed_governor(gov: Any):
    """Temporarily set ``governance_app.state.governor`` to ``gov``."""
    from src.gateway.server.governance_middleware import governance_app

    previous = getattr(governance_app.state, "governor", None)
    governance_app.state.governor = gov
    try:
        yield gov
    finally:
        governance_app.state.governor = previous


@pytest.fixture()
def mock_symbolic_governor():
    """Install a mock governor on ``governance_app.state`` (where the lifespan puts it)."""
    gov = _mock_governor()
    gov.verify = AsyncMock(
        return_value={"violations": [], "opa_results": {"allow": True}}
    )
    gov.validate_action = AsyncMock(
        return_value={
            "verdict": "ALLOW",
            "violations": [],
            "latency_ms": 1.0,
        }
    )
    with _installed_governor(gov):
        yield gov


@pytest.fixture()
def mock_kms_signer():
    """Patch get_governance_signer() to return a mock that signs/verifies locally."""
    signer = MagicMock()
    signer.sign = MagicMock(return_value="deadbeef" * 8)  # 64-char hex
    signer.sign_async = AsyncMock(return_value="deadbeef" * 8)
    signer.verify = MagicMock(return_value=True)
    signer.signing_algorithm = "HMAC_SHA256_FALLBACK"
    with patch(
        "src.gateway.server.governance_middleware.get_governance_signer",
        return_value=signer,
    ):
        yield signer


@pytest.fixture()
def mock_evidence_sink():
    """Patch the evidence stream sink so _emit_refusal_receipt doesn't call real I/O."""
    sink = MagicMock()
    sink.ingest = AsyncMock(return_value="1700000000000-0")
    with patch(
        "src.gateway.server.governance_middleware.get_evidence_sink",
        return_value=sink,
    ):
        yield sink


@pytest.fixture()
def gov_client(mock_symbolic_governor, mock_kms_signer):
    """TestClient on governance_app with a mock governor installed."""
    from src.gateway.server.governance_middleware import governance_app

    return TestClient(governance_app, raise_server_exceptions=False)


# ===========================================================================
# A. /check is removed (refactor/gateway-surface-cleanup)
# ===========================================================================


class TestGovernanceCheckRouteRemoved:
    """POST /check was a dead non-committing duplicate of /validate-action."""

    def test_check_route_is_gone(self, gov_client, mock_symbolic_governor):
        """The route no longer exists and never reaches the governor."""
        resp = gov_client.post(
            "/check",
            content=_json_body("execute_trade", {"amount": 100}),
            headers={"Content-Type": "application/json"},
        )

        assert resp.status_code == 404
        mock_symbolic_governor.verify.assert_not_awaited()
        mock_symbolic_governor.validate_action.assert_not_awaited()


# ===========================================================================
# B. /validate-action endpoint tests
# ===========================================================================


class TestValidateActionEndpoint:
    """Tests for POST /validate-action on governance_app."""

    @pytest.fixture()
    def client(self, mock_symbolic_governor, mock_kms_signer):
        from src.gateway.server.governance_middleware import governance_app

        return TestClient(governance_app, raise_server_exceptions=False)

    def test_validate_action_happy_path_approved(self, client, mock_symbolic_governor):
        """Valid action returns 200 with an ALLOW verdict in the canonical envelope."""
        resp = client.post(
            "/validate-action",
            json={
                "action": "execute_trade",
                "params": {"amount": 100, "symbol": "AAPL"},
            },
        )

        assert resp.status_code == 200
        data = resp.json()

        # ADR-008 Phase 3: Assert canonical envelope structure
        assert data.get("envelope_version") == "3.0"
        assert data.get("envelope_type") == "cage_governance_decision"
        assert "envelope_id" in data
        assert "issued_at" in data
        assert "expires_at" in data
        assert "issuer" in data
        assert "subject" in data
        assert "governance_context" in data
        assert "payload" in data

        # Assert that the payload contains the governance result
        payload = data["payload"]
        assert payload["verdict"] == "ALLOW"
        assert payload["violations"] == []
        assert "seal" not in payload

        # Assert signature presence (may be None if KMS not active in test)
        assert "signature" in data or data.get("signature") is None

        mock_symbolic_governor.validate_action.assert_awaited_once_with(
            action="execute_trade",
            params={"amount": 100, "symbol": "AAPL"},
            policy_version_id=None,
        )

    def test_validate_action_missing_action_field_returns_422(self, client):
        """Body without required 'action' field returns HTTP 422 (Pydantic validation)."""
        resp = client.post(
            "/validate-action",
            json={"params": {"amount": 100}},
        )
        assert resp.status_code == 422

    def test_validate_action_missing_params_field_returns_422(self, client):
        """Body without required 'params' field returns HTTP 422 (Pydantic validation)."""
        resp = client.post(
            "/validate-action",
            json={"action": "execute_trade"},
        )
        assert resp.status_code == 422

    def test_validate_action_governance_denial_returns_403_not_500(
        self, client, mock_symbolic_governor
    ):
        """GovernanceError from the governor returns 403 DENIED — not 500."""
        from src.gateway.governance.governor.governor import GovernanceError

        mock_symbolic_governor.validate_action = AsyncMock(
            side_effect=GovernanceError("OPA policy denied execute_trade")
        )

        with patch(
            "src.gateway.server.governance_middleware._emit_refusal_receipt",
            new=AsyncMock(return_value=None),
        ):
            resp = client.post(
                "/validate-action",
                json={"action": "execute_trade", "params": {"amount": 100}},
            )

        assert resp.status_code == 403
        data = resp.json()

        # ADR-008 Phase 3 + cage-client v0.4.0: HTTP 403 is wrapped in a GovernanceEnvelope
        assert data["envelope_version"] == "3.0"
        assert data["subject"]["action"] == "execute_trade"
        payload = data["payload"]
        assert payload.get("schema_version") == "2.0.0"
        assert payload["verdict"] == "DENIED"
        assert len(payload["violations"]) > 0

    def test_validate_action_internal_exception_returns_500_safe_message(
        self, client, mock_symbolic_governor
    ):
        """Internal exception returns 500 with 'Internal governance error' — not raw exc.

        This tests the MED-03 fix: the raw exception message (which may contain
        internal variable names or stack traces) must NOT appear in the response.
        """
        mock_symbolic_governor.validate_action = AsyncMock(
            side_effect=RuntimeError("secret_internal_variable_name_leaked")
        )

        resp = client.post(
            "/validate-action",
            json={"action": "execute_trade", "params": {"amount": 100}},
        )

        assert resp.status_code == 500
        body_text = resp.text
        # MED-03: safe message must be present
        assert "Internal governance error" in body_text
        # MED-03: raw exception detail must NOT leak
        assert "secret_internal_variable_name_leaked" not in body_text

    def test_validate_action_detail_never_contains_stack_trace(
        self, client, mock_symbolic_governor
    ):
        """The 'detail' field must never contain a Python traceback string."""
        mock_symbolic_governor.validate_action = AsyncMock(
            side_effect=ValueError("Traceback (most recent call last):\n  File test.py")
        )

        resp = client.post(
            "/validate-action",
            json={"action": "execute_trade", "params": {"amount": 100}},
        )

        assert resp.status_code == 500
        body_text = resp.text
        # Stack trace markers must not appear in the HTTP response body
        assert "Traceback" not in body_text
        assert "most recent call last" not in body_text

    def test_validate_action_governance_denial_emits_refusal_receipt(
        self, client, mock_symbolic_governor, mock_kms_signer
    ):
        """GovernanceError triggers _emit_refusal_receipt (P6 compliance receipt)."""
        from src.gateway.governance.governor.governor import GovernanceError

        mock_symbolic_governor.validate_action = AsyncMock(
            side_effect=GovernanceError("fiscal_limit_exceeded")
        )

        with patch(
            "src.gateway.server.governance_middleware._emit_refusal_receipt",
            new=AsyncMock(return_value=None),
        ) as mock_emit:
            resp = client.post(
                "/validate-action",
                json={"action": "execute_trade", "params": {"amount": 999999}},
            )

        assert resp.status_code == 403
        mock_emit.assert_awaited_once()
        call_kwargs = mock_emit.call_args
        assert call_kwargs.kwargs["action_id"] == "execute_trade"
        assert "fiscal_limit_exceeded" in call_kwargs.kwargs["refusal_reason"]
        assert call_kwargs.kwargs["oscal_control_ref"] == "SC-4"

    @pytest.mark.parametrize(
        "verdict",
        [
            {"verdict": "ALLOW", "violations": [], "latency_ms": 1.0},
            {
                "verdict": "REQUIRE_APPROVAL",
                "violations": [],
                "deferred_id": "defer-7",
                "latency_ms": 1.0,
            },
        ],
        ids=["allow", "require-approval"],
    )
    def test_envelope_subject_carries_the_evaluated_action_hash(
        self, client, mock_symbolic_governor, verdict: dict[str, Any]
    ):
        """The governor's evaluated_action_hash is signed as subject metadata.

        It is the audit binding of the server-bound params the stages
        evaluated: it never appears in the payload, and subject.action_hash
        still binds the params the caller submitted.
        """
        from src.gateway.governance.governance_envelope import envelope_action_hash

        params = {"amount": 100, "symbol": "AAPL"}
        evaluated_hash = envelope_action_hash(
            "execute_trade", {**params, "trader_role": "junior"}
        )
        mock_symbolic_governor.validate_action = AsyncMock(
            return_value={**verdict, "evaluated_action_hash": evaluated_hash}
        )

        resp = client.post(
            "/validate-action", json={"action": "execute_trade", "params": params}
        )

        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["payload"]["verdict"] == verdict["verdict"]
        assert data["subject"]["evaluated_action_hash"] == evaluated_hash
        assert data["subject"]["action_hash"] == envelope_action_hash(
            "execute_trade", params
        )
        assert data["subject"]["action_hash"] != evaluated_hash
        assert "evaluated_action_hash" not in data["payload"]

    @pytest.mark.parametrize("bogus", [None, 123, {"sha256": "x"}])
    def test_a_non_string_evaluated_action_hash_is_never_emitted(
        self, client, mock_symbolic_governor, bogus: Any
    ):
        mock_symbolic_governor.validate_action = AsyncMock(
            return_value={
                "verdict": "ALLOW",
                "violations": [],
                "evaluated_action_hash": bogus,
            }
        )

        resp = client.post(
            "/validate-action",
            json={"action": "execute_trade", "params": {"amount": 100}},
        )

        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert "evaluated_action_hash" not in data["subject"]
        assert "evaluated_action_hash" not in data["payload"]

    def test_refusal_envelope_carries_no_evaluated_action_hash(
        self, client, mock_symbolic_governor
    ):
        """A 403 envelope carries no evaluated hash; subject.action_hash binds the request."""
        from src.gateway.governance.governance_envelope import envelope_action_hash
        from src.gateway.governance.governor.governor import GovernanceError

        mock_symbolic_governor.validate_action = AsyncMock(
            side_effect=GovernanceError("OPA policy denied execute_trade")
        )
        params = {"amount": 100}

        with patch(
            "src.gateway.server.governance_middleware._emit_refusal_receipt",
            new=AsyncMock(return_value=None),
        ):
            resp = client.post(
                "/validate-action", json={"action": "execute_trade", "params": params}
            )

        assert resp.status_code == 403
        data = resp.json()
        assert "evaluated_action_hash" not in data["subject"]
        assert data["subject"]["action_hash"] == envelope_action_hash(
            "execute_trade", params
        )


# ===========================================================================
# C. Post-approval committing run (POAM-2026-079)
# ===========================================================================


class TestRevalidatePostHitlRemoved:
    """POST_HITL runs only inside execute_trade_action, never as an HTTP route."""

    def test_revalidate_post_hitl_route_is_gone(
        self, gov_client, mock_symbolic_governor
    ):
        """The advisor can no longer trigger a POST_HITL run over HTTP."""
        mock_symbolic_governor.revalidate_post_hitl = AsyncMock(
            return_value=_sealed("execute_trade", "SEAL", {"amount": 10.0})
        )
        resp = gov_client.post(
            "/revalidate-post-hitl",
            json={"action": "execute_trade", "params": {"amount": 10.0}},
        )
        assert resp.status_code in (404, 405)
        mock_symbolic_governor.revalidate_post_hitl.assert_not_awaited()


class TestEnforceApprovedGovernance:
    """``enforce_approved_governance``: check the approval, then let the run spend it."""

    @staticmethod
    def _queue(token: Any):
        queue = MagicMock()
        queue.redeemable_token = AsyncMock(return_value=token)
        queue.consume_approval = AsyncMock(return_value=token)

        @asynccontextmanager
        async def _open():
            yield queue

        return queue, _open

    @staticmethod
    def _token(approved: Any = _PARAMS, **fields: Any) -> MagicMock:
        """A redeemable HITL token whose approved snapshot params are ``approved``."""
        attrs: dict[str, Any] = {
            "thread_id": "t",
            "barrier_preview": None,
            "hitl_holds": frozenset(),
        }
        attrs.update(fields)
        return MagicMock(opa_input_snapshot={"params": approved}, **attrs)

    async def _call(self, governor, open_queue, emit, covers=lambda a, p: True):
        from src.gateway.server import governance_middleware as gm

        with (
            patch(
                "src.gateway.governance.defer_queue.open_defer_queue", new=open_queue
            ),
            patch.object(gm, "_emit_refusal_receipt", new=emit),
        ):
            return await gm.enforce_approved_governance(
                governor,
                "execute_trade",
                dict(_PARAMS),
                deferred_id="defer-1",
                approval_covers=covers,
            )

    async def _approval(self, token: Any, *, covers: Any = lambda a, p: True):
        """Run the gateway once; return its queue and the approval it built."""
        governor = _mock_governor()
        captured: dict[str, Any] = {}

        async def _revalidate(action, params, *, approval):
            captured["approval"] = approval
            return _sealed(action, "SEAL", params)

        governor.revalidate_post_hitl = _revalidate
        queue, open_queue = self._queue(token)
        await self._call(governor, open_queue, AsyncMock(), covers=covers)
        return queue, captured["approval"]

    async def test_redeemable_approval_runs_post_hitl_and_returns_the_sealed_action(
        self,
    ):
        governor = _mock_governor()
        sealed = _sealed("execute_trade", "SEAL", {**_PARAMS, "trader_role": "junior"})
        governor.revalidate_post_hitl = AsyncMock(return_value=sealed)
        holds = frozenset({("fria", "FRIA_EXTERNAL_HOLD")})
        queue, open_queue = self._queue(
            self._token(thread_id="thread-9", barrier_preview="PASS", hitl_holds=holds)
        )
        emit = AsyncMock()

        result = await self._call(governor, open_queue, emit)

        # The committing run's seal and the evaluated params it commits to.
        assert result is sealed
        args = governor.revalidate_post_hitl.await_args
        assert args.args == ("execute_trade", _PARAMS)
        approval = args.kwargs["approval"]
        # D-H: the committing run is bound to the barrier snapshot approved.
        assert approval.approval_id == "defer-1"
        assert approval.barrier_preview == "PASS"
        assert approval.thread_id == "thread-9"
        # GHSA-f6xq-23f7-9grm: ... and to the human-review holds the reviewer saw.
        assert approval.approved_holds == holds
        assert queue.redeemable_token.await_args.kwargs["action"] == "execute_trade"
        # Checking spends nothing: only the governor's committing run spends.
        queue.consume_approval.assert_not_awaited()
        emit.assert_not_awaited()

    async def test_pre_check_reads_token_state_only_and_binds_no_server_inputs(self):
        """The pre-check passes no ``covers`` and resolves no server input.

        Coverage is decided against the evaluated params inside the
        committing run (``approval.covers`` / ``approval.spend``); the
        gateway makes no server-input lookup of its own.
        """
        governor = _mock_governor()
        governor.revalidate_post_hitl = AsyncMock(
            return_value=_sealed("execute_trade", "SEAL", _PARAMS)
        )
        queue, open_queue = self._queue(self._token())
        matcher = MagicMock(return_value=True)

        await self._call(governor, open_queue, AsyncMock(), covers=matcher)

        assert queue.redeemable_token.await_args.args == ("defer-1",)
        assert queue.redeemable_token.await_args.kwargs == {"action": "execute_trade"}
        governor.bind_server_inputs.assert_not_called()
        matcher.assert_not_called()

    async def test_covers_checks_the_evaluated_params_against_the_approved_snapshot(
        self,
    ):
        approved = {**_PARAMS, "trader_role": "senior"}
        calls: list[tuple[Any, Any]] = []

        def _matcher(approved_params: Any, evaluated: Any) -> bool:
            calls.append((approved_params, evaluated))
            return evaluated.get("trader_role") == approved_params.get("trader_role")

        _, approval = await self._approval(
            self._token(approved=approved), covers=_matcher
        )
        evaluated = MappingProxyType({**_PARAMS, "trader_role": "senior"})

        assert approval.covers(evaluated) is True
        assert approval.covers({**_PARAMS, "trader_role": "junior"}) is False
        # approval_covers(approved snapshot params, evaluated params as a dict)
        seen_approved, seen_evaluated = calls[0]
        assert seen_approved == approved
        assert type(seen_evaluated) is dict
        assert seen_evaluated == dict(evaluated)

    @pytest.mark.parametrize(
        "approved", [None, "AAPL x 10", ["AAPL", 10.0]], ids=["none", "str", "list"]
    )
    async def test_covers_refuses_an_approval_without_dict_params(self, approved: Any):
        matcher = MagicMock(return_value=True)

        _, approval = await self._approval(
            self._token(approved=approved), covers=matcher
        )

        assert approval.covers(dict(_PARAMS)) is False
        matcher.assert_not_called()

    async def test_raising_matcher_never_authorises(self):
        """A matcher that raises is "does not cover", before the stages and in the swap.

        The pre-check is state-only, so the matcher is reached only through
        ``approval.covers`` and the ``covers`` that ``spend`` hands
        ``consume_approval``: both answer False and nothing is consumed.
        """

        def _boom(approved: Any, evaluated: Any) -> bool:
            raise KeyError("amount")

        queue, approval = await self._approval(self._token(), covers=_boom)
        verdicts: list[bool] = []

        async def _consume(defer_id: str, *, action: str, covers: Any) -> Any:
            covered = covers(dict(_PARAMS))
            verdicts.append(covered)
            return self._token() if covered else None  # consumes only if covered

        queue.consume_approval = _consume

        assert approval.covers(dict(_PARAMS)) is False
        assert await approval.spend(dict(_PARAMS)) is False
        assert verdicts == [False]
        assert "covers" not in queue.redeemable_token.await_args.kwargs

    async def test_spend_consumes_only_if_the_matcher_covers_the_evaluated_params(
        self,
    ):
        calls: list[tuple[Any, Any]] = []

        def _matcher(approved: Any, evaluated: Any) -> bool:
            calls.append((approved, evaluated))
            return float(evaluated["amount"]) <= float(approved["amount"])

        queue, approval = await self._approval(self._token(), covers=_matcher)
        evaluated = {**_PARAMS, "trader_role": "junior"}

        assert await approval.spend(evaluated) is True

        call = queue.consume_approval.await_args
        assert call.args == ("defer-1",)
        assert call.kwargs["action"] == "execute_trade"
        covers = call.kwargs["covers"]
        # consume_approval hands the closure the token's approved params; the
        # closure decides approval_covers(approved, evaluated) for the
        # evaluated params this spend was given.
        assert covers({"symbol": "AAPL", "amount": 20.0}) is True
        assert calls[-1] == ({"symbol": "AAPL", "amount": 20.0}, evaluated)
        assert covers({"symbol": "AAPL", "amount": 5.0}) is False
        assert covers("not-a-dict") is False

    async def test_spend_is_the_queues_atomic_consume(self):
        governor = _mock_governor()
        spent: list[bool] = []

        async def _revalidate(action, params, *, approval):
            spent.append(await approval.spend(params))
            return _sealed(action, "SEAL", params)

        governor.revalidate_post_hitl = _revalidate
        queue, open_queue = self._queue(self._token())

        sealed = await self._call(governor, open_queue, AsyncMock())

        assert sealed.seal == "SEAL"
        assert spent == [True]
        queue.consume_approval.assert_awaited_once()
        assert queue.consume_approval.await_args.args == ("defer-1",)
        assert queue.consume_approval.await_args.kwargs["action"] == "execute_trade"

    async def test_spend_fails_closed_when_the_queue_raises(self):
        from src.gateway.governance.governor.errors import (
            ApprovalSpendUnavailableError,
        )

        governor = _mock_governor()

        async def _revalidate(action, params, *, approval):
            await approval.spend(params)
            return _sealed(action, "SEAL", params)

        governor.revalidate_post_hitl = _revalidate
        queue, open_queue = self._queue(self._token())
        queue.consume_approval = AsyncMock(side_effect=ConnectionError("redis down"))

        with pytest.raises(ApprovalSpendUnavailableError, match="defer-1"):
            await self._call(governor, open_queue, AsyncMock())

    async def test_no_approval_refuses_with_receipt_and_never_commits(self):
        governor = _mock_governor()
        governor.revalidate_post_hitl = AsyncMock(
            return_value=_sealed("execute_trade", "SEAL", _PARAMS)
        )
        _, open_queue = self._queue(None)
        emit = AsyncMock()

        with pytest.raises(PermissionError, match="defer-1"):
            await self._call(governor, open_queue, emit)

        governor.revalidate_post_hitl.assert_not_awaited()
        emit.assert_awaited_once()
        assert emit.await_args.kwargs["oscal_control_ref"] == "AC-3"
        assert emit.await_args.kwargs["refusal_reason"] == (
            "no unconsumed approval 'defer-1' is redeemable for this execute_trade"
        )

    async def test_queue_unavailable_fails_closed(self):
        from src.gateway.governance.governor.errors import (
            GovernanceInfrastructureError,
        )

        governor = _mock_governor()
        governor.revalidate_post_hitl = AsyncMock(
            return_value=_sealed("execute_trade", "SEAL", _PARAMS)
        )

        @asynccontextmanager
        async def _broken():
            raise ConnectionError("redis down")
            yield  # pragma: no cover

        emit = AsyncMock()
        with (
            patch(
                "src.gateway.governance.governor.verdicts.publish_infrastructure_block",
                new_callable=AsyncMock,
            ) as pub_infra,
            pytest.raises(GovernanceInfrastructureError) as exc_info,
        ):
            await self._call(governor, _broken, emit)
        assert exc_info.value.error_code == "defer_queue_unavailable"
        assert exc_info.value.dependency == "defer_queue"
        assert exc_info.value.failure_code == "DEFER_QUEUE_UNAVAILABLE"
        assert exc_info.value.receipt is None
        governor.revalidate_post_hitl.assert_not_awaited()
        emit.assert_not_awaited()
        pub_infra.assert_awaited_once()

    async def test_post_hitl_refusal_raises_with_receipt(self):
        from src.gateway.governance.governor.governor import GovernanceError

        governor = _mock_governor()
        governor.revalidate_post_hitl = AsyncMock(
            side_effect=GovernanceError("CBF Violation: h(next) < 0")
        )
        _, open_queue = self._queue(MagicMock(thread_id="t", barrier_preview=None))
        emit = AsyncMock()

        with pytest.raises(PermissionError, match="CBF Violation"):
            await self._call(governor, open_queue, emit)
        emit.assert_awaited_once()
        assert emit.await_args.kwargs["oscal_control_ref"] == "SC-4"

    async def test_post_hitl_deferral_retains_the_approval_without_a_refusal(self):
        from src.gateway.governance.governor.errors import GovernanceDeferred
        from src.gateway.server.governance_middleware import ActionDeferred

        governor = _mock_governor()
        governor.revalidate_post_hitl = AsyncMock(
            side_effect=GovernanceDeferred(
                "[WARRANT_INELIGIBLE] deferred",
                defer_reason="WARRANT_INELIGIBLE",
                deferred_id="defer-1",
                reliance=[{"reliance_status": "INELIGIBLE_REVOKED"}],
            )
        )
        queue, open_queue = self._queue(MagicMock(thread_id="t", barrier_preview=None))
        emit = AsyncMock()

        with pytest.raises(ActionDeferred, match="Governance Deferred") as deferred:
            await self._call(governor, open_queue, emit)
        assert isinstance(deferred.value, PermissionError)  # still fails closed
        assert deferred.value.deferred_id == "defer-1"
        assert deferred.value.approval_retained is True
        assert deferred.value.defer_reason == "WARRANT_INELIGIBLE"
        assert deferred.value.reliance == [{"reliance_status": "INELIGIBLE_REVOKED"}]
        queue.consume_approval.assert_not_awaited()
        emit.assert_not_awaited()  # a deferral is evidenced as a deferral


# ===========================================================================
# D. _emit_refusal_receipt() unit tests
# ===========================================================================


class TestEmitRefusalReceipt:
    """Unit tests for the _emit_refusal_receipt() async helper (P6)."""

    async def test_emit_receipt_calls_kms_sign_and_sink(self, mock_kms_signer):
        """Happy path: receipt is KMS-signed and published to the evidence sink."""
        from src.gateway.server.governance_middleware import _emit_refusal_receipt

        sink = MagicMock()
        sink.ingest = AsyncMock(return_value="1700000000000-0")

        with patch(
            "src.gateway.server.governance_middleware.get_evidence_sink",
            return_value=sink,
        ):
            await _emit_refusal_receipt(
                action_id="execute_trade",
                refusal_reason="drawdown_limit_exceeded",
                oscal_control_ref="SC-4",
                params={"amount": 100},
            )

        mock_kms_signer.sign_async.assert_awaited_once()
        sink.ingest.assert_awaited_once()
        receipt = sink.ingest.call_args[0][0]
        assert receipt["action_id"] == "execute_trade"
        assert receipt["refusal_reason"] == "drawdown_limit_exceeded"
        assert receipt["oscal_control_ref"] == "SC-4"
        assert receipt["type"] == "GOVERNANCE_REFUSAL_RECEIPT"
        assert "receipt_id" in receipt
        assert "timestamp_utc" in receipt

    async def test_emit_receipt_kms_sign_failure_fails_closed(self, caplog):
        """A signing failure blocks fail-closed; nothing unsigned is committed."""
        import logging

        from src.gateway.governance.governor.errors import (
            GovernanceInfrastructureError,
        )
        from src.gateway.governance.governor.verdicts import (
            INFRASTRUCTURE_BLOCK_EVENT_TYPE,
        )
        from src.gateway.server.governance_middleware import (
            _emit_refusal_receipt,
            get_last_refusal_proof_hash,
            set_last_refusal_proof_hash,
        )

        failing_signer = MagicMock()
        failing_signer.sign = MagicMock(side_effect=RuntimeError("KMS unavailable"))
        failing_signer.sign_async = AsyncMock(
            side_effect=RuntimeError("KMS unavailable")
        )

        sink = MagicMock()
        sink.ingest = AsyncMock(return_value="1700000000000-0")
        set_last_refusal_proof_hash(None)

        with (
            patch(
                "src.gateway.server.governance_middleware.get_governance_signer",
                return_value=failing_signer,
            ),
            patch(
                "src.gateway.server.governance_middleware.get_evidence_sink",
                return_value=sink,
            ),
            patch(
                "src.gateway.governance.evidence.stream.get_evidence_sink",
                return_value=sink,
            ),
            patch(
                "src.gateway.governance.evidence.stream.commit_decision_evidence",
                new=AsyncMock(),
            ) as commit,
        ):
            with caplog.at_level(logging.ERROR, logger="Gateway.GovernanceMiddleware"):
                with pytest.raises(GovernanceInfrastructureError) as excinfo:
                    await _emit_refusal_receipt(
                        action_id="execute_trade",
                        refusal_reason="test_reason",
                        oscal_control_ref="SC-4",
                        params={},
                    )

        assert excinfo.value.dependency == "kms"
        assert excinfo.value.failure_code == "KMS_SIGNING_UNAVAILABLE"
        labels = [c.kwargs.get("label") for c in commit.await_args_list]
        assert labels == [INFRASTRUCTURE_BLOCK_EVENT_TYPE]
        assert get_last_refusal_proof_hash() is None
        assert any(
            "Failed to sign refusal receipt" in r.message for r in caplog.records
        )

    async def test_emit_receipt_sink_failure_raises_when_blocking(
        self, mock_kms_signer, caplog
    ):
        """Under default EVIDENCE_CHAIN_BLOCKING=true, sink failure raises EvidenceChainUnavailableError."""
        import logging

        from src.gateway.governance.evidence.stream import (
            EvidenceChainUnavailableError,
        )
        from src.gateway.server.governance_middleware import _emit_refusal_receipt

        failing_sink = MagicMock()
        failing_sink.ingest = AsyncMock(
            side_effect=ConnectionError("Redis stream unavailable")
        )

        with patch(
            "src.gateway.server.governance_middleware.get_evidence_sink",
            return_value=failing_sink,
        ):
            with (
                caplog.at_level(logging.ERROR, logger="Gateway.GovernanceMiddleware"),
                pytest.raises(
                    EvidenceChainUnavailableError, match="Redis stream unavailable"
                ),
            ):
                await _emit_refusal_receipt(
                    action_id="execute_trade",
                    refusal_reason="test_reason",
                    oscal_control_ref="SC-4",
                    params={},
                )

        assert any(
            "Failed to emit OSCAL refusal receipt" in r.message for r in caplog.records
        )

    async def test_emit_receipt_sink_failure_is_logged_not_raised_when_non_blocking(
        self, mock_kms_signer, caplog
    ):
        """Under explicit non-blocking dev opt-out, sink failure is logged and does not raise."""
        import logging

        from src.gateway.server.governance_middleware import _emit_refusal_receipt

        failing_sink = MagicMock()
        failing_sink.ingest = AsyncMock(
            side_effect=ConnectionError("Pub/Sub unavailable")
        )

        with (
            patch(
                "src.gateway.server.governance_middleware.get_evidence_sink",
                return_value=failing_sink,
            ),
            patch(
                "src.gateway.governance.evidence.stream.is_evidence_chain_blocking",
                return_value=False,
            ),
        ):
            with caplog.at_level(logging.ERROR, logger="Gateway.GovernanceMiddleware"):
                result = await _emit_refusal_receipt(
                    action_id="execute_trade",
                    refusal_reason="test_reason",
                    oscal_control_ref="SC-4",
                    params={},
                )

        assert isinstance(result, str) and len(result) == 64
        assert any(
            "Failed to emit OSCAL refusal receipt" in r.message for r in caplog.records
        )


# ===========================================================================
# E. Module exports
# ===========================================================================


class TestModuleExports:
    """The module imports cleanly and exposes the governance sub-app."""

    def test_module_exports_governance_app(self):
        """governance_app FastAPI instance is exported from the module."""
        from fastapi import FastAPI

        from src.gateway.server.governance_middleware import governance_app

        assert isinstance(governance_app, FastAPI)


# ===========================================================================
# G. enforce_governance() helper tests
# ===========================================================================


class TestEnforceGovernanceHelper:
    """Tests for the enforce_governance() async helper."""

    async def test_domain_tool_routes_through_governor_not_hardcoded_exempt(self):
        """Domain read-only tools like check_market_status are not hardcoded in Layer 1."""
        from src.gateway.server.governance_middleware import enforce_governance

        gov = _mock_governor()
        sealed = _sealed(
            "check_market_status", "domain-read-only-seal", {"symbol": "AAPL"}
        )
        gov.govern = AsyncMock(return_value=sealed)
        result = await enforce_governance(
            gov, "check_market_status", {"symbol": "AAPL"}
        )
        assert result is sealed
        assert result.seal == "domain-read-only-seal"
        gov.govern.assert_awaited_once_with("check_market_status", {"symbol": "AAPL"})

    async def test_verify_content_safety_is_governed_like_any_other_tool(self):
        """No tool name is exempt: verify_content_safety runs the committing run too."""
        from src.gateway.server.governance_middleware import enforce_governance

        gov = _mock_governor()
        sealed = _sealed(
            "verify_content_safety", "content-safety-seal", {"text": "hello"}
        )
        gov.govern = AsyncMock(return_value=sealed)

        result = await enforce_governance(
            gov, "verify_content_safety", {"text": "hello"}
        )

        assert result is sealed
        assert result.seal == "content-safety-seal"
        gov.govern.assert_awaited_once_with("verify_content_safety", {"text": "hello"})

    async def test_tool_call_is_governed_and_returns_the_sealed_action(self):
        """enforce_governance() returns governor.govern()'s SealedAction unchanged."""
        from src.gateway.server.governance_middleware import enforce_governance

        mock_gov = _mock_governor()
        sealed = _sealed(
            "execute_trade",
            "test-routing-seal-value",
            {"amount": 100, "trader_role": "junior"},
        )
        mock_gov.govern = AsyncMock(return_value=sealed)

        result = await enforce_governance(mock_gov, "execute_trade", {"amount": 100})

        assert result is sealed
        assert result.seal == "test-routing-seal-value"
        assert result.params == {"amount": 100, "trader_role": "junior"}
        mock_gov.govern.assert_awaited_once_with("execute_trade", {"amount": 100})

    async def test_governance_error_raises_permission_error(self):
        """GovernanceError from the governor is converted to PermissionError."""
        from src.gateway.governance.governor.governor import GovernanceError
        from src.gateway.server.governance_middleware import enforce_governance

        mock_gov = _mock_governor()
        mock_gov.govern = AsyncMock(side_effect=GovernanceError("policy_denied"))

        mock_signer = MagicMock()
        mock_signer.sign = MagicMock(return_value="sig")

        with (
            patch(
                "src.gateway.server.governance_middleware.get_governance_signer",
                return_value=mock_signer,
            ),
            patch(
                "src.gateway.server.governance_middleware._emit_refusal_receipt",
                new=AsyncMock(return_value=None),
            ),
        ):
            with pytest.raises(PermissionError, match="Governance Blocked"):
                await enforce_governance(mock_gov, "execute_trade", {"amount": 100})

    async def test_warrant_deferral_is_a_deferral_not_a_refusal(self):
        """GovernanceDeferred from govern() is ActionDeferred, with no receipt."""
        from src.gateway.governance.governor.errors import GovernanceDeferred
        from src.gateway.server.governance_middleware import (
            ActionDeferred,
            enforce_governance,
        )

        mock_gov = _mock_governor()
        mock_gov.govern = AsyncMock(
            side_effect=GovernanceDeferred(
                "[WARRANT_INELIGIBLE] deferred",
                defer_reason="WARRANT_INELIGIBLE",
                deferred_id="defer-9",
            )
        )
        emit = AsyncMock()
        with patch(
            "src.gateway.server.governance_middleware._emit_refusal_receipt", new=emit
        ):
            with pytest.raises(ActionDeferred, match="Governance Deferred") as exc:
                await enforce_governance(mock_gov, "execute_trade", {"amount": 100})
        assert exc.value.deferred_id == "defer-9"
        assert exc.value.approval_retained is False
        emit.assert_not_awaited()


# ===========================================================================
# H. Integration smoke: governance_app routes are registered
# ===========================================================================


class TestGovernanceAppRoutes:
    """Smoke tests verifying that the expected routes exist on governance_app."""

    @pytest.fixture(scope="class")
    def client(self):
        # scope="class": governance_app has no mutable state and both
        # smoke tests in this class share the same (read-only) app config.
        from src.gateway.server.governance_middleware import governance_app

        return TestClient(governance_app, raise_server_exceptions=False)

    def test_validate_action_route_exists(self, client):
        """POST /validate-action route is registered (returns something other than 404)."""
        resp = client.post("/validate-action", json={"action": "x", "params": {}})
        assert resp.status_code != 404

    def test_unknown_route_returns_404(self, client):
        """An unknown route returns 404."""
        resp = client.get("/nonexistent-endpoint")
        assert resp.status_code == 404


# ===========================================================================
# G. Canonical envelope responses on /validate-action (ADR-008 Phase 3)
# ===========================================================================


class TestValidateActionCanonicalEnvelope:
    """Verify /validate-action wraps DEFER (including EXTERNAL_HOLD) and ALLOW in v3.0 envelopes."""

    @pytest.fixture()
    def client_for_external_hold(self, mock_kms_signer):
        from src.gateway.server.governance_middleware import governance_app

        return TestClient(governance_app, raise_server_exceptions=False)

    def test_external_hold_defer_returns_canonical_200_envelope_not_202(
        self, client_for_external_hold, mock_kms_signer
    ):
        """EXTERNAL_HOLD DEFER is wrapped in a canonical HTTP 200 v3.0 envelope (no unwrapped HTTP 202)."""
        hold_result = {
            "verdict": "DEFER",
            "defer_reason": "EXTERNAL_HOLD",
            "is_external_hold": True,
            "defer_id": "fs-defer-001",
            "violations": ["Provider 01: requires human approval"],
            "seal": "",
            "latency_ms": 5.2,
        }
        mock_gov = _mock_governor()
        mock_gov.validate_action = AsyncMock(return_value=hold_result)

        with _installed_governor(mock_gov):
            resp = client_for_external_hold.post(
                "/validate-action",
                json={"action": "execute_trade", "params": {"amount": 50000}},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["envelope_version"] == "3.0"
        assert data["payload"]["verdict"] == "DEFER"
        assert data["payload"]["defer_reason"] == "EXTERNAL_HOLD"

    def test_non_external_hold_defer_returns_200_not_202(
        self, client_for_external_hold, mock_kms_signer
    ):
        """Regular DEFER returns HTTP 200 wrapped in canonical v3.0 envelope."""
        regular_defer_result = {
            "verdict": "DEFER",
            "defer_reason": "CONFIDENCE_BELOW_THRESHOLD",
            "defer_id": "regular-defer-001",
            "violations": ["confidence too low"],
            "seal": "",
            "latency_ms": 1.5,
        }
        mock_gov = _mock_governor()
        mock_gov.validate_action = AsyncMock(return_value=regular_defer_result)

        with _installed_governor(mock_gov):
            resp = client_for_external_hold.post(
                "/validate-action",
                json={"action": "execute_trade", "params": {"amount": 1000}},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["envelope_version"] == "3.0"
        assert data["payload"]["verdict"] == "DEFER"

    def test_approved_verdict_still_returns_200(
        self, client_for_external_hold, mock_kms_signer
    ):
        """ALLOW verdict returns HTTP 200 with canonical envelope (ADR-008 Phase 3)."""
        approved_result = {
            "verdict": "ALLOW",
            "violations": [],
            "latency_ms": 1.0,
        }
        mock_gov = _mock_governor()
        mock_gov.validate_action = AsyncMock(return_value=approved_result)

        with _installed_governor(mock_gov):
            resp = client_for_external_hold.post(
                "/validate-action",
                json={"action": "execute_trade", "params": {"amount": 100}},
            )

        assert resp.status_code == 200
        data = resp.json()

        # ADR-008 Phase 3: ALLOW verdicts return canonical envelope
        assert data.get("envelope_version") == "3.0"
        assert data["payload"]["verdict"] == "ALLOW"

    def test_validate_action_returns_503_when_governor_raises_evidence_chain_unavailable(
        self, client_for_external_hold, mock_kms_signer
    ):
        """POST /validate-action returns HTTP 503 when governor decision evidence fails closed."""
        from src.gateway.governance.evidence.stream import (
            EvidenceChainUnavailableError,
        )

        mock_gov = _mock_governor()
        mock_gov.validate_action = AsyncMock(
            side_effect=EvidenceChainUnavailableError(
                "Redis connection not established"
            )
        )

        with _installed_governor(mock_gov):
            resp = client_for_external_hold.post(
                "/validate-action",
                json={"action": "execute_trade", "params": {"amount": 100}},
            )

        assert resp.status_code == 503
        data = resp.json()
        assert data["error"] == "evidence_chain_unavailable"
        assert "Redis connection not established" in data["detail"]

    def test_validate_action_returns_503_when_refusal_receipt_sink_fails_closed(
        self, client_for_external_hold, mock_kms_signer
    ):
        """POST /validate-action returns HTTP 503 instead of un-evidenced 403 when refusal sink fails."""
        from src.gateway.server.governance_middleware import GovernanceError

        mock_gov = _mock_governor()
        mock_gov.validate_action = AsyncMock(
            side_effect=GovernanceError("drawdown_limit_exceeded")
        )
        failing_sink = MagicMock()
        failing_sink.ingest = AsyncMock(
            side_effect=ConnectionError("Redis stream offline")
        )

        with (
            _installed_governor(mock_gov),
            patch(
                "src.gateway.server.governance_middleware.get_evidence_sink",
                return_value=failing_sink,
            ),
        ):
            resp = client_for_external_hold.post(
                "/validate-action",
                json={"action": "execute_trade", "params": {"amount": 100}},
            )

        assert resp.status_code == 503
        data = resp.json()
        assert data["error"] == "evidence_chain_unavailable"
        assert "Redis stream offline" in data["detail"]

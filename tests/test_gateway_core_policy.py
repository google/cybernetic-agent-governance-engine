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

"""Unit tests for src/gateway/core/policy.py.

All tests are marked pytest.mark.local — no live OPA, Redis, or network
connections required.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

# ---------------------------------------------------------------------------
# Import the module under test
# ---------------------------------------------------------------------------
import src.gateway.core.policy as policy_mod
from src.gateway.core.policy import (
    BreakerState,
    CallOutcome,
    CircuitBreaker,
    OPAClient,
    OPAPolicyMismatchError,
)


class _Clock:
    """Manually advanced monotonic clock."""

    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _breaker(clock: _Clock, **kwargs: float) -> CircuitBreaker:
    params: dict = {"failure_threshold": 3, "recovery_timeout": 30.0}
    params.update(kwargs)
    return CircuitBreaker(clock=clock, **params)


def _fail(cb: CircuitBreaker, times: int = 1) -> None:
    for _ in range(times):
        ticket = cb.admit()
        assert ticket is not None
        cb.record(ticket, CallOutcome.UPSTREAM_FAILURE)


def _open(cb: CircuitBreaker) -> None:
    _fail(cb, cb.failure_threshold)
    assert cb.state is BreakerState.OPEN


# ===========================================================================
# TestCircuitBreaker
# ===========================================================================


@pytest.mark.local
class TestCircuitBreaker:
    """CircuitBreaker state machine: CLOSED → OPEN → HALF_OPEN → CLOSED/OPEN."""

    def test_starts_closed_and_admits(self) -> None:
        cb = _breaker(_Clock())
        assert cb.state is BreakerState.CLOSED
        assert cb.failures == 0
        ticket = cb.admit()
        assert ticket is not None and not ticket.probe

    def test_opens_at_the_threshold_within_the_window(self) -> None:
        cb = _breaker(_Clock())
        _fail(cb, 2)
        assert cb.state is BreakerState.CLOSED
        _fail(cb)
        assert cb.state is BreakerState.OPEN
        assert cb.admit() is None

    def test_failures_outside_the_window_expire(self) -> None:
        clock = _Clock()
        cb = _breaker(clock, failure_window_s=10.0)
        _fail(cb, 2)
        clock.advance(10.0)
        assert cb.failures == 0
        _fail(cb, 2)
        assert cb.state is BreakerState.CLOSED

    def test_healthy_and_inconclusive_outcomes_never_count(self) -> None:
        cb = _breaker(_Clock())
        for outcome in [CallOutcome.HEALTHY, CallOutcome.INCONCLUSIVE] * 5:
            ticket = cb.admit()
            assert ticket is not None
            cb.record(ticket, outcome)
        assert cb.state is BreakerState.CLOSED
        assert cb.failures == 0

    def test_stays_open_until_the_recovery_timeout(self) -> None:
        clock = _Clock()
        cb = _breaker(clock, recovery_timeout=30.0)
        _open(cb)
        clock.advance(29.9)
        assert cb.admit() is None
        assert cb.state is BreakerState.OPEN

    def test_admits_exactly_one_probe_after_the_timeout(self) -> None:
        clock = _Clock()
        cb = _breaker(clock)
        _open(cb)
        clock.advance(30.0)

        probe = cb.admit()
        assert probe is not None and probe.probe
        assert cb.state is BreakerState.HALF_OPEN
        assert cb.admit() is None  # a second caller fails fast

    def test_healthy_probe_closes_and_clears_failures(self) -> None:
        clock = _Clock()
        cb = _breaker(clock)
        _open(cb)
        clock.advance(30.0)
        probe = cb.admit()
        assert probe is not None

        cb.record(probe, CallOutcome.HEALTHY)

        assert cb.state is BreakerState.CLOSED
        assert cb.failures == 0
        assert cb.admit() is not None

    def test_failed_probe_reopens_for_a_full_timeout(self) -> None:
        clock = _Clock()
        cb = _breaker(clock)
        _open(cb)
        clock.advance(30.0)
        probe = cb.admit()
        assert probe is not None

        cb.record(probe, CallOutcome.UPSTREAM_FAILURE)

        assert cb.state is BreakerState.OPEN
        clock.advance(29.9)
        assert cb.admit() is None
        clock.advance(0.1)
        assert cb.admit() is not None

    def test_inconclusive_probe_frees_the_slot(self) -> None:
        clock = _Clock()
        cb = _breaker(clock)
        _open(cb)
        clock.advance(30.0)
        probe = cb.admit()
        assert probe is not None

        cb.record(probe, CallOutcome.INCONCLUSIVE)

        assert cb.state is BreakerState.HALF_OPEN
        next_probe = cb.admit()
        assert next_probe is not None and next_probe.probe

    def test_late_failures_from_before_opening_do_not_reopen(self) -> None:
        """A call admitted while CLOSED that fails during HALF_OPEN is not the probe."""
        clock = _Clock()
        cb = _breaker(clock)
        straggler = cb.admit()
        assert straggler is not None
        _open(cb)
        clock.advance(30.0)
        probe = cb.admit()
        assert probe is not None

        cb.record(straggler, CallOutcome.UPSTREAM_FAILURE)
        assert cb.state is BreakerState.HALF_OPEN
        cb.record(probe, CallOutcome.HEALTHY)
        assert cb.state is BreakerState.CLOSED

    def test_is_bankrupt_when_over_budget(self) -> None:
        cb = CircuitBreaker(max_latency_budget=3000)
        assert cb.is_bankrupt(3001.0) is True

    def test_not_bankrupt_when_under_budget(self) -> None:
        cb = CircuitBreaker(max_latency_budget=3000)
        assert cb.is_bankrupt(2999.0) is False

    def test_check_soft_ceiling_above(self) -> None:
        cb = CircuitBreaker()
        assert cb.check_soft_ceiling(2001.0, soft_ceiling_ms=2000.0) is True

    def test_check_soft_ceiling_below(self) -> None:
        cb = CircuitBreaker()
        assert cb.check_soft_ceiling(1999.0, soft_ceiling_ms=2000.0) is False

    def test_check_soft_ceiling_default(self) -> None:
        cb = CircuitBreaker()
        assert cb.check_soft_ceiling(2001.0) is True


# ===========================================================================
# TestOPAClientInit
# ===========================================================================


@pytest.mark.local
class TestOPAClientInit:
    """Tests for OPAClient.__init__ URL resolution logic."""

    def _make_client(self, opa_url: str, auth_token: str = "") -> OPAClient:
        with patch("config.settings.Config") as mock_cfg:
            mock_cfg.OPA_URL = opa_url
            mock_cfg.OPA_AUTH_TOKEN = auth_token
            with patch("src.gateway.core.policy.Config") as policy_cfg:
                policy_cfg.OPA_URL = opa_url
                policy_cfg.OPA_AUTH_TOKEN = auth_token
                return OPAClient()

    def test_target_url_uses_active_domain_package(self) -> None:
        client = self._make_client("http://localhost:8181")
        assert client.package == "trade.governance"
        assert client.target_url == "http://localhost:8181/v1/data/trade/governance"

    def test_trailing_slash_base_url_accepted(self) -> None:
        client = self._make_client("http://localhost:8181/")
        assert client.target_url == "http://localhost:8181/v1/data/trade/governance"

    def test_explicit_package_overrides_domain(self) -> None:
        with patch("src.gateway.core.policy.Config") as mock_cfg:
            mock_cfg.OPA_URL = "http://localhost:8181"
            mock_cfg.OPA_AUTH_TOKEN = ""
            client = OPAClient("dosing.governance")
        assert client.target_url == "http://localhost:8181/v1/data/dosing/governance"

    def test_uds_base_url_resolves_socket(self) -> None:
        client = self._make_client("http+unix://%2Frun%2Fopa.sock")
        assert client.target_url == "http://localhost/v1/data/trade/governance"
        assert client._resolve_endpoint()[1] == "/run/opa.sock"

    @pytest.mark.parametrize(
        "opa_url",
        [
            "http://localhost:8181/v1/data/trade/governance",
            "http://localhost:8181/v1/data/dosing/governance",
            "http+unix://%2Frun%2Fopa.sock/v1/data/trade/governance",
            "http://localhost:8181?x=1",
            "ftp://localhost:8181",
            "",
            None,
        ],
    )
    def test_non_base_or_missing_opa_url_fails_closed(self, opa_url) -> None:
        """A path in OPA_URL could point the kernel at another domain's policy."""
        client = self._make_client(
            opa_url
        )  # construction never raises (import-time singleton)
        with pytest.raises(RuntimeError, match="FAIL-CLOSED"):
            _ = client.target_url
        with pytest.raises(RuntimeError, match="FAIL-CLOSED"):
            client._get_client()

    @pytest.mark.asyncio
    async def test_evaluate_policy_denies_when_opa_url_has_path(self) -> None:
        client = self._make_client("http://localhost:8181/v1/data/trade/governance")
        assert await client.evaluate_policy({"action": "trade"}) == "DENY"

    def test_circuit_breaker_initialised(self) -> None:
        with patch("src.gateway.core.policy.Config") as mock_cfg:
            mock_cfg.OPA_URL = "http://localhost:8181"
            mock_cfg.OPA_AUTH_TOKEN = ""
            client = OPAClient()
        assert isinstance(client.cb, CircuitBreaker)

    def test_http_client_initially_none(self) -> None:
        with patch("src.gateway.core.policy.Config") as mock_cfg:
            mock_cfg.OPA_URL = "http://localhost:8181"
            mock_cfg.OPA_AUTH_TOKEN = ""
            client = OPAClient()
        assert client._http_client is None


# ===========================================================================
# TestOPAClientGetClient
# ===========================================================================


@pytest.mark.local
class TestOPAClientGetClient:
    """Tests for OPAClient._get_client() lazy initialisation."""

    def _make_client(self) -> OPAClient:
        with patch("src.gateway.core.policy.Config") as mock_cfg:
            mock_cfg.OPA_URL = "http://localhost:8181"
            mock_cfg.OPA_AUTH_TOKEN = ""
            return OPAClient()

    def test_creates_client_on_first_call(self) -> None:
        client = self._make_client()
        http_client = client._get_client()
        assert http_client is not None

    def test_returns_same_instance_on_second_call(self) -> None:
        client = self._make_client()
        c1 = client._get_client()
        c2 = client._get_client()
        assert c1 is c2

    def test_recreates_client_when_closed(self) -> None:
        client = self._make_client()
        client._get_client()
        # Simulate closed client
        mock_closed = MagicMock()
        mock_closed.is_closed = True
        client._http_client = mock_closed
        c2 = client._get_client()
        # Must be a new instance (not the mock)
        assert c2 is not mock_closed


# ===========================================================================
# TestOPAClientClose
# ===========================================================================


@pytest.mark.local
class TestOPAClientClose:
    """Tests for OPAClient.close()."""

    @pytest.mark.asyncio
    async def test_close_calls_aclose_on_client(self) -> None:
        with patch("src.gateway.core.policy.Config") as mock_cfg:
            mock_cfg.OPA_URL = "http://localhost:8181"
            mock_cfg.OPA_AUTH_TOKEN = ""
            client = OPAClient()

        mock_http = AsyncMock()
        mock_http.is_closed = False
        client._http_client = mock_http

        await client.close()
        mock_http.aclose.assert_awaited_once()
        assert client._http_client is None

    @pytest.mark.asyncio
    async def test_close_noop_when_client_already_closed(self) -> None:
        with patch("src.gateway.core.policy.Config") as mock_cfg:
            mock_cfg.OPA_URL = "http://localhost:8181"
            mock_cfg.OPA_AUTH_TOKEN = ""
            client = OPAClient()

        mock_http = AsyncMock()
        mock_http.is_closed = True
        client._http_client = mock_http

        await client.close()
        mock_http.aclose.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_close_noop_when_http_client_is_none(self) -> None:
        with patch("src.gateway.core.policy.Config") as mock_cfg:
            mock_cfg.OPA_URL = "http://localhost:8181"
            mock_cfg.OPA_AUTH_TOKEN = ""
            client = OPAClient()

        client._http_client = None
        # Must not raise
        await client.close()


# ===========================================================================
# TestOPAClientCheckPolicyExists
# ===========================================================================


def _module(package: str, *rules: str, ref_style: bool = False) -> dict:
    """Minimal OPA /v1/policies module with a parsed AST."""
    path = [{"type": "var", "value": "data"}] + [
        {"type": "string", "value": part} for part in package.split(".")
    ]
    heads = [
        {"ref": [{"type": "var", "value": r}]} if ref_style else {"name": r}
        for r in rules
    ]
    return {
        "id": f"{package}.rego",
        "ast": {"package": {"path": path}, "rules": [{"head": h} for h in heads]},
    }


@pytest.mark.local
class TestOPAClientVerifyDomainPolicy:
    """OPAClient.verify_domain_policy() — startup package/rule handshake."""

    def _client_returning(
        self,
        payload=None,
        *,
        status: int = 200,
        exc: Exception | None = None,
        token: str = "",
    ):
        with patch("src.gateway.core.policy.Config") as mock_cfg:
            mock_cfg.OPA_URL = "http://localhost:8181"
            mock_cfg.OPA_AUTH_TOKEN = token
            client = OPAClient()
        response = MagicMock()
        response.status_code = status
        response.json = MagicMock(return_value=payload)
        if status >= 400:
            response.raise_for_status = MagicMock(
                side_effect=httpx.HTTPStatusError(
                    "err", request=MagicMock(), response=response
                )
            )
        else:
            response.raise_for_status = MagicMock()
        mock_http = AsyncMock()
        mock_http.get = (
            AsyncMock(side_effect=exc) if exc else AsyncMock(return_value=response)
        )
        return client, mock_http

    @pytest.mark.asyncio
    async def test_passes_when_package_and_rules_loaded(self) -> None:
        client, http = self._client_returning(
            {"result": [_module("trade.governance", "allow", "allowed_roles")]}
        )
        with patch.object(client, "_get_client", return_value=http):
            await client.verify_domain_policy("trade.governance", ("allow",))
        assert http.get.call_args[0][0] == "http://localhost:8181/v1/policies"

    @pytest.mark.asyncio
    async def test_opa_1x_ref_style_heads_recognised(self) -> None:
        client, http = self._client_returning(
            {"result": [_module("trade.governance", "allow", ref_style=True)]}
        )
        with patch.object(client, "_get_client", return_value=http):
            await client.verify_domain_policy("trade.governance", ("allow",))

    @pytest.mark.asyncio
    async def test_rules_unioned_across_modules_of_one_package(self) -> None:
        payload = {
            "result": [
                _module("trade.governance", "allow"),
                _module("trade.governance", "reasons"),
            ]
        }
        client, http = self._client_returning(payload)
        with patch.object(client, "_get_client", return_value=http):
            await client.verify_domain_policy("trade.governance", ("allow", "reasons"))

    @pytest.mark.asyncio
    async def test_other_domains_package_only_fails_closed(self) -> None:
        """Healthcare policy loaded, finance domain active → refuse."""
        client, http = self._client_returning(
            {"result": [_module("dosing.governance", "allow")]}
        )
        with patch.object(client, "_get_client", return_value=http):
            with pytest.raises(
                OPAPolicyMismatchError,
                match="no module declaring package 'trade.governance'",
            ):
                await client.verify_domain_policy("trade.governance", ("allow",))

    @pytest.mark.asyncio
    async def test_prefix_package_does_not_match(self) -> None:
        client, http = self._client_returning(
            {
                "result": [
                    _module("trade", "allow"),
                    _module("trade.governance.v2", "allow"),
                ]
            }
        )
        with patch.object(client, "_get_client", return_value=http):
            with pytest.raises(
                OPAPolicyMismatchError, match="no module declaring package"
            ):
                await client.verify_domain_policy("trade.governance", ("allow",))

    @pytest.mark.asyncio
    async def test_missing_required_rule_fails_closed(self) -> None:
        client, http = self._client_returning(
            {"result": [_module("trade.governance", "allowed_roles")]}
        )
        with patch.object(client, "_get_client", return_value=http):
            with pytest.raises(
                OPAPolicyMismatchError, match=r"lacks required rules \['allow'\]"
            ):
                await client.verify_domain_policy("trade.governance", ("allow",))

    @pytest.mark.asyncio
    async def test_unreachable_opa_fails_closed(self) -> None:
        client, http = self._client_returning(exc=httpx.ConnectError("refused"))
        with patch.object(client, "_get_client", return_value=http):
            with pytest.raises(OPAPolicyMismatchError, match="cannot verify"):
                await client.verify_domain_policy("trade.governance", ("allow",))

    @pytest.mark.asyncio
    async def test_non_2xx_fails_closed(self) -> None:
        client, http = self._client_returning({"code": "unauthorized"}, status=401)
        with patch.object(client, "_get_client", return_value=http):
            with pytest.raises(OPAPolicyMismatchError, match="cannot verify"):
                await client.verify_domain_policy("trade.governance", ("allow",))

    @pytest.mark.parametrize(
        "payload", [{}, {"result": None}, {"result": ["not-a-module"]}, []]
    )
    @pytest.mark.asyncio
    async def test_malformed_payload_fails_closed(self, payload) -> None:
        client, http = self._client_returning(payload)
        with patch.object(client, "_get_client", return_value=http):
            with pytest.raises(OPAPolicyMismatchError, match="cannot verify"):
                await client.verify_domain_policy("trade.governance", ("allow",))

    @pytest.mark.asyncio
    async def test_misconfigured_opa_url_fails_closed(self) -> None:
        with patch("src.gateway.core.policy.Config") as mock_cfg:
            mock_cfg.OPA_URL = "http://localhost:8181/v1/data/trade/governance"
            mock_cfg.OPA_AUTH_TOKEN = ""
            client = OPAClient()
        with pytest.raises(OPAPolicyMismatchError, match="OPA_URL must be a base URL"):
            await client.verify_domain_policy("trade.governance", ("allow",))

    @pytest.mark.asyncio
    async def test_auth_header_included_when_token_set(self) -> None:
        client, http = self._client_returning(
            {"result": [_module("trade.governance", "allow")]}, token="my-secret-token"
        )
        with patch.object(client, "_get_client", return_value=http):
            await client.verify_domain_policy("trade.governance", ("allow",))
        assert (
            http.get.call_args[1]["headers"]["Authorization"]
            == "Bearer my-secret-token"
        )


# ===========================================================================
# TestOPAClientEvaluatePolicy
# ===========================================================================


def _response(
    status: int = 200, payload: object = None, *, json_error: bool = False
) -> MagicMock:
    response = MagicMock()
    response.status_code = status
    if json_error:
        response.json = MagicMock(side_effect=ValueError("not json"))
    else:
        response.json = MagicMock(
            return_value={"result": "ALLOW"} if payload is None else payload
        )
    return response


@pytest.mark.local
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ({"allow": True}, "ALLOW"),
        ({"allow": False}, "DENY"),
        ({"decision": "manual_review"}, "MANUAL_REVIEW"),
        ({}, "DENY"),
        (True, "ALLOW"),
        (False, "DENY"),
        ("allow", "ALLOW"),
        (None, "DENY"),
    ],
)
def test_decision_string_normalizes_result_shapes(raw: object, expected: str) -> None:
    assert policy_mod._decision_string(raw) == expected


@pytest.mark.local
class TestOPAClientEvaluatePolicy:
    """Tests for OPAClient.evaluate_policy()."""

    def _make_opa_client(self, opa_url: str = "http://localhost:8181") -> OPAClient:
        with patch("src.gateway.core.policy.Config") as mock_cfg:
            mock_cfg.OPA_URL = opa_url
            mock_cfg.OPA_AUTH_TOKEN = ""
            return OPAClient()

    def _half_open_client(self) -> OPAClient:
        """A client whose breaker has just reached its recovery timeout."""
        clock = _Clock()
        client = self._make_opa_client()
        client.cb = CircuitBreaker(clock=clock)
        _open(client.cb)
        clock.advance(client.cb.recovery_timeout)
        return client

    @staticmethod
    def _http(*, response: MagicMock | None = None, exc: Exception | None = None):
        mock_http = AsyncMock()
        mock_http.post = (
            AsyncMock(side_effect=exc) if exc else AsyncMock(return_value=response)
        )
        return mock_http

    @staticmethod
    async def _evaluate(client: OPAClient, http: AsyncMock, **kwargs: float) -> str:
        with patch.object(client, "_get_client", return_value=http):
            return await client.evaluate_policy({"action": "trade"}, **kwargs)

    @pytest.mark.asyncio
    async def test_successful_opa_response_returns_result(self) -> None:
        client = self._make_opa_client()
        http = self._http(response=_response(payload={"result": "ALLOW"}))
        assert await self._evaluate(client, http) == "ALLOW"

    @pytest.mark.asyncio
    async def test_every_call_queries_opa(self) -> None:
        """Decisions are never cached: identical inputs each reach OPA."""
        client = self._make_opa_client()
        http = self._http(response=_response())
        for _ in range(3):
            assert await self._evaluate(client, http) == "ALLOW"
        assert http.post.await_count == 3

    @pytest.mark.asyncio
    async def test_missing_result_key_defaults_to_deny(self) -> None:
        client = self._make_opa_client()
        http = self._http(response=_response(payload={}))
        assert await self._evaluate(client, http) == "DENY"

    @pytest.mark.asyncio
    async def test_malformed_body_denies_without_charging_the_breaker(self) -> None:
        client = self._make_opa_client()
        for response in (_response(json_error=True), _response(payload=["a", "b"])):
            assert await self._evaluate(client, self._http(response=response)) == "DENY"
        assert client.cb.failures == 0

    @pytest.mark.parametrize(
        "exc",
        [
            httpx.ConnectError("refused"),
            httpx.ReadTimeout("slow"),
            httpx.RemoteProtocolError("reset"),
        ],
    )
    @pytest.mark.asyncio
    async def test_transport_failures_deny_and_count(self, exc: Exception) -> None:
        client = self._make_opa_client()
        assert await self._evaluate(client, self._http(exc=exc)) == "DENY"
        assert client.cb.failures == 1

    @pytest.mark.asyncio
    async def test_5xx_denies_and_counts(self) -> None:
        client = self._make_opa_client()
        http = self._http(response=_response(503))
        assert await self._evaluate(client, http) == "DENY"
        assert client.cb.failures == 1

    @pytest.mark.asyncio
    async def test_4xx_denies_without_counting(self) -> None:
        client = self._make_opa_client()
        http = self._http(response=_response(404))
        assert await self._evaluate(client, http) == "DENY"
        assert client.cb.failures == 0

    @pytest.mark.asyncio
    async def test_pool_timeout_denies_without_tripping_the_breaker(self) -> None:
        client = self._make_opa_client()
        saturated = self._http(exc=httpx.PoolTimeout("pool full"))
        for _ in range(client.cb.failure_threshold + 1):
            assert await self._evaluate(client, saturated) == "DENY"
        assert client.cb.failures == 0
        assert client.cb.state is BreakerState.CLOSED

    @pytest.mark.asyncio
    async def test_misconfigured_url_denies_without_counting(self) -> None:
        client = self._make_opa_client("http://localhost:8181/v1/data/trade/governance")
        assert await client.evaluate_policy({"action": "trade"}) == "DENY"
        assert client.cb.failures == 0

    @pytest.mark.asyncio
    async def test_upstream_failures_open_the_circuit_and_fail_fast(self) -> None:
        client = self._make_opa_client()
        failing = self._http(exc=httpx.ConnectError("refused"))
        for _ in range(client.cb.failure_threshold):
            await self._evaluate(client, failing)
        assert client.cb.state is BreakerState.OPEN

        healthy = self._http(response=_response())
        assert await self._evaluate(client, healthy) == "DENY"
        healthy.post.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_healthy_probe_closes_the_circuit(self) -> None:
        client = self._half_open_client()
        assert await self._evaluate(client, self._http(response=_response())) == "ALLOW"
        assert client.cb.state is BreakerState.CLOSED

    @pytest.mark.asyncio
    async def test_only_the_probe_reaches_opa_while_half_open(self) -> None:
        client = self._half_open_client()
        started, release = asyncio.Event(), asyncio.Event()

        async def slow_post(*args: object, **kwargs: object) -> MagicMock:
            started.set()
            await release.wait()
            return _response()

        http = AsyncMock()
        http.post = AsyncMock(side_effect=slow_post)
        with patch.object(client, "_get_client", return_value=http):
            probe = asyncio.create_task(client.evaluate_policy({"action": "trade"}))
            await started.wait()
            others = await asyncio.gather(
                *(client.evaluate_policy({"action": "trade"}) for _ in range(3))
            )
            release.set()
            assert await probe == "ALLOW"

        assert others == ["DENY"] * 3
        assert http.post.await_count == 1
        assert client.cb.state is BreakerState.CLOSED

    @pytest.mark.asyncio
    async def test_cancelled_probe_frees_the_slot(self) -> None:
        client = self._half_open_client()
        started = asyncio.Event()

        async def hang(*args: object, **kwargs: object) -> MagicMock:
            started.set()
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

        http = AsyncMock()
        http.post = AsyncMock(side_effect=hang)
        with patch.object(client, "_get_client", return_value=http):
            probe = asyncio.create_task(client.evaluate_policy({"action": "trade"}))
            await started.wait()
            probe.cancel()
            with pytest.raises(asyncio.CancelledError):
                await probe

        ticket = client.cb.admit()
        assert ticket is not None and ticket.probe

    @pytest.mark.asyncio
    async def test_bankrupt_request_denies_without_claiming_the_probe(self) -> None:
        client = self._half_open_client()
        http = self._http(response=_response())

        assert (
            await self._evaluate(client, http, current_latency_ms=999_999.0) == "DENY"
        )
        http.post.assert_not_awaited()
        assert await self._evaluate(client, http) == "ALLOW"

    @pytest.mark.asyncio
    async def test_explain_logging_enqueues_when_enabled(self) -> None:
        client = self._make_opa_client()
        http = self._http(response=_response())
        with patch.object(policy_mod, "CAGE_OPA_EXPLAIN_LOGGING", True):
            q_size_before = policy_mod._explain_queue.qsize()
            await self._evaluate(client, http)
            assert policy_mod._explain_queue.qsize() == q_size_before + 1
            # Clean up
            policy_mod._explain_queue.get_nowait()

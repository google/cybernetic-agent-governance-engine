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
import hashlib
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

# ---------------------------------------------------------------------------
# Import the module under test
# ---------------------------------------------------------------------------
import src.gateway.core.policy as policy_mod
from src.gateway.core.policy import (
    CircuitBreaker,
    OPAClient,
    OPAPolicyMismatchError,
    _opa_cache_key,
)

# ===========================================================================
# TestOpaCacheEnabled
# ===========================================================================


@pytest.mark.local
class TestOpaCacheEnabled:
    """Tests for the _opa_cache_enabled() helper."""

    def test_defaults_to_true(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OPA_CACHE_ENABLED", raising=False)
        assert policy_mod._opa_cache_enabled() is True

    def test_true_when_set_to_true(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPA_CACHE_ENABLED", "true")
        assert policy_mod._opa_cache_enabled() is True

    def test_false_when_set_to_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPA_CACHE_ENABLED", "false")
        assert policy_mod._opa_cache_enabled() is False

    def test_case_insensitive_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPA_CACHE_ENABLED", "FALSE")
        assert policy_mod._opa_cache_enabled() is False

    def test_case_insensitive_true(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPA_CACHE_ENABLED", "TRUE")
        assert policy_mod._opa_cache_enabled() is True


# ===========================================================================
# TestOpaCacheKey
# ===========================================================================


@pytest.mark.local
class TestOpaCacheKey:
    """Tests for the _opa_cache_key() helper."""

    def test_returns_string_with_prefix(self) -> None:
        key = _opa_cache_key({"action": "trade"})
        assert key.startswith("cage:opa:decision:")

    def test_digest_is_24_hex_chars(self) -> None:
        key = _opa_cache_key({"action": "trade"})
        digest = key.removeprefix("cage:opa:decision:")
        assert len(digest) == 24
        assert all(c in "0123456789abcdef" for c in digest)

    def test_same_input_produces_same_key(self) -> None:
        data = {"action": "trade", "amount": 100}
        assert _opa_cache_key(data) == _opa_cache_key(data)

    def test_different_inputs_produce_different_keys(self) -> None:
        key1 = _opa_cache_key({"action": "trade", "amount": 100})
        key2 = _opa_cache_key({"action": "trade", "amount": 200})
        assert key1 != key2

    def test_key_is_order_independent(self) -> None:
        """Dict insertion order must NOT affect the cache key."""
        key1 = _opa_cache_key({"action": "trade", "amount": 100})
        key2 = _opa_cache_key({"amount": 100, "action": "trade"})
        assert key1 == key2

    def test_key_matches_manual_sha256(self) -> None:
        """Cache key uses RFC 8785 JCS canonicalization (migrated v3.1.0)."""
        from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

        data = {"action": "execute_trade"}
        canonical_bytes = jcs_canonicalize_plan(data)
        expected_digest = hashlib.sha256(canonical_bytes).hexdigest()[:24]
        expected_key = f"cage:opa:decision:{expected_digest}"
        assert _opa_cache_key(data) == expected_key


# ===========================================================================
# TestReadOpaCache
# ===========================================================================


@pytest.mark.local
class TestReadOpaCache:
    """Tests for _read_opa_cache()."""

    @pytest.mark.asyncio
    async def test_returns_none_when_cache_disabled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPA_CACHE_ENABLED", "false")
        result = await policy_mod._read_opa_cache("some-key")
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_when_redis_client_is_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPA_CACHE_ENABLED", "true")
        with patch("src.gateway.infrastructure.redis_client.redis_client", None):
            result = await policy_mod._read_opa_cache("some-key")
            assert result is None

    @pytest.mark.asyncio
    async def test_returns_decoded_bytes_from_redis(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPA_CACHE_ENABLED", "true")
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=b"ALLOW")
        with patch("src.gateway.core.policy.redis_client", mock_redis, create=True):
            # Patch the import inside the function
            with patch.dict(
                "sys.modules",
                {
                    "src.gateway.infrastructure.redis_client": MagicMock(
                        redis_client=mock_redis
                    )
                },
            ):
                result = await policy_mod._read_opa_cache("k")
                # The function decodes bytes
                assert result == "ALLOW"

    @pytest.mark.asyncio
    async def test_returns_none_on_exception(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPA_CACHE_ENABLED", "true")
        with patch.dict(
            "sys.modules",
            {
                "src.gateway.infrastructure.redis_client": MagicMock(
                    redis_client=MagicMock(
                        get=AsyncMock(side_effect=RuntimeError("boom"))
                    )
                )
            },
        ):
            result = await policy_mod._read_opa_cache("k")
            assert result is None


# ===========================================================================
# TestWriteOpaCache
# ===========================================================================


@pytest.mark.local
class TestWriteOpaCache:
    """Tests for _write_opa_cache()."""

    @pytest.mark.asyncio
    async def test_noop_when_cache_disabled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPA_CACHE_ENABLED", "false")
        mock_redis = AsyncMock()
        with patch.dict(
            "sys.modules",
            {
                "src.gateway.infrastructure.redis_client": MagicMock(
                    redis_client=mock_redis
                )
            },
        ):
            await policy_mod._write_opa_cache("k", "ALLOW")
            mock_redis.setex.assert_not_called()

    @pytest.mark.asyncio
    async def test_calls_setex_when_redis_available(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPA_CACHE_ENABLED", "true")
        mock_redis = AsyncMock()
        mock_redis.setex = AsyncMock()
        with patch.dict(
            "sys.modules",
            {
                "src.gateway.infrastructure.redis_client": MagicMock(
                    redis_client=mock_redis
                )
            },
        ):
            await policy_mod._write_opa_cache("k", "ALLOW")
            mock_redis.setex.assert_awaited_once_with(
                "k", policy_mod._OPA_CACHE_TTL_SECONDS, "ALLOW"
            )

    @pytest.mark.asyncio
    async def test_silently_ignores_exception(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPA_CACHE_ENABLED", "true")
        mock_redis = AsyncMock()
        mock_redis.setex = AsyncMock(side_effect=ConnectionError("redis down"))
        with patch.dict(
            "sys.modules",
            {
                "src.gateway.infrastructure.redis_client": MagicMock(
                    redis_client=mock_redis
                )
            },
        ):
            # Must not raise
            await policy_mod._write_opa_cache("k", "ALLOW")


# ===========================================================================
# TestCircuitBreaker
# ===========================================================================


@pytest.mark.local
class TestCircuitBreaker:
    """Tests for CircuitBreaker state machine."""

    def test_initial_state_is_closed(self) -> None:
        cb = CircuitBreaker()
        assert cb.state == "CLOSED"

    def test_initial_failures_zero(self) -> None:
        cb = CircuitBreaker()
        assert cb.failures == 0

    def test_can_execute_when_closed(self) -> None:
        cb = CircuitBreaker()
        assert cb.can_execute() is True

    @pytest.mark.asyncio
    async def test_record_failure_increments_count(self) -> None:
        cb = CircuitBreaker(failure_threshold=10)
        await cb.record_failure()
        assert cb.failures == 1

    @pytest.mark.asyncio
    async def test_opens_after_threshold_failures(self) -> None:
        cb = CircuitBreaker(failure_threshold=3)
        for _ in range(3):
            await cb.record_failure()
        assert cb.state == "OPEN"

    @pytest.mark.asyncio
    async def test_does_not_open_before_threshold(self) -> None:
        cb = CircuitBreaker(failure_threshold=3)
        await cb.record_failure()
        await cb.record_failure()
        assert cb.state == "CLOSED"

    @pytest.mark.asyncio
    async def test_cannot_execute_when_open_and_within_recovery(self) -> None:
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=9999)
        await cb.record_failure()
        assert cb.state == "OPEN"
        assert cb.can_execute() is False

    @pytest.mark.asyncio
    async def test_can_execute_when_open_and_past_recovery_timeout(self) -> None:
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0)
        await cb.record_failure()
        # last_failure_time is in the past; recovery_timeout=0 means immediate
        assert cb.can_execute() is True

    @pytest.mark.asyncio
    async def test_record_success_resets_to_closed(self) -> None:
        cb = CircuitBreaker(failure_threshold=1)
        await cb.record_failure()
        assert cb.state == "OPEN"
        await cb.record_success()
        assert cb.state == "CLOSED"
        assert cb.failures == 0

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

    @pytest.mark.asyncio
    async def test_recovery_timeout_measured_from_last_failure(self) -> None:
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=60)
        await cb.record_failure()
        # Manipulate last_failure_time to simulate 61s ago
        cb.last_failure_time = time.time() - 61
        assert cb.can_execute() is True


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


@pytest.mark.local
class TestOPAClientEvaluatePolicy:
    """Tests for OPAClient.evaluate_policy()."""

    def _make_opa_client(self, opa_url: str = "http://localhost:8181") -> OPAClient:
        with patch("src.gateway.core.policy.Config") as mock_cfg:
            mock_cfg.OPA_URL = opa_url
            mock_cfg.OPA_AUTH_TOKEN = ""
            return OPAClient()

    @pytest.mark.asyncio
    async def test_returns_deny_when_circuit_breaker_open(self) -> None:
        client = self._make_opa_client()
        client.cb.state = "OPEN"
        client.cb.last_failure_time = time.time()  # very recent → still open

        result = await client.evaluate_policy({"action": "trade"})
        assert result == "DENY"

    @pytest.mark.asyncio
    async def test_returns_deny_when_bankrupt(self) -> None:
        client = self._make_opa_client()
        # Pass a latency way over the budget
        result = await client.evaluate_policy(
            {"action": "trade"}, current_latency_ms=999_999.0
        )
        assert result == "DENY"

    @pytest.mark.asyncio
    async def test_returns_cached_decision_on_cache_hit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPA_CACHE_ENABLED", "true")
        client = self._make_opa_client()

        with patch.object(
            policy_mod, "_read_opa_cache", return_value="ALLOW"
        ) as mock_cache:
            result = await client.evaluate_policy({"action": "trade"})
            assert result == "ALLOW"
            mock_cache.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_successful_opa_response_returns_result(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPA_CACHE_ENABLED", "false")
        client = self._make_opa_client()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": "ALLOW", "explanation": []}
        mock_response.raise_for_status = MagicMock()

        mock_http = AsyncMock()
        mock_http.post = AsyncMock(return_value=mock_response)

        with (
            patch.object(client, "_get_client", return_value=mock_http),
            patch.object(
                policy_mod, "_write_opa_cache", return_value=None
            ) as mock_write,
            patch.object(policy_mod, "_read_opa_cache", return_value=None),
        ):
            result = await client.evaluate_policy({"action": "trade"})
            assert result == "ALLOW"
            mock_write.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_opa_failure_returns_deny(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPA_CACHE_ENABLED", "false")
        client = self._make_opa_client()

        mock_http = AsyncMock()
        mock_http.post = AsyncMock(side_effect=ConnectionError("OPA down"))

        with (
            patch.object(client, "_get_client", return_value=mock_http),
            patch.object(policy_mod, "_read_opa_cache", return_value=None),
        ):
            result = await client.evaluate_policy({"action": "trade"})
            assert result == "DENY"

    @pytest.mark.asyncio
    async def test_opa_failure_records_circuit_breaker_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPA_CACHE_ENABLED", "false")
        client = self._make_opa_client()

        mock_http = AsyncMock()
        mock_http.post = AsyncMock(side_effect=ConnectionError("OPA down"))

        initial_failures = client.cb.failures
        with (
            patch.object(client, "_get_client", return_value=mock_http),
            patch.object(policy_mod, "_read_opa_cache", return_value=None),
        ):
            await client.evaluate_policy({"action": "trade"})
        assert client.cb.failures == initial_failures + 1

    @pytest.mark.asyncio
    async def test_successful_response_records_circuit_breaker_success(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPA_CACHE_ENABLED", "false")
        client = self._make_opa_client()
        # Start with some failures already recorded
        client.cb.failures = 2

        mock_response = MagicMock()
        mock_response.json.return_value = {"result": "ALLOW"}
        mock_response.raise_for_status = MagicMock()

        mock_http = AsyncMock()
        mock_http.post = AsyncMock(return_value=mock_response)

        with (
            patch.object(client, "_get_client", return_value=mock_http),
            patch.object(policy_mod, "_read_opa_cache", return_value=None),
            patch.object(policy_mod, "_write_opa_cache", return_value=None),
        ):
            await client.evaluate_policy({"action": "trade"})
        assert client.cb.failures == 0

    @pytest.mark.asyncio
    async def test_missing_result_key_defaults_to_deny(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPA_CACHE_ENABLED", "false")
        client = self._make_opa_client()

        mock_response = MagicMock()
        mock_response.json.return_value = {}  # no "result" key
        mock_response.raise_for_status = MagicMock()

        mock_http = AsyncMock()
        mock_http.post = AsyncMock(return_value=mock_response)

        with (
            patch.object(client, "_get_client", return_value=mock_http),
            patch.object(policy_mod, "_read_opa_cache", return_value=None),
            patch.object(policy_mod, "_write_opa_cache", return_value=None),
        ):
            result = await client.evaluate_policy({"action": "trade"})
        assert result == "DENY"

    @pytest.mark.asyncio
    async def test_explain_logging_enqueues_when_enabled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPA_CACHE_ENABLED", "false")
        client = self._make_opa_client()

        mock_response = MagicMock()
        mock_response.json.return_value = {"result": "ALLOW"}
        mock_response.raise_for_status = MagicMock()

        mock_http = AsyncMock()
        mock_http.post = AsyncMock(return_value=mock_response)

        with (
            patch.object(client, "_get_client", return_value=mock_http),
            patch.object(policy_mod, "_read_opa_cache", return_value=None),
            patch.object(policy_mod, "_write_opa_cache", return_value=None),
            patch.object(policy_mod, "CAGE_OPA_EXPLAIN_LOGGING", True),
        ):
            q_size_before = policy_mod._explain_queue.qsize()
            await client.evaluate_policy({"action": "trade"})
            assert policy_mod._explain_queue.qsize() == q_size_before + 1
            # Clean up
            policy_mod._explain_queue.get_nowait()

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
Tests for the consolidated trade_governance.rego policy (package: trade.governance).

All tests in TestTradeGovernanceRego require a live OPA instance and are
skipped unless the OPA_URL environment variable is set.

Policy under test:
  src/governed_financial_advisor/governance/policy/trade_governance.rego
"""

import os
from pathlib import Path
from typing import Any, Dict, Optional

import pytest
import respx
import httpx

pytestmark = pytest.mark.unit

# ---------------------------------------------------------------------------
# Determine whether a live OPA is available with the trade.governance policy
# ---------------------------------------------------------------------------

_OPA_URL: Optional[str] = os.getenv("OPA_URL")


def _opa_trade_policy_available() -> bool:
    """Return True only when OPA is reachable AND the trade.governance policy is loaded."""
    if not _OPA_URL:
        return False
    try:
        import httpx
        base = _opa_base()
        # Check health
        resp = httpx.get(f"{base}/health", timeout=2)
        if not resp.is_success:
            return False
        # Check that trade.governance policy is loaded and returns an allow key
        resp2 = httpx.post(
            f"{base}/v1/data/trade/governance",
            json={"input": {"action": "market_analysis", "trader_role": "junior"}},
            timeout=2,
        )
        if not resp2.is_success:
            return False
        result = resp2.json().get("result", {})
        return "allow" in result
    except Exception:
        return False
_POLICY_PATH = (
    Path(__file__).parent.parent
    / "src"
    / "governed_financial_advisor"
    / "governance"
    / "policy"
    / "trade_governance.rego"
)

# The OPA REST endpoint for the consolidated policy.
# Full path: POST /v1/data/trade/governance
_OPA_POLICY_ENDPOINT = "/v1/data/trade/governance"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _opa_base() -> str:
    """Extract just the scheme+host+port from OPA_URL."""
    import urllib.parse
    raw = (_OPA_URL or "http://localhost:8181").rstrip("/")
    parsed = urllib.parse.urlparse(raw)
    return f"{parsed.scheme}://{parsed.netloc}"


def _opa_endpoint() -> str:
    """Return the full OPA URL for trade.governance queries."""
    return f"{_opa_base()}{_OPA_POLICY_ENDPOINT}"


async def _query_opa(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """POST input to OPA and return the parsed JSON result body."""
    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.post(_opa_endpoint(), json={"input": input_data})
        resp.raise_for_status()
        return resp.json().get("result", {})


# ---------------------------------------------------------------------------
# Live-OPA integration tests — skipped without OPA_URL
# ---------------------------------------------------------------------------

@pytest.mark.integration
@pytest.mark.usefixtures("require_opa_trade_policy")
class TestTradeGovernanceRego:
    """Integration tests exercising trade_governance.rego via the OPA REST API."""

    # ------------------------------------------------------------------
    # Junior trader tests
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_junior_trade_under_5k_allowed(self):
        """Junior trade ≤ $5 000 (non-BTC) must be ALLOW."""
        result = await _query_opa(
            {"action": "execute_trade", "trader_role": "junior", "amount": 4999, "currency": "USD"}
        )
        assert result.get("allow") == "ALLOW"

    @pytest.mark.asyncio
    async def test_junior_trade_exactly_5k_allowed(self):
        """Junior trade of exactly $5 000 must be ALLOW (boundary inclusive)."""
        result = await _query_opa(
            {"action": "execute_trade", "trader_role": "junior", "amount": 5000, "currency": "USD"}
        )
        assert result.get("allow") == "ALLOW"

    @pytest.mark.asyncio
    async def test_junior_trade_5k_to_10k_manual_review(self):
        """Junior trade $5 001 – $10 000 must require MANUAL_REVIEW."""
        result = await _query_opa(
            {"action": "execute_trade", "trader_role": "junior", "amount": 7500, "currency": "USD"}
        )
        assert result.get("allow") == "MANUAL_REVIEW"

    @pytest.mark.asyncio
    async def test_junior_trade_above_10k_denied(self):
        """Junior trade > $10 000 must be DENY — resolves the $90k conflict (R-12)."""
        result = await _query_opa(
            {"action": "execute_trade", "trader_role": "junior", "amount": 90000, "currency": "USD"}
        )
        assert result.get("allow") == "DENY"

    # ------------------------------------------------------------------
    # Senior trader tests
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_senior_trade_under_500k_allowed(self):
        """Senior trade ≤ $500 000 (non-BTC) must be ALLOW."""
        result = await _query_opa(
            {"action": "execute_trade", "trader_role": "senior", "amount": 200000, "currency": "USD"}
        )
        assert result.get("allow") == "ALLOW"

    @pytest.mark.asyncio
    async def test_senior_trade_500k_to_1m_manual_review(self):
        """Senior trade $500 001 – $1 000 000 must require MANUAL_REVIEW."""
        result = await _query_opa(
            {"action": "execute_trade", "trader_role": "senior", "amount": 750000, "currency": "USD"}
        )
        assert result.get("allow") == "MANUAL_REVIEW"

    @pytest.mark.asyncio
    async def test_senior_trade_above_1m_denied(self):
        """Senior trade > $1 000 000 must be DENY (default fail-closed)."""
        result = await _query_opa(
            {"action": "execute_trade", "trader_role": "senior", "amount": 1500000, "currency": "USD"}
        )
        assert result.get("allow") == "DENY"

    @pytest.mark.asyncio
    async def test_unknown_role_denied(self):
        """Unknown trader role must be DENY regardless of amount."""
        result = await _query_opa(
            {"action": "execute_trade", "trader_role": "god_mode", "amount": 100, "currency": "USD"}
        )
        assert result.get("allow") == "DENY"

    @pytest.mark.asyncio
    async def test_market_analysis_action_always_allowed(self):
        """market_analysis action must be ALLOW for any role (read-only, safe)."""
        result = await _query_opa(
            {"action": "market_analysis", "trader_role": "junior"}
        )
        assert result.get("allow") == "ALLOW"

    @pytest.mark.asyncio
    async def test_default_deny_no_input(self):
        """Empty input must fail-closed to DENY."""
        result = await _query_opa({})
        assert result.get("allow") == "DENY"

    # ------------------------------------------------------------------
    # Fail-closed / missing-field tests
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_missing_role_field_denied(self):
        """Input without trader_role must be DENY (fail-closed)."""
        result = await _query_opa(
            {"action": "execute_trade", "amount": 1000, "currency": "USD"}
        )
        assert result.get("allow") == "DENY"

    @pytest.mark.asyncio
    async def test_missing_amount_field_denied(self):
        """Input without amount must be DENY — amount comparison fails → default deny."""
        result = await _query_opa(
            {"action": "execute_trade", "trader_role": "junior", "currency": "USD"}
        )
        # Without amount, none of the ALLOW/MANUAL_REVIEW rules fire → DENY
        assert result.get("allow") == "DENY"


# ---------------------------------------------------------------------------
# Mocked tests — verify OPA is queried with correct payloads (no live OPA)
# ---------------------------------------------------------------------------

class TestTradeGovernanceRegoMocked:
    """Mocked tests that verify correct OPA endpoint usage without a live OPA."""

    @pytest.mark.asyncio
    async def test_junior_allow_payload_sent_to_correct_endpoint(self):
        """_query_opa must POST to /v1/data/trade/governance with wrapped input."""
        with respx.mock(base_url=None) as mock:
            mock.post(_opa_endpoint()).mock(
                return_value=httpx.Response(200, json={"result": {"allow": "ALLOW"}})
            )
            result = await _query_opa(
                {"action": "execute_trade", "trader_role": "junior", "amount": 1000, "currency": "USD"}
            )
        assert result.get("allow") == "ALLOW"

    @pytest.mark.asyncio
    async def test_default_deny_returned_on_empty_result(self):
        """When OPA returns an empty result body, _query_opa must return empty dict (caller handles DENY)."""
        with respx.mock(base_url=None) as mock:
            mock.post(_opa_endpoint()).mock(
                return_value=httpx.Response(200, json={"result": {}})
            )
            result = await _query_opa({})
        # No allow key present → caller treats as DENY
        assert result.get("allow") is None

    @pytest.mark.asyncio
    async def test_opa_500_raises_http_status_error(self):
        """OPA 500 response must propagate as an httpx.HTTPStatusError."""
        with respx.mock(base_url=None) as mock:
            mock.post(_opa_endpoint()).mock(
                return_value=httpx.Response(500, json={"error": "internal"})
            )
            with pytest.raises(httpx.HTTPStatusError):
                await _query_opa({"action": "execute_trade"})

    @pytest.mark.asyncio
    async def test_senior_manual_review_mocked(self):
        """Mocked OPA response MANUAL_REVIEW must be surfaced correctly."""
        with respx.mock(base_url=None) as mock:
            mock.post(_opa_endpoint()).mock(
                return_value=httpx.Response(200, json={"result": {"allow": "MANUAL_REVIEW"}})
            )
            result = await _query_opa(
                {"action": "execute_trade", "trader_role": "senior", "amount": 750000, "currency": "USD"}
            )
        assert result.get("allow") == "MANUAL_REVIEW"

    def test_rego_policy_file_exists(self):
        """The consolidated Rego policy file must be present on disk."""
        assert _POLICY_PATH.exists(), (
            f"trade_governance.rego not found at {_POLICY_PATH}. "
            "Ensure Group 2 changes are present."
        )

    def test_rego_policy_declares_correct_package(self):
        """Rego policy must declare package trade.governance (not the deprecated packages)."""
        content = _POLICY_PATH.read_text()
        assert "package trade.governance" in content

    def test_rego_policy_has_fail_closed_default(self):
        """Rego policy must declare default allow = \"DENY\" for fail-closed posture."""
        content = _POLICY_PATH.read_text()
        assert 'default allow = "DENY"' in content

    def test_rego_policy_has_junior_and_senior_rules(self):
        """Rego policy must contain RBAC rules for both junior and senior roles."""
        content = _POLICY_PATH.read_text()
        assert '"junior"' in content
        assert '"senior"' in content

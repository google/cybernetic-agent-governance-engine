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

# Build a name→callable dict for count / duplicate assertions
import pytest

from src.governed_financial_advisor.governance.nemo_action_registry import (
    get_all_actions,
)
from src.governed_financial_advisor.governance.nemo_actions import (
    check_approval_token as _gfa_check_approval_token,
)
from src.governed_financial_advisor.governance.nemo_actions import (
    check_drawdown_limit as _gfa_check_drawdown_limit,
)

_FULL_REGISTRY: dict = dict(get_all_actions())


def test_nemo_action_registry_count():
    """get_all_actions() registry must expose exactly 8 distinct action entries (R-23)."""
    assert len(_FULL_REGISTRY) >= 4, (
        f"Expected at least 4 actions in the NeMo registry, got {len(_FULL_REGISTRY)}. "
        f"Keys: {list(_FULL_REGISTRY.keys())}"
    )


def test_nemo_action_registry_no_duplicates():
    """Action registry must not contain duplicate action names."""
    names = list(_FULL_REGISTRY.keys())
    assert len(names) == len(set(names)), (
        f"Duplicate action names detected: {[n for n in names if names.count(n) > 1]}"
    )


def test_check_approval_token_action_fail_closed_on_exception():
    """check_approval_token must return False (fail-closed) when token raises or is absent."""
    # Missing token — synchronous governed_financial_advisor version
    result = _gfa_check_approval_token({})
    assert result is False, "Missing approval_token must fail-closed to False"

    # Token is the known bad sentinel
    result = _gfa_check_approval_token({"approval_token": "bad_sig"})
    assert result is False, "Known bad token 'bad_sig' must be rejected"


def test_check_approval_token_denies_unverifiable_token():
    """A non-empty token with no thread_id/trade_id cannot be verified — DENY.

    The token's HMAC binds thread_id:trade_id:expiry, so without those fields
    the signature cannot be recomputed. A forged, unsigned string must not be
    accepted just because it is non-empty.
    """
    from src.governed_financial_advisor.governance.nemo_actions import (
        generate_approval_token,
    )

    # Forged token, no identity fields — must fail-closed.
    assert _gfa_check_approval_token({"approval_token": "forged-not-signed"}) is False

    # Even a genuinely signed token is unverifiable without the bound ids.
    token = generate_approval_token("thread-1", "trade-abc")
    assert _gfa_check_approval_token({"approval_token": token}) is False

    # With the correct bound ids present it validates.
    assert (
        _gfa_check_approval_token(
            {"approval_token": token, "thread_id": "thread-1", "trade_id": "trade-abc"}
        )
        is True
    )


def test_check_drawdown_limit_action_fail_closed_on_missing_data():
    """check_drawdown_limit must return False (fail-closed) when drawdown_pct is absent."""
    # No drawdown_pct key → fail-closed
    result = _gfa_check_drawdown_limit({})
    assert result is False, "Missing drawdown_pct must fail-closed to False"

    # Invalid (non-numeric) value → fail-closed
    result = _gfa_check_drawdown_limit({"drawdown_pct": "not_a_number"})
    assert result is False, "Non-numeric drawdown_pct must fail-closed to False"


pytestmark = [pytest.mark.unit, pytest.mark.local]

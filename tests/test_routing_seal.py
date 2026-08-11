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
Unit tests — Routing Seal (gateway issuance + GFA verification mirror).

Covers:
- Happy path: generate → verify succeeds
- Expired seal: verify raises SymbolicGovernorViolation
- Tampered sig: verify raises SymbolicGovernorViolation
- Action mismatch: verify raises SymbolicGovernorViolation
- Malformed seal: verify raises SymbolicGovernorViolation
- Canonical payload determinism: dict ordering doesn't affect HMAC
- GFA mirror: uses same HMAC key; verify_seal produces same result as gateway

CRIT-1 fix note: verify_seal() (both gateway and GFA versions) now raises
``SymbolicGovernorViolation`` on any verification failure instead of returning
``False``. This prevents callers from silently ignoring a failed seal check.
"""

import datetime
import os
import time

import pytest
from freezegun import freeze_time

# Set GOVERNANCE_SALT before importing modules under test
os.environ.setdefault("GOVERNANCE_SALT", "TEST_SALT_UNIT_32_CHARACTERS_OK!")

from src.gateway.governance.routing_seal import generate_seal
from src.governed_financial_advisor.utils.routing_seal import (
    SymbolicGovernorViolation,
)
from src.governed_financial_advisor.utils.routing_seal import (
    verify_seal as gfa_verify_seal,
)

PARAMS = {
    "symbol": "AAPL",
    "amount": 10000.0,
    "currency": "USD",
    "confidence": 0.85,
    "trader_role": "junior",
}


class TestRoutingSeal:
    """Gateway issuance + GFA verification."""

    def test_happy_path(self):
        """A freshly generated seal must verify successfully."""
        seal = generate_seal("execute_trade", PARAMS)
        assert gfa_verify_seal(seal, "execute_trade", PARAMS) is True

    def test_expired_seal(self):
        """A seal generated with ttl=0 should be expired immediately."""
        now = time.time()
        seal = generate_seal("execute_trade", PARAMS, ttl_s=0)
        # Advance frozen time 2 s past seal creation so expiry is definitive
        frozen_dt = datetime.datetime.fromtimestamp(now + 2, tz=datetime.timezone.utc)
        with freeze_time(frozen_dt):
            with pytest.raises(SymbolicGovernorViolation):
                gfa_verify_seal(seal, "execute_trade", PARAMS)

    def test_tampered_signature(self):
        """Mutating the HMAC signature component must fail verification."""
        seal = generate_seal("execute_trade", PARAMS)
        parts = seal.split(".")
        # Flip last char of sig
        parts[2] = parts[2][:-1] + ("a" if parts[2][-1] != "a" else "b")
        tampered = ".".join(parts)
        with pytest.raises(SymbolicGovernorViolation):
            gfa_verify_seal(tampered, "execute_trade", PARAMS)

    def test_action_mismatch(self):
        """Verifying with a different action name must fail."""
        seal = generate_seal("execute_trade", PARAMS)
        with pytest.raises(SymbolicGovernorViolation):
            gfa_verify_seal(seal, "cancel_trade", PARAMS)

    def test_param_mismatch(self):
        """Verifying with modified params must fail (HMAC covers payload)."""
        seal = generate_seal("execute_trade", PARAMS)
        bad_params = {**PARAMS, "amount": 99999.0}
        with pytest.raises(SymbolicGovernorViolation):
            gfa_verify_seal(seal, "execute_trade", bad_params)

    def test_malformed_seal_too_few_parts(self):
        """A seal missing a dot segment must raise SymbolicGovernorViolation."""
        with pytest.raises(SymbolicGovernorViolation):
            gfa_verify_seal("abc.def", "execute_trade", PARAMS)

    def test_malformed_seal_empty(self):
        """An empty seal string must raise SymbolicGovernorViolation."""
        with pytest.raises(SymbolicGovernorViolation):
            gfa_verify_seal("", "execute_trade", PARAMS)

    def test_canonical_payload_dict_order_invariant(self):
        """Dict ordering must not affect seal validity (JSON sort_keys=True)."""
        params_a = {"symbol": "AAPL", "amount": 1000.0, "currency": "USD"}
        params_b = {"currency": "USD", "amount": 1000.0, "symbol": "AAPL"}
        seal = generate_seal("execute_trade", params_a)
        assert gfa_verify_seal(seal, "execute_trade", params_b) is True

    def test_action_slug_normalisation(self):
        """Action names with underscores are normalised to dashes in slug."""
        params_a = {"symbol": "AAPL", "amount": 1000.0, "currency": "USD"}
        seal = generate_seal("execute_trade", params_a)
        # Action slug is 'execute-trade' internally — verify must still pass
        assert gfa_verify_seal(seal, "execute_trade", params_a) is True


class TestRoutingSealGatewayMirrorParity:
    """Ensure both modules produce identical HMAC under the same GOVERNANCE_SALT."""

    def test_gfa_verify_accepts_gateway_seal(self):
        """The GFA's verify_seal must accept seals issued by the gateway module."""
        for action in (
            "execute_trade",
            "evaluate_policy",
            "trigger_safety_intervention",
        ):
            seal = generate_seal(action, PARAMS)
            assert gfa_verify_seal(seal, action, PARAMS) is True, (
                f"GFA verify_seal rejected a valid gateway seal for action='{action}'"
            )

    def test_correct_seal_required_before_actuation(self):
        """Simulates the defense-in-depth check in tools/api.py."""
        seal = generate_seal("execute_trade", PARAMS)
        # Correct: verify passes → actuation allowed
        assert gfa_verify_seal(seal, "execute_trade", PARAMS) is True
        # Tampered seal: verify raises → actuation blocked
        tampered = seal[:-4] + "XXXX"
        with pytest.raises(SymbolicGovernorViolation):
            gfa_verify_seal(tampered, "execute_trade", PARAMS)

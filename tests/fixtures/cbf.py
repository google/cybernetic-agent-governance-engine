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

"""Test fixture factories for Control Barrier Function (CBF) instances.

Provides hermetic, offline-first construction of CBF engines with mock Redis,
eliminating ~82 duplicated CBF instantiations across the test suite.

Per W1 (Post-v3 Remediation): All CBF constructions must provide a mandatory
InvariantModel instance. The `make_cbf()` factory provides sensible defaults
while allowing per-test customization.
"""

from typing import Any, Callable
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction


@pytest.fixture
def make_cbf():
    """Factory fixture for ControlBarrierFunction instances with mock Redis.
    
    Returns a factory function that creates hermetic CBF instances with:
    - Mandatory invariant (defaults to CashBarrier())
    - Skipped Redis epoch seeding (offline-first)
    - Optional cost resolver override
    - Mocked Redis client (AsyncMock)
    
    Usage:
        def test_cbf_behavior(make_cbf):
            cbf = make_cbf()  # Default CashBarrier, finance_cost_resolver
            cbf = make_cbf(gamma=0.9)  # Override gamma
            cbf = make_cbf(cost_resolver=lambda a, p: 10.0)  # Custom resolver
    
    The factory returns a tuple (cbf, mock_redis) to allow test-specific
    Redis response mocking.
    """
    
    def _factory(
        invariant: Any | None = None,
        cost_resolver: Callable[[str, dict[str, Any]], float] | None = None,
        skip_epoch_seed: bool = True,
        **invariant_overrides: Any,
    ) -> tuple[ControlBarrierFunction, AsyncMock]:
        """Create a CBF instance with optional parameter overrides.
        
        Args:
            invariant: InvariantModel instance. If None, uses CashBarrier()
                with any overrides from **invariant_overrides.
            cost_resolver: Cost resolution function. Defaults to finance_cost_resolver.
            skip_epoch_seed: Skip Redis epoch fetch at construction. Default True
                for offline testing.
            **invariant_overrides: Keyword args to override CashBarrier defaults
                (e.g., gamma=0.9, state_key="custom:key").
        
        Returns:
            (cbf, mock_redis): The ControlBarrierFunction instance and its mocked
                Redis client. Tests can configure Redis responses via mock_redis.
        """
        from dataclasses import replace
        
        # Default to CashBarrier with optional overrides
        if invariant is None:
            base_invariant = CashBarrier()
            if invariant_overrides:
                invariant = replace(base_invariant, **invariant_overrides)
            else:
                invariant = base_invariant
        
        # Default to finance domain cost resolver
        if cost_resolver is None:
            cost_resolver = finance_cost_resolver
        
        # Construct CBF with mandatory invariant
        cbf = ControlBarrierFunction(
            invariant=invariant,
            cost_resolver=cost_resolver,
            skip_epoch_seed=skip_epoch_seed,
        )
        
        # Mock Redis client for offline testing
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=b"1000.0")  # Default cash balance
        mock_redis.execute_command = AsyncMock(return_value=1)  # WAIT command
        mock_redis.ping = AsyncMock(return_value=True)
        mock_redis.pipeline = MagicMock()
        
        # Inject mock into CBF instance
        cbf._redis_client = mock_redis
        
        return cbf, mock_redis
    
    return _factory

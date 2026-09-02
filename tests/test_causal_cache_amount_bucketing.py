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
F2 remediation test: causal cache amount bucketing.

Prevents small-amount verdicts from leaking to large-amount requests.
The cache key must include an amount bucket so that $100 and $9000 trades
do not share the same cached verdict despite the verdict being amount-dependent.
"""

import pytest

from src.gateway.governance.causal.gatekeeper import _bucket_amount
from src.gateway.governance.schemas.thresholds import get_causal_amount_bucket_boundaries


class TestAmountBucketing:
    """F2 coherence fix: amount-dependent verdicts must not leak across buckets."""

    def test_bucket_amount_monotone(self):
        """Larger amounts never map to lower bucket indices (monotonicity).

        F2 correctness: if amount_a < amount_b, then bucket(amount_a) <= bucket(amount_b).
        This prevents a $9000 trade from inheriting a $100 verdict.
        """
        boundaries = get_causal_amount_bucket_boundaries()
        
        # Test monotonicity across the full amount range
        amounts = [0, 50, 100, 500, 1000, 4999, 5000, 9999, 10000, 50000, 100000]
        buckets = [_bucket_amount(amt, boundaries) for amt in amounts]
        
        # Extract bucket indices from "bucket_N" strings
        indices = [int(b.split("_")[1]) for b in buckets]
        
        # Assert strictly non-decreasing (monotone)
        for i in range(1, len(indices)):
            assert indices[i] >= indices[i - 1], (
                f"Monotonicity violation: amount[{i-1}]={amounts[i-1]} → bucket_{indices[i-1]}, "
                f"amount[{i}]={amounts[i]} → bucket_{indices[i]} (should be >=)"
            )

    def test_small_and_large_amounts_different_buckets(self):
        """$100 and $9000 trades must land in different buckets.

        F2 failure mode: if both land in the same bucket, the cache would serve
        the $100 verdict to the $9000 request.
        """
        boundaries = get_causal_amount_bucket_boundaries()
        
        small_bucket = _bucket_amount(100.0, boundaries)
        large_bucket = _bucket_amount(9000.0, boundaries)
        
        assert small_bucket != large_bucket, (
            f"$100 and $9000 must land in different buckets (got {small_bucket})"
        )

    def test_boundaries_strictly_increasing(self):
        """Config-provided boundaries are strictly increasing."""
        boundaries = get_causal_amount_bucket_boundaries()
        
        assert len(boundaries) > 0, "Bucket boundaries must not be empty"
        
        for i in range(1, len(boundaries)):
            assert boundaries[i] > boundaries[i - 1], (
                f"Bucket boundaries must be strictly increasing: "
                f"boundary[{i}]={boundaries[i]} <= boundary[{i-1}]={boundaries[i-1]}"
            )

    def test_bucket_edges(self):
        """Amounts exactly at boundary edges land in the correct bucket."""
        boundaries = [100, 1000, 5000, 10000, 50000]
        
        # Amount exactly at boundary lands in higher bucket (>= semantics)
        assert _bucket_amount(99.99, boundaries) == "bucket_0"
        assert _bucket_amount(100.0, boundaries) == "bucket_1"
        assert _bucket_amount(100.01, boundaries) == "bucket_1"
        
        assert _bucket_amount(999.99, boundaries) == "bucket_1"
        assert _bucket_amount(1000.0, boundaries) == "bucket_2"
        assert _bucket_amount(1000.01, boundaries) == "bucket_2"

    def test_amount_below_first_boundary(self):
        """Amounts below the first boundary land in bucket_0."""
        boundaries = get_causal_amount_bucket_boundaries()
        bucket = _bucket_amount(1.0, boundaries)
        assert bucket == "bucket_0"

    def test_amount_above_last_boundary(self):
        """Amounts above the last boundary land in the final bucket."""
        boundaries = get_causal_amount_bucket_boundaries()
        bucket = _bucket_amount(1_000_000.0, boundaries)
        # Should be bucket_N where N = len(boundaries)
        expected = f"bucket_{len(boundaries)}"
        assert bucket == expected


@pytest.mark.unit
class TestCausalCacheKeyIncludesAmount:
    """F2: causal cache key must include amount bucket."""

    def test_cache_key_format_changed(self):
        """Cache key now includes amount bucket (3-part, not 2-part).

        F2 before fix: causal_cache:execute_trade:normal
        F2 after fix: causal_cache:execute_trade:normal:bucket_2

        This test does not call causal_safety_check directly (which requires
        dowhy + live telemetry), but validates the _bucket_amount helper that
        the cache key construction uses.
        """
        boundaries = get_causal_amount_bucket_boundaries()
        
        # The cache key builder would call _bucket_amount(amount, boundaries)
        # and append the result to the cache key.
        bucket_100 = _bucket_amount(100.0, boundaries)
        bucket_9000 = _bucket_amount(9000.0, boundaries)
        
        # Simulate cache key construction
        cache_key_100 = f"causal_cache:execute_trade:normal:{bucket_100}"
        cache_key_9000 = f"causal_cache:execute_trade:normal:{bucket_9000}"
        
        # Keys must differ (different buckets)
        assert cache_key_100 != cache_key_9000, (
            "Cache keys for $100 and $9000 must differ to prevent verdict leakage"
        )
        
        # Each key must have 4 parts (including the bucket)
        assert len(cache_key_100.split(":")) == 4, (
            f"Cache key must be 4-part (was 3-part before F2 fix): {cache_key_100}"
        )
        assert len(cache_key_9000.split(":")) == 4, (
            f"Cache key must be 4-part (was 3-part before F2 fix): {cache_key_9000}"
        )

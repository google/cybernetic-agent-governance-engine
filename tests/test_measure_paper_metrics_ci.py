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

"""Tests for the Wilson confidence interval helper in measure_paper_metrics.py.

Issue #2 in peer-review remediation: _wilson_interval() added to
scripts/measure_paper_metrics.py must have CI-exercised unit tests so regressions
in the interval arithmetic are caught before paper metrics are re-generated.

The scripts/ directory is not a package (no __init__.py), so the module is
imported directly via sys.path manipulation — matching the pattern used in
other standalone-script tests in this test suite.
"""

from __future__ import annotations

import os
import sys

import pytest

# ---------------------------------------------------------------------------
# Import the scripts/ module directly (not a package — no __init__.py).
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from measure_paper_metrics import _wilson_interval  # noqa: E402

pytestmark = pytest.mark.local


class TestWilsonInterval:
    """Unit tests for _wilson_interval(successes, n, z=1.96).

    Wilson score CI reference:
        lower = max(0, (p̂ + z²/2n - z·√(p̂(1-p̂)/n + z²/4n²)) / (1 + z²/n))
        upper = min(1, (p̂ + z²/2n + z·√(p̂(1-p̂)/n + z²/4n²)) / (1 + z²/n))
    """

    def test_zero_successes(self) -> None:
        """Lower bound must be ≈ 0 and upper bound must be in [0, 1]."""
        low, high = _wilson_interval(0, 20)
        assert low == pytest.approx(0.0, abs=0.01), (
            f"Lower bound for 0/20 should be ≈ 0.0; got {low}"
        )
        assert 0.0 <= high <= 1.0, (
            f"Upper bound for 0/20 must be in [0, 1]; got {high}"
        )

    def test_all_successes(self) -> None:
        """Upper bound must be ≈ 1.0 and lower bound must be in [0, 1]."""
        low, high = _wilson_interval(20, 20)
        assert high == pytest.approx(1.0, abs=0.01), (
            f"Upper bound for 20/20 should be ≈ 1.0; got {high}"
        )
        assert 0.0 <= low <= 1.0, (
            f"Lower bound for 20/20 must be in [0, 1]; got {low}"
        )

    def test_midpoint_brackets_proportion(self) -> None:
        """13/19 ≈ 0.684 — the Wilson interval must strictly bracket the MLE."""
        low, high = _wilson_interval(13, 19)
        mle = 13 / 19
        assert low < mle < high, (
            f"Wilson interval [{low:.4f}, {high:.4f}] must bracket MLE={mle:.4f}"
        )

    def test_zero_n_returns_full_interval(self) -> None:
        """n=0 is the degenerate case; the function must return (0.0, 1.0)."""
        low, high = _wilson_interval(0, 0)
        assert low == 0.0, f"lower must be 0.0 for n=0; got {low}"
        assert high == 1.0, f"upper must be 1.0 for n=0; got {high}"

    def test_bounds_are_valid_proportions(self) -> None:
        """All (s, n) combos must produce lower, upper in [0, 1] with lower <= upper."""
        for s, n in [(0, 5), (1, 5), (3, 5), (5, 5), (0, 1), (1, 1)]:
            low, high = _wilson_interval(s, n)
            assert 0.0 <= low <= 1.0, (
                f"low={low} out of range for s={s}, n={n}"
            )
            assert 0.0 <= high <= 1.0, (
                f"high={high} out of range for s={s}, n={n}"
            )
            assert low <= high, (
                f"low={low} > high={high} for s={s}, n={n}"
            )

    def test_interval_narrows_with_larger_n(self) -> None:
        """Larger sample → narrower Wilson CI for the same proportion (5/10 vs 50/100)."""
        low_small, high_small = _wilson_interval(5, 10)
        low_large, high_large = _wilson_interval(50, 100)
        width_small = high_small - low_small
        width_large = high_large - low_large
        assert width_large < width_small, (
            f"Expected narrower CI for n=100 ({width_large:.4f}) than n=10 ({width_small:.4f})"
        )

    def test_symmetric_around_half(self) -> None:
        """For p̂ = 0.5 the interval is symmetric around 0.5."""
        low, high = _wilson_interval(50, 100)
        midpoint = (low + high) / 2
        assert midpoint == pytest.approx(0.5, abs=0.02), (
            f"Midpoint of Wilson CI for 50/100 should be ≈ 0.5; got {midpoint}"
        )

    def test_single_observation_success(self) -> None:
        """1/1 — upper bound must be 1.0 and lower bound must be valid."""
        low, high = _wilson_interval(1, 1)
        assert high == pytest.approx(1.0, abs=0.01)
        assert 0.0 <= low <= 1.0
        assert low <= high

    def test_single_observation_failure(self) -> None:
        """0/1 — lower bound must be 0.0 and upper bound must be valid."""
        low, high = _wilson_interval(0, 1)
        assert low == pytest.approx(0.0, abs=0.01)
        assert 0.0 <= high <= 1.0
        assert low <= high

    def test_known_value_10_successes_20_trials(self) -> None:
        """Verify against a hand-computed reference value for 10/20 (p̂=0.5).

        Using z=1.96, n=20, p̂=0.5:
          denominator = 1 + 1.96²/20 = 1.19208
          centre = (0.5 + 1.96²/40) / 1.19208 ≈ 0.50000
          half_width ≈ (1.96 * sqrt(0.25/20 + 1.96²/1600)) / 1.19208 ≈ 0.21879
          lower ≈ 0.281, upper ≈ 0.719
        """
        low, high = _wilson_interval(10, 20)
        # Generous tolerance — we're testing the formula, not reproducing paper values.
        assert low == pytest.approx(0.281, abs=0.02), (
            f"lower for 10/20 expected ≈ 0.281; got {low:.4f}"
        )
        assert high == pytest.approx(0.719, abs=0.02), (
            f"upper for 10/20 expected ≈ 0.719; got {high:.4f}"
        )

    def test_high_confidence_large_sample(self) -> None:
        """190/200 (p̂=0.95) — CI should be tight and upper must be < 1.0."""
        low, high = _wilson_interval(190, 200)
        mle = 190 / 200
        assert low < mle < high
        assert high < 1.0, (
            f"Upper bound for 190/200 should be strictly < 1.0; got {high}"
        )
        # Width should be small (large n, high p̂)
        assert (high - low) < 0.1, (
            f"CI width for 190/200 should be < 0.1; got {high - low:.4f}"
        )

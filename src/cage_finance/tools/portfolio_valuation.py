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

"""Server-side portfolio valuation for the FIN-1 sell-fraction limit (UCA-13).

UCA-13 compares a sell's ``amount`` with
``stpa.max_sell_portfolio_fraction * portfolio_total``. The caller never
supplies ``portfolio_total``. It comes from the custodian ledger: the
ground-truth provider the finance plugin contributes for
``finance.cash_balance``, which is the same ledger the CBF reconciles
against. In the reference deployment that ledger holds the account's whole
value, so its settled balance is the portfolio total.

The snapshot gets the same checks the reconciler applies before it trusts a
reading: matching invariant, verified source, finite positive value, and a
fresh timestamp with no future skew. Any failure raises
:class:`PortfolioValuationUnavailable`. The trade tool then leaves
``portfolio_total`` unset, and UCA-13 refuses the sell inside the governor.
"""

from __future__ import annotations

import math
import time
from typing import TYPE_CHECKING

from src.cage_finance.invariants import CashBarrier
from src.gateway.governance.reconciliation.daemon import TTL_SECONDS

if TYPE_CHECKING:
    from src.gateway.governance.governor.governor import SymbolicGovernor

#: Oldest custodian snapshot accepted, matching the reconciler's verified-state TTL.
MAX_SNAPSHOT_AGE_S: float = float(TTL_SECONDS)

#: Future-timestamp tolerance, matching the reconciler's clock-skew default.
MAX_CLOCK_SKEW_S: float = 5.0


class PortfolioValuationUnavailable(RuntimeError):
    """No trustworthy server-side portfolio value could be read."""


async def resolve_portfolio_total(governor: SymbolicGovernor) -> float:
    """Return the account's portfolio value from the custodian ledger.

    Raises:
        PortfolioValuationUnavailable: no ledger provider is assembled, the
            fetch fails, or the snapshot fails a validity check.
    """
    invariant_id = CashBarrier.invariant_id
    provider = governor.components.ground_truth_providers.get(invariant_id)
    if provider is None:
        raise PortfolioValuationUnavailable(
            f"no ground-truth provider assembled for {invariant_id!r}"
        )
    try:
        snapshot = await provider.fetch_snapshot()  # type: ignore[attr-defined]
    except Exception as exc:
        raise PortfolioValuationUnavailable(
            f"custodian ledger fetch failed: {type(exc).__name__}: {exc}"
        ) from exc

    if getattr(snapshot, "invariant_id", None) != invariant_id:
        raise PortfolioValuationUnavailable(
            f"snapshot invariant {getattr(snapshot, 'invariant_id', None)!r} "
            f"is not {invariant_id!r}"
        )
    source = getattr(snapshot, "source_id", None)
    if not isinstance(source, str) or not source or source.startswith("unverified"):
        raise PortfolioValuationUnavailable(f"unverified ledger source {source!r}")
    try:
        total = float(snapshot.scalar)
        observed_at = float(snapshot.observed_at)
    except (AttributeError, TypeError, ValueError) as exc:
        raise PortfolioValuationUnavailable(f"malformed snapshot: {exc}") from exc
    if not math.isfinite(total) or total <= 0.0:
        raise PortfolioValuationUnavailable(f"invalid portfolio value {total!r}")
    if not math.isfinite(observed_at):
        raise PortfolioValuationUnavailable("non-finite snapshot timestamp")
    age = time.time() - observed_at
    if age > MAX_SNAPSHOT_AGE_S:
        raise PortfolioValuationUnavailable(
            f"stale snapshot: age {age:.1f}s > {MAX_SNAPSHOT_AGE_S:.1f}s"
        )
    if -age > MAX_CLOCK_SKEW_S:
        raise PortfolioValuationUnavailable(
            f"snapshot timestamp {-age:.1f}s in the future"
        )
    return total


__all__ = [
    "MAX_CLOCK_SKEW_S",
    "MAX_SNAPSHOT_AGE_S",
    "PortfolioValuationUnavailable",
    "resolve_portfolio_total",
]

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

"""Fail-closed validation of declarative safety barriers at registration time.

A malformed barrier must never reach the Lua compiler: it would silently
weaken safety coverage with no runtime signal. Validating at registration
makes a bad plugin fail at startup instead.

The declarative ``InvariantModel`` protocol (invariant_id, state_key,
threshold_key, gamma) compiles into the KEYS/ARGV of the atomic Redis Lua hop
(proof/DistributedCBF.tla), so every field is checked here.
"""

from __future__ import annotations

from collections.abc import Sequence

from src.gateway.governance.contracts import InvariantModel
from src.gateway.governance.schemas.thresholds import load_and_validate_thresholds


def validate_invariant(
    invariant: InvariantModel, registered: Sequence[InvariantModel]
) -> None:
    """Validate ``invariant`` against the already-``registered`` barriers.

    Raises:
        ValueError: If any check fails:
            - V1: invariant_id is already registered
            - V2: state_key is not namespaced (missing ':')
            - V3: threshold_key does not resolve in the active thresholds tree
            - V4: gamma is not in (0, 1]
    """
    # V1: Uniqueness — each domain must own its invariant_id namespace.
    if any(inv.invariant_id == invariant.invariant_id for inv in registered):
        raise ValueError(f"duplicate invariant registration: {invariant.invariant_id}")

    # V2: State key must be namespaced (e.g. "safety:current_cash") to prevent
    # cross-domain key collisions in the shared Redis state store.
    if ":" not in invariant.state_key:
        raise ValueError(
            f"invariant {invariant.invariant_id}: state_key must be namespaced "
            f"(contains ':'): got '{invariant.state_key}'"
        )

    # V3: Threshold key must resolve in the active thresholds tree, so the
    # barrier never falls back to a silent None at runtime.
    try:
        load_and_validate_thresholds().resolve(invariant.threshold_key)
    except (KeyError, TypeError) as exc:
        raise ValueError(
            f"invariant {invariant.invariant_id}: threshold_key "
            f"'{invariant.threshold_key}' does not resolve in THRESHOLDS tree"
        ) from exc

    # V4: gamma must be in (0, 1]. gamma=0 is a degenerate barrier that never
    # constrains; gamma>1 makes the CBF decay condition impossible to satisfy.
    if not (0 < invariant.gamma <= 1):
        raise ValueError(
            f"invariant {invariant.invariant_id}: gamma must be in (0, 1], "
            f"got {invariant.gamma}"
        )

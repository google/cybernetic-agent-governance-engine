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

"""Kernel-owned value types shared across the governance seam.

These types are part of the Layer 1 public contract. They must never
import from Layer 2 (src/cage_*) or Layer 4.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ReservationToken:
    """Result of a ResourceGuard.reserve() call.

    Promoted from src/cage_finance/safety/fiscal_limit_guard.py — a kernel
    protocol cannot annotate against a plugin-owned type.

    Domain-agnostic field names per the ResourceGuard protocol:
      principal_id  (was agent_id)
      magnitude     (was amount_usd)
    """

    reservation_id: str
    principal_id: str
    magnitude: float
    running_total: float
    rejected: bool = False
    reason: str = ""
    context: dict[str, object] = field(default_factory=dict)

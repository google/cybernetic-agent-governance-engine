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
Compatibility shim for tests that reference the old CBF module location.

After the domain pipeline refactor (PR #127), the CBF engine moved from
`src.cage_finance.safety.cbf` to `src.gateway.governance.safety.cbf_engine`.
This module re-exports the moved components to maintain backward compatibility
with existing tests.
"""

import asyncio  # Re-exported for test patching

from src.gateway.governance.safety.cbf_engine import (
    _CURRENT_FENCE_EPOCH_GAUGE,
    _EPOCH_REGRESSION_COUNTER,
    _FENCE_EPOCH_ENABLED,
    _IS_PRODUCTION,
    _REDIS_SENTINEL_MASTER_NAME,
    _STRICT_REPLICATION,
    ControlBarrierFunction,
    logger,
    redis_client,
    sync_redis_client,
)
from src.gateway.governance.schemas.thresholds import THRESHOLDS

__all__ = [
    "asyncio",
    "_CURRENT_FENCE_EPOCH_GAUGE",
    "_EPOCH_REGRESSION_COUNTER",
    "_FENCE_EPOCH_ENABLED",
    "_IS_PRODUCTION",
    "_REDIS_SENTINEL_MASTER_NAME",
    "_STRICT_REPLICATION",
    "ControlBarrierFunction",
    "logger",
    "redis_client",
    "sync_redis_client",
    "THRESHOLDS",
]

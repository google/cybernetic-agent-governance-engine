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

"""The agent's self-reported confidence, parsed one way everywhere.

Classification, DeferQueue parking and conditional FTRA clearance all read
``params["confidence"]``. They share this parser so a value cannot clear one
gate while failing another.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any


def reported_confidence(params: Mapping[str, Any]) -> float:
    """Agent self-reported confidence; unparseable values read as 0.0.

    ``bool`` is rejected (``True`` would otherwise read as 1.0), as are
    non-numeric and non-finite values. ``ConfidenceStage`` separately emits a
    HARD violation for invalid values, so reading them as 0.0 here can only
    narrow a verdict, never widen it.
    """
    raw = params.get("confidence", 0.0)
    if isinstance(raw, bool):
        return 0.0
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return 0.0
    return value if math.isfinite(value) else 0.0

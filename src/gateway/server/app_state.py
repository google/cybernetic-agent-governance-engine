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

"""Typed access to per-app state set by the gateway lifespan."""

from __future__ import annotations

from typing import Any

from src.gateway.governance.governor.governor import SymbolicGovernor


def governor_of(app: Any) -> SymbolicGovernor:
    """The governor the lifespan assembled for ``app``; fail closed if absent.

    Raises:
        RuntimeError: The lifespan has not stored a ``SymbolicGovernor`` on
            ``app.state.governor`` (startup failed or never ran).
    """
    governor = getattr(getattr(app, "state", None), "governor", None)
    if not isinstance(governor, SymbolicGovernor):
        raise RuntimeError("no assembled governor on app.state; refusing to govern")
    return governor

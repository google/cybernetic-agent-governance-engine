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

from __future__ import annotations

import importlib

__all__ = [
    "GovernanceError",
    "SymbolicGovernor",
    "causal_gatekeeper",
    "causal_safety_check",
    "generate_mock_telemetry",
    "langgraph_harness",
]


def __getattr__(name: str) -> object:  # noqa: N807
    """Lazily import heavy submodules on first attribute access.

    This function is called by Python's import machinery when an attribute
    lookup on this module fails the normal attribute dict lookup.  We use it
    to defer the import of expensive ML-stack submodules until they are
    actually needed.

    After the first access each name is cached in the module's ``__dict__``
    (via ``globals()``), so subsequent lookups are O(1) dict hits and this
    function is never called again for that name.

    Note: ``unittest.mock.patch("src.gateway.governance.causal_gatekeeper.X")``
    triggers a ``getattr(module, "causal_gatekeeper")`` call, which correctly
    reaches this function and loads the submodule before patching its attribute.
    """
    if name in ("GovernanceError", "SymbolicGovernor"):
        try:
            from .symbolic_governor import GovernanceError, SymbolicGovernor

            globals()["GovernanceError"] = GovernanceError
            globals()["SymbolicGovernor"] = SymbolicGovernor
        except ImportError:
            pass
        return globals().get(name)

    if name == "langgraph_harness":
        try:
            # NOTE: `from . import langgraph_harness` would trigger Python's
            # internal `hasattr(package, "langgraph_harness")` check while
            # resolving the fromlist, which re-enters this __getattr__ for the
            # same name before the submodule is cached in globals() —
            # causing infinite recursion (RecursionError). importlib.import_module
            # loads the submodule directly via sys.modules, sidestepping the
            # package attribute lookup entirely.
            langgraph_harness = importlib.import_module(f"{__name__}.langgraph_harness")
            globals()["langgraph_harness"] = langgraph_harness
            return langgraph_harness
        except ImportError:
            return None

    if name in ("causal_gatekeeper", "causal_safety_check", "generate_mock_telemetry"):
        try:
            # See note above re: avoiding `from . import causal_gatekeeper`.
            causal_gatekeeper = importlib.import_module(f"{__name__}.causal.gatekeeper")
            import sys

            sys.modules[f"{__name__}.causal_gatekeeper"] = causal_gatekeeper
            causal_safety_check = causal_gatekeeper.causal_safety_check
            generate_mock_telemetry = causal_gatekeeper.generate_mock_telemetry
            globals()["causal_gatekeeper"] = causal_gatekeeper
            globals()["causal_safety_check"] = causal_safety_check
            globals()["generate_mock_telemetry"] = generate_mock_telemetry
        except ImportError:
            pass
        return globals().get(name)

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

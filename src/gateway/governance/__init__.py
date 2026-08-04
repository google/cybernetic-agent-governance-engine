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

# GovernanceError and SymbolicGovernor are in symbolic_governor.py which only
# depends on core packages (opentelemetry, pydantic). Import them separately so
# they remain accessible even when optional extras (e.g. langgraph) are absent.
try:
    from .symbolic_governor import GovernanceError, SymbolicGovernor
except ImportError:
    pass

# langgraph_harness requires the 'advisor' extra (langgraph, langchain_core …).
# Keep it in a separate try so the failure doesn't suppress GovernanceError above.
try:
    from . import langgraph_harness
except ImportError:
    pass

# causal_gatekeeper.py depends on networkx / numpy / pandas which are optional.
# Expose the module itself as a package attribute so tests can patch
# `src.gateway.governance.causal_gatekeeper.*` correctly.
try:
    from . import causal_gatekeeper
    from .causal_gatekeeper import causal_safety_check, generate_mock_telemetry
except ImportError:
    pass

__all__ = [
    "GovernanceError",
    "SymbolicGovernor",
    "causal_gatekeeper",
    "causal_safety_check",
    "generate_mock_telemetry",
    "langgraph_harness",
]

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

"""Guard test to verify permanent removal of deprecated CBF compatibility shim.

Per AGENTS.md, plans/vendor_decoupling_implementation_plan.md §3 Task W1.7, and AW-5:
The legacy shim `src/cage_finance/safety/cbf.py` is permanently deleted.
Callers must strictly import canonical `src.gateway.governance.safety.cbf_engine`.
This guard prevents accidental re-introduction of the compatibility shim.
"""

import importlib.util
import pytest


@pytest.mark.local
@pytest.mark.unit
def test_cbf_compatibility_shim_does_not_exist():
    """Verify that src.cage_finance.safety.cbf cannot be found or imported."""
    spec = importlib.util.find_spec("src.cage_finance.safety.cbf")
    assert spec is None, (
        "Forbidden compatibility shim 'src.cage_finance.safety.cbf' was detected! "
        "Per AGENTS.md and W1.7, all CBF logic lives in 'src.gateway.governance.safety.cbf_engine' "
        "and backward-compatibility shims must not exist."
    )

    with pytest.raises(ModuleNotFoundError):
        import src.cage_finance.safety.cbf  # noqa: F401


@pytest.mark.local
@pytest.mark.unit
def test_cbf_engine_canonical_import():
    """Verify that canonical cbf_engine is importable and exports ControlBarrierFunction."""
    from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

    assert callable(ControlBarrierFunction)


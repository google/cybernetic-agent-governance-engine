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

"""Entry-point bootstrap: the one sequence every process uses to get a governor.

The gateway lifespan, the advisor lifespan and CLI scripts all call
:func:`bootstrap_governor`. It loads the single ``CAGE_DOMAIN`` plugin,
assembles the governor, refuses null engine slots, registers the domain's
compliance overlays (process-wide, needed by every entry point's
``ControlRegistry`` lookups) and runs :func:`assert_production_posture`, in
that order. Server-specific hooks (MCP tools, rails, background tasks) are
installed by the server. Importing this module has no side effects.
"""

from __future__ import annotations

from typing import Any

from src.gateway.governance.env_posture import resolve_posture
from src.gateway.governance.governor.assembly import assemble_governor
from src.gateway.governance.governor.governor import SymbolicGovernor
from src.gateway.governance.governor.posture import assert_production_posture


def bootstrap_governor(**assembly_overrides: Any) -> SymbolicGovernor:
    """Load ``CAGE_DOMAIN``, assemble, check posture; return the governor.

    ``assembly_overrides`` are passed to :func:`assemble_governor` (e.g. a
    shared ``opa`` client).

    Raises:
        RuntimeError: No usable domain plugin, or the domain left an engine
            slot (safety filter, consensus) unfilled.
        GovernorAssemblyError: The contribution is unsafe.
        PostureViolation: An enforcing posture failed a startup check.
    """
    from src.gateway.governance.plugin_loader import (
        domain_config_of,
        load_domain_plugin,
    )

    posture = resolve_posture()
    plugin = load_domain_plugin()
    domain_config_of(plugin)  # before assembly: never half-activate a domain
    governor = assemble_governor([plugin], posture=posture, **assembly_overrides)
    if governor.components.unfilled_slots:
        raise RuntimeError(
            f"domain {plugin.name!r} left kernel slots {list(governor.components.unfilled_slots)} "
            "unfilled; refusing to serve traffic"
        )
    from src.gateway.governance.constants import register_overlay_dir

    for contribution in governor.components.contributions:
        for overlay_dir in contribution.compliance_overlay_dirs:
            register_overlay_dir(overlay_dir)
    assert_production_posture(posture, components=governor.components)
    return governor

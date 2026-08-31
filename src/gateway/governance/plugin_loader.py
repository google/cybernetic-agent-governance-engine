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

"""CAGE plugin discovery and activation.

Discovers capability plugins via ``importlib.metadata`` entry points in the
``cage.plugins`` group.  Each discovered plugin is structurally and version-
validated via :func:`validate_plugin` before activation.

Activation semantics (D1 fix)
-----------------------------
* ``CAGE_ACTIVE_PLUGINS`` **unset** (variable absent from the environment):
  load all discovered plugins — preserving current behavior for existing
  deployments.
* ``CAGE_ACTIVE_PLUGINS=""`` (set but empty): load **no** plugins — the
  bare-kernel mode exercised by Gate 0.
* ``CAGE_ACTIVE_PLUGINS="finance,other"``: load only the named plugins.

These two states (unset vs. empty) must be distinguished by presence, not
truthiness.
"""

from __future__ import annotations

import importlib.metadata
import logging
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.gateway.governance.contracts import CagePlugin

logger = logging.getLogger("cage.plugin_loader")

_ENTRY_POINT_GROUP = "cage.plugins"


def _resolve_activation_list(
    activation_list: list[str] | None,
) -> list[str] | None:
    """Return None for 'load all', or an explicit (possibly empty) allowlist.

    Resolution order:
    1. Explicit ``activation_list`` argument wins (for tests and programmatic use).
    2. ``CAGE_ACTIVE_PLUGINS`` environment variable.
    3. ``None`` → load all discovered plugins.
    """
    if activation_list is not None:
        return activation_list
    raw = os.getenv("CAGE_ACTIVE_PLUGINS")
    if raw is None:
        return None  # unset → load all discovered plugins
    return [p.strip() for p in raw.split(",") if p.strip()]  # "" → [] → load none


def discover_plugins(
    activation_list: list[str] | None = None,
) -> list[CagePlugin]:
    """Load CAGE plugins via entry points, filtered by the activation list.

    Args:
        activation_list: Explicit plugin allowlist.  ``None`` defers to the
            ``CAGE_ACTIVE_PLUGINS`` environment variable (see module docstring
            for semantics).

    Returns:
        List of validated and instantiated :class:`CagePlugin` objects.

    Raises:
        Exception: If a plugin fails to load or validate — fail-closed by
            design.  A plugin that cannot be imported must not be silently
            downgraded to "absent".
    """
    from src.gateway.governance.contracts import validate_plugin

    allowlist = _resolve_activation_list(activation_list)

    plugins: list[CagePlugin] = []
    for ep in importlib.metadata.entry_points(group=_ENTRY_POINT_GROUP):
        # D1 FIX: skip when an allowlist exists and this plugin is not in it.
        if allowlist is not None and ep.name not in allowlist:
            logger.info("plugin %s skipped (not in activation list)", ep.name)
            continue
        try:
            plugin_cls = ep.load()
        except Exception:
            # Fail closed: a plugin that cannot be imported must not be
            # silently downgraded to "absent" — the caller decides.
            logger.exception("plugin %s failed to load", ep.name)
            raise
        plugin = plugin_cls()
        validate_plugin(plugin, ep.name)
        plugins.append(plugin)
        logger.info("plugin %s loaded", ep.name)
    return plugins

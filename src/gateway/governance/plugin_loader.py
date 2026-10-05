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

"""CAGE single-domain plugin loading.

A CAGE process runs **exactly one** domain plugin, named by ``CAGE_DOMAIN``
(resolved by :func:`env_posture.resolve_domain`). The plugin is found among the
``cage.plugins`` entry points, structurally and version-validated via
:func:`validate_plugin`, and must declare a :class:`DomainConfig` whose files
exist. Every failure raises: a process that cannot identify its one domain
must not serve traffic.
"""

from __future__ import annotations

import functools
import importlib.metadata
import logging
import re
from typing import TYPE_CHECKING

from src.gateway.governance.env_posture import DOMAIN_ENV_VAR, resolve_domain

if TYPE_CHECKING:
    from src.gateway.governance.contracts import CagePlugin, DomainConfig

logger = logging.getLogger("cage.plugin_loader")

_ENTRY_POINT_GROUP = "cage.plugins"

_REGO_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_REGO_PACKAGE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*")


def load_domain_plugin(domain: str | None = None) -> CagePlugin:
    """Load and validate the plugin for ``domain`` (default: ``CAGE_DOMAIN``).

    Raises:
        RuntimeError: ``CAGE_DOMAIN`` unset/multi-valued, no entry point with
            that name, or more than one.
        Exception: Whatever the plugin import raises; a plugin that cannot be
            imported must not be silently downgraded to "absent".
        TypeError, ValueError: The plugin fails :func:`validate_plugin`.
    """
    from src.gateway.governance.contracts import validate_plugin

    name = domain if domain is not None else resolve_domain()
    available = importlib.metadata.entry_points(group=_ENTRY_POINT_GROUP)
    matches = [ep for ep in available if ep.name == name]
    if not matches:
        known = sorted({ep.name for ep in available})
        raise RuntimeError(
            f"{DOMAIN_ENV_VAR}={name!r} matches no registered plugin; known: {known}"
        )
    if len(matches) > 1:
        raise RuntimeError(
            f"{DOMAIN_ENV_VAR}={name!r} matches {len(matches)} entry points; must be unique"
        )

    try:
        plugin_cls = matches[0].load()
    except Exception:
        logger.exception("plugin %s failed to load", name)
        raise
    plugin = validate_plugin(plugin_cls(), name)
    logger.info("domain plugin %s loaded", name)
    return plugin


def domain_config_of(plugin: CagePlugin) -> DomainConfig:
    """Return ``plugin.domain_config`` after checking it is complete.

    Raises:
        RuntimeError: No ``DomainConfig`` declared, a path is relative, or a
            declared file is missing. The kernel would otherwise fall back to
            another domain's config and govern actions it does not describe.
    """
    config = plugin.domain_config
    if config is None:
        raise RuntimeError(
            f"domain {plugin.name!r} declares no DomainConfig (FTRA registry required); refusing to start"
        )
    paths = {"ftra_registry_path": config.ftra_registry_path}
    if config.causal_graph_path is not None:
        paths["causal_graph_path"] = config.causal_graph_path
    for field_name, path in paths.items():
        if not path.is_absolute():
            raise RuntimeError(
                f"domain {plugin.name!r}: {field_name} must be absolute, got {path}"
            )
        if not path.is_file():
            raise RuntimeError(
                f"domain {plugin.name!r}: {field_name} does not exist: {path}"
            )
    if not _REGO_PACKAGE.fullmatch(config.opa_package):
        raise RuntimeError(
            f"domain {plugin.name!r}: opa_package must be a dotted Rego package, got {config.opa_package!r}"
        )
    rules = config.opa_required_rules
    if not rules or not all(
        isinstance(r, str) and _REGO_IDENT.fullmatch(r) for r in rules
    ):
        raise RuntimeError(
            f"domain {plugin.name!r}: opa_required_rules must be a non-empty tuple of rule names, got {rules!r}"
        )
    return config


@functools.cache
def active_domain_config() -> DomainConfig:
    """``DomainConfig`` of the process's single active domain (cached).

    ``CAGE_DOMAIN`` is a process constant, so the result is cached for the
    process lifetime. Tests that change the domain call ``cache_clear()``.
    """
    return domain_config_of(load_domain_plugin())

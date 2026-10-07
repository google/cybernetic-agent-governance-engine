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

"""Warrant source factory: the composition root's only route to an issuer adapter.

``CAGE_WARRANT_SOURCE`` names the adapter that supplies warrants through the
:class:`~src.gateway.governance.seams.warrant.WarrantSource` seam. Unset or
empty means no source is configured; :func:`assemble_governor` then refuses
any norm a region marks ``requires_warrant`` (fail closed). An unknown name
raises rather than falling back to "no source".

The adapter is imported lazily inside :func:`warrant_source_from_env`, so
this module is on the Gate G3 ``INTEGRATIONS_FACTORY_ALLOWLIST`` and no
other kernel module ever names an integration package.
"""

from __future__ import annotations

import os

from src.gateway.governance.seams.warrant import WarrantSource

#: Environment variable naming the configured warrant source.
WARRANT_SOURCE_ENV = "CAGE_WARRANT_SOURCE"

_ALIASES: dict[str, str] = {"p05": "provider_05"}


class UnknownWarrantSourceError(ValueError):
    """``CAGE_WARRANT_SOURCE`` names no known warrant source adapter."""


def warrant_source_from_env(name: str | None = None) -> WarrantSource | None:
    """The configured warrant source, or ``None`` when none is configured.

    Args:
        name: Adapter name; defaults to ``$CAGE_WARRANT_SOURCE``.

    Raises:
        UnknownWarrantSourceError: The name matches no adapter.
    """
    raw = (name if name is not None else os.environ.get(WARRANT_SOURCE_ENV, "")).strip()
    if not raw:
        return None
    normalized = _ALIASES.get(raw.lower(), raw.lower())
    if normalized == "provider_05":
        from src.integrations.provider_05.warrant_source import (
            Provider05WarrantSource,
        )

        return Provider05WarrantSource()
    raise UnknownWarrantSourceError(
        f"{WARRANT_SOURCE_ENV}={raw!r} names no warrant source; supported: provider_05"
    )


__all__ = [
    "WARRANT_SOURCE_ENV",
    "UnknownWarrantSourceError",
    "warrant_source_from_env",
]

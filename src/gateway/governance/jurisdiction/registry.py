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

"""The one table mapping a deployment region to its jurisdiction contribution."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from types import MappingProxyType

from src.gateway.governance.jurisdiction.contribution import JurisdictionContribution


def _no_obligations(region: str) -> Callable[[], JurisdictionContribution]:
    return lambda: JurisdictionContribution(region=region)


def _eu_ai_act() -> JurisdictionContribution:
    # Lazy: only an EU deployment resolves (and constructs) a normative provider.
    from src.gateway.governance.jurisdiction.eu_ai_act import contribution

    return contribution()


#: Region → factory. ``US_FED`` and ``APAC_MAS`` contribute no tiers; other
#: jurisdiction obligations (e.g. MAS FEAT, SR 11-7 attestations) need their
#: own decision before they appear here (D-L item 4).
JURISDICTIONS: Mapping[str, Callable[[], JurisdictionContribution]] = MappingProxyType(
    {
        "US_FED": _no_obligations("US_FED"),
        "APAC_MAS": _no_obligations("APAC_MAS"),
        "EU_ECB": _eu_ai_act,
    }
)


def active_region() -> str:
    """The region whose compliance profile ``ControlRegistry`` has loaded.

    Same reader as every other region-dependent control: an unknown
    ``CAGE_DEPLOYMENT_REGION`` falls back to ``US_FED`` there, and so here.
    """
    from src.gateway.governance.constants import ControlRegistry

    return ControlRegistry().active_region


def resolve_jurisdiction(region: str | None = None) -> JurisdictionContribution:
    """Build the contribution for ``region`` (default: :func:`active_region`).

    Raises:
        ValueError: ``region`` has no entry in :data:`JURISDICTIONS` — a
            region the kernel cannot attribute obligations to is refused
            rather than silently treated as obligation-free.
    """
    resolved = (region if region is not None else active_region()).strip().upper()
    factory = JURISDICTIONS.get(resolved)
    if factory is None:
        raise ValueError(
            f"no jurisdiction entry for region {resolved!r}; known: {sorted(JURISDICTIONS)}"
        )
    return factory()

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

"""Posture-selected jurisdiction obligations (D-L).

Some obligations exist only in one legal order — the EU AI Act's
Fundamental Rights Impact Assessment (Regulation (EU) 2024/1689, Art. 27)
has no US or Singapore counterpart. They are not universal governance
mechanics, so they never live in the kernel's universal path. Instead the
deployment region (``CAGE_DEPLOYMENT_REGION``, as resolved by
``ControlRegistry``) selects one :class:`JurisdictionContribution`, which the
composition root merges into the tier set after the domain tiers.

This package is the only kernel location that maps a region to obligations;
:data:`~src.gateway.governance.jurisdiction.registry.JURISDICTIONS` is the one
table that does it.
"""

from src.gateway.governance.jurisdiction.contribution import (
    JurisdictionContribution,
    PostureRequirement,
)
from src.gateway.governance.jurisdiction.registry import (
    JURISDICTIONS,
    active_region,
    resolve_jurisdiction,
)

__all__ = [
    "JURISDICTIONS",
    "JurisdictionContribution",
    "PostureRequirement",
    "active_region",
    "resolve_jurisdiction",
]

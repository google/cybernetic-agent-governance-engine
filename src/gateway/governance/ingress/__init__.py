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

"""
Policy Ingress Package
======================

Accepts external policy specifications (ACS, AAIF, OSCAL, Lula) and
translates them into CAGE-native enforcement artifacts.

Public API::

    from src.gateway.governance.ingress import translate_policy, detect_format

    artifact_bundle = translate_policy(spec_dict)
    fmt = detect_format(spec_dict)  # "acs" | "aaif" | "oscal" | "lula" | "cage_yaml"
"""

from src.gateway.governance.ingress.agw_adapter import (
    AgwAdapter,
    AgwAdapterResult,
    AgwRequest,
    get_agw_adapter,
)
from src.gateway.governance.ingress.policy_translator import (
    ArtifactBundle,
    PolicyFormat,
    detect_format,
    translate_policy,
)

__all__ = [
    "AgwAdapter",
    "AgwAdapterResult",
    "AgwRequest",
    "ArtifactBundle",
    "PolicyFormat",
    "detect_format",
    "get_agw_adapter",
    "translate_policy",
]

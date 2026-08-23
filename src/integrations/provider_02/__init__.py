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
Provider 02 Integration Package
================================

Provides two components:

1. **Provider02AttestationProvider** — CER creation, JWK-cached verification,
   and Project Bundle registration against the attestation API.

2. **Provider02AttestationCallback** — LangGraph callback handler that captures
   immutable state snapshots at governance-significant node boundaries and
   assembles Project Bundles.

Usage::

    from src.integrations.provider_02 import Provider02AttestationProvider, Provider02AttestationCallback
"""

from .adapter import (
    AttestationBundle,
    Provider02AttestationCallback,
    Provider02Client,
    ProjectBundleStepEntry,
)
from .provider import (
    CERReceipt,
    CERVerification,
    JWKCache,
    Provider02AttestationProvider,
    get_provider_02,
)

__all__ = [
    "AttestationBundle",
    "CERReceipt",
    "CERVerification",
    "JWKCache",
    "Provider02AttestationCallback",
    "Provider02AttestationProvider",
    "Provider02Client",
    "ProjectBundleStepEntry",
    "get_provider_02",
]

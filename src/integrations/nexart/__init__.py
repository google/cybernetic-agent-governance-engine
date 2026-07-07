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
NexArt Integration Package
===========================

Provides two components:

1. **NexArtAttestationProvider** — CER creation, JWK-cached verification,
   and Project Bundle registration against the NexArt attestation API.

2. **NexArtAttestationCallback** — LangGraph callback handler that captures
   immutable state snapshots at governance-significant node boundaries and
   assembles NexArt Project Bundles.

Usage::

    from src.integrations.nexart import NexArtAttestationProvider, NexArtAttestationCallback
"""

from .adapter import (
    AttestationBundle,
    NexArtAttestationCallback,
    NexArtClient,
    ProjectBundleStepEntry,
)
from .provider import (
    CERReceipt,
    CERVerification,
    JWKCache,
    NexArtAttestationProvider,
    get_nexart_provider,
)

__all__ = [
    "AttestationBundle",
    "CERReceipt",
    "CERVerification",
    "JWKCache",
    "NexArtAttestationCallback",
    "NexArtAttestationProvider",
    "NexArtClient",
    "ProjectBundleStepEntry",
    "get_nexart_provider",
]

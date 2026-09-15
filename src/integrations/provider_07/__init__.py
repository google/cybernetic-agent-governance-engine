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
provider_07 — Bayesian Causal Suitability Adapter

Layer 3 integration adapter for Bayesian belief network inference over financial
suitability constraints (SEC Reg BI, FINRA Rule 2111, EU AI Act Art. 29a).

Public Exports:
- Phase 1: Wire protocol schema models (Pydantic v2)
- Phase 2: NormativeProvider adapter, JWKS client, signature verification
"""

from .adapter import NormativeProviderError, Provider07NormativeProvider
from .jwks_client import Provider07JwksClient
from .schema import (
    ActionUtility,
    ClientProfile,
    InferThetaBaselineResponse,
    InferThetaInferenceRequest,
    InferThetaInferenceResponse,
    NormativeRule,
    ProposedTrade,
)
from .signature import verify_inference_signature

__all__ = [
    "ActionUtility",
    "ClientProfile",
    "InferThetaBaselineResponse",
    "InferThetaInferenceRequest",
    "InferThetaInferenceResponse",
    "NormativeProviderError",
    "NormativeRule",
    "ProposedTrade",
    "Provider07JwksClient",
    "Provider07NormativeProvider",
    "verify_inference_signature",
]

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
actuator_01 — Downstream Execution Actuator Adapter (Phase 2, Stream C)

Anonymized slot name for the first external downstream actuator integration.
Vendor-neutral implementation per execution actuator protocol specification.

This adapter implements the ExecutionActuator protocol for secure execution
authorization with dual-control quorum signatures.
"""

from .adapter import Actuator01Adapter
from .assertion import AssertionBuildError, build_assertion, decode_assertion
from .client import ActuatorHttpClient
from .envelope_builder import (
    EnvelopeTooLargeError,
    InvalidClearanceError,
    build_and_canonicalize,
)
from .response_classifier import (
    ClassifiedResponse,
    ResponseCategory,
    classify_network_error,
    classify_response,
)
from .signatures import sign_for_quorum

__all__ = [
    "Actuator01Adapter",
    "ActuatorHttpClient",
    "AssertionBuildError",
    "ClassifiedResponse",
    "EnvelopeTooLargeError",
    "InvalidClearanceError",
    "ResponseCategory",
    "build_and_canonicalize",
    "build_assertion",
    "classify_network_error",
    "classify_response",
    "decode_assertion",
    "sign_for_quorum",
]

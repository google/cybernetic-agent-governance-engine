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
Cryptographic Routing Seal — Defense-in-Depth for Tool Actuation.

This module provides the actuator-side verification functions for routing seals.
It re-exports the implementation from the authoritative gateway module to prevent
cryptographic drift while maintaining the defense-in-depth import boundary for
the GFA actuator (PEP).
"""

from src.gateway.governance.routing_seal import (
    SymbolicGovernorViolation,
    extract_record_hash,
    generate_seal,
    is_default_salt,
    require_cleared_seal,
    verify_and_consume_seal,
    verify_seal,
)

__all__ = [
    "SymbolicGovernorViolation",
    "extract_record_hash",
    "generate_seal",
    "is_default_salt",
    "require_cleared_seal",
    "verify_and_consume_seal",
    "verify_seal",
]

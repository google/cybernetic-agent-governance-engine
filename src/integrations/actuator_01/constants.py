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
Constants for the actuator_01 adapter.

All vendor-specific identifiers are sourced from environment/config at runtime.
The constant names are anonymized; the runtime values are wire-load-bearing.
"""

# Hard 4KB ceiling on canonical envelope body (bytes only, headers measured separately)
ENVELOPE_MAX_BYTES = 4096

# TTL ceiling per partner Micro-TTL
MAX_TTL_SECONDS = 30

# Nonce format: 32 hex chars (16 bytes)
NONCE_HEX_LENGTH = 32

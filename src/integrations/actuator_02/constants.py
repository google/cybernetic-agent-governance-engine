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

"""Cryptographic domain tags and protocol constants for actuator_02."""

from __future__ import annotations

ACTUATOR_02_ID: str = "actuator_02"

ASSERTION_DOMAIN_TAG: bytes = b"CAGE_OPENSHELL_ASSERTION_V1:"
RECEIPT_SIGNATURE_DOMAIN_TAG: bytes = b"CAGE_ACTUATION_RECEIPT_V1:"

MAX_ENVELOPE_BYTES: int = 4096

# Allowed OCSF class UIDs emitted by sandboxed supervisor telemetry:
#   1001 = File System Activity
#   1007 = Process Activity
#   4001 = Network Activity
ALLOWED_OCSF_CLASS_UIDS: frozenset[int] = frozenset({1001, 1007, 4001})

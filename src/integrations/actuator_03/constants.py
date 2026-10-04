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

"""Cryptographic domain tags and constants for actuator_03."""

from __future__ import annotations

ACTUATOR_03_ID: str = "actuator_03"

QUARANTINE_ASSERTION_DOMAIN_TAG: bytes = b"CAGE_QUARANTINE_ASSERTION_V1:"
QUARANTINE_RECEIPT_DOMAIN_TAG: bytes = b"CAGE_QUARANTINE_RECEIPT_V1:"

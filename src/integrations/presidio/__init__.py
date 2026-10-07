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

"""Microsoft Presidio PII Detection & Anonymization Adapter (Layer 3)."""

from src.integrations.presidio.redactor import (
    build_presidio_sdd_action,
    ensure_presidio_engines,
    get_analyzer_patch,
    redact_pii,
)

__all__ = [
    "build_presidio_sdd_action",
    "ensure_presidio_engines",
    "get_analyzer_patch",
    "redact_pii",
]

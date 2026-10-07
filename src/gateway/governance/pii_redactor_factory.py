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
PII Redactor Factory (Layer 1 Kernel)
=====================================

Single allowlisted factory module in Layer 1 that lazily binds the configured
Layer 3 identity-PII redaction provider (default: ``src.integrations.presidio``).
"""

from __future__ import annotations


def ensure_pii_engines() -> None:
    """Lazy-initialize the Layer 3 PII detection and anonymization engines."""
    from src.integrations.presidio.redactor import ensure_presidio_engines

    ensure_presidio_engines()


def redact_identity_pii(text: str) -> tuple[str, list[str]]:
    """Replace identity-bearing PII in *text* via the Layer 3 PII redactor provider."""
    from src.integrations.presidio.redactor import redact_pii

    return redact_pii(text)

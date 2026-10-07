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
PiiRedactorProvider Seam Protocol (Layer 1 Kernel)
==================================================

Defines the vendor-neutral protocol for identity-bearing PII detection and
redaction. Concrete implementations (such as Microsoft Presidio in
``src/integrations/presidio/``) reside in Layer 3 and are loaded lazily
through ``src.gateway.governance.pii_redactor_factory``.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class PiiRedactorProvider(Protocol):
    """Vendor-neutral interface for identity-PII detection and redaction."""

    def ensure_engines(self) -> None:
        """Lazy-initialize the underlying PII detection and anonymization engines."""
        ...

    def redact_pii(self, text: str) -> tuple[str, list[str]]:
        """Replace identity-bearing PII in ``text`` with ``<ENTITY_TYPE>`` tokens."""
        ...

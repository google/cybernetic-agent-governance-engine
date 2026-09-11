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
CAGE Seam Contracts — Vendor-Neutral Integration Interfaces.

This package contains protocol definitions and dataclasses that define the
boundaries between CAGE's governance kernel and external adapters. By isolating
these contracts into a dedicated package with zero kernel imports, we eliminate
circular dependencies that previously forced function-scope imports in vendor
adapters.

Modules:
    normative: Normative provider seam (baseline supply, FRIA validation, evidence sealing)
    attestation: Attestation provider seam (external trust service integration)
    actuation: Execution actuator seam (downstream clearance transmission)
    graph_topology: Domain-agnostic graph structure for attestation adapters

Architecture Principle:
    Seam modules must NEVER import from the rest of the kernel. They define
    the contract, not the implementation. This is the load-bearing property
    that breaks the circular import cycle.
"""

from __future__ import annotations

__all__ = [
    "actuation",
    "attestation",
    "graph_topology",
    "normative",
]

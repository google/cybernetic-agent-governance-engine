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

"""Domain-neutral STAMP/STPA ontology primitives (Layer 1 kernel)."""

from __future__ import annotations

from dataclasses import dataclass

from src.gateway.governance.ontology_validator import KnowledgeGraphValidator


@dataclass
class Constraint:
    """Represents a semantic safety constraint."""

    id: str
    description: str
    logic: str  # Formal or semi-formal representation of the rule
    scope: list[str]  # Applicable actions


@dataclass
class STAMP_UCA:
    """
    Systems-Theoretic Accident Model and Processes (STAMP)
    Unsafe Control Action (UCA) Definition.
    """

    id: str
    category: str  # "Not Provided", "Unsafe Action", "Wrong Timing", "Duration Too Long"
    description: str
    hazard_link: str  # Link to High-Level Hazard (e.g., H-1: Financial Loss)
    detection_pattern: str  # Pseudo-code or Regex for the Evaluator


__all__ = [
    "Constraint",
    "KnowledgeGraphValidator",
    "STAMP_UCA",
]

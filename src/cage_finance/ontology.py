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

"""Finance domain knowledge graph for STAMP/STPA UCAs and constraints."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import ClassVar

from src.gateway.governance.ontology import STAMP_UCA, Constraint

logger = logging.getLogger(__name__)


@dataclass
class TradingKnowledgeGraph:
    """
    Knowledge Graph representing the Trading Governance Ontology.
    Maps Actions -> Risks -> Controls (STAMP/STPA + ISO 42001).

    Region-aware control mapping:
    - _UNIVERSAL_CONTROL_MAP: ISO 42001 controls applicable to all regions
    - _JURISDICTIONAL_CONTROL_MAP: region-keyed additions (US_FED, EU_ECB, APAC_MAS)
    - get_control_map(region): merges universal + jurisdictional controls for the region
    """

    ucas: dict[str, STAMP_UCA] = field(default_factory=dict)
    constraints: dict[str, Constraint] = field(default_factory=dict)

    # Universal ISO 42001 control mappings — applicable to ALL deployment regions
    _UNIVERSAL_CONTROL_MAP: ClassVar[dict[str, str]] = {
        "SOCIAL_IMPACT": "ISO_42001_A.5.2 (Assess AI System Impact)",
        "LOGGING_AUDIT": "ISO_42001_A.6.2.8 (Event Logging)",
        "DATA_PRIVACY": "ISO_42001_A.7.4 (Quality of Data for AI)",
        "FISCAL_CONTROLS": "ISO_42001_A.8.4 (System Boundary & Resource Limits)",
        "EXPLAINABILITY": "ISO_42001_A.9.3 (Objectives for Responsible Use)",
        # Event-level mappings (ISO 42001 universal)
        "Consensus_Vote": "A.5.2",
        "CBF_Violation": "A.8.4",
        "NeMo_Block": "A.9.2",
        "Causal_Intervention": "A.5.3",
    }

    # Jurisdictional control mappings — added ONLY when CAGE_DEPLOYMENT_REGION matches
    _JURISDICTIONAL_CONTROL_MAP: ClassVar[dict[str, dict[str, str]]] = {
        "US_FED": {
            "Fiscal_Reservation": "SC-4",  # NIST SP 800-53 SC-4
            "EBPF_Alert": "SI-4",  # NIST SP 800-53 SI-4
            "Agent_Identity_Check": "IA-3",  # NIST SP 800-53 IA-3
            "Memory_Poisoning_Defense": "SI-16",  # NIST SP 800-53 SI-16
            "Confidence_Floor_Enforcement": "AU-6",  # NIST SP 800-53 AU-6
            "Human_Escalation": "AC-5",  # NIST SP 800-53 AC-5
            "Audit_Seal_Verification": "AU-10",  # NIST SP 800-53 AU-10
        },
        "EU_ECB": {
            "Fiscal_Reservation": "DORA-Art-9",  # DORA Art. 9 (Protection & Prevention)
            "EBPF_Alert": "Article 15",  # EU AI Act Art. 15 (Cybersecurity)
            "Agent_Identity_Check": "Article 9",  # EU AI Act Art. 9 (Risk Management)
            "Memory_Poisoning_Defense": "Article 15",  # EU AI Act Art. 15
            "Confidence_Floor_Enforcement": "Article 13",  # EU AI Act Art. 13 (Transparency)
            "Human_Escalation": "Article 14",  # EU AI Act Art. 14 (Human Oversight)
            "Audit_Seal_Verification": "Article 12",  # EU AI Act Art. 12 (Record-Keeping)
        },
        "APAC_MAS": {
            "Fiscal_Reservation": "MAS-TRM-9.1",  # MAS TRM §9.1 (Access Control)
            "EBPF_Alert": "MAS-TRM-11.1",  # MAS TRM §11.1 (Security Monitoring)
            "Agent_Identity_Check": "MAS-FEAT-2",  # MAS FEAT Accountability
            "Memory_Poisoning_Defense": "MAS-TRM-11.2",  # MAS TRM §11.2
            "Confidence_Floor_Enforcement": "MAS-FEAT-3",  # MAS FEAT Transparency
            "Human_Escalation": "MAS-FEAT-2",  # MAS FEAT Accountability
            "Audit_Seal_Verification": "MAS-FEAT-4",  # MAS FEAT Soundness
        },
    }

    @classmethod
    def get_control_map(cls, region: str | None = None) -> dict[str, str]:
        """Return control mappings applicable to the given deployment region."""
        effective_region = (
            region or os.environ.get("CAGE_DEPLOYMENT_REGION", "LOCAL")
        ).upper()
        result = dict(cls._UNIVERSAL_CONTROL_MAP)
        if effective_region in cls._JURISDICTIONAL_CONTROL_MAP:
            result.update(cls._JURISDICTIONAL_CONTROL_MAP[effective_region])
        return result

    def __post_init__(self) -> None:
        self._initialize_ontology()

    def _initialize_ontology(self) -> None:
        """Populates the graph with standard Trading Safety Constraints and STAMP UCAs."""
        self.add_uca(
            STAMP_UCA(
                id="UCA-1",
                category="Unsafe Action",
                description="Agent executes a WRITE operation (Trade/DB) without a valid Human Approval Token.",
                hazard_link="H-1: Unauthorized Financial Transaction",
                detection_pattern="action in ['write_db', 'execute_trade'] and not approval_token",
            )
        )

        self.add_uca(
            STAMP_UCA(
                id="UCA-2",
                category="Wrong Timing",
                description="Agent executes a Market Order during high latency (>500ms), risking slippage.",
                hazard_link="H-2: Uncontrolled Financial Loss due to Slippage",
                detection_pattern="action == 'execute_trade' and order_type == 'MARKET' and latency > 500",
            )
        )

        self.add_uca(
            STAMP_UCA(
                id="UCA-5",
                category="Unsafe Action",
                description="Agent generates investment advice without retrieving the User Risk Profile first.",
                hazard_link="H-3: Unsuitable Investment Recommendation (Fiduciary Breach)",
                detection_pattern="intent == 'provide_advice' and 'get_risk_profile' not in tool_history",
            )
        )

        self.add_uca(
            STAMP_UCA(
                id="UCA-6",
                category="Duration Too Long",
                description="Reasoning loop exceeds 5 steps without converging on a verdict.",
                hazard_link="H-4: Resource Exhaustion / Infinite Loop",
                detection_pattern="step_count > 5",
            )
        )

        self.add_uca(
            STAMP_UCA(
                id="UCA-7",
                category="Unsafe Action",
                description=(
                    "Agent attempts to route a confidence-starved context (confidence < 0.70) "
                    "to human manual review or autonomous execution instead of parking in DEFER queue."
                ),
                hazard_link="H-7: Corrupt Context Execution / Operator Alert Fatigue",
                detection_pattern="confidence < 0.70 and verdict != 'DEFER'",
            )
        )

        self.add_constraint(
            Constraint(
                id="SC-1",
                description="All Write Operations require a cryptographic signature.",
                logic="action.signature is not None",
                scope=["write_db", "delete_record"],
            )
        )

        self.add_constraint(
            Constraint(
                id="FIN-1",
                description="Sell volume cannot exceed current portfolio holdings (No Naked Shorts).",
                logic="sell_amount <= current_holdings",
                scope=["execute_sell"],
            )
        )

    def add_uca(self, uca: STAMP_UCA) -> None:
        self.ucas[uca.id] = uca

    def add_constraint(self, constraint: Constraint) -> None:
        self.constraints[constraint.id] = constraint

    def get_rubric(self) -> list[STAMP_UCA]:
        """Returns the list of all UCAs for Evaluator scoring."""
        return list(self.ucas.values())

    def get_constraints_for_action(self, action_name: str) -> list[Constraint]:
        """Retrieves applicable constraints for a given action."""
        return [c for c in self.constraints.values() if action_name in c.scope]


__all__ = [
    "STAMP_UCA",
    "Constraint",
    "TradingKnowledgeGraph",
]

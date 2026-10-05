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

"""Shared HITL approval-path bundle builder and invariant checks for Provider 02.

The bundle is produced by driving the real ``Provider02AttestationCallback``
through the Governed Financial Advisor approval path, so the hermetic
conformance tests, the committed ``06_hitl_approval.json`` fixture and the
over-the-wire staging case all exercise exactly what CAGE emits:

    safety_check ──► hitl_interrupt ──► governed_trader

Regenerate the committed fixture with::

    uv run python -m tests.integrations.provider_02.hitl_bundle
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from src.cage_finance.graph_topology import FINANCIAL_ADVISOR_TOPOLOGY
from src.integrations.provider_02.adapter import Provider02AttestationCallback

STATE_HASH_PATTERN = re.compile(r"^[a-f0-9]{64}$")

FIXTURE_PATH = (
    Path(__file__).resolve().parents[2]
    / "fixtures"
    / "provider_02_native"
    / "06_hitl_approval.json"
)

_PRE_INTERRUPT_NODES = (
    "nemo_guardrail",
    "thinker_node",
    "doer_node",
    "execution_analyst",
    "evaluator",
    "safety_check",
)
_POST_APPROVAL_NODES = ("governed_trader", "explainer", "nemo_output_rail")


def _agent_state(**overrides: Any) -> dict[str, Any]:
    state: dict[str, Any] = {
        "messages": [],
        "next_step": "evaluator",
        "risk_status": "APPROVED",
        "loop_count": 0,
        "safety_status": "APPROVED",
        "governance_signature": "sig_pre_hitl",
        "risk_attitude": "moderate",
        "investment_period": "long",
        "user_id": "hitl-fixture-user",
        "completed_transactions": [],
        "approval_required": False,
        "approval_decision": None,
        "guardrail_blocked": False,
        "guardrail_reason": "",
    }
    state.update(overrides)
    return state


def _approved_state() -> dict[str, Any]:
    return _agent_state(
        approval_required=True,
        approval_decision={
            "approved": True,
            "reviewer": "reviewer@example.com",
            "rationale": "Trade within acceptable parameters",
            "comment": "",
            "timestamp": "2026-10-04T12:00:00Z",
        },
        governance_signature="sig_hitl_approved",
    )


def build_hitl_approval_bundle(thread_id: str = "hitl-approval-path") -> dict[str, Any]:
    """Drive the adapter through the HITL approval path and return the bundle dict."""
    cb = Provider02AttestationCallback(
        topology=FINANCIAL_ADVISOR_TOPOLOGY, thread_id=thread_id
    )
    pre = _agent_state()
    for node in _PRE_INTERRUPT_NODES:
        cb.on_chain_start(node, pre)
        cb.on_chain_end(node, pre)

    approved = _approved_state()
    cb.handle_hitl_interrupt(approved)

    for node in _POST_APPROVAL_NODES:
        cb.on_chain_start(node, approved)
        cb.on_chain_end(node, approved)

    return cb.get_bundle().to_dict()


def hitl_invariant_violations(bundle: dict[str, Any]) -> list[str]:
    """Return every violation of the three HITL interop invariants (empty = pass).

    1. Every ``stateHash`` (including ``hitl_interrupt``) matches ``^[a-f0-9]{64}$``.
    2. ``hitl_interrupt`` is declared in the topology nodes and attestation nodes.
    3. Lineage is strictly causal: ``hitl_interrupt.parentStepIds == [safety_check]``
       and ``governed_trader.parentStepIds == [hitl_interrupt]``.
    """
    errors: list[str] = []
    steps = bundle.get("steps", [])
    by_node: dict[str, list[dict[str, Any]]] = {}
    for step in steps:
        by_node.setdefault(step.get("nodeName", ""), []).append(step)
        if not STATE_HASH_PATTERN.match(str(step.get("stateHash", ""))):
            errors.append(
                f"{step.get('nodeName')}: stateHash {step.get('stateHash')!r} "
                "does not match ^[a-f0-9]{64}$"
            )

    if "hitl_interrupt" not in FINANCIAL_ADVISOR_TOPOLOGY.nodes:
        errors.append("hitl_interrupt missing from GraphTopology.nodes")
    if "hitl_interrupt" not in FINANCIAL_ADVISOR_TOPOLOGY.attestation_nodes:
        errors.append("hitl_interrupt missing from GraphTopology.attestation_nodes")

    for name in ("safety_check", "hitl_interrupt", "governed_trader"):
        if len(by_node.get(name, [])) != 1:
            errors.append(
                f"expected exactly one {name} step, got {len(by_node.get(name, []))}"
            )
    if errors:
        return errors

    safety = by_node["safety_check"][0]
    hitl = by_node["hitl_interrupt"][0]
    trader = by_node["governed_trader"][0]
    if hitl["parentStepIds"] != [safety["stepId"]]:
        errors.append(
            f"hitl_interrupt.parentStepIds {hitl['parentStepIds']} != [safety_check]"
        )
    if trader["parentStepIds"] != [hitl["stepId"]]:
        errors.append(
            f"governed_trader.parentStepIds {trader['parentStepIds']} != [hitl_interrupt]"
        )
    order = [s["nodeName"] for s in steps]
    if (
        not order.index("safety_check")
        < order.index("hitl_interrupt")
        < order.index("governed_trader")
    ):
        errors.append(f"steps not in causal order: {order}")
    return errors


if __name__ == "__main__":
    bundle = build_hitl_approval_bundle()
    violations = hitl_invariant_violations(bundle)
    if violations:
        raise SystemExit("Refusing to write fixture:\n" + "\n".join(violations))
    FIXTURE_PATH.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {FIXTURE_PATH}")

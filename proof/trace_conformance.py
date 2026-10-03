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

"""Check governance trace events against the formal model (``proof/model.py``).

The gateway emits one ``GOVERNANCE_TRACE`` event per governor decision and one
per actuation (``src/gateway/governance/governor/trace.py``). This module
projects each decision onto a ``proof.model.State`` and checks it against the
model's transition relation instantiated over the run's own plan
(:func:`proof.model.reachable_over`). It imports nothing from ``src/``: the
event schema is the only contract.

Projection. ``plan`` gives the tiers in execution order; ``outcomes`` give
``PASS``/``FAIL`` for the tiers that ran; an absent tier is ``PENDING``. The
model fails closed at the first ``FAIL`` (DENIED or NARROW), whereas the
runtime keeps evaluating past non-HARD findings so a reviewer sees them all.
The projection therefore keeps the first ``FAIL`` and sets every later tier to
``PENDING``. That abstraction cannot hide a seal over a failure: the phase is
kept, and no sealing state with a ``FAIL`` is reachable.

Rules (each finding names one):

* ``schema``: the event has the fields and vocabulary of schema 1.
* ``plan``: no phase-1 tier after a phase-2 tier; every planned tier runs
  under the profile (``runs_under_profile``); outcomes follow plan order.
* ``coverage``: a governed FULL/DRY_RUN run plans every kernel tier; a
  governed POST_HITL run plans ``opa`` and at least one phase-2 tier; an
  ungoverned run plans only ``UNGOVERNED_TIERS``.
* ``seal``: a seal is present iff the phase is ``SEAL_ISSUED`` or ``NARROW``;
  DRY_RUN never seals; ``REQUIRE_APPROVAL``/``DEFER`` are ``CHECKING``.
* ``reachable``: the projected state is reachable in the model. Unsealed
  non-refusals with findings (approval pending, deferral, NARROW candidate)
  are outside the model's alphabet and are checked by ``seal`` only.
* ``no_direct_bind``: an ``EXECUTED`` event joins, by ``seal_ref``, to an
  earlier ``SEAL_ISSUED``/``NARROW`` event; the joined ``EXECUTED`` state is
  reachable (for ``SEAL_ISSUED``) and resolves ALLOW.
* ``single_use``: at most one ``EXECUTED`` event per ``seal_ref``.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from typing import Any

from proof.model import (
    KERNEL_TIERS,
    PHASES,
    PROFILES,
    UNGOVERNED_TIERS,
    State,
    reachable_over,
    runs_under_profile,
)

TRACE_EVENT_TYPE = "GOVERNANCE_TRACE"
TRACE_SCHEMA_VERSION = 1
VERDICTS = frozenset({"ALLOW", "NARROW", "REQUIRE_APPROVAL", "DEFER", "DENY"})
SEALING_PHASES = frozenset({"SEAL_ISSUED", "NARROW"})
PENDING_VERDICTS = frozenset({"REQUIRE_APPROVAL", "DEFER"})


@dataclass(frozen=True)
class Finding:
    """One rule a trace event breaks."""

    index: int
    rule: str
    detail: str


def _plan(event: Mapping[str, Any]) -> tuple[tuple[str, int], ...]:
    return tuple((str(name), int(phase)) for name, phase in event["plan"])


def project(event: Mapping[str, Any]) -> State:
    """The model state a decision event describes (see the module docstring)."""
    plan = _plan(event)
    outcomes = {str(name): str(result) for name, result in event["outcomes"]}
    phase = str(event["phase"])
    results: list[tuple[str, str]] = []
    failed = False
    for name, _ in plan:
        result = "PENDING" if failed else outcomes.get(name, "PENDING")
        failed = failed or result == "FAIL"
        results.append((name, result))
    return State(
        phase=phase,
        tier_results=tuple(results),
        seal_present=bool(event["seal_present"]),
        resolved_allow=phase in SEALING_PHASES,
        profile=str(event["profile"]),
        narrower_present=bool(event.get("narrower_present", False)),
        clamped_params_valid=bool(event.get("clamped_params_valid", False)),
    )


def _schema(event: Mapping[str, Any]) -> list[str]:
    if event.get("type") != TRACE_EVENT_TYPE:
        return [f"type is {event.get('type')!r}"]
    if event.get("schema_version") != TRACE_SCHEMA_VERSION:
        return [f"schema_version is {event.get('schema_version')!r}"]
    if event.get("phase") not in PHASES:
        return [f"unknown phase {event.get('phase')!r}"]
    if event["phase"] == "EXECUTED":
        return [] if event.get("seal_ref") else ["EXECUTED without seal_ref"]
    problems = []
    if event.get("profile") not in PROFILES:
        problems.append(f"unknown profile {event.get('profile')!r}")
    if event.get("verdict") not in VERDICTS:
        problems.append(f"unknown verdict {event.get('verdict')!r}")
    for key in ("plan", "outcomes"):
        if not isinstance(event.get(key), list):
            problems.append(f"{key} is not a list")
    for name, result in event.get("outcomes") or []:
        if result not in ("PASS", "FAIL"):
            problems.append(f"outcome {name}={result!r}")
    return problems


def _plan_rules(event: Mapping[str, Any]) -> list[str]:
    plan = _plan(event)
    problems = []
    phases = [phase for _, phase in plan]
    if phases != sorted(phases):
        problems.append(f"phase-1 tier after a phase-2 tier: {plan}")
    for name, phase in plan:
        if not runs_under_profile(str(event["profile"]), name, phase):
            problems.append(f"{name} (phase {phase}) does not run under {event['profile']}")
    order = [name for name, _ in plan]
    ran = [str(name) for name, _ in event["outcomes"]]
    positions = [order.index(name) for name in ran if name in order]
    if len(positions) != len(ran) or positions != sorted(set(positions)):
        problems.append(f"outcomes {ran} do not follow plan order {order}")
    return problems


def _coverage(event: Mapping[str, Any]) -> list[str]:
    plan = _plan(event)
    names = {name for name, _ in plan}
    if not event.get("governed", True):
        extra = names - UNGOVERNED_TIERS
        return [f"ungoverned run planned {sorted(extra)}"] if extra else []
    if event["profile"] == "POST_HITL":
        problems = [] if "opa" in names else ["POST_HITL did not plan opa"]
        if not any(phase == 2 for _, phase in plan):
            problems.append("POST_HITL planned no phase-2 tier")
        return problems
    missing = [t for t in KERNEL_TIERS if t not in names]
    return [f"governed {event['profile']} run did not plan {missing}"] if missing else []


def _seal(event: Mapping[str, Any]) -> list[str]:
    phase, sealed = event["phase"], bool(event["seal_present"])
    problems = []
    if sealed != (phase in SEALING_PHASES):
        problems.append(f"seal_present={sealed} in phase {phase}")
    if sealed and not event.get("seal_ref"):
        problems.append("seal without seal_ref")
    if event["profile"] == "DRY_RUN" and sealed:
        problems.append("DRY_RUN issued a seal")
    if event["verdict"] in PENDING_VERDICTS and phase != "CHECKING":
        problems.append(f"{event['verdict']} in phase {phase}")
    return problems


def _in_model(event: Mapping[str, Any], state: State) -> bool:
    return state in reachable_over(_plan(event), state.profile)


def check_event(event: Mapping[str, Any]) -> list[tuple[str, str]]:
    """``(rule, detail)`` for every rule a single decision event breaks."""
    problems = [("schema", p) for p in _schema(event)]
    if problems or event["phase"] == "EXECUTED":
        return problems
    problems += [("plan", p) for p in _plan_rules(event)]
    problems += [("coverage", p) for p in _coverage(event)]
    problems += [("seal", p) for p in _seal(event)]
    state = project(event)
    abstracted = state.phase == "CHECKING" and any(r == "FAIL" for _, r in state.tier_results)
    if not abstracted and not _in_model(event, state):
        problems.append(("reachable", f"{state} is not reachable over {_plan(event)}"))
    return problems


def check_trace(events: Iterable[Mapping[str, Any]]) -> list[Finding]:
    """Check a sequence of trace events, in emission order."""
    findings: list[Finding] = []
    issued: dict[str, tuple[Mapping[str, Any], State]] = {}
    executed: set[str] = set()
    for index, event in enumerate(events):
        findings += [Finding(index, rule, detail) for rule, detail in check_event(event)]
        if event.get("type") != TRACE_EVENT_TYPE or event.get("phase") not in PHASES:
            continue
        ref = event.get("seal_ref")
        if event["phase"] in SEALING_PHASES and ref:
            issued[ref] = (event, project(event))
        if event["phase"] != "EXECUTED" or not ref:
            continue
        if ref in executed:
            findings.append(Finding(index, "single_use", f"seal {ref[:16]} executed twice"))
            continue
        executed.add(ref)
        if ref not in issued:
            findings.append(Finding(index, "no_direct_bind", f"seal {ref[:16]} has no issuance"))
            continue
        source, state = issued[ref]
        after = replace(state, phase="EXECUTED", seal_consumed=True)
        if not after.resolved_allow:
            findings.append(Finding(index, "no_direct_bind", "EXECUTED without resolved ALLOW"))
        elif state.phase == "SEAL_ISSUED" and not _in_model(source, after):
            findings.append(Finding(index, "no_direct_bind", f"{after} is not reachable"))
    return findings

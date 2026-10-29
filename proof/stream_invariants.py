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

"""Black-box conformance oracle over the hash-chained evidence stream.

Checks all five CAGE runtime safety invariants and the active-threshold
baseline directly from ``cage-audit/3.0`` records read off ``cage:evidence:stream``
(or exported JSONL), with zero imports from ``src/`` so the external
conformance harness (``packages/cage-conformance``) can reuse this module
unchanged:

1. **No action binds without a routing seal** (``no_direct_bind``,
   ``single_use``): every ``GOVERNANCE_SEAL_CONSUMED`` binds by
   ``decision_record_hash`` to an earlier valid ``GOVERNANCE_DECISION`` with
   matching ``action`` and ``params_hash``, at most once per decision and per
   ``seal_ref``; every actuation receipt (``ACTUATION_RECEIPT``,
   ``ACTUATION_REFUSAL_RECEIPT``, ``ACTUATION_INDETERMINATE_RECEIPT``) binds by
   ``governance_decision_digest`` to an earlier ``GOVERNANCE_SEAL_CONSUMED``,
   at most once per ``seal_ref``.
2. **The control barrier is never breached** (``cbf_barrier``): every
   ``CBF_COMMIT`` satisfies ``h_t = state_before - threshold``,
   ``state_after = state_before - cost``, ``h_next = state_after - threshold``,
   ``h_next >= 0``, and ``h_next >= (1 - gamma) * h_t`` with unique
   ``debit_id``.
3. **A seal implies every stage passed** (``decision_schema``, ``plan``,
   ``coverage``, ``seal``, ``reachable``, ``narrow_reverified``): every
   ``GOVERNANCE_DECISION`` carries schema v2 stage coverage whose projection is
   reachable in :func:`proof.model.reachable_over` (and, on ``NARROW``, whose
   clamped re-run independently plans and passes every stage).
4. **Rollback conserves the balance** (``cbf_rollback``, ``settlement``):
   ``ROLLED_BACK`` restores the exact ledgered ``cost`` of its ``CBF_COMMIT``
   once, ``ROLLED_BACK_UNLEDGERED`` and ``NOOP`` restore ``0.0``, and
   ``GOVERNANCE_SETTLEMENT`` has no failures and agrees with both rollback
   records and actuation outcomes.
5. **Every denial produces an evidence record** (``refusal_evidence``,
   ``evidence_loss``): every refusal record carries a 64-hex ``proof_hash``
   (or ``receipt_digest``), every caller-observed refusal hash appears on the
   stream, observed distinct refusals cover ``expected_refusal_count``, and
   ``publish_failures == 0``.

In addition, ``chain_schema``, ``chain_hash``, and ``chain_continuity`` verify
the ``cage-audit/3.0`` RFC 8785 JCS SHA-256 link hashes, contiguous sequences,
and ``prev_hash`` linkage across the stream, while ``thresholds`` checks the
loaded ``GovernanceThresholds`` digest (POAM-2026-151 Option 2).

Shared specification lineage
----------------------------
While this module imports nothing from ``src/``, it is not independent of the
repository's formal stage model: it imports ``PROFILES``, ``narrow_valid``, and
``reachable_over`` from :mod:`proof.model` (plus stage-plan and coverage
projection helpers from :mod:`proof.trace_conformance`), which share a
specification lineage with the runtime governor's stage selection and tier
ordering in ``src/gateway/governance/governor/``. Agreement between
:mod:`proof.model` and the production pipeline is pinned by
``tests/test_formal_profile_parity.py``,
``tests/test_tier_registry_formal_parity.py``, and
``tests/governor/test_governance_trace_conformance.py``; any external copy of
this oracle relies on that parity contract holding.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Iterable, Mapping
from typing import Any

from proof.model import PROFILES, narrow_valid, reachable_over
from proof.trace_conformance import (
    SEALING_PHASES,
    Finding,
    _coverage,
    _plan,
    _plan_rules,
    project,
)

AUDIT_SCHEMA = "cage-audit/3.0"
CANONICALIZATION = "RFC8785"
HASH_ALGORITHM = "SHA-256"
DECISION_SCHEMA_VERSION = 2

ACTUATION_EVENT_TYPES = frozenset(
    {
        "ACTUATION_RECEIPT",
        "ACTUATION_REFUSAL_RECEIPT",
        "ACTUATION_INDETERMINATE_RECEIPT",
    }
)
ROLLBACK_STATUSES = frozenset({"ROLLED_BACK", "ROLLED_BACK_UNLEDGERED", "NOOP"})
SETTLEMENT_STATUSES = frozenset({"CONFIRMED", "ROLLED_BACK", "FAILED"})

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_ESCAPE_RE = re.compile(r'[\x00-\x1f\\"]')
_ESCAPE_MAP: dict[str, str] = {
    "\\": "\\\\",
    '"': '\\"',
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
    **{chr(i): f"\\u{i:04x}" for i in range(0x20) if chr(i) not in "\b\f\n\r\t"},
}
_EPS = 1e-9


def _is_hex64(value: Any) -> bool:
    return isinstance(value, str) and bool(_HEX64_RE.match(value))


def _is_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def _close(lhs: float, rhs: float) -> bool:
    scale = max(1.0, abs(lhs), abs(rhs))
    return abs(lhs - rhs) <= _EPS * scale


# ---------------------------------------------------------------------------
# Pure-stdlib RFC 8785 JSON Canonicalization Scheme (JCS)
# ---------------------------------------------------------------------------


def _es6_number(value: int | float) -> str:
    """Format an IEEE-754 finite number per ECMAScript / RFC 8785 §3.2.2.3."""
    fvalue = float(value)
    if not math.isfinite(fvalue):
        raise ValueError(f"Non-finite JSON number: {value!r}")
    if fvalue == 0.0:
        return "0"
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) < 10**21:
        # Exact integers below 10^21 serialize as plain base-10 digits in ES6;
        # guard that value round-trips through IEEE-754 double without loss.
        if int(fvalue) == value:
            return str(value)

    raw = str(fvalue)
    sign = ""
    if raw.startswith("-"):
        sign = "-"
        raw = raw[1:]

    exp_str = ""
    exp_val = 0
    exp_idx = raw.find("e")
    if exp_idx > 0:
        exp_str = raw[exp_idx:]
        if exp_str[2:3] == "0":
            exp_str = exp_str[:2] + exp_str[3:]
        raw = raw[:exp_idx]
        exp_val = int(exp_str[1:])

    first = raw
    dot = ""
    last = ""
    dot_idx = raw.find(".")
    if dot_idx > 0:
        dot = "."
        first = raw[:dot_idx]
        last = raw[dot_idx + 1 :]

    if last == "0":
        dot = ""
        last = ""
    if 0 < exp_val < 21:
        first += last
        last = ""
        dot = ""
        exp_str = ""
        zeros = exp_val - len(first)
        if zeros >= 0:
            first += "0" * (zeros + 1)
    elif -7 < exp_val < 0:
        last = ("0" * (-1 - exp_val)) + first + last
        first = "0"
        dot = "."
        exp_str = ""
    return sign + first + dot + last + exp_str


def _jcs_str(value: str) -> str:
    return '"' + _ESCAPE_RE.sub(lambda m: _ESCAPE_MAP[m.group(0)], value) + '"'


def _jcs_encode(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _jcs_str(value)
    if isinstance(value, (int, float)):
        return _es6_number(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_jcs_encode(item) for item in value) + "]"
    if isinstance(value, Mapping):
        items: list[tuple[str, Any]] = []
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"JCS object key must be str, got {type(key).__name__}")
            items.append((key, item))
        items.sort(key=lambda kv: kv[0].encode("utf-16-be"))
        return (
            "{"
            + ",".join(f"{_jcs_str(key)}:{_jcs_encode(item)}" for key, item in items)
            + "}"
        )
    raise TypeError(f"Object of type {type(value).__name__!r} is not JCS serializable")


def jcs_bytes(value: Any) -> bytes:
    """Return RFC 8785 canonical UTF-8 bytes of *value*."""
    return _jcs_encode(value).encode("utf-8")


# ---------------------------------------------------------------------------
# cage-audit/3.0 wire verification
# ---------------------------------------------------------------------------


def _decode_mapping(raw: Any) -> dict[str, Any] | None:
    """Normalize a Redis Stream entry or JSON dict to string-keyed values."""
    if isinstance(raw, tuple) and len(raw) == 2 and isinstance(raw[1], Mapping):
        raw = raw[1]
    if not isinstance(raw, Mapping):
        return None
    out: dict[str, Any] = {}
    for k, v in raw.items():
        key = k.decode("utf-8") if isinstance(k, bytes) else str(k)
        val = v.decode("utf-8") if isinstance(v, bytes) else v
        out[key] = val
    return out


def compute_cage_audit_hash(
    *,
    prev_hash: str,
    sequence: int,
    event_type: str,
    control_id: str,
    payload_json: str,
    chain_id: str,
    trace_id: str,
    classification_reason: str | None = None,
    narrowing_applied: Mapping[str, Any] | None = None,
    pause_token: str | None = None,
) -> str:
    """Recompute the ``cage-audit/3.0`` record hash from wire header + payload."""
    header: dict[str, Any] = {
        "canonicalization": CANONICALIZATION,
        "chain_id": chain_id,
        "control_id": control_id,
        "event_type": event_type,
        "hash_algorithm": HASH_ALGORITHM,
        "schema": AUDIT_SCHEMA,
        "sequence": sequence,
        "trace_id": trace_id,
    }
    if classification_reason is not None:
        header["classification_reason"] = classification_reason
    if narrowing_applied is not None:
        header["narrowing_applied"] = dict(narrowing_applied)
    if pause_token is not None:
        header["pause_token"] = pause_token
    material = (
        prev_hash.encode("utf-8") + jcs_bytes(header) + payload_json.encode("utf-8")
    )
    return hashlib.sha256(material).hexdigest()


def verify_chain_record(
    record: Any,
) -> tuple[list[tuple[str, str]], dict[str, Any] | None, dict[str, Any] | None]:
    """Verify one ``cage-audit/3.0`` record's schema and self-hash.

    Returns ``(problems, normalized_header, payload_dict)``.
    """
    entry = _decode_mapping(record)
    if entry is None:
        return ([("chain_schema", "record is not a mapping")], None, None)

    problems: list[tuple[str, str]] = []
    if entry.get("schema") != AUDIT_SCHEMA:
        problems.append(("chain_schema", f"schema is {entry.get('schema')!r}"))
    if entry.get("canonicalization") != CANONICALIZATION:
        problems.append(
            ("chain_schema", f"canonicalization is {entry.get('canonicalization')!r}")
        )
    if entry.get("hash_algorithm") != HASH_ALGORITHM:
        problems.append(
            ("chain_schema", f"hash_algorithm is {entry.get('hash_algorithm')!r}")
        )

    chain_id = entry.get("chain_id")
    if not isinstance(chain_id, str) or not chain_id:
        problems.append(("chain_schema", "missing chain_id"))
        chain_id = ""

    trace_id = entry.get("trace_id")
    if not isinstance(trace_id, str) or not trace_id:
        problems.append(("chain_schema", "missing trace_id"))
        trace_id = ""

    seq_raw = entry.get("sequence")
    sequence = -1
    if isinstance(seq_raw, bool) or seq_raw is None:
        problems.append(("chain_schema", f"invalid sequence {seq_raw!r}"))
    else:
        try:
            sequence = int(seq_raw)
            if sequence < 0:
                problems.append(("chain_schema", f"negative sequence {sequence}"))
        except (TypeError, ValueError):
            problems.append(("chain_schema", f"non-integer sequence {seq_raw!r}"))

    prev_hash = entry.get("prev_hash")
    if not isinstance(prev_hash, str):
        problems.append(("chain_schema", f"prev_hash is {prev_hash!r}"))
        prev_hash = ""
    elif sequence == 0 and prev_hash != "":
        problems.append(("chain_continuity", "genesis record has non-empty prev_hash"))
    elif sequence > 0 and not _is_hex64(prev_hash):
        problems.append(
            ("chain_continuity", f"sequence {sequence} has invalid prev_hash")
        )

    record_hash = entry.get("record_hash")
    if not _is_hex64(record_hash):
        problems.append(("chain_schema", f"invalid record_hash {record_hash!r}"))
        record_hash = ""

    event_type = entry.get("event_type")
    if not isinstance(event_type, str) or not event_type:
        problems.append(("chain_schema", f"invalid event_type {event_type!r}"))
        event_type = ""

    control_id = entry.get("control_id", "")
    if not isinstance(control_id, str):
        problems.append(("chain_schema", f"invalid control_id {control_id!r}"))
        control_id = ""

    raw_payload = entry.get("payload_json")
    if raw_payload is None:
        raw_payload = entry.get("payload")
    payload_json = ""
    payload_obj: dict[str, Any] | None = None
    if isinstance(raw_payload, str):
        payload_json = raw_payload
        try:
            parsed = json.loads(raw_payload)
            if isinstance(parsed, dict):
                payload_obj = parsed
            else:
                problems.append(("chain_schema", "payload_json is not a JSON object"))
        except json.JSONDecodeError as exc:
            problems.append(("chain_schema", f"malformed payload_json: {exc}"))
    elif isinstance(raw_payload, Mapping):
        payload_obj = dict(raw_payload)
        try:
            payload_json = jcs_bytes(payload_obj).decode("utf-8")
        except (TypeError, ValueError) as exc:
            problems.append(("chain_schema", f"non-canonicalizable payload: {exc}"))
    else:
        problems.append(("chain_schema", "missing payload_json"))

    narrowing_raw = entry.get("narrowing_applied")
    narrowing_applied: Mapping[str, Any] | None = None
    if isinstance(narrowing_raw, str):
        try:
            loaded_narrowing = json.loads(narrowing_raw)
            if isinstance(loaded_narrowing, dict):
                narrowing_applied = loaded_narrowing
            else:
                problems.append(
                    ("chain_schema", "narrowing_applied header is not a JSON object")
                )
        except json.JSONDecodeError as exc:
            problems.append(("chain_schema", f"malformed narrowing_applied: {exc}"))
    elif isinstance(narrowing_raw, Mapping):
        narrowing_applied = narrowing_raw
    elif narrowing_raw is not None:
        problems.append(("chain_schema", "invalid narrowing_applied header"))

    classification_reason = entry.get("classification_reason")
    if classification_reason is not None and not isinstance(classification_reason, str):
        problems.append(("chain_schema", "classification_reason must be str"))
        classification_reason = None

    pause_token = entry.get("pause_token")
    if pause_token is not None and not isinstance(pause_token, str):
        problems.append(("chain_schema", "pause_token must be str"))
        pause_token = None

    if payload_obj is not None and "type" in payload_obj:
        if str(payload_obj["type"]) != event_type:
            problems.append(
                (
                    "chain_schema",
                    f"header event_type {event_type!r} != payload type {payload_obj['type']!r}",
                )
            )

    if not problems and record_hash and sequence >= 0:
        computed = compute_cage_audit_hash(
            prev_hash=prev_hash,
            sequence=sequence,
            event_type=event_type,
            control_id=control_id,
            payload_json=payload_json,
            chain_id=chain_id,
            trace_id=trace_id,
            classification_reason=classification_reason,
            narrowing_applied=narrowing_applied,
            pause_token=pause_token,
        )
        if computed != record_hash:
            problems.append(
                (
                    "chain_hash",
                    f"record_hash mismatch: computed={computed[:16]}... expected={record_hash[:16]}...",
                )
            )

    meta = {
        "chain_id": chain_id,
        "sequence": sequence,
        "prev_hash": prev_hash,
        "record_hash": record_hash,
        "event_type": event_type,
    }
    return (problems, meta, payload_obj)


# ---------------------------------------------------------------------------
# Per-invariant validators
# ---------------------------------------------------------------------------


def _pair_list_problems(payload: Mapping[str, Any], key: str) -> list[str]:
    val = payload.get(key)
    if not isinstance(val, list):
        return [f"{key} is not a list"]
    if any(not isinstance(item, (list, tuple)) or len(item) != 2 for item in val):
        return [f"{key} items must be 2-element pairs"]
    if key.endswith("outcomes"):
        bad = [
            f"{item[0]}={item[1]!r}" for item in val if item[1] not in ("PASS", "FAIL")
        ]
        if bad:
            return [f"invalid outcome(s) in {key}: {', '.join(bad)}"]
    else:
        for item in val:
            if (
                not isinstance(item[0], str)
                or isinstance(item[1], bool)
                or not isinstance(item[1], int)
            ):
                return [f"{key} items must be [tier_name, phase_int]"]
    return []


def _check_decision_payload(payload: Mapping[str, Any]) -> list[tuple[str, str]]:
    """Check Invariant 3 on a ``GOVERNANCE_DECISION`` payload."""
    if payload.get("schema_version") != DECISION_SCHEMA_VERSION:
        return [
            (
                "decision_schema",
                f"GOVERNANCE_DECISION schema_version is {payload.get('schema_version')!r}, expected {DECISION_SCHEMA_VERSION}",
            )
        ]

    schema_problems: list[str] = []
    if not isinstance(payload.get("action"), str) or not payload.get("action"):
        schema_problems.append("missing action")
    if not _is_hex64(payload.get("params_hash")):
        schema_problems.append(f"invalid params_hash {payload.get('params_hash')!r}")
    if payload.get("profile") not in PROFILES:
        schema_problems.append(f"unknown profile {payload.get('profile')!r}")
    if payload.get("verdict") not in ("ALLOW", "NARROW"):
        schema_problems.append(
            f"unexpected decision verdict {payload.get('verdict')!r}"
        )
    if payload.get("phase") not in SEALING_PHASES:
        schema_problems.append(f"unexpected decision phase {payload.get('phase')!r}")
    for bkey in (
        "seal_present",
        "governed",
        "narrower_present",
        "clamped_params_valid",
    ):
        if not isinstance(payload.get(bkey), bool):
            schema_problems.append(f"{bkey} is {payload.get(bkey)!r}")
    schema_problems.extend(_pair_list_problems(payload, "plan"))
    schema_problems.extend(_pair_list_problems(payload, "outcomes"))

    is_narrow = payload.get("phase") == "NARROW" or payload.get("verdict") == "NARROW"
    if is_narrow:
        if not isinstance(payload.get("clamped_governed"), bool):
            schema_problems.append(
                f"clamped_governed is {payload.get('clamped_governed')!r}"
            )
        schema_problems.extend(_pair_list_problems(payload, "clamped_plan"))
        schema_problems.extend(_pair_list_problems(payload, "clamped_outcomes"))

    if schema_problems:
        return [("decision_schema", p) for p in schema_problems]

    problems: list[tuple[str, str]] = []
    problems.extend(("plan", p) for p in _plan_rules(payload))
    problems.extend(("coverage", p) for p in _coverage(payload))

    if payload["seal_present"] is not True:
        problems.append(("seal", "GOVERNANCE_DECISION has seal_present != True"))
    if payload["profile"] == "DRY_RUN":
        problems.append(("seal", "DRY_RUN issued a GOVERNANCE_DECISION seal"))
    expected_phase = "NARROW" if payload["verdict"] == "NARROW" else "SEAL_ISSUED"
    if payload["phase"] != expected_phase:
        problems.append(
            (
                "seal",
                f"verdict {payload['verdict']} disagrees with phase {payload['phase']}",
            )
        )

    state = project(payload)
    if not narrow_valid(state) or state not in reachable_over(
        _plan(payload), state.profile
    ):
        problems.append(
            ("reachable", f"{state} is not reachable over {_plan(payload)}")
        )

    if is_narrow:
        if not payload["narrower_present"] or not payload["clamped_params_valid"]:
            problems.append(
                (
                    "narrow_reverified",
                    "NARROW decision missing narrower_present/clamped_params_valid",
                )
            )
        clamped_event: dict[str, Any] = {
            "profile": payload["profile"],
            "verdict": "ALLOW",
            "phase": "SEAL_ISSUED",
            "seal_present": True,
            "governed": payload["clamped_governed"],
            "narrower_present": False,
            "clamped_params_valid": False,
            "plan": payload["clamped_plan"],
            "outcomes": payload["clamped_outcomes"],
        }
        for p in _plan_rules(clamped_event):
            problems.append(("narrow_reverified", f"clamped plan: {p}"))
        for p in _coverage(clamped_event):
            problems.append(("narrow_reverified", f"clamped coverage: {p}"))
        clamped_state = project(clamped_event)
        if clamped_state not in reachable_over(
            _plan(clamped_event), clamped_state.profile
        ):
            problems.append(
                (
                    "narrow_reverified",
                    f"clamped run {clamped_state} did not pass every planned stage",
                )
            )

    return problems


def _check_cbf_commit(
    payload: Mapping[str, Any], seen_commits: Mapping[str, Mapping[str, Any]]
) -> list[str]:
    """Check Invariant 2 on a ``CBF_COMMIT`` payload."""
    problems: list[str] = []
    debit_id = payload.get("debit_id")
    if not isinstance(debit_id, str) or not debit_id:
        problems.append("CBF_COMMIT missing debit_id")
    elif debit_id in seen_commits:
        problems.append(f"duplicate CBF_COMMIT debit_id {debit_id!r}")

    if not isinstance(payload.get("invariant_id"), str) or not payload.get(
        "invariant_id"
    ):
        problems.append("CBF_COMMIT missing invariant_id")

    numeric_keys = (
        "state_before",
        "cost",
        "state_after",
        "threshold",
        "gamma",
        "h_t",
        "h_next",
    )
    for key in numeric_keys:
        if not _is_number(payload.get(key)):
            problems.append(f"CBF_COMMIT {key}={payload.get(key)!r} is not finite")
    if problems:
        return problems

    state_before = float(payload["state_before"])
    cost = float(payload["cost"])
    state_after = float(payload["state_after"])
    threshold = float(payload["threshold"])
    gamma = float(payload["gamma"])
    h_t = float(payload["h_t"])
    h_next = float(payload["h_next"])

    if cost < -_EPS:
        problems.append(f"CBF_COMMIT negative cost {cost}")
    if not (0.0 < gamma <= 1.0):
        problems.append(f"CBF_COMMIT gamma {gamma} outside (0, 1]")
    if not _close(state_after, state_before - cost):
        problems.append(
            f"state_after={state_after} != state_before - cost ({state_before - cost})"
        )
    if not _close(h_t, state_before - threshold):
        problems.append(
            f"h_t={h_t} != state_before - threshold ({state_before - threshold})"
        )
    if not _close(h_next, state_after - threshold):
        problems.append(
            f"h_next={h_next} != state_after - threshold ({state_after - threshold})"
        )
    if h_next < -_EPS:
        problems.append(f"barrier safe-set breached: h_next={h_next} < 0")
    required = (1.0 - gamma) * h_t
    tol = _EPS * max(1.0, abs(h_next), abs(required))
    if h_next + tol < required:
        problems.append(
            f"barrier decay breached: h_next={h_next} < (1 - gamma) * h_t ({required})"
        )
    return problems


def _check_cbf_rollback(
    payload: Mapping[str, Any],
    *,
    cbf_commits: Mapping[str, Mapping[str, Any]],
    rolled_back_debits: set[str],
    genesis_complete: bool,
) -> list[str]:
    """Check Invariant 4 on a ``CBF_ROLLBACK`` payload."""
    problems: list[str] = []
    debit_id = payload.get("debit_id")
    if not isinstance(debit_id, str) or not debit_id:
        return ["CBF_ROLLBACK missing debit_id"]

    status = payload.get("status")
    if status not in ROLLBACK_STATUSES:
        return [f"CBF_ROLLBACK unknown status {status!r}"]

    for key in ("state_before", "restore", "state_after"):
        if not _is_number(payload.get(key)):
            problems.append(f"CBF_ROLLBACK {key}={payload.get(key)!r} is not finite")
    if problems:
        return problems

    state_before = float(payload["state_before"])
    restore = float(payload["restore"])
    state_after = float(payload["state_after"])

    if status == "ROLLED_BACK":
        if debit_id in rolled_back_debits:
            problems.append(
                f"debit_id {debit_id[:16]} rolled back twice as ROLLED_BACK"
            )
        commit = cbf_commits.get(debit_id)
        if commit is None:
            if genesis_complete:
                problems.append(
                    f"ROLLED_BACK debit_id {debit_id[:16]} has no preceding CBF_COMMIT"
                )
        else:
            expected_cost = float(commit["cost"])
            if not _close(restore, expected_cost):
                problems.append(
                    f"ROLLED_BACK restore={restore} != committed cost={expected_cost}"
                )
        if not _close(state_after, state_before + restore):
            problems.append(
                f"state_after={state_after} != state_before + restore ({state_before + restore})"
            )
        rolled_back_debits.add(debit_id)
    elif status == "ROLLED_BACK_UNLEDGERED":
        if debit_id in rolled_back_debits:
            problems.append(
                f"debit_id {debit_id[:16]} rolled back again as ROLLED_BACK_UNLEDGERED"
            )
        if not _close(restore, 0.0):
            problems.append(f"ROLLED_BACK_UNLEDGERED restored non-zero {restore}")
        if not _close(state_after, state_before):
            problems.append(
                f"ROLLED_BACK_UNLEDGERED mutated state {state_before} -> {state_after}"
            )
        rolled_back_debits.add(debit_id)
    elif status == "NOOP":
        if genesis_complete and debit_id not in rolled_back_debits:
            problems.append(f"NOOP rollback for {debit_id[:16]} without prior rollback")
        if not _close(restore, 0.0):
            problems.append(f"NOOP rollback restored non-zero {restore}")
        if not _close(state_after, state_before):
            problems.append(
                f"NOOP rollback mutated state {state_before} -> {state_after}"
            )

    return problems


# ---------------------------------------------------------------------------
# Stream-level conformance entry point
# ---------------------------------------------------------------------------


def check_stream(
    records: Iterable[Any],
    *,
    expected_thresholds_digest: str | None = None,
    expected_refusal_hashes: Iterable[str] = (),
    expected_refusal_count: int | None = None,
    publish_failures: int = 0,
    require_thresholds_loaded: bool = False,
    require_settled: bool = False,
) -> list[Finding]:
    """Check an ordered slice (or full genesis log) of ``cage:evidence:stream``."""
    findings: list[Finding] = []
    if publish_failures != 0:
        findings.append(
            Finding(
                -1,
                "evidence_loss",
                f"evidence publish failure/shed counter is {publish_failures}",
            )
        )

    chain_id_seen: str | None = None
    prev_seq: int | None = None
    prev_hash_expected: str | None = None
    first_seq: int | None = None

    seen_thresholds_loaded = False
    active_thresholds_digest: str | None = None

    # record_hash -> (decision_payload, is_valid)
    decisions: dict[str, tuple[Mapping[str, Any], bool]] = {}
    consumed_decision_hashes: set[str] = set()
    # seal_ref -> consumed_payload
    consumed_seals: dict[str, Mapping[str, Any]] = {}
    # seal_ref -> actuation event_type
    actuated_seals: dict[str, str] = {}
    # seal_ref -> settlement payload
    settled_seals: dict[str, Mapping[str, Any]] = {}

    # debit_id -> CBF_COMMIT payload
    cbf_commits: dict[str, Mapping[str, Any]] = {}
    rolled_back_debits: set[str] = set()
    confirmed_debits: set[str] = set()

    observed_refusal_hashes: set[str] = set()

    for index, raw_record in enumerate(records):
        rec_problems, meta, payload = verify_chain_record(raw_record)
        for rule, detail in rec_problems:
            findings.append(Finding(index, rule, detail))
        if meta is None or payload is None:
            continue

        seq = meta["sequence"]
        rec_chain_id = meta["chain_id"]
        rec_prev_hash = meta["prev_hash"]
        rec_hash = meta["record_hash"]
        event_type = meta["event_type"]

        if first_seq is None and seq >= 0:
            first_seq = seq
        if chain_id_seen is None and rec_chain_id:
            chain_id_seen = rec_chain_id
        elif (
            chain_id_seen is not None and rec_chain_id and rec_chain_id != chain_id_seen
        ):
            findings.append(
                Finding(
                    index,
                    "chain_continuity",
                    f"chain_id changed from {chain_id_seen} to {rec_chain_id}",
                )
            )

        if prev_seq is not None and seq >= 0:
            if seq != prev_seq + 1:
                findings.append(
                    Finding(
                        index,
                        "chain_continuity",
                        f"non-contiguous sequence: {prev_seq} -> {seq}",
                    )
                )
            if prev_hash_expected is not None and rec_prev_hash != prev_hash_expected:
                findings.append(
                    Finding(
                        index,
                        "chain_continuity",
                        f"prev_hash {rec_prev_hash[:16]}... != prior record_hash {prev_hash_expected[:16]}...",
                    )
                )
        if seq >= 0:
            prev_seq = seq
        if rec_hash:
            prev_hash_expected = rec_hash

        genesis_complete = first_seq == 0

        # -- Thresholds baseline (POAM-2026-151 Option 2) --
        if event_type == "GOVERNANCE_THRESHOLDS_LOADED":
            seen_thresholds_loaded = True
            digest = payload.get("thresholds_digest")
            if not _is_hex64(digest):
                findings.append(
                    Finding(
                        index,
                        "thresholds",
                        f"GOVERNANCE_THRESHOLDS_LOADED invalid thresholds_digest {digest!r}",
                    )
                )
            else:
                active_thresholds_digest = str(digest)
                if (
                    expected_thresholds_digest is not None
                    and digest != expected_thresholds_digest
                ):
                    findings.append(
                        Finding(
                            index,
                            "thresholds",
                            f"loaded thresholds_digest {digest[:16]}... != expected {expected_thresholds_digest[:16]}...",
                        )
                    )

        # -- Invariant 3: A seal implies every stage passed --
        elif event_type == "GOVERNANCE_DECISION":
            digest = payload.get("thresholds_digest")
            if not _is_hex64(digest):
                findings.append(
                    Finding(
                        index,
                        "thresholds",
                        f"GOVERNANCE_DECISION missing/invalid thresholds_digest {digest!r}",
                    )
                )
            else:
                if (
                    active_thresholds_digest is not None
                    and digest != active_thresholds_digest
                ):
                    findings.append(
                        Finding(
                            index,
                            "thresholds",
                            f"decision thresholds_digest {digest[:16]}... != loaded {active_thresholds_digest[:16]}...",
                        )
                    )
                if (
                    expected_thresholds_digest is not None
                    and digest != expected_thresholds_digest
                ):
                    findings.append(
                        Finding(
                            index,
                            "thresholds",
                            f"decision thresholds_digest {digest[:16]}... != expected {expected_thresholds_digest[:16]}...",
                        )
                    )

            dec_problems = _check_decision_payload(payload)
            for rule, detail in dec_problems:
                findings.append(Finding(index, rule, detail))
            if rec_hash:
                decisions[rec_hash] = (payload, len(dec_problems) == 0)

        # -- Invariant 1 (part 1): Seal consumption binds to valid decision --
        elif event_type == "GOVERNANCE_SEAL_CONSUMED":
            seal_ref = payload.get("seal_ref")
            dec_hash = payload.get("decision_record_hash")
            action = payload.get("action")
            params_hash = payload.get("params_hash")
            if not _is_hex64(seal_ref):
                findings.append(
                    Finding(
                        index,
                        "no_direct_bind",
                        f"GOVERNANCE_SEAL_CONSUMED invalid seal_ref {seal_ref!r}",
                    )
                )
                continue
            assert isinstance(seal_ref, str)
            if seal_ref in consumed_seals:
                findings.append(
                    Finding(
                        index,
                        "single_use",
                        f"seal_ref {seal_ref[:16]}... consumed twice",
                    )
                )
                continue
            consumed_seals[seal_ref] = payload

            if not _is_hex64(dec_hash):
                findings.append(
                    Finding(
                        index,
                        "no_direct_bind",
                        f"seal {seal_ref[:16]}... consumed without bound decision_record_hash",
                    )
                )
                continue
            assert isinstance(dec_hash, str)
            if dec_hash in consumed_decision_hashes:
                findings.append(
                    Finding(
                        index,
                        "single_use",
                        f"decision {dec_hash[:16]}... consumed by multiple seals",
                    )
                )
                continue
            consumed_decision_hashes.add(dec_hash)

            if dec_hash not in decisions:
                findings.append(
                    Finding(
                        index,
                        "no_direct_bind",
                        f"seal {seal_ref[:16]}... binds unknown decision {dec_hash[:16]}...",
                    )
                )
                continue
            dec_payload, dec_ok = decisions[dec_hash]
            if not dec_ok:
                findings.append(
                    Finding(
                        index,
                        "no_direct_bind",
                        f"seal {seal_ref[:16]}... binds invalid decision {dec_hash[:16]}...",
                    )
                )
            if action != dec_payload.get("action"):
                findings.append(
                    Finding(
                        index,
                        "no_direct_bind",
                        f"consumed action {action!r} != decision action {dec_payload.get('action')!r}",
                    )
                )
            if params_hash != dec_payload.get("params_hash"):
                findings.append(
                    Finding(
                        index,
                        "no_direct_bind",
                        f"consumed params_hash != decision params_hash for {action!r}",
                    )
                )

        # -- Invariant 1 (part 2): Actuation binds to consumed seal --
        elif event_type in ACTUATION_EVENT_TYPES:
            seal_ref = payload.get("governance_decision_digest")
            if not _is_hex64(seal_ref):
                findings.append(
                    Finding(
                        index,
                        "no_direct_bind",
                        f"{event_type} missing/invalid governance_decision_digest {seal_ref!r}",
                    )
                )
                continue
            assert isinstance(seal_ref, str)
            if seal_ref in actuated_seals:
                findings.append(
                    Finding(
                        index,
                        "single_use",
                        f"seal_ref {seal_ref[:16]}... actuated twice",
                    )
                )
                continue
            actuated_seals[seal_ref] = event_type
            if seal_ref not in consumed_seals:
                findings.append(
                    Finding(
                        index,
                        "no_direct_bind",
                        f"{event_type} for {seal_ref[:16]}... has no preceding GOVERNANCE_SEAL_CONSUMED",
                    )
                )
            else:
                consumed_action = consumed_seals[seal_ref].get("action")
                if payload.get("action") != consumed_action:
                    findings.append(
                        Finding(
                            index,
                            "no_direct_bind",
                            f"{event_type} action {payload.get('action')!r} != consumed action {consumed_action!r}",
                        )
                    )

        # -- Invariant 2: Control barrier is never breached --
        elif event_type == "CBF_COMMIT":
            commit_problems = _check_cbf_commit(payload, cbf_commits)
            for detail in commit_problems:
                findings.append(Finding(index, "cbf_barrier", detail))
            debit_id = payload.get("debit_id")
            if isinstance(debit_id, str) and debit_id and debit_id not in cbf_commits:
                cbf_commits[debit_id] = payload

        # -- Invariant 4 (part 1): Rollback conserves the balance --
        elif event_type == "CBF_ROLLBACK":
            rb_problems = _check_cbf_rollback(
                payload,
                cbf_commits=cbf_commits,
                rolled_back_debits=rolled_back_debits,
                genesis_complete=genesis_complete,
            )
            for detail in rb_problems:
                findings.append(Finding(index, "cbf_rollback", detail))

        # -- Invariant 4 (part 2): Settlement consistency --
        elif event_type == "GOVERNANCE_SETTLEMENT":
            seal_ref = payload.get("seal_ref")
            status = payload.get("status")
            executed = payload.get("executed")
            failures = payload.get("failures")
            debit_ids = payload.get("debit_ids")

            if not _is_hex64(seal_ref):
                findings.append(
                    Finding(
                        index,
                        "settlement",
                        f"GOVERNANCE_SETTLEMENT invalid seal_ref {seal_ref!r}",
                    )
                )
                continue
            assert isinstance(seal_ref, str)
            if seal_ref in settled_seals:
                findings.append(
                    Finding(
                        index,
                        "settlement",
                        f"seal_ref {seal_ref[:16]}... settled twice",
                    )
                )
                continue
            settled_seals[seal_ref] = payload

            if not isinstance(executed, bool) or status not in SETTLEMENT_STATUSES:
                findings.append(
                    Finding(
                        index,
                        "settlement",
                        f"invalid executed={executed!r} / status={status!r}",
                    )
                )
                continue
            if status == "FAILED" or (isinstance(failures, list) and len(failures) > 0):
                findings.append(
                    Finding(
                        index,
                        "settlement",
                        f"settlement failed for {seal_ref[:16]}...: {failures!r}",
                    )
                )
            expected_status = "CONFIRMED" if executed else "ROLLED_BACK"
            if status != "FAILED" and status != expected_status:
                findings.append(
                    Finding(
                        index,
                        "settlement",
                        f"status {status!r} disagrees with executed={executed}",
                    )
                )
            if not isinstance(debit_ids, list) or any(
                not isinstance(d, str) or not d for d in debit_ids
            ):
                findings.append(
                    Finding(
                        index,
                        "settlement",
                        f"invalid debit_ids {debit_ids!r}",
                    )
                )
                continue

            if not executed:
                for d in debit_ids:
                    if d in cbf_commits and d not in rolled_back_debits:
                        findings.append(
                            Finding(
                                index,
                                "settlement",
                                f"ROLLED_BACK settlement missing CBF_ROLLBACK for debit_id {d[:16]}",
                            )
                        )
            else:
                for d in debit_ids:
                    if d in rolled_back_debits:
                        findings.append(
                            Finding(
                                index,
                                "settlement",
                                f"CONFIRMED settlement includes rolled-back debit_id {d[:16]}",
                            )
                        )
                    else:
                        confirmed_debits.add(d)

            act_type = actuated_seals.get(seal_ref)
            if act_type == "ACTUATION_REFUSAL_RECEIPT" and executed:
                findings.append(
                    Finding(
                        index,
                        "settlement",
                        f"seal {seal_ref[:16]}... settled executed=True after ACTUATION_REFUSAL_RECEIPT",
                    )
                )
            elif (
                act_type in ("ACTUATION_RECEIPT", "ACTUATION_INDETERMINATE_RECEIPT")
                and not executed
            ):
                findings.append(
                    Finding(
                        index,
                        "settlement",
                        f"seal {seal_ref[:16]}... settled executed=False after {act_type}",
                    )
                )

        # -- Invariant 5: Refusal evidence records --
        elif event_type == "GOVERNANCE_REFUSAL":
            receipt = payload.get("receipt")
            ph = receipt.get("proof_hash") if isinstance(receipt, Mapping) else None
            if not _is_hex64(ph):
                findings.append(
                    Finding(
                        index,
                        "refusal_evidence",
                        f"GOVERNANCE_REFUSAL missing/invalid receipt.proof_hash {ph!r}",
                    )
                )
            else:
                observed_refusal_hashes.add(str(ph))

        elif event_type == "GOVERNANCE_REFUSAL_RECEIPT":
            ph = payload.get("proof_hash") or payload.get("receipt_digest")
            if not _is_hex64(ph):
                findings.append(
                    Finding(
                        index,
                        "refusal_evidence",
                        f"GOVERNANCE_REFUSAL_RECEIPT missing/invalid proof_hash/receipt_digest {ph!r}",
                    )
                )
            else:
                observed_refusal_hashes.add(str(ph))

    # -- Post-stream completeness checks --
    if require_thresholds_loaded and not seen_thresholds_loaded:
        findings.append(
            Finding(
                -1,
                "thresholds",
                "no GOVERNANCE_THRESHOLDS_LOADED record found on stream",
            )
        )

    if require_settled:
        for debit_id in cbf_commits:
            if debit_id not in confirmed_debits and debit_id not in rolled_back_debits:
                findings.append(
                    Finding(
                        -1,
                        "settlement",
                        f"CBF_COMMIT debit_id {debit_id[:16]} was neither confirmed nor rolled back",
                    )
                )

    for expected_hash in expected_refusal_hashes:
        if expected_hash not in observed_refusal_hashes:
            findings.append(
                Finding(
                    -1,
                    "refusal_evidence",
                    f"expected refusal proof_hash {expected_hash[:16]}... missing from stream",
                )
            )

    if (
        expected_refusal_count is not None
        and len(observed_refusal_hashes) < expected_refusal_count
    ):
        findings.append(
            Finding(
                -1,
                "refusal_evidence",
                f"observed {len(observed_refusal_hashes)} distinct refusal(s) < expected {expected_refusal_count}",
            )
        )

    return findings

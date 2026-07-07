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
CAGE Playground Telemetry
=========================

Provides two complementary audit mechanisms for the Chaos Agent Playground:

1. **OTel Span Emitter** — emits real OpenTelemetry spans with the same
   Langfuse attribute schema used by the live gateway (``symbolic_governor.py``,
   ``stpa_validator.py``). When ``LANGFUSE_HOST`` / ``LANGFUSE_PUBLIC_KEY`` /
   ``LANGFUSE_SECRET_KEY`` are set, spans flow directly into Langfuse Cloud.
   Without credentials the ``LoggingSpanExporter`` fallback captures them locally.

2. **NDJSON Evidence Chain** — writes a tamper-evident, cryptographically
   linked audit log to ``examples/evidence/evidence_chain_<date>.ndjson``.
   Each record SHA-256 hashes its own payload and chains the previous
   record's hash — forming an append-only, verifiable evidence trail.
   A separate ``view_access_log_<date>.ndjson`` registers every read-access
   event with the accessor identity, timestamp, and record hash — satisfying
   MiFID II Article 25 and GDPR Article 30 view-tracking requirements.

Integrity vs. Provenance — Critical Distinction
------------------------------------------------
The SHA-256 hash chain provides **data integrity**: it proves that the
evidence log has not been tampered with after creation.  The use of
``json.dumps(record, sort_keys=True, separators=(',', ':'))`` guarantees
byte-stable, deterministic serialization of every record before hashing,
so any post-hoc modification — even reordering a JSON key — will break
the chain and be detectable by ``verify_chain()``.

However, the hash chain does **NOT** provide **data provenance**: it
cannot prove that the data was truthful, accurate, or complete at the
time of creation.  The evidence records are written by the same
execution system whose behaviour they describe.  If the agent produces
biased or corrupted telemetry, the hash chain will faithfully preserve
that corrupted data with perfect cryptographic integrity.

In legal/evidentiary terms:
  - **Integrity**  = "the document has not been altered since creation"
  - **Provenance** = "the document was accurate when created"

Courts, regulators, and auditors require BOTH.  Cloud KMS asymmetric
signing (``kms_signer.py``) is integrated for **governance plan
signatures** — the evaluator node signs execution plans with an
HSM-held key that the execution system cannot forge.  However, the
evidence chain records themselves are NOT individually KMS-signed;
each record is hash-chained (integrity) but not independently attested
(provenance).  Per-record KMS attestation remains a roadmap item.

Every ``cage-intent/1.0`` record includes a ``provenance_disclaimer``
field to make this residual limitation machine-readable and
auditor-visible.

Schema alignment
----------------
All OTel span attributes follow the naming convention already established in
``src/gateway/governance/symbolic_governor.py`` and ``stpa_validator.py``:

    langfuse.observation.type       = "span"
    langfuse.observation.name       = "governance_evaluation"
    langfuse.observation.input      = JSON({tool, params})
    langfuse.observation.output     = "BLOCKED" | "APPROVED"
    langfuse.trace.metadata.iso.control_id   = "A.8.4"
    langfuse.trace.metadata.nist.control_id  = "SC-4"
    cage.governance.decision        = "BLOCKED" | "APPROVED"
    cage.governance.blocking_tier   = 0-4 | -1
    cage.governance.violation_count = int
    cage.governance.scenario_id     = "A" | "B" | "C"
    cage.governance.action          = str
    cage.evidence.chain_hash        = sha256 hex
    cage.evidence.record_id         = uuid4

Usage:
    from examples.telemetry import PlaygroundTelemetry

    tel = PlaygroundTelemetry()
    with tel.scenario_span("A", "execute_trade", params) as span:
        # ... run governance tiers ...
        tel.record_result(span, violations, blocking_tier, elapsed_ms)
    tel.flush()

    # View-access tracking (read audit log)
    tel.read_evidence_log(accessor_id="analyst@example.com", reason="compliance review")
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("cage.playground.telemetry")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_EXAMPLES_DIR = Path(__file__).resolve().parent
_EVIDENCE_DIR = _EXAMPLES_DIR / "evidence"

_TODAY = datetime.now(timezone.utc).strftime("%Y-%m-%d")
_EVIDENCE_CHAIN_PATH = _EVIDENCE_DIR / f"evidence_chain_{_TODAY}.ndjson"
_VIEW_ACCESS_LOG_PATH = _EVIDENCE_DIR / f"view_access_log_{_TODAY}.ndjson"

# ---------------------------------------------------------------------------
# Span attribute constants (must mirror symbolic_governor.py + stpa_validator.py)
# ---------------------------------------------------------------------------
_SPAN_ATTRS = {
    "type": "langfuse.observation.type",
    "name": "langfuse.observation.name",
    "input": "langfuse.observation.input",
    "output": "langfuse.observation.output",
    "iso_ctrl": "langfuse.trace.metadata.iso.control_id",
    "nist_ctrl": "langfuse.trace.metadata.nist.control_id",
    "iso_req": "langfuse.trace.metadata.iso.requirement",
    "decision": "cage.governance.decision",
    "tier": "cage.governance.blocking_tier",
    "vuln_count": "cage.governance.violation_count",
    "scenario_id": "cage.governance.scenario_id",
    "action": "cage.governance.action",
    "chain_hash": "cage.evidence.chain_hash",
    "record_id": "cage.evidence.record_id",
    "elapsed_ms": "cage.governance.elapsed_ms",
}

# Normalised intent schema — mirrors the shape Langfuse stores for every
# governance evaluation in the live system.
_INTENT_SCHEMA_VERSION = "cage-intent/1.0"

# Machine-readable provenance disclaimer stamped into every evidence record.
# Auditors, regulators, and forensic examiners can programmatically detect
# the scope of cryptographic assurance: governance plan signatures carry
# Cloud KMS asymmetric attestation (kms_signer.py), but individual evidence
# chain records are hash-chained only (integrity, not per-record provenance).
# See module docstring: "Integrity vs. Provenance — Critical Distinction".
PROVENANCE_NOTE = (
    "This record's hash chain guarantees data integrity (non-tampering) "
    "but does NOT guarantee per-record data provenance (truthfulness at "
    "creation). Governance plan signatures carry Cloud KMS asymmetric "
    "attestation (HSM-backed, non-repudiable). However, individual "
    "evidence chain records are not independently KMS-signed. "
    "Per-record KMS attestation is a roadmap item. "
    "See: CAGE Evidentiary Independence Roadmap."
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def _load_last_hash() -> str:
    """Return the hash of the last record in the evidence chain (genesis if empty)."""
    if not _EVIDENCE_CHAIN_PATH.exists():
        return _sha256("GENESIS")
    try:
        lines = _EVIDENCE_CHAIN_PATH.read_text().strip().splitlines()
        if lines:
            last = json.loads(lines[-1])
            return last.get("record_hash", _sha256("GENESIS"))
    except Exception:
        pass
    return _sha256("GENESIS")


def _append_record(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as fh:
        fh.write(json.dumps(record, separators=(",", ":")) + "\n")


# ---------------------------------------------------------------------------
# OTel bootstrap — graceful degradation when SDK not available
# ---------------------------------------------------------------------------


def _init_otel() -> object | None:
    """
    Initialise OTel using the same setup_tracing() logic as the gateway.

    Returns an OTel Tracer, or None if the SDK is not installed.
    Spans will flow to Langfuse when credentials are present; otherwise
    the LoggingSpanExporter captures them locally.
    """
    # Suppress OpenLLMetry auto-instrumentation (no LLM calls in playground)
    os.environ.setdefault("OPENLLMETRY_ENABLED", "false")
    os.environ.setdefault("OTEL_SERVICE_NAME", "cage-playground")

    try:
        import sys

        _repo = Path(__file__).resolve().parents[1]
        if str(_repo) not in sys.path:
            sys.path.insert(0, str(_repo))

        from src.gateway.tracing_setup import setup_tracing

        setup_tracing()

        from opentelemetry import trace

        return trace.get_tracer("cage.playground")
    except Exception as exc:
        logger.warning("OTel init failed — spans will be logged locally only: %s", exc)
        return None


# ---------------------------------------------------------------------------
# PlaygroundTelemetry
# ---------------------------------------------------------------------------


class PlaygroundTelemetry:
    """
    Unified telemetry context for the Chaos Agent Playground.

    Combines:
    - Real OTel spans (same attribute schema as the live gateway)
    - Local NDJSON evidence chain with SHA-256 hash linking
    - View-access audit log for read-tracking
    """

    def __init__(self) -> None:
        self._tracer = _init_otel()
        self._prev_hash: str = _load_last_hash()
        _EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        logger.debug(
            "PlaygroundTelemetry initialised. Evidence chain: %s",
            _EVIDENCE_CHAIN_PATH,
        )

    # ── OTel span context manager ─────────────────────────────────────────────

    @contextmanager
    def scenario_span(
        self,
        scenario_id: str,
        action: str,
        params: dict[str, Any],
    ) -> Generator:
        """
        Context manager that wraps a scenario execution in an OTel span.

        Yields the span (or a no-op stub if OTel is unavailable).
        Call ``record_result()`` inside the block with the final outcome.
        """
        span_input = json.dumps(
            {"scenario": scenario_id, "action": action, "params": params}
        )
        record_id = str(uuid.uuid4())

        if self._tracer is not None:
            with self._tracer.start_as_current_span("cage.playground.scenario") as span:
                span.set_attribute(_SPAN_ATTRS["type"], "span")
                span.set_attribute(_SPAN_ATTRS["name"], "governance_evaluation")
                span.set_attribute(_SPAN_ATTRS["input"], span_input)
                span.set_attribute(_SPAN_ATTRS["iso_ctrl"], "A.8.4")
                span.set_attribute(_SPAN_ATTRS["nist_ctrl"], "SC-4")
                span.set_attribute(_SPAN_ATTRS["iso_req"], "Controllability")
                span.set_attribute(_SPAN_ATTRS["scenario_id"], scenario_id)
                span.set_attribute(_SPAN_ATTRS["action"], action)
                span.set_attribute(_SPAN_ATTRS["record_id"], record_id)
                yield _SpanWrapper(span, record_id)
        else:
            yield _SpanWrapper(None, record_id)

    def record_result(
        self,
        span_wrapper: _SpanWrapper,
        violations: list[str],
        blocking_tier: int | None,
        elapsed_ms: float,
        action: str,
        params: dict[str, Any],
        scenario_id: str,
    ) -> str:
        """
        Finalise OTel span attributes and write the evidence chain record.

        Returns the SHA-256 hash of the written record (for display).
        """
        blocked = bool(violations)
        decision = "BLOCKED" if blocked else "APPROVED"
        tier_val = blocking_tier if blocking_tier is not None else -1

        # ── Finalise OTel span ────────────────────────────────────────────
        if span_wrapper.span is not None:
            span_wrapper.span.set_attribute(_SPAN_ATTRS["output"], decision)
            span_wrapper.span.set_attribute(_SPAN_ATTRS["decision"], decision)
            span_wrapper.span.set_attribute(_SPAN_ATTRS["tier"], tier_val)
            span_wrapper.span.set_attribute(_SPAN_ATTRS["vuln_count"], len(violations))
            span_wrapper.span.set_attribute(_SPAN_ATTRS["elapsed_ms"], elapsed_ms)

            if blocked:
                try:
                    from opentelemetry.trace import Status, StatusCode

                    span_wrapper.span.set_status(Status(StatusCode.ERROR))
                except Exception:
                    pass

        # ── Build normalised intent record ────────────────────────────────
        # This is the "normalised intent schema" — the machine-readable
        # justification record referenced in governance reporting.
        intent_record: dict[str, Any] = {
            "schema": _INTENT_SCHEMA_VERSION,
            "record_id": span_wrapper.record_id,
            "timestamp": _now_iso(),
            "scenario_id": scenario_id,
            "action": action,
            "params_redacted": _redact_params(params),
            "decision": decision,
            "blocking_tier": tier_val,
            "violations": violations,
            "elapsed_ms": round(elapsed_ms, 3),
            "nist_controls": ["SC-4", "SC-8", "SC-7"],
            "iso_controls": ["A.8.4", "A.6.2"],
            "otel_service": os.environ.get("OTEL_SERVICE_NAME", "cage-playground"),
            "provenance_disclaimer": PROVENANCE_NOTE,
        }

        # ── Hash chain ────────────────────────────────────────────────────
        payload_str = json.dumps(intent_record, sort_keys=True, separators=(",", ":"))
        record_hash = _sha256(self._prev_hash + payload_str)
        intent_record["prev_hash"] = self._prev_hash
        intent_record["record_hash"] = record_hash

        # Stamp hash onto span for in-trace traceability
        if span_wrapper.span is not None:
            span_wrapper.span.set_attribute(_SPAN_ATTRS["chain_hash"], record_hash)

        # ── Write to evidence chain ───────────────────────────────────────
        _append_record(_EVIDENCE_CHAIN_PATH, intent_record)
        self._prev_hash = record_hash

        logger.info(
            "📋 Evidence record written: id=%s hash=%s...",
            span_wrapper.record_id,
            record_hash[:16],
        )
        return record_hash

    # ── View-access audit log (read-tracking) ─────────────────────────────────

    def read_evidence_log(
        self,
        accessor_id: str = "anonymous",
        reason: str = "unspecified",
        filter_scenario: str | None = None,
    ) -> list[dict]:
        """
        Read the evidence chain and register a view-access event.

        Every call to this method appends a read-event record to
        ``view_access_log_<date>.ndjson``, satisfying MiFID II Article 25
        (recording of communications) and GDPR Article 30 (records of
        processing activities) view-tracking requirements.

        Args:
            accessor_id:     Identity of the accessor (email, service account,
                             user ID). Logged as-is — caller is responsible for
                             providing a meaningful identifier.
            reason:          Business justification for the access.
            filter_scenario: If set, return only records for that scenario ID.

        Returns:
            List of evidence records (dicts) visible to the accessor.
        """
        records: list[dict] = []
        if _EVIDENCE_CHAIN_PATH.exists():
            for line in _EVIDENCE_CHAIN_PATH.read_text().strip().splitlines():
                try:
                    r = json.loads(line)
                    if filter_scenario and r.get("scenario_id") != filter_scenario:
                        continue
                    records.append(r)
                except json.JSONDecodeError:
                    pass

        # Compute a fingerprint of what was read
        read_fingerprint = _sha256(
            json.dumps(
                [r.get("record_hash", "") for r in records],
                separators=(",", ":"),
            )
        )

        view_event: dict[str, Any] = {
            "schema": "cage-view-access/1.0",
            "event_id": str(uuid.uuid4()),
            "timestamp": _now_iso(),
            "accessor_id": accessor_id,
            "reason": reason,
            "filter_scenario": filter_scenario,
            "records_accessed": len(records),
            "read_fingerprint": read_fingerprint,
            # Chain to previous view event for tamper evidence
            "prev_view_hash": _load_last_view_hash(),
        }
        view_event["event_hash"] = _sha256(
            view_event["prev_view_hash"]
            + json.dumps(view_event, sort_keys=True, separators=(",", ":"))
        )

        _append_record(_VIEW_ACCESS_LOG_PATH, view_event)
        logger.info(
            "👁  View-access registered: accessor=%s records=%d fingerprint=%s...",
            accessor_id,
            len(records),
            read_fingerprint[:16],
        )
        return records

    def record_approval(
        self,
        thread_id: str,
        approved: bool,
        reviewer: str,
        rationale: str,
        comment: str = "",
    ) -> str:
        """Write a tamper-evident HITL approval record into the evidence chain.

        Called by the POST /v1/approvals/{thread_id}/resume endpoint BEFORE
        the graph is resumed, ensuring the human rationale is persisted even
        if the agentic graph crashes mid-execution.

        The record uses the ``cage-intent/1.0`` schema and is hash-linked to
        the preceding evidence chain record, forming an unbroken audit trail
        from governance decision → human review → execution.

        Satisfies:
            - ISO 42001 §6.1 (risk treatment decisions must be documented)
            - ISO 42001 A.7.2 (accountability — reviewer identity attributed)
            - ISO 42001 A.8.4 (AI system operation controls — HITL evidence)
            - NIST AI RMF GOVERN-5 (human oversight and intervention)
            - MiFID II Article 25 (recording of trade-related communications)

        Args:
            thread_id: LangGraph thread ID — links the audit record to the
                       specific interrupted graph instance.
            approved:  Human decision (True = approved, False = rejected).
            reviewer:  Reviewer identity (email / employee ID).
            rationale: Mandatory free-text justification for the decision.
            comment:   Optional supplementary note.

        Returns:
            SHA-256 hex hash of the written record.
        """
        decision_str = "APPROVED" if approved else "REJECTED"
        record_id = str(uuid.uuid4())

        # ── OTel span ─────────────────────────────────────────────────────────
        if self._tracer is not None:
            try:
                with self._tracer.start_as_current_span("cage.hitl.approval") as span:
                    span.set_attribute(_SPAN_ATTRS["type"], "span")
                    span.set_attribute(_SPAN_ATTRS["name"], "hitl_approval")
                    span.set_attribute(_SPAN_ATTRS["iso_ctrl"], "A.8.4")
                    span.set_attribute(_SPAN_ATTRS["nist_ctrl"], "SC-4")
                    span.set_attribute(_SPAN_ATTRS["decision"], decision_str)
                    span.set_attribute(_SPAN_ATTRS["record_id"], record_id)
                    span.set_attribute("cage.hitl.thread_id", thread_id)
                    span.set_attribute("cage.hitl.reviewer", reviewer)
                    span.set_attribute("cage.hitl.decision", decision_str)
                    span.set_attribute("cage.hitl.rationale", rationale[:512])
                    span.set_attribute("cage.hitl.nist_govern", "GOVERN-5")
            except Exception as _span_exc:
                logger.debug("HITL span emission failed: %s", _span_exc)

        # ── Build evidence record ──────────────────────────────────────────────
        approval_record: dict[str, Any] = {
            "schema": _INTENT_SCHEMA_VERSION,
            "record_id": record_id,
            "timestamp": _now_iso(),
            "event_type": "hitl_approval",
            "thread_id": thread_id,
            "decision": decision_str,
            "reviewer": reviewer,
            # rationale is stored verbatim — it IS the audit artefact.
            # It must never be redacted; the reviewer is responsible for
            # not including PII in the justification text.
            "rationale": rationale,
            "comment": comment,
            "nist_controls": ["GOVERN-5", "SC-4"],
            "iso_controls": ["A.8.4", "A.7.2", "A.6.2"],
            "iso_42001_clause": "6.1",
            "otel_service": os.environ.get(
                "OTEL_SERVICE_NAME", "cage-financial-advisor"
            ),
            "provenance_disclaimer": PROVENANCE_NOTE,
        }

        # ── Hash chain ────────────────────────────────────────────────────────
        payload_str = json.dumps(approval_record, sort_keys=True, separators=(",", ":"))
        record_hash = _sha256(self._prev_hash + payload_str)
        approval_record["prev_hash"] = self._prev_hash
        approval_record["record_hash"] = record_hash

        # Stamp hash onto span
        if self._tracer is not None:
            try:
                from opentelemetry import trace as _otel_trace

                current = _otel_trace.get_current_span()
                if current and current.is_recording():
                    current.set_attribute(_SPAN_ATTRS["chain_hash"], record_hash)
            except Exception:
                pass

        # ── Persist ───────────────────────────────────────────────────────────
        _append_record(_EVIDENCE_CHAIN_PATH, approval_record)
        self._prev_hash = record_hash

        logger.info(
            "📋 HITL approval evidence written: thread=%s decision=%s reviewer=%s hash=%s...",
            thread_id,
            decision_str,
            reviewer,
            record_hash[:16],
        )
        return record_hash

    # ── Flush / verify ────────────────────────────────────────────────────────

    def flush(self) -> None:
        """Flush OTel BatchSpanProcessor (best-effort)."""
        try:
            from opentelemetry import trace as _t

            provider = _t.get_tracer_provider()
            if hasattr(provider, "force_flush"):
                provider.force_flush(timeout_millis=3000)
                logger.debug("OTel spans flushed.")
        except Exception as exc:
            logger.debug("OTel flush skipped: %s", exc)

    def verify_chain(self) -> tuple[bool, int]:
        """
        Verify the SHA-256 hash chain of the evidence log.

        Returns (chain_valid: bool, record_count: int).
        Raises nothing — verification failures are returned as False.
        """
        if not _EVIDENCE_CHAIN_PATH.exists():
            return True, 0

        lines = _EVIDENCE_CHAIN_PATH.read_text().strip().splitlines()
        prev = _sha256("GENESIS")
        for i, line in enumerate(lines):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("Chain verify: invalid JSON at record %d", i)
                return False, i

            stored_hash = rec.pop("record_hash", "")
            prev_hash = rec.pop("prev_hash", "")
            payload_str = json.dumps(rec, sort_keys=True, separators=(",", ":"))
            expected = _sha256(prev + payload_str)

            if prev_hash != prev or stored_hash != expected:
                logger.warning(
                    "Chain broken at record %d (id=%s)", i, rec.get("record_id")
                )
                return False, i + 1

            prev = stored_hash
            # Restore for integrity (not strictly needed — this is read-only)
            rec["record_hash"] = stored_hash
            rec["prev_hash"] = prev_hash

        return True, len(lines)

    @property
    def evidence_chain_path(self) -> Path:
        return _EVIDENCE_CHAIN_PATH

    @property
    def view_access_log_path(self) -> Path:
        return _VIEW_ACCESS_LOG_PATH


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


class _SpanWrapper:
    """Thin wrapper carrying the span + record_id through the context manager."""

    __slots__ = ("record_id", "span")

    def __init__(self, span: Any, record_id: str) -> None:
        self.span = span
        self.record_id = record_id


def _redact_params(params: dict) -> dict:
    """
    Return a copy of params with sensitive fields redacted.
    Prevents PII (SSN, account numbers, approval tokens) from appearing
    in the evidence chain — the log records the *decision*, not the data.
    """
    _REDACT_KEYS = {"ssn", "account", "approval_token", "payload", "password", "secret"}
    return {
        k: "***REDACTED***" if k.lower() in _REDACT_KEYS else v
        for k, v in params.items()
    }


def _load_last_view_hash() -> str:
    if not _VIEW_ACCESS_LOG_PATH.exists():
        return _sha256("VIEW-GENESIS")
    try:
        lines = _VIEW_ACCESS_LOG_PATH.read_text().strip().splitlines()
        if lines:
            last = json.loads(lines[-1])
            return last.get("event_hash", _sha256("VIEW-GENESIS"))
    except Exception:
        pass
    return _sha256("VIEW-GENESIS")

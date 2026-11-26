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

"""Post-execution output sanitizer coordinator (Layer 1 kernel, POAM-2026-253).

Shared by both committing-tool transports (``POST /tools/execute`` in
``mcp_tool_server.py`` and ``/mcp/`` in ``mcp_tracing.py``) so neither can
convert an executed or may-have-executed committing run into a refusal.

Core invariant ("don't refuse after execution"):

* Once a committing run may have executed — either the active kernel
  :class:`~src.gateway.governance.execution_idempotency.ActuationAttempt`
  reports ``may_have_executed is True`` (``EXECUTED`` or ``UNKNOWN``), **or**
  the tool returned a structured :class:`CommitOutcome` in
  ``{EXECUTED, INDETERMINATE, UNSETTLED_DUPLICATE}`` (covering same-key
  execution-ledger replays that return before ``dispatch_actuation()``) — a
  pattern hit from :func:`detect_indirect_injection` MUST NOT convert the
  answer into a refusal, MUST NOT set the per-request refusal flag, and MUST
  NOT stamp ISO 42001 ``A.9.2`` ``BLOCK``.
* Instead, untrusted agent-facing text is replaced with a constant placeholder
  carrying zero actuator or caller bytes (:data:`REDACTED_POST_EXEC_MESSAGE`),
  the structured :class:`CommitOutcome` is preserved (or synthesized from
  ``ActuationAttempt`` when the tool returned a plain dict/string), operational
  non-block span attributes are recorded, and a non-refusal
  ``POST_EXECUTION_OUTPUT_SANITIZED`` (``controlId="SI-15"``) record is
  appended to ``cage:evidence:stream``.
* When no side effect may have occurred (read-only tools, ``DRY_RUN``,
  ``REFUSED``, ``DEFERRED``, or a definitive actuator ``REJECTED`` receipt),
  the blocking refusal path (ISO 42001 ``A.9.2`` ``BLOCK``, HTTP ``403`` /
  ``PermissionError``, ``mark_request_refused()``) is preserved unchanged.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Final

from src.gateway.governance.commit_outcome import (
    CommitOutcome,
    CommitOutcomeDecodeError,
    CommitStatus,
)
from src.gateway.governance.execution_idempotency import (
    ActuationAttempt,
    ExecutionStatus,
    current_actuation_attempt,
    outcome_after_dispatch,
)
from src.gateway.governance.iso_control import stamp_iso_control
from src.gateway.governance.prompt_injection_detector import (
    detect_indirect_injection,
)

logger = logging.getLogger("Gateway.Governance.PostExecutionSanitizer")

#: Constant agent-facing placeholder used when a post-execution sanitizer hit
#: redacts output from an executed or may-have-executed committing run. Carries
#: zero bytes from the actuator or caller.
REDACTED_POST_EXEC_MESSAGE: Final[str] = (
    "[REDACTED: post-execution tool output withheld by indirect "
    "prompt-injection filter ({violation}); consult evidence chain for receipt]"
)

#: Structured ``CommitStatus`` values whose outcome indicates a prior or current
#: run executed or may have executed (including same-key ledger replays).
POST_EXEC_PROTECTED_COMMIT_STATUSES: Final[frozenset[CommitStatus]] = frozenset(
    {
        CommitStatus.EXECUTED,
        CommitStatus.INDETERMINATE,
        CommitStatus.UNSETTLED_DUPLICATE,
    }
)

#: Dedicated non-refusal evidence event type emitted when post-execution tool
#: output is redacted without converting the execution outcome into a refusal.
POST_EXECUTION_SANITIZER_EVENT_TYPE: Final[str] = "POST_EXECUTION_OUTPUT_SANITIZED"


@dataclass(frozen=True)
class SanitizationOutcome:
    """Decision returned by :func:`evaluate_post_execution_output`.

    Attributes:
        violation: Violation identifier (``indirect_injection:<pattern>``) or
            ``None`` when clean.
        pattern_matched: Detector pattern name or ``None`` when clean.
        post_exec_protected: Whether the run executed or may have executed.
        redacted_message: Constant placeholder text when ``redacted`` is True.
        redacted_outcome: Preserved or synthesized ``CommitOutcome`` carrying
            ``redacted_message`` when ``redacted`` is True.
        evidence_msg_id: Stream message ID of the ``POST_EXECUTION_OUTPUT_SANITIZED``
            event when ingested, else ``None``.
    """

    violation: str | None
    pattern_matched: str | None
    post_exec_protected: bool
    redacted_message: str | None = None
    redacted_outcome: CommitOutcome | None = None
    evidence_msg_id: str | None = None

    @property
    def blocked(self) -> bool:
        """True iff the transport must refuse the response (no side effect occurred)."""
        return self.violation is not None and not self.post_exec_protected

    @property
    def redacted(self) -> bool:
        """True iff the transport must preserve the outcome with redacted output."""
        return self.violation is not None and self.post_exec_protected


def _recording_span(span: Any) -> Any:
    """Return ``span`` only if it is present and recording."""
    if span is None:
        return None
    is_rec = getattr(span, "is_recording", None)
    if callable(is_rec) and not is_rec():
        return None
    return span


def extract_tool_output_text(result: Any) -> str:
    """Extract scannable text from raw or FastMCP-converted tool outputs."""
    if isinstance(result, str):
        return result
    if result is None:
        return ""
    if isinstance(result, Mapping):
        return json.dumps(dict(result), default=str)
    content_attr = getattr(result, "content", None)
    structured_attr = getattr(result, "structuredContent", None)
    if isinstance(content_attr, (list, tuple)) or isinstance(structured_attr, Mapping):
        extracted_parts: list[str] = []
        if isinstance(content_attr, (list, tuple)):
            extracted_parts.append(extract_tool_output_text(content_attr))
        if isinstance(structured_attr, Mapping):
            extracted_parts.append(json.dumps(dict(structured_attr), default=str))
        return "\n".join(p for p in extracted_parts if p)
    if isinstance(result, (list, tuple)):
        parts: list[str] = []
        for item in result:
            text_attr = getattr(item, "text", None)
            if isinstance(text_attr, str):
                parts.append(text_attr)
            elif isinstance(item, (list, tuple, Mapping)):
                parts.append(extract_tool_output_text(item))
            elif item is not None:
                parts.append(str(item))
        return "\n".join(parts)
    return str(result)


def extract_commit_outcome(result: Any) -> CommitOutcome | None:
    """Decode a structured :class:`CommitOutcome` from a tool return value, or ``None``."""
    candidate: Any = None
    structured_attr = getattr(result, "structuredContent", None)
    if isinstance(structured_attr, Mapping):
        candidate = structured_attr
    elif (
        isinstance(result, tuple)
        and len(result) == 2
        and isinstance(result[1], Mapping)
    ):
        candidate = result[1]
    elif isinstance(result, Mapping):
        candidate = result
    if candidate is None:
        return None
    try:
        return CommitOutcome.from_wire(candidate)
    except CommitOutcomeDecodeError:
        return None


def is_post_exec_protected(
    attempt: ActuationAttempt | None,
    decoded_outcome: CommitOutcome | None,
) -> bool:
    """Whether the tool run executed or may have executed (including ledger replays)."""
    return (attempt is not None and attempt.may_have_executed) or (
        decoded_outcome is not None
        and decoded_outcome.status in POST_EXEC_PROTECTED_COMMIT_STATUSES
    )


def _outcome_from_attempt(
    attempt: ActuationAttempt | None, message: str
) -> CommitOutcome | None:
    """Synthesize a ``CommitOutcome`` from ``attempt`` when the tool returned none."""
    if attempt is None or not attempt.may_have_executed:
        return None
    if attempt is current_actuation_attempt():
        return outcome_after_dispatch(message)
    if attempt.status is ExecutionStatus.EXECUTED:
        return CommitOutcome(CommitStatus.EXECUTED, message)
    return CommitOutcome(CommitStatus.INDETERMINATE, message)


def scan_tool_response_text(
    tool_name: str,
    response_text: Any,
    *,
    span: Any = None,
    post_exec_protected: bool = False,
) -> tuple[str | None, str | None]:
    """Run indirect-injection detection and stamp operational or blocking span tags.

    Stamps ISO 42001 ``A.9.2`` ``BLOCK`` ONLY when ``not post_exec_protected``.
    When ``post_exec_protected`` is ``True``, stamps non-block operational
    redaction attributes (``mcp.tool.post_execution_output_redacted`` and
    ``mcp.tool.redaction_pattern``) and never stamps ``BLOCK``.

    Returns:
        ``(violation, pattern_matched)`` on a hit, or ``(None, None)`` when clean.
    """
    safe_text = (
        response_text
        if isinstance(response_text, str)
        else str(response_text if response_text is not None else "")
    )
    active_span = _recording_span(span)
    result = detect_indirect_injection(tool_name, safe_text)
    if not result.detected:
        stamp_iso_control(active_span, ingress_stage=2, control="A.9.2", outcome="PASS")
        return None, None

    pattern = str(result.pattern_matched or "unknown")
    violation = f"indirect_injection:{pattern}"
    if post_exec_protected:
        if active_span is not None:
            active_span.set_attribute("mcp.tool.post_execution_output_redacted", True)
            active_span.set_attribute("mcp.tool.redaction_pattern", pattern)
        logger.warning(
            "🟡 [AI600-003] Post-execution tool output withheld without refusing "
            "execution outcome: tool=%s pattern=%s",
            tool_name,
            pattern,
        )
        return violation, pattern

    stamp_iso_control(active_span, ingress_stage=2, control="A.9.2", outcome="BLOCK")
    logger.warning(
        "🔴 [AI600-003] MCP tool response rejected: tool=%s pattern=%s "
        "(control=A.9.2 — indirect injection blocked)",
        tool_name,
        pattern,
    )
    return violation, pattern


async def emit_post_execution_sanitized_event(
    *,
    tool_name: str,
    violation: str,
    pattern_matched: str,
    commit_status: CommitStatus,
    actuation_status: str,
    transport: str,
) -> str | None:
    """Append a non-refusal ``POST_EXECUTION_OUTPUT_SANITIZED`` record (NIST SI-15 / AU-2).

    Sink failures are logged and counted via
    ``governor_metrics().evidence_publish_failure("post_execution_sanitizer")``
    without raising so a post-execution telemetry error never discards the
    execution outcome.
    """
    from src.gateway.governance.evidence.stream import get_evidence_sink

    event: dict[str, Any] = {
        "type": POST_EXECUTION_SANITIZER_EVENT_TYPE,
        "controlId": "SI-15",
        "action_refused": False,
        "may_have_executed": True,
        "output_withheld": True,
        "tool_name": tool_name,
        "violation": violation,
        "pattern_matched": pattern_matched,
        "commit_status": commit_status.value,
        "actuation_status": actuation_status,
        "transport": transport,
        "timestamp_utc": datetime.now(tz=timezone.utc).isoformat(),
    }
    try:
        sink = get_evidence_sink()
        has_redis = getattr(sink, "_redis", None) is not None
        msg_id = await sink.ingest(event)
        if has_redis and msg_id is None:
            from src.gateway.governance.governor.metrics import governor_metrics

            governor_metrics().evidence_publish_failure("post_execution_sanitizer")
        return msg_id
    except Exception as exc:
        from src.gateway.governance.governor.metrics import governor_metrics

        governor_metrics().evidence_publish_failure("post_execution_sanitizer")
        logger.error(
            "[PostExecutionSanitizer] Failed to ingest %s for tool=%s "
            "(commit_status=%s, violation=%s): %s",
            POST_EXECUTION_SANITIZER_EVENT_TYPE,
            tool_name,
            commit_status.value,
            violation,
            exc,
        )
        return None


async def evaluate_post_execution_output(
    tool_name: str,
    raw_output: Any,
    *,
    span: Any = None,
    attempt: ActuationAttempt | None = None,
    transport: str = "unknown",
) -> SanitizationOutcome:
    """Coordinate post-execution indirect prompt-injection sanitization across transports.

    Shared by ``POST /tools/execute`` and ``/mcp/``. Preserves blocking refusal
    semantics when ``not post_exec_protected``, and switches to non-refusal
    redaction + ``POST_EXECUTION_OUTPUT_SANITIZED`` evidence emission once the
    run executed or may have executed.
    """
    active_attempt = attempt if attempt is not None else current_actuation_attempt()
    decoded_outcome = extract_commit_outcome(raw_output)
    protected = is_post_exec_protected(active_attempt, decoded_outcome)
    safe_text = extract_tool_output_text(raw_output)

    violation, pattern = scan_tool_response_text(
        tool_name,
        safe_text,
        span=span,
        post_exec_protected=protected,
    )
    if violation is None:
        return SanitizationOutcome(
            violation=None,
            pattern_matched=None,
            post_exec_protected=protected,
        )

    if not protected:
        return SanitizationOutcome(
            violation=violation,
            pattern_matched=pattern,
            post_exec_protected=False,
        )

    redacted_msg = REDACTED_POST_EXEC_MESSAGE.format(violation=violation)
    if (
        decoded_outcome is not None
        and decoded_outcome.status in POST_EXEC_PROTECTED_COMMIT_STATUSES
    ):
        redacted_outcome = CommitOutcome(
            status=decoded_outcome.status,
            message=redacted_msg,
            redemption_refusal=decoded_outcome.redemption_refusal,
            deferred_id=decoded_outcome.deferred_id,
            approval_retained=decoded_outcome.approval_retained,
        )
    else:
        redacted_outcome = _outcome_from_attempt(
            active_attempt, redacted_msg
        ) or CommitOutcome(CommitStatus.INDETERMINATE, redacted_msg)

    actuation_status = (
        active_attempt.status.value
        if active_attempt is not None and active_attempt.dispatched
        else "NOT_DISPATCHED"
    )
    msg_id = await emit_post_execution_sanitized_event(
        tool_name=tool_name,
        violation=violation,
        pattern_matched=pattern or "unknown",
        commit_status=redacted_outcome.status,
        actuation_status=actuation_status,
        transport=transport,
    )
    return SanitizationOutcome(
        violation=violation,
        pattern_matched=pattern,
        post_exec_protected=True,
        redacted_message=redacted_msg,
        redacted_outcome=redacted_outcome,
        evidence_msg_id=msg_id,
    )

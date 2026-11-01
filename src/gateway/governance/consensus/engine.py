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
Consensus Engine — Tier 5: Multi-Critic Consensus Gate.

High-stakes actions (meeting or exceeding the domain magnitude threshold or
listed in ``high_stakes_actions``) require synchronous, unanimous approval
across all configured critic personas. Completed consensus audit records
are pushed to a background ``asyncio.Queue`` for asynchronous audit logging.

This module is the deterministic half of consensus. It decides:

- when a check triggers;
- what context each critic may see;
- how the prompt is rendered;
- how a reply parses into a vote;
- how votes become a decision.

It imports no model client. The model call crosses the
:class:`~src.gateway.governance.seams.critic.CriticBackend` seam. The backend
is bound through ``critic_backend_factory`` only when critics are enabled
(``CAGE_CONSENSUS_CRITICS_ENABLED=true``) and an inference backend exists.
Per-role model routing (Priority 4, Evidentiary Independence: a distinct
model backend per critic persona) belongs to the Layer 3 backend.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import re
from collections.abc import Callable, Mapping, Sequence
from collections.abc import Set as AbstractSet
from pathlib import Path
from typing import Any, Final

import yaml
from opentelemetry import trace

from src.gateway.governance.contracts import ConsensusContribution, CriticSpec
from src.gateway.governance.critic_backend_factory import load_critic_backend
from src.gateway.governance.feature_flags import consensus_critics_enabled
from src.gateway.governance.inference_backend import inference_disabled
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.seams.critic import CriticBackend, CriticRequest
from src.gateway.infrastructure.telemetry_client import genai_span
from src.gateway.observability.attributes import (
    TRACE_METADATA_CONSENSUS_DECISION,
    TRACE_METADATA_CONSENSUS_VOTES,
    TRACE_METADATA_ISO_CONTROL_ID,
    TRACE_METADATA_ISO_CONTROL_ID_SECONDARY,
    TRACE_METADATA_ISO_REQUIREMENT,
    TRACE_METADATA_ISO_REQUIREMENT_SECONDARY,
)

logger = logging.getLogger("ConsensusGate")
tracer = trace.get_tracer("src.governance.consensus")

# ---------------------------------------------------------------------------
# Background audit queue (Phase 4.4)
# ---------------------------------------------------------------------------

_AUDIT_QUEUE: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=1000)

_RESERVED_PROMPT_KEYS: frozenset[str] = frozenset(
    {"role", "action", "action_type", "params", "magnitude"}
)
_VALID_DECISIONS: frozenset[str] = frozenset({"APPROVE", "REJECT", "ESCALATE"})

# A triggered check escalated deterministically to HITL (REQUIRE_APPROVAL)
# because LLM critic voting is disabled (CAGE_CONSENSUS_CRITICS_ENABLED=false,
# the default; read by feature_flags.consensus_critics_enabled()).
NOTIONAL_THRESHOLD_ESCALATION: Final[str] = "NOTIONAL_THRESHOLD_ESCALATION"

# A triggered check refused because critics are enabled
# (CAGE_CONSENSUS_CRITICS_ENABLED=true) but no model exists to act as a critic
# (CAGE_INFERENCE_BACKEND=none). It is a DENY that the evidence chain can
# tell apart from a REJECT on the merits.
CONSENSUS_NO_INFERENCE_BACKEND: Final[str] = "CONSENSUS_NO_INFERENCE_BACKEND"

# The statuses a domain tier admits. The mapping lives here, once, so no
# domain can translate a refusal into an admit.
CONSENSUS_ADMIT_STATUSES: Final[frozenset[str]] = frozenset(
    {"APPROVE", "APPROVED", "SKIPPED"}
)


_LINE_PREFIX_DECISION_RE = re.compile(r"^(APPROVE|REJECT|ESCALATE)\b")
_WHOLE_WORD_REJECT_RE = re.compile(r"\bREJECT\b")
_LEADING_THINK_BLOCK_RE = re.compile(
    r"^\s*(?:<think>.*?</think>\s*)+", re.DOTALL | re.IGNORECASE
)
_ANY_THINK_TAG_RE = re.compile(r"</?think>", re.IGNORECASE)

_CRITIC_VOTE_RESPONSE_FORMAT: dict[str, Any] = {
    "type": "json_schema",
    "json_schema": {
        "name": "critic_vote",
        "strict": True,
        "schema": {
            "type": "object",
            "properties": {
                "decision": {
                    "type": "string",
                    "enum": ["APPROVE", "REJECT", "ESCALATE"],
                },
                "reason": {"type": "string"},
            },
            "required": ["decision", "reason"],
            "additionalProperties": False,
        },
    },
}


class _FormatContext(dict[str, Any]):
    """Safe format_map dictionary that substitutes 'UNKNOWN' for missing keys."""

    def __missing__(self, key: str) -> str:
        return "UNKNOWN"


def _normalize_for_json(value: Any) -> Any:
    """Recursively normalize arbitrary values into finite JSON-compatible primitives."""
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, Mapping):
        return {str(k): _normalize_for_json(v) for k, v in value.items()}
    if isinstance(value, (Sequence, AbstractSet)) and not isinstance(
        value, (str, bytes, bytearray)
    ):
        return [_normalize_for_json(item) for item in value]
    return str(value)


def _format_params_block(params: Mapping[str, Any]) -> str:
    """Render non-reserved parameters as a delimited RFC 8785 canonical JSON block."""
    normalized = _normalize_for_json(dict(params))
    canonical = jcs_canonicalize_plan(normalized).decode("utf-8")
    return f"<params_json>{canonical}</params_json>"


def _parse_critic_vote(raw_content: str | None) -> str:
    """Strictly parse a critic response into APPROVE, REJECT, ESCALATE, or ERROR."""
    if raw_content is None or not isinstance(raw_content, str):
        return "ERROR"

    stripped = _LEADING_THINK_BLOCK_RE.sub("", raw_content).strip()
    if not stripped or _ANY_THINK_TAG_RE.search(stripped):
        return "ERROR"

    if stripped.startswith("{"):
        try:
            parsed = json.loads(stripped)
        except Exception:
            return "ERROR"
        if not isinstance(parsed, dict):
            return "ERROR"
        decision = parsed.get("decision")
        if not isinstance(decision, str) or decision not in _VALID_DECISIONS:
            return "ERROR"
        reason = parsed.get("reason", "")
        if reason is not None and not isinstance(reason, str):
            return "ERROR"
        if decision == "APPROVE" and _WHOLE_WORD_REJECT_RE.search(reason or ""):
            return "REJECT"
        return decision

    first_line = next(
        (line.strip() for line in stripped.splitlines() if line.strip()), ""
    )
    match = _LINE_PREFIX_DECISION_RE.match(first_line)
    if match is None:
        return "ERROR"
    if _WHOLE_WORD_REJECT_RE.search(stripped):
        return "REJECT"
    return match.group(1)


def extract_field_magnitude(key: str) -> Callable[[Mapping[str, Any]], float]:
    """Build a fail-closed magnitude extractor for ``key`` in an action parameter mapping."""

    def _extract(params: Mapping[str, Any]) -> float:
        if key not in params:
            return 0.0
        raw = params[key]
        if raw is None or isinstance(raw, bool):
            raise TypeError(f"invalid {key}: {raw!r}")
        value = float(raw)
        if not math.isfinite(value) or value < 0.0:
            raise ValueError(f"non-finite or negative {key}: {raw!r}")
        return value

    return _extract


def load_critic_specs(path: Path) -> tuple[CriticSpec, ...]:
    """Load domain critic specifications from a YAML file."""
    with open(path, encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}
    raw_critics = raw.get("critics", ())
    entries: list[tuple[str, Mapping[str, Any]]] = []
    if isinstance(raw_critics, Mapping):
        for role_key, entry in raw_critics.items():
            if isinstance(entry, Mapping):
                entries.append((str(role_key), entry))
    elif isinstance(raw_critics, Sequence):
        for entry in raw_critics:
            if isinstance(entry, Mapping):
                role_key = str(entry.get("role") or entry.get("id") or "").strip()
                entries.append((role_key, entry))

    specs: list[CriticSpec] = []
    for role_key, entry in entries:
        role = str(entry.get("role") or role_key or entry.get("id") or "").strip()
        prompt = str(entry.get("prompt_template") or entry.get("prompt") or "").strip()
        if not role or not prompt:
            raise ValueError(
                f"Invalid critic specification in {path}: 'role' and 'prompt_template' are required"
            )
        raw_context_keys = entry.get("context_keys") or ()
        if isinstance(raw_context_keys, str) or not isinstance(
            raw_context_keys, Sequence
        ):
            raise ValueError(
                f"Invalid critic specification in {path}: 'context_keys' must be a sequence of strings"
            )
        context_keys = tuple(str(k).strip() for k in raw_context_keys if str(k).strip())
        specs.append(
            CriticSpec(
                role=role,
                prompt=prompt,
                weight=float(entry.get("weight", 1.0)),
                provider=str(entry.get("provider", "google")),
                model=str(entry.get("model", "gemini-2.5-pro")),
                temperature=float(entry.get("temperature", 0.0)),
                system_instruction=str(
                    entry.get("system_instruction", "You are a strict {role}.")
                ),
                context_keys=context_keys,
            )
        )
    return tuple(specs)


def consensus_admits(result: Mapping[str, Any]) -> bool:
    """True when a consensus result lets the action proceed.

    Only an admitting ``status`` admits, and a result that carries a kernel
    ``reason_code`` is a refusal whatever its status says.
    """
    return result.get("status") in CONSENSUS_ADMIT_STATUSES and not result.get(
        "reason_code"
    )


def consensus_violation_code(result: Mapping[str, Any], default_code: str) -> str:
    """Return the violation code a domain tier records for a refused result.

    A kernel reason code (``CONSENSUS_NO_INFERENCE_BACKEND``) wins over the
    domain's own default, so the evidence chain keeps it.
    """
    code = result.get("reason_code")
    return code if isinstance(code, str) and code else default_code


async def _background_audit_worker() -> None:
    """Drain the audit queue and log completed consensus results.

    This coroutine is intended to run as a long-lived background task
    (started once at gateway startup, e.g. via asyncio.create_task).
    It does not raise; errors are logged and the worker continues.
    """
    logger.info("🔄 Consensus background audit worker started.")
    while True:
        try:
            record = await _AUDIT_QUEUE.get()
            logger.info(
                "📋 [AUDIT] Post-hoc consensus | action=%s magnitude=%.2f "
                "decision=%s votes=%s",
                record.get("action"),
                record.get("magnitude", 0.0),
                record.get("decision"),
                record.get("votes"),
            )
            _AUDIT_QUEUE.task_done()
        except Exception as exc:
            logger.error("Audit worker error: %s", exc)
            _AUDIT_QUEUE.task_done()


class ConsensusGate:
    """
    Domain-agnostic multi-critic consensus gate for high-stakes actions.

    Actions whose magnitude meets or exceeds ``self.threshold`` (or that appear
    in ``self.high_stakes_actions``) trigger a synchronous consensus check
    across the domain-contributed ``CriticSpec`` personas.
    """

    def __init__(
        self,
        critics: Sequence[CriticSpec] = (),
        threshold: float = 0.0,
        magnitude_extractor: Callable[[Mapping[str, Any]], float] | None = None,
        high_stakes_actions: AbstractSet[str] = frozenset(),
        critic_backend: CriticBackend | None = None,
        critics_enabled: bool | None = None,
    ) -> None:
        self.critics: tuple[CriticSpec, ...] = tuple(critics)
        self.threshold: float = float(threshold)
        self.magnitude_extractor: Callable[[Mapping[str, Any]], float] | None = (
            magnitude_extractor
        )
        self.high_stakes_actions: frozenset[str] = frozenset(high_stakes_actions)
        # Resolved once, at composition time.
        # - By default (CAGE_CONSENSUS_CRITICS_ENABLED=false), a triggered
        #   check escalates deterministically with NOTIONAL_THRESHOLD_ESCALATION.
        # - With critics enabled under CAGE_INFERENCE_BACKEND=none, a triggered
        #   check is refused before any critic is consulted.
        # On both paths no critic backend is bound, so no model client package
        # is imported. A backend passed in is ignored there too: the gate
        # cannot consult critics.
        self._critics_enabled: bool = (
            consensus_critics_enabled()
            if critics_enabled is None
            else bool(critics_enabled)
        )
        self._inference_disabled: bool = inference_disabled()
        self._critic_backend: CriticBackend | None = None
        if self._critics_enabled and not self._inference_disabled:
            self._critic_backend = (
                critic_backend
                if critic_backend is not None
                else load_critic_backend([c.role for c in self.critics])
            )

    @classmethod
    def from_contribution(
        cls,
        contribution: ConsensusContribution,
        critic_backend: CriticBackend | None = None,
        critics_enabled: bool | None = None,
    ) -> ConsensusGate:
        """Build a ``ConsensusGate`` from a domain ``ConsensusContribution``."""
        return cls(
            critics=contribution.critics,
            threshold=contribution.threshold,
            magnitude_extractor=contribution.magnitude_extractor,
            high_stakes_actions=contribution.high_stakes_actions,
            critic_backend=critic_backend,
            critics_enabled=critics_enabled,
        )

    def _resolve_critic_spec(self, critic: CriticSpec | str) -> CriticSpec | None:
        if isinstance(critic, CriticSpec):
            return critic
        for candidate in getattr(self, "critics", ()):
            if candidate.role == critic:
                return candidate
        return None

    async def _get_critic_vote(
        self,
        critic: CriticSpec | str,
        action: str,
        context: Mapping[str, Any],
        magnitude: float | None,
    ) -> str:
        """Consult a critic persona and return a strictly parsed decision.

        The kernel chooses the context the critic sees, renders the prompt
        and parses the reply. The critic backend only carries the request.
        """
        spec = self._resolve_critic_spec(critic)
        role = spec.role if spec is not None else str(critic)
        if spec is None or not spec.prompt:
            logger.error(
                "No CriticSpec prompt configured for role '%s' — failing closed with ERROR",
                role,
            )
            return "ERROR"

        backend = getattr(self, "_critic_backend", None)
        if backend is None:
            logger.error(
                "No critic backend for critic '%s' — failing closed with ERROR", role
            )
            return "ERROR"

        try:
            if spec.context_keys:
                allowed_params: dict[str, Any] = {
                    key: context[key]
                    for key in spec.context_keys
                    if key in context and key not in _RESERVED_PROMPT_KEYS
                }
            else:
                allowed_params = {
                    str(key): value
                    for key, value in context.items()
                    if str(key) not in _RESERVED_PROMPT_KEYS
                }

            fmt_ctx = _FormatContext(allowed_params)
            fmt_ctx["params"] = _format_params_block(allowed_params)
            fmt_ctx["role"] = role
            fmt_ctx["action"] = action
            fmt_ctx["action_type"] = action
            fmt_ctx["magnitude"] = magnitude if magnitude is not None else 0.0

            prompt = spec.prompt.format_map(fmt_ctx)
            system_instruction = (
                spec.system_instruction or "You are a strict {role}."
            ).format_map(fmt_ctx)

            timeout_s = float(os.getenv("CONSENSUS_CRITIC_TIMEOUT_S", "10.0"))
            request = CriticRequest(
                role=role,
                model=spec.model,
                system_instruction=system_instruction,
                prompt=prompt,
                timeout_s=timeout_s,
                response_format=_CRITIC_VOTE_RESPONSE_FORMAT,
            )
            try:
                raw_content = await asyncio.wait_for(
                    backend.complete(request), timeout=timeout_s
                )
            except asyncio.TimeoutError:
                logger.warning(
                    "⏱️ Consensus critic %s timed out after %.0fs — returning "
                    "ERROR verdict.",
                    role,
                    timeout_s,
                )
                return "ERROR"

            return _parse_critic_vote(raw_content)

        except Exception as exc:
            logger.error("Critic %s failed: %s", role, exc)
            return "ERROR"

    async def check_consensus(
        self,
        action: str = "",
        context: dict[str, Any] | None = None,
        magnitude: float | None = None,
        *,
        action_type: str | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Run a consensus check if the action exceeds the magnitude threshold."""
        resolved_action = action or action_type or ""
        if context is not None and not isinstance(context, Mapping):
            return {
                "status": "DENY",
                "decision": "DENY",
                "reason": "invalid_context",
                "votes": [],
            }
        if params is not None and not isinstance(params, Mapping):
            return {
                "status": "DENY",
                "decision": "DENY",
                "reason": "invalid_context",
                "votes": [],
            }
        resolved_context: dict[str, Any] = (
            dict(context)
            if context is not None
            else (dict(params) if params is not None else {})
        )
        extractor = getattr(self, "magnitude_extractor", None)
        try:
            raw_magnitude: Any
            if magnitude is not None:
                raw_magnitude = magnitude
            elif extractor is not None:
                raw_magnitude = extractor(resolved_context)
            else:
                raw_magnitude = 0.0
            if raw_magnitude is None or isinstance(raw_magnitude, bool):
                raise TypeError("magnitude cannot be None or bool")
            resolved_magnitude = float(raw_magnitude)
        except Exception:
            return {
                "status": "DENY",
                "decision": "DENY",
                "reason": "invalid_magnitude",
                "votes": [],
            }
        if not math.isfinite(resolved_magnitude) or resolved_magnitude < 0.0:
            return {
                "status": "DENY",
                "decision": "DENY",
                "reason": "invalid_magnitude",
                "votes": [],
            }

        try:
            threshold = float(getattr(self, "threshold", 0.0))
        except (TypeError, ValueError):
            threshold = float("nan")
        if not math.isfinite(threshold):
            return {
                "status": "DENY",
                "decision": "DENY",
                "reason": "invalid_threshold",
                "votes": [],
            }
        high_stakes = getattr(self, "high_stakes_actions", frozenset())

        if resolved_magnitude < threshold and resolved_action not in high_stakes:
            return {
                "status": "SKIPPED",
                "decision": "SKIPPED",
                "reason": "Below threshold",
                "votes": [],
            }

        if not getattr(self, "_critics_enabled", True):
            logger.info(
                "⚖️ Notional threshold escalation for action=%s magnitude=%.2f "
                "(threshold=%.2f, CAGE_CONSENSUS_CRITICS_ENABLED=false) — ESCALATE %s",
                resolved_action,
                resolved_magnitude,
                threshold,
                NOTIONAL_THRESHOLD_ESCALATION,
            )
            return {
                "status": "ESCALATE",
                "decision": "ESCALATE",
                "reason": (
                    f"Action '{resolved_action}' magnitude ({resolved_magnitude:.2f}) "
                    f"meets or exceeds threshold ({threshold:.2f}) — escalating to "
                    "human review (NOTIONAL_THRESHOLD_ESCALATION)."
                ),
                "reason_code": NOTIONAL_THRESHOLD_ESCALATION,
                "votes": [],
            }

        if getattr(self, "_inference_disabled", False):
            logger.warning(
                "ConsensusGate triggered for action=%s magnitude=%.2f with no "
                "inference backend (CAGE_INFERENCE_BACKEND=none) — DENY %s",
                resolved_action,
                resolved_magnitude,
                CONSENSUS_NO_INFERENCE_BACKEND,
            )
            return {
                "status": "DENY",
                "decision": "DENY",
                "reason": (
                    "No inference backend (CAGE_INFERENCE_BACKEND=none): consensus "
                    "needs model critics, so no critic was consulted."
                ),
                "reason_code": CONSENSUS_NO_INFERENCE_BACKEND,
                "votes": [],
            }

        critics: tuple[CriticSpec, ...] = tuple(getattr(self, "critics", ()))
        if not critics:
            logger.error(
                "ConsensusGate triggered for action=%s magnitude=%.2f with no critics configured — failing closed (DENY)",
                resolved_action,
                resolved_magnitude,
            )
            return {
                "status": "DENY",
                "decision": "DENY",
                "reason": "no_critics_configured",
                "votes": [],
            }

        logger.info(
            "⚖️ Consensus Engine Triggered for action=%s magnitude=%.2f",
            resolved_action,
            resolved_magnitude,
        )
        action = resolved_action
        context = resolved_context

        with genai_span(
            "consensus.check",
            prompt=f"Review action: {action} magnitude={resolved_magnitude}",
        ) as span:
            span.set_attribute(TRACE_METADATA_ISO_CONTROL_ID, "A.8.4")

            votes = list(
                await asyncio.gather(
                    *(
                        self._get_critic_vote(
                            critic, action, context, resolved_magnitude
                        )
                        for critic in critics
                    )
                )
            )

            non_error_votes = [v for v in votes if v != "ERROR"]
            error_votes = [v for v in votes if v == "ERROR"]
            if all(v == "ERROR" for v in votes):
                logger.warning(
                    "🔴 All consensus critics returned ERROR — escalating for human review "
                    "(action=%s magnitude=%.2f). "
                    "Fail-open APPROVE would allow a DoS bypass of the consensus gate.",
                    action,
                    resolved_magnitude,
                )
                decision = "ESCALATE"
                reason = "consensus_unanimous_error"
            elif (
                non_error_votes
                and all(v == "REJECT" for v in non_error_votes)
                and not error_votes
            ):
                decision = "REJECT"
                reason = f"Unanimous rejection by all critics. Votes: {votes}"
            elif (
                non_error_votes
                and all(v == "REJECT" for v in non_error_votes)
                and error_votes
            ):
                logger.warning(
                    "⚠️ Degraded consensus quorum: %d critic(s) errored, %d rejected "
                    "(action=%s magnitude=%.2f). Escalating for human review — "
                    "a partial REJECT quorum is not a full unanimous denial.",
                    len(error_votes),
                    len(non_error_votes),
                    action,
                    resolved_magnitude,
                )
                decision = "ESCALATE"
                reason = (
                    f"Degraded quorum: {len(error_votes)} critic(s) unavailable, "
                    f"remaining votes all REJECT — escalating for human review. Votes: {votes}"
                )
            elif set(votes) == {"ERROR", "APPROVE"}:
                logger.warning(
                    "⚠️ Degraded consensus quorum: ERROR + APPROVE — escalating for human review "
                    "(action=%s magnitude=%.2f).",
                    action,
                    resolved_magnitude,
                )
                decision = "ESCALATE"
                reason = f"Degraded quorum (ERROR + APPROVE) — escalating for human review. Votes: {votes}"
            elif any(v == "REJECT" for v in non_error_votes) and any(
                v == "APPROVE" for v in non_error_votes
            ):
                decision = "ESCALATE"
                reason = f"Split consensus vote — escalating for human review. Votes: {votes}"
            elif any(v == "ESCALATE" for v in votes):
                decision = "ESCALATE"
                reason = f"Escalated for human review. Votes: {votes}"
            elif all(v == "APPROVE" for v in votes):
                decision = "APPROVE"
                reason = "Unanimous approval from all configured critics."
            else:
                decision = "ESCALATE"
                reason = f"Consensus unclear. Votes: {votes}"

            span.set_attribute(TRACE_METADATA_CONSENSUS_DECISION, decision)
            span.set_attribute(TRACE_METADATA_CONSENSUS_VOTES, str(votes))
            span.set_attribute(TRACE_METADATA_ISO_CONTROL_ID, "A.8.4")
            span.set_attribute(
                TRACE_METADATA_ISO_REQUIREMENT, "AI System Impact Assessment"
            )
            if decision == "ESCALATE":
                span.set_attribute(TRACE_METADATA_ISO_CONTROL_ID_SECONDARY, "A.4.2")
                span.set_attribute(
                    TRACE_METADATA_ISO_REQUIREMENT_SECONDARY,
                    "Risk Management",
                )

            result = {
                "status": decision,
                "decision": decision,
                "reason": reason,
                "votes": votes,
            }

            audit_record = {
                "action": action,
                "magnitude": resolved_magnitude,
                "decision": decision,
                "reason": reason,
                "votes": votes,
            }
            try:
                _AUDIT_QUEUE.put_nowait(audit_record)
            except asyncio.QueueFull:
                logger.critical(
                    json.dumps(
                        {
                            "event": "CONSENSUS_AUDIT_RECORD_DROPPED",
                            "severity": "CRITICAL",
                            "action": action,
                            "audit_note": (
                                "Consensus audit queue full — record lost. "
                                "Start _background_audit_worker() at application startup "
                                "to prevent record loss."
                            ),
                        }
                    )
                )

            return result


# Backward-compatibility alias for external consumers
ConsensusEngine = ConsensusGate

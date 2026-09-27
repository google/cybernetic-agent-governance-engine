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
Consensus Engine — Layer 4: Adaptive Compute.

High-latency LLM critic votes for non-critical actions are pushed to a
background ``asyncio.Queue`` for post-execution audit alerting, keeping the
primary governance hot-path within the latency budget.

Priority 4 (Evidentiary Independence): Heterogeneous Model Infrastructure.
  The consensus engine routes each domain-injected critic persona to a
  distinct model backend via ``ConsensusModelRegistry``.

  In production, each critic should run on:
    - A different model family (e.g., DeepSeek-R1 vs Llama 3.1)
    - Different GPU hardware (to eliminate correlated hardware faults)
    - Ideally different infrastructure (separate clusters or providers)

  Configure via environment variables per role ``{ROLE}`` (upper-snake-case):
    CONSENSUS_{ROLE}_URL   — vLLM base URL for the critic role
    CONSENSUS_{ROLE}_MODEL — model name for the critic role
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from collections.abc import Callable, Mapping, Sequence
from collections.abc import Set as AbstractSet
from pathlib import Path
from typing import Any

import yaml
from opentelemetry import trace

from src.gateway.core.llm import GatewayClient
from src.gateway.governance.contracts import ConsensusContribution, CriticSpec
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


class _FormatContext(dict[str, Any]):
    """Safe format_map dictionary that substitutes 'UNKNOWN' for missing keys."""

    def __missing__(self, key: str) -> str:
        return "UNKNOWN"


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
            )
        )
    return tuple(specs)


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


# ---------------------------------------------------------------------------
# ConsensusModelRegistry (Priority 4 — Heterogeneous Model Infrastructure)
# ---------------------------------------------------------------------------


class ConsensusModelRegistry:
    """Maps each consensus critic persona to a distinct model backend.

    Ensures that each persona runs on a different model family and/or
    infrastructure, providing genuine algorithmic diversity rather than
    the illusion of consensus from a single model with different prompts.

    Creates dedicated ``AsyncOpenAI`` clients per persona rather than
    using the shared ``GatewayClient`` (which reads from ``Config`` at
    init time and does not support per-call base_url overrides).

    Args:
        persona_configs: Dict mapping persona role name to a dict with
                         "base_url" and "model" keys.
    """

    def __init__(self, persona_configs: dict[str, dict[str, str]]) -> None:
        from openai import AsyncOpenAI

        from config.settings import Config

        self._clients: dict[str, AsyncOpenAI] = {}
        self._models: dict[str, str] = {}
        self._has_dedicated: dict[str, bool] = {}

        for role, config in persona_configs.items():
            base_url = config.get("base_url", "")
            model = config.get("model", "")

            if base_url:
                self._clients[role] = AsyncOpenAI(
                    base_url=base_url,
                    api_key=Config.VLLM_API_KEY or "EMPTY",
                )
                self._models[role] = model
                self._has_dedicated[role] = True
                logger.info(
                    "[ConsensusRegistry] %s → %s (model=%s)",
                    role,
                    base_url,
                    model or "default",
                )
            else:
                # No dedicated URL — fall back to default GatewayClient
                self._clients[role] = None  # type: ignore[assignment]
                self._models[role] = model
                self._has_dedicated[role] = False
                logger.warning(
                    "[ConsensusRegistry] %s has no dedicated URL — "
                    "will use default GatewayClient. This reduces model "
                    "diversity and weakens consensus independence.",
                    role,
                )

    def get_client(self, role: str) -> Any:
        """Return the AsyncOpenAI client for a given persona role, or None."""
        return self._clients.get(role)

    def get_model(self, role: str) -> str:
        """Return the model name for a given persona role."""
        return self._models.get(role, "")

    def has_dedicated_backend(self, role: str) -> bool:
        """True if the role has a dedicated model backend (not shared)."""
        return self._has_dedicated.get(role, False)

    @classmethod
    def from_env(cls, roles: Sequence[str] = ()) -> ConsensusModelRegistry:
        """Construct from environment variables for the supplied critic roles.

        Reads ``CONSENSUS_{ROLE}_URL`` and ``CONSENSUS_{ROLE}_MODEL`` for each
        persona. Falls back to the split-brain reasoning/fast vLLM endpoints
        and then to ``GatewayClient`` when dedicated URLs are unset.
        """
        default_fallbacks = (
            ("VLLM_REASONING_API_BASE", "MODEL_REASONING"),
            ("VLLM_FAST_API_BASE", "MODEL_FAST"),
        )
        persona_configs: dict[str, dict[str, str]] = {}
        for idx, role in enumerate(roles):
            role_key = role.upper().replace(" ", "_").replace("-", "_")
            fb_url_var, fb_model_var = default_fallbacks[idx % len(default_fallbacks)]
            persona_configs[role] = {
                "base_url": os.environ.get(
                    f"CONSENSUS_{role_key}_URL",
                    os.environ.get(fb_url_var, ""),
                ),
                "model": os.environ.get(
                    f"CONSENSUS_{role_key}_MODEL",
                    os.environ.get(fb_model_var, ""),
                ),
            }
        return cls(persona_configs)


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
        quorum: int | float = 2,
        high_stakes_actions: AbstractSet[str] = frozenset(),
        registry: ConsensusModelRegistry | None = None,
    ) -> None:
        self.critics: tuple[CriticSpec, ...] = tuple(critics)
        self.threshold: float = float(threshold)
        self.magnitude_extractor: Callable[[Mapping[str, Any]], float] | None = (
            magnitude_extractor
        )
        self.quorum: int | float = quorum
        self.high_stakes_actions: frozenset[str] = frozenset(high_stakes_actions)
        self._registry = registry or ConsensusModelRegistry.from_env(
            [c.role for c in self.critics]
        )
        self._default_client = GatewayClient()

    @classmethod
    def from_contribution(
        cls,
        contribution: ConsensusContribution,
        registry: ConsensusModelRegistry | None = None,
    ) -> ConsensusGate:
        """Build a ``ConsensusGate`` from a domain ``ConsensusContribution``."""
        return cls(
            critics=contribution.critics,
            threshold=contribution.threshold,
            magnitude_extractor=contribution.magnitude_extractor,
            quorum=contribution.quorum,
            high_stakes_actions=contribution.high_stakes_actions,
            registry=registry,
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
        """Consult an LLM critic persona and return a structured decision."""
        spec = self._resolve_critic_spec(critic)
        role = spec.role if spec is not None else str(critic)
        if spec is None or not spec.prompt:
            logger.error(
                "No CriticSpec prompt configured for role '%s' — failing closed with ERROR",
                role,
            )
            return "ERROR"

        try:
            fmt_ctx = _FormatContext(context)
            fmt_ctx.setdefault("role", role)
            fmt_ctx.setdefault("action", action)
            fmt_ctx.setdefault("action_type", action)
            fmt_ctx.setdefault("params", dict(context))
            fmt_ctx.setdefault("magnitude", magnitude if magnitude is not None else 0.0)

            prompt = spec.prompt.format_map(fmt_ctx)
            system_instruction = (
                spec.system_instruction or "You are a strict {role}."
            ).format_map(fmt_ctx)

            dedicated_client = self._registry.get_client(role)
            model = self._registry.get_model(role) or spec.model

            _CRITIC_TIMEOUT_S: float = float(
                os.getenv("CONSENSUS_CRITIC_TIMEOUT_S", "10.0")
            )

            if dedicated_client is not None:
                try:
                    response = await asyncio.wait_for(
                        dedicated_client.chat.completions.create(
                            model=model or "default",
                            messages=[
                                {
                                    "role": "system",
                                    "content": system_instruction,
                                },
                                {"role": "user", "content": prompt},
                            ],
                            temperature=0.0,
                            timeout=_CRITIC_TIMEOUT_S,
                        ),
                        timeout=_CRITIC_TIMEOUT_S,
                    )
                except asyncio.TimeoutError:
                    logger.warning(
                        "⏱️ Consensus critic %s (dedicated client) timed out "
                        "after %.0fs — returning ERROR verdict.",
                        role,
                        _CRITIC_TIMEOUT_S,
                    )
                    return "ERROR"
                content = response.choices[0].message.content.strip()
            else:
                try:
                    content = await asyncio.wait_for(
                        self._default_client.generate(
                            prompt=prompt,
                            system_instruction=system_instruction,
                            mode="verifier",
                            temperature=0.0,
                        ),
                        timeout=_CRITIC_TIMEOUT_S,
                    )
                except asyncio.TimeoutError:
                    logger.warning(
                        "⏱️ Consensus critic %s (GatewayClient fallback) timed out "
                        "after %.0fs — returning ERROR verdict.",
                        role,
                        _CRITIC_TIMEOUT_S,
                    )
                    return "ERROR"
                content = content.strip()

            if "APPROVE" in content:
                return "APPROVE"
            elif "REJECT" in content:
                return "REJECT"
            elif "ESCALATE" in content:
                return "ESCALATE"
            return "ESCALATE (Unclear)"

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
        resolved_context: dict[str, Any] = (
            dict(context)
            if context is not None
            else (dict(params) if params is not None else {})
        )
        extractor = getattr(self, "magnitude_extractor", None)
        if magnitude is not None:
            resolved_magnitude = float(magnitude)
        elif extractor is not None:
            try:
                resolved_magnitude = float(extractor(resolved_context))
            except (TypeError, ValueError):
                resolved_magnitude = 0.0
        else:
            resolved_magnitude = 0.0

        threshold = float(getattr(self, "threshold", 0.0))
        high_stakes = getattr(self, "high_stakes_actions", frozenset())

        if resolved_magnitude < threshold and resolved_action not in high_stakes:
            return {
                "status": "SKIPPED",
                "decision": "SKIPPED",
                "reason": "Below threshold",
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
            elif any("ESCALATE" in v for v in votes):
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


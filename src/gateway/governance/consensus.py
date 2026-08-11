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

Phase 2.3: Threshold literals replaced with THRESHOLDS singleton.
Phase 4.4: High-latency LLM critic votes for non-critical trades are pushed
           to a background ``asyncio.Queue`` for post-execution audit alerting,
           keeping the primary governance hot-path within the 3-second budget.

Priority 4 (Evidentiary Independence): Heterogeneous Model Infrastructure.
  The consensus engine now routes each critic persona to a DISTINCT model
  backend via the ConsensusModelRegistry.  This eliminates the previous
  vulnerability where two personas ("Risk Manager" and "Compliance Officer")
  ran on the same Llama 3.1 instance — which was not independent validation,
  but the same model validating itself from different prompt angles.

  In production, each critic should run on:
    - A different model family (e.g., DeepSeek-R1 vs Llama 3.1)
    - Different GPU hardware (to eliminate correlated hardware faults)
    - Ideally different infrastructure (separate clusters or providers)

  Configure via environment variables:
    CONSENSUS_RISK_MANAGER_URL       — vLLM base URL for the Risk Manager
    CONSENSUS_RISK_MANAGER_MODEL     — model name for the Risk Manager
    CONSENSUS_COMPLIANCE_OFFICER_URL — vLLM base URL for the Compliance Officer
    CONSENSUS_COMPLIANCE_OFFICER_MODEL — model name for the Compliance Officer
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any

from opentelemetry import trace

from src.gateway.core.llm import GatewayClient
from src.gateway.governance.schemas.thresholds import THRESHOLDS
from src.governed_financial_advisor.utils.telemetry import genai_span

logger = logging.getLogger("ConsensusEngine")
tracer = trace.get_tracer("src.governance.consensus")

# ---------------------------------------------------------------------------
# Background audit queue (Phase 4.4)
# ---------------------------------------------------------------------------

_AUDIT_QUEUE: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=1000)


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
                "📋 [AUDIT] Post-hoc consensus | action=%s symbol=%s amount=%.2f "
                "decision=%s votes=%s",
                record.get("action"),
                record.get("symbol"),
                record.get("amount", 0),
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
    def from_env(cls) -> ConsensusModelRegistry:
        """Construct from environment variables.

        Reads CONSENSUS_{ROLE}_URL and CONSENSUS_{ROLE}_MODEL for each
        persona.  Falls back to default GatewayClient if not set.

        Default configuration uses the existing split-brain architecture:
          - Risk Manager → vLLM-Brain (VLLM_REASONING_API_BASE / DeepSeek-R1)
          - Compliance Officer → vLLM-Police (VLLM_FAST_API_BASE / Llama 3.1)

        This provides model family diversity by default without requiring
        additional infrastructure configuration.
        """
        return cls(
            {
                "Risk Manager": {
                    "base_url": os.environ.get(
                        "CONSENSUS_RISK_MANAGER_URL",
                        os.environ.get("VLLM_REASONING_API_BASE", ""),
                    ),
                    "model": os.environ.get(
                        "CONSENSUS_RISK_MANAGER_MODEL",
                        os.environ.get("MODEL_REASONING", ""),
                    ),
                },
                "Compliance Officer": {
                    "base_url": os.environ.get(
                        "CONSENSUS_COMPLIANCE_OFFICER_URL",
                        os.environ.get("VLLM_FAST_API_BASE", ""),
                    ),
                    "model": os.environ.get(
                        "CONSENSUS_COMPLIANCE_OFFICER_MODEL",
                        os.environ.get("MODEL_FAST", ""),
                    ),
                },
            }
        )


class ConsensusEngine:
    """
    Implements a 'Critic' check for high-stakes decisions using separate LLM calls.

    Trades above ``THRESHOLDS.consensus.threshold_usd`` trigger a synchronous
    consensus check (on the hot path).  All consensus results are also pushed
    to ``_AUDIT_QUEUE`` for post-execution background logging.

    For non-critical trades (below threshold) the check is skipped and the
    background queue is NOT burdened — the caller receives SKIPPED immediately.

    Priority 4: Each critic persona now runs on a DISTINCT model backend via
    the ConsensusModelRegistry.  This provides genuine algorithmic diversity.
    """

    def __init__(self, registry: ConsensusModelRegistry | None = None):
        # Threshold from singleton — no inline literal (Phase 2.3)
        self.threshold: float = THRESHOLDS.consensus.threshold_usd
        self._registry = registry or ConsensusModelRegistry.from_env()
        # Fallback client for backward compatibility
        self._default_client = GatewayClient()

    async def _get_critic_vote(
        self, role: str, action: str, amount: float, symbol: str
    ) -> str:
        """Consult an LLM critic persona and return a structured decision.

        Each role is routed to its dedicated model backend via the
        ConsensusModelRegistry, ensuring genuine model diversity.

        If the persona has a dedicated AsyncOpenAI client (from the registry),
        we call it directly.  Otherwise we fall back to the shared
        GatewayClient with mode-based routing.
        """
        try:
            prompt = (
                f"You are a {role} for a financial institution.\n"
                f"Review the following trade proposal:\n"
                f"ACTION: {action}\nAMOUNT: {amount}\nSYMBOL: {symbol}\n\n"
                "Your job is to identify high-risk or irregular activity.\n"
                "If the trade looks reasonable for a standard portfolio, say 'APPROVE'.\n"
                "If it looks suspicious, reckless, or undefined, say 'REJECT'.\n"
                "If the trade is legitimate but requires human verification "
                "(e.g., large withdrawals, complex life events), say 'ESCALATE'.\n\n"
                "Format: [DECISION] - [Reason]\n"
                "Example: APPROVE - Standard equity purchase."
            )

            dedicated_client = self._registry.get_client(role)
            model = self._registry.get_model(role)

            # Consensus critic timeout — 10 s hard limit.
            # Rationale: the governance hot-path budget is 3 s; critics run in
            # parallel (asyncio.gather) so the combined cost is max(t1, t2).
            # 30 s was too long under GPU load / unreachable vLLM sidecars,
            # causing the test to time out before the consensus gate resolved.
            # 10 s is sufficient for a healthy vLLM instance and still allows
            # the test to complete within its 120 s pytest-timeout budget even
            # when both critics are unreachable (2 x 10 s = 20 s worst case).
            _CRITIC_TIMEOUT_S: float = float(
                os.getenv("CONSENSUS_CRITIC_TIMEOUT_S", "10.0")
            )

            if dedicated_client is not None:
                # Use the persona-specific AsyncOpenAI client directly.
                # Wrap in asyncio.wait_for so the 10 s limit is enforced even
                # when the AsyncOpenAI client's own timeout is not set.
                try:
                    response = await asyncio.wait_for(
                        dedicated_client.chat.completions.create(
                            model=model or "default",
                            messages=[
                                {
                                    "role": "system",
                                    "content": f"You are a strict {role}.",
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
                # Fall back to shared GatewayClient — enforce hard limit.
                # (HIGH-07: GatewayClient has no built-in timeout; default is 600s)
                try:
                    content = await asyncio.wait_for(
                        self._default_client.generate(
                            prompt=prompt,
                            system_instruction=f"You are a strict {role}.",
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
        self, action: str, amount: float, symbol: str
    ) -> dict[str, Any]:
        """Run a consensus check if the trade exceeds the USD threshold.

        Hot-path guarantee (Phase 4.4):
          - Below threshold → immediate SKIPPED return (no LLM calls).
          - Above threshold → two concurrent critic votes gathered via
            ``asyncio.gather`` (parallel, not sequential), then result pushed
            to ``_AUDIT_QUEUE`` for the background worker.

        Priority 4: Each critic now runs on a distinct model backend,
        providing genuine algorithmic diversity rather than the illusion
        of consensus from a single model with different prompts.

        Returns:
            dict with keys: status, reason, votes.
        """
        if amount < self.threshold:
            return {"status": "SKIPPED", "reason": "Below threshold", "votes": []}

        logger.info(
            "⚖️ Consensus Engine Triggered for %s %.2f %s", action, amount, symbol
        )

        with genai_span(
            "consensus.check", prompt=f"Review trade: {action} {amount} {symbol}"
        ) as span:
            span.set_attribute("langfuse.trace.metadata.iso.control_id", "A.8.4")

            # Parallel critic calls — each on a distinct model backend (Priority 4)
            vote1, vote2 = await asyncio.gather(
                self._get_critic_vote("Risk Manager", action, amount, symbol),
                self._get_critic_vote("Compliance Officer", action, amount, symbol),
            )
            votes = [vote1, vote2]

            # Consensus rule (updated for split-vote and degraded-quorum handling):
            #   ALL ERROR                    → ESCALATE (fail-closed: unanimous error must escalate)
            #   ALL REJECT (no ERRORs)       → REJECT   (genuine unanimous denial)
            #   Some ERROR + remaining REJECT → ESCALATE (degraded quorum — not a full unanimous
            #                                             rejection; human review required)
            #   Mixed APPROVE+REJECT (split) → ESCALATE for human review
            #   Any ESCALATE                 → ESCALATE
            #   ALL APPROVE                  → APPROVE
            #
            # Rationale: outright REJECT requires ALL critics to have voted and ALL
            # to have rejected.  When one or more critics error (e.g. vLLM timeout),
            # the remaining REJECT votes do not constitute a quorum — the trade must
            # be escalated for human review rather than silently blocked.  This
            # prevents a single critic's REJECT from becoming a de-facto veto when
            # the other critic is unreachable (e.g. GPU load, network partition).
            non_error_votes = [v for v in votes if v != "ERROR"]
            error_votes = [v for v in votes if v == "ERROR"]
            if all(v == "ERROR" for v in votes):
                # Unanimous ERROR must escalate, not approve — a DoS attack causing
                # both backends to error would otherwise bypass the consensus gate
                # entirely, allowing any trade to pass through unchecked.
                logger.warning(
                    "🔴 All consensus critics returned ERROR — escalating for human review "
                    "(action=%s amount=%.2f symbol=%s). "
                    "Fail-open APPROVE would allow a DoS bypass of the consensus gate.",
                    action,
                    amount,
                    symbol,
                )
                decision = "ESCALATE"
                reason = "consensus_unanimous_error"
            elif (
                non_error_votes
                and all(v == "REJECT" for v in non_error_votes)
                and not error_votes
            ):
                # Genuine unanimous rejection: ALL critics voted and ALL rejected.
                # No ERRORs present — this is a full quorum denial.
                decision = "REJECT"
                reason = f"Unanimous rejection by all critics. Votes: {votes}"
            elif (
                non_error_votes
                and all(v == "REJECT" for v in non_error_votes)
                and error_votes
            ):
                # Degraded quorum: some critics errored, remaining non-error votes are
                # all REJECT.  This is NOT a unanimous rejection — the errored critics
                # could not participate.  Escalate for human review.
                logger.warning(
                    "⚠️ Degraded consensus quorum: %d critic(s) errored, %d rejected "
                    "(action=%s amount=%.2f symbol=%s). Escalating for human review — "
                    "a partial REJECT quorum is not a full unanimous denial.",
                    len(error_votes),
                    len(non_error_votes),
                    action,
                    amount,
                    symbol,
                )
                decision = "ESCALATE"
                reason = (
                    f"Degraded quorum: {len(error_votes)} critic(s) unavailable, "
                    f"remaining votes all REJECT — escalating for human review. Votes: {votes}"
                )
            # Reviewer note H54: degraded quorum (ERROR + APPROVE) → ESCALATE to HITL.
            elif set(votes) == {"ERROR", "APPROVE"}:
                # Degraded quorum: one critic errored, one approved.  The single
                # APPROVE does not constitute a genuine unanimous quorum — escalate
                # for human review rather than letting a lone APPROVE pass through
                # when its counterpart critic is unreachable.
                logger.warning(
                    "⚠️ Degraded consensus quorum: ERROR + APPROVE — escalating for human review "
                    "(action=%s amount=%.2f symbol=%s).",
                    action,
                    amount,
                    symbol,
                )
                decision = "ESCALATE"
                reason = f"Degraded quorum (ERROR + APPROVE) — escalating for human review. Votes: {votes}"
            elif any(v == "REJECT" for v in non_error_votes) and any(
                v == "APPROVE" for v in non_error_votes
            ):
                # Split vote: at least one APPROVE and one REJECT → escalate for human review
                decision = "ESCALATE"
                reason = f"Split consensus vote — escalating for human review. Votes: {votes}"
            elif any("ESCALATE" in v for v in votes):
                decision = "ESCALATE"
                reason = f"Escalated for human review. Votes: {votes}"
            elif all(v == "APPROVE" for v in votes):
                decision = "APPROVE"
                reason = "Unanimous approval from Risk and Compliance."
            else:
                decision = "ESCALATE"
                reason = f"Consensus unclear. Votes: {votes}"

            span.set_attribute("langfuse.trace.metadata.consensus.decision", decision)
            span.set_attribute("langfuse.trace.metadata.consensus.votes", str(votes))
            span.set_attribute("langfuse.trace.metadata.iso.control_id", "A.8.4")
            span.set_attribute(
                "langfuse.trace.metadata.iso.requirement", "AI System Impact Assessment"
            )
            if decision == "ESCALATE":
                span.set_attribute(
                    "langfuse.trace.metadata.iso.control_id_secondary", "A.4.2"
                )
                span.set_attribute(
                    "langfuse.trace.metadata.iso.requirement_secondary",
                    "Risk Management",
                )

            result = {"status": decision, "reason": reason, "votes": votes}

            # Push to background audit queue (Phase 4.4) — non-blocking
            audit_record = {
                "action": action,
                "symbol": symbol,
                "amount": amount,
                "decision": decision,
                "reason": reason,
                "votes": votes,
            }
            try:
                _AUDIT_QUEUE.put_nowait(audit_record)
            except asyncio.QueueFull:
                # LOW-3 fix: dropped audit records are a compliance gap — log at
                # CRITICAL so SIEM/alerting picks them up.  Also: ensure
                # _background_audit_worker() is started at application startup
                # so the queue is drained and records are not dropped at all.
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


consensus_engine = ConsensusEngine()

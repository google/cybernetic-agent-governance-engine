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
NeMo Guardrails Action Implementations — CANONICAL PRODUCTION IMPLEMENTATION

These actions support semantic guardrails owned by NeMo: content screening,
knowledge retrieval, and jailbreak prevention.

Financial policy enforcement (drawdown limits, authorization, latency thresholds)
is handled by the explicit safety_check_node → OPA path in the LangGraph graph.

This is the ONLY NeMo action implementation registered with production NeMo Guardrails.

Alternative implementations (for reference/fallback only):
  - src.governed_financial_advisor.governance.nemo_actions — synchronous in-process fallbacks (testing)
  - src.gateway.governance.nemo.actions — async gateway singleton actions (gateway-internal use)

See: docs/technical-report/05-AI-GOVERNANCE-POLICY-ENGINE.md §6
"""

import logging
import os

import httpx
from opentelemetry import trace as _otel_trace
from opentelemetry.trace import Status, StatusCode

try:
    from nemoguardrails.actions import action as _nemo_action

    def action(name: str):  # type: ignore[misc]
        """Thin wrapper that delegates to nemoguardrails.actions.action."""
        return _nemo_action(name=name)
except ImportError:
    # nemoguardrails not installed (e.g. in unit-test environments).
    # Provide a no-op decorator so the module can still be imported and
    # all action functions remain callable.
    def action(name: str):  # type: ignore[misc]
        """No-op decorator used when nemoguardrails is not installed."""

        def decorator(fn):
            return fn

        return decorator


logger = logging.getLogger(__name__)

_tracer = _otel_trace.get_tracer("config.rails.actions")


# ---------------------------------------------------------------------------
# RetrieveKnowledgeAction (pre-existing)
# ---------------------------------------------------------------------------


@action(name="RetrieveKnowledgeAction")
def retrieve_knowledge(events=None, context=None):
    """
    RetrieveKnowledgeAction: retrieves relevant knowledge for NeMo Guardrails flows.
    Reads KNOWLEDGE_BASE_URL from environment. Falls back to empty list with a warning
    if the knowledge base is not configured (non-blocking for guardrails).
    """
    with _tracer.start_as_current_span("nemo.action.retrieve_knowledge") as span:
        span.set_attribute("langfuse.observation.type", "span")
        span.set_attribute(
            "langfuse.trace.metadata.guardrail.action", "RetrieveKnowledgeAction"
        )
        span.set_attribute("iso42001.control_id", "A.6.1.2")

        kb_url = os.environ.get("KNOWLEDGE_BASE_URL", "")
        span.set_attribute("nemo.action.kb_url", kb_url)

        if not kb_url:
            logger.warning(
                "RetrieveKnowledgeAction: KNOWLEDGE_BASE_URL not set — "
                "returning empty knowledge base. Guardrails will operate without knowledge retrieval."
            )
            span.set_attribute("nemo.action.outcome", "SKIPPED_NO_URL")
            return []

        try:
            query = ""
            if events:
                last = events[-1] if events else {}
                query = last.get("content", "") if isinstance(last, dict) else str(last)
            resp = httpx.get(f"{kb_url}/retrieve", params={"q": query}, timeout=5.0)
            resp.raise_for_status()
            results = resp.json().get("results", [])
            span.set_attribute("nemo.action.result_count", len(results))
            span.set_attribute("nemo.action.outcome", "SUCCESS")
            return results
        except Exception as exc:
            span.record_exception(exc)
            span.set_status(Status(StatusCode.ERROR, str(exc)))
            span.set_attribute("nemo.action.outcome", "ERROR")
            logger.error(
                "RetrieveKnowledgeAction: knowledge retrieval failed: %s",
                exc,
                exc_info=True,
            )
            return []


# ---------------------------------------------------------------------------
# MaskPIIAction — Presidio-backed PII masking for both input and output rails
# ---------------------------------------------------------------------------
# Dependency note: requires presidio_analyzer and presidio_anonymizer.
# These are standard NeMo Guardrails sensitive-data-detection dependencies.
# If not installed, the action logs a warning and returns text unmodified
# (graceful degradation; NeMo's built-in SDD rail is still active via config.yml).
# ---------------------------------------------------------------------------


@action(name="MaskPIIAction")
async def mask_pii_action(
    context: dict | None = None, llm: object | None = None, **kwargs
):
    """Mask PII in the text using Presidio.

    Called for both input and output rails:
      - Input:  MaskPIIAction(text=$user_event.final_transcript)
      - Output: MaskPIIAction(text=$bm)

    The explicitly-passed ``text`` kwarg is always preferred so that the
    output rail masks the *bot message* rather than the still-resident
    ``last_user_message`` context key.
    """
    with _tracer.start_as_current_span("nemo.action.mask_pii") as span:
        span.set_attribute("langfuse.observation.type", "span")
        span.set_attribute("langfuse.trace.metadata.guardrail.action", "MaskPIIAction")
        span.set_attribute("iso42001.control_id", "A.6.1.2")

        logger.debug("MaskPIIAction called with kwargs keys: %s", list(kwargs.keys()))
        ctx = context or {}
        text = (
            kwargs.get(
                "text"
            )  # Explicit argument — highest priority (input AND output callers)
            or ctx.get("last_user_message")  # NeMo context fallback for input rail
            or ctx.get("bot_message")  # NeMo context fallback for output rail
            or ctx.get("last_bot_message")  # Legacy NeMo context key
            or ""
        )
        span.set_attribute("nemo.action.text_length_in", len(text))

        if not text:
            logger.warning(
                "MaskPIIAction: no text in context. Context keys: %s, kwargs: %s",
                list(ctx.keys()),
                list(kwargs.keys()),
            )
            span.set_attribute("nemo.action.outcome", "SKIPPED_NO_TEXT")
            return ""

        try:
            from presidio_analyzer import AnalyzerEngine
            from presidio_analyzer.nlp_engine import NlpEngineProvider
            from presidio_anonymizer import AnonymizerEngine
        except ImportError:
            logger.warning(
                "MaskPIIAction: presidio_analyzer / presidio_anonymizer not installed. "
                "PII masking skipped — install 'presidio-analyzer presidio-anonymizer' to enable."
            )
            span.set_attribute("nemo.action.outcome", "SKIPPED_NO_PRESIDIO")
            return text

        try:
            # Configure Presidio to use the installed en_core_web_sm model
            configuration = {
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
            }
            provider = NlpEngineProvider(nlp_configuration=configuration)
            nlp_engine = provider.create_engine()

            analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
            anonymizer = AnonymizerEngine()
            results = analyzer.analyze(text=text, language="en")
            if results:
                anonymized = anonymizer.anonymize(text=text, analyzer_results=results)
                entity_count = len(results)
                logger.debug(
                    "MaskPIIAction: masked %d PII entity/entities.", entity_count
                )
                span.set_attribute("nemo.action.entity_count", entity_count)
                span.set_attribute("nemo.action.text_length_out", len(anonymized.text))
                span.set_attribute("nemo.action.outcome", "MASKED")
                return anonymized.text
            span.set_attribute("nemo.action.entity_count", 0)
            span.set_attribute("nemo.action.text_length_out", len(text))
            span.set_attribute("nemo.action.outcome", "CLEAN")
            return text
        except Exception as exc:
            span.record_exception(exc)
            span.set_status(Status(StatusCode.ERROR, str(exc)))
            span.set_attribute("nemo.action.outcome", "ERROR")
            logger.error(
                "MaskPIIAction: Presidio masking failed: %s", exc, exc_info=True
            )
            return text


# ---------------------------------------------------------------------------
# Custom Financial Domain Self-Check Actions
# ---------------------------------------------------------------------------


@action(name="CustomSelfCheckInputAction")
async def custom_self_check_input(
    context: dict | None = None, llm: object | None = None, **kwargs
):
    """Hybrid self-check for financial domain inputs - PHASE 2 UPGRADE.

    Four-stage approach (ORDER IS SECURITY-CRITICAL — see 2026-08-02 and 2026-08-03 fixes):
    1. Blocklist jailbreak patterns → BLOCK (0ms) [~5% of queries]
    1B. Blocklist illegal-finance patterns → BLOCK (0ms) [harmful_financial category]
    2. Allowlist financial keywords → ALLOW (0ms) [~70% of queries]
    3. LLM-based semantic check → EVALUATE (2-5s) [~25% of queries]

    SECURITY NOTE (2026-08-02): The blocklist MUST run before the allowlist.
    Running the allowlist first (as this function originally did) allows any
    injection payload that also mentions a common finance word (e.g.
    "trading", "stock", "analyze", "market") to short-circuit ALLOW before
    the jailbreak blocklist is ever consulted — this was measured to let
    4/6 adversarial prompt-injection payloads (INJ-001, INJ-003, INJ-004,
    INJ-005) bypass detection entirely, since each one references finance in
    the same sentence as its attack. See docs/paper/REVISION_TRACKER.md for
    the full measurement writeup. This preserves the same 0ms fast-path
    performance characteristic for genuinely safe queries while closing the
    bypass — the blocklist check is equally O(1) substring matching.

    SECURITY NOTE (2026-08-03): The illegal-finance blocklist (STAGE 1B) must
    also run before the allowlist. HARM-002 ("money laundering...trading profits")
    triggered the ALLOWLIST via "trading" before any harmful-finance check ran.
    Broad allowlist keywords like "trading", "market", "strategy" are insufficient
    to distinguish harmful from benign finance requests — illegal-finance terms must
    be rejected as early as jailbreaks. See docs/paper/REVISION_TRACKER.md §2026-08-03.
    """
    with _tracer.start_as_current_span("nemo.action.self_check_input") as span:
        span.set_attribute("langfuse.observation.type", "span")
        span.set_attribute(
            "langfuse.trace.metadata.guardrail.action", "CustomSelfCheckInputAction"
        )
        span.set_attribute("iso42001.control_id", "A.6.1.2")

        ctx = context or {}
        text = (ctx.get("last_user_message") or kwargs.get("content") or "").lower()

        if not text:
            span.set_attribute("nemo.action.stage", "EMPTY")
            span.set_attribute("nemo.action.outcome", "ALLOW")
            return True

        # STAGE 1: BLOCKLIST — checked FIRST so a jailbreak attempt cannot be
        # short-circuited to ALLOW merely by co-mentioning a finance keyword.
        jailbreak_patterns = [
            "ignore previous instructions",
            "ignore all previous",
            "dan mode",
            "developer mode",
            "repeat your prompt",
            "show me your system prompt",
            "bypass your restrictions",
            "you are now unrestricted",
            "jailbreak",
            "forget everything",
            "pretend you",
            "roleplay as",
            "act as if",
            "act as a developer with root access",
            "system:",
        ]

        if any(pattern in text for pattern in jailbreak_patterns):
            logger.warning("HybridSelfCheckInput: STAGE 1 BLOCK (jailbreak pattern)")
            span.set_attribute("nemo.action.stage", "BLOCKLIST")
            span.set_attribute("nemo.action.outcome", "BLOCK")
            return False

        # STAGE 1B: ILLEGAL-FINANCE BLOCKLIST — catches harmful_financial category
        # payloads that use financial keywords (triggering stage-2 ALLOW) while
        # describing explicitly illegal acts. These must be blocked BEFORE the
        # financial-keyword allowlist runs — HARM-002 ("...trading profits") was
        # observed to bypass via "trading" in the allowlist (2026-08-03 finding).
        illegal_finance_patterns = [
            "insider trading",
            "insider knowledge",
            "insider information",
            "insider tip",
            "money laundering",
            "launder",
            "pump and dump",
            "pump-and-dump",
            "market manipulation",
            "market manipulat",
            "artificially inflat",
            "dump my shares",
            "front running",
            "front-running",
            "naked short",
            "without triggering sec",
            "without triggering regulat",
            "evade sec",
            "evade regulat",
            "evade surveillance",
            "avoid sec",
            "avoid regulat",
            "avoid detection",
            "not get caught",
            "undisclosed source",
            "layering through",
            "layer it through",
        ]

        if any(pattern in text for pattern in illegal_finance_patterns):
            logger.warning(
                "HybridSelfCheckInput: STAGE 1B BLOCK (illegal-finance pattern)"
            )
            span.set_attribute("nemo.action.stage", "ILLEGAL_FINANCE_BLOCKLIST")
            span.set_attribute("nemo.action.outcome", "BLOCK")
            return False

        # STAGE 2: ALLOWLIST - Fast-path for known-safe financial queries (0ms)
        financial_keywords = [
            "portfolio",
            "diversification",
            "risk",
            "return",
            "stock",
            "bond",
            "etf",
            "fund",
            "asset",
            "allocation",
            "rebalance",
            "sharpe",
            "volatility",
            "analyze",
            "investment",
            "trading",
            "strategy",
            "market",
            "price",
            "performance",
            "ratio",
            "dividend",
            "explain",
            "what is",
            "how does",
            "define",
            "compliance",
            "regulatory",
        ]

        if any(keyword in text for keyword in financial_keywords):
            logger.debug("HybridSelfCheckInput: STAGE 2 ALLOW (financial keyword)")
            span.set_attribute("nemo.action.stage", "ALLOWLIST")
            span.set_attribute("nemo.action.outcome", "ALLOW")
            return True

        # STAGE 3: LLM JUDGE - Semantic analysis for ambiguous cases (2-5s)
        logger.info(
            "HybridSelfCheckInput: STAGE 3 - Invoking LLM judge for ambiguous input"
        )
        span.set_attribute("nemo.action.stage", "LLM_JUDGE")

        # Use NeMo's built-in self-check with financial-domain-aware prompt
        try:
            from nemoguardrails.library.self_check.input_check import (
                self_check_input as nemo_self_check,
            )

            # Invoke with LLM (NeMo will use the configured vLLM model)
            is_safe = await nemo_self_check(context=context, llm=llm)
            logger.info("HybridSelfCheckInput: LLM judge result = %s", is_safe)
            span.set_attribute("nemo.action.outcome", "ALLOW" if is_safe else "BLOCK")
            return is_safe
        except Exception as e:
            # On LLM failure, fail OPEN (allow query through)
            # Rationale: OPA layer still enforces financial policy downstream
            logger.error("HybridSelfCheckInput: LLM judge failed: %s - failing OPEN", e)
            span.record_exception(e)
            span.set_attribute("nemo.action.stage", "LLM_JUDGE_FAILED")
            span.set_attribute("nemo.action.outcome", "ALLOW_ON_ERROR")
            return True


@action(name="CustomSelfCheckOutputAction")
async def custom_self_check_output(
    context: dict | None = None, llm: object | None = None, **kwargs
):
    """Hybrid self-check for financial domain outputs - PHASE 2 UPGRADE.

    Three-stage approach (ORDER IS SECURITY-CRITICAL — see 2026-08-02 fix,
    matches the identical reordering applied to CustomSelfCheckInputAction):
    1. Harmful pattern blocklist → BLOCK (0ms) [~2% of outputs]
    2. Safe financial content → ALLOW (0ms) [~80% of outputs]
    3. LLM-based semantic check → EVALUATE (2-5s) [~18% of outputs]

    SECURITY NOTE (2026-08-02): The blocklist MUST run before the
    safe-indicator allowlist. A harmful output that also contains a
    hedging/safe word (e.g. "risk", "may", "could") would otherwise
    short-circuit ALLOW before the harmful-pattern blocklist is ever
    consulted. See CustomSelfCheckInputAction for the analogous input-side
    fix and rationale.
    """
    with _tracer.start_as_current_span("nemo.action.self_check_output") as span:
        span.set_attribute("langfuse.observation.type", "span")
        span.set_attribute(
            "langfuse.trace.metadata.guardrail.action", "CustomSelfCheckOutputAction"
        )
        span.set_attribute("iso42001.control_id", "A.6.1.2")

        ctx = context or {}
        text = (
            ctx.get("bot_message")
            or ctx.get("last_bot_message")
            or kwargs.get("content")
            or ""
        ).lower()

        if not text:
            span.set_attribute("nemo.action.stage", "EMPTY")
            span.set_attribute("nemo.action.outcome", "ALLOW")
            return True

        # STAGE 1: BLOCKLIST — checked FIRST so a harmful output cannot be
        # short-circuited to ALLOW merely by co-mentioning a hedging word.
        harmful_patterns = [
            "guaranteed returns",
            "risk-free investment",
            "can't lose",
            "insider information",
            "sure thing",
            "100% profit",
            "no risk",
            "guaranteed profit",
            "get rich quick",
        ]

        if any(pattern in text for pattern in harmful_patterns):
            logger.warning("HybridSelfCheckOutput: STAGE 1 BLOCK (harmful pattern)")
            span.set_attribute("nemo.action.stage", "BLOCKLIST")
            span.set_attribute("nemo.action.outcome", "BLOCK")
            return False

        # STAGE 2: Safe financial content (allow without LLM check)
        safe_indicators = [
            "risk",
            "portfolio",
            "consider",
            "consult",
            "disclaimer",
            "not financial advice",
            "diversification",
            "volatility",
            "may",
            "could",
            "potential",
            "assessment",
        ]

        if any(indicator in text for indicator in safe_indicators):
            logger.debug(
                "HybridSelfCheckOutput: STAGE 2 ALLOW (safe financial content)"
            )
            span.set_attribute("nemo.action.stage", "SAFE_INDICATOR")
            span.set_attribute("nemo.action.outcome", "ALLOW")
            return True

        # STAGE 3: LLM JUDGE - For ambiguous outputs
        logger.info(
            "HybridSelfCheckOutput: STAGE 3 - Invoking LLM judge for ambiguous output"
        )
        span.set_attribute("nemo.action.stage", "LLM_JUDGE")

        try:
            from nemoguardrails.library.self_check.output_check import (
                self_check_output as nemo_self_check,
            )

            is_safe = await nemo_self_check(context=context, llm=llm)
            logger.info("HybridSelfCheckOutput: LLM judge result = %s", is_safe)
            span.set_attribute("nemo.action.outcome", "ALLOW" if is_safe else "BLOCK")
            return is_safe
        except Exception as e:
            # On LLM failure, fail CLOSED (block output to be safe)
            logger.error(
                "HybridSelfCheckOutput: LLM judge failed: %s - failing CLOSED", e
            )
            span.record_exception(e)
            span.set_attribute("nemo.action.stage", "LLM_JUDGE_FAILED")
            span.set_attribute("nemo.action.outcome", "BLOCK_ON_ERROR")
            return False  # Conservative: block if we can't verify safety


# ---------------------------------------------------------------------------
# Financial Policy Pass-Through Stubs (R-22 fix)
# ---------------------------------------------------------------------------
# These actions exist so the standalone nemo-service pod resolves its action
# registry without falling back to the synchronous stubs in nemo_actions.py.
#
# DESIGN: Financial policy enforcement was intentionally moved to the
# safety_check_node → OPA path on 2026-03-10 (see ARCHITECTURE.md §R-22).
# No active Colang flow in config/rails/main_logic.co invokes these actions.
# They are registered purely to keep nemo_action_registry.get_all_actions()
# operating on Priority 1 (config.rails.actions) without an ImportError.
#
# Audit visibility: every invocation emits an OTel span stamped
# PASS_THROUGH_OPA_AUTHORITATIVE so compliance reviewers can confirm
# these stubs are never called instead of real policy enforcement.
# ---------------------------------------------------------------------------


@action(name="CheckApprovalTokenAction")
async def check_approval_token_action(context: dict | None = None, **kwargs) -> bool:
    """Pass-through stub — approval-token enforcement owned by OPA safety_check_node.

    Financial policy (SC-1) is enforced by the safety_check_node → OPA path
    in the LangGraph graph.  This stub prevents action-not-found errors if a
    Colang flow referencing this action is ever re-enabled, and eliminates the
    ImportError fallback path in nemo_action_registry.get_all_actions().
    """
    with _tracer.start_as_current_span("nemo.action.check_approval_token") as span:
        span.set_attribute("langfuse.observation.type", "span")
        span.set_attribute(
            "langfuse.trace.metadata.guardrail.action", "CheckApprovalTokenAction"
        )
        span.set_attribute("iso42001.control_id", "A.6.1.2")
        span.set_attribute("nemo.action.outcome", "PASS_THROUGH_OPA_AUTHORITATIVE")
        span.set_attribute("nemo.action.stpa_ref", "SC-1")
        logger.debug(
            "CheckApprovalTokenAction: pass-through (OPA/safety_check_node is authoritative)"
        )
        return True


@action(name="CheckDataLatencyAction")
async def check_data_latency_action(context: dict | None = None, **kwargs) -> bool:
    """Pass-through stub — market data latency enforcement owned by OPA safety_check_node.

    Financial policy (FIN-2) is enforced by the safety_check_node → OPA path.
    See CheckApprovalTokenAction for rationale.
    """
    with _tracer.start_as_current_span("nemo.action.check_data_latency") as span:
        span.set_attribute("langfuse.observation.type", "span")
        span.set_attribute(
            "langfuse.trace.metadata.guardrail.action", "CheckDataLatencyAction"
        )
        span.set_attribute("iso42001.control_id", "A.6.1.2")
        span.set_attribute("nemo.action.outcome", "PASS_THROUGH_OPA_AUTHORITATIVE")
        span.set_attribute("nemo.action.stpa_ref", "FIN-2")
        logger.debug(
            "CheckDataLatencyAction: pass-through (OPA/safety_check_node is authoritative)"
        )
        return True


@action(name="CheckDrawdownLimitAction")
async def check_drawdown_limit_action(context: dict | None = None, **kwargs) -> bool:
    """Pass-through stub — drawdown limit enforcement owned by OPA safety_check_node.

    Financial policy (UCA-5) is enforced by the safety_check_node → OPA path.
    See CheckApprovalTokenAction for rationale.
    """
    with _tracer.start_as_current_span("nemo.action.check_drawdown_limit") as span:
        span.set_attribute("langfuse.observation.type", "span")
        span.set_attribute(
            "langfuse.trace.metadata.guardrail.action", "CheckDrawdownLimitAction"
        )
        span.set_attribute("iso42001.control_id", "A.6.1.2")
        span.set_attribute("nemo.action.outcome", "PASS_THROUGH_OPA_AUTHORITATIVE")
        span.set_attribute("nemo.action.stpa_ref", "UCA-5")
        logger.debug(
            "CheckDrawdownLimitAction: pass-through (OPA/safety_check_node is authoritative)"
        )
        return True


@action(name="CheckSlippageRiskAction")
async def check_slippage_risk_action(context: dict | None = None, **kwargs) -> bool:
    """Pass-through stub — slippage risk enforcement owned by OPA safety_check_node.

    Financial policy (UCA-6) is enforced by the safety_check_node → OPA path.
    See CheckApprovalTokenAction for rationale.
    """
    with _tracer.start_as_current_span("nemo.action.check_slippage_risk") as span:
        span.set_attribute("langfuse.observation.type", "span")
        span.set_attribute(
            "langfuse.trace.metadata.guardrail.action", "CheckSlippageRiskAction"
        )
        span.set_attribute("iso42001.control_id", "A.6.1.2")
        span.set_attribute("nemo.action.outcome", "PASS_THROUGH_OPA_AUTHORITATIVE")
        span.set_attribute("nemo.action.stpa_ref", "UCA-6")
        logger.debug(
            "CheckSlippageRiskAction: pass-through (OPA/safety_check_node is authoritative)"
        )
        return True


@action(name="CheckAtomicExecutionAction")
async def check_atomic_execution_action(context: dict | None = None, **kwargs) -> bool:
    """Pass-through stub — atomic execution enforcement owned by OPA safety_check_node.

    Multi-leg trade atomicity (UCA-4) is enforced by the LangGraph Saga WAL path.
    See CheckApprovalTokenAction for rationale.
    """
    with _tracer.start_as_current_span("nemo.action.check_atomic_execution") as span:
        span.set_attribute("langfuse.observation.type", "span")
        span.set_attribute(
            "langfuse.trace.metadata.guardrail.action", "CheckAtomicExecutionAction"
        )
        span.set_attribute("iso42001.control_id", "A.6.1.2")
        span.set_attribute("nemo.action.outcome", "PASS_THROUGH_OPA_AUTHORITATIVE")
        span.set_attribute("nemo.action.stpa_ref", "UCA-4")
        logger.debug(
            "CheckAtomicExecutionAction: pass-through (Saga WAL is authoritative)"
        )
        return True


@action(name="LogSafetyAuditAction")
async def log_safety_audit_action(context: dict | None = None, **kwargs) -> bool:
    """Explicit no-op audit log stub (declared in definitions.co).

    Declared in config/rails/definitions.co as ``action LogSafetyAuditAction``.
    Emits an OTel span so any invocation is visible in Langfuse.
    """
    with _tracer.start_as_current_span("nemo.action.log_safety_audit") as span:
        span.set_attribute("langfuse.observation.type", "span")
        span.set_attribute(
            "langfuse.trace.metadata.guardrail.action", "LogSafetyAuditAction"
        )
        span.set_attribute("iso42001.control_id", "A.6.2.8")
        span.set_attribute("nemo.action.outcome", "LOGGED")
        event_type = (
            (context or {}).get("event_type", "unknown") if context else "unknown"
        )
        logger.info(
            "LogSafetyAuditAction: safety event logged (event_type=%s)", event_type
        )
        return True


__all__ = [
    "check_approval_token_action",
    "check_atomic_execution_action",
    "check_data_latency_action",
    "check_drawdown_limit_action",
    "check_slippage_risk_action",
    "custom_self_check_input",
    "custom_self_check_output",
    "log_safety_audit_action",
    "mask_pii_action",
    "retrieve_knowledge",
]

# NOTE: InvokeVllmFallbackAction is registered via nemo_action_registry.py
# which is the canonical registration mechanism for this deployment.
# See: src/governed_financial_advisor/governance/nemo_action_registry.py

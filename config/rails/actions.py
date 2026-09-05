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

from src.gateway.observability.attributes import (
    OBSERVATION_TYPE,
    TRACE_METADATA_GUARDRAIL_ACTION,
)

# Import the ContextVar from manager.py so Stage-1/1'/1B/1C/1D deterministic
# block verdicts can be signalled back to validate_with_nemo().  The import is
# wrapped in a try/except so the action module remains importable in restricted
# unit-test environments where the full gateway stack is not available.
try:
    from src.gateway.governance.nemo.manager import (
        _deterministic_verdict as _det_verdict,
    )

    def _mark_deterministic() -> None:
        """Set the per-request deterministic-verdict flag to True."""
        _det_verdict.set(True)

except ImportError:

    def _mark_deterministic() -> None:  # type: ignore[misc]
        """No-op fallback when manager is not importable."""
        pass


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
        span.set_attribute(OBSERVATION_TYPE, "span")
        span.set_attribute(TRACE_METADATA_GUARDRAIL_ACTION, "RetrieveKnowledgeAction")
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
        span.set_attribute(OBSERVATION_TYPE, "span")
        span.set_attribute(TRACE_METADATA_GUARDRAIL_ACTION, "MaskPIIAction")
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

    Stage order (ORDER IS SECURITY-CRITICAL — do not reorder without a
    security review):

    1'. detect_prompt_injection() — structural injection detector
        (prompt_injection_detector.py), the SINGLE authoritative source
        for AI/LLM injection patterns. Runs FIRST, unconditionally.
        → BLOCK (0ms) on any match.
    1.  Residual jailbreak substring scan — narrow list of attack phrases
        whose coverage is BROADER than the regex patterns in Stage 1' (e.g.
        bare "pretend you", "roleplay as", "act as if" without a restriction
        qualifier; "system:" without a bracket; "act as a developer with root
        access"). Kept as a defence-in-depth thin wrapper.
        → BLOCK (0ms) on any match.
    1B. Illegal-finance blocklist — harmful_financial category payloads
        (insider trading, money laundering, pump-and-dump, etc.) that co-
        mention financial keywords and would otherwise bypass via Stage 2
        ALLOW. Different threat class from injection; kept in full.
        → BLOCK (0ms) on any match.
    1C. Structural-attack blocklist — SQL injection syntax ('; DROP …,
        UNION SELECT, xp_cmdshell) and HTML/script injection (<script>,
        javascript:, onerror=). Different threat class from AI injection;
        kept in full. Does NOT re-invoke detect_prompt_injection() (already
        handled by Stage 1' above).
        → BLOCK (0ms) on any match.
    1D. Authorization-claim / impersonation detector (PR 2) — RBAC
        escalation attempts (detect_authorization_claim).
        → BLOCK (0ms) on any match.
    1E. Confidence-spoofing / human-review suppression detector —
        numeric confidence overrides, API parameter injection
        (bypass_review, auto_approve), certainty claims, negation-
        uncertainty framing, and skip-review imperatives
        (detect_confidence_claim).
        → BLOCK (0ms) on any match.
    2.  Financial-keyword allowlist — fast-path ALLOW for known-safe queries.
        → ALLOW (0ms) [~70% of queries]
    3.  LLM judge — semantic analysis for ambiguous cases.
        → EVALUATE (2-5s) [~25% of queries]

    SECURITY NOTE (2026-08-02): The blocklist MUST run before the allowlist.
    Running the allowlist first (as this function originally did) allows any
    injection payload that also mentions a common finance word (e.g.
    "trading", "stock", "analyze", "market") to short-circuit ALLOW before
    the jailbreak blocklist is ever consulted — this was measured to let
    4/6 adversarial prompt-injection payloads (INJ-001, INJ-003, INJ-004,
    INJ-005) bypass detection entirely, since each one references finance in
    the same sentence as its attack. See docs/paper/REVISION_TRACKER.md for
    the full measurement writeup.

    SECURITY NOTE (2026-08-03): The illegal-finance blocklist (STAGE 1B) must
    also run before the allowlist. HARM-002 ("money laundering...trading profits")
    triggered the ALLOWLIST via "trading" before any harmful-finance check ran.
    See docs/paper/REVISION_TRACKER.md §2026-08-03.

    SECURITY NOTE (2026-08-03b): Stage 1C closes the allowlist-bypass
    architectural defect for code injection markers (SQL, HTML/script). See
    docs/paper/REVISION_TRACKER.md §2026-08-03b.

    SECURITY NOTE (2026-08-04 / PR 5): detect_prompt_injection() promoted to
    Stage 1' — the first check to run, before all other blocklist stages.
    Previously it was a sub-step inside Stage 1C after the hand-rolled
    substring scan. All injection patterns it covers (DAN mode, developer
    mode, bypass restrictions, forget instructions, you-are-unrestricted,
    etc.) have been removed from the Stage 1 residual list to eliminate
    the parallel-list maintenance drift that caused the 2026-08-04 defect
    class. Stage 1 is now a thin residual wrapper for patterns that are
    intentionally BROADER than the regex detector (see list below).
    """
    with _tracer.start_as_current_span("nemo.action.self_check_input") as span:
        span.set_attribute(OBSERVATION_TYPE, "span")
        span.set_attribute(
            TRACE_METADATA_GUARDRAIL_ACTION, "CustomSelfCheckInputAction"
        )
        span.set_attribute("iso42001.control_id", "A.6.1.2")

        ctx = context or {}
        text = (ctx.get("last_user_message") or kwargs.get("content") or "").lower()

        if not text:
            span.set_attribute("nemo.action.stage", "EMPTY")
            span.set_attribute("nemo.action.outcome", "ALLOW")
            return True

        # STAGE 1': STRUCTURAL INJECTION DETECTOR — detect_prompt_injection() is
        # the SINGLE authoritative source of truth for AI/LLM injection patterns.
        # Called unconditionally as the very first check so no downstream allowlist
        # can short-circuit ALLOW before it runs.
        #
        # Patterns covered (as of 2026-08-04): ignore_previous_instructions,
        # persona_override, you_are_unrestricted, fake_system_prompt,
        # chatml_injection, instruction_override, disregard_training,
        # jailbreak_dan, developer_mode_jailbreak, bypass_restrictions,
        # forget_instructions, role_play_bypass, system_prompt_extraction,
        # broadened_persona_override.
        try:
            from src.gateway.governance.prompt_injection_detector import (
                detect_prompt_injection,
            )

            _injection_result = detect_prompt_injection(text)
            if _injection_result.detected:
                logger.warning(
                    "HybridSelfCheckInput: STAGE 1' BLOCK (prompt_injection_detector "
                    "pattern=%s confidence=%.2f)",
                    _injection_result.pattern_matched,
                    _injection_result.confidence,
                )
                span.set_attribute("nemo.action.stage", "INJECTION_DETECTOR")
                span.set_attribute(
                    "nemo.action.injection_pattern",
                    _injection_result.pattern_matched or "unknown",
                )
                span.set_attribute("nemo.action.outcome", "BLOCK")
                _mark_deterministic()  # Stage 1' — structural/regex detector
                return False
        except ImportError:
            # prompt_injection_detector not importable in restricted test envs;
            # Stage 1 residual substring scan below still runs — graceful degradation.
            logger.debug(
                "HybridSelfCheckInput: STAGE 1' — prompt_injection_detector unavailable, "
                "falling through to residual substring scan"
            )

        # STAGE 1: RESIDUAL JAILBREAK SUBSTRING SCAN — thin defence-in-depth wrapper
        # for attack phrasings whose substring coverage is INTENTIONALLY BROADER than
        # the regex patterns in Stage 1'.  Each item is kept because the regex
        # requires a restriction-bypass qualifier that the substring does not:
        #
        #   "pretend you"    — role_play_bypass needs "no restrictions" qualifier
        #   "roleplay as"    — same
        #   "act as if"      — same
        #   "system:"        — fake_system_prompt needs "[" bracket after colon
        #   "act as a developer with root access" — defence-in-depth (also in
        #                      tier1_keywords Aho-Corasick scan)
        #
        # Items REMOVED from this list (now fully covered by Stage 1' / _INJECTION_PATTERNS):
        #   "ignore previous instructions", "ignore all previous",
        #   "dan mode", "developer mode", "repeat your prompt",
        #   "show me your system prompt", "bypass your restrictions",
        #   "you are now unrestricted", "jailbreak", "forget everything"
        residual_jailbreak_patterns = [
            "pretend you",
            "roleplay as",
            "act as if",
            "act as a developer with root access",
            "system:",
        ]

        if any(pattern in text for pattern in residual_jailbreak_patterns):
            logger.warning(
                "HybridSelfCheckInput: STAGE 1 BLOCK (residual jailbreak substring)"
            )
            span.set_attribute("nemo.action.stage", "RESIDUAL_JAILBREAK_BLOCKLIST")
            span.set_attribute("nemo.action.outcome", "BLOCK")
            _mark_deterministic()  # Stage 1 — keyword/substring blocklist
            return False

        # STAGE 1B: ILLEGAL-FINANCE BLOCKLIST — catches harmful_financial category
        # payloads that use financial keywords (triggering stage-2 ALLOW) while
        # describing explicitly illegal acts. These must be blocked BEFORE the
        # financial-keyword allowlist runs — HARM-002 ("...trading profits") was
        # observed to bypass via "trading" in the allowlist (2026-08-03 finding).
        # Different threat class from injection — kept in full.
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
            _mark_deterministic()  # Stage 1B — deterministic keyword blocklist
            return False

        # STAGE 1C: STRUCTURAL-ATTACK BLOCKLIST — SQL injection, HTML/script injection.
        # Checked before the Stage 2 allowlist so that payloads co-mentioning a
        # finance keyword (e.g. "'; DROP TABLE trades; -- Analyze ticker:AAPL",
        # "<script>steal()</script> analyze AAPL") do not short-circuit to ALLOW
        # before structural attack markers are detected. This is the identical
        # allowlist-bypass pattern fixed for jailbreaks in Stage 1 (2026-08-02)
        # and for illegal-finance in Stage 1B (2026-08-03).
        #
        # Note: detect_prompt_injection() is NOT re-invoked here — it already ran
        # as Stage 1' above.  This list covers SQL/code injection markers only,
        # which are a different threat class and are not expressed in _INJECTION_PATTERNS.
        structural_attack_patterns = [
            # SQL injection markers
            "; drop",
            "'; drop",
            '"; drop',
            "union select",
            "' or '1'='1",
            '" or "1"="1',
            "'; select",
            "--",  # SQL comment terminator in injection context checked below
            "/**/",  # SQL block comment bypass
            "xp_cmdshell",
            # HTML / script injection markers
            "<script",
            "</script>",
            "javascript:",
            "onerror=",
            "onload=",
            "<iframe",
            "<img src=",
        ]

        # The "--" token is a legitimate Markdown/CLI character; only block when it
        # appears adjacent to SQL syntax (i.e. after a quote or semicolon).
        _has_sql_comment = "--" in text and any(
            marker in text
            for marker in (";", "'", '"', "select", "insert", "update", "delete")
        )

        if (
            any(pat in text for pat in structural_attack_patterns if pat != "--")
            or _has_sql_comment
        ):
            logger.warning(
                "HybridSelfCheckInput: STAGE 1C BLOCK (structural-attack pattern)"
            )
            span.set_attribute("nemo.action.stage", "STRUCTURAL_ATTACK_BLOCKLIST")
            span.set_attribute("nemo.action.outcome", "BLOCK")
            _mark_deterministic()  # Stage 1C — structural SQL/HTML injection detector
            return False

        # STAGE 1D: Authorization-claim / impersonation detection.
        # Closes the rbac_escalation attack category (0 % deflection measured
        # 2026-08). Runs before the Stage 2 allowlist for the same reason as
        # Stage 1B/1C: payloads often co-mention financial keywords (execute,
        # trade, market) that would short-circuit ALLOW before the authority-
        # claim check runs. Universal — no CAGE_DEPLOYMENT_REGION guard.
        try:
            from src.gateway.governance.authorization_claim_detector import (
                detect_authorization_claim,
            )

            authclaim_result = detect_authorization_claim(text)
            if authclaim_result.detected:
                logger.warning(
                    "AuthClaimDetector: blocked category=%s confidence=%.2f",
                    authclaim_result.category,
                    authclaim_result.confidence,
                )
                span.set_attribute(
                    "nemo.action.authclaim_category",
                    authclaim_result.category or "",
                )
                span.set_attribute("nemo.action.outcome", "BLOCK_AUTHCLAIM")
                _mark_deterministic()  # Stage 1D — deterministic authorization-claim detector
                return False
        except ImportError:
            # authorization_claim_detector not importable in restricted test envs;
            # graceful degradation — previous stages still active.
            logger.debug(
                "HybridSelfCheckInput: STAGE 1D — authorization_claim_detector unavailable"
            )

        # STAGE 1E: Confidence-spoofing / human-review suppression detection.
        # Closes the confidence_spoofing attack category (CONF-SPOOF-002 through
        # 005 had zero detector coverage before this stage). Runs before the
        # Stage 2 allowlist for the same reason as Stage 1B/1C/1D: payloads
        # co-mention financial keywords (execute, trade, market, confidence)
        # that would short-circuit ALLOW before the confidence-claim check runs.
        # Universal — no CAGE_DEPLOYMENT_REGION guard required.
        try:
            from src.gateway.governance.confidence_claim_detector import (
                detect_confidence_claim,
            )

            _conf_result = detect_confidence_claim(text)
            if _conf_result.detected:
                _mark_deterministic()
                logger.warning(
                    "Stage 1E BLOCK: confidence_spoofing detected",
                    extra={
                        "pattern": _conf_result.pattern_matched,
                        "details": _conf_result.details,
                    },
                )
                span.set_attribute(
                    "nemo.action.confclaim_pattern",
                    _conf_result.pattern_matched or "",
                )
                span.set_attribute("nemo.action.outcome", "BLOCK_CONFCLAIM")
                return False
        except ImportError:
            # confidence_claim_detector not importable in restricted test envs;
            # graceful degradation — previous stages still active.
            logger.debug(
                "HybridSelfCheckInput: STAGE 1E — confidence_claim_detector unavailable"
            )

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
            # On LLM failure, fail CLOSED (block input) — an attacker inducing
            # timeouts or errors must not receive an automatic ALLOW. The OPA
            # downstream layer remains a second line of defence, but the
            # guardrail itself must be conservative on any LLM exception.
            logger.error(
                "HybridSelfCheckInput: LLM judge failed: %s - failing CLOSED (block)", e
            )
            span.record_exception(e)
            span.set_status(Status(StatusCode.ERROR, str(e)))
            span.set_attribute("nemo.action.stage", "LLM_JUDGE_FAILED")
            span.set_attribute("nemo.action.outcome", "BLOCK_ON_ERROR")
            return False


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
        span.set_attribute(OBSERVATION_TYPE, "span")
        span.set_attribute(
            TRACE_METADATA_GUARDRAIL_ACTION, "CustomSelfCheckOutputAction"
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
            # Trade operation confirmation words (prevent false positives on
            # terse trade confirmations such as "Your limit order has been
            # cancelled" — these contain none of the above hedging words and
            # were falling through to Stage 3 LLM judge, which errors under
            # certain conditions, triggering the fail-closed handler → FP).
            "order",
            "shares",
            "executed",
            "cancelled",
            "filled",
            "placed",
            "confirmed",
            "trade",
            "position",
            "market order",
            "limit order",
            "stop order",
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
        span.set_attribute(OBSERVATION_TYPE, "span")
        span.set_attribute(TRACE_METADATA_GUARDRAIL_ACTION, "CheckApprovalTokenAction")
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
        span.set_attribute(OBSERVATION_TYPE, "span")
        span.set_attribute(TRACE_METADATA_GUARDRAIL_ACTION, "CheckDataLatencyAction")
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
        span.set_attribute(OBSERVATION_TYPE, "span")
        span.set_attribute(TRACE_METADATA_GUARDRAIL_ACTION, "CheckDrawdownLimitAction")
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
        span.set_attribute(OBSERVATION_TYPE, "span")
        span.set_attribute(TRACE_METADATA_GUARDRAIL_ACTION, "CheckSlippageRiskAction")
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
        span.set_attribute(OBSERVATION_TYPE, "span")
        span.set_attribute(
            TRACE_METADATA_GUARDRAIL_ACTION, "CheckAtomicExecutionAction"
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
        span.set_attribute(OBSERVATION_TYPE, "span")
        span.set_attribute(TRACE_METADATA_GUARDRAIL_ACTION, "LogSafetyAuditAction")
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

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
NeMo guardrail-node factories — produce async LangGraph nodes for input/output rails.

The factories encapsulate:
  - NeMo LLMRails singleton management (``get_nemo_rails``)
  - ``validate_with_nemo()`` for input rails
  - ``verify_and_mask_output()`` for output rails
  - OTel span instrumentation with Langfuse attributes
  - Fail-closed exception handling (any error → blocked / sentinel)
  - CAGE_SEAL_ENFORCEMENT mode awareness

Domain-specific message extraction is injected via ``NemoNodeConfig.message_extractor``.
"""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Callable
from typing import Any

from opentelemetry import trace

from src.gateway.governance.langgraph_harness.types import NemoNodeConfig, StateDict

logger = logging.getLogger("gateway.governance.langgraph_harness.nemo_node_factory")
tracer = trace.get_tracer("src.gateway.governance.langgraph_harness.nemo_node_factory")


# ---------------------------------------------------------------------------
# NeMo singleton management — imported lazily so the harness doesn't blow
# up if nemoguardrails is not installed (fail-closed at runtime instead).
# ---------------------------------------------------------------------------

_nemo_rails = None
_NEMO_AVAILABLE = False

# Stubs — overwritten below if NeMo is installed.  These must always exist as
# module-level attributes so that unittest.mock.patch() can target them.
create_nemo_manager = None  # type: ignore[assignment]


async def validate_with_nemo(user_input, rails, pre_check_results=None) -> tuple:  # type: ignore[misc, no-untyped-def]
    """Fail-closed stub — NeMo not available."""
    raise RuntimeError("NeMo manager not available (validate_with_nemo stub)")


async def verify_and_mask_output(rails, text):  # type: ignore[misc, no-untyped-def]
    """Fail-closed stub — NeMo not available."""
    raise RuntimeError("NeMo manager not available (verify_and_mask_output stub)")


async def validate_output_semantics(rails, text):  # type: ignore[misc, no-untyped-def]
    """Fail-closed stub — NeMo not available."""
    raise RuntimeError("NeMo manager not available (validate_output_semantics stub)")


try:
    from src.gateway.governance.nemo.manager import (  # type: ignore[assignment]
        create_nemo_manager,
        validate_output_semantics,
        validate_with_nemo,
        verify_and_mask_output,
    )

    _NEMO_AVAILABLE = True
except ImportError:
    logger.warning("NeMo manager not importable — guardrail nodes will fail-closed")

# ---------------------------------------------------------------------------
# Presidio input-side PII scan — module-level singletons (Fix 3 / P1)
#
# Uses the same AnalyzerEngine + AnonymizerEngine pattern as manager.py's
# _build_presidio_action().  Engines are built once at import time and reused
# across all node invocations.  If Presidio is unavailable the singletons are
# None and the scan is skipped (graceful degradation).
# ---------------------------------------------------------------------------

_PII_ENTITIES: list[str] = [
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "EMAIL_ADDRESS",
    "LOCATION",
    "PERSON",
    "DATE_TIME",
    "NRP",
    "CRYPTO",
    "US_SSN",
    "US_ITIN",
    "US_PASSPORT",
    "US_BANK_NUMBER",
    "US_DRIVER_LICENSE",
    "IBAN_CODE",
    "IP_ADDRESS",
]

_presidio_analyzer = None
_presidio_anonymizer = None
_presidio_init_done = False


def _ensure_presidio_engines() -> None:
    """Lazy-initialise Presidio engines on first use.

    Presidio (spaCy + transformer NLP engine) takes ~2-3 s to import and
    build at module load time.  Because this module is imported by
    governance/__init__.py (and thus by every test file that touches the
    governance package), that cost was paid unconditionally at collection
    time — even for tests that never exercise the PII-scan path.

    Moving initialization here means the cost is only paid when the first
    actual NeMo guardrail invocation runs, not at pytest --collect-only.

    Tests that need to patch ``_presidio_analyzer`` / ``_presidio_anonymizer``
    can do so normally — the module-level names remain visible as ``None``
    until this function is called, and unittest.mock.patch replaces them
    before any call site reaches ``_ensure_presidio_engines()``.
    """
    global _presidio_analyzer, _presidio_anonymizer, _presidio_init_done
    if _presidio_init_done:
        return
    _presidio_init_done = True
    try:
        import spacy as _spacy
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider
        from presidio_anonymizer import AnonymizerEngine

        _spacy_model = (
            "en_core_web_lg"
            if _spacy.util.is_package("en_core_web_lg")
            else "en_core_web_sm"
        )
        _nlp_provider = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": _spacy_model}],
            }
        )
        _presidio_analyzer = AnalyzerEngine(
            nlp_engine=_nlp_provider.create_engine(),
            default_score_threshold=0.3,
        )
        _presidio_anonymizer = AnonymizerEngine()
        logger.info(
            "✅ Presidio input-PII engines initialised (model=%s, entities=%d)",
            _spacy_model,
            len(_PII_ENTITIES),
        )
    except ImportError:
        logger.warning(
            "⚠️ Presidio not available — input-side PII scan disabled (graceful degradation). "
            "Install presidio-analyzer, presidio-anonymizer, and a spaCy model to enable."
        )
    except Exception as _presidio_init_exc:
        logger.warning(
            "⚠️ Presidio engine initialisation failed — input-side PII scan disabled: %s",
            _presidio_init_exc,
        )

# ---------------------------------------------------------------------------
# SymbolicGovernor singleton — imported lazily to avoid circular imports.
# Used to call pre_check() before NeMo rails so actions receive pre-computed
# STPA/CBF results via context instead of calling back into the governor.
# ---------------------------------------------------------------------------
_symbolic_governor = None


def _get_symbolic_governor():  # type: ignore[no-untyped-def]
    """Return the SymbolicGovernor singleton, or None if unavailable."""
    global _symbolic_governor
    if _symbolic_governor is None:
        try:
            from src.gateway.governance.singletons import symbolic_governor

            _symbolic_governor = symbolic_governor
        except Exception as exc:
            logger.warning(
                "⚠️ Could not import symbolic_governor singleton (%s) — "
                "NeMo actions will use fail-open defaults.",
                exc,
            )
    return _symbolic_governor


_nemo_reload_lock: asyncio.Lock | None = None


def _get_reload_lock() -> asyncio.Lock:
    """Return (lazily creating) the module-level reload lock.

    A factory is used instead of a module-level instantiation because
    ``asyncio.Lock()`` must be created inside a running event-loop context on
    Python ≥ 3.10.
    """
    global _nemo_reload_lock
    if _nemo_reload_lock is None:
        _nemo_reload_lock = asyncio.Lock()
    return _nemo_reload_lock


async def reload_nemo_rails(config_path: str = "config/rails") -> None:
    """Atomically replace the module-level ``LLMRails`` singleton.

    Called by the GFA hot-reload approval endpoint so that a rail-config
    update is propagated to **all** call sites (graph nodes, tools, server
    endpoints) in a single atomic swap rather than each call site maintaining
    its own independent ``LLMRails`` instance.

    The swap is guarded by ``_nemo_reload_lock`` to prevent a race between
    an in-flight ``validate_with_nemo()`` call and a concurrent reload.  The
    lock is intentionally coarse-grained (covers the entire manager creation)
    because ``create_nemo_manager()`` is fast relative to the safety margin
    required for governance-critical rail changes.

    Args:
        config_path: Path to the NeMo Guardrails config directory.
            Defaults to ``"config/rails"`` (same default used by
            ``get_nemo_rails()``).
    """
    global _nemo_rails
    async with _get_reload_lock():
        logger.info(
            "nemo_singleton_reload_start",
            extra={"config_path": config_path},
        )
        new_rails = create_nemo_manager(config_path=config_path)  # type: ignore[misc]  # create_nemo_manager is set at import; None only before _NEMO_AVAILABLE guard
        _nemo_rails = new_rails
        logger.info(
            "nemo_singleton_reload_complete",
            extra={"config_path": config_path},
        )


def get_nemo_rails():  # type: ignore[no-untyped-def]
    """Return the singleton LLMRails instance, initializing on first call.

    Raises ``RuntimeError`` (fail-closed) if initialization fails.
    """
    global _nemo_rails
    if _nemo_rails is None:
        if not _NEMO_AVAILABLE:
            raise RuntimeError(
                "NeMo manager not available. Cannot initialize guardrail. "
                "Ensure nemoguardrails is installed and config/rails/ is accessible."
            )
        logger.info("Initializing NeMo rails singleton for harness guardrail node")
        _nemo_rails = create_nemo_manager()  # type: ignore[misc]  # create_nemo_manager is set at import; None only before _NEMO_AVAILABLE guard
        logger.info("NeMo rails singleton initialized successfully")
    return _nemo_rails


# ---------------------------------------------------------------------------
# Default extractors — used when config.message_extractor is None
# ---------------------------------------------------------------------------


def _default_user_message_extractor(state: StateDict) -> str:
    """Extract the most recent user message text from ``state["messages"]``.

    Handles ``BaseMessage`` objects, raw dicts, and tuples defensively.
    """
    messages = state.get("messages", [])
    if not messages:
        return ""
    last_msg = messages[-1]
    if hasattr(last_msg, "content"):
        return str(last_msg.content)
    if isinstance(last_msg, dict):
        return str(last_msg.get("content", ""))
    if isinstance(last_msg, tuple) and len(last_msg) >= 2:
        return str(last_msg[1])
    return str(last_msg)


def _default_ai_message_extractor(state: StateDict) -> tuple[str, bool]:
    """Extract the last AI/assistant message content from ``state["messages"]``.

    Returns ``(content, found)``.
    """
    messages = state.get("messages", [])
    if not messages:
        return "", False
    last_msg = messages[-1]
    try:
        from langchain_core.messages import BaseMessage as _LCBaseMessage

        if isinstance(last_msg, _LCBaseMessage):
            return str(last_msg.content), True
    except ImportError:
        if hasattr(last_msg, "content"):
            return str(last_msg.content), True
    if isinstance(last_msg, dict):
        return str(last_msg.get("content", "")), True
    if isinstance(last_msg, tuple) and len(last_msg) >= 2:
        return str(last_msg[1]), True
    return str(last_msg), True


# ---------------------------------------------------------------------------
# Input rail factory
# ---------------------------------------------------------------------------


def create_nemo_guardrail_node(config: NemoNodeConfig | None = None) -> Callable:
    """Return an async LangGraph node for mandatory NeMo input rail enforcement.

    The returned node:
      1. Extracts user input via ``config.message_extractor`` (or default).
      2. Calls ``validate_with_nemo()`` — NeMo input rails (LLM-backed filter).
      3. Sets ``config.blocked_state_key`` and ``config.reason_state_key``.
      4. Fail-closed: any exception → block.
      5. Respects ``CAGE_SEAL_ENFORCEMENT`` env var for dev/log-only mode.

    If ``config.pass_through_state`` is ``True`` (default), the returned dict
    includes ``{**state, ...}`` so that downstream conditional edges can read
    pre-existing state keys.

    Args:
        config: Optional :class:`NemoNodeConfig`.  ``None`` uses defaults.

    Returns:
        An ``async def nemo_guardrail_node(state) -> dict`` for
        ``workflow.add_node()``.
    """
    cfg = config or NemoNodeConfig()
    _extract = cfg.message_extractor or _default_user_message_extractor

    # Eagerly warm up the Presidio/spaCy engines when the node is constructed
    # (i.e. once, at LangGraph build time / process startup) rather than
    # lazily on the first live request. create_nemo_guardrail_node() is only
    # called once per process (see governed_financial_advisor/graph/nodes/
    # guardrail_node.py), so this pays the ~0.2-2s Presidio/spaCy init cost
    # a single time at startup instead of on the first user-facing trade or
    # inference call — which would otherwise silently blow the Tier 1 input
    # rail's latency budget for that one unlucky request.
    # _ensure_presidio_engines() is idempotent (guarded by
    # _presidio_init_done), so repeated calls (e.g. across multiple node
    # instances in tests) are cheap after the first.
    _ensure_presidio_engines()

    async def nemo_guardrail_node(state: StateDict) -> dict[str, Any]:
        with tracer.start_as_current_span("nemo.input_rail") as span:
            span.set_attribute("langfuse.observation.type", "span")

            user_input = _extract(state)

            if not user_input or not user_input.strip():
                logger.warning(
                    "nemo_guardrail_node: no user input found in state — blocking by default"
                )
                span.set_attribute("nemo.input_rail.result", "BLOCKED")
                span.set_attribute("nemo.input_rail.reason", "empty_input")
                base = {**state} if cfg.pass_through_state else {}
                return {
                    **base,
                    cfg.blocked_state_key: True,
                    cfg.reason_state_key: "STPA: empty or missing input",
                }

            span.set_attribute("nemo.input_rail.input_length", len(user_input))

            cage_enforcement = os.environ.get(
                "CAGE_SEAL_ENFORCEMENT", "enforce"
            ).lower()
            span.set_attribute("nemo.cage_enforcement", cage_enforcement)

            try:
                rails = get_nemo_rails()

                # --- Pre-check injection (re-entrant loop fix) ---
                # Call symbolic_governor.pre_check() ONCE here, before NeMo rails
                # run, and inject the results into the NeMo context.  NeMo actions
                # (CheckApprovalTokenAction, CheckDataLatencyAction, etc.) will read
                # from context["pre_check_results"] instead of calling back into the
                # governor's sub-components — eliminating the double-execution of
                # stpa_validator.validate() and safety_filter.verify_action().
                pre_check_results: dict | None = None
                governor = _get_symbolic_governor()
                if governor is not None:
                    # Extract governance params from state if available
                    governance_params = state.get("governance_params", {})
                    if not governance_params:
                        # Fall back to extracting what we can from state
                        governance_params = {
                            k: state[k]
                            for k in (
                                "approval_token",
                                "amount",
                                "symbol",
                                "latency_ms",
                                "drawdown_pct",
                                "order_size",
                                "daily_vol",
                                "confidence",
                                "risk_assessed",
                                "compliance_checked",
                            )
                            if k in state
                        }
                    try:
                        pre_check_results = await governor.pre_check(governance_params)
                        logger.debug(
                            "🔍 nemo_guardrail_node: pre_check complete "
                            "(stpa_allowed=%s, cbf_allowed=%s)",
                            pre_check_results.get("stpa_result", {}).get(
                                "allowed", "?"
                            ),
                            pre_check_results.get("cbf_result", {}).get("allowed", "?"),
                        )
                    except Exception as pre_exc:
                        logger.warning(
                            "⚠️ nemo_guardrail_node: pre_check failed (%s) — "
                            "NeMo actions will use fail-open defaults.",
                            pre_exc,
                        )

                # --- Input-side PII scan (Fix 3 / P1) ---
                # Scan the input for PII BEFORE it reaches the LLM.  If PII is
                # detected, redact it in-place so the downstream NeMo rail and
                # any LLM call never see raw personal data.
                # The scan is wrapped in try/except so a Presidio failure never
                # blocks the input rail (graceful degradation).
                try:
                    _ensure_presidio_engines()
                    if (
                        _presidio_analyzer is not None
                        and _presidio_anonymizer is not None
                    ):
                        pii_results = _presidio_analyzer.analyze(
                            text=user_input,
                            entities=_PII_ENTITIES,
                            language="en",
                        )
                        if pii_results:
                            entity_types: list[str] = sorted(
                                {r.entity_type for r in pii_results}
                            )
                            logger.warning(
                                "⚠️ Input PII detected — redacting before NeMo rail "
                                "(entity_types=%s, count=%d). Raw values NOT logged.",
                                entity_types,
                                len(pii_results),
                            )
                            from presidio_anonymizer.entities import OperatorConfig

                            anonymized = _presidio_anonymizer.anonymize(
                                text=user_input,
                                analyzer_results=pii_results,  # type: ignore[arg-type]
                                operators={
                                    et: OperatorConfig(
                                        "replace", {"new_value": f"<{et}>"}
                                    )
                                    for et in entity_types
                                },
                            )
                            user_input = anonymized.text
                            # OTel audit trail — types only, never values
                            span.set_attribute("input.pii_redacted", True)
                            span.set_attribute(
                                "input.pii_entity_types", str(entity_types)
                            )
                        else:
                            span.set_attribute("input.pii_redacted", False)
                    else:
                        span.set_attribute("input.pii_redacted", False)
                except Exception as pii_exc:
                    logger.warning(
                        "⚠️ Input PII scan failed — continuing without redaction: %s",
                        pii_exc,
                    )
                    span.set_attribute("input.pii_redacted", False)

                is_safe, reason, deterministic = await validate_with_nemo(
                    user_input, rails, pre_check_results=pre_check_results
                )
                span.set_attribute(
                    "nemo.input_rail.result",
                    "PASSED" if is_safe else "BLOCKED",
                )
                span.set_attribute("nemo.input_rail.reason", reason or "")
                span.set_attribute("nemo.input_rail.deterministic", deterministic)
            except Exception as exc:
                if cage_enforcement == "enforce":
                    logger.error(
                        "nemo_guardrail_node: exception during validate_with_nemo — blocking: %s",
                        exc,
                    )
                    span.record_exception(exc)
                    span.set_status(trace.Status(trace.StatusCode.ERROR, str(exc)))
                    base = {**state} if cfg.pass_through_state else {}
                    return {
                        **base,
                        cfg.blocked_state_key: True,
                        cfg.reason_state_key: f"GUARDRAIL_ERROR: {exc}",
                    }
                else:
                    logger.warning(
                        "nemo_guardrail_node: exception (enforcement=%s) — proceeding anyway: %s",
                        cage_enforcement,
                        exc,
                    )
                    base = {**state} if cfg.pass_through_state else {}
                    return {
                        **base,
                        cfg.blocked_state_key: False,
                        cfg.reason_state_key: "",
                    }

            if not is_safe:
                if deterministic or cage_enforcement == "enforce":
                    # Hard-block when:
                    #   (a) the verdict came from a deterministic stage (Stage 1/1'/1B/1C/1D) — always block
                    #       regardless of enforcement mode, because these detectors have zero false-positive
                    #       risk and are the primary defence against regex/keyword/structural attacks; OR
                    #   (b) CAGE_SEAL_ENFORCEMENT=enforce — enforce mode always blocks on any unsafe verdict.
                    #
                    # The stochastic Stage-3 LLM judge with enforcement=log is the ONLY path that proceeds
                    # despite an unsafe verdict.
                    logger.warning(
                        "nemo_guardrail_node: input BLOCKED (deterministic=%s, enforcement=%s) — reason: %s",
                        deterministic,
                        cage_enforcement,
                        reason,
                    )
                    base = {**state} if cfg.pass_through_state else {}
                    return {
                        **base,
                        cfg.blocked_state_key: True,
                        cfg.reason_state_key: reason,
                    }
                else:
                    logger.warning(
                        "⚠️ nemo_guardrail_node: input flagged by non-deterministic stage "
                        "(enforcement=%s) — proceeding. reason: %s",
                        cage_enforcement,
                        reason,
                    )

            logger.info("nemo_guardrail_node: input PASSED — proceeding")
            base = {**state} if cfg.pass_through_state else {}
            return {
                **base,
                cfg.blocked_state_key: False,
                cfg.reason_state_key: "",
            }

    nemo_guardrail_node.__qualname__ = "nemo_guardrail_node[harness]"
    return nemo_guardrail_node


# ---------------------------------------------------------------------------
# Output rail factory
# ---------------------------------------------------------------------------


def create_nemo_output_rail_node(config: NemoNodeConfig | None = None) -> Callable:
    """Return an async LangGraph node for mandatory NeMo output rail enforcement.

    The returned node:
      1. Extracts the last AI message from ``state["messages"]``.
      2. Calls ``verify_and_mask_output()`` — NeMo output rails (PII, policy).
      3. Returns a replacement ``AIMessage`` with the same ``id`` (for the
         ``add_messages`` reducer to replace in-place).
      4. Fail-closed: any exception → output replaced with a safe sentinel.

    Args:
        config: Optional :class:`NemoNodeConfig`.  ``None`` uses defaults.

    Returns:
        An ``async def nemo_output_rail_node(state) -> dict`` for
        ``workflow.add_node()``.
    """
    cfg = config or NemoNodeConfig()

    async def nemo_output_rail_node(state: StateDict) -> dict[str, Any]:
        with tracer.start_as_current_span("nemo.output_rail") as span:
            span.set_attribute("langfuse.observation.type", "span")

            output_text, found = _default_ai_message_extractor(state)

            if not found or not output_text.strip():
                logger.warning(
                    "nemo_output_rail_node: no AI message found in state — nothing to screen"
                )
                span.set_attribute("nemo.output_rail.skipped", True)
                return {cfg.output_rail_applied_key: True}

            span.set_attribute("nemo.output_rail.input_length", len(output_text))

            cage_enforcement = os.environ.get(
                "CAGE_SEAL_ENFORCEMENT", "enforce"
            ).lower()
            span.set_attribute("nemo.cage_enforcement", cage_enforcement)

            # --- Optimization opportunity (Group D / D2) ---
            # Currently PII masking and semantic validation are two sequential
            # NeMo LLMRails invocations on the same LLMRails instance.  They
            # cannot be collapsed into a single Colang execution pass without a
            # dedicated combined output flow in config/rails/main_logic.co.
            #
            # What a future combined Colang flow would look like:
            #
            #   flow verify and validate output $output_text
            #     $masked = await MaskPIIAction text=$output_text
            #     $safe   = await CustomSelfCheckOutputAction text=$masked
            #     if not $safe
            #       bot refuse to respond
            #       abort
            #     return $masked
            #
            # Once that flow exists, both calls below collapse to a single
            # rails.generate() invocation, saving one full LLM round-trip per
            # request on the output path.  Track this as a Colang authoring task.
            #
            # OTel attributes below make the two-call cost visible in traces so
            # it can be measured and prioritised for the Colang authoring sprint.
            span.set_attribute("nemo.output_rail.pii_mask_call", 1)
            span.set_attribute("nemo.output_rail.semantic_validate_call", 1)
            span.set_attribute("nemo.output_rail.total_llm_calls", 2)
            span.set_attribute(
                "nemo.output_rail.optimization_opportunity",
                "combine_into_single_colang_flow",
            )

            # --- Call 1 of 2: PII masking ---
            try:
                rails = get_nemo_rails()
                masked_text = await verify_and_mask_output(rails, output_text)
                span.set_attribute(
                    "nemo.output_rail.masked", masked_text != output_text
                )
            except Exception as exc:
                logger.error(
                    "nemo_output_rail_node: verify_and_mask_output raised — blocking output: %s",
                    exc,
                )
                span.record_exception(exc)
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(exc)))
                masked_text = cfg.output_blocked_sentinel

            # --- Call 2 of 2: Semantic safety validation ---
            # Run validate_output_semantics() on the PII-masked text.
            # In enforce mode: block on UNSAFE verdict.
            # In log mode: warn but pass through.
            final_text = masked_text
            try:
                rails = get_nemo_rails()
                sem_safe, sem_reason = await validate_output_semantics(
                    rails, masked_text
                )
                span.set_attribute("output.semantic_validated", True)
                span.set_attribute("output.semantic_safe", sem_safe)
                if not sem_safe:
                    if cage_enforcement == "enforce":
                        logger.warning(
                            "nemo_output_rail_node: output BLOCKED by semantic validation — reason: %s",
                            sem_reason,
                        )
                        span.set_attribute("output.semantic_blocked", True)
                        final_text = cfg.output_blocked_sentinel
                    else:
                        logger.warning(
                            "⚠️ nemo_output_rail_node: output flagged by semantic validation "
                            "(enforcement=%s) — passing through. reason: %s",
                            cage_enforcement,
                            sem_reason,
                        )
                        span.set_attribute("output.semantic_flagged", True)
                else:
                    logger.debug("nemo_output_rail_node: semantic validation PASSED")
            except Exception as sem_exc:
                logger.error(
                    "nemo_output_rail_node: validate_output_semantics raised — "
                    "applying fail-closed logic (enforcement=%s): %s",
                    cage_enforcement,
                    sem_exc,
                )
                span.set_attribute("output.semantic_validated", False)
                if cage_enforcement == "enforce":
                    span.set_attribute("output.semantic_blocked", True)
                    final_text = cfg.output_blocked_sentinel
                else:
                    span.set_attribute("output.semantic_flagged", True)

            # Write the final text back.  add_messages reducer replaces an
            # existing message when the returned message carries the same id.
            messages = state.get("messages", [])
            last_msg = messages[-1] if messages else None

            try:
                from langchain_core.messages import (
                    AIMessage as _LCAIMessage,
                    BaseMessage as _LCBaseMessage,
                )

                if isinstance(last_msg, _LCBaseMessage) and last_msg.id:
                    replacement = _LCAIMessage(content=final_text, id=last_msg.id)
                else:
                    replacement = _LCAIMessage(content=final_text)
            except ImportError:
                replacement = {"role": "assistant", "content": final_text}  # type: ignore[assignment]

            logger.info("nemo_output_rail_node: output rail applied")
            return {
                "messages": [replacement],
                cfg.output_rail_applied_key: True,
            }

    nemo_output_rail_node.__qualname__ = "nemo_output_rail_node[harness]"
    return nemo_output_rail_node

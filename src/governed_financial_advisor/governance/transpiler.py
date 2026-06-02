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
Policy Transpiler — converts STPA Unsafe Control Actions (UCAs) into
NeMo Guardrails action stubs and OPA Rego policy fragments.

Uses an OpenAI-compatible LLM (via ChatOpenAI pointed at the local vLLM
inference stack) when credentials are available, otherwise falls back to
deterministic templates. Any OpenAI-compatible endpoint is supported —
set OPENAI_API_BASE / OPENAI_API_KEY in the environment.
"""

import logging
import os
import re
import textwrap
from typing import Optional

logger = logging.getLogger("governance.transpiler")

# Import LLM at module level so tests can patch it via
# "src.governed_financial_advisor.governance.transpiler.ChatOpenAI".
# If the library is absent (e.g. minimal test environment), the name is set to
# None and the transpiler falls back to deterministic templates.
try:
    from langchain_openai import ChatOpenAI  # noqa: F401
except ImportError:
    ChatOpenAI = None  # type: ignore[assignment,misc]


# ---------------------------------------------------------------------------
# Judge Agent — lightweight verifier that checks generated code quality
# ---------------------------------------------------------------------------

class JudgeAgent:
    """Evaluates LLM-generated policy code for correctness."""

    def verify(self, code: str) -> bool:
        """Return True if the generated code looks syntactically reasonable."""
        if not code or not code.strip():
            return False
        # Basic structural checks
        return "def " in code or "decision" in code or "package" in code


# ---------------------------------------------------------------------------
# Policy Transpiler
# ---------------------------------------------------------------------------

_NEMO_ACTION_TEMPLATE = textwrap.dedent(
    """\
    def check_{func_name}(context: dict) -> bool:
        \"\"\"Auto-generated NeMo action for hazard: {hazard}.

        Constraint: {variable} {operator} {threshold}
        \"\"\"
        value = context.get("{variable}")
        if value is None:
            return False  # fail-closed
        try:
            return not (float(value) {operator} {threshold})
        except (TypeError, ValueError):
            return False
    """
)

_REGO_POLICY_TEMPLATE = textwrap.dedent(
    """\
    package trade.governance

    import future.keywords.if

    default decision = "DENY"

    decision = "ALLOW" if {{
        input.action != "execute_trade"
    }}
    """
)


# ---------------------------------------------------------------------------
# Hazard-to-function-name mapping (merged from legacy src.governance.transpiler)
# ---------------------------------------------------------------------------

_HAZARD_TO_FUNC = {
    "slippage": "slippage_risk",
    "drawdown": "drawdown_limit",
    "latency": "data_latency",
    "approval": "approval_token",
    "atomic": "atomic_execution",
}


class PolicyTranspiler:
    """Converts ProposedUCA objects into executable governance artefacts."""

    # Known hazard→function name mappings (case-insensitive, substring match).
    # Merged from legacy src.governance.transpiler (R-03).
    _HAZARD_TO_FUNC = _HAZARD_TO_FUNC

    def __init__(self) -> None:
        self._llm = None
        self.use_llm: bool = False
        self._judge = JudgeAgent()

        # Attempt to initialise the LLM client; fail gracefully if creds absent.
        # ChatOpenAI is imported at module level so tests can patch it.
        # Supports any OpenAI-compatible endpoint (local vLLM, OpenAI, etc.) via
        # OPENAI_API_BASE and OPENAI_API_KEY environment variables.
        if ChatOpenAI is not None:
            try:
                api_key = os.environ.get("OPENAI_API_KEY", "not-needed-for-local")
                api_base = os.environ.get("OPENAI_API_BASE") or os.environ.get("VLLM_FAST_API_BASE")
                model = os.environ.get("TRANSPILER_MODEL") or os.environ.get("MODEL_FAST")
                kwargs: dict = {"model": model, "api_key": api_key}
                if api_base:
                    kwargs["base_url"] = api_base
                self._llm = ChatOpenAI(**kwargs)
                self.use_llm = True
                logger.debug("PolicyTranspiler: LLM initialised (model=%s, base_url=%s)", model, api_base)
            except Exception as exc:
                logger.warning("PolicyTranspiler: LLM unavailable (%s) — using templates", exc)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _generate_with_llm(self, prompt: str) -> str:
        """Call the LLM with *prompt* and return the text content."""
        if not self._llm:
            raise RuntimeError("LLM is not initialised")
        response = self._llm.invoke(prompt)
        return response.content if hasattr(response, "content") else str(response)

    def _safe_func_name(self, text: str) -> str:
        """Return a deterministic Python identifier for *text*.

        Uses _HAZARD_TO_FUNC for well-known hazard keywords (merged from
        legacy src.governance.transpiler — R-03), then falls back to a
        generic slug for unknown hazards.
        """
        lower = text.lower()
        for keyword, func_suffix in self._HAZARD_TO_FUNC.items():
            if keyword in lower:
                return func_suffix
        # Generic fallback
        return re.sub(r"[^a-z0-9_]", "_", lower)[:40].strip("_")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_nemo_action(self, uca) -> str:
        """Generate a Python NeMo Guardrails action stub for *uca*.

        Args:
            uca: A ``ProposedUCA`` instance.

        Returns:
            Python source string containing the action function.
        """
        logic = uca.constraint_logic

        if self.use_llm:
            prompt = (
                f"Generate a Python NeMo Guardrails action function to enforce the following constraint.\n"
                f"Hazard: {uca.hazard}\n"
                f"Description: {uca.description}\n"
                f"Constraint: {logic.variable} {logic.operator} {logic.threshold}\n"
                f"Condition: {logic.condition or 'always'}\n\n"
                f"The function must be named 'check_{self._safe_func_name(uca.hazard)}' and return bool.\n"
                f"Fail-closed: return False on any missing or invalid input.\n"
                f"Output only the Python function, no explanation."
            )
            try:
                code = self._generate_with_llm(prompt)
                if self._judge.verify(code):
                    return code
                logger.warning("PolicyTranspiler: judge rejected LLM output, using template")
            except Exception as exc:
                logger.warning("PolicyTranspiler: LLM call failed (%s), using template", exc)

        # Template fallback
        func_name = self._safe_func_name(uca.hazard or "check")
        return _NEMO_ACTION_TEMPLATE.format(
            func_name=func_name,
            hazard=uca.hazard,
            variable=logic.variable,
            operator=logic.operator,
            threshold=logic.threshold,
        )

    def generate_rego_policy(self, uca) -> str:
        """Generate an OPA Rego policy fragment for *uca*.

        Args:
            uca: A ``ProposedUCA`` instance.

        Returns:
            Rego source string.
        """
        if self.use_llm:
            logic = uca.constraint_logic
            prompt = (
                f"Generate an OPA Rego policy for the following financial governance constraint.\n"
                f"Hazard: {uca.hazard}\n"
                f"Description: {uca.description}\n"
                f"Constraint: {logic.variable} {logic.operator} {logic.threshold}\n\n"
                f"The policy must:\n"
                f"  - Start with 'package trade.governance'\n"
                f"  - Set 'default decision = \"DENY\"'\n"
                f"  - Use future.keywords if needed\n"
                f"Output only the Rego source, no explanation."
            )
            try:
                code = self._generate_with_llm(prompt)
                if self._judge.verify(code):
                    return code
                logger.warning("PolicyTranspiler: judge rejected LLM rego output, using template")
            except Exception as exc:
                logger.warning("PolicyTranspiler: LLM rego call failed (%s), using template", exc)

        return _REGO_POLICY_TEMPLATE


# Module-level singleton (used by legacy tests)
transpiler = PolicyTranspiler()

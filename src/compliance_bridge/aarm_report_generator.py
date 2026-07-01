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
aarm_report_generator.py — vLLM narrative generator for AARM Conformance Reports (CAGE v0.1.0)

Generates per-vector prose narratives for the AARM Conformance Report Card by
calling the out-of-band vLLM diagnostic sidecar — the same sovereign endpoint
used by Step 5 of the audit workflow (remediation advisory generation).

Concurrency design (Q4 architectural decision, CAGE v0.1.0):
  11 vectors are fanned out concurrently via asyncio.gather(), but the raw
  concurrency is bounded by an asyncio.Semaphore(3) to prevent rate-limit
  dropouts (HTTP 429) on the sovereign vLLM endpoint.  This matches the fan-out
  pattern of _step5_remediation_advisor in audit_workflow.py.

Non-fatal design:
  If VLLM_BASE_URL is not set, or if any individual vLLM call fails, the generator
  falls back to a deterministic template-based narrative. The AARM report card is
  always produced; prose enrichment is best-effort.

ISO 42001 mapping: A.5.3 (Logging and Monitoring) — narrative generation creates
human-readable audit evidence supporting the machine-readable OSCAL findings.
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timezone

from .aarm_mapper import (
    AARM_THREAT_VECTORS,
    AARMConformanceReport,
    AARMVectorResult,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Semaphore: bound concurrency to 3 to avoid vLLM rate-limit saturation
# ---------------------------------------------------------------------------

_NARRATIVE_SEM = asyncio.Semaphore(3)
_MAX_TOKENS    = int(os.environ.get("AARM_NARRATIVE_MAX_TOKENS", "512"))
_TIMEOUT_SEC   = int(os.environ.get("AARM_NARRATIVE_TIMEOUT_MS", "25000")) / 1000


# ---------------------------------------------------------------------------
# Template fallback — deterministic, no LLM required
# ---------------------------------------------------------------------------

def _template_narrative(result: AARMVectorResult) -> str:
    """Produce a deterministic prose narrative when vLLM is unavailable."""
    ctrl_summary = ", ".join(
        f"{cid}={v}"
        for cid, v in result.control_results.items()
    )
    return (
        f"AARM {result.vector_id} ({result.name}) — {result.status}. "
        f"Severity: {result.aarm_severity}. "
        f"Neutralizing controls: {ctrl_summary}. "
        f"({result.pass_count} PASS / {result.fail_count} FAIL / "
        f"{result.not_found_count} NOT_FOUND). "
        f"{result.notes}"
    )


# ---------------------------------------------------------------------------
# _build_narrative_prompt — construct the LLM prompt for one vector
# ---------------------------------------------------------------------------

def _build_narrative_prompt(result: AARMVectorResult) -> str:
    ctrl_lines = "\n".join(
        f"  - {cid}: {v}" for cid, v in result.control_results.items()
    )
    vector_meta = AARM_THREAT_VECTORS.get(result.vector_id)
    impl_files  = "\n".join(
        f"  - {f}" for f in (vector_meta.implementation_files if vector_meta else [])
    )
    return f"""You are a cybersecurity engineer writing the AARM Conformance Report Card
for the Cybernetic Governance Engine (CAGE).

Write a concise, professional 2–3 paragraph conformance narrative for this threat vector.
The narrative should explain HOW the listed controls neutralize the attack, referencing
the specific implementation mechanisms. Tone: technical but accessible to a security examiner.

THREAT VECTOR
  ID:          {result.vector_id}
  Name:        {result.name}
  Severity:    {result.aarm_severity}
  Description: {AARM_THREAT_VECTORS.get(result.vector_id, result).description if hasattr(AARM_THREAT_VECTORS.get(result.vector_id, result), "description") else ""}
  Status:      {result.status}

CONTROL VERDICTS
{ctrl_lines}

KEY IMPLEMENTATION FILES
{impl_files}

IMPLEMENTATION NOTES
{result.notes}

REQUIRED FORMAT:
- 2–3 tight paragraphs (max 300 words total)
- Reference specific file names and mechanism names
- Close with one sentence on how Lula/OSCAL provides machine-readable proof
- No bullet points in the narrative prose
- Do NOT mention LLM inference was used to generate this text"""


# ---------------------------------------------------------------------------
# generate_aarm_narrative — single vector, semaphore-bounded
# ---------------------------------------------------------------------------

async def generate_aarm_narrative(
    result:     AARMVectorResult,
    vllm_base:  str,
    model_name: str,
) -> str:
    """Generate a prose narrative for one AARM vector using the vLLM sidecar.

    Bounded by _NARRATIVE_SEM (concurrency=3) to prevent rate-limit saturation.
    Falls back to _template_narrative() on any error.

    Args:
        result:     The AARMVectorResult to narrate.
        vllm_base:  Base URL of the sovereign vLLM endpoint.
        model_name: Model identifier (passed as ``model`` to the chat API).

    Returns:
        A prose narrative string (never None — falls back to template on error).
    """
    async with _NARRATIVE_SEM:
        try:
            from openai import AsyncOpenAI  # noqa: PLC0415 — lazy import

            _api_key = os.environ.get("VLLM_API_KEY")
            if not _api_key:
                raise RuntimeError("VLLM_API_KEY not set — falling back to template")

            client = AsyncOpenAI(base_url=vllm_base, api_key=_api_key)
            prompt  = _build_narrative_prompt(result)

            response = await asyncio.wait_for(
                client.chat.completions.create(
                    model=model_name,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=_MAX_TOKENS,
                ),
                timeout=_TIMEOUT_SEC,
            )
            text = (response.choices[0].message.content or "").strip()
            logger.info(
                "[aarm_report_generator] ✅ Narrative generated for %s (%d chars)",
                result.vector_id, len(text),
            )
            return text

        except asyncio.TimeoutError:
            logger.warning(
                "[aarm_report_generator] vLLM timeout for %s — using template fallback",
                result.vector_id,
            )
        except Exception as exc:
            logger.warning(
                "[aarm_report_generator] vLLM error for %s (%s) — using template fallback",
                result.vector_id, exc,
            )

    return _template_narrative(result)


# ---------------------------------------------------------------------------
# enrich_report_with_narratives — enrich all 11 vectors concurrently
# ---------------------------------------------------------------------------

async def enrich_report_with_narratives(
    report: AARMConformanceReport,
) -> dict[str, str]:
    """Fan out narrative generation across all 11 vectors concurrently.

    Respects asyncio.Semaphore(3) for rate-limit safety.

    Args:
        report: The base AARMConformanceReport to enrich.

    Returns:
        Dict mapping vector_id → prose narrative string.
        Always returns all 11 entries (template fallback on any error).
    """
    vllm_base  = os.environ.get("VLLM_BASE_URL", "")
    model_name = (
        os.environ.get("REMEDIATION_MODEL")
        or os.environ.get("MODEL_REASONING")
        or os.environ.get("MODEL_FAST")
        or os.environ.get("MODEL_CONSENSUS")
        or "default"
    )

    if not vllm_base:
        logger.info(
            "[aarm_report_generator] VLLM_BASE_URL not set — "
            "using deterministic template narratives for all vectors"
        )
        return {r.vector_id: _template_narrative(r) for r in report.vectors}

    tasks = [
        generate_aarm_narrative(vector_result, vllm_base, model_name)
        for vector_result in report.vectors
    ]

    narratives_list: list[str] = await asyncio.gather(*tasks, return_exceptions=False)

    return {
        result.vector_id: narrative
        for result, narrative in zip(report.vectors, narratives_list)
    }

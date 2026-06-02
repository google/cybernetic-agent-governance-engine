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
audit_workflow.py — 6-step compliance audit pipeline (CAGE v2.0.0).

Ports complianceAuditWorkflow.ts + remediationAdvisorStep.ts

Steps:
  1. Persist raw OSCAL YAML to GCS/S3 (idempotent — skip if exists)
  2. Parse OSCAL YAML → list[OscalFinding]  (deterministic, zero-LLM)
     2b. Append each finding to the SHA-256 hash-chained ContextAccumulator
         (AARM Context Accumulator mandate, CAGE v2.0.0)
  3. Ingest findings as compliance scores into the dedicated Langfuse
     compliance project (separate from application performance metrics)
  4. Filter FAIL findings for CRITICAL_CONTROLS → notify_critical_failure()
  5. (Conditional) If critical failures AND VLLM_BASE_URL is set →
     call vLLM via openai Python SDK → notify_remediation()
     All Step 5 errors are non-fatal (wrapped in try/except).
  6. Generate AARM Conformance Report Card and serialize to GCS/S3
     (<audit_id>/aarm_conformance.json) — auto-runs on every Lula scheduled
     audit; also available on-demand via GET /v1/aarm/conformance-report.

AUDIT INTEGRITY SAFEGUARDS:
  - Lula validation result is NOT influenced by LLM output.
  - Steps 1–4 are fully deterministic.
  - Human review is required before applying any suggestion (ISO 42001 A.7.2).
  - LLM model version and trace IDs are logged to the Langfuse compliance
    project for reproducibility.
  - SHA-256 hash-chained Context Accumulator provides tamper-evident
    chain of custody (CSA AARM Context Accumulator mandate, ISO 42001 A.5.3).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any


def _ensure_uuid(s: str) -> str:
    """Ensure a string is a valid UUID, or convert it deterministically to one (ISO 42001 A.7.5)."""
    try:
        val = uuid.UUID(s)
        return val.hex
    except ValueError:
        return uuid.uuid5(uuid.NAMESPACE_DNS, s).hex


# Lazy import: langfuse and openai are only imported when audit_workflow is
# actually called at runtime.  This prevents ModuleNotFoundError in test
# environments where neither package is installed.
Langfuse = None  # populated by _get_langfuse_class() on first use
AsyncOpenAI = None  # populated by _get_openai_class() on first use


def _get_langfuse_class():
    global Langfuse
    if Langfuse is None:
        from langfuse import Langfuse as _LF  # noqa: PLC0415
        Langfuse = _LF
    return Langfuse


def _get_openai_class():
    global AsyncOpenAI
    if AsyncOpenAI is None:
        from openai import AsyncOpenAI as _OAI  # noqa: PLC0415
        AsyncOpenAI = _OAI
    return AsyncOpenAI

from .context_accumulator import ContextAccumulator
from .eval_dataset import populate_eval_dataset
from .notifier import create_notifier
from .oscal_parser import parse_oscal_yaml
from .sse_events import event_bus
from .storage import put_oscal_artifact
from .types import CONTROL_META, CRITICAL_CONTROLS, OscalFinding

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Compliance Langfuse client factory
# Separate from the main app project to keep audit traces isolated.
# ---------------------------------------------------------------------------

def _make_compliance_langfuse():
    import httpx  # noqa: PLC0415
    return _get_langfuse_class()(
        public_key=os.environ.get("LANGFUSE_COMPLIANCE_PUBLIC_KEY", ""),
        secret_key=os.environ.get("LANGFUSE_COMPLIANCE_SECRET_KEY", ""),
        host=os.environ.get(
            "LANGFUSE_COMPLIANCE_HOST",
            os.environ.get("LANGFUSE_HOST", "https://cloud.langfuse.com"),
        ),
        httpx_client=httpx.Client(timeout=_LANGFUSE_SDK_TIMEOUT_S),
    )


# Short timeout for Langfuse SDK calls in audit_workflow — prevents _fetch_failing_traces
# and flush() from blocking the synchronous ingest for >30s when Langfuse is slow.
_LANGFUSE_SDK_TIMEOUT_S: float = float(os.environ.get("LANGFUSE_API_TIMEOUT_S", "8"))


def _flush_with_timeout(lf_client: Any, timeout: float = _LANGFUSE_SDK_TIMEOUT_S) -> None:
    """Call lf_client.flush() with a hard wall-clock timeout via a daemon thread.

    The Langfuse SDK flush() has no built-in timeout parameter and blocks until
    all queued events are delivered.  When the Langfuse host is slow this can
    stall the audit pipeline for minutes.  We fire flush() in a daemon thread
    and join() with a timeout so the caller is never blocked longer than
    ``timeout`` seconds.  Any un-flushed events are dropped — acceptable for
    non-fatal observability data.
    """
    import threading  # noqa: PLC0415
    t = threading.Thread(target=lf_client.flush, daemon=True)
    t.start()
    t.join(timeout=timeout)
    if t.is_alive():
        logger.warning(
            "[audit_workflow] Langfuse flush() did not complete within %.1fs — "
            "some events may be dropped (non-fatal).",
            timeout,
        )


def _make_app_langfuse():
    import httpx  # noqa: PLC0415
    return _get_langfuse_class()(
        public_key=os.environ.get("LANGFUSE_PUBLIC_KEY", ""),
        secret_key=os.environ.get("LANGFUSE_SECRET_KEY", ""),
        host=os.environ.get("LANGFUSE_HOST", "https://cloud.langfuse.com"),
        httpx_client=httpx.Client(timeout=_LANGFUSE_SDK_TIMEOUT_S),
    )


# ---------------------------------------------------------------------------
# Step 1: Persist OSCAL artifact (idempotent)
# ---------------------------------------------------------------------------

async def _step1_persist_artifact(
    oscal_yaml: str,
    audit_id: str,
) -> str | None:
    """Returns artifact key on success, None if storage is unconfigured or fails."""
    if not os.environ.get("OSCAL_S3_ENDPOINT"):
        logger.warning(
            "[audit_workflow] OSCAL_S3_ENDPOINT not set — skipping artifact persistence. "
            "Set OSCAL_S3_ENDPOINT, OSCAL_S3_BUCKET, OSCAL_S3_ACCESS_KEY, "
            "OSCAL_S3_SECRET_KEY to enable durable evidence storage (ISO 42001 A.7.5)."
        )
        return None

    try:
        key = await put_oscal_artifact(audit_id, oscal_yaml)
        return key
    except Exception as exc:
        logger.warning(
            "[audit_workflow] Artifact persistence failed (non-fatal): %s", exc
        )
        return None


# ---------------------------------------------------------------------------
# Step 2: Parse OSCAL YAML (deterministic, zero-LLM)
# ---------------------------------------------------------------------------

async def _step2_parse_oscal(oscal_yaml: str) -> list[OscalFinding]:
    logger.info("[audit_workflow] Parsing OSCAL Assessment Result (deterministic)...")
    # parse_oscal_yaml is CPU-bound but typically sub-millisecond; run in thread
    # for async compatibility when called from a heavily-loaded event loop.
    findings = await asyncio.to_thread(parse_oscal_yaml, oscal_yaml)
    logger.info("[audit_workflow] Parsed %d findings.", len(findings))
    return findings


# ---------------------------------------------------------------------------
# Step 3: Ingest findings into Langfuse compliance project
# ---------------------------------------------------------------------------

def _ingest_sync(
    findings: list[OscalFinding],
    audit_id: str,
    artifact_key: str | None,
) -> int:
    """Synchronous ingestion — wrapped in to_thread by caller."""
    compliance_langfuse = _make_compliance_langfuse()

    for finding in findings:
        # SDK v4.x compliant trace context structure
        trace_context = {
            "trace_id": finding.finding_id,
            "name": "lula-audit",
            "tags": [
                "compliance",
                "iso-42001",
                "automated-audit",
                "lula",
                f"control:{finding.control_id}",
                f"result:{finding.result}",
            ],
            "metadata": {
                "iso_42001_control":    finding.control_id,
                "lula_result":          finding.result,
                "evidence_age_seconds": str(finding.evidence_age_s),
                "oscal_finding_id":     finding.finding_id,
                "safety_rate":          str(finding.safety_rate) if finding.safety_rate is not None else "-1.0",
                "standard":             "ISO/IEC 42001:2023",
                "audit_id":             audit_id,
                "artifact_key":         artifact_key or "",
                "audit_timestamp_utc":  datetime.now(tz=timezone.utc).isoformat(),
            }
        }
        
        # Implicit trace creation via span initiation
        span = compliance_langfuse.start_observation(
            name="lula-audit-result",
            as_type="span",
            trace_context=trace_context,
        )
        # ERROR findings score 0.0 — they must not be treated as compliant.
        # A scanner failure on a critical control is a security blind spot;
        # scoring it as 1.0 (PASS) would mask the gap from compliance dashboards.
        # (NIST SP 800-53A §3.2: evaluation errors → Incomplete/Unknown, not Satisfied)
        span.score(
            name=f"iso42001.{finding.control_id}.compliant",
            value=1.0 if finding.result == "PASS" else 0.0,
            comment=finding.remarks or f"Automated Lula audit — {finding.result}",
        )
        span.end()

    _flush_with_timeout(compliance_langfuse)
    logger.info("[audit_workflow] Flushed %d traces and scores to Langfuse compliance project.", len(findings))
    return len(findings)


async def _step3_ingest_to_langfuse(
    findings: list[OscalFinding],
    audit_id: str,
    artifact_key: str | None,
) -> int:
    return await asyncio.to_thread(_ingest_sync, findings, audit_id, artifact_key)


# ---------------------------------------------------------------------------
# Step 4: Alert on critical failures
# ---------------------------------------------------------------------------

async def _step4_alert_on_critical_fail(
    findings: list[OscalFinding],
    audit_id: str,
) -> tuple[bool, list[str]]:
    """Returns (alerted, alert_targets).

    Both FAIL and ERROR results on CRITICAL_CONTROLS trigger an alert.
    ERROR means evidence collection failed — the control may be violated but
    we cannot confirm it.  Per NIST SP 800-53A §3.2, an evaluation error must
    never be silently treated as compliant; it must be escalated so a human
    can investigate the scanner failure and close the evidence gap.
    """
    critical_fails = [
        f for f in findings
        if f.result in ("FAIL", "ERROR") and f.control_id in CRITICAL_CONTROLS
    ]

    if not critical_fails:
        logger.info("[audit_workflow] No critical control failures. No alert sent.")
        return False, []

    notifier = create_notifier()
    await notifier.send_critical_alert(critical_fails, audit_id)

    alert_targets = [f.control_id for f in critical_fails]
    logger.info("[audit_workflow] Critical alert sent for: %s", ", ".join(alert_targets))
    return True, alert_targets


# ---------------------------------------------------------------------------
# Step 5 (conditional): Remediation advisor via vLLM
# ---------------------------------------------------------------------------

async def _fetch_failing_traces(
    control_id: str,
    limit: int = 10,
) -> list[dict]:
    """Fetch failing traces from the app Langfuse project for evidence."""
    def _sync() -> list[dict]:
        app_lf = _make_app_langfuse()
        since = datetime.now(tz=timezone.utc) - timedelta(hours=24)
        try:
            response = app_lf.fetch_traces(
                tags=[f"control:{control_id}"],
                from_timestamp=since,
                limit=limit * 2,
            )
            results = []
            for t in (response.data or []):
                metadata = t.metadata or {}
                outcome = metadata.get("iso_42001_outcome") if isinstance(metadata, dict) else None
                if outcome != "PASSED":
                    results.append({
                        "id":       t.id,
                        "input":    json.dumps(t.input  or "")[:250],
                        "output":   json.dumps(t.output or "")[:250],
                        "metadata": metadata if isinstance(metadata, dict) else {},
                    })
            return results[:limit]
        except Exception as exc:
            logger.warning(
                "[audit_workflow] Failed to fetch failing traces for %s: %s",
                control_id, exc,
            )
            return []

    return await asyncio.to_thread(_sync)


def _build_remediation_prompt(
    finding: OscalFinding,
    control_name: str,
    failing_traces: list[dict],
) -> str:
    if failing_traces:
        trace_list = "\n".join(
            f'  - Trace {t["id"]}:\n    input="{t["input"]}"\n    output="{t["output"]}"'
            for t in failing_traces
        )
    else:
        trace_list = "  (no failing traces available in the 24h evidence window)"

    safety_str = (
        f"{finding.safety_rate * 100:.2f}%"
        if finding.safety_rate is not None
        else "unknown"
    )

    return f"""You are an ISO/IEC 42001 AI Management System compliance engineer.
Analyze this failed compliance control and provide specific, actionable remediation.

FAILED CONTROL
  Control ID:   {finding.control_id} — {control_name}
  Finding ID:   {finding.finding_id}
  Safety Rate:  {safety_str} (required: ≥ 99%)
  Remarks:      {finding.remarks or 'none provided'}

EVIDENCE — Failing traces from the last 24 hours
{trace_list}

CODEBASE REFERENCE (use these paths in your fix)
  - Production gateway (Python):      src/gateway/server/hybrid_server.py
  - Financial advisor graph:          src/governed_financial_advisor/graph/
  - OPA trade policy (Rego):          src/governed_financial_advisor/graph/governance/trade_policy.rego
  - System authorization policy:      deployment/system_authz.rego
  - Compliance bridge (Python):       src/compliance_bridge/
  - ISO 42001 control validators:     compliance/lula/
  - OSCAL component definition:       compliance/oscal/component-definition.yaml

REQUIRED OUTPUT FORMAT — respond in exactly this structure (keep concise):
1. ROOT CAUSE (2-3 sentences): Why is this control failing?
2. CODE FIX (file path + exact change): What file and line needs modification?
3. VERIFICATION: How to confirm the fix before the next Lula audit cycle?
4. URGENCY: IMMEDIATE | NEXT_SPRINT

⚠️ Your response will be reviewed by a human engineer before any change is applied.
Keep your response under 400 words. Be specific to this codebase."""


async def _step5_one_control(
    control_id: str,
    findings: list[OscalFinding],
    audit_id: str,
    vllm_base: str,
    model_name: str,
    max_tokens: int,
    timeout_sec: float,
) -> dict:
    """
    Generate and deliver a remediation advisory for a single control.
    Returns a per-control result dict (non-fatal — all errors captured).
    """
    finding = next(
        (f for f in findings if f.control_id == control_id and f.result == "FAIL"),
        None,
    )
    if finding is None:
        return {
            "control_id":        control_id,
            "remediation_sent":  False,
            "advisor_error":     f"No FAIL finding for {control_id}",
            "trace_ids_sampled": [],
        }

    control_name      = CONTROL_META.get(control_id, {}).get("name", control_id)
    failing_traces    = await _fetch_failing_traces(control_id, 10)
    trace_ids_sampled = [t["id"] for t in failing_traces]
    prompt            = _build_remediation_prompt(finding, control_name, failing_traces)

    remediation_text: str
    try:
        _vllm_api_key = os.environ.get("VLLM_API_KEY")
        if not _vllm_api_key:
            raise RuntimeError("VLLM_API_KEY must be set in the environment")
        client = _get_openai_class()(
            base_url=vllm_base,
            api_key=_vllm_api_key,
        )
        response = await asyncio.wait_for(
            client.chat.completions.create(
                model=model_name,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens,
            ),
            timeout=timeout_sec,
        )
        remediation_text = (response.choices[0].message.content or "").strip()
        logger.info(
            "[audit_workflow] ✅ LLM advisory generated for %s (%d chars)",
            control_id, len(remediation_text),
        )
    except asyncio.TimeoutError:
        logger.error(
            "[audit_workflow] LLM call timed out after %ds for %s",
            int(timeout_sec), control_id,
        )
        return {
            "control_id":        control_id,
            "remediation_sent":  False,
            "advisor_error":     f"LLM timeout after {int(timeout_sec * 1000)}ms",
            "trace_ids_sampled": trace_ids_sampled,
        }
    except Exception as exc:
        logger.error("[audit_workflow] LLM call failed for %s: %s", control_id, exc)
        return {
            "control_id":        control_id,
            "remediation_sent":  False,
            "advisor_error":     f"LLM error: {exc}",
            "trace_ids_sampled": trace_ids_sampled,
        }

    # Deliver notification
    notifier = create_notifier()
    await notifier.send_remediation_followup(
        control_id=control_id,
        audit_id=audit_id,
        model_name=model_name,
        remediation_text=remediation_text,
        trace_ids=trace_ids_sampled,
    )

    # Log advisory to compliance Langfuse (non-fatal)
    try:
        def _log_advisory_sync() -> None:
            comp_lf = _make_compliance_langfuse()
            from langfuse import propagate_attributes
            with propagate_attributes(
                tags=["compliance", "iso-42001", "llm-remediation", f"control:{control_id}"],
                metadata={
                    "model":                 model_name,
                    "max_tokens":            max_tokens,
                    "audit_id":              audit_id,
                    "control_id":            control_id,
                    "generated_utc":         datetime.now(tz=timezone.utc).isoformat(),
                    "human_review_required": True,
                    "disclaimer": "LLM-generated — human verification required (ISO 42001 A.7.2)",
                },
            ):
                span = comp_lf.start_observation(
                    name="remediation-advisory",
                    as_type="span",
                    input={
                        "finding":           finding.model_dump(),
                        "trace_ids_sampled": trace_ids_sampled,
                        "prompt_length":     len(prompt),
                    },
                    output={"remediation_text": remediation_text},
                )
                span.score(
                    name=f"iso42001.{control_id}.remediation_generated",
                    value=1.0,
                    comment=f"Advisory generated by {model_name} for audit {audit_id}",
                )
                span.end()
            # Do NOT flush here — runs inside background task via asyncio.to_thread;
            # explicit flush blocks thread pool and causes port-forward stream timeouts.
            # Langfuse SDK auto-flushes on its own schedule.
        await asyncio.to_thread(_log_advisory_sync)
    except Exception as exc:
        logger.warning(
            "[audit_workflow] Failed to log advisory to Langfuse (non-fatal): %s", exc
        )

    # Publish per-control REMEDIATION_GENERATED SSE event (non-fatal)
    try:
        await event_bus.publish({
            "type":       "REMEDIATION_GENERATED",
            "traceId":    None,
            "controlId":  control_id,
            "result":     None,
            "safetyRate": None,
            "auditId":    audit_id,
            "modelName":  model_name,
            "textLength": len(remediation_text),
            "traceCount": len(trace_ids_sampled),
            "timestamp":  datetime.now(tz=timezone.utc).isoformat(),
        })
    except Exception as exc:
        logger.warning(
            "[audit_workflow] Failed to publish REMEDIATION_GENERATED (non-fatal): %s", exc
        )

    return {
        "control_id":        control_id,
        "remediation_sent":  True,
        "remediation_text":  remediation_text,
        "advisor_error":     None,
        "trace_ids_sampled": trace_ids_sampled,
    }


async def _step5_remediation_advisor(
    alerted: bool,
    alert_targets: list[str],
    findings: list[OscalFinding],
    audit_id: str,
) -> dict:
    """
    Tier 3.1: Fan out remediation advisories to ALL alert_targets in parallel.

    Returns dict with aggregate keys:
      remediation_sent (bool)       — True if ≥1 advisory succeeded
      remediation_text (str|None)   — advisory for the first target (backward compat)
      advisor_error (str|None)      — first error if all failed
      trace_ids_sampled (list[str]) — traces sampled for the first target
      per_control (list[dict])      — per-control result dicts
    """
    if not alerted or not alert_targets:
        logger.info("[audit_workflow] No critical alert — skipping remediation advisory.")
        return {
            "remediation_sent":  False,
            "remediation_text":  None,
            "advisor_error":     None,
            "trace_ids_sampled": [],
            "per_control":       [],
        }

    vllm_base = os.environ.get("VLLM_BASE_URL")
    if not vllm_base:
        logger.warning("[audit_workflow] VLLM_BASE_URL not set — skipping LLM advisory.")
        return {
            "remediation_sent":  False,
            "remediation_text":  None,
            "advisor_error":     "VLLM_BASE_URL not configured",
            "trace_ids_sampled": [],
            "per_control":       [],
        }

    model_name  = (
        os.environ.get("REMEDIATION_MODEL")
        or os.environ.get("MODEL_REASONING")
        or os.environ.get("MODEL_FAST")
        or os.environ.get("MODEL_CONSENSUS")
    )
    max_tokens  = int(os.environ.get("REMEDIATION_MAX_TOKENS", "1024"))
    timeout_sec = int(os.environ.get("REMEDIATION_TIMEOUT_MS", "8000")) / 1000

    # De-duplicate alert_targets, preserving first-occurrence order
    seen: set[str] = set()
    deduped: list[str] = []
    for cid in alert_targets:
        if cid not in seen:
            seen.add(cid)
            deduped.append(cid)

    logger.info(
        "[audit_workflow] Step 5: generating advisories for %d control(s) in parallel: %s",
        len(deduped), ", ".join(deduped),
    )

    per_control: list[dict] = await asyncio.gather(*[
        _step5_one_control(
            control_id=cid,
            findings=findings,
            audit_id=audit_id,
            vllm_base=vllm_base,
            model_name=model_name,
            max_tokens=max_tokens,
            timeout_sec=timeout_sec,
        )
        for cid in deduped
    ], return_exceptions=False)

    # Aggregate for backward-compatible top-level keys
    first_ok = next((r for r in per_control if r.get("remediation_sent")), None)
    any_sent = any(r.get("remediation_sent") for r in per_control)
    first_err = next((r.get("advisor_error") for r in per_control if r.get("advisor_error")), None)

    return {
        "remediation_sent":  any_sent,
        "remediation_text":  first_ok["remediation_text"] if first_ok else None,
        "advisor_error":     None if any_sent else first_err,
        "trace_ids_sampled": first_ok["trace_ids_sampled"] if first_ok else [],
        "per_control":       per_control,
    }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

async def run_audit_workflow(oscal_yaml: str, audit_id: str) -> dict:
    """
    Execute the 6-step compliance audit pipeline (CAGE v2.0.0).

    Returns:
        {
          "status":               "ok",
          "audit_id":             str,
          "findings_count":       int,
          "artifact_key":         str | None,
          "ingested":             int,
          "alerted":              bool,
          "alert_targets":        list[str],
          "remediation_sent":     bool,
          "remediation_text":     str | None,
          "advisor_error":        str | None,
          "chain_root":           str,          # SHA-256 root of the Context Accumulator
          "chain_length":         int,          # number of chained nodes
          "chain_integrity_valid": bool,        # post-seal integrity check
          "aarm_report_artifact": str | None,   # GCS/S3 key for the AARM conformance JSON
        }
    """
    logger.info("[audit_workflow] Starting compliance audit for audit_id=%s", audit_id)

    # Step 1 — persist artifact (non-fatal if storage not configured)
    artifact_key = await _step1_persist_artifact(oscal_yaml, audit_id)

    # Step 2 — parse OSCAL (raises ValueError on failure → propagated to caller)
    findings = await _step2_parse_oscal(oscal_yaml)

    # Normalize finding_ids to valid deterministic UUIDs to prevent Langfuse/DB errors
    for finding in findings:
        finding.finding_id = _ensure_uuid(finding.finding_id)

    # Step 2b — SHA-256 hash-chained Context Accumulator (AARM mandate, CAGE v2.0.0)
    # Append every OSCAL finding as a chained node, then seal to lock the chain.
    # ISO 42001 A.5.3: tamper-evident chain of custody for session state.
    accumulator = ContextAccumulator(audit_id=audit_id)
    for finding in findings:
        accumulator.append_finding(finding)
    accumulator.seal()
    chain_integrity_valid, _   = accumulator.verify_integrity()
    chain_root                 = accumulator.chain_root()
    chain_length               = accumulator.length
    logger.info(
        "[audit_workflow] Context chain sealed: audit_id=%s nodes=%d root=%s… valid=%s",
        audit_id, chain_length, chain_root[:16], chain_integrity_valid,
    )

    # Persist the NDJSON context chain to GCS/S3 alongside the OSCAL artifact (non-fatal)
    chain_artifact_key: str | None = None
    if artifact_key and os.environ.get("OSCAL_S3_ENDPOINT"):
        try:
            chain_ndjson    = accumulator.export_ndjson()
            chain_artifact_key = await put_oscal_artifact(
                f"{audit_id}/context_chain", chain_ndjson
            )
            logger.info(
                "[audit_workflow] Context chain persisted to storage: %s",
                chain_artifact_key,
            )
        except Exception as exc:
            logger.warning(
                "[audit_workflow] Context chain persistence failed (non-fatal): %s", exc
            )

    # Publish CONTEXT_CHAIN_SEALED SSE event so KernelDashboard can show chain status
    try:
        await event_bus.publish({
            "type":               "CONTEXT_CHAIN_SEALED",
            "traceId":            None,
            "controlId":          "A.5.3",
            "result":             "PASS" if chain_integrity_valid else "FAIL",
            "safetyRate":         None,
            "auditId":            audit_id,
            "chainRoot":          chain_root,
            "chainLength":        chain_length,
            "chainIntegrityValid": chain_integrity_valid,
            "timestamp":          datetime.now(tz=timezone.utc).isoformat(),
        })
    except Exception as exc:
        logger.warning(
            "[audit_workflow] Failed to publish CONTEXT_CHAIN_SEALED (non-fatal): %s", exc
        )

    # Step 3 — ingest findings to compliance Langfuse
    ingested = await _step3_ingest_to_langfuse(findings, audit_id, artifact_key)

    # Step 3b — publish AUDIT_FINDING events to connected SSE clients (non-fatal).
    # Each finding becomes one governance-event frame so the agentsight-ui
    # KernelDashboard can display real-time audit results without polling.
    now_utc = datetime.now(tz=timezone.utc).isoformat()
    try:
        for finding in findings:
            await event_bus.publish({
                "type":       "AUDIT_FINDING",
                "traceId":    finding.finding_id,
                "controlId":  finding.control_id,
                "result":     finding.result,
                "safetyRate": finding.safety_rate,
                "auditId":    audit_id,
                "timestamp":  now_utc,
            })
        logger.info(
            "[audit_workflow] Published %d AUDIT_FINDING event(s) to %d SSE subscriber(s).",
            len(findings),
            event_bus.subscriber_count,
        )
    except Exception as exc:
        logger.warning("[audit_workflow] Failed to publish AUDIT_FINDING events (non-fatal): %s", exc)

    # Step 3c — auto-populate Langfuse eval dataset for FAIL findings (Tier 3.2 / ISO 42001 A.7.5).
    # Fire-and-forget: must not block the HTTP response — runs in background after Step 4.
    async def _step3c_eval_dataset_bg() -> None:
        try:
            _comp_lf = _make_compliance_langfuse()
            _dataset_count = await populate_eval_dataset(findings, audit_id, _comp_lf)
            # Do NOT flush here — explicit flush blocks thread pool threads and causes
            # port-forward stream timeouts. Langfuse SDK auto-flushes on its own schedule.
            if _dataset_count:
                logger.info(
                    "[audit_workflow] 📚 %d eval dataset item(s) created for audit %s.",
                    _dataset_count, audit_id,
                )
        except Exception as exc:
            logger.warning(
                "[audit_workflow] Eval dataset population failed (non-fatal): %s", exc
            )

    # Step 4 — alert on critical failures
    alerted, alert_targets = await _step4_alert_on_critical_fail(findings, audit_id)

    # Step 4b — publish GOVERNANCE_VIOLATION events for critical FAIL findings (non-fatal).
    # These trigger the security alert modal in KernelDashboard.tsx.
    if alerted and alert_targets:
        try:
            for control_id in alert_targets:
                failing_finding = next(
                    (f for f in findings if f.control_id == control_id and f.result == "FAIL"),
                    None,
                )
                if failing_finding is not None:
                    await event_bus.publish({
                        "type":       "GOVERNANCE_VIOLATION",
                        "traceId":    failing_finding.finding_id,
                        "controlId":  failing_finding.control_id,
                        "result":     "FAIL",
                        "safetyRate": failing_finding.safety_rate,
                        "auditId":    audit_id,
                        "timestamp":  now_utc,
                    })
            logger.info(
                "[audit_workflow] Published GOVERNANCE_VIOLATION event(s) for: %s",
                ", ".join(alert_targets),
            )
        except Exception as exc:
            logger.warning(
                "[audit_workflow] Failed to publish GOVERNANCE_VIOLATION events (non-fatal): %s", exc
            )

    # Steps 3c, 5, 6 — fire-and-forget background tasks.
    # These are all non-fatal and must NOT block the HTTP response.
    # The response is returned immediately after Step 4 (alert detection),
    # which is the last step that populates response fields the tests assert on.
    # Background tasks run in the same event loop and complete asynchronously.

    async def _step5_bg() -> None:
        """Step 5 — remediation advisor (fire-and-forget)."""
        try:
            await _step5_remediation_advisor(alerted, alert_targets, findings, audit_id)
        except Exception as exc:
            logger.warning(
                "[audit_workflow] Step 5 (remediation advisor) failed (non-fatal): %s", exc
            )

    async def _step6_bg() -> None:
        """Step 6 — AARM Conformance Report Card (fire-and-forget)."""
        try:
            from .aarm_mapper import build_aarm_conformance_report  # noqa: PLC0415
            aarm_report = build_aarm_conformance_report(
                findings   = findings,
                audit_id   = audit_id,
                chain_root = chain_root,
            )
            aarm_report_json = aarm_report.model_dump_json(indent=2)
            if os.environ.get("OSCAL_S3_ENDPOINT"):
                try:
                    key = await put_oscal_artifact(
                        f"{audit_id}/aarm_conformance", aarm_report_json
                    )
                    logger.info("[audit_workflow] AARM conformance report persisted: %s", key)
                except Exception as exc:
                    logger.warning(
                        "[audit_workflow] AARM report persistence failed (non-fatal): %s", exc
                    )
            logger.info(
                "[audit_workflow] AARM conformance report: posture=%s "
                "neutralized=%d partial=%d exposed=%d",
                aarm_report.overall_posture,
                aarm_report.neutralized,
                aarm_report.partial,
                aarm_report.exposed,
            )
        except Exception as exc:
            logger.warning(
                "[audit_workflow] Step 6 (AARM conformance report) failed (non-fatal): %s", exc
            )

    # Schedule all three background tasks concurrently (non-blocking)
    asyncio.create_task(_step3c_eval_dataset_bg())
    asyncio.create_task(_step5_bg())
    asyncio.create_task(_step6_bg())

    logger.info(
        "[audit_workflow] Audit complete (Steps 3c/5/6 running in background): "
        "audit_id=%s findings=%d alerted=%s chain_root=%s… integrity=%s",
        audit_id, len(findings), alerted, chain_root[:16], chain_integrity_valid,
    )

    return {
        "status":                "ok",
        "audit_id":              audit_id,
        "findings_count":        len(findings),
        "artifact_key":          artifact_key,
        "ingested":              ingested,
        "alerted":               alerted,
        "alert_targets":         alert_targets,
        # Steps 5/6 run in background — remediation fields reflect deferred state
        "remediation_sent":      False,
        "remediation_text":      None,
        "advisor_error":         None,
        "chain_root":            chain_root,
        "chain_length":          chain_length,
        "chain_integrity_valid": chain_integrity_valid,
        "aarm_report_artifact":  None,
    }

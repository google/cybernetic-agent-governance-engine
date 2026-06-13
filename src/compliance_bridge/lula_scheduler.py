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
lula_scheduler.py — Active Lula validation scheduler  (Tier 3.4)

Implements continuous control validation by periodically running
``lula validate`` against the OSCAL component definition and feeding
results back into the compliance audit pipeline.

This eliminates the dependency on a Kubernetes CronJob for evidence
generation — the bridge itself becomes the active compliance driver,
making it viable for local development and environments without a
full K8s control plane.

Architecture:
  1. Background asyncio task (started in lifespan) polls at LULA_SCHEDULE_INTERVAL_SECONDS.
  2. Each tick calls `lula validate --assessment-results /tmp/results.yaml ...`
     via asyncio.create_subprocess_exec().
  3. On success, reads the generated assessment results YAML and POSTs it
     to POST /v1/audit/ingest (internal loopback to avoid bypassing the pipeline).
  4. On failure (lula not installed, validation timeout), logs a warning and
     continues to the next tick — never blocks the bridge.

Environment variables:
  LULA_SCHEDULE_INTERVAL_SECONDS     — poll cadence (default: 3600 = 1 hour)
  LULA_COMPONENT_DEFINITION_PATH     — path to OSCAL component definition YAML
                                        (default: compliance/oscal/component-definition.yaml)
  LULA_ASSESSMENT_RESULTS_PATH       — where lula writes results
                                        (default: /tmp/lula-assessment-results.yaml)
  LULA_TIMEOUT_SECONDS               — per-run timeout (default: 120)
  LULA_SCHEDULER_DISABLED            — set to "1" to disable the scheduler
  COMPLIANCE_BRIDGE_URL              — internal loopback URL for audit ingest
                                        (default: http://localhost:3001)
"""

from __future__ import annotations

import asyncio
import logging
import os
import secrets
import tempfile
import uuid
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

_DEFAULT_INTERVAL    = 3600    # 1 hour
_DEFAULT_TIMEOUT     = 120     # 2 minutes per lula run
_DEFAULT_COMPONENT   = "compliance/oscal/component-definition.yaml"
# M-11: _DEFAULT_RESULTS is now a prefix for tempfile.mkstemp() — not a fixed /tmp path
_DEFAULT_RESULTS_PREFIX = "lula-assessment-results-"
_INGEST_ENDPOINT     = "/v1/audit/ingest"

# M-12: Module-level loopback auth token (generated once at startup)
# Used to authenticate the internal POST /v1/audit/ingest call.
_LOOPBACK_AUTH_TOKEN: str = secrets.token_hex(32)


def _is_disabled() -> bool:
    return os.environ.get("LULA_SCHEDULER_DISABLED", "").strip() == "1"


def _interval() -> int:
    return int(os.environ.get("LULA_SCHEDULE_INTERVAL_SECONDS", _DEFAULT_INTERVAL))


def _timeout() -> int:
    return int(os.environ.get("LULA_TIMEOUT_SECONDS", _DEFAULT_TIMEOUT))


def _component_path() -> str:
    return os.environ.get("LULA_COMPONENT_DEFINITION_PATH", _DEFAULT_COMPONENT)


def _results_path() -> str:
    # M-11: If env var is set, use it; otherwise tempfile.mkstemp() is used per-cycle
    return os.environ.get("LULA_ASSESSMENT_RESULTS_PATH", "")


def _bridge_url() -> str:
    base = os.environ.get("COMPLIANCE_BRIDGE_URL", "http://localhost:3001").rstrip("/")
    return f"{base}{_INGEST_ENDPOINT}"


# ---------------------------------------------------------------------------
# Lula subprocess runner
# ---------------------------------------------------------------------------

async def _run_lula_validate(component_path: str, results_path: str, timeout: int) -> bool:
    """
    Run `lula validate` as a subprocess.

    Returns True on success (exit code 0), False otherwise.
    Raises FileNotFoundError if lula binary is not found (caller handles this).
    """
    cmd = [
        "lula", "validate",
        "--component", component_path,
        "--assessment-results", results_path,
        "--confirm",   # non-interactive: don't prompt for user confirmation
    ]
    logger.info("[lula_scheduler] Running: %s", " ".join(cmd))

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            logger.error(
                "[lula_scheduler] lula validate timed out after %ds", timeout
            )
            return False

        if proc.returncode == 0:
            logger.info(
                "[lula_scheduler] ✅ lula validate succeeded (%d bytes output)",
                len(stdout),
            )
            return True
        else:
            logger.warning(
                "[lula_scheduler] lula validate exited %d. stderr: %s",
                proc.returncode,
                (stderr or b"").decode(errors="replace")[:500],
            )
            return False

    except FileNotFoundError:
        logger.warning(
            "[lula_scheduler] 'lula' binary not found. "
            "Install lula (https://lula.dev) or set LULA_SCHEDULER_DISABLED=1. "
            "Skipping this validation cycle."
        )
        return False


# ---------------------------------------------------------------------------
# OSCAL results ingest — POST to the bridge's own audit/ingest endpoint
# ---------------------------------------------------------------------------

async def _post_results_to_bridge(results_path: str, audit_id: str) -> bool:
    """
    Read the lula-generated assessment results YAML and POST it to
    POST /v1/audit/ingest so the full 5-step pipeline runs.

    Returns True on success, False on any error.
    """
    path = Path(results_path)
    if not path.exists():
        logger.warning(
            "[lula_scheduler] Results file not found at %s — skipping ingest.", results_path
        )
        return False

    try:
        oscal_yaml = path.read_text(encoding="utf-8")
    except Exception as exc:
        logger.error("[lula_scheduler] Failed to read results file: %s", exc)
        return False

    url = _bridge_url()
    try:
        # M-12: Include loopback auth token to authenticate internal POST
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                url,
                json={"oscal_yaml": oscal_yaml, "audit_id": audit_id},
                headers={
                    "Content-Type": "application/json",
                    "X-Lula-Scheduler-Token": _LOOPBACK_AUTH_TOKEN,
                },
            )
        if resp.is_success:
            logger.info(
                "[lula_scheduler] 📨 Assessment results ingested (audit_id=%s, HTTP %d)",
                audit_id, resp.status_code,
            )
            return True
        else:
            logger.warning(
                "[lula_scheduler] Ingest returned HTTP %d: %s",
                resp.status_code, resp.text[:300],
            )
            return False
    except Exception as exc:
        logger.error("[lula_scheduler] Failed to POST results to bridge: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Scheduler loop
# ---------------------------------------------------------------------------

async def _run_lula_cycle() -> dict:
    """Execute one lula validate → ingest cycle. Returns a status dict."""
    component = _component_path()
    timeout   = _timeout()
    audit_id  = f"lula-scheduled-{uuid.uuid4().hex[:12]}"

    if not Path(component).exists():
        logger.warning(
            "[lula_scheduler] Component definition not found at '%s'. "
            "Set LULA_COMPONENT_DEFINITION_PATH or create the file. Skipping cycle.",
            component,
        )
        return {"status": "skipped", "reason": "component_not_found", "audit_id": audit_id}

    # M-11: Use tempfile.mkstemp() to avoid TOCTOU race on /tmp path.
    # If LULA_ASSESSMENT_RESULTS_PATH is set, use it; otherwise create a secure temp file.
    fixed_results = _results_path()
    if fixed_results:
        results = fixed_results
        tmp_fd = None
    else:
        tmp_fd, results = tempfile.mkstemp(
            prefix=_DEFAULT_RESULTS_PREFIX, suffix=".yaml"
        )
        os.close(tmp_fd)  # lula will write to the path; we just need the name

    try:
        lula_ok = await _run_lula_validate(component, results, timeout)
        if not lula_ok:
            return {"status": "failed", "reason": "lula_validate_failed", "audit_id": audit_id}

        ingested = await _post_results_to_bridge(results, audit_id)
        if not ingested:
            return {"status": "failed", "reason": "ingest_failed", "audit_id": audit_id}

        return {"status": "ok", "audit_id": audit_id}
    finally:
        # Clean up temp file if we created one
        if tmp_fd is None and not fixed_results:
            try:
                os.unlink(results)
            except OSError:
                pass


async def run_lula_scheduler() -> None:
    """
    Continuous Lula validation scheduler — runs until the task is cancelled.

    Designed to be started via asyncio.create_task() inside the FastAPI
    lifespan context manager (alongside the SLA monitor).

    Example lifespan usage::

        _lula_task = asyncio.create_task(run_lula_scheduler(), name="lula-scheduler")
        try:
            yield
        finally:
            _lula_task.cancel()
            await _lula_task
    """
    if _is_disabled():
        logger.info("[lula_scheduler] LULA_SCHEDULER_DISABLED=1 — scheduler not started.")
        return

    interval = _interval()
    logger.info(
        "[lula_scheduler] Starting Lula validation scheduler. "
        "Interval: %ds (%0.1fh). Component: %s",
        interval, interval / 3600, _component_path(),
    )

    try:
        while True:
            await asyncio.sleep(interval)
            try:
                result = await _run_lula_cycle()
                if result["status"] == "ok":
                    logger.info(
                        "[lula_scheduler] ✅ Scheduled validation complete (audit_id=%s)",
                        result["audit_id"],
                    )
                else:
                    logger.warning(
                        "[lula_scheduler] ⚠️  Validation cycle: status=%s reason=%s",
                        result.get("status"), result.get("reason"),
                    )
            except Exception as exc:
                logger.error(
                    "[lula_scheduler] Unexpected error in validation cycle (continuing): %s", exc
                )
    except asyncio.CancelledError:
        logger.info("[lula_scheduler] Lula scheduler task cancelled — shutting down.")

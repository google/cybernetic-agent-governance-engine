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
eval_dataset.py — Langfuse evaluation dataset auto-population  (Tier 3.2)

Implements the ISO 42001 A.7.5 (Documented Information) requirement to retain
evidence of control failures in a structured, queryable form.

Whenever the audit pipeline produces FAIL findings, this module creates a
Langfuse Dataset Item in a named compliance dataset so that:
  - QA engineers can run eval suites against historic failure patterns.
  - Langfuse dashboards display failure trends without exporting data.
  - LLM-generated remediation advisories can be scored against known-good fixes.

Dataset naming convention:
  cage-compliance-<control_id>      (one dataset per control, e.g. cage-compliance-A.9.2)

Dataset item structure:
  input:    { "finding": OscalFinding.dict(), "audit_id": str }
  expected_output: { "result": "PASS", "remediation_required": False }
  metadata: { "audit_id", "control_id", "iso_clause", "framework_refs" }
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timezone

from .types import OscalFinding, get_control_meta

logger = logging.getLogger(__name__)

_DATASET_PREFIX = "cage-compliance"


def _dataset_name(control_id: str) -> str:
    return f"{_DATASET_PREFIX}-{control_id}"


def _create_dataset_item_sync(  # type: ignore[no-untyped-def]
    control_id: str,
    finding: OscalFinding,
    audit_id: str,
    langfuse,
) -> None:
    """Synchronous Langfuse SDK call — run via asyncio.to_thread()."""
    dataset_name = _dataset_name(control_id)

    # Region-aware control metadata lookup
    _region = os.environ.get("CAGE_DEPLOYMENT_REGION", "LOCAL")
    _control_meta = get_control_meta(_region)

    # Ensure dataset exists (upsert semantics — Langfuse will not error if it exists)
    try:
        langfuse.create_dataset(
            name=dataset_name,
            description=(
                f"Automated compliance failure dataset for ISO 42001 control {control_id}. "
                f"Items are created by the CAGE audit pipeline on every FAIL finding. "
                f"ISO clause: {_control_meta.get(control_id, {}).get('iso_clause', control_id)}"
            ),
            metadata={
                "control_id": control_id,
                "iso_clause": _control_meta.get(control_id, {}).get("iso_clause", ""),
                "frameworks": list(
                    _control_meta.get(control_id, {}).get("frameworks", {}).keys()
                ),
                "created_by": "cage-compliance-bridge",
            },
        )
    except Exception:
        pass  # Dataset already exists — continue to create item

    # Unique item key: audit_id + finding_id to prevent exact duplicates
    item_id = f"{audit_id}::{finding.finding_id}"

    langfuse.create_dataset_item(
        dataset_name=dataset_name,
        input={
            "finding": finding.model_dump(),
            "audit_id": audit_id,
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        },
        expected_output={
            "result": "PASS",
            "remediation_required": False,
            "note": (
                "Expected: control passes with full safety_rate=1.0. "
                "This item represents a regression baseline."
            ),
        },
        metadata={
            "audit_id": audit_id,
            "control_id": control_id,
            "iso_clause": _control_meta.get(control_id, {}).get("iso_clause", ""),
            "framework_refs": _control_meta.get(control_id, {}).get("frameworks", {}),
            "finding_id": finding.finding_id,
            "safety_rate": finding.safety_rate,
            "generated_utc": datetime.now(tz=timezone.utc).isoformat(),
        },
        id=item_id,
    )
    logger.info(
        "[eval_dataset] 📚 Created dataset item in '%s' for audit %s (finding %s)",
        dataset_name,
        audit_id,
        finding.finding_id,
    )


async def populate_eval_dataset(  # type: ignore[no-untyped-def]
    findings: list[OscalFinding],
    audit_id: str,
    langfuse,
) -> int:
    """
    Asynchronously create Langfuse Dataset Items for every FAIL finding.

    Only FAIL findings are recorded — PASS findings are not useful as negative
    examples for an evaluation dataset targeting regression detection.

    Args:
        findings:  All findings from the current audit run.
        audit_id:  Audit run identifier.
        langfuse:  An initialised Langfuse SDK client (compliance project).

    Returns:
        Number of dataset items successfully created.
    """
    fail_findings = [f for f in findings if f.result == "FAIL"]
    if not fail_findings:
        logger.debug("[eval_dataset] No FAIL findings — skipping dataset population.")
        return 0

    created = 0
    errors = 0

    async def _populate_one(finding: OscalFinding) -> None:
        nonlocal created, errors
        try:
            await asyncio.to_thread(
                _create_dataset_item_sync,
                finding.control_id,
                finding,
                audit_id,
                langfuse,
            )
            created += 1
        except Exception as exc:
            errors += 1
            logger.warning(
                "[eval_dataset] Failed to create dataset item for %s (non-fatal): %s",
                finding.control_id,
                exc,
            )

    await asyncio.gather(*[_populate_one(f) for f in fail_findings])

    if errors:
        logger.warning(
            "[eval_dataset] %d/%d items failed to create.", errors, len(fail_findings)
        )
    else:
        logger.info(
            "[eval_dataset] ✅ %d/%d eval dataset items created for audit %s.",
            created,
            len(fail_findings),
            audit_id,
        )
    return created

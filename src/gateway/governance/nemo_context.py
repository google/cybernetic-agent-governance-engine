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

"""NeMo context utilities for governance."""
import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)

async def compute_nemo_context(
    stpa_validator: Any,
    safety_filter: Any,
    action: str,
    params: Dict[str, Any],
) -> Dict[str, Any]:
    """Compute pre-checks for NeMo Layer-0 context injection with fail-closed semantics."""
    tool_name = action

    # --- STPA validation (synchronous) ---
    stpa_violations = []
    stpa_allowed = True
    if stpa_validator is not None:
        try:
            stpa_violations = stpa_validator.validate(tool_name, params)
            stpa_allowed = len(stpa_violations) == 0
        except Exception as exc:
            logger.warning(
                "⚠️ compute_nemo_context: STPA validation failed (%s) — failing closed.",
                exc,
            )
            stpa_violations = [f"STPA exception (fail-closed): {exc}"]
            stpa_allowed = False

    stpa_result = {
        "allowed": stpa_allowed,
        "violations": stpa_violations,
    }

    # --- CBF barrier check (async) ---
    cbf_allowed = False
    cbf_reason = "UNSAFE: uninitialized"
    
    if safety_filter is not None:
        try:
            cbf_raw = await safety_filter.verify_action(tool_name, params)
            # allowed=True only when verify_action returns a string starting with "SAFE"
            if isinstance(cbf_raw, str) and cbf_raw.startswith("SAFE"):
                cbf_allowed = True
            cbf_reason = cbf_raw
        except Exception as exc:
            logger.error(
                "CBF compute_nemo_context failed due to error — denying request for safety",
                exc_info=True,
            )
            cbf_allowed = False
            cbf_reason = f"CBF unavailable (fail-closed): {exc}"
    else:
        cbf_allowed = False
        cbf_reason = "CBF unavailable (fail-closed): safety_filter is None"

    cbf_result = {
        "allowed": cbf_allowed,
        "reason": cbf_reason,
    }

    logger.debug(
        "🔍 compute_nemo_context complete: stpa_allowed=%s cbf_allowed=%s",
        stpa_result["allowed"],
        cbf_result["allowed"],
    )
    return {
        "stpa_result": stpa_result,
        "cbf_result": cbf_result,
    }

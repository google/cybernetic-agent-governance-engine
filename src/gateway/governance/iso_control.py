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
ISO 42001 OTel Evidence Tagging
================================
Mirrors ``stampIsoControl()`` from the TypeScript governance layer:
  src/gateway/src/governance/middleware/stpaGovernanceMiddleware.ts

Every governance decision (PASS / BLOCK / REDACT) must call
:func:`stamp_iso_control` so that OTel spans flowing to the Langfuse OTLP
collector carry a consistent ISO 42001 audit trail that the compliance-bridge
can aggregate.

Attribute schema (6 mandatory attributes):
    iso42001.control        — Annex A control ID string, e.g. "A.6.1.2"
    iso42001.tier           — integer enforcement tier (1 = heuristic, 2 = semantic, 3 = OPA)
    iso42001.outcome        — one of "PASS", "BLOCK", "REDACT"
    iso42001.timestamp      — Unix epoch in milliseconds (int)
    iso42001.gateway_version — package version string (SemVer)
    iso42001.evidence_chain — composite key "{control}:{tier}:{outcome}"
"""

import logging
import time
from importlib.metadata import version as _pkg_version, PackageNotFoundError
from typing import Any

logger = logging.getLogger("Gateway.Governance.IsoControl")

# ---------------------------------------------------------------------------
# Gateway version — resolved once at import time
# ---------------------------------------------------------------------------

def _resolve_gateway_version() -> str:
    try:
        return _pkg_version("cybernetic-governance-engine")
    except PackageNotFoundError:
        logger.debug(
            "Package 'cybernetic-governance-engine' not found via importlib.metadata; "
            "defaulting gateway_version to '0.0.0'."
        )
        return "0.0.0"


_GATEWAY_VERSION: str = _resolve_gateway_version()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def stamp_iso_control(
    span: Any,
    tier: int,
    control: str,
    outcome: str,
) -> None:
    """Stamp ISO 42001 compliance evidence onto an active OTel span.

    Sets exactly the six attributes required by the compliance-bridge audit
    trail.  A no-op when *span* is ``None`` or falsy (e.g. tracing is
    disabled in tests).

    Args:
        span:     An ``opentelemetry.trace.Span`` instance (or any object
                  exposing ``set_attribute``).  If falsy the function returns
                  immediately without raising.
        tier:     Integer enforcement tier.
                  1 = Tier-1 heuristic (Aho-Corasick)
                  2 = Tier-2 semantic (SLM similarity)
                  3 = Tier-3 policy (OPA / NeMo)
        control:  ISO 42001 Annex A control identifier, e.g. ``"A.6.1.2"``.
        outcome:  Governance decision — one of ``"PASS"``, ``"BLOCK"``,
                  ``"REDACT"``.
    """
    if not span:
        return

    timestamp_ms: int = int(time.time() * 1000)
    evidence_chain: str = f"{control}:{tier}:{outcome}"

    span.set_attribute("iso42001.control",         control)
    span.set_attribute("iso42001.tier",            tier)
    span.set_attribute("iso42001.outcome",         outcome)
    span.set_attribute("iso42001.timestamp",       timestamp_ms)
    span.set_attribute("iso42001.gateway_version", _GATEWAY_VERSION)
    span.set_attribute("iso42001.evidence_chain",  evidence_chain)

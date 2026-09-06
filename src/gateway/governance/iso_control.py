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

import collections
import logging
import os
import time
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version
from typing import Any

logger = logging.getLogger("Gateway.Governance.IsoControl")

# ---------------------------------------------------------------------------
# In-memory audit trail — fast local cache (last 1000 entries)
# ---------------------------------------------------------------------------
_audit_trail: collections.deque = collections.deque(maxlen=1000)

_REDIS_STREAM_KEY = "iso_control:audit_trail"

# ---------------------------------------------------------------------------
# Deployment region — resolved at call time via the same env-var pattern used
# throughout src/gateway/governance/ (constants.py, normative_provider.py).
# Defaults to "US_FED" so that existing deployments without the env var set
# continue to stamp spans exactly as before (backward-compatible).
# ---------------------------------------------------------------------------


def _get_deployment_region() -> str:
    return os.environ.get("CAGE_DEPLOYMENT_REGION", "US_FED").strip().upper()


# ---------------------------------------------------------------------------
# FINDING-02 (CRITICAL) — Jurisdictional control mapping tables
#
# These maps extend the universal ISO 42001 span attributes with
# jurisdiction-specific control identifiers.  They are only applied when
# CAGE_DEPLOYMENT_REGION matches the corresponding jurisdiction.
#
# R-1: ISO 42001 evidence MUST always be produced (no region guard).
# R-2: NIST mapping only for US_FED.
# R-3: EU AI Act mapping only for EU_ECB.
# R-4: MAS FEAT mapping only for APAC_MAS.
# ---------------------------------------------------------------------------

# ISO 42001 Annex A control → NIST SP 800-53 Rev 5 control (US_FED only)
NIST_MAP: dict[str, str] = {
    "A.5.2": "GOVERN 1.1",
    "A.5.3": "AU-12",
    "A.6.2": "SA-15",
    "A.8.4": "SI-7",
    "A.9.2": "SA-9",
    "SC-4": "AC-6",
}

# ISO 42001 Annex A control → EU AI Act article (EU_ECB only)
EU_MAP: dict[str, str] = {
    "A.5.2": "Art. 9 (Risk Management System)",
    "A.5.3": "Art. 12 (Record-Keeping)",
    "A.6.2": "Art. 9 §4 (Lifecycle Risk Management)",
    "A.8.4": "Art. 13 (Transparency & Human Oversight)",
    "A.9.2": "Art. 10 (Data Governance)",
}

# ISO 42001 Annex A control → MAS FEAT / MAS Notice 655 reference (APAC_MAS only)
MAS_MAP: dict[str, str] = {
    "A.5.2": "MAS FEAT Principle 2 (Ethics)",
    "A.5.3": "MAS Notice 655 §4.3 (Audit Logging)",
    "A.6.2": "MAS FEAT Principle 4 (Accountability)",
    "A.8.4": "MAS FEAT Principle 3 (Transparency)",
    "A.9.2": "MAS TRM §4.2 (Data Residency)",
}

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
# Redis persistence helper
# ---------------------------------------------------------------------------


def _persist_evaluation(result: dict) -> None:
    """Write an ISO control evaluation result to a Redis stream for durable audit trail.

    Uses stream key 'iso_control:audit_trail' with XADD.
    Failures are logged and swallowed — Redis unavailability must not break
    the control evaluation path.
    """
    try:
        from src.gateway.infrastructure.redis_client import (
            sync_redis_client,
        )

        if sync_redis_client is None:
            return
        # XADD requires a flat dict of str→str fields
        fields = {k: str(v) for k, v in result.items()}
        sync_redis_client._get().xadd(_REDIS_STREAM_KEY, fields)  # type: ignore[arg-type]
    except Exception as exc:
        logger.error(
            "iso_control: failed to persist evaluation to Redis stream '%s': %s",
            _REDIS_STREAM_KEY,
            exc,
        )


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

    FINDING-02 (CRITICAL): The previous implementation had an inverted region
    guard that silenced the entire function for EU_ECB and APAC_MAS deployments,
    producing zero ISO 42001 compliance telemetry for those regions.

    Correct behaviour (R-1, R-2, R-3, R-4):
      - ISO 42001 attributes are ALWAYS stamped (universal — no region guard).
      - NIST SP 800-53 mapping is added ONLY for US_FED (R-2).
      - EU AI Act mapping is added ONLY for EU_ECB (R-3).
      - MAS FEAT mapping is added ONLY for APAC_MAS (R-4).

    Sets exactly the six mandatory ISO 42001 attributes plus one optional
    jurisdictional extension attribute.  A no-op when *span* is ``None`` or
    falsy (e.g. tracing is disabled in tests).

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

    region = _get_deployment_region()
    timestamp_ms: int = int(time.time() * 1000)
    evidence_chain: str = f"{control}:{tier}:{outcome}"

    # Universal: ISO 42001 evidence always produced (R-1 — no region guard).
    span.set_attribute("iso42001.control", control)
    span.set_attribute("iso42001.tier", tier)
    span.set_attribute("iso42001.outcome", outcome)
    span.set_attribute("iso42001.timestamp", timestamp_ms)
    span.set_attribute("iso42001.gateway_version", _GATEWAY_VERSION)
    span.set_attribute("iso42001.evidence_chain", evidence_chain)
    span.set_attribute("cage.iso_framework", "ISO/IEC 42001:2023")

    # Jurisdictional extension: add region-specific control mapping (R-2/R-3/R-4).
    if region == "US_FED":
        # NIST SP 800-53 mapping — US_FED only (SR 26-2 suppression pattern:
        # NIST control IDs have no legal force outside US_FED).
        nist_ref = NIST_MAP.get(control, "")
        if nist_ref:
            span.set_attribute("cage.nist_control", nist_ref)
    elif region == "EU_ECB":
        # EU AI Act mapping — EU_ECB only.
        eu_ref = EU_MAP.get(control, "")
        if eu_ref:
            span.set_attribute("cage.eu_ai_act_control", eu_ref)
    elif region == "APAC_MAS":
        # MAS FEAT / MAS Notice 655 mapping — APAC_MAS only.
        mas_ref = MAS_MAP.get(control, "")
        if mas_ref:
            span.set_attribute("cage.mas_feat_control", mas_ref)

    logger.debug(
        "stamp_iso_control: control=%s tier=%d outcome=%s region=%s",
        control,
        tier,
        outcome,
        region,
    )

    # Build evaluation result dict and persist durably
    result = {
        "control": control,
        "tier": tier,
        "outcome": outcome,
        "timestamp_ms": timestamp_ms,
        "gateway_version": _GATEWAY_VERSION,
        "evidence_chain": evidence_chain,
        "deployment_region": region,
    }
    # Keep fast local cache (bounded deque, maxlen=1000)
    _audit_trail.append(result)
    # Persist to Redis stream for durable cross-pod audit trail
    _persist_evaluation(result)


# ---------------------------------------------------------------------------
# ISO_CONTROL_MAP — governance event name → control ID (universal / ISO 42001)
# Canonical source of truth in Layer 1 Kernel.
# ---------------------------------------------------------------------------

_UNIVERSAL_CONTROL_MAP: dict[str, str] = {
    "nemo_input_scan": "A.9.2",  # Data Privacy / PII Masking
    "nemo_output_rail": "A.5.2",  # Social Impact / Content Safety
    "opa_policy_check": "SC-4",  # Fiscal Controls / RBAC
    "otel_trace": "A.5.3",  # Logging & Monitoring / Audit Trail
    "stpa_validation": "A.8.4",  # AI System Operation — STPA UCA checks
    "causal_gatekeeper": "A.6.2",  # AI Lifecycle — DoWhy causal refutation
    "saga_rollback": "A.8.4",  # AI System Operation — Saga compensating node execution
    # CAGE v2.0.0+ — AARM primitives
    "context_accumulate": "A.5.3",  # Context Accumulator chain node — Logging & Monitoring
    "defer_parking": "A.8.4",  # DEFER state machine — AI System Operation Controls
}

_JURISDICTIONAL_CONTROL_MAP: dict[str, dict[str, str]] = {
    # US_FED — NIST SP 800-53 / FedRAMP HIGH governance event mappings.
    "US_FED": {
        "stpa_compile": "SA-11",  # Developer Safety Testing — compiler run
        "linkerd_mtls": "SC-8",  # Transmission Confidentiality — Linkerd mTLS
        "cilium_l7_egress": "SC-7",  # Boundary Protection — Cilium FQDN filtering
    },
}


def get_iso_control_map(region: str) -> dict[str, str]:
    """Return the governance event → control ID map for the given deployment region."""
    return {
        **_UNIVERSAL_CONTROL_MAP,
        **_JURISDICTIONAL_CONTROL_MAP.get(region, {}),
    }

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
Governance Control Constants & Registry
========================================

Defines stable Internal Control IDs (CTRL_*) and the thread-safe singleton
``ControlRegistry`` that translates them to external regulatory citations.

Plugin Overlay Registry (PR B, T-B4)
-------------------------------------
Plugins can register compliance overlay directories via ``register_overlay_dir()``.
Overlays are applied in registration order after the baseline is loaded.

Design rationale
----------------
Hardcoding framework strings (e.g. "SR 26-2 §IV.B", "ISO 42001 §A.5.2") in
Python source files couples business logic to external regulatory schedules.
When a framework is updated or superseded, every Python file that embeds the
string must be edited — creating silent audit-trail discontinuities.

Solution: Python source code references only stable ``GovernanceControl`` enum
members.  The ``ControlRegistry`` singleton resolves those IDs to their current
regulatory mapping at runtime by reading a region-specific JSON profile.

Regional Configuration
----------------------
Set the ``CAGE_DEPLOYMENT_REGION`` environment variable to activate the
appropriate compliance profile:

  - ``US_FED``   → config/compliance/US_FED_BASELINE.json
                   (SR 26-2 / NIST AI RMF / ISO 42001)
  - ``EU_ECB``   → config/compliance/EU_ECB_BASELINE.json
                   (EU AI Act / DORA / GDPR / EBA/GL/2023/02)
  - ``APAC_MAS`` → config/compliance/APAC_MAS_BASELINE.json
                   (MAS FEAT / MAS TRM Guidelines / ISO 42001)

If CAGE_DEPLOYMENT_REGION is unset, the registry falls back first to the
regional profiles directory using ``US_FED`` as default, then to the legacy
``config/control_mappings.json`` for backward compatibility.

Usage::

    from src.gateway.governance.constants import GovernanceControl, ControlRegistry

    registry = ControlRegistry()  # returns the cached singleton
    meta = registry.get_mapping(GovernanceControl.AGENT_CONFIDENCE_THRESHOLD)
    # meta["primary_framework"] -> varies by active region
    # meta["legacy_citation"]   -> preserved for SIEM consumers

    # Check active region:
    print(registry.active_region)  # e.g. "EU_ECB"

    # Force re-configuration (e.g. during container init or testing):
    ControlRegistry.reconfigure("EU_ECB")
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from enum import Enum
from pathlib import Path
from typing import Any

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

logger = logging.getLogger("Gateway.Governance.Constants")


# ---------------------------------------------------------------------------
# Plugin overlay registry (PR B, T-B4)
# ---------------------------------------------------------------------------

_OVERLAY_DIRS: list[Path] = []


def register_overlay_dir(path: Path) -> None:
    """Register a plugin's compliance-overlay directory.

    Called from CagePlugin.register(). Directories are applied in
    registration order, which is deterministic because plugin discovery
    iterates entry points in a stable order. A later plugin overriding an
    earlier plugin's control mapping is logged at WARNING.

    Args:
        path: Path to the plugin's compliance overlay directory
              (e.g. src/cage_finance/config/compliance/)
    """
    resolved = path.resolve()
    if resolved not in _OVERLAY_DIRS:
        _OVERLAY_DIRS.append(resolved)
        logger.info(f"✅ Registered compliance overlay dir: {resolved}")


# ---------------------------------------------------------------------------
# Secure environment variable helper
# ---------------------------------------------------------------------------


def _require_env(key: str, fallback: str, *, sensitive: bool = True) -> str:
    """Return the value of environment variable *key*, or *fallback* in dev.

    In production (CAGE_ENV=prod), raises RuntimeError for sensitive variables
    that are not set — preventing silent use of insecure defaults.

    In dev/test, logs a warning and returns the fallback so existing
    non-production deployments are not broken.

    Args:
        key:       Environment variable name.
        fallback:  Default value to use in non-production environments.
        sensitive: When True, raises in prod if the variable is unset.
                   Set to False for non-secret configuration values.

    Returns:
        The environment variable value, or *fallback* in dev/test.

    Raises:
        RuntimeError: If *sensitive* is True, CAGE_ENV=prod, and *key* is unset.
    """
    value = os.environ.get(key)
    if value:
        return value
    cage_env = os.environ.get(
        "CAGE_ENV", "prod"
    ).lower()  # Default to "prod" to fail-secure: missing CAGE_ENV must not silently disable enforcement
    if cage_env == "prod" and sensitive:
        raise RuntimeError(
            f"Required environment variable {key!r} is not set in production. "
            f"Set it via Kubernetes Secret or environment injection before starting."
        )
    logging.getLogger(__name__).warning(
        "Using fallback for %s — set this in production", key
    )
    return fallback


# ---------------------------------------------------------------------------
# Supported deployment regions
# ---------------------------------------------------------------------------

SUPPORTED_REGIONS = frozenset({"US_FED", "EU_ECB", "APAC_MAS"})

_DEFAULT_REGION = "US_FED"

# ---------------------------------------------------------------------------
# Internal Control ID Enum
# ---------------------------------------------------------------------------


class GovernanceControl(Enum):
    """Stable internal control identifiers.

    Values (CTRL_*) are permanent keys that never change regardless of which
    external frameworks are in effect.  Add new entries here when new control
    points are introduced; never embed framework citation strings in src/.
    """

    AGENT_CONFIDENCE_THRESHOLD = "CTRL_AGT_001"
    """Minimum agentic model confidence required to execute a trade."""

    WAL_NODE_EXECUTION = "CTRL_WAL_002"
    """Atomic transaction guarantee via Write-Ahead Log and LIFO rollback."""

    TELEMETRY_LIVE_VALIDATION = "CTRL_TEL_003"
    """World-model validation must reflect live runtime telemetry."""

    TRADITIONAL_MRM_VALIDATION = "CTRL_MRM_004"
    """Traditional quantitative model validation (non-agentic components)."""

    OPA_POLICY_ENFORCEMENT = "CTRL_OPA_005"
    """OPA policy must ALLOW before any agentic action is executed."""

    FRIA_ASSESSMENT = "CTRL_FRIA_006"
    """Pre-market Fundamental Rights Impact Assessment (EU AI Act Art. 29a).
    Only present in EU_ECB regional profile; raises KeyError in other regions."""

    TOKEN_QUOTA_ENFORCEMENT = "CTRL_TQP_007"
    """Per-session token and step-count quota enforcement via Redis atomic counters.
    ISO 42001 Annex A.4. Enforcement tier 2. Primary enforcer: TokenQuotaProxy."""

    AGENTIC_SCOPE_STATEMENT = "agentic_scope_statement"
    """Reference to the agentic scope statement document (SR 26-2 §3.1, AI 600-1 §2.5).
    Declares authorized action space, HITL boundaries, and inter-agent trust model.
    POAM: AI600-001 (secondary). Region: US_FED."""

    FTRA_REACHABILITY_GATE = "CTRL_FTRA_001"
    """Forward-Looking Trajectory Reachability Analyzer — Tier 0.5 governance gate.

    Performs commencement-time worst-case reachability analysis on the
    ExecutionPlan before the first LangGraph node fires.  Classifies each
    reachable action against the compiled terminal registry
    (config/ftra/terminal_registry.json) and issues one of three verdicts:

        CLEAR          — no IRREVERSIBLE_TERMINAL node reachable; proceed to OPA
        HITL_REQUIRED  — irreversible terminal reachable, confidence >= 0.70;
                         park in DeferQueue db=1 pending human clearance
        BLOCKED        — irreversible terminal reachable, confidence < 0.70;
                         route to explainer; plan cannot proceed

    OTel span: ``cage.ftra_analysis``
    DeferReason: ``FTRA_IRREVERSIBLE_TERMINAL``
    Registry: ``config/ftra/terminal_registry.json``
    Compiler target: ``--targets ftra`` (stpa_compiler.py)
    """


# ---------------------------------------------------------------------------
# Singleton ControlRegistry
# ---------------------------------------------------------------------------


class ControlRegistry:
    """Thread-safe singleton that resolves GovernanceControl IDs to regulatory metadata.

    The registry is loaded exactly once from the appropriate regional JSON
    profile at first instantiation. Subsequent calls to ``ControlRegistry()``
    return the same in-memory instance — no repeated disk I/O or stale-state
    risk across parallel workers.

    Regional profile resolution order
    ----------------------------------
    1. ``CAGE_DEPLOYMENT_REGION`` environment variable (at instantiation time).
    2. Default region ``US_FED`` if env var is unset.
    3. ``config/compliance/{REGION}_BASELINE.json`` regional profile (required).

    Raises:
        RuntimeError: If no JSON file can be found or parsed at startup.
        KeyError: If a requested CTRL_* ID is absent from the active registry.
    """

    _instance: ControlRegistry | None = None
    _lock: threading.RLock = threading.RLock()
    _mappings: dict[str, Any] = {}
    _active_region: str = _DEFAULT_REGION
    _active_hash: str = ""

    # Paths
    _REPO_ROOT: Path = Path(__file__).resolve().parents[3]
    _COMPLIANCE_DIR: Path = _REPO_ROOT / "config" / "compliance"

    def __new__(cls) -> ControlRegistry:
        if cls._instance is None:
            with cls._lock:
                # Double-checked locking — prevents redundant loads under
                # concurrent instantiation in multi-threaded test runners.
                if cls._instance is None:
                    instance = super().__new__(cls)
                    instance._load_registry()
                    cls._instance = instance
        return cls._instance

    # ------------------------------------------------------------------
    # Public properties
    # ------------------------------------------------------------------

    @property
    def active_region(self) -> str:
        """The deployment region whose profile is currently loaded.

        Returns the string identifier (e.g. ``"EU_ECB"``, ``"US_FED"``,
        ``"APAC_MAS"``).
        """
        return self.__class__._active_region

    @property
    def active_hash(self) -> str:
        """Read-only access to the pinned baseline profile hash."""
        with self.__class__._lock:
            return self.__class__._active_hash

    @classmethod
    def _coerce_floats(cls, data: Any) -> Any:
        """Recursively normalizes floats to standard decimal format strings to prevent token discrepancies."""
        if isinstance(data, dict):
            return {k: cls._coerce_floats(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [cls._coerce_floats(item) for item in data]
        elif isinstance(data, float):
            # Normalize float representation consistently
            if data.is_integer():
                return int(data)
            return round(data, 6)
        return data

    # ------------------------------------------------------------------
    # Internal loading
    # ------------------------------------------------------------------

    def _load_registry(self, region: str | None = None) -> None:
        """Load the JSON profile for the given or environment-resolved region.

        Resolution order:
          1. ``region`` argument (explicit override — for reconfigure()).
          2. ``CAGE_DEPLOYMENT_REGION`` environment variable.
          3. ``US_FED`` default.
          4. Legacy ``config/control_mappings.json`` if regional file missing.
        """
        if region is None:
            region = (
                os.getenv("CAGE_DEPLOYMENT_REGION", _DEFAULT_REGION).strip().upper()
            )

        # Validate region string
        if region not in SUPPORTED_REGIONS:
            logger.warning(
                "ControlRegistry: unknown region '%s'. Supported: %s. "
                "Falling back to default '%s'.",
                region,
                sorted(SUPPORTED_REGIONS),
                _DEFAULT_REGION,
            )
            region = _DEFAULT_REGION

        config_path = self._COMPLIANCE_DIR / f"{region}_BASELINE.json"

        if not config_path.exists():
            raise RuntimeError(
                f"ControlRegistry: regional profile not found at {config_path}. "
                f"Cannot start governance engine without a valid profile."
            )

        try:
            with open(config_path) as fh:
                raw = json.load(fh)

            # Apply plugin-supplied overlays in registration order (PR B, T-B4)
            for overlay_dir in _OVERLAY_DIRS:
                overlay_path = overlay_dir / f"{region}_OVERLAY.json"
                if overlay_path.exists():
                    with open(overlay_path) as fh:
                        overlay_raw = json.load(fh)
                    # Warn on control collision (later plugin overriding earlier)
                    for key in overlay_raw:
                        if key in raw and not key.startswith("_"):
                            logger.warning(
                                "Control mapping collision: %s from %s overrides "
                                "earlier mapping",
                                key,
                                overlay_path,
                            )
                    raw.update(overlay_raw)

            # Strip meta-keys that start with "_"
            self._mappings = {
                k: v
                for k, v in raw.items()
                if not k.startswith("_") and isinstance(v, dict)
            }
            self.__class__._active_region = region

            # Canonical stringification: sorted keys, compact separators
            # v3.1.0: Migrated to RFC 8785 JCS canonicalization
            normalized_raw = self._coerce_floats(raw)
            canonical_bytes = jcs_canonicalize_plan(normalized_raw)
            computed_hash = hashlib.sha256(canonical_bytes).hexdigest()

            with self.__class__._lock:
                self.__class__._active_hash = computed_hash

            logger.info(
                "✅ ControlRegistry loaded %d control mappings from %s (region: %s, hash: %s)",
                len(self._mappings),
                config_path,
                region,
                computed_hash[:12],
            )
        except FileNotFoundError:
            raise RuntimeError(
                f"ControlRegistry: no control mappings file found at {config_path}. "
                f"Cannot start governance engine without a valid profile."
            )
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"ControlRegistry: control mappings JSON at {config_path} is malformed: {exc}"
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_mapping(self, control: GovernanceControl) -> dict[str, Any]:
        """Return the full regulatory metadata dict for a GovernanceControl.

        Args:
            control: A ``GovernanceControl`` enum member.

        Returns:
            Dict containing ``internal_id``, ``primary_framework``,
            ``co_frameworks``, ``legacy_citation``, ``scope``, and
            ``description``.

        Raises:
            KeyError: If the control ID is not present in the active regional
                profile.  Some controls (e.g. CTRL_FRIA_006) are only defined
                in specific regional profiles (e.g. EU_ECB).
        """
        control_id = control.value
        if control_id not in self._mappings:
            raise KeyError(
                f"ControlRegistry: control ID '{control_id}' is not defined in "
                f"the active '{self.active_region}' regional profile. "
                f"If this is a region-specific control (e.g. CTRL_FRIA_006 for EU_ECB), "
                f"ensure the correct CAGE_DEPLOYMENT_REGION is set."
            )
        return self._mappings[control_id]

    def get_mapping_safe(self, control: GovernanceControl) -> dict[str, Any] | None:
        """Return the mapping dict, or None if the control is absent in this region.

        Use this variant for region-specific controls (e.g. CTRL_FRIA_006) that
        should be silently skipped in regions where they are not applicable,
        rather than raising a KeyError.
        """
        try:
            return self.get_mapping(control)
        except KeyError:
            return None

    # ------------------------------------------------------------------
    # Class-level lifecycle helpers
    # ------------------------------------------------------------------

    @classmethod
    def reconfigure(cls, region: str) -> None:
        """Destroy the current singleton and reload with the specified region.

        This is the production-safe replacement for ``reset_for_testing``.
        Call this during container initialization when the deployment region
        is determined at runtime (e.g. from a Kubernetes ConfigMap or Workload
        Identity metadata).

        Args:
            region: One of ``"US_FED"``, ``"EU_ECB"``, ``"APAC_MAS"``.

        Example::

            # In your container entrypoint / FastAPI lifespan:
            region = os.getenv("CAGE_DEPLOYMENT_REGION", "US_FED")
            ControlRegistry.reconfigure(region)

        Thread-safety note (C-13 fix):
            The previous implementation released the lock between clearing
            ``_instance`` and re-assigning it, creating a TOCTOU window where
            a concurrent ``ControlRegistry()`` call could observe ``_instance
            is None`` and construct a new instance with the *old* region.
            In a multi-region deployment this could cause US_FED controls to
            be evaluated against EU_ECB mappings during a baseline refresh.

            The fix: load the new registry *outside* the lock (I/O-bound work
            should not hold a lock), then swap ``_instance`` atomically inside
            a single lock acquisition.  Concurrent readers that acquire the
            lock between the clear and the swap will block until the swap
            completes, then see the fully-loaded new instance.
        """
        normalized_region = region.strip().upper()

        # Build the new instance outside the lock — _load_registry() does
        # file I/O and JSON parsing which should not block other threads.
        new_instance = object.__new__(cls)
        new_instance._load_registry(region=normalized_region)

        # Atomically swap: clear the old singleton and install the new one
        # in a single lock acquisition, eliminating the TOCTOU window.
        with cls._lock:
            cls._instance = None
            cls._mappings = {}
            cls._active_region = _DEFAULT_REGION
            cls._instance = new_instance

        logger.info("ControlRegistry reconfigured to region: %s", normalized_region)

    @classmethod
    def reset_for_testing(cls) -> None:
        """Destroy the singleton — for use in unit tests that swap config paths.

        Do NOT call this in production code; use ``reconfigure()`` instead.
        """
        with cls._lock:
            cls._instance = None
            cls._mappings = {}
            cls._active_region = _DEFAULT_REGION


# ---------------------------------------------------------------------------
# Jurisdiction-keyed regulatory citation tables
#
# These constants are defined here (in constants.py, which is excluded from
# the architecture guardrail scan) so that executable source files in
# src/gateway/governance/ can import stable identifiers rather than embedding
# volatile regulatory citation strings directly.
#
# Pattern: import the dict from constants and call .get(region, DEFAULT_*).
# ---------------------------------------------------------------------------

# HITL SLA citations — jurisdiction-specific escalation authority
# PR B T-B5: These are now loaded from regional baseline JSONs (_hitl section)
# instead of being imported from cage_finance.constants.
HITL_CITATIONS: dict[str, str] = {}
HITL_CITATION_DEFAULT: str = "ISO 42001 A.8.4 (AI system operation controls)"

# FINDING-09 — HITL SLA hours, keyed identically to HITL_CITATIONS above.
HITL_SLA_HOURS: dict[str, float] = {}
HITL_SLA_HOURS_DEFAULT: float = 4.0  # ISO 42001 §A.8.4 fallback

# PII audit retention authority — jurisdiction-specific data retention law
PII_RETENTION_AUTHORITY: dict[str, str] = {}
PII_RETENTION_AUTHORITY_DEFAULT: str = "ISO 42001 A.9.2"

# Prompt injection detection citation — jurisdiction-specific robustness authority
INJECTION_CITATION: dict[str, str] = {}
INJECTION_CITATION_DEFAULT: str = (
    "ISO 42001 A.9.2 (data transfer to suppliers — input validation)"
)


def _load_hitl_constants_from_baselines() -> None:
    """Load HITL regulatory constants from regional baseline JSONs.

    Called at module import time to populate HITL_CITATIONS, HITL_SLA_HOURS,
    PII_RETENTION_AUTHORITY, and INJECTION_CITATION from the _hitl section
    of each regional baseline JSON file.

    These are regulatory constants (not domain-specific), so they belong in
    the regional baselines rather than in cage_finance (PR B, T-B5).
    """
    global HITL_CITATIONS, HITL_SLA_HOURS, PII_RETENTION_AUTHORITY, INJECTION_CITATION

    # Path(__file__) = src/gateway/governance/constants.py
    # .parent = src/gateway/governance/
    # .parent = src/gateway/
    # .parent = src/
    # .parent = repo_root
    repo_root = Path(__file__).parent.parent.parent.parent
    compliance_dir = repo_root / "config" / "compliance"

    logger.debug(f"Loading HITL constants from {compliance_dir}")

    for region in SUPPORTED_REGIONS:
        baseline_path = compliance_dir / f"{region}_BASELINE.json"
        if not baseline_path.exists():
            logger.debug(f"Baseline not found: {baseline_path}")
            continue

        try:
            with open(baseline_path) as fh:
                baseline = json.load(fh)

            hitl = baseline.get("_hitl", {})
            if hitl:
                logger.debug(f"Found _hitl section for {region}: {hitl}")
                if "citation" in hitl:
                    HITL_CITATIONS[region] = hitl["citation"]
                if "sla_hours" in hitl:
                    HITL_SLA_HOURS[region] = float(hitl["sla_hours"])
                if "pii_retention_authority" in hitl:
                    PII_RETENTION_AUTHORITY[region] = hitl["pii_retention_authority"]
                if "injection_citation" in hitl:
                    INJECTION_CITATION[region] = hitl["injection_citation"]
            else:
                logger.debug(f"No _hitl section found for {region}")
        except Exception as e:
            logger.warning(
                "Failed to load HITL constants from %s: %s",
                baseline_path,
                e,
            )

    logger.debug(f"Loaded INJECTION_CITATION: {INJECTION_CITATION}")
    logger.debug(f"Loaded HITL_CITATIONS: {HITL_CITATIONS}")


# Load HITL constants at module import time
_load_hitl_constants_from_baselines()

# PII audit retention authority field default for Pydantic schema
PII_AUDIT_RETENTION_AUTHORITY_FIELD_DEFAULT: str = "ISO 42001 A.9.2"

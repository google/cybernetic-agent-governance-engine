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

import json
import logging
import os
import threading
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("Gateway.Governance.Constants")

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
    3. ``config/compliance/{REGION}_BASELINE.json`` regional profile.
    4. Legacy fallback: ``config/control_mappings.json`` (backward compat).

    Raises:
        RuntimeError: If no JSON file can be found or parsed at startup.
        KeyError: If a requested CTRL_* ID is absent from the active registry.
    """

    _instance: "ControlRegistry | None" = None
    _lock: threading.Lock = threading.Lock()
    _mappings: Dict[str, Any] = {}
    _active_region: str = _DEFAULT_REGION

    # Paths
    _REPO_ROOT: Path = Path(__file__).resolve().parents[3]
    _COMPLIANCE_DIR: Path = _REPO_ROOT / "config" / "compliance"
    _LEGACY_PATH: Path = _REPO_ROOT / "config" / "control_mappings.json"

    def __new__(cls) -> "ControlRegistry":
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
        ``"APAC_MAS"``) or ``"LEGACY"`` if the fallback file was used.
        """
        return self.__class__._active_region

    # ------------------------------------------------------------------
    # Internal loading
    # ------------------------------------------------------------------

    def _load_registry(self, region: Optional[str] = None) -> None:
        """Load the JSON profile for the given or environment-resolved region.

        Resolution order:
          1. ``region`` argument (explicit override — for reconfigure()).
          2. ``CAGE_DEPLOYMENT_REGION`` environment variable.
          3. ``US_FED`` default.
          4. Legacy ``config/control_mappings.json`` if regional file missing.
        """
        if region is None:
            region = os.getenv("CAGE_DEPLOYMENT_REGION", _DEFAULT_REGION).strip().upper()

        # Validate region string
        if region not in SUPPORTED_REGIONS:
            logger.warning(
                "ControlRegistry: unknown region '%s'. Supported: %s. "
                "Falling back to default '%s'.",
                region, sorted(SUPPORTED_REGIONS), _DEFAULT_REGION,
            )
            region = _DEFAULT_REGION

        config_path = self._COMPLIANCE_DIR / f"{region}_BASELINE.json"

        if not config_path.exists():
            logger.warning(
                "ControlRegistry: regional profile not found at %s — "
                "falling back to legacy control_mappings.json.",
                config_path,
            )
            config_path = self._LEGACY_PATH
            region = "LEGACY"

        try:
            with open(config_path, "r") as fh:
                raw = json.load(fh)
            # Strip meta-keys that start with "_"
            self._mappings = {k: v for k, v in raw.items() if not k.startswith("_")}
            self.__class__._active_region = region
            logger.info(
                "✅ ControlRegistry loaded %d control mappings from %s (region: %s)",
                len(self._mappings),
                config_path,
                region,
            )
        except FileNotFoundError:
            raise RuntimeError(
                f"ControlRegistry: no control mappings file found. "
                f"Tried regional path {self._COMPLIANCE_DIR / f'{region}_BASELINE.json'} "
                f"and legacy fallback {self._LEGACY_PATH}. "
                f"Cannot start governance engine without a valid profile."
            )
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"ControlRegistry: control mappings JSON at {config_path} is malformed: {exc}"
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_mapping(self, control: GovernanceControl) -> Dict[str, Any]:
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

    def get_mapping_safe(self, control: GovernanceControl) -> Optional[Dict[str, Any]]:
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
        """
        with cls._lock:
            cls._instance = None
            cls._mappings = {}
            cls._active_region = _DEFAULT_REGION
        # Re-instantiate with the explicit region
        instance = object.__new__(cls)
        instance._load_registry(region=region.strip().upper())
        with cls._lock:
            cls._instance = instance
        logger.info("ControlRegistry reconfigured to region: %s", region)

    @classmethod
    def reset_for_testing(cls) -> None:
        """Destroy the singleton — for use in unit tests that swap config paths.

        Do NOT call this in production code; use ``reconfigure()`` instead.
        """
        with cls._lock:
            cls._instance = None
            cls._mappings = {}
            cls._active_region = _DEFAULT_REGION

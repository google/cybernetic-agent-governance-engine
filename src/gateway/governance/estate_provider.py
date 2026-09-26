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
Estate Provider Factory & Kernel-Resident Providers.

This module is the Gate G3 allowlisted factory for the EstateProvider seam
(``src/gateway/governance/seams/estate.py``). It mirrors the pattern of
``get_normative_provider()`` in ``src/gateway/governance/normative_provider.py``.

Kernel-resident providers:
    - ``UnavailableEstateProvider`` — fail-closed default when no provider is
      configured. Every result has ``status=UNAVAILABLE``.
    - ``StubEstateProvider`` — permissive hermetic fixture for local/CI tests.
      Refuses to construct outside development/test postures.

Usage:
    from src.gateway.governance.estate_provider import get_estate_provider

    provider = get_estate_provider()  # CAGE_ESTATE_PROVIDER, else fail-closed
    predicate = await provider.get_resource_predicate("test:resource:urn")
    if not predicate.is_trustworthy:
        ...  # fail closed
"""

from __future__ import annotations

import logging
import os

from src.gateway.governance.seams.estate import (
    BlastRadiusEstimate,
    CloudOpsResourcePredicate,
    CloudOpsReversibility,
    CriticalityTier,
    EnvironmentTier,
    EstateProvider,
    EstateQueryStatus,
    IaCDriftStatus,
    TopologySnapshot,
)

logger = logging.getLogger(__name__)

_ZERO_HASH = "sha256:" + "0" * 64
_NON_PRODUCTION_ENVS = frozenset({"development", "test", "dev", "ci"})

UNAVAILABLE_PROVIDER_NAME = "unavailable"
STUB_PROVIDER_NAME = "stub"


class UnavailableEstateProvider(EstateProvider):
    """Fail-closed estate provider used when no provider is configured.

    Every result carries ``status=EstateQueryStatus.UNAVAILABLE`` (the primary
    fail-closed signal) and maximally conservative field values (defence in
    depth for any consumer that inspects fields directly).
    """

    def __init__(self, reason: str = "no estate provider configured") -> None:
        self._reason = reason

    async def get_resource_predicate(
        self, resource_urn: str
    ) -> CloudOpsResourcePredicate:
        """Return an UNAVAILABLE predicate with worst-case field values."""
        return CloudOpsResourcePredicate(
            status=EstateQueryStatus.UNAVAILABLE,
            resource_urn=resource_urn,
            resource_type="unknown",
            is_load_bearing=True,
            direct_dependents_count=0,
            transitive_dependency_depth=0,
            has_failover_redundancy=False,
            active_network_flows_last_1h=0,
            environment_tier=EnvironmentTier.PRODUCTION,
            criticality_tier=CriticalityTier.TIER_0,
            owner_team_urn="unknown",
            managed_by_terraform=False,
            iac_drift_status=IaCDriftStatus.UNMANAGED,
            reversibility_tier=CloudOpsReversibility.IRREVERSIBLE_TERMINAL,
            estimated_blast_radius_score=1.0,
            snapshot_id=UNAVAILABLE_PROVIDER_NAME,
            snapshot_hash=_ZERO_HASH,
            evaluated_at_utc="",
            error=self._reason,
        )

    async def query_blast_radius(
        self, resource_urn: str, action: str
    ) -> BlastRadiusEstimate:
        """Return an UNAVAILABLE estimate that always requires approval."""
        return BlastRadiusEstimate(
            status=EstateQueryStatus.UNAVAILABLE,
            resource_urn=resource_urn,
            action=action,
            estimated_affected_services=0,
            estimated_affected_users=0,
            estimated_recovery_time_minutes=0,
            requires_approval=True,
            approval_tier="VP_ENG",
            error=self._reason,
        )

    async def get_topology_snapshot(self, scope: str) -> TopologySnapshot:
        """Return an UNAVAILABLE, empty snapshot with zero TTL."""
        return TopologySnapshot(
            status=EstateQueryStatus.UNAVAILABLE,
            scope=scope,
            snapshot_id=UNAVAILABLE_PROVIDER_NAME,
            snapshot_hash=_ZERO_HASH,
            nodes=(),
            edges=(),
            captured_at_utc="",
            ttl_seconds=0,
            error=self._reason,
        )


class StubEstateProvider(EstateProvider):
    """Permissive hermetic stub for local/CI testing.

    WARNING: This provider returns *permissive* predicates (non-load-bearing,
    non-production, low blast radius, no approval required). It would ground
    every infrastructure action as safe, so construction raises
    ``RuntimeError`` unless ``CAGE_ENV`` is a development/test posture
    (mirrors ``StubNormativeProvider``).
    """

    def __init__(self) -> None:
        cage_env = os.getenv("CAGE_ENV", "production").lower()
        if cage_env not in _NON_PRODUCTION_ENVS:
            raise RuntimeError(
                "StubEstateProvider cannot be used outside development/test "
                f"postures (CAGE_ENV={cage_env!r}). Set CAGE_ESTATE_PROVIDER to "
                "a real provider (e.g. provider_09) or leave it unset to use "
                "the fail-closed UnavailableEstateProvider."
            )
        logger.warning(
            "⚠️  StubEstateProvider active (CAGE_ENV=%s) — estate predicates are "
            "synthetic and permissive. Never use in production.",
            cage_env,
        )

    async def get_resource_predicate(
        self, resource_urn: str
    ) -> CloudOpsResourcePredicate:
        """Return a permissive non-production predicate for hermetic tests."""
        return CloudOpsResourcePredicate(
            status=EstateQueryStatus.OK,
            resource_urn=resource_urn,
            resource_type="test.resource",
            is_load_bearing=False,
            direct_dependents_count=0,
            transitive_dependency_depth=0,
            has_failover_redundancy=True,
            active_network_flows_last_1h=0,
            environment_tier=EnvironmentTier.DEVELOPMENT,
            criticality_tier=CriticalityTier.TIER_3,
            owner_team_urn="urn:team:test",
            managed_by_terraform=True,
            iac_drift_status=IaCDriftStatus.SYNCHRONIZED,
            last_iac_commit_hash="0" * 40,
            reversibility_tier=CloudOpsReversibility.REVERSIBLE,
            estimated_blast_radius_score=0.1,
            compensating_rollback_action="rollback_deployment",
            snapshot_id="stub-snapshot-001",
            snapshot_hash=_ZERO_HASH,
            evaluated_at_utc="2026-01-01T00:00:00Z",
        )

    async def query_blast_radius(
        self, resource_urn: str, action: str
    ) -> BlastRadiusEstimate:
        """Return a minimal blast radius for hermetic tests."""
        return BlastRadiusEstimate(
            status=EstateQueryStatus.OK,
            resource_urn=resource_urn,
            action=action,
            estimated_affected_services=0,
            estimated_affected_users=0,
            estimated_recovery_time_minutes=1,
            requires_approval=False,
            approval_tier="NONE",
        )

    async def get_topology_snapshot(self, scope: str) -> TopologySnapshot:
        """Return an empty topology snapshot for hermetic tests."""
        return TopologySnapshot(
            status=EstateQueryStatus.OK,
            scope=scope,
            snapshot_id="stub-snapshot-001",
            snapshot_hash=_ZERO_HASH,
            nodes=(),
            edges=(),
            captured_at_utc="2026-01-01T00:00:00Z",
        )


_ALIAS_MAP = {
    "p09": "provider_09",
    "opscanvas": "provider_09",
    "ops-canvas": "provider_09",
    "ops_canvas": "provider_09",
}

_VALID_PROVIDERS = (UNAVAILABLE_PROVIDER_NAME, STUB_PROVIDER_NAME, "provider_09")


def get_estate_provider(name: str | None = None) -> EstateProvider:
    """Resolve and instantiate an EstateProvider by name.

    Args:
        name: Provider name. If None, reads ``CAGE_ESTATE_PROVIDER``. When that
              is unset or empty, resolves to the fail-closed
              ``UnavailableEstateProvider`` — never to the permissive stub.

    Supported providers:
        - "unavailable"  — Fail-closed default (kernel-resident)
        - "stub"         — Permissive hermetic fixture; dev/test postures only
        - "provider_09"  — OpsCanvas MCP estate provider (alias: "opscanvas")

    Returns:
        An instantiated EstateProvider.

    Raises:
        ValueError: If the provider name is not registered.
        RuntimeError: If "stub" is requested outside a dev/test posture.
    """
    raw_name = name if name is not None else os.environ.get("CAGE_ESTATE_PROVIDER", "")
    provider_name = raw_name.split("#")[0].strip().lower() or UNAVAILABLE_PROVIDER_NAME
    provider_name = _ALIAS_MAP.get(provider_name, provider_name)

    if provider_name == UNAVAILABLE_PROVIDER_NAME:
        logger.warning(
            "EstateProvider: none configured (CAGE_ESTATE_PROVIDER unset) — "
            "using fail-closed UnavailableEstateProvider."
        )
        return UnavailableEstateProvider()

    if provider_name == STUB_PROVIDER_NAME:
        return StubEstateProvider()

    # Vendor providers — function-scope lazy import (Gate G3 factory allowlist)
    if provider_name == "provider_09":
        from src.integrations.provider_09 import Provider09EstateProvider

        return Provider09EstateProvider.from_env()

    raise ValueError(
        f"Unknown estate provider: {provider_name!r}. "
        f"Available providers: {list(_VALID_PROVIDERS)}."
    )

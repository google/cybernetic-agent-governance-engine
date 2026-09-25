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
Stub Estate Provider — Hermetic Test Fixture.

Provides deterministic responses for local development and CI without requiring
a live OpsCanvas MCP daemon or cloud API credentials. This stub mirrors the
pattern of StubNormativeProvider in src/gateway/governance/normative_provider.py.

Usage:
    from src.gateway.governance.seams.estate import get_estate_provider

    provider = get_estate_provider("stub")
    predicate = await provider.get_resource_predicate("test:resource:urn")
"""

from __future__ import annotations

from src.gateway.governance.seams.estate import (
    BlastRadiusEstimate,
    CloudOpsResourcePredicate,
    CloudOpsReversibility,
    CriticalityTier,
    EnvironmentTier,
    EstateProvider,
    IaCDriftStatus,
    TopologySnapshot,
)


class StubEstateProvider(EstateProvider):
    """Hermetic stub for local/CI testing — always returns safe defaults.

    This provider returns non-production, low-risk predicates suitable for
    hermetic unit tests that don't require live CloudOps infrastructure.
    All predicates are deliberately conservative (non-load-bearing, low blast
    radius, synchronized with IaC) to enable fast test execution.
    """

    async def get_resource_predicate(
        self, resource_urn: str
    ) -> CloudOpsResourcePredicate:
        """Return safe non-production predicate for hermetic tests.

        Args:
            resource_urn: Target resource URN (ignored in stub)

        Returns:
            CloudOpsResourcePredicate with safe test defaults
        """
        return CloudOpsResourcePredicate(
            resource_urn=resource_urn,
            resource_type="test.resource",
            # Topology & Blast Radius — safe defaults
            is_load_bearing=False,
            direct_dependents_count=0,
            transitive_dependency_depth=0,
            has_failover_redundancy=True,
            active_network_flows_last_1h=0,
            # Classification — non-production
            environment_tier=EnvironmentTier.DEVELOPMENT,
            criticality_tier=CriticalityTier.TIER_3,
            owner_team_urn="urn:team:test",
            # State & Drift — synchronized
            managed_by_terraform=True,
            iac_drift_status=IaCDriftStatus.SYNCHRONIZED,
            last_iac_commit_hash="0000000000000000000000000000000000000000",
            # FTRA Reversibility — reversible with low blast radius
            reversibility_tier=CloudOpsReversibility.REVERSIBLE,
            estimated_blast_radius_score=0.1,
            compensating_rollback_action="rollback_deployment",
            # Provenance
            snapshot_id="stub-snapshot-001",
            snapshot_hash="sha256:0000000000000000000000000000000000000000000000000000000000000000",
            evaluated_at_utc="2026-01-01T00:00:00Z",
            query_latency_ms=0.0,
        )

    async def query_blast_radius(
        self, resource_urn: str, action: str
    ) -> BlastRadiusEstimate:
        """Return minimal blast radius for hermetic tests.

        Args:
            resource_urn: Target resource URN (ignored in stub)
            action: Proposed action verb (ignored in stub)

        Returns:
            BlastRadiusEstimate with minimal impact
        """
        return BlastRadiusEstimate(
            resource_urn=resource_urn,
            action=action,
            estimated_affected_services=0,
            estimated_affected_users=0,
            estimated_recovery_time_minutes=1,
            requires_approval=False,
            approval_tier="NONE",
        )

    async def get_topology_snapshot(self, scope: str) -> TopologySnapshot:
        """Return empty topology snapshot for hermetic tests.

        Args:
            scope: Scope filter (ignored in stub)

        Returns:
            TopologySnapshot with empty graph
        """
        return TopologySnapshot(
            scope=scope,
            snapshot_id="stub-snapshot-001",
            snapshot_hash="sha256:0000000000000000000000000000000000000000000000000000000000000000",
            nodes=[],
            edges=[],
            captured_at_utc="2026-01-01T00:00:00Z",
            ttl_seconds=300,
        )

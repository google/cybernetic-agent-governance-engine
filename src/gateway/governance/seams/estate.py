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
Infrastructure Estate Provider Seam — Vendor-Neutral CloudOps Context Interface.

This module defines the contract between CAGE's governance kernel and external
infrastructure topology providers (OpsCanvas, Steampipe, cloud asset inventories).

By defining this seam separately from the kernel, we enable dynamic integration
of CloudOps estate context (blast radius, topology, drift) into FTRA reachability
analysis and deferral queue hydration without polluting Layer 1 with vendor logic.

Architectural Invariant:
    This module must NEVER import from src.gateway.governance or any kernel module
    except other seam dataclasses. It defines pure data contracts and protocols only.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol


class CloudOpsReversibility(str, Enum):
    """Infrastructure mutation reversibility tiers (maps to FTRA TerminalClassification)."""

    READ_ONLY = "READ_ONLY"
    REVERSIBLE = "REVERSIBLE"
    EXTERNALLY_REVERSIBLE = "EXTERNALLY_REVERSIBLE"
    IRREVERSIBLE_TERMINAL = "IRREVERSIBLE_TERMINAL"


class EnvironmentTier(str, Enum):
    """Deployment environment classification."""

    PRODUCTION = "PRODUCTION"
    STAGING = "STAGING"
    DEVELOPMENT = "DEVELOPMENT"
    SANDBOX = "SANDBOX"


class CriticalityTier(str, Enum):
    """Service criticality classification (descending importance)."""

    TIER_0 = "TIER_0"  # Core routing, auth, primary DB
    TIER_1 = "TIER_1"  # User-facing business microservices
    TIER_2 = "TIER_2"  # Internal async tooling, reporting
    TIER_3 = "TIER_3"  # Non-critical batch jobs


class IaCDriftStatus(str, Enum):
    """Infrastructure-as-Code drift detection status."""

    SYNCHRONIZED = "SYNCHRONIZED"
    DRIFT_DETECTED = "DRIFT_DETECTED"
    UNMANAGED = "UNMANAGED"


@dataclass
class CloudOpsResourcePredicate:
    """Deterministic CloudOps predicate for FTRA grounding and deferral hydration.

    This structure provides strongly-typed, scalar infrastructure predicates
    suitable for microsecond OPA Rego evaluation and CBF barrier functions.
    Returned by EstateProvider.get_resource_predicate().

    Attributes:
        resource_urn: Canonical resource URN (e.g. "gcp:cloudrun:us-central1:gateway")
        resource_type: Resource type classifier (e.g. "compute.instance", "run.service")
        is_load_bearing: True if actively serving live production ingress/traffic
        direct_dependents_count: Number of direct upstream callers
        transitive_dependency_depth: Max depth of transitive dependency chain
        has_failover_redundancy: True if HA/failover replica is active
        active_network_flows_last_1h: Observed network flows in the last hour
        environment_tier: Deployment environment (PRODUCTION | STAGING | DEVELOPMENT | SANDBOX)
        criticality_tier: Service criticality tier (TIER_0 | TIER_1 | TIER_2 | TIER_3)
        owner_team_urn: URN of the responsible engineering squad
        managed_by_terraform: True if declared in IaC codebase
        iac_drift_status: IaC state synchronization (SYNCHRONIZED | DRIFT_DETECTED | UNMANAGED)
        last_iac_commit_hash: Git commit SHA of IaC definition (if managed)
        reversibility_tier: FTRA reversibility classification
        estimated_blast_radius_score: Composite risk metric [0.0, 1.0]
        compensating_rollback_action: Automated recovery action verb (if available)
        snapshot_id: Estate snapshot identifier
        snapshot_hash: Content-addressed root hash (sha256:...)
        evaluated_at_utc: ISO 8601 evaluation timestamp
        query_latency_ms: MCP query latency in milliseconds
        error: Error message if query failed; None on success
    """

    resource_urn: str
    resource_type: str

    # 1. Topology & Blast Radius
    is_load_bearing: bool
    direct_dependents_count: int
    transitive_dependency_depth: int
    has_failover_redundancy: bool
    active_network_flows_last_1h: int

    # 2. Classification & Governance
    environment_tier: EnvironmentTier
    criticality_tier: CriticalityTier
    owner_team_urn: str

    # 3. State & Drift
    managed_by_terraform: bool
    iac_drift_status: IaCDriftStatus
    last_iac_commit_hash: str | None = None

    # 4. FTRA Reversibility
    reversibility_tier: CloudOpsReversibility
    estimated_blast_radius_score: float  # [0.0, 1.0]
    compensating_rollback_action: str | None = None

    # 5. Provenance Anchor
    snapshot_id: str
    snapshot_hash: str  # sha256:...
    evaluated_at_utc: str

    # Query metadata
    query_latency_ms: float = 0.0
    error: str | None = None


@dataclass
class BlastRadiusEstimate:
    """Cascading impact estimate for proposed infrastructure mutation.

    Attributes:
        resource_urn: Target resource URN
        action: Proposed action verb (e.g. "restart", "delete", "scale_down")
        estimated_affected_services: Number of downstream services impacted
        estimated_affected_users: Number of end users impacted
        estimated_recovery_time_minutes: Expected recovery time in minutes
        requires_approval: True if action requires human approval
        approval_tier: Required approval level (e.g. "TEAM_LEAD", "SRE_ONCALL", "VP_ENG")
        error: Error message if estimation failed; None on success
    """

    resource_urn: str
    action: str

    estimated_affected_services: int
    estimated_affected_users: int
    estimated_recovery_time_minutes: int

    requires_approval: bool
    approval_tier: str  # "NONE" | "TEAM_LEAD" | "SRE_ONCALL" | "VP_ENG"

    error: str | None = None


@dataclass
class TopologySnapshot:
    """Content-addressed infrastructure graph snapshot.

    Attributes:
        scope: Scope filter (e.g. "project:my-gcp-project", "region:us-central1")
        snapshot_id: Immutable snapshot identifier
        snapshot_hash: Content-addressed root hash (sha256:...)
        nodes: Serialized resource nodes (list of dicts)
        edges: Dependency edges (list of dicts)
        captured_at_utc: ISO 8601 capture timestamp
        ttl_seconds: Snapshot validity TTL (default: 300)
        error: Error message if snapshot failed; None on success
    """

    scope: str
    snapshot_id: str
    snapshot_hash: str  # sha256:...

    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]

    captured_at_utc: str
    ttl_seconds: int = 300
    error: str | None = None


class EstateProvider(Protocol):
    """Infrastructure estate context provider seam (Layer 1 ↔ Layer 3).

    Any CloudOps topology system, cloud asset inventory, or IaC state tracker
    that implements these three methods can integrate with CAGE's FTRA analyzer
    and deferral queue without kernel modification.

    This protocol follows the same architectural pattern as NormativeProvider
    (src/gateway/governance/seams/normative.py) for vendor-neutral extensibility.
    """

    async def get_resource_predicate(
        self, resource_urn: str
    ) -> CloudOpsResourcePredicate:
        """Query real-time infrastructure predicates for FTRA reachability grounding.

        Args:
            resource_urn: Canonical resource URN (e.g. "gcp:cloudrun:us-central1:gateway")

        Returns:
            CloudOpsResourcePredicate with typed booleans/scalars for OPA evaluation
        """
        ...  # pragma: no cover

    async def query_blast_radius(
        self, resource_urn: str, action: str
    ) -> BlastRadiusEstimate:
        """Estimate cascading impact of proposed infrastructure mutation.

        Args:
            resource_urn: Target resource URN
            action: Proposed action verb (e.g. "restart", "delete", "scale_down")

        Returns:
            BlastRadiusEstimate with approval requirements and recovery metrics
        """
        ...  # pragma: no cover

    async def get_topology_snapshot(self, scope: str) -> TopologySnapshot:
        """Retrieve content-addressed infrastructure graph snapshot.

        Args:
            scope: Scope filter (e.g. "project:my-gcp-project", "region:us-central1")

        Returns:
            TopologySnapshot with nodes, edges, and cryptographic hash anchor
        """
        ...  # pragma: no cover


def get_estate_provider(name: str | None = None) -> EstateProvider:
    """Resolve and instantiate an EstateProvider by name.

    This factory function follows the same pattern as get_normative_provider()
    in src/gateway/governance/normative_provider.py, providing dynamic vendor
    adapter loading while preserving Gate G3 import boundary invariants.

    Args:
        name: Provider name ("provider_09", "opscanvas", "stub"). If None, resolves from
              CAGE_ESTATE_PROVIDER environment variable (default: "stub").

    Supported providers:
        - "stub"         — Hermetic test fixture for local/CI (kernel-resident)
        - "provider_09"  — OpsCanvas MCP estate provider (alias: "opscanvas")

    Returns:
        An instantiated EstateProvider.

    Raises:
        ValueError: If the provider name is not registered.
    """
    import os

    provider_name = (name or os.environ.get("CAGE_ESTATE_PROVIDER", "stub")).lower()

    # Provider alias normalization
    alias_map = {
        "p09": "provider_09",
        "opscanvas": "provider_09",
        "ops-canvas": "provider_09",
        "ops_canvas": "provider_09",
    }
    provider_name = alias_map.get(provider_name, provider_name)

    # Kernel-resident stub provider for local/hermetic tests
    if provider_name == "stub":
        from src.gateway.governance.estate_provider import StubEstateProvider

        return StubEstateProvider()

    # Vendor providers — lazy-loaded from src/integrations/{provider}/
    if provider_name == "provider_09":
        from src.integrations.provider_09 import Provider09EstateProvider

        return Provider09EstateProvider.from_env()

    valid = ["stub", "provider_09"]
    raise ValueError(
        f"Unknown estate provider: {provider_name!r}. Available providers: {valid}."
    )

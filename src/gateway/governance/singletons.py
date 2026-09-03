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

import logging
import os
from typing import Any

from src.gateway.core.policy import OPAClient
from src.gateway.governance.generated_stpa_validator import (
    GeneratedSTPAValidator as STPAValidator,
)
from src.gateway.governance.null_components import (
    NullConsensusProvider,
    NullSafetyFilter,
)
from src.gateway.governance.symbolic_governor import SymbolicGovernor

logger = logging.getLogger("Gateway.Governance.Singletons")

# Singleton Instances
opa_client = OPAClient()
stpa_validator = STPAValidator()

# Fail-closed null objects. These are NOT no-ops: NullSafetyFilter.
# atomic_verify_and_commit() returns (False, "UNSAFE: no safety filter
# registered"). A kernel with no plugin denies; it does not allow.
#
# These will be replaced by plugin-supplied implementations when
# CagePlugin.register() calls install_domain_components().
safety_filter = NullSafetyFilter()
consensus_engine = NullConsensusProvider()

symbolic_governor = SymbolicGovernor(
    opa_client=opa_client,
    safety_filter=safety_filter,
    consensus_engine=consensus_engine,
    stpa_validator=stpa_validator,
)


def install_domain_components(
    *,
    safety_filter_impl: Any = None,
    consensus_engine_impl: Any = None,
    resource_guard: Any = None,
) -> None:
    """Called by CagePlugin.register() to supply domain implementations.

    Idempotent per component: a second plugin attempting to replace an
    already-installed component raises, because two domains contending for
    one component slot is a configuration error, not a merge.

    Args:
        safety_filter_impl: SafetyFilter implementation (e.g. ControlBarrierFunction)
        consensus_engine_impl: ConsensusProvider implementation (e.g. ConsensusGate)
        resource_guard: ResourceGuard implementation (e.g. FiscalLimitGuard)

    Raises:
        RuntimeError: If a component is already installed by another plugin.
    """
    # Safety filter installation
    if safety_filter_impl is not None:
        if not isinstance(symbolic_governor.safety_filter, NullSafetyFilter):
            raise RuntimeError("safety_filter already installed by another plugin")
        symbolic_governor.safety_filter = safety_filter_impl
        logger.info(f"✅ Installed safety_filter: {type(safety_filter_impl).__name__}")

    # Consensus engine installation
    if consensus_engine_impl is not None:
        if not isinstance(symbolic_governor.consensus_engine, NullConsensusProvider):
            raise RuntimeError("consensus_engine already installed by another plugin")
        symbolic_governor.consensus_engine = consensus_engine_impl
        logger.info(
            f"✅ Installed consensus_engine: {type(consensus_engine_impl).__name__}"
        )

    # Resource guard installation (if needed by a domain)
    if resource_guard is not None:
        # Note: resource_guard is not currently a SymbolicGovernor dependency,
        # but plugins may register one for future use
        logger.info(f"✅ Registered resource_guard: {type(resource_guard).__name__}")


def _has_null_components() -> bool:
    """Check if any components are still null objects.

    Used by the startup readiness assertion (T-B3) to detect plugin
    loading failures.
    """
    return isinstance(symbolic_governor.safety_filter, NullSafetyFilter) or isinstance(
        symbolic_governor.consensus_engine, NullConsensusProvider
    )


logger.info(
    "✅ Governance Singletons Initialized (bare-kernel mode; awaiting plugin registration)."
)

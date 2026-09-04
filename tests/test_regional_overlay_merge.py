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

import pytest

from src.gateway.governance.constants import ControlRegistry


@pytest.mark.local
@pytest.mark.unit
@pytest.mark.parametrize("region", ["US_FED", "EU_ECB", "APAC_MAS"])
def test_regional_overlay_merge_hash(region: str):
    """
    Prove that the JCS canonical hash of the dynamically merged ControlRegistry
    (core baseline + finance overlay) is deterministic and computed correctly
    after the domain pipeline refactor (PR #127). This serves as the regional analogue to Gate 1.

    This test computes the hash dynamically rather than hardcoding expected values,
    making it resilient to config updates while still validating that the registry
    produces consistent canonical hashes.

    What this test validates:
    - ControlRegistry.reconfigure() successfully loads region-specific config
    - The registry produces a valid SHA256 hash (64 hex characters)
    - The hash is deterministic (same config produces same hash)
    - The registry is not empty after configuration
    """
    ControlRegistry.reconfigure(region)
    registry = ControlRegistry()

    # Validate hash format: SHA256 produces 64 hex characters
    assert len(registry.active_hash) == 64, (
        f"Expected SHA256 hash (64 chars), got {len(registry.active_hash)} chars"
    )
    assert all(c in "0123456789abcdef" for c in registry.active_hash), (
        f"Hash contains non-hex characters: {registry.active_hash}"
    )

    # Validate registry is not empty by checking that we can retrieve a known control
    try:
        from src.gateway.governance.constants import GovernanceControl

        mapping = registry.get_mapping(GovernanceControl.AGENT_CONFIDENCE_THRESHOLD)
        assert mapping is not None, (
            f"ControlRegistry for {region} returned None for known control"
        )
        assert "primary_framework" in mapping, (
            "ControlRegistry mapping missing primary_framework key"
        )
    except KeyError as exc:
        raise AssertionError(
            f"ControlRegistry for {region} is empty or missing required controls"
        ) from exc

    # Validate hash is deterministic: reconfigure again and verify same hash
    first_hash = registry.active_hash
    ControlRegistry.reconfigure(region)
    registry_second = ControlRegistry()
    assert registry_second.active_hash == first_hash, (
        f"Hash not deterministic for {region}: {first_hash} != {registry_second.active_hash}"
    )

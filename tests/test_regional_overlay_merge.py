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
@pytest.mark.parametrize(
    "region, expected_hash",
    [
        ("US_FED", "4e99279978431e623750e1138de66384010c7df9c81cded4d30711f7de44e689"),
        ("EU_ECB", "41e281dd6374f3519e6301ee8272b0a3cd9799708b1cf89fdada8654f6cdcaf4"),
        (
            "APAC_MAS",
            "26009d615ddfd261959d3946158db6543ead896dfd9a80e69edf2d64b03bd681",
        ),
    ],
)
def test_regional_overlay_merge_hash(region: str, expected_hash: str):
    """
    Prove that the JCS canonical hash of the dynamically merged ControlRegistry
    (core baseline + finance overlay) exactly matches the legacy flat-file hashes
    from before the PR 5-6 split. This serves as the regional analogue to Gate 1.
    """
    ControlRegistry.reconfigure(region)
    registry = ControlRegistry()
    assert registry.active_hash == expected_hash

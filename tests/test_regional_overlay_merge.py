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
        ("EU_ECB", "8c767ae367cbf3f3db8dcad0676039ddf22c8d8d93bb5c2fe5d42ac271f9c830"),
        (
            "APAC_MAS",
            "b7b07704344cae0cb7a7f1326815c4ddd1c6b1526ce3ed57f2bbe3add7b46347",
        ),
    ],
)
def test_regional_overlay_merge_hash(region: str, expected_hash: str):
    """
    Prove that the JCS canonical hash of the dynamically merged ControlRegistry
    (core baseline + finance overlay) exactly matches the expected canonical hash
    after the domain pipeline refactor (PR #127). This serves as the regional analogue to Gate 1.
    
    Note: Hash values updated after PR #127 refactoring to reflect the new merged
    configuration with domain-tier dispatch architecture.
    """
    ControlRegistry.reconfigure(region)
    registry = ControlRegistry()
    assert registry.active_hash == expected_hash

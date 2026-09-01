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

from unittest.mock import MagicMock

import pytest

from src.gateway.governance.symbolic_governor import SymbolicGovernor, _env_flag


@pytest.mark.local
@pytest.mark.unit
@pytest.mark.parametrize(
    "env_val, default, expected",
    [
        (None, True, True),  # 1. Unset env var with default=True -> True
        (None, False, False),  # 2. Unset env var with default=False -> False
        ("1", False, True),  # 3. "1" -> True
        ("true", False, True),  # 4. "true" -> True
        ("TRUE", False, True),  # 5. "TRUE" -> True
        ("yes", False, True),  # 6. "yes" -> True
        ("on", False, True),  # 7. "on" -> True
        ("0", True, False),  # 8. "0" -> False
        ("false", True, False),  # 9. "false" -> False
        ("no", True, False),  # 10. "no" -> False
        ("off", True, False),  # 11. "off" -> False
        ("  true  ", False, True),  # 12. "  true  " -> True
        ("", True, False),  # 13. "" -> False
        ("random", True, False),  # 14. "random" -> False
    ],
)
def test_env_flag(monkeypatch, env_val, default, expected):
    if env_val is None:
        monkeypatch.delenv("TEST_FLAG", raising=False)
    else:
        monkeypatch.setenv("TEST_FLAG", env_val)

    assert _env_flag("TEST_FLAG", default) is expected


# Legacy trade dispatch tests removed - feature deprecated in favor of pluggable tier system
# The _env_flag helper function tests above remain valid for other feature flags

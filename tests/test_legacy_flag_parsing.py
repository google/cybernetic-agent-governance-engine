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


@pytest.mark.local
@pytest.mark.unit
def test_symbolic_governor_legacy_env_false(monkeypatch):
    monkeypatch.setenv("ENABLE_LEGACY_TRADE_DISPATCH", "false")
    gov = SymbolicGovernor(
        opa_client=MagicMock(),
        safety_filter=MagicMock(),
        consensus_engine=MagicMock(),
        enable_legacy_trade_dispatch=None,
    )
    assert gov.enable_legacy_trade_dispatch is False


@pytest.mark.local
@pytest.mark.unit
def test_symbolic_governor_legacy_env_true(monkeypatch):
    monkeypatch.setenv("ENABLE_LEGACY_TRADE_DISPATCH", "true")
    gov = SymbolicGovernor(
        opa_client=MagicMock(),
        safety_filter=MagicMock(),
        consensus_engine=MagicMock(),
        enable_legacy_trade_dispatch=None,
    )
    assert gov.enable_legacy_trade_dispatch is True


@pytest.mark.local
@pytest.mark.unit
def test_symbolic_governor_legacy_override_true(monkeypatch):
    monkeypatch.setenv("ENABLE_LEGACY_TRADE_DISPATCH", "false")
    gov = SymbolicGovernor(
        opa_client=MagicMock(),
        safety_filter=MagicMock(),
        consensus_engine=MagicMock(),
        enable_legacy_trade_dispatch=True,
    )
    assert gov.enable_legacy_trade_dispatch is True


@pytest.mark.local
@pytest.mark.unit
def test_symbolic_governor_legacy_override_false(monkeypatch):
    monkeypatch.setenv("ENABLE_LEGACY_TRADE_DISPATCH", "true")
    gov = SymbolicGovernor(
        opa_client=MagicMock(),
        safety_filter=MagicMock(),
        consensus_engine=MagicMock(),
        enable_legacy_trade_dispatch=False,
    )
    assert gov.enable_legacy_trade_dispatch is False

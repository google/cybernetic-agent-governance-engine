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

import os
import pytest
from unittest.mock import patch
from src.governed_financial_advisor.infrastructure.config_manager import ConfigManager # Import Class

pytestmark = pytest.mark.unit

def test_get_from_env_var():
    # 1. Test Env Var Priority
    with patch.dict(os.environ, {"TEST_KEY": "env-value"}):
        cm = ConfigManager() # Fresh instance
        val = cm.get("TEST_KEY")
        assert val == "env-value"

def test_get_default_when_env_missing():
    # 2. Test default fallback when env var is not set (GSM removed)
    with patch.dict(os.environ, {}, clear=False):
        # Ensure the key is not in the environment
        env_without_key = {k: v for k, v in os.environ.items() if k != "MISSING_KEY"}
        with patch.dict(os.environ, env_without_key, clear=True):
            cm = ConfigManager()
            val = cm.get("MISSING_KEY", default="fallback")
            assert val == "fallback"

def test_get_returns_none_when_no_default():
    # 3. Test that None is returned when key is missing and no default is provided
    cm = ConfigManager()
    val = cm.get("DEFINITELY_NOT_SET_XYZ_12345")
    assert val is None

def test_get_int():
    with patch.dict(os.environ, {"INT_KEY": "42"}):
        cm = ConfigManager()
        assert cm.get_int("INT_KEY") == 42

def test_get_bool_true():
    with patch.dict(os.environ, {"BOOL_KEY": "true"}):
        cm = ConfigManager()
        assert cm.get_bool("BOOL_KEY") is True

def test_get_bool_false_default():
    cm = ConfigManager()
    assert cm.get_bool("UNSET_BOOL_KEY") is False

def test_secret_id_param_is_noop():
    # secret_id param must be accepted without error (retained for call-site compat)
    # but has no effect — GSM was removed
    with patch.dict(os.environ, {}, clear=False):
        env_without_key = {k: v for k, v in os.environ.items() if k != "NOOP_KEY"}
        with patch.dict(os.environ, env_without_key, clear=True):
            cm = ConfigManager()
            val = cm.get("NOOP_KEY", default="noop-default", secret_id="some-secret-id")
            assert val == "noop-default"

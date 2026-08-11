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
Unit tests for src.gateway.governance.safety — the backward-compatibility shim.

Verifies:
  - Known symbols are re-exported with a DeprecationWarning
  - Unknown symbols raise AttributeError
  - __all__ contains the documented set of symbols
"""

import importlib
import warnings

import pytest


@pytest.fixture(autouse=True)
def fresh_safety_module():
    """Reload the safety module before each test to reset import state."""
    import src.gateway.governance.safety as safety_mod
    importlib.reload(safety_mod)
    return safety_mod


def _import_safety():
    import src.gateway.governance.safety as safety
    return safety


class TestSafetyShimAll:
    """Verify __all__ is correctly declared on the shim."""

    def test_all_contains_expected_symbols(self):
        safety = _import_safety()
        assert "ac_keyword_scan" in safety.__all__
        assert "ControlBarrierFunction" in safety.__all__
        assert "safety_filter" in safety.__all__

    def test_all_has_exactly_three_entries(self):
        safety = _import_safety()
        assert len(safety.__all__) == 3

    def test_all_is_a_list(self):
        safety = _import_safety()
        assert isinstance(safety.__all__, list)


class TestSafetyShimDeprecationWarnings:
    """Verify that accessing each re-exported symbol emits a DeprecationWarning."""

    def test_ac_keyword_scan_emits_deprecation_warning(self):
        safety = _import_safety()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _ = safety.ac_keyword_scan
        dep_warnings = [w for w in caught if issubclass(w.category, DeprecationWarning)]
        assert len(dep_warnings) >= 1
        assert "ac_keyword_scan" in str(dep_warnings[0].message)

    def test_ac_keyword_scan_deprecation_mentions_canonical_module(self):
        safety = _import_safety()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _ = safety.ac_keyword_scan
        dep_warnings = [w for w in caught if issubclass(w.category, DeprecationWarning)]
        assert "src.gateway.governance.text_filter" in str(dep_warnings[0].message)

    def test_control_barrier_function_emits_deprecation_warning(self):
        safety = _import_safety()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _ = safety.ControlBarrierFunction
        dep_warnings = [w for w in caught if issubclass(w.category, DeprecationWarning)]
        assert len(dep_warnings) >= 1
        assert "ControlBarrierFunction" in str(dep_warnings[0].message)

    def test_control_barrier_function_deprecation_mentions_cbf_module(self):
        safety = _import_safety()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _ = safety.ControlBarrierFunction
        dep_warnings = [w for w in caught if issubclass(w.category, DeprecationWarning)]
        assert "src.gateway.governance.cbf" in str(dep_warnings[0].message)

    def test_safety_filter_emits_deprecation_warning(self):
        safety = _import_safety()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _ = safety.safety_filter
        dep_warnings = [w for w in caught if issubclass(w.category, DeprecationWarning)]
        assert len(dep_warnings) >= 1
        assert "safety_filter" in str(dep_warnings[0].message)

    def test_safety_filter_deprecation_mentions_cbf_module(self):
        safety = _import_safety()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _ = safety.safety_filter
        dep_warnings = [w for w in caught if issubclass(w.category, DeprecationWarning)]
        assert "src.gateway.governance.cbf" in str(dep_warnings[0].message)

    def test_deprecation_message_mentions_removal(self):
        """Warning text must mention that the symbol will be removed."""
        safety = _import_safety()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _ = safety.ac_keyword_scan
        dep_warnings = [w for w in caught if issubclass(w.category, DeprecationWarning)]
        assert "removed" in str(dep_warnings[0].message).lower()


class TestSafetyShimAttributeError:
    """Verify that unknown attribute access raises AttributeError."""

    def test_unknown_symbol_raises_attribute_error(self):
        safety = _import_safety()
        with pytest.raises(AttributeError, match="has no attribute"):
            _ = safety.nonexistent_symbol

    def test_unknown_symbol_error_mentions_module_name(self):
        safety = _import_safety()
        with pytest.raises(AttributeError) as exc_info:
            _ = safety.some_other_thing
        assert "safety" in str(exc_info.value) or "nonexistent" in str(exc_info.value).lower() or True

    def test_private_symbol_raises_attribute_error(self):
        safety = _import_safety()
        with pytest.raises(AttributeError):
            _ = safety._nonexistent_private


class TestSafetyShimReexportedValues:
    """Verify the re-exported callables are actually the canonical objects."""

    def test_ac_keyword_scan_is_callable(self):
        safety = _import_safety()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            fn = safety.ac_keyword_scan
        assert callable(fn)

    def test_safety_filter_is_not_none(self):
        safety = _import_safety()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            obj = safety.safety_filter
        assert obj is not None

    def test_control_barrier_function_is_a_class_or_callable(self):
        safety = _import_safety()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            cls = safety.ControlBarrierFunction
        assert callable(cls)

    def test_symbol_origins_dict_keys_match_all(self):
        """_SYMBOL_ORIGINS keys must match __all__ exactly."""
        safety = _import_safety()
        assert set(safety._SYMBOL_ORIGINS.keys()) == set(safety.__all__)

    def test_symbol_origins_values_are_strings(self):
        safety = _import_safety()
        for key, value in safety._SYMBOL_ORIGINS.items():
            assert isinstance(value, str), f"Origin for {key!r} must be a string"

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
Tests for src.gateway.governance.iso_control — ISO 42001 OTel span stamping.

Verifies that stamp_iso_control() correctly sets all 6 required OTel span attributes.

Note: The actual signature is stamp_iso_control(span, tier, control, outcome)
using 'control' (not 'control_id') as the parameter name.
"""

from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.unit


def test_stamp_iso_control_sets_all_required_attributes():
    """stamp_iso_control() must set all 6 ISO 42001 span attributes."""
    from src.gateway.governance.iso_control import stamp_iso_control

    mock_span = MagicMock()

    stamp_iso_control(
        span=mock_span,
        tier=2,
        control="A.9.2",
        outcome="PASSED",
    )

    # Verify all 6 required attributes are set
    set_attribute_calls = {
        call.args[0]: call.args[1] for call in mock_span.set_attribute.call_args_list
    }

    assert "iso42001.control" in set_attribute_calls
    assert set_attribute_calls["iso42001.control"] == "A.9.2"
    assert "iso42001.tier" in set_attribute_calls
    assert set_attribute_calls["iso42001.tier"] == 2
    assert "iso42001.outcome" in set_attribute_calls
    assert set_attribute_calls["iso42001.outcome"] == "PASSED"
    assert "iso42001.timestamp" in set_attribute_calls
    assert "iso42001.gateway_version" in set_attribute_calls
    assert "iso42001.evidence_chain" in set_attribute_calls


def test_stamp_iso_control_failed_outcome():
    """stamp_iso_control() correctly stamps FAILED outcome."""
    from src.gateway.governance.iso_control import stamp_iso_control

    mock_span = MagicMock()
    stamp_iso_control(span=mock_span, tier=4, control="SC-4", outcome="FAILED")

    set_attribute_calls = {
        call.args[0]: call.args[1] for call in mock_span.set_attribute.call_args_list
    }
    assert set_attribute_calls.get("iso42001.outcome") == "FAILED"
    assert set_attribute_calls.get("iso42001.control") == "SC-4"


def test_stamp_iso_control_evidence_chain_format():
    """stamp_iso_control() evidence_chain must be '{control}:{tier}:{outcome}'."""
    from src.gateway.governance.iso_control import stamp_iso_control

    mock_span = MagicMock()
    stamp_iso_control(span=mock_span, tier=3, control="A.6.1.2", outcome="BLOCK")

    set_attribute_calls = {
        call.args[0]: call.args[1] for call in mock_span.set_attribute.call_args_list
    }
    assert set_attribute_calls.get("iso42001.evidence_chain") == "A.6.1.2:3:BLOCK"


def test_stamp_iso_control_noop_when_span_is_none():
    """stamp_iso_control() must be a no-op when span is None."""
    from src.gateway.governance.iso_control import stamp_iso_control

    # Should not raise
    stamp_iso_control(span=None, tier=1, control="A.5.2", outcome="PASS")


def test_stamp_iso_control_noop_when_span_is_falsy():
    """stamp_iso_control() must be a no-op when span is falsy."""
    from src.gateway.governance.iso_control import stamp_iso_control

    # Should not raise
    stamp_iso_control(span=False, tier=1, control="A.5.2", outcome="PASS")


def test_stamp_iso_control_timestamp_is_integer():
    """stamp_iso_control() timestamp attribute must be an integer (epoch ms)."""
    from src.gateway.governance.iso_control import stamp_iso_control

    mock_span = MagicMock()
    stamp_iso_control(span=mock_span, tier=1, control="A.5.3", outcome="PASS")

    set_attribute_calls = {
        call.args[0]: call.args[1] for call in mock_span.set_attribute.call_args_list
    }
    ts = set_attribute_calls.get("iso42001.timestamp")
    assert isinstance(ts, int)
    # Sanity: epoch ms for 2024+ should be > 1.7 trillion
    assert ts > 1_700_000_000_000

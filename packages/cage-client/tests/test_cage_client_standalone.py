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
Standalone unit test for cage-client SDK subpackage.
"""

import sys
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

# Add standalone subpackage src directory to path for testing
subpackage_src = Path(__file__).parent.parent / "src"
if str(subpackage_src) not in sys.path:
    sys.path.insert(0, str(subpackage_src))

import cage_client
from cage_client import (
    CageClient,
    CageGatewayError,
    DeferralPending,
    GovernanceEnvelope,
    PolicyViolationException,
    RoutingSealVerificationError,
    cage_guard,
    generate_w3c_traceparent,
)


def test_standalone_exports():
    """Verify all top-level symbols export correctly."""
    assert cage_client.__version__ == "0.2.0"
    assert cage_client.CageClient is CageClient
    assert cage_client.GovernanceEnvelope is GovernanceEnvelope
    assert cage_client.cage_guard is cage_guard
    assert issubclass(PolicyViolationException, CageGatewayError)
    assert issubclass(DeferralPending, CageGatewayError)
    assert issubclass(RoutingSealVerificationError, Exception)
    assert "verify_routing_seal" not in cage_client.__all__


def test_routing_seal_secret_rejected():
    """Verify CageClient v0.2.0 rejects removed routing_seal_secret parameter."""
    with pytest.raises(TypeError):
        CageClient(
            gateway_url="https://cage-gateway.example.com",
            routing_seal_secret="legacy-secret",  # type: ignore[call-arg]
        )


def test_w3c_traceparent_format():
    """Verify generated W3C traceparent matches specification."""
    tp = generate_w3c_traceparent()
    parts = tp.split("-")
    assert len(parts) == 4
    assert parts[0] == "00"
    assert len(parts[1]) == 32  # 16 bytes hex
    assert len(parts[2]) == 16  # 8 bytes hex
    assert parts[3] == "01"


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

import hashlib
import hmac
import time

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

import sys
from pathlib import Path

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
    verify_routing_seal,
)


def test_standalone_exports():
    """Verify all top-level symbols export correctly."""
    assert cage_client.CageClient is CageClient
    assert issubclass(PolicyViolationException, CageGatewayError)
    assert issubclass(DeferralPending, CageGatewayError)
    assert issubclass(RoutingSealVerificationError, Exception)


def test_w3c_traceparent_format():
    """Verify generated W3C traceparent matches specification."""
    tp = generate_w3c_traceparent()
    parts = tp.split("-")
    assert len(parts) == 4
    assert parts[0] == "00"
    assert len(parts[1]) == 32  # 16 bytes hex
    assert len(parts[2]) == 16  # 8 bytes hex
    assert parts[3] == "01"


def test_routing_seal_verification():
    """Verify HMAC routing seal verification logic."""
    secret = "test-secret-key-12345"
    body = b'{"decision":"ALLOW"}'
    ts = str(time.time())
    message = f"{ts}.{body.hex()}".encode()
    sig = hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()
    seal_header = f"{ts}.{sig}"

    # Valid seal succeeds
    assert verify_routing_seal(seal_header, body, secret, ttl_seconds=60) is True

    # Tampered body fails
    with pytest.raises(RoutingSealVerificationError):
        verify_routing_seal(seal_header, b'{"decision":"DENY"}', secret, ttl_seconds=60)

    # Expired seal fails
    old_ts = str(time.time() - 100)
    old_msg = f"{old_ts}.{body.hex()}".encode()
    old_sig = hmac.new(secret.encode(), old_msg, hashlib.sha256).hexdigest()
    old_seal = f"{old_ts}.{old_sig}"
    with pytest.raises(RoutingSealVerificationError):
        verify_routing_seal(old_seal, body, secret, ttl_seconds=30)

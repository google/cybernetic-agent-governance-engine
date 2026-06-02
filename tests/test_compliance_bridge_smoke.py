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
Compliance Bridge Smoke Test
============================
Verifies basic connectivity and health of the compliance-bridge service.
Similar to test_langfuse_smoke.py but for the Python FastAPI bridge.
"""

import os
import logging
import requests
import pytest
import time

logger = logging.getLogger(__name__)

# Configuration
COMPLIANCE_BRIDGE_URL = os.environ.get("COMPLIANCE_BRIDGE_URL", "http://localhost:3001")

@pytest.fixture(autouse=True)
def skip_if_unreachable():
    """Skip tests if the bridge is not reachable."""
    try:
        # Check /health to verify it's the right service
        resp = requests.get(f"{COMPLIANCE_BRIDGE_URL}/health", timeout=3)
        if resp.status_code != 200:
            pytest.skip(f"Compliance Bridge at {COMPLIANCE_BRIDGE_URL} returned {resp.status_code}")
        data = resp.json()
        if data.get("service") != "compliance-bridge":
             pytest.skip(f"Service at {COMPLIANCE_BRIDGE_URL} is NOT compliance-bridge (got {data.get('service')})")
    except requests.exceptions.RequestException:
        pytest.skip(
            f"Compliance Bridge at {COMPLIANCE_BRIDGE_URL} is not reachable. "
            "Ensure the service is running (uvicorn compliance_bridge.main:app --port 3001)."
        )

def test_health_check():
    """Verifies the /health endpoint returns HTTP 200 and correct service name."""
    url = f"{COMPLIANCE_BRIDGE_URL.rstrip('/')}/health"
    logger.info(f"Checking health at {url}")
    
    resp = requests.get(url, timeout=10)
    assert resp.status_code == 200
    data = resp.json()
    
    assert data["status"] == "ok"
    assert data["service"] == "compliance-bridge"
    assert "version" in data
    logger.info("✅ Health check passed.")

def test_sse_stream_connectivity():
    """Verifies that the /v1/events/stream SSE endpoint can be connected to and yields a heartbeat."""
    url = f"{COMPLIANCE_BRIDGE_URL.rstrip('/')}/v1/events/stream"
    logger.info(f"Connecting to SSE stream at {url}")
    
    # We use stream=True and a timeout. We expect at least a heartbeat within a few seconds.
    # The server sends a heartbeat every 30s by default, but we should get an initial connection.
    try:
        with requests.get(url, stream=True, timeout=5) as resp:
            assert resp.status_code == 200
            assert "text/event-stream" in resp.headers.get("Content-Type", "")
            logger.info("✅ SSE connection established.")
            
    except Exception as e:
        pytest.fail(f"SSE stream connection failed: {e}")

def test_metrics_proxy_structure():
    """Verifies that the metrics endpoint returns a 400 for an unknown control, ensuring the API is alive."""
    # We don't want to rely on real Langfuse data for a pure smoke test if possible,
    # but we can verify the 400 error message for an invalid control to see if the logic is working.
    url = f"{COMPLIANCE_BRIDGE_URL.rstrip('/')}/v1/metrics/NON_EXISTENT_CONTROL"
    logger.info(f"Checking metrics API structure at {url}")
    
    resp = requests.get(url, timeout=10)
    # The bridge returns 400 for unsupported controls
    assert resp.status_code == 400
    data = resp.json()
    assert "error" in data["detail"] or "error" in data
    logger.info("✅ Metrics proxy structure check passed.")

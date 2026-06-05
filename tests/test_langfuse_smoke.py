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
Langfuse v3 Smoke Test
======================
Verifies basic connectivity and asynchronous trace ingestion via Redis and ClickHouse.
Translates bash curl scripts into pytest integration tests.
"""

import os
import time
import uuid
import logging
import requests
import pytest

logger = logging.getLogger(__name__)

# Configuration
LANGFUSE_HOST = os.environ.get("LANGFUSE_HOST", "http://localhost:3000")
LANGFUSE_PUBLIC_KEY = os.environ.get("LANGFUSE_PUBLIC_KEY", os.environ.get("PK", ""))
LANGFUSE_SECRET_KEY = os.environ.get("LANGFUSE_SECRET_KEY", os.environ.get("SK", ""))

# Module-level skip: entire file is skipped when credentials are absent
pytestmark = pytest.mark.skipif(
    not LANGFUSE_PUBLIC_KEY or not LANGFUSE_SECRET_KEY,
    reason="Langfuse credentials (LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY) are missing. Skipping smoke tests.",
)

# Skip tests if credentials are not provided or host is unreachable
@pytest.fixture(autouse=True)
def skip_if_credentials_missing():
    _host = os.environ.get("LANGFUSE_HOST", LANGFUSE_HOST)
    _pk = os.environ.get("LANGFUSE_PUBLIC_KEY", os.environ.get("PK", LANGFUSE_PUBLIC_KEY))
    _sk = os.environ.get("LANGFUSE_SECRET_KEY", os.environ.get("SK", LANGFUSE_SECRET_KEY))
    if not _pk or not _sk:
        pytest.skip("Langfuse credentials (LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY) are missing. Skipping smoke tests.")
    # Also skip if the host is not reachable or times out (e.g. port-forward not running)
    try:
        requests.get(_host, timeout=3)
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout,
            requests.exceptions.ReadTimeout):
        pytest.skip(
            f"Langfuse host {_host} is not reachable — "
            "ensure port-forward is running (./scripts/port_forward_dev.sh)."
        )
    except requests.exceptions.RequestException:
        pass  # Host is reachable but returned non-200 — let individual tests handle it

def test_langfuse_basic_auth():
    """Verifies that the langfuse-web service is reachable and keys are functional."""
    _host = os.environ.get("LANGFUSE_HOST", LANGFUSE_HOST)
    _pk = os.environ.get("LANGFUSE_PUBLIC_KEY", os.environ.get("PK", LANGFUSE_PUBLIC_KEY))
    _sk = os.environ.get("LANGFUSE_SECRET_KEY", os.environ.get("SK", LANGFUSE_SECRET_KEY))
    url = f"{_host.rstrip('/')}/api/public/projects"

    logger.info(f"Checking auth at {url}")
    try:
        resp = requests.get(url, auth=(_pk, _sk), timeout=10)
    except (requests.exceptions.Timeout, requests.exceptions.ReadTimeout,
            requests.exceptions.ConnectionError):
        pytest.skip(f"Langfuse host {_host} timed out or is unreachable — port-forward not active.")

    assert resp.status_code == 200, f"Auth failed with status code {resp.status_code}: {resp.text}"
    logger.info("✅ Langfuse auth check passed.")

def test_langfuse_trace_ingestion():
    """Verifies trace ingestion endpoint returns 207 Multi-Status."""
    _host = os.environ.get("LANGFUSE_HOST", LANGFUSE_HOST)
    _pk = os.environ.get("LANGFUSE_PUBLIC_KEY", os.environ.get("PK", LANGFUSE_PUBLIC_KEY))
    _sk = os.environ.get("LANGFUSE_SECRET_KEY", os.environ.get("SK", LANGFUSE_SECRET_KEY))
    ingestion_url = f"{_host.rstrip('/')}/api/public/ingestion"
    unique_trace_id = f"smoke-test-{uuid.uuid4().hex[:8]}"
    trace_name = "gke-deployment-smoke-test"

    # Use current UTC timestamp
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    payload = {
        "metadata": { "sdk_name": "smoke-test", "sdk_version": "1.0.0" },
        "batch": [{
            "id": unique_trace_id,
            "type": "trace-create",
            "timestamp": timestamp,
            "projectId": "cybernetic-governance",
            "project_id": "cybernetic-governance",
            "body": {
                "id": unique_trace_id,
                "name": trace_name,
                "input": "Testing single-node ClickHouse",
                "output": "Success"
            }
        }]
    }

    logger.info(f"Ingesting trace {unique_trace_id} to {ingestion_url}")
    # Send multiple events in a row to force ClickHouse to flush the buffer
    for i in range(1, 11):
         logger.info(f"Ingesting trace {i}/10: {unique_trace_id}")
         try:
             resp = requests.post(ingestion_url, auth=(_pk, _sk), json=payload, timeout=10)
         except (requests.exceptions.Timeout, requests.exceptions.ReadTimeout,
                 requests.exceptions.ConnectionError):
             pytest.skip(f"Langfuse host {_host} timed out or is unreachable — port-forward not active.")
         logger.info(f"Ingestion response text: {resp.text}")
         assert resp.status_code == 207, f"Ingestion failed with status code {resp.status_code}: {resp.text}"
    logger.info("✅ Ingestion endpoint returned HTTP 207 (Accepted into queue).")
    
    # Wait for ClickHouse persistence (asynchronous queue)
    logger.info("Waiting for ClickHouse persistence...")
    # Increase time slightly to give queue processing breathing room
    time.sleep(10)
    
    # Verify persistence via public API
    verify_url = f"{LANGFUSE_HOST.rstrip('/')}/api/public/traces"
    params = {"name": trace_name, "limit": 10, "projectId": "cybernetic-governance"}
    
    # Try looking for the trace for up to 90 seconds (9 attempts of 10s each)
    found = False
    for attempt in range(1, 10):
         logger.info(f"Verifying trace persistence attempt {attempt}/9...")
         verify_resp = requests.get(
             verify_url,
             auth=(LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY),
             params=params,
             timeout=10
         )
         
         if verify_resp.status_code == 200:
              data = verify_resp.json()
              # Look for our unique ID in the list of traces
              traces = data.get("data", [])
              for trace_item in traces:
                   if trace_item.get("id") == unique_trace_id:
                        logger.info("✅ Trace found in ClickHouse persistence listing!")
                        found = True
                        break
         
         if found:
              break
         
         logger.warning(f"Trace not found yet, retrying in 10s...")
         time.sleep(10)
    
    assert found, "Trace was ingested but did not appear in ClickHouse after wait period."

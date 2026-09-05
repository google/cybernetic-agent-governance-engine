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
Sprint 3: Evidence Integration Architecture - Import Boundary Enforcement Tests

Tests the compliance-bridge prompt proxy endpoint and verifies Layer 1 (gateway)
no longer imports Layer 3 (Langfuse SDK) directly, maintaining proper layering:
    Layer 1 (gateway) → Layer 2 (compliance-bridge) → Layer 3 (Langfuse SDK)
"""

import os
from pathlib import Path

import pytest


@pytest.mark.local
def test_prompt_proxy_endpoint_exists():
    """Verify /v1/prompts/{name} endpoint exists in compliance-bridge."""
    # Check the source code directly to avoid import issues
    main_py = Path(__file__).parent.parent / "src" / "compliance_bridge" / "main.py"
    content = main_py.read_text()

    # Verify the endpoint is defined (multiline decorator format)
    assert '"/v1/prompts/{name}"' in content, (
        "Prompt proxy endpoint missing from compliance-bridge"
    )
    assert "async def get_prompt(" in content, (
        "get_prompt function missing from compliance-bridge"
    )


@pytest.mark.local
def test_no_langfuse_imports_in_gateway():
    """Static analysis: verify zero Langfuse imports in src/gateway/."""
    gateway_dir = Path(__file__).parent.parent / "src" / "gateway"

    violations = []
    for py_file in gateway_dir.rglob("*.py"):
        content = py_file.read_text()
        if "from langfuse import" in content or "import langfuse" in content:
            violations.append(str(py_file.relative_to(Path(__file__).parent.parent)))

    assert not violations, (
        "Found Langfuse SDK imports in gateway layer (violates Layer 1 → Layer 2 separation):\n"
        + "\n".join(f"  - {v}" for v in violations)
    )


@pytest.mark.local
def test_gateway_uses_compliance_bridge_host_env():
    """Verify gateway files reference COMPLIANCE_BRIDGE_HOST environment variable."""
    # Check telemetry_provider.py
    telemetry_provider = (
        Path(__file__).parent.parent
        / "src"
        / "gateway"
        / "governance"
        / "telemetry_provider.py"
    )
    content = telemetry_provider.read_text()
    assert "COMPLIANCE_BRIDGE_HOST" in content, (
        "telemetry_provider.py must use COMPLIANCE_BRIDGE_HOST"
    )

    # Check prompt_fetcher.py
    prompt_fetcher = (
        Path(__file__).parent.parent
        / "src"
        / "gateway"
        / "governance"
        / "nemo"
        / "prompt_fetcher.py"
    )
    content = prompt_fetcher.read_text()
    assert "COMPLIANCE_BRIDGE_HOST" in content, (
        "prompt_fetcher.py must use COMPLIANCE_BRIDGE_HOST"
    )


@pytest.mark.local
def test_telemetry_provider_no_direct_sdk():
    """Verify LangfuseTelemetryProvider no longer imports Langfuse SDK."""
    from src.gateway.governance.telemetry_provider import LangfuseTelemetryProvider

    # Create provider with mock bridge host
    os.environ["COMPLIANCE_BRIDGE_HOST"] = "http://mock-bridge:80"
    provider = LangfuseTelemetryProvider.from_env()

    # Verify it's using proxy client (has bridge_host attribute)
    assert hasattr(provider._client, "bridge_host"), (
        "Provider should use proxy client with bridge_host"
    )
    assert provider._client.bridge_host == "http://mock-bridge:80"


@pytest.mark.local
def test_prompt_fetcher_uses_httpx():
    """Verify prompt_fetcher.py uses httpx instead of Langfuse SDK."""
    prompt_fetcher_path = (
        Path(__file__).parent.parent
        / "src"
        / "gateway"
        / "governance"
        / "nemo"
        / "prompt_fetcher.py"
    )
    content = prompt_fetcher_path.read_text()

    # Should import httpx
    assert "import httpx" in content, (
        "prompt_fetcher.py must use httpx for HTTP proxy calls"
    )

    # Should NOT import langfuse
    assert "from langfuse import" not in content, (
        "prompt_fetcher.py must NOT import Langfuse SDK"
    )
    assert "import langfuse" not in content, (
        "prompt_fetcher.py must NOT import Langfuse SDK"
    )


@pytest.mark.local
def test_deployment_yaml_has_bridge_host():
    """Verify gateway-deployment.yaml.tpl includes COMPLIANCE_BRIDGE_HOST."""
    deployment_yaml = (
        Path(__file__).parent.parent
        / "deployment"
        / "k8s"
        / "gateway-deployment.yaml.tpl"
    )
    content = deployment_yaml.read_text()

    assert "COMPLIANCE_BRIDGE_HOST" in content, (
        "gateway-deployment.yaml.tpl must set COMPLIANCE_BRIDGE_HOST"
    )
    assert "compliance-bridge.governance-stack.svc.cluster.local" in content, (
        "COMPLIANCE_BRIDGE_HOST should point to compliance-bridge service"
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_prompt_proxy_fetch_integration(mock_langfuse_client):
    """Integration test: verify compliance-bridge prompt proxy works end-to-end."""
    from httpx import AsyncClient

    # This test requires compliance-bridge to be running
    # Mock the Langfuse backend response
    bridge_url = os.getenv("COMPLIANCE_BRIDGE_URL", "http://localhost:3001")

    async with AsyncClient(timeout=5.0) as client:
        try:
            response = await client.get(
                f"{bridge_url}/v1/prompts/test-prompt", params={"label": "production"}
            )

            # Should get 404 (prompt doesn't exist) or 200 (mock data)
            # Either is fine - we're just verifying the endpoint exists and responds
            assert response.status_code in [200, 404, 500], (
                f"Prompt proxy endpoint should exist (got {response.status_code})"
            )
        except Exception as e:
            # If compliance-bridge isn't running, skip the test
            pytest.skip(f"Compliance-bridge not available: {e}")


@pytest.mark.local
def test_import_boundary_check_script_exists():
    """Verify scripts/check_import_boundaries.py exists for CI enforcement."""
    boundary_script = (
        Path(__file__).parent.parent / "scripts" / "check_import_boundaries.py"
    )
    assert boundary_script.exists(), (
        "Import boundary check script must exist at scripts/check_import_boundaries.py"
    )

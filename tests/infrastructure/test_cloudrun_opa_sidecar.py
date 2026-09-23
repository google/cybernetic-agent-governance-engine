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
Cloud Run OPA Sidecar Pattern Tests

Validates the multi-container Cloud Run service configuration with OPA sidecar:
- OPA Dockerfile uses fail-closed entrypoint wrapper
- Gateway container declares depends_on = ["opa"]
- Gateway container sets OPA_URL = "http://localhost:8181"
- OPA container has NO ports block (localhost-only communication)
- OPA startup probe completes before gateway starts
"""

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent
DOCKERFILE_OPA = REPO_ROOT / "deployment" / "docker" / "Dockerfile.opa"
TERRAFORM_MAIN = REPO_ROOT / "infra" / "targets" / "gcp-cloudrun" / "main.tf"

pytestmark = [pytest.mark.unit, pytest.mark.local]


def test_opa_dockerfile_fail_closed_entrypoint():
    """
    OPA Dockerfile MUST use the fail-closed entrypoint wrapper to resolve
    environment variables (CAGE_COMPLIANCE_BRIDGE_URL, CAGE_DEPLOYMENT_REGION)
    before starting OPA server.
    """
    assert DOCKERFILE_OPA.exists(), f"OPA Dockerfile not found at {DOCKERFILE_OPA}"
    
    content = DOCKERFILE_OPA.read_text()
    
    # Verify ENTRYPOINT points to the wrapper script
    assert re.search(
        r'ENTRYPOINT\s*\[\s*"[^"]*opa-entrypoint\.sh"\s*\]',
        content
    ), "OPA Dockerfile MUST use fail-closed entrypoint wrapper (opa-entrypoint.sh)"
    
    # Verify CMD passes --config-file to OPA
    assert re.search(
        r'CMD\s*\[.*"--config-file=/config/opa_config\.yaml"',
        content
    ), "OPA CMD MUST specify --config-file=/config/opa_config.yaml"


def test_gateway_terraform_declares_opa_depends_on():
    """
    Gateway container MUST declare depends_on = ["opa"] to ensure OPA sidecar
    starts and becomes healthy before the gateway container starts.
    """
    assert TERRAFORM_MAIN.exists(), f"Terraform main.tf not found at {TERRAFORM_MAIN}"
    
    content = TERRAFORM_MAIN.read_text()
    
    # Verify gateway container declares depends_on = ["opa"]
    # Look for pattern: name = "gateway" ... depends_on = ["opa"]
    assert re.search(
        r'name\s*=\s*"gateway".*?depends_on\s*=\s*\[\s*"opa"\s*\]',
        content,
        re.DOTALL
    ), 'Gateway container MUST declare depends_on = ["opa"]'


def test_gateway_terraform_opa_url_localhost():
    """
    Gateway container MUST set OPA_URL environment variable to
    "http://localhost:8181" for localhost-only communication with OPA sidecar.
    """
    assert TERRAFORM_MAIN.exists(), f"Terraform main.tf not found at {TERRAFORM_MAIN}"
    
    content = TERRAFORM_MAIN.read_text()
    
    # Verify OPA_URL = "http://localhost:8181" exists in gateway service
    # Look for env block with name = "OPA_URL" and value = "http://localhost:8181"
    assert re.search(
        r'env\s*\{\s*name\s*=\s*"OPA_URL"\s*value\s*=\s*"http://localhost:8181"\s*\}',
        content
    ), 'Gateway container MUST set OPA_URL = "http://localhost:8181"'


def test_opa_terraform_no_ports_declaration():
    """
    OPA sidecar container MUST NOT have a ports block. OPA communicates with
    the gateway container via localhost only and does not expose external ports.
    """
    assert TERRAFORM_MAIN.exists(), f"Terraform main.tf not found at {TERRAFORM_MAIN}"
    
    content = TERRAFORM_MAIN.read_text()
    
    # Extract OPA container block (name = "opa" until next containers block or template close)
    opa_match = re.search(
        r'name\s*=\s*"opa".*?(?=containers\s*\{|template\s*\{)',
        content,
        re.DOTALL
    )
    
    assert opa_match, "OPA container block not found in Terraform"
    
    opa_block = opa_match.group(0)
    
    # Verify NO ports block exists in OPA container
    assert not re.search(
        r'\bports\s*\{',
        opa_block
    ), "OPA container MUST NOT declare a ports block (localhost-only communication)"


def test_opa_startup_probe_before_gateway():
    """
    OPA sidecar container MUST have a startup_probe to ensure it is healthy
    before the gateway container starts (enforced via depends_on).
    """
    assert TERRAFORM_MAIN.exists(), f"Terraform main.tf not found at {TERRAFORM_MAIN}"
    
    content = TERRAFORM_MAIN.read_text()
    
    # Extract OPA container block (name = "opa" until next containers block)
    opa_match = re.search(
        r'name\s*=\s*"opa".*?(?=containers\s*\{|template\s*\{)',
        content,
        re.DOTALL
    )
    
    assert opa_match, "OPA container block not found in Terraform"
    
    opa_block = opa_match.group(0)
    
    # Verify startup_probe exists with http_get to /health on port 8181
    assert re.search(
        r'startup_probe\s*\{.*?http_get\s*\{.*?path\s*=\s*"/health".*?port\s*=\s*8181',
        opa_block,
        re.DOTALL
    ), "OPA container MUST have startup_probe with http_get to /health on port 8181"

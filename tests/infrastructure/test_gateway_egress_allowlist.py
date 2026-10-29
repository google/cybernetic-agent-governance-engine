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
"""POAM-2026-152: the gateway's egress allowlist names no model provider.

On GKE, model inference stays in the cluster and the external-provider backend
is compose-only (AG-7), so an allowlisted provider FQDN is egress surface that
serves nothing. The Terraform default and the static manifest the SSP cites as
SC-7 evidence must agree, and neither may list a provider.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
VARIABLES = REPO_ROOT / "infra" / "targets" / "gcp-gke" / "variables.tf"
MANIFEST = REPO_ROOT / "deployment" / "k8s" / "cilium" / "egress-lockdown.yaml"

MODEL_PROVIDER_FQDNS = {
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
}


def _terraform_default() -> set[str]:
    text = VARIABLES.read_text(encoding="utf-8")
    block = text[text.index('variable "gateway_egress_allowed_fqdns"') :]
    block = block[: block.index("\n}\n")]
    return set(re.findall(r'"([^"]+)"', block[block.index("default") :]))


def _static_manifest() -> set[str]:
    docs = [d for d in yaml.safe_load_all(MANIFEST.read_text(encoding="utf-8")) if d]
    policy = next(
        d
        for d in docs
        if d.get("kind") == "FQDNNetworkPolicy"
        and d["metadata"]["name"] == "gateway-egress-fqdn-allowlist"
    )
    return {
        fqdn
        for rule in policy["spec"]["egress"]
        for peer in rule.get("to", [])
        for fqdn in peer.get("fqdns", [])
    }


def test_gateway_allowlists_name_no_model_provider() -> None:
    assert not _terraform_default() & MODEL_PROVIDER_FQDNS
    assert not _static_manifest() & MODEL_PROVIDER_FQDNS


def test_terraform_default_and_static_manifest_agree() -> None:
    assert _terraform_default() == _static_manifest()

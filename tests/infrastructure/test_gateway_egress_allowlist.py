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
serves nothing. The Terraform default, every environment ``.tfvars`` profile,
and ``gateway_egress_fqdn_allowlist`` in ``network_policy.tf`` must name zero
external model providers.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
GKE_DIR = REPO_ROOT / "infra" / "targets" / "gcp-gke"
VARIABLES = GKE_DIR / "variables.tf"
NETWORK_POLICY = GKE_DIR / "network_policy.tf"

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


def _gateway_fqdn_policy_block() -> str:
    text = NETWORK_POLICY.read_text(encoding="utf-8")
    start = text.index("gateway_egress_fqdn_allowlist = {")
    pos = text.index("{", start) + 1
    depth = 1
    while depth:
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
        pos += 1
    return text[start:pos]


def test_gateway_allowlists_name_no_model_provider() -> None:
    defaults = _terraform_default()
    assert defaults, "gateway_egress_allowed_fqdns default must be non-empty"
    assert not (defaults & MODEL_PROVIDER_FQDNS)

    for tfvars in sorted(GKE_DIR.glob("*.tfvars")):
        text = tfvars.read_text(encoding="utf-8")
        m = re.search(
            r"gateway_egress_allowed_fqdns\s*=\s*\[(.*?)\]",
            text,
            re.S,
        )
        if m is not None:
            entries = set(re.findall(r'"([^"]+)"', m.group(1)))
            assert not (entries & MODEL_PROVIDER_FQDNS), (
                f"{tfvars.name} allowlists external model provider: {entries & MODEL_PROVIDER_FQDNS}"
            )


def test_gateway_fqdn_policy_sources_strictly_from_variable() -> None:
    block = _gateway_fqdn_policy_block()
    assert "for fqdn in var.gateway_egress_allowed_fqdns" in block
    for fqdn in MODEL_PROVIDER_FQDNS:
        assert fqdn not in block

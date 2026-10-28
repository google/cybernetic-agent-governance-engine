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
"""POAM-2026-126: no enforcing posture may open the GKE control plane to every address.

``staging.tfvars`` authorized ``0.0.0.0/0`` while its header claimed VPN scope, and
nothing read the list. Two guards now hold the claim:

* the shipped profiles: no profile with a compliance posture active authorizes a /0;
* the plan: the gcp-gke target's ``control_plane_access_guard`` refuses an empty list
  or a /0 whenever compliance is active. An empty list makes the cluster module emit
  no allowlist, and GKE then accepts any address.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
GKE_TARGET_DIR = REPO_ROOT / "infra" / "targets" / "gcp-gke"
PROFILES = sorted(p.name for p in GKE_TARGET_DIR.glob("*.tfvars"))


def _setting(text: str, name: str) -> str | None:
    match = re.search(rf'^\s*{name}\s*=\s*"?([^"\s#]+)"?', text, re.MULTILINE)
    return match.group(1) if match else None


def _compliance_active(text: str) -> bool:
    """Mirror ``local.any_compliance_active`` plus deploy_all.sh's NIST default.

    A profile's explicit ``enable_nist_compliance`` wins. Otherwise deploy_all.sh
    turns it on for the staging and prod tiers in US_FED only.
    """
    nist = _setting(text, "enable_nist_compliance")
    if nist is None:
        nist_on = _setting(text, "environment") in {"staging", "prod"} and (
            _setting(text, "cage_deployment_region") == "US_FED"
        )
    else:
        nist_on = nist == "true"
    return nist_on or any(
        _setting(text, flag) == "true"
        for flag in ("enable_eu_ecb_compliance", "enable_apac_mas_compliance")
    )


def _authorized_cidrs(text: str) -> list[str]:
    block = re.search(
        r"^authorized_networks\s*=\s*\[(.*?)\]", text, re.MULTILINE | re.DOTALL
    )
    return re.findall(r'cidr\s*=\s*"([^"]+)"', block.group(1)) if block else []


ENFORCING = [
    name
    for name in PROFILES
    if _compliance_active((GKE_TARGET_DIR / name).read_text(encoding="utf-8"))
]


def test_enforcing_profiles_are_the_ones_terraform_hardens() -> None:
    # Pins the classifier, so the profile check below cannot pass by finding no
    # enforcing profile. A new profile has to be classified on purpose.
    assert set(ENFORCING) == {
        "staging.tfvars",
        "prod.tfvars",
        "eu-dev.tfvars",
        "apac-dev.tfvars",
        "eu-prod.tfvars",
        "apac-prod.tfvars",
    }


@pytest.mark.parametrize("profile", ENFORCING)
def test_no_enforcing_profile_authorizes_every_address(profile: str) -> None:
    text = (GKE_TARGET_DIR / profile).read_text(encoding="utf-8")
    open_entries = [
        cidr
        for cidr in _authorized_cidrs(text)
        if ipaddress.ip_network(cidr, strict=False).prefixlen == 0
    ]
    assert not open_entries, (
        f"{profile} activates a compliance posture and authorizes {open_entries} "
        "on the GKE control plane (POAM-2026-126)"
    )


def _guard_block() -> str:
    main_tf = (GKE_TARGET_DIR / "main.tf").read_text(encoding="utf-8")
    start = main_tf.find('resource "terraform_data" "control_plane_access_guard"')
    assert start != -1, "the plan-time control-plane guard is missing (POAM-2026-126)"
    return main_tf[start : main_tf.find("\n}\n", start)]


def test_plan_refuses_an_open_or_empty_allowlist_under_compliance() -> None:
    guard = re.sub(r"\s+", " ", _guard_block())
    assert "condition = !local.any_compliance_active ||" in guard, (
        "the guard must apply whenever a compliance posture is active"
    )
    assert "length(var.authorized_networks) > 0" in guard, (
        "an empty list leaves GKE's allowlist off, so the guard must refuse it"
    )
    assert '!endswith(n.cidr, "/0")' in guard, "the guard must refuse a /0 entry"

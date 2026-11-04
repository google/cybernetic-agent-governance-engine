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

* the shipped profiles: no enforcing profile authorizes a /0;
* the plan: the gcp-gke target's ``control_plane_access_guard`` refuses an empty list
  or a /0 under an enforcing posture: every staging and prod plan, and a dev plan with
  a compliance flag. An empty list makes the cluster module emit no allowlist, and GKE
  then accepts any address. A plan targeted at ``module.gke`` skips the guard
  (POAM-2026-180; see test_guard_placement.py).

POAM-2026-181: the guards, the cluster allowlist, PITR and the NeMo securityContext
follow ``local.enforcing_posture``, the tier, rather than the jurisdiction flags, so
a staging or prod plan keeps them whatever jurisdiction it selects. The jurisdiction
flags now decide only whether a dev plan enforces.

POAM-2026-174: every committed profile sets ``enable_nist_compliance`` itself, so a
direct terraform run plans the same posture as deploy_all.sh, and the classifier
below reads only what the profile says.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
GKE_TARGET_DIR = REPO_ROOT / "infra" / "targets" / "gcp-gke"
# Committed profiles only. terraform.tfvars and *.auto.tfvars are operator-local
# (gitignored), and Terraform loads them without being asked.
PROFILES = sorted(
    p.name
    for p in GKE_TARGET_DIR.glob("*.tfvars")
    if p.name != "terraform.tfvars" and not p.name.endswith(".auto.tfvars")
)
COMPLIANCE_FLAGS = (
    "enable_nist_compliance",
    "enable_eu_ecb_compliance",
    "enable_apac_mas_compliance",
)


def _setting(text: str, name: str) -> str | None:
    match = re.search(rf'^\s*{name}\s*=\s*"?([^"\s#]+)"?', text, re.MULTILINE)
    return match.group(1) if match else None


ENFORCING_TIERS = ("prod", "staging")


def _enforcing(text: str) -> bool:
    """Mirror ``local.enforcing_posture`` from the profile's own settings.

    The prod and staging tiers always enforce; a dev profile enforces only with a
    compliance flag. ``test_every_profile_sets_the_nist_flag_itself`` keeps every
    profile explicit, so there is no deploy_all.sh default to model.
    """
    return _setting(text, "environment") in ENFORCING_TIERS or any(
        _setting(text, flag) == "true" for flag in COMPLIANCE_FLAGS
    )


def _authorized_cidrs(text: str) -> list[str]:
    block = re.search(
        r"^authorized_networks\s*=\s*\[(.*?)\]", text, re.MULTILINE | re.DOTALL
    )
    return re.findall(r'cidr\s*=\s*"([^"]+)"', block.group(1)) if block else []


ENFORCING = [
    name
    for name in PROFILES
    if _enforcing((GKE_TARGET_DIR / name).read_text(encoding="utf-8"))
]


def test_enforcing_profiles_are_the_ones_terraform_hardens() -> None:
    # Pins the classifier, so the profile check below cannot pass by finding no
    # enforcing profile. A new profile has to be classified on purpose, and a new
    # staging or prod profile enforces whatever flags it sets (POAM-2026-181).
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
        f"{profile} enforces and authorizes {open_entries} "
        "on the GKE control plane (POAM-2026-126)"
    )


def _guard_block() -> str:
    main_tf = (GKE_TARGET_DIR / "main.tf").read_text(encoding="utf-8")
    start = main_tf.find('resource "terraform_data" "control_plane_access_guard"')
    assert start != -1, "the plan-time control-plane guard is missing (POAM-2026-126)"
    return main_tf[start : main_tf.find("\n}\n", start)]


def test_plan_refuses_an_open_or_empty_allowlist_under_an_enforcing_posture() -> None:
    guard = re.sub(r"\s+", " ", _guard_block())
    assert "condition = !local.enforcing_posture ||" in guard, (
        "the guard must apply to every staging and prod plan (POAM-2026-181)"
    )
    assert "length(var.authorized_networks) > 0" in guard, (
        "an empty list leaves GKE's allowlist off, so the guard must refuse it"
    )
    assert '!endswith(n.cidr, "/0")' in guard, "the guard must refuse a /0 entry"


def test_posture_controls_follow_the_tier_not_a_jurisdiction_flag() -> None:
    # POAM-2026-181: these bound on local.any_compliance_active, so a staging or
    # prod plan that selected no jurisdiction flag dropped every one of them.
    main_tf = (GKE_TARGET_DIR / "main.tf").read_text(encoding="utf-8")
    code = [line for line in main_tf.splitlines() if not line.lstrip().startswith("#")]
    readers = sorted(
        line.split("=")[0].strip()
        for line in code
        if "local.any_compliance_active" in line
    )
    assert readers == ["enforcing_posture", "force_destroy"], (
        "only enforcing_posture and the dev-only force_destroy may read the "
        f"jurisdiction flags; found {readers}"
    )
    flat = re.sub(r"\s+", " ", "\n".join(code))
    for binding in (
        "enable_nist_compliance = local.enforcing_posture",
        "enable_point_in_time_recovery = local.enforcing_posture",
        "enable_security_context = local.enforcing_posture",
    ):
        assert binding in flat, f"main.tf must set {binding}"
    assert flat.count("condition = !local.enforcing_posture ||") == 3, (
        "the control-plane guard and both POAM-019 key guards must bind on "
        "local.enforcing_posture"
    )


@pytest.mark.parametrize("profile", PROFILES)
def test_every_profile_sets_the_nist_flag_itself(profile: str) -> None:
    # POAM-2026-174: staging.tfvars left the flag to deploy_all.sh, so a direct
    # terraform run with it planned no compliance posture and skipped the guard
    # above. A profile that states the flag plans the same posture on every path.
    text = (GKE_TARGET_DIR / profile).read_text(encoding="utf-8")
    assert re.search(
        r"^enable_nist_compliance\s*=\s*(true|false)\b", text, re.MULTILINE
    ), f"{profile} must set enable_nist_compliance to true or false, uncommented"

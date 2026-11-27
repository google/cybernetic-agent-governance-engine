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

POAM-2026-181 & POAM-2026-130: the guards, the cluster allowlist, PITR and the NeMo
securityContext follow ``local.enforcing_posture``, the tier, and the three
jurisdiction flags (``enable_nist_compliance``, ``enable_eu_ecb_compliance``,
``enable_apac_mas_compliance``) and ``local.any_compliance_active`` were removed.
``enforce_in_dev`` is the one posture variable for opting a ``dev`` profile into
``local.enforcing_posture``.

POAM-2026-174: every committed profile states its posture itself (``environment`` in
every profile, plus ``enforce_in_dev`` in every ``dev`` profile), so a direct
terraform run plans the same posture as deploy_all.sh.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
GKE_TARGET_DIR = REPO_ROOT / "infra" / "targets" / "gcp-gke"
GKE_CLUSTER_MODULE_DIR = REPO_ROOT / "infra" / "modules" / "gcp_gke_cluster"
# Committed profiles only. terraform.tfvars and *.auto.tfvars are operator-local
# (gitignored), and Terraform loads them without being asked.
PROFILES = sorted(
    p.name
    for p in GKE_TARGET_DIR.glob("*.tfvars")
    if p.name != "terraform.tfvars" and not p.name.endswith(".auto.tfvars")
)
REMOVED_COMPLIANCE_FLAGS = (
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

    The prod and staging tiers always enforce; a dev profile enforces only with
    ``enforce_in_dev = true``.
    """
    return (
        _setting(text, "environment") in ENFORCING_TIERS
        or _setting(text, "enforce_in_dev") == "true"
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


@pytest.mark.parametrize("profile", PROFILES)
def test_every_profile_sets_the_nist_flag_itself(profile: str) -> None:
    # POAM-2026-174 & POAM-2026-130: every profile states its tier, no profile
    # sets a removed enable_*_compliance flag, and every dev profile states
    # enforce_in_dev explicitly so a direct terraform run plans the same posture
    # as deploy_all.sh. Staging and prod profiles never set enforce_in_dev.
    text = (GKE_TARGET_DIR / profile).read_text(encoding="utf-8")
    tier = _setting(text, "environment")
    assert tier in ("dev", "staging", "prod"), (
        f"{profile} must set environment to dev, staging, or prod"
    )
    for flag in REMOVED_COMPLIANCE_FLAGS:
        assert not re.search(rf"^\s*{flag}\s*=", text, re.MULTILINE), (
            f"{profile} must not set removed flag {flag} (POAM-2026-130)"
        )
    if tier == "dev":
        assert re.search(r"^enforce_in_dev\s*=\s*(true|false)\b", text, re.MULTILINE), (
            f"{profile} (dev tier) must set enforce_in_dev to true or false, uncommented"
        )
    else:
        assert not re.search(r"^\s*enforce_in_dev\s*=", text, re.MULTILINE), (
            f"{profile} ({tier} tier) always enforces and must not set enforce_in_dev"
        )


def _strip_comments(text: str) -> str:
    return "\n".join(
        re.sub(r"(#|//).*$", "", line)
        for line in text.splitlines()
        if not line.lstrip().startswith(("#", "//"))
    )


def _primary_cluster_block() -> str:
    cluster_tf = (GKE_CLUSTER_MODULE_DIR / "main.tf").read_text(encoding="utf-8")
    start = cluster_tf.find('resource "google_container_cluster" "primary"')
    assert start != -1, "resource google_container_cluster.primary is missing"
    end = cluster_tf.find("\n}\n", start)
    return cluster_tf[start : end if end != -1 else len(cluster_tf)]


def _variable_block(path: Path, name: str) -> str:
    text = path.read_text(encoding="utf-8")
    match = re.search(
        rf'variable\s+"{re.escape(name)}"\s*\{{(.*?)\n\}}', text, re.DOTALL
    )
    assert match is not None, f'variable "{name}" missing in {path}'
    return _strip_comments(match.group(1))


def test_cluster_lifecycle_does_not_mask_control_plane_or_monitoring_drift() -> None:
    """POAM-2026-174 step 3: forbid silent ignore_changes latches on security blocks."""
    primary_block = _primary_cluster_block()
    assert not re.search(
        r"ignore_changes\s*=\s*all\b", _strip_comments(primary_block)
    ), (
        "google_container_cluster.primary must never set ignore_changes = all: "
        "unlike invalid config literals that fail terraform plan loudly, ignoring "
        "all attributes silently restores the POAM-2026-174 drift-masking latches."
    )
    ic_match = re.search(r"ignore_changes\s*=\s*\[(.*?)\]", primary_block, re.DOTALL)
    assert ic_match is not None, (
        "google_container_cluster.primary must define lifecycle.ignore_changes"
    )
    ignored_attrs = {
        tok.strip()
        for tok in _strip_comments(ic_match.group(1)).split(",")
        if tok.strip()
    }
    assert "master_authorized_networks_config" not in ignored_attrs, (
        "master_authorized_networks_config was re-added to "
        "google_container_cluster.primary lifecycle.ignore_changes! Unlike an invalid "
        "GKE component that fails a plan/apply loudly, ignoring "
        "master_authorized_networks_config fails nothing and silently restores the "
        "POAM-2026-174 drift-masking latch (leaving an existing cluster stuck at "
        "0.0.0.0/0 or out-of-band control-plane CIDRs across applies)."
    )
    assert "monitoring_config" not in ignored_attrs, (
        "monitoring_config was re-added to google_container_cluster.primary "
        "lifecycle.ignore_changes! Unlike an invalid GKE component that fails a "
        "plan/apply loudly, ignoring monitoring_config fails nothing and silently "
        "restores the POAM-2026-174 drift-masking latch on AU-12 Managed Prometheus "
        "and Dataplane V2 observability."
    )


def test_cluster_monitoring_and_min_master_version_match_gke_api_ef10() -> None:
    """POAM-2026-164 EF10a/EF10b: no retired WORKLOADS monitoring or 1.28 version."""
    primary_block = _primary_cluster_block()
    mon_match = re.search(
        r'dynamic\s+"monitoring_config"\s*\{(.*?)\n  \}',
        primary_block,
        re.DOTALL,
    )
    assert mon_match is not None, (
        'google_container_cluster.primary must define dynamic "monitoring_config"'
    )
    mon_body = _strip_comments(mon_match.group(1))
    assert "WORKLOADS" not in mon_body, (
        "EF10a regression: monitoring_config.enable_components must not include "
        "WORKLOADS (retired in GKE 1.24+; fails CreateCluster with 400 Bad Request)."
    )
    assert re.search(
        r'enable_components\s*=\s*\[\s*"SYSTEM_COMPONENTS"\s*\]', mon_body
    ), (
        'EF10a regression: monitoring_config.enable_components must be ["SYSTEM_COMPONENTS"]'
    )

    for tf_vars in (
        GKE_CLUSTER_MODULE_DIR / "variables.tf",
        GKE_TARGET_DIR / "variables.tf",
    ):
        block = _variable_block(tf_vars, "min_master_version")
        assert re.search(r"\bdefault\s*=\s*null\b", block), (
            f"EF10b regression in {tf_vars}: min_master_version must default to null "
            "(not retired '1.28' or any pinned minor version that breaks CreateCluster)."
        )

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

"""Hold what each Active Lula manifest selects to what ``infra/`` creates.

``test_lula_description_parity.py`` holds each Active README row to the *names*
of the rules its manifest composes, so it cannot see what a rule selects.
Before ``#664`` every object ``lula-validation-ftra.yaml`` selected by name was
one no Terraform module creates: a ``cage-gateway`` Deployment, a
terminal-registry ConfigMap and two NetworkPolicies. Both of its ``validate``
rules required the Deployment, so no cluster Terraform builds could have
satisfied the manifest, and name parity would have passed it.

Invariant 3 of ``scripts/check_k8s_terraform_parity.py`` closes that gap: every
object an Active manifest's Rego selects by name must be one that a Terraform
resource, ``locals`` manifest or Helm template in ``infra/`` names, or a declared
platform object whose enabling Terraform setting holds. Strict on purpose: an
alternate name in a set (``{"gateway", "stera-gateway"}``) must also exist. A
name nothing creates checks nothing, and ``#664`` wrote ``stera-gateway`` into
the match of eleven manifests, four of which (``eu-fria``, ``flowsignal``,
``ftra``, ``tqp007``) had matched only a Deployment nothing creates until it
added ``gateway`` beside it.

Neither check judges whether a rule that selects a real object checks enough of
it. Today's ``ftra`` would pass both if its dead alternates were removed, and it
is rated Stub for that reason.
"""

# Regression coverage binding: POAM-2026-219

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from scripts import check_k8s_terraform_parity as parity

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
LULA_DIR = REPO_ROOT / "compliance" / "lula"


@pytest.fixture(scope="module")
def live_report() -> parity.ParityReport:
    return parity.verify_k8s_terraform_parity(REPO_ROOT)


def _created(report: parity.ParityReport) -> dict[str, set[str]]:
    created: dict[str, set[str]] = {}
    for obj in report.terraform_objects:
        if obj.name is not None:
            created.setdefault(obj.resource, set()).add(obj.name)
    return created


# ---------------------------------------------------------------------------
# The live tree
# ---------------------------------------------------------------------------


def test_every_active_kubernetes_manifest_selects_by_name(
    live_report: parity.ParityReport,
) -> None:
    """A Kubernetes-domain Active manifest read as selecting nothing is a parser gap."""
    kubernetes = {
        name
        for name in live_report.lula_manifests
        if "type: kubernetes" in (LULA_DIR / name).read_text(encoding="utf-8")
    }
    assert kubernetes
    assert {sel.manifest for sel in live_report.lula_selectors} == kubernetes


@pytest.mark.parametrize(
    ("manifest", "resource", "name"),
    [
        # A Helm template under infra/modules/gateway/metrics-monitors/.
        ("lula-validation-metrics.yaml", "podmonitorings", "gateway-metrics"),
        # The Deployment embedded in module.gateway's locals.
        ("lula-validation-ac3.yaml", "deployments", "gateway"),
        # A named set iterated with every.
        ("lula-validation-sc8.yaml", "deployments", "compliance-bridge"),
        # An inline set iterated with every.
        ("lula-validation-ia3.yaml", "deployments", "compliance-bridge"),
        ("lula-validation-ia3.yaml", "networkpolicies", "gateway-egress-l3-l4"),
        ("lula-validation-iso001-token-quota.yaml", "configmaps", "opa-policies"),
        # The GKE Dataplane V2 DaemonSet, a declared platform object.
        ("lula-validation-cilium-dpv2.yaml", "daemonsets", "anetd"),
    ],
)
def test_live_selectors_are_read_and_held(
    live_report: parity.ParityReport, manifest: str, resource: str, name: str
) -> None:
    selected = {(s.manifest, s.resource, s.name) for s in live_report.lula_selectors}
    assert (manifest, resource, name) in selected


def test_anetd_is_held_to_the_dataplane_v2_setting() -> None:
    """The platform object is accepted because the GKE module enables Dataplane V2."""
    infra_dir = REPO_ROOT / "infra"
    instances = parity._discover_module_instances(infra_dir)
    (anetd,) = parity.PLATFORM_OBJECTS
    assert parity._platform_object_shortfall(infra_dir, instances, anetd) is None


# ---------------------------------------------------------------------------
# Replaying #664
# ---------------------------------------------------------------------------

#: ``372daad2^:compliance/lula/lula-validation-ftra.yaml``: its domain resources,
#: translated from the pre-v0.16 ``kind`` fields, and its Rego verbatim.
_FTRA_BEFORE_664_ALIASES = {
    "cage-gateway": parity.LulaAlias("deployments", ("governance-stack",)),
    "ftra-terminal-registry": parity.LulaAlias("configmaps", ("governance-stack",)),
    "ftra-egress-lockdown": parity.LulaAlias("networkpolicies", ("governance-stack",)),
    "ftra-allow-gfa-ingress": parity.LulaAlias(
        "networkpolicies", ("governance-stack",)
    ),
}

_FTRA_BEFORE_664_REGO = """\
package lula

import rego.v1

# FTRA Tier 0.5 Gate Validation
# Control ID: CTRL_FTRA_001
# POAM: POAM-2026-030

# Check that cage-gateway deployment exists
gateway_exists if {
  some deployment in input["cage-gateway"]
  deployment.kind == "Deployment"
  deployment.metadata.name == "cage-gateway"
}

# Check that FTRA code is deployed on gateway
# The FTRA boundary check is mandatory (hardcoded in symbolic_governor.py)
# No env var check needed — the check runs unconditionally
ftra_env_configured if {
  some deployment in input["cage-gateway"]
  some container in deployment.spec.template.spec.containers
  container.name == "gateway"
  true  # Gateway exists means mandatory FTRA check is active
}

# Check that terminal-registry ConfigMap exists
terminal_registry_exists if {
  some cm in input["ftra-terminal-registry"]
  cm.kind == "ConfigMap"
  cm.metadata.name == "ftra-terminal-registry"
}

# Fallback: terminal registry may be embedded in gateway image
# rather than as a ConfigMap (both patterns are valid)
terminal_registry_valid if {
  terminal_registry_exists
}
terminal_registry_valid if {
  not terminal_registry_exists
  gateway_exists  # Registry is embedded in image
}

# Check that NetworkPolicy interim controls are deployed
# Defense-in-depth layer alongside the mandatory FTRA boundary check.
networkpolicy_lockdown_exists if {
  some np in input["ftra-egress-lockdown"]
  np.kind == "NetworkPolicy"
  np.metadata.name == "ftra-egress-lockdown"
  np.metadata.labels["cage.io/component"] == "ftra-interim-control"
}

networkpolicy_gfa_ingress_exists if {
  some np in input["ftra-allow-gfa-ingress"]
  np.kind == "NetworkPolicy"
  np.metadata.name == "ftra-allow-gfa-ingress"
  np.metadata.labels["cage.io/component"] == "ftra-interim-control"
}

# FTRA boundary check is mandatory — this rule now validates that EITHER:
# 1. NetworkPolicy defense-in-depth layer exists, OR
# 2. Gateway is deployed (FTRA check is built-in, always active)
networkpolicy_or_boundary_enabled if {
  networkpolicy_lockdown_exists
  networkpolicy_gfa_ingress_exists
}
networkpolicy_or_boundary_enabled if {
  # Gateway deployment exists = FTRA boundary check is active (mandatory)
  some deployment in input["cage-gateway"]
  some container in deployment.spec.template.spec.containers
  container.name == "gateway"
}

# Main validation rule
validate if {
  gateway_exists
  ftra_env_configured
  terminal_registry_valid
  networkpolicy_or_boundary_enabled
}

# Fallback: if NetworkPolicy resources are not queried (Phase 0),
# validate passes if gateway exists
validate if {
  gateway_exists
  not input["ftra-egress-lockdown"]
  not input["ftra-allow-gfa-ingress"]
}
"""


def test_ftra_before_664_selected_four_objects_infra_does_not_create(
    live_report: parity.ParityReport,
) -> None:
    """Every object ``ftra`` selected before ``#664`` is one nothing in ``infra/`` names."""
    selected = parity.rego_name_selectors(
        _FTRA_BEFORE_664_REGO, _FTRA_BEFORE_664_ALIASES, "lula-validation-ftra.yaml"
    )
    created = _created(live_report)
    assert {
        (sel.resource, sel.name)
        for sel in selected
        if sel.name not in created.get(sel.resource, set())
    } == {
        ("deployments", "cage-gateway"),
        ("configmaps", "ftra-terminal-registry"),
        ("networkpolicies", "ftra-egress-lockdown"),
        ("networkpolicies", "ftra-allow-gfa-ingress"),
    }


#: The other objects the manifests ``#664`` hollowed selected before it, by the
#: ``filters`` on ``metadata.name`` in their pre-v0.16 domains (``372daad2^``):
#: the ``cage-gateway`` Deployment (``eu-fria`` and ``flowsignal``), the
#: ``token-quota-proxy`` Deployment (``tqp007``) and the ``opa-policy``
#: ConfigMap (``iso001-token-quota``). ``sc8`` selected only Deployments
#: Terraform creates.
_ORPHANS_SELECTED_BEFORE_664 = (
    ("deployments", "cage-gateway"),
    ("deployments", "token-quota-proxy"),
    ("configmaps", "opa-policy"),
)


@pytest.mark.parametrize(
    ("resource", "name"),
    _ORPHANS_SELECTED_BEFORE_664,
    ids=[f"{resource}:{name}" for resource, name in _ORPHANS_SELECTED_BEFORE_664],
)
def test_objects_selected_before_664_are_not_created(
    live_report: parity.ParityReport, resource: str, name: str
) -> None:
    assert name not in _created(live_report).get(resource, set())


# ---------------------------------------------------------------------------
# Selector forms
# ---------------------------------------------------------------------------

_ALIASES = {
    "deploys": parity.LulaAlias("deployments", ("governance-stack",)),
    "maps": parity.LulaAlias("configmaps", ("governance-stack",)),
}


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        pytest.param(
            'ok if {\n  some d in input["deploys"]\n  d.metadata.name == "gateway"\n}',
            {("deployments", "gateway")},
            id="equals-literal",
        ),
        pytest.param(
            'ok if {\n  some d in input["deploys"]\n'
            '  d.metadata.name in {"gateway", "compliance-bridge"}\n}',
            {("deployments", "gateway"), ("deployments", "compliance-bridge")},
            id="in-set-literal",
        ),
        pytest.param(
            'wanted := {\n  "gateway",\n}\n\nok if {\n  every n in wanted {\n'
            '    hits := [d | some d in input["deploys"]; d.metadata.name == n]\n'
            "    count(hits) >= 1\n  }\n}",
            {("deployments", "gateway")},
            id="named-set-iterated",
        ),
        pytest.param(
            'ok if {\n  every n in {"gateway", "agentsight-ui"} {\n'
            '    hits := [d | some d in input["deploys"]; d.metadata.name == n]\n'
            "    count(hits) >= 1\n  }\n}",
            {("deployments", "gateway"), ("deployments", "agentsight-ui")},
            id="set-literal-iterated",
        ),
        pytest.param(
            'is_gateway(d) if {\n  d.metadata.name == "gateway"\n}\n\n'
            'ok if {\n  some d in input["deploys"]\n  is_gateway(d)\n}',
            {("deployments", "gateway")},
            id="function-parameter",
        ),
        pytest.param(
            'ok if {\n  cm := input["maps"][_]\n  "opa-policies" == cm.metadata.name\n}',
            {("configmaps", "opa-policies")},
            id="reversed-literal",
        ),
        pytest.param(
            'wanted := {"opa-policies"}\n\nok if {\n  some cm in input["maps"]\n'
            "  wanted[cm.metadata.name]\n}",
            {("configmaps", "opa-policies")},
            id="named-set-lookup",
        ),
        pytest.param(
            'ok if {\n  input["maps"].metadata.name == "opa-policies"\n}',
            {("configmaps", "opa-policies")},
            id="direct-input",
        ),
        pytest.param(
            'ok if {\n  some cm in input["maps"]\n  cm.metadata.name != "default"\n}',
            set(),
            id="exclusion-selects-nothing",
        ),
        pytest.param(
            '# d.metadata.name == "ghost" in a comment\nok if {\n'
            '  some d in input["deploys"]\n  d.metadata.labels.app == "x.metadata.name"\n}',
            set(),
            id="comment-and-string-are-not-selectors",
        ),
    ],
)
def test_each_selector_form_is_read(body: str, expected: set[tuple[str, str]]) -> None:
    selected = parity.rego_name_selectors(
        f"package lula\n\n{body}\n", _ALIASES, "planted.yaml"
    )
    assert {(sel.resource, sel.name) for sel in selected} == expected


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(
            'ok if {\n  some d in input["deploys"]\n  startswith(d.metadata.name, "gate")\n}',
            id="prefix-match",
        ),
        pytest.param(
            'ok if {\n  some d in input["deploys"]\n  d.metadata.name == input.wanted\n}',
            id="computed-name",
        ),
        pytest.param(
            'ok if {\n  d.metadata.name == "gateway"\n}', id="unbound-variable"
        ),
        pytest.param(
            'ok if {\n  some d in input["deploys"]\n  some d in input["maps"]\n'
            '  d.metadata.name == "gateway"\n}',
            id="two-aliases-one-variable",
        ),
        pytest.param(
            'ok if {\n  some d in input["ghosts"]\n  d.metadata.name == "gateway"\n}',
            id="undeclared-alias",
        ),
        pytest.param(
            'is_gateway(d) if {\n  d.metadata.name == "gateway"\n}',
            id="uncalled-function",
        ),
        pytest.param(
            'ok if {\n  input["deploys"][0].metadata.name == "gateway"\n}',
            id="indexed-input",
        ),
        pytest.param(
            'ok if {\n  some d in input["deploys"]\n'
            '  d.spec.template.metadata.name == "gateway"\n}',
            id="field-path",
        ),
        pytest.param(
            'ok if {\n  some d in input["deploys"]\n  d.metadata.name == "gate\\qway"\n}',
            id="malformed-literal",
        ),
    ],
)
def test_unreadable_selector_fails_closed(body: str) -> None:
    with pytest.raises(parity.OrphanSelectorError, match="planted.yaml"):
        parity.rego_name_selectors(
            f"package lula\n\n{body}\n", _ALIASES, "planted.yaml"
        )


# ---------------------------------------------------------------------------
# Synthetic trees through the whole gate
# ---------------------------------------------------------------------------

_GATEWAY_TF = """\
resource "kubernetes_deployment" "gateway" {
  metadata { name = "gateway" }
  spec {
    template {
      metadata {
        labels = {
          app = "gateway"
        }
      }
    }
  }
}
"""

_DATAPATH_FROM_FLAG = (
    'var.enable_dataplane_v2 ? "ADVANCED_DATAPATH" : "DATAPATH_PROVIDER_UNSPECIFIED"'
)


def _plant(
    tmp_path: Path,
    rego: str,
    *,
    status: str = "\u2705 Active",
    datapath: str = _DATAPATH_FROM_FLAG,
    dataplane_v2_default: str = "true",
    anetd_namespace: str = "kube-system",
) -> Path:
    """Write a tree with one gateway Deployment, a GKE module and one Lula manifest."""
    repo = tmp_path / "repo"
    gateway = repo / "infra" / "modules" / "gateway"
    gateway.mkdir(parents=True)
    (gateway / "main.tf").write_text(_GATEWAY_TF, encoding="utf-8")
    gke = repo / "infra" / "modules" / "gcp_gke_cluster"
    gke.mkdir(parents=True)
    (gke / "main.tf").write_text(
        f'resource "google_container_cluster" "primary" {{\n'
        f"  datapath_provider = {datapath}\n}}\n",
        encoding="utf-8",
    )
    (gke / "variables.tf").write_text(
        f'variable "enable_dataplane_v2" {{\n  type    = bool\n'
        f"  default = {dataplane_v2_default}\n}}\n",
        encoding="utf-8",
    )
    lula = repo / "compliance" / "lula"
    lula.mkdir(parents=True)
    (lula / "README.md").write_text(
        "| [`lula-validation-planted.yaml`](lula-validation-planted.yaml) "
        f"| AU-12 | NIST SP 800-53 | US_FED | {status} | planted |\n",
        encoding="utf-8",
    )
    manifest = {
        "domain": {
            "type": "kubernetes",
            "kubernetes-spec": {
                "resources": [
                    {
                        "name": "deploys",
                        "resource-rule": {
                            "group": "apps",
                            "version": "v1",
                            "resource": "deployments",
                            "namespaces": ["governance-stack"],
                        },
                    },
                    {
                        "name": "daemons",
                        "resource-rule": {
                            "group": "apps",
                            "version": "v1",
                            "resource": "daemonsets",
                            "namespaces": [anetd_namespace],
                        },
                    },
                ]
            },
        },
        "provider": {"type": "opa", "opa-spec": {"rego": rego}},
    }
    (lula / "lula-validation-planted.yaml").write_text(
        yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8"
    )
    return repo


_DEAD_ALTERNATE_REGO = """\
package lula

import future.keywords.if
import future.keywords.in

gateway_ready if {
  some deploy in input["deploys"]
  deploy.metadata.name in {"gateway", "stera-gateway"}
  deploy.status.readyReplicas >= 1
}

validate if {
  gateway_ready
}
"""

_ANETD_REGO = """\
package lula

import future.keywords.if
import future.keywords.in

validate if {
  ds_list := [d | some d in input["daemons"]; d.metadata.name == "anetd"]
  count(ds_list) >= 1
}
"""


def test_active_manifest_selecting_a_dead_alternate_fails(tmp_path: Path) -> None:
    """``au12``'s set before this change: ``gateway`` exists, ``stera-gateway`` does not."""
    repo = _plant(tmp_path, _DEAD_ALTERNATE_REGO)
    with pytest.raises(parity.OrphanSelectorError, match="'stera-gateway'") as caught:
        parity.verify_k8s_terraform_parity(repo, enforce_floors=False)
    assert "'gateway'" not in str(caught.value).split("Named objects")[0]
    assert parity.main(["--repo-root", str(repo), "--no-floors"]) == 1


def test_stub_manifest_is_not_held(tmp_path: Path) -> None:
    """A Stub backs no closure; promoting it to Active is when the check applies."""
    repo = _plant(tmp_path, _DEAD_ALTERNATE_REGO, status="\U0001f536 Stub")
    report = parity.verify_k8s_terraform_parity(repo, enforce_floors=False)
    assert report.lula_manifests == ()
    assert report.lula_selectors == ()


@pytest.mark.parametrize(
    ("datapath", "dataplane_v2_default", "enabled"),
    [
        pytest.param(_DATAPATH_FROM_FLAG, "true", True, id="flag-on"),
        pytest.param(_DATAPATH_FROM_FLAG, "false", False, id="flag-off"),
        pytest.param('"ADVANCED_DATAPATH"', "false", True, id="literal-advanced"),
        pytest.param(
            '"DATAPATH_PROVIDER_UNSPECIFIED"', "true", False, id="literal-legacy"
        ),
    ],
)
def test_platform_object_is_accepted_only_while_terraform_enables_it(
    tmp_path: Path, datapath: str, dataplane_v2_default: str, enabled: bool
) -> None:
    repo = _plant(
        tmp_path,
        _ANETD_REGO,
        datapath=datapath,
        dataplane_v2_default=dataplane_v2_default,
    )
    if enabled:
        report = parity.verify_k8s_terraform_parity(repo, enforce_floors=False)
        assert [(s.resource, s.name) for s in report.lula_selectors] == [
            ("daemonsets", "anetd")
        ]
    else:
        with pytest.raises(parity.OrphanSelectorError, match="GKE Dataplane V2"):
            parity.verify_k8s_terraform_parity(repo, enforce_floors=False)


def test_platform_object_must_be_selected_in_its_namespace(tmp_path: Path) -> None:
    repo = _plant(tmp_path, _ANETD_REGO, anetd_namespace="governance-stack")
    with pytest.raises(parity.OrphanSelectorError, match="'anetd'"):
        parity.verify_k8s_terraform_parity(repo, enforce_floors=False)


def test_repository_run_requires_the_lula_readme(tmp_path: Path) -> None:
    repo = _plant(tmp_path, _ANETD_REGO)
    (repo / "compliance" / "lula" / "README.md").unlink()
    with pytest.raises(
        parity.OrphanSelectorError, match=r"compliance/lula/README\.md is missing"
    ):
        parity.verify_k8s_terraform_parity(repo, enforce_floors=True)

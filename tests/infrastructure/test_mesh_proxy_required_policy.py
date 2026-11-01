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

"""Static gate: governance pods cannot be admitted without the Linkerd proxy.

The proxy injector's webhook fails open, so a pod created while no injector
replica is ready is admitted without the proxy. On staging on 2026-10-29 a
gateway replica was admitted that way (POAM-2026-167).
``infra/modules/service_mesh`` installs the ValidatingAdmissionPolicy in
``charts/mesh-proxy-required`` for the namespaces in
``proxy_required_namespaces``, and the gcp-gke target lists the namespace it
meshes. This test checks:

1. The policy matches pod creation only, and refuses a pod with no
   ``linkerd-proxy`` container, whether native sidecar or ordinary container.
2. It fails closed: ``failurePolicy: Fail``, and the binding denies.
3. Nothing exempts a pod: no match condition, no annotation, no object
   selector.
4. The binding covers exactly the listed namespaces, by name, and the chart
   refuses an empty list.
5. The module installs it after the control plane, and the target lists the
   same namespace it annotates for injection.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO = Path(__file__).resolve().parents[2]
_MODULE = _REPO / "infra/modules/service_mesh"
_TEMPLATE = _MODULE / "charts/mesh-proxy-required/templates/proxy-required-policy.yaml"
_TARGET = _REPO / "infra/targets/gcp-gke/main.tf"
_NAMESPACES_EXPR = "{{ toJson .Values.namespaces }}"
_GUARD = re.compile(
    r'^\{\{- if empty \.Values\.namespaces \}\}\{\{ fail "[^"]+" \}\}\{\{ end \}\}\n',
    re.M,
)


def _render(namespaces: list[str]) -> tuple[dict, dict]:
    text = _TEMPLATE.read_text()
    assert len(_GUARD.findall(text)) == 1, (
        "the chart must refuse an empty namespace list"
    )
    assert text.count(_NAMESPACES_EXPR) == 1, (
        "the namespaces must come from values, once"
    )
    rendered = _GUARD.sub("", text).replace(_NAMESPACES_EXPR, json.dumps(namespaces))
    assert "{{" not in rendered, "unexpected template expression in the policy"
    by_kind = {doc["kind"]: doc for doc in yaml.safe_load_all(rendered) if doc}
    assert set(by_kind) == {
        "ValidatingAdmissionPolicy",
        "ValidatingAdmissionPolicyBinding",
    }
    return by_kind["ValidatingAdmissionPolicy"], by_kind[
        "ValidatingAdmissionPolicyBinding"
    ]


def _block(text: str, kind: str, rtype: str, name: str) -> str:
    match = re.search(
        rf'^{kind} "{rtype}"(?: "{name}")? \{{\n(.*?)^\}}', text, re.S | re.M
    )
    assert match, f"{kind} {rtype} {name} not found"
    return match.group(1)


def test_policy_matches_pod_creation_only() -> None:
    policy, _ = _render(["governance-stack"])
    assert policy["spec"]["matchConstraints"]["resourceRules"] == [
        {
            "apiGroups": [""],
            "apiVersions": ["v1"],
            "operations": ["CREATE"],
            "resources": ["pods"],
        }
    ]


def test_policy_requires_the_proxy_container() -> None:
    policy, _ = _render(["governance-stack"])
    validations = policy["spec"]["validations"]
    assert len(validations) == 1
    expression = " ".join(validations[0]["expression"].split())
    # The injector adds the proxy as a native sidecar (an init container), or
    # as an ordinary container when native sidecars are off.
    assert (
        "object.spec.initContainers.exists(c, c.name == 'linkerd-proxy')" in expression
    )
    assert "object.spec.containers.exists(c, c.name == 'linkerd-proxy')" in expression
    assert validations[0]["reason"] == "Forbidden"


def test_policy_fails_closed() -> None:
    policy, binding = _render(["governance-stack"])
    assert policy["spec"]["failurePolicy"] == "Fail"
    assert binding["spec"]["policyName"] == policy["metadata"]["name"]
    assert binding["spec"]["validationActions"] == ["Deny"]


def test_nothing_exempts_a_pod() -> None:
    policy, binding = _render(["governance-stack"])
    assert "matchConditions" not in policy["spec"]
    assert "annotations" not in policy["spec"]["validations"][0]["expression"]
    assert "objectSelector" not in binding["spec"]["matchResources"]


def test_binding_covers_exactly_the_listed_namespaces() -> None:
    _, binding = _render(["governance-stack", "other"])
    assert binding["spec"]["matchResources"] == {
        "namespaceSelector": {
            "matchExpressions": [
                {
                    "key": "kubernetes.io/metadata.name",
                    "operator": "In",
                    "values": ["governance-stack", "other"],
                }
            ]
        }
    }


def test_module_installs_the_policy_after_the_control_plane() -> None:
    release = _block(
        (_MODULE / "main.tf").read_text(),
        "resource",
        "helm_release",
        "mesh_proxy_required",
    )
    assert "count = length(var.proxy_required_namespaces) > 0 ? 1 : 0" in release
    assert 'chart     = "${path.module}/charts/mesh-proxy-required"' in release
    assert "namespaces = var.proxy_required_namespaces" in release
    assert "depends_on = [helm_release.linkerd_control_plane]" in release


def test_target_requires_the_proxy_in_the_namespace_it_meshes() -> None:
    target = _TARGET.read_text()
    namespace = _block(target, "module", "namespace", "")
    assert "name        = var.namespace" in namespace
    assert '"linkerd.io/inject" = "enabled"' in namespace
    mesh = _block(target, "module", "service_mesh", "")
    assert "proxy_required_namespaces = [var.namespace]" in mesh

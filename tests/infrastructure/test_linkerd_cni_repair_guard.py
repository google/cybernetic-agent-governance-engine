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

"""Static gate: the linkerd-cni repair-scope admission policy stays a confinement.

With its repair controller enabled, the linkerd2-cni chart grants its service
account ``delete`` on pods cluster-wide. ``infra/modules/service_mesh`` confines
that grant with the ValidatingAdmissionPolicy in ``charts/cni-repair-guard``.
The module's terraform test checks that the guard release is planned with the
chart's service account; this test checks what the guard says and when it is
installed:

1. It matches pod deletions by that one service account and nothing else.
2. It fails closed: ``failurePolicy: Fail``, and the binding denies in every
   namespace rather than warning or auditing.
3. It allows a deletion only when the requesting token's node is the pod's node
   and the pod's ``linkerd-network-validator`` last exited 95.
4. The module installs it before the linkerd2-cni chart grants the permission.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO = Path(__file__).resolve().parents[2]
_MODULE = _REPO / "infra/modules/service_mesh"
_TEMPLATE = _MODULE / "charts/cni-repair-guard/templates/repair-scope-policy.yaml"
_MAIN = _MODULE / "main.tf"
_USERNAME = "system:serviceaccount:linkerd-cni:linkerd-cni"
_USERNAME_EXPR = re.compile(
    r'\{\{\s*required "serviceAccountUsername is required" '
    r"\.Values\.serviceAccountUsername \| squote\s*\}\}"
)


def _render() -> tuple[dict, dict]:
    """Substitute the template's one expression and parse its two documents."""
    text = _TEMPLATE.read_text()
    assert len(_USERNAME_EXPR.findall(text)) == 1, (
        "the service account must come from values, once"
    )
    rendered = _USERNAME_EXPR.sub(f"'{_USERNAME}'", text)
    assert "{{" not in rendered, "unexpected template expression in the policy"
    by_kind = {doc["kind"]: doc for doc in yaml.safe_load_all(rendered) if doc}
    assert set(by_kind) == {
        "ValidatingAdmissionPolicy",
        "ValidatingAdmissionPolicyBinding",
    }
    return by_kind["ValidatingAdmissionPolicy"], by_kind[
        "ValidatingAdmissionPolicyBinding"
    ]


def _expressions(policy: dict) -> list[str]:
    return [" ".join(v["expression"].split()) for v in policy["spec"]["validations"]]


def _resource_block(text: str, address: str) -> str:
    match = re.search(
        rf'^resource "helm_release" "{address}" \{{\n(.*?)^\}}', text, re.S | re.M
    )
    assert match, f"helm_release.{address} not found in {_MAIN.name}"
    return match.group(1)


def test_policy_matches_only_pod_deletes_by_the_cni_service_account() -> None:
    policy, _ = _render()
    assert policy["spec"]["matchConstraints"]["resourceRules"] == [
        {
            "apiGroups": [""],
            "apiVersions": ["v1"],
            "operations": ["DELETE"],
            "resources": ["pods"],
        }
    ]
    conditions = policy["spec"]["matchConditions"]
    assert [" ".join(c["expression"].split()) for c in conditions] == [
        f"request.userInfo.username == '{_USERNAME}'"
    ]


def test_policy_fails_closed_in_every_namespace() -> None:
    policy, binding = _render()
    assert policy["spec"]["failurePolicy"] == "Fail"
    assert binding["spec"]["policyName"] == policy["metadata"]["name"]
    assert binding["spec"]["validationActions"] == ["Deny"]
    assert "matchResources" not in binding["spec"], (
        "the binding must not narrow the namespaces it covers"
    )


def test_policy_requires_the_requesters_node() -> None:
    policy, _ = _render()
    assert any(
        "'authentication.kubernetes.io/node-name' in request.userInfo.extra" in e
        and "oldObject.spec.nodeName in request.userInfo.extra['authentication.kubernetes.io/node-name']"
        in e
        for e in _expressions(policy)
    ), (
        "a deletion must be refused unless the pod is on the node named by the requesting pod-bound token"
    )


def test_policy_requires_a_validator_that_exited_95() -> None:
    policy, _ = _render()
    assert any(
        "s.name == 'linkerd-network-validator'" in e
        and "s.lastState.terminated.exitCode == 95" in e
        for e in _expressions(policy)
    ), (
        "a deletion must be refused unless the pod's linkerd-network-validator last exited 95"
    )


def test_module_installs_the_guard_before_the_cni_chart() -> None:
    main = _MAIN.read_text()
    guard = _resource_block(main, "linkerd_cni_repair_guard")
    assert 'chart     = "${path.module}/charts/cni-repair-guard"' in guard
    cni = _resource_block(main, "linkerd_cni")
    depends_on = re.search(r"depends_on = \[(.*?)\]", cni, re.S)
    assert depends_on, "helm_release.linkerd_cni declares no depends_on"
    assert "helm_release.linkerd_cni_repair_guard" in depends_on.group(1), (
        "linkerd2-cni must depend on the guard, so the delete grant never exists unconfined"
    )

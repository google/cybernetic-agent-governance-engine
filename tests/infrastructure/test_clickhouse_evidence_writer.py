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

"""Static gate: the ClickHouse evidence sink runs as a least-privilege writer.

The compliance bridge's ClickHouseSink authenticates as ``cage_evidence_sink``,
a config-defined user (``users.d/evidence_sink_user.xml``) whose only privilege
is ``INSERT`` on ``cage_evidence.evidence_stream``. It never uses the admin
``default`` user or the admin password in ``advisor-secrets``.

Enforced for the Terraform module/target and the raw manifests.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
import yaml

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO = Path(__file__).resolve().parents[2]
_CH_MAIN = _REPO / "infra/modules/clickhouse_operator/main.tf"
_CH_VARS = _REPO / "infra/modules/clickhouse_operator/variables.tf"
_CH_OUTPUTS = _REPO / "infra/modules/clickhouse_operator/outputs.tf"
_BRIDGE_VARS = _REPO / "infra/modules/compliance_bridge/variables.tf"
_GKE_MAIN = _REPO / "infra/targets/gcp-gke/main.tf"
_SCHEMA = _REPO / "deployment/clickhouse/evidence_stream_schema.sql"
_SINK = _REPO / "src/compliance_bridge/clickhouse_sink.py"
_K8S = _REPO / "deployment/k8s"

_WRITER = "cage_evidence_sink"
_SECRET = "clickhouse-evidence-sink"
_ALLOWED_GRANT = re.compile(r"^GRANT INSERT ON [\w${}.]+\.evidence_stream$")


class LeastPrivilegeViolation(AssertionError):
    """The writer user's configuration grants more than INSERT on evidence_stream."""


def _check_writer(xml_text: str, username: str) -> None:
    """Fail closed unless ``username`` is a password-from-env, INSERT-only writer."""
    root = ET.fromstring(xml_text)
    user = root.find(f"users/{username}")
    if user is None:
        raise LeastPrivilegeViolation(f"user {username!r} not defined")
    grants = [q.text.strip() for q in user.findall("grants/query")]
    if not grants or any(not _ALLOWED_GRANT.match(g) for g in grants):
        raise LeastPrivilegeViolation(
            f"writer grants exceed INSERT on evidence_stream: {grants}"
        )
    if user.findtext("access_management", "0").strip() != "0":
        raise LeastPrivilegeViolation("writer may manage access")
    pw = user.find("password")
    if pw is None or not pw.get("from_env") or (pw.text or "").strip():
        raise LeastPrivilegeViolation(
            "writer password must come from the environment, not config"
        )
    profile = root.find(f"profiles/{user.findtext('profile')}")
    if (
        profile is None
        or profile.findtext("allow_ddl") != "0"
        or profile.find("constraints/allow_ddl/const") is None
    ):
        raise LeastPrivilegeViolation(
            "writer profile must pin allow_ddl=0 with a CONST constraint"
        )


def _tf_heredoc(text: str, key: str) -> str:
    m = re.search(rf'"{re.escape(key)}"\s*=\s*<<-EOT\n(.*?)\n\s*EOT', text, re.S)
    assert m, f"{key} heredoc not found"
    return m.group(1)


def _block(text: str, header: str) -> str:
    start = text.find(header)
    assert start != -1, f"{header!r} not found"
    pos, depth = text.index("{", start) + 1, 1
    while depth:
        depth += {"{": 1, "}": -1}.get(text[pos], 0)
        pos += 1
    return text[start:pos]


def _docs(path: Path) -> list[dict]:
    text = path.read_text()
    if path.name.endswith(".tpl"):
        text = re.sub(r"\$\{[A-Z0-9_]+(:-[^}]*)?\}", "placeholder", text)
    return [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]


# ---------------------------------------------------------------------------
# The checker itself fails closed
# ---------------------------------------------------------------------------

_GOOD = f"""<clickhouse><profiles><p><allow_ddl>0</allow_ddl>
<constraints><allow_ddl><const/></allow_ddl></constraints></p></profiles>
<users><{_WRITER}><password from_env="X"/><profile>p</profile>
<access_management>0</access_management>
<grants><query>GRANT INSERT ON cage_evidence.evidence_stream</query></grants>
</{_WRITER}></users></clickhouse>"""


def test_checker_accepts_insert_only_writer() -> None:
    _check_writer(_GOOD, _WRITER)


@pytest.mark.parametrize(
    "mutation",
    [
        (
            "</query></grants>",
            "</query><query>GRANT SELECT ON cage_evidence.evidence_stream</query></grants>",
        ),
        ("evidence_stream</query>", "evidence_chain_divergence</query>"),
        ("GRANT INSERT ON cage_evidence.evidence_stream", "GRANT ALL ON *.*"),
        ('<password from_env="X"/>', "<password>literal</password>"),
        ("<access_management>0<", "<access_management>1<"),
        ("<constraints><allow_ddl><const/></allow_ddl></constraints>", ""),
    ],
    ids=[
        "extra-select",
        "divergence-insert",
        "grant-all",
        "literal-password",
        "access-mgmt",
        "no-const",
    ],
)
def test_checker_rejects_widened_writer(mutation: tuple[str, str]) -> None:
    bad = _GOOD.replace(*mutation)
    assert bad != _GOOD
    with pytest.raises(LeastPrivilegeViolation):
        _check_writer(bad, _WRITER)


# ---------------------------------------------------------------------------
# Terraform
# ---------------------------------------------------------------------------


def test_module_renders_least_privilege_writer() -> None:
    xml_text = _tf_heredoc(_CH_MAIN.read_text(), "evidence_sink_user.xml")
    xml_text = xml_text.replace("${var.evidence_sink_username}", _WRITER)
    _check_writer(xml_text, _WRITER)


def test_module_mounts_writer_config_and_injects_password_from_own_secret() -> None:
    main = _CH_MAIN.read_text()
    assert (
        'mount_path = "/etc/clickhouse-server/users.d/evidence_sink_user.xml"' in main
    )
    env_start = main.index('name = "CLICKHOUSE_EVIDENCE_SINK_PASSWORD"')
    env_ref = _block(main[env_start:], "value_from")
    assert "kubernetes_secret.evidence_sink.metadata[0].name" in env_ref
    secret = _block(main, 'resource "kubernetes_secret" "evidence_sink"')
    assert "random_password.evidence_sink.result" in secret
    assert "random_password.clickhouse.result" not in secret


def test_module_refuses_default_as_writer() -> None:
    block = _block(_CH_VARS.read_text(), 'variable "evidence_sink_username"')
    assert f'default     = "{_WRITER}"' in block
    assert '!= "default"' in block
    outputs = _CH_OUTPUTS.read_text()
    for name in (
        "evidence_sink_username",
        "evidence_sink_password_secret_name",
        "evidence_sink_password_secret_key",
    ):
        assert f'output "{name}"' in outputs


def test_bridge_module_defaults_and_validation_forbid_admin_user() -> None:
    user = _block(_BRIDGE_VARS.read_text(), 'variable "clickhouse_username"')
    assert f'default     = "{_WRITER}"' in user
    assert 'var.clickhouse_username != "default"' in user
    secret = _block(
        _BRIDGE_VARS.read_text(), 'variable "clickhouse_password_secret_name"'
    )
    assert f'default     = "{_SECRET}"' in secret


def test_gke_target_wires_bridge_to_writer_outputs() -> None:
    bridge = _block(_GKE_MAIN.read_text(), 'module "compliance_bridge"')
    assert "module.clickhouse_operator.evidence_sink_username" in bridge
    assert "module.clickhouse_operator.evidence_sink_password_secret_name" in bridge
    assert "module.clickhouse_operator.evidence_sink_password_secret_key" in bridge
    assert 'clickhouse_username        = "default"' not in bridge
    assert not re.search(r'clickhouse_username\s*=\s*"default"', bridge)


# ---------------------------------------------------------------------------
# Raw manifests, schema and sink default
# ---------------------------------------------------------------------------


def test_raw_clickhouse_manifest_defines_writer_and_mounts_it() -> None:
    docs = _docs(_K8S / "langfuse-db.yaml")
    cm = next(
        d
        for d in docs
        if d["kind"] == "ConfigMap"
        and d["metadata"]["name"] == "clickhouse-users-config"
    )
    _check_writer(cm["data"]["evidence_sink_user.xml"], _WRITER)
    sts = next(
        d
        for d in docs
        if d["kind"] == "StatefulSet" and d["metadata"]["name"] == "clickhouse"
    )
    container = sts["spec"]["template"]["spec"]["containers"][0]
    env = {e["name"]: e for e in container["env"]}
    assert (
        env["CLICKHOUSE_EVIDENCE_SINK_PASSWORD"]["valueFrom"]["secretKeyRef"]["name"]
        == _SECRET
    )
    mounts = {m["mountPath"] for m in container["volumeMounts"]}
    assert "/etc/clickhouse-server/users.d/evidence_sink_user.xml" in mounts


@pytest.mark.parametrize(
    "manifest", ["compliance-bridge.yaml", "compliance-bridge-deployment.yaml.tpl"]
)
def test_bridge_manifests_use_writer_not_admin(manifest: str) -> None:
    dep = next(d for d in _docs(_K8S / manifest) if d["kind"] == "Deployment")
    env = {
        e["name"]: e for e in dep["spec"]["template"]["spec"]["containers"][0]["env"]
    }
    assert env["CLICKHOUSE_USERNAME"]["value"] == _WRITER
    assert env["CLICKHOUSE_PASSWORD"]["valueFrom"]["secretKeyRef"]["name"] == _SECRET


def test_writer_secret_template_is_placeholder_only() -> None:
    (secret,) = _docs(_K8S / "clickhouse-evidence-sink-secret.yaml")
    assert secret["metadata"]["name"] == _SECRET
    assert secret["stringData"]["CLICKHOUSE_PASSWORD"].startswith("<")


def test_schema_does_not_create_or_widen_the_writer() -> None:
    sql = "\n".join(
        line
        for line in _SCHEMA.read_text().splitlines()
        if not line.lstrip().startswith("--")
    )
    assert f"CREATE USER IF NOT EXISTS {_WRITER}" not in sql
    assert "TO evidence_writer" not in sql
    assert not re.search(
        r"GRANT\s+INSERT\s+ON\s+cage_evidence\.evidence_chain_divergence\s+TO\s+evidence_writer",
        sql,
    )


def test_sink_default_username_is_writer() -> None:
    assert f'os.environ.get("CLICKHOUSE_USERNAME", "{_WRITER}")' in _SINK.read_text()

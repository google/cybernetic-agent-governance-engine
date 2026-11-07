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

"""Static & structural gates for F-108: ClickHouse RBAC isolation for Langfuse.

Enforces four coupled invariants across ``clickhouse_operator``, ``langfuse_stack``,
``app_secrets``, and ``gcp-gke/main.tf``:

1. ``<default>`` superuser is restricted to loopback (``127.0.0.1`` and ``::1``)
   with ``replace="replace"`` so ClickHouse overwrites ``users.xml``'s ``::/0``
   entry rather than appending to it, keeps ``access_management=0``, and
   ``clickhouse_operator/outputs.tf`` never exports the superuser password
   outside the module.
2. ``langfuse_app`` (``users.d/langfuse_user.xml``) reads its password from
   ``CLICKHOUSE_LANGFUSE_PASSWORD`` (own Secret ``clickhouse-langfuse-app``),
   defaults to ``langfuse``, disables ``access_management``, and holds grants
   strictly on ``langfuse.*`` — zero grants on ``default.*``, ``system.*``,
   or ``*.*``.
3. ``clickhouse_init_sql`` mounts ``01_databases.sql`` read-only into
   ``/docker-entrypoint-initdb.d`` so ``CREATE DATABASE IF NOT EXISTS langfuse;``
   runs over loopback before Langfuse migrations execute.
4. ``langfuse_stack`` injects ``CLICKHOUSE_DB`` into both ``langfuse-web`` and
   ``langfuse-worker``, ``gcp-gke/main.tf`` wires ``module.langfuse`` to
   ``langfuse_app`` + ``/langfuse`` migration URL, and ``app_secrets`` carries
   zero dead ClickHouse superuser pass-throughs.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO = Path(__file__).resolve().parents[2]
_CH_MAIN = _REPO / "infra/modules/clickhouse_operator/main.tf"
_CH_VARS = _REPO / "infra/modules/clickhouse_operator/variables.tf"
_CH_OUTPUTS = _REPO / "infra/modules/clickhouse_operator/outputs.tf"
_LF_MAIN = _REPO / "infra/modules/langfuse_stack/main.tf"
_LF_VARS = _REPO / "infra/modules/langfuse_stack/variables.tf"
_APP_SECRETS_VARS = _REPO / "infra/modules/app_secrets/variables.tf"
_GKE_MAIN = _REPO / "infra/targets/gcp-gke/main.tf"

_LANGFUSE_USER = "langfuse_app"
_LANGFUSE_DB = "langfuse"

_LANGFUSE_GRANT_RE = re.compile(rf"^GRANT [A-Z ,]+ ON {_LANGFUSE_DB}\.\*$")
_FORBIDDEN_LANGFUSE_PRIVS = {
    "ACCESS MANAGEMENT",
    "SYSTEM",
    "CREATE USER",
    "ALTER USER",
    "DROP USER",
    "CREATE ROLE",
}


class RBACViolation(AssertionError):
    """ClickHouse RBAC isolation invariant violated."""


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


def _check_default_loopback_only(xml_text: str) -> None:
    root = ET.fromstring(xml_text)
    default_user = root.find("users/default")
    if default_user is None:
        raise RBACViolation("<users><default> missing from networks.xml")
    if default_user.findtext("access_management", "").strip() != "0":
        raise RBACViolation(
            "<default> must set access_management=0 so loopback default cannot issue SQL RBAC grants"
        )
    networks = default_user.find("networks")
    if networks is None or networks.get("replace") != "replace":
        raise RBACViolation(
            '<default><networks> must set replace="replace" or ClickHouse appends to ::/0'
        )
    ips = [(ip.text or "").strip() for ip in networks.findall("ip")]
    if not ips or set(ips) != {"127.0.0.1", "::1"}:
        raise RBACViolation(
            f"<default> networks must contain exactly 127.0.0.1 and ::1, got {ips}"
        )


def _check_langfuse_user(xml_text: str, username: str) -> None:
    root = ET.fromstring(xml_text)
    user = root.find(f"users/{username}")
    if user is None:
        raise RBACViolation(f"langfuse user {username!r} not defined")
    pw = user.find("password")
    if pw is None or not pw.get("from_env") or (pw.text or "").strip():
        raise RBACViolation("langfuse password must come from env, not config")
    if user.findtext("default_database", "").strip() != _LANGFUSE_DB:
        raise RBACViolation("langfuse default_database must be langfuse")
    if user.findtext("access_management", "0").strip() != "0":
        raise RBACViolation("langfuse user must not hold access_management")
    grants = [(q.text or "").strip() for q in user.findall("grants/query")]
    if not grants or any(not _LANGFUSE_GRANT_RE.match(g) for g in grants):
        raise RBACViolation(
            f"langfuse grants must be scoped strictly to {_LANGFUSE_DB}.*: {grants}"
        )
    for grant in grants:
        for forbidden in _FORBIDDEN_LANGFUSE_PRIVS:
            if forbidden in grant:
                raise RBACViolation(f"forbidden privilege {forbidden} in {grant}")


# ---------------------------------------------------------------------------
# 1. Self-tests: the XML checkers fail closed on every widening mutation
# ---------------------------------------------------------------------------

_GOOD_NETWORKS = """<clickhouse><users><default>
<access_management>0</access_management>
<networks replace="replace"><ip>127.0.0.1</ip><ip>::1</ip></networks>
</default></users></clickhouse>"""

_GOOD_LANGFUSE = f"""<clickhouse>
<profiles><lp><readonly>0</readonly><allow_ddl>1</allow_ddl></lp></profiles>
<users><{_LANGFUSE_USER}><password from_env="CLICKHOUSE_LANGFUSE_PASSWORD"/>
<profile>lp</profile><default_database>{_LANGFUSE_DB}</default_database>
<access_management>0</access_management>
<grants><query>GRANT SHOW, SELECT, INSERT, ALTER, CREATE TABLE, TRUNCATE ON {_LANGFUSE_DB}.*</query></grants>
</{_LANGFUSE_USER}></users></clickhouse>"""


def test_checkers_accept_valid_configs() -> None:
    _check_default_loopback_only(_GOOD_NETWORKS)
    _check_langfuse_user(_GOOD_LANGFUSE, _LANGFUSE_USER)


@pytest.mark.parametrize(
    "mutation",
    [
        ('replace="replace"', ""),
        ("<ip>::1</ip>", "<ip>::1</ip><ip>::/0</ip>"),
        ("<ip>127.0.0.1</ip>", "<ip>0.0.0.0/0</ip>"),
        (
            "<access_management>0</access_management>",
            "<access_management>1</access_management>",
        ),
    ],
    ids=["missing-replace", "extra-wildcard-v6", "open-v4", "access-mgmt-enabled"],
)
def test_default_loopback_checker_rejects_widening(mutation: tuple[str, str]) -> None:
    bad = _GOOD_NETWORKS.replace(*mutation)
    assert bad != _GOOD_NETWORKS
    with pytest.raises(RBACViolation):
        _check_default_loopback_only(bad)


@pytest.mark.parametrize(
    "mutation",
    [
        ("ON langfuse.*", "ON *.*"),
        ("ON langfuse.*", "ON default.*"),
        ("ON langfuse.*", "ON system.*"),
        (
            "<default_database>langfuse</default_database>",
            "<default_database>default</default_database>",
        ),
        (
            "<access_management>0</access_management>",
            "<access_management>1</access_management>",
        ),
        (
            '<password from_env="CLICKHOUSE_LANGFUSE_PASSWORD"/>',
            "<password>literal</password>",
        ),
    ],
    ids=[
        "global-wildcard",
        "default-db-grant",
        "system-db-grant",
        "default-db-fallback",
        "access-mgmt",
        "literal-password",
    ],
)
def test_langfuse_checker_rejects_widening(mutation: tuple[str, str]) -> None:
    bad = _GOOD_LANGFUSE.replace(*mutation)
    assert bad != _GOOD_LANGFUSE
    with pytest.raises(RBACViolation):
        _check_langfuse_user(bad, _LANGFUSE_USER)


# ---------------------------------------------------------------------------
# 2. clickhouse_operator module RBAC & non-exported superuser password
# ---------------------------------------------------------------------------


def test_clickhouse_operator_restricts_default_user_to_loopback() -> None:
    xml_text = _tf_heredoc(_CH_MAIN.read_text(), "networks.xml")
    _check_default_loopback_only(xml_text)


def test_clickhouse_operator_does_not_export_admin_password() -> None:
    outputs = _CH_OUTPUTS.read_text()
    assert 'output "password"' not in outputs, (
        "clickhouse_operator must not export the loopback-only `default` superuser password"
    )
    assert "random_password.clickhouse.result" not in outputs


def test_clickhouse_operator_renders_least_privilege_langfuse_user() -> None:
    main = _CH_MAIN.read_text()
    langfuse_xml = (
        _tf_heredoc(main, "langfuse_user.xml")
        .replace("${var.langfuse_username}", _LANGFUSE_USER)
        .replace("${var.langfuse_database}", _LANGFUSE_DB)
    )
    _check_langfuse_user(langfuse_xml, _LANGFUSE_USER)


def test_clickhouse_statefulset_mounts_langfuse_user_and_init_sql_from_dedicated_secret() -> (
    None
):
    main = _CH_MAIN.read_text()
    for mount in (
        'mount_path = "/etc/clickhouse-server/users.d/langfuse_user.xml"',
        'mount_path = "/docker-entrypoint-initdb.d"',
    ):
        assert mount in main, f"Missing volume_mount {mount}"

    langfuse_env = _block(
        main[main.index('name = "CLICKHOUSE_LANGFUSE_PASSWORD"') :], "value_from"
    )
    assert "kubernetes_secret.langfuse_app.metadata[0].name" in langfuse_env

    secret_block = _block(main, 'resource "kubernetes_secret" "langfuse_app"')
    assert "random_password.langfuse_app.result" in secret_block
    assert "random_password.clickhouse.result" not in secret_block

    # Config rollout annotation hashes BOTH clickhouse_config and clickhouse_init_sql.
    assert "kubernetes_config_map.clickhouse_config.data" in main
    assert "kubernetes_config_map.clickhouse_init_sql.data" in main


def test_clickhouse_init_sql_configmap_creates_langfuse_database() -> None:
    main = _CH_MAIN.read_text()
    init_cm = _block(main, 'resource "kubernetes_config_map" "clickhouse_init_sql"')
    init_dbs = _tf_heredoc(init_cm, "01_databases.sql")
    assert "CREATE DATABASE IF NOT EXISTS ${var.langfuse_database};" in init_dbs
    assert "02_evidence_stream_schema.sql" not in init_cm


def test_clickhouse_operator_retires_evidence_sink_principal_and_secret() -> None:
    combined = (
        _CH_MAIN.read_text()
        + "\n"
        + _CH_VARS.read_text()
        + "\n"
        + _CH_OUTPUTS.read_text()
    )
    for retired in (
        "evidence_sink_user.xml",
        "CLICKHOUSE_EVIDENCE_SINK_PASSWORD",
        "evidence_sink",
        "cage_evidence",
        "evidence_database",
    ):
        assert retired not in combined, (
            f"Retired ClickHouse evidence token {retired!r} still present in clickhouse_operator"
        )


# ---------------------------------------------------------------------------
# 3. langfuse_stack, app_secrets & gcp-gke root target wiring
# ---------------------------------------------------------------------------


def test_langfuse_stack_sets_clickhouse_db_on_web_and_worker_and_forbids_default_user() -> (
    None
):
    lf_main = _LF_MAIN.read_text()
    web_block = _block(lf_main, 'resource "kubernetes_deployment" "langfuse_web"')
    worker_block = _block(lf_main, 'resource "kubernetes_deployment" "langfuse_worker"')
    for label, block in (
        ("langfuse_web", web_block),
        ("langfuse_worker", worker_block),
    ):
        assert 'name  = "CLICKHOUSE_DB"' in block, f"{label} missing CLICKHOUSE_DB env"
        assert "value = var.clickhouse_db" in block, (
            f"{label} CLICKHOUSE_DB not bound to var.clickhouse_db"
        )

    lf_vars = _LF_VARS.read_text()
    user_var = _block(lf_vars, 'variable "clickhouse_user"')
    assert f'default     = "{_LANGFUSE_USER}"' in user_var
    assert 'var.clickhouse_user != "default"' in user_var
    db_var = _block(lf_vars, 'variable "clickhouse_db"')
    assert f'default     = "{_LANGFUSE_DB}"' in db_var
    assert '"default"' in db_var and '"system"' in db_var
    mig_var = _block(lf_vars, 'variable "clickhouse_migration_url"')
    assert "^clickhouse://default[:@]" in mig_var


def test_gke_target_wires_langfuse_to_scoped_user_and_eliminates_superuser_consumers() -> (
    None
):
    gke_main = _GKE_MAIN.read_text()
    assert "module.clickhouse_operator.password" not in gke_main
    assert not re.search(r'clickhouse_user\s*=\s*"default"', gke_main)

    lf_call = _block(gke_main, 'module "langfuse"')
    assert (
        "clickhouse_db            = module.clickhouse_operator.langfuse_database"
        in lf_call
    )
    assert (
        "clickhouse_user          = module.clickhouse_operator.langfuse_username"
        in lf_call
    )
    assert (
        "clickhouse_password      = module.clickhouse_operator.langfuse_password"
        in lf_call
    )
    assert (
        'clickhouse_migration_url = "clickhouse://${module.clickhouse_operator.langfuse_username}:${module.clickhouse_operator.langfuse_password}@${module.clickhouse_operator.service_name}:${module.clickhouse_operator.tcp_port}/${module.clickhouse_operator.langfuse_database}"'
        in lf_call
    )

    app_secrets_call = _block(gke_main, 'module "app_secrets"')
    assert not re.search(r"^\s*clickhouse_\w+\s*=", app_secrets_call, re.M)
    assert "clickhouse_" not in _APP_SECRETS_VARS.read_text()

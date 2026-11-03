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

"""`scripts/gen_tfvars.py` merges into terraform.auto.tfvars (POAM-2026-164, EF11).

Before this fix the script rewrote the file with only
``otel_exporter_otlp_headers``, so an operator's ``authorized_networks`` was
erased on every ``deploy_all.sh --target gcp-gke`` run.
"""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from scripts import gen_tfvars

pytestmark = [pytest.mark.unit, pytest.mark.local]

HEADERS = "Authorization=Basic dGVzdDp0ZXN0"
NEW_HEADERS = "Authorization=Basic bmV3Om5ldw=="

AUTHORIZED_NETWORKS = """\
# Deployer egress and VPN (operator-set; gen_tfvars.py must keep this).
authorized_networks = [
  { cidr = "203.0.113.10/32", display_name = "deployer egress" },
  {
    cidr         = "198.51.100.0/24" # office VPN
    display_name = "vpn [primary] {eu}"
  },
]"""

OTHER_KEYS = """\
kms_key_id = "projects/<PROJECT_ID>/locations/<ZONE>/keyRings/r/cryptoKeys/k"

startup_note = <<-EOT
  brackets ] } ) inside a heredoc are text
  EOT

replica_count = 3 // trailing comment
"""


def _write_env(tmp_path: Path, headers: str) -> Path:
    env_file = tmp_path / ".env"
    env_file.write_text(f'OTEL_EXPORTER_OTLP_HEADERS="{headers}"\n', encoding="utf-8")
    return env_file


def _run(env_file: Path, out_file: Path) -> int:
    return gen_tfvars.main(["--env", str(env_file), "--output", str(out_file)])


def _by_key(text: str) -> dict[str, str]:
    return {a.key: a.text for a in gen_tfvars.parse_tfvars_assignments(text)}


def test_existing_authorized_networks_survives_with_exact_value(tmp_path: Path) -> None:
    out_file = tmp_path / "terraform.auto.tfvars"
    out_file.write_text(
        f'otel_exporter_otlp_headers = "stale"\n\n{AUTHORIZED_NETWORKS}\n\n{OTHER_KEYS}',
        encoding="utf-8",
    )

    assert _run(_write_env(tmp_path, HEADERS), out_file) == 0

    rendered = out_file.read_text(encoding="utf-8")
    assert AUTHORIZED_NETWORKS in rendered
    keys = _by_key(rendered)
    assert keys["authorized_networks"] == AUTHORIZED_NETWORKS
    assert set(keys) == {
        "authorized_networks",
        "kms_key_id",
        "startup_note",
        "replica_count",
        "otel_exporter_otlp_headers",
    }
    for key, text in _by_key(OTHER_KEYS).items():
        assert keys[key] == text


def test_otel_headers_present_and_current(tmp_path: Path) -> None:
    out_file = tmp_path / "terraform.auto.tfvars"
    out_file.write_text(
        f'{AUTHORIZED_NETWORKS}\n\notel_exporter_otlp_headers = "{HEADERS}"\n',
        encoding="utf-8",
    )

    assert _run(_write_env(tmp_path, NEW_HEADERS), out_file) == 0

    rendered = out_file.read_text(encoding="utf-8")
    assert _by_key(rendered)["otel_exporter_otlp_headers"] == (
        f'otel_exporter_otlp_headers = "{NEW_HEADERS}"'
    )
    assert rendered.count("otel_exporter_otlp_headers =") == 1
    assert HEADERS not in rendered


def test_two_consecutive_runs_are_byte_identical(tmp_path: Path) -> None:
    out_file = tmp_path / "terraform.auto.tfvars"
    out_file.write_text(
        f"# standalone note\n\n{AUTHORIZED_NETWORKS}\n{OTHER_KEYS}", encoding="utf-8"
    )
    env_file = _write_env(tmp_path, HEADERS)

    assert _run(env_file, out_file) == 0
    first = out_file.read_bytes()
    assert _run(env_file, out_file) == 0
    assert out_file.read_bytes() == first


def test_absent_file_is_created(tmp_path: Path) -> None:
    out_file = tmp_path / "nested" / "terraform.auto.tfvars"
    env_file = _write_env(tmp_path, HEADERS)

    assert _run(env_file, out_file) == 0

    rendered = out_file.read_text(encoding="utf-8")
    assert rendered == gen_tfvars.build_tfvars_content(HEADERS, env_file)
    assert _by_key(rendered) == {
        "otel_exporter_otlp_headers": f'otel_exporter_otlp_headers = "{HEADERS}"'
    }
    assert rendered.endswith(f'otel_exporter_otlp_headers = "{HEADERS}"\n')
    assert stat.S_IMODE(out_file.stat().st_mode) == 0o600
    assert [p.name for p in out_file.parent.iterdir()] == ["terraform.auto.tfvars"]


def test_unparseable_existing_file_is_left_untouched(tmp_path: Path) -> None:
    out_file = tmp_path / "terraform.auto.tfvars"
    broken = 'authorized_networks = [\n  { cidr = "203.0.113.10/32" },\n'
    out_file.write_text(broken, encoding="utf-8")

    assert _run(_write_env(tmp_path, HEADERS), out_file) == 1
    assert out_file.read_text(encoding="utf-8") == broken


@pytest.mark.parametrize(
    "text",
    [
        "a = 1\na = 2\n",
        "resource {\n}\n",
        'a = "unterminated\n',
        "a = [1, 2)\n",
        "a =\n",
        "a = <<EOT\nno terminator\n",
    ],
)
def test_parser_rejects_malformed_input(text: str) -> None:
    with pytest.raises(gen_tfvars.TfvarsParseError):
        gen_tfvars.parse_tfvars_assignments(text)


def test_parse_error_messages_do_not_echo_values() -> None:
    with pytest.raises(gen_tfvars.TfvarsParseError) as exc_info:
        gen_tfvars.parse_tfvars_assignments('secret = "s3cr3t-value\n')
    assert "s3cr3t-value" not in str(exc_info.value)


def test_dry_run_leaves_existing_file_untouched(tmp_path: Path) -> None:
    out_file = tmp_path / "terraform.auto.tfvars"
    out_file.write_text(f"{AUTHORIZED_NETWORKS}\n", encoding="utf-8")
    env_file = _write_env(tmp_path, HEADERS)

    rc = gen_tfvars.main(
        ["--env", str(env_file), "--output", str(out_file), "--dry-run"]
    )
    assert rc == 0
    assert out_file.read_text(encoding="utf-8") == f"{AUTHORIZED_NETWORKS}\n"

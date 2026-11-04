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
"""POAM-2026-182: GKE ``database_encryption`` ``ignore_changes`` workaround and self-firing provider-schema check.

On GKE 1.32+, enabling CMEK on a cluster reports ``databaseEncryption.state =
"ALL_OBJECTS_ENCRYPTION_ENABLED"`` on ``GET``. In ``hashicorp/google`` 6.50.0,
``google_container_cluster.database_encryption.state`` validates against
``["ENCRYPTED", "DECRYPTED"]`` and rejects ``"ALL_OBJECTS_ENCRYPTION_ENABLED"``
at plan/validate time. When ``database_encryption`` is not in
``lifecycle.ignore_changes``, every ``terraform apply`` sees
``"ALL_OBJECTS_ENCRYPTION_ENABLED" -> "ENCRYPTED"``, sends ``UpdateCluster``
(``desiredDatabaseEncryption``), runs a ~9-minute control-plane operation, and
reads ``"ALL_OBJECTS_ENCRYPTION_ENABLED"`` back again (observed across four
consecutive ``UpdateCluster`` operations on ``cage-staging`` on 2026-09-29).

This test does two things:
1. Pins the workaround in ``infra/modules/gcp_gke_cluster/main.tf`` and the
   removal of the dead ``database_encryption_state`` variable from ``infra/``.
2. Asserts that ``ALL_OBJECTS_ENCRYPTION_ENABLED`` is still absent from the
   ``hashicorp/google`` provider schema and rejected by ``terraform validate``.
   The moment a provider upgrade adds ``ALL_OBJECTS_ENCRYPTION_ENABLED``, this
   check fails so ``database_encryption`` is removed from ``ignore_changes``
   and ``POAM-2026-182`` is closed instead of decaying into folklore.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

try:
    import pytest
except ModuleNotFoundError:  # pragma: no cover - bare python3 in terraform-test job
    import types

    pytest = types.SimpleNamespace(  # type: ignore[assignment]
        mark=types.SimpleNamespace(unit="unit", local="local")
    )

pytestmark = [pytest.mark.unit, pytest.mark.local]


@contextmanager
def _expect_assertion_error(match: str) -> Iterator[None]:
    try:
        yield
    except AssertionError as exc:
        if not re.search(match, str(exc)):
            raise AssertionError(
                f"Expected AssertionError matching {match!r}, got {str(exc)!r}"
            ) from exc
        return
    raise AssertionError(f"Expected AssertionError matching {match!r}, but none raised")


REPO_ROOT = Path(__file__).resolve().parents[2]
GKE_TARGET_DIR = REPO_ROOT / "infra" / "targets" / "gcp-gke"
GKE_CLUSTER_MODULE_DIR = REPO_ROOT / "infra" / "modules" / "gcp_gke_cluster"
PROVIDERS_DIR = GKE_TARGET_DIR / ".terraform" / "providers"

ALL_OBJECTS_STATE = "ALL_OBJECTS_ENCRYPTION_ENABLED"

_PROBE_TF_TEMPLATE = """\
terraform {{
  required_providers {{
    google = {{
      source = "hashicorp/google"
    }}
  }}
}}

resource "google_container_cluster" "probe" {{
  name     = "probe"
  location = "us-central1-a"

  database_encryption {{
    state    = "{state}"
    key_name = "projects/probe-project/locations/us-central1/keyRings/probe-ring/cryptoKeys/probe-key"
  }}
}}
"""


def _strip_comments(text: str) -> str:
    return "\n".join(
        re.sub(r"(#|//).*$", "", line)
        for line in text.splitlines()
        if not line.lstrip().startswith(("#", "//"))
    )


def assert_no_dead_database_encryption_state(tf_paths: list[Path]) -> None:
    """Fail if any .tf or .tfvars file still references database_encryption_state."""
    offenders: list[str] = []
    for path in tf_paths:
        clean = _strip_comments(path.read_text(encoding="utf-8"))
        if re.search(r"\bdatabase_encryption_state\b", clean):
            offenders.append(str(path))
    assert not offenders, (
        "Dead variable database_encryption_state was reintroduced in "
        f"{offenders} (POAM-2026-182)"
    )


def assert_cluster_hcl_workaround(cluster_main_tf: str) -> None:
    """Verify google_container_cluster.primary keeps state = ENCRYPTED and ignore_changes."""
    start = cluster_main_tf.find('resource "google_container_cluster" "primary"')
    assert start != -1, "resource google_container_cluster.primary is missing"
    end = cluster_main_tf.find("\n}\n", start)
    primary_block = cluster_main_tf[start : end if end != -1 else len(cluster_main_tf)]

    enc_match = re.search(
        r'dynamic\s+"database_encryption"\s*\{(.*?)\n  \}',
        primary_block,
        re.DOTALL,
    )
    assert enc_match is not None, (
        'google_container_cluster.primary must define dynamic "database_encryption"'
    )
    enc_body = _strip_comments(enc_match.group(1))
    assert re.search(r'\bstate\s*=\s*"ENCRYPTED"', enc_body), (
        'database_encryption must set state = "ENCRYPTED" while provider rejects '
        f"{ALL_OBJECTS_STATE} (POAM-2026-182)"
    )
    assert re.search(r"\bkey_name\s*=\s*var\.kms_key_id\b", enc_body), (
        "database_encryption must bind key_name = var.kms_key_id"
    )

    ic_match = re.search(
        r"ignore_changes\s*=\s*\[(.*?)\]",
        primary_block,
        re.DOTALL,
    )
    assert ic_match is not None, (
        "google_container_cluster.primary must define lifecycle.ignore_changes"
    )
    ic_raw = ic_match.group(1)
    ic_clean = _strip_comments(ic_raw)
    assert re.search(r"\bdatabase_encryption\b(?!\s*\[)", ic_clean), (
        "google_container_cluster.primary lifecycle.ignore_changes must include "
        "whole-block database_encryption (not database_encryption[0].state, which "
        "merges state = DECRYPTED with a non-empty key_name; POAM-2026-182)"
    )
    assert "POAM-2026-182" in ic_raw, (
        "database_encryption in ignore_changes must cite POAM-2026-182"
    )


def assert_schema_lacks_all_objects_encryption(schema_data: dict[str, Any]) -> None:
    """Fail if the provider schema for google_container_cluster mentions ALL_OBJECTS_ENCRYPTION_ENABLED."""
    try:
        db_enc = schema_data["provider_schemas"][
            "registry.terraform.io/hashicorp/google"
        ]["resource_schemas"]["google_container_cluster"]["block"]["block_types"][
            "database_encryption"
        ]
        block_desc = db_enc["block"]["description"]
        state_desc = db_enc["block"]["attributes"]["state"]["description"]
    except (KeyError, TypeError) as exc:
        raise AssertionError(
            "Provider schema is missing google_container_cluster.database_encryption.state"
        ) from exc

    for label, desc in (
        ("database_encryption.description", block_desc),
        ("database_encryption.state.description", state_desc),
    ):
        assert isinstance(desc, str) and "ENCRYPTED" in desc and "DECRYPTED" in desc, (
            f"Provider schema {label} did not list ENCRYPTED and DECRYPTED "
            f"(got {desc!r}); check cannot pass vacuously"
        )
        assert ALL_OBJECTS_STATE not in desc, (
            f"hashicorp/google provider schema now includes {ALL_OBJECTS_STATE} in "
            f"google_container_cluster.{label}! Remove "
            "database_encryption from lifecycle.ignore_changes in "
            "infra/modules/gcp_gke_cluster/main.tf and close POAM-2026-182 in docs/POAM.md."
        )


def assert_validate_rejects_all_objects_encryption(
    validate_data: dict[str, Any],
) -> None:
    """Fail if terraform validate accepts state = ALL_OBJECTS_ENCRYPTION_ENABLED."""
    assert validate_data.get("valid") is False, (
        f'hashicorp/google now accepts state = "{ALL_OBJECTS_STATE}" on '
        "google_container_cluster.database_encryption! Remove database_encryption "
        "from lifecycle.ignore_changes in infra/modules/gcp_gke_cluster/main.tf "
        "and close POAM-2026-182 in docs/POAM.md."
    )
    diagnostics = validate_data.get("diagnostics") or []
    matching = [
        d
        for d in diagnostics
        if d.get("severity") == "error"
        and "database_encryption.0.state" in (d.get("summary") or "")
        and ALL_OBJECTS_STATE in (d.get("summary") or "")
    ]
    assert matching, (
        "terraform validate failed for an unexpected reason instead of "
        f"rejecting database_encryption.0.state = {ALL_OBJECTS_STATE}: {diagnostics!r}"
    )


def run_live_provider_check(
    providers_dir: Path = PROVIDERS_DIR,
    terraform_bin: str | None = None,
) -> None:
    """Run terraform providers schema -json and terraform validate -json against the installed provider."""
    resolved_tf = terraform_bin or shutil.which("terraform")
    assert resolved_tf is not None, "terraform binary not found on PATH"
    assert providers_dir.is_dir(), (
        f"Initialized provider directory {providers_dir} not found; "
        "run `terraform -chdir=infra/targets/gcp-gke init -backend=false` first"
    )

    with tempfile.TemporaryDirectory(prefix="cage_poam_182_") as tmp:
        tmp_path = Path(tmp)
        (tmp_path / "main.tf").write_text(
            _PROBE_TF_TEMPLATE.format(state=ALL_OBJECTS_STATE),
            encoding="utf-8",
        )
        subprocess.run(
            [
                resolved_tf,
                f"-chdir={tmp_path}",
                "init",
                "-backend=false",
                "-input=false",
                "-no-color",
                f"-plugin-dir={providers_dir}",
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        schema_res = subprocess.run(
            [resolved_tf, f"-chdir={tmp_path}", "providers", "schema", "-json"],
            check=True,
            capture_output=True,
            text=True,
        )
        assert_schema_lacks_all_objects_encryption(json.loads(schema_res.stdout))

        val_reject = subprocess.run(
            [resolved_tf, f"-chdir={tmp_path}", "validate", "-json"],
            check=False,
            capture_output=True,
            text=True,
        )
        assert_validate_rejects_all_objects_encryption(json.loads(val_reject.stdout))

        # Control probe: state = "ENCRYPTED" on the identical resource validates cleanly.
        (tmp_path / "main.tf").write_text(
            _PROBE_TF_TEMPLATE.format(state="ENCRYPTED"),
            encoding="utf-8",
        )
        val_accept = subprocess.run(
            [resolved_tf, f"-chdir={tmp_path}", "validate", "-json"],
            check=False,
            capture_output=True,
            text=True,
        )
        accept_data = json.loads(val_accept.stdout)
        assert accept_data.get("valid") is True, (
            f'Control probe with state = "ENCRYPTED" failed validation: {accept_data!r}'
        )


# ─── Repository HCL & Provider Tests ─────────────────────────────────────────


def test_database_encryption_state_variable_is_removed() -> None:
    tf_paths = sorted(
        p
        for p in (REPO_ROOT / "infra").rglob("*")
        if p.suffix in {".tf", ".tfvars"}
        and not any(part.startswith(".terraform") for part in p.parts)
    )
    assert tf_paths
    assert_no_dead_database_encryption_state(tf_paths)


def test_gke_cluster_keeps_database_encryption_in_ignore_changes() -> None:
    cluster_main = (GKE_CLUSTER_MODULE_DIR / "main.tf").read_text(encoding="utf-8")
    assert_cluster_hcl_workaround(cluster_main)


def test_live_provider_schema_and_validator_when_initialized() -> None:
    if shutil.which("terraform") is None or not PROVIDERS_DIR.is_dir():
        pytest.skip(
            "terraform or initialized .terraform/providers not present on this runner; "
            "enforced unconditionally in CI job 'Terraform Tests (gcp-gke, mock providers)'"
        )
    run_live_provider_check(PROVIDERS_DIR)


# ─── Detector Mutation / Planted-Defect Tests ────────────────────────────────


_SYNTHETIC_6_50_SCHEMA: dict[str, Any] = {
    "provider_schemas": {
        "registry.terraform.io/hashicorp/google": {
            "resource_schemas": {
                "google_container_cluster": {
                    "block": {
                        "block_types": {
                            "database_encryption": {
                                "nesting_mode": "list",
                                "block": {
                                    "attributes": {
                                        "key_name": {
                                            "type": "string",
                                            "description": "The key to use to encrypt/decrypt secrets.",
                                            "optional": True,
                                        },
                                        "state": {
                                            "type": "string",
                                            "description": "ENCRYPTED or DECRYPTED.",
                                            "required": True,
                                        },
                                    },
                                    "description": (
                                        "Application-layer Secrets Encryption settings. "
                                        'Valid values of state are: "ENCRYPTED"; "DECRYPTED".'
                                    ),
                                },
                                "max_items": 1,
                            }
                        }
                    }
                }
            }
        }
    }
}


def test_schema_detector_accepts_6_50_schema() -> None:
    assert_schema_lacks_all_objects_encryption(_SYNTHETIC_6_50_SCHEMA)


def test_schema_detector_fails_when_provider_adds_all_objects_encryption() -> None:
    upgraded_state = copy.deepcopy(_SYNTHETIC_6_50_SCHEMA)
    state_attr = upgraded_state["provider_schemas"][
        "registry.terraform.io/hashicorp/google"
    ]["resource_schemas"]["google_container_cluster"]["block"]["block_types"][
        "database_encryption"
    ]["block"]["attributes"]["state"]
    state_attr["description"] = (
        "ENCRYPTED, DECRYPTED, or ALL_OBJECTS_ENCRYPTION_ENABLED."
    )
    with _expect_assertion_error("POAM-2026-182"):
        assert_schema_lacks_all_objects_encryption(upgraded_state)

    upgraded_block = copy.deepcopy(_SYNTHETIC_6_50_SCHEMA)
    db_block = upgraded_block["provider_schemas"][
        "registry.terraform.io/hashicorp/google"
    ]["resource_schemas"]["google_container_cluster"]["block"]["block_types"][
        "database_encryption"
    ]["block"]
    db_block["description"] = (
        'Valid values of state are: "ENCRYPTED"; "DECRYPTED"; '
        '"ALL_OBJECTS_ENCRYPTION_ENABLED".'
    )
    with _expect_assertion_error("POAM-2026-182"):
        assert_schema_lacks_all_objects_encryption(upgraded_block)


def test_schema_detector_refuses_vacuous_or_missing_schema() -> None:
    with _expect_assertion_error("missing"):
        assert_schema_lacks_all_objects_encryption({})

    # Neither block.description nor state.description may silently return empty
    # and be masked by the other.
    blank_state = copy.deepcopy(_SYNTHETIC_6_50_SCHEMA)
    blank_state["provider_schemas"]["registry.terraform.io/hashicorp/google"][
        "resource_schemas"
    ]["google_container_cluster"]["block"]["block_types"]["database_encryption"][
        "block"
    ]["attributes"]["state"]["description"] = ""
    with _expect_assertion_error("cannot pass vacuously"):
        assert_schema_lacks_all_objects_encryption(blank_state)

    blank_block = copy.deepcopy(_SYNTHETIC_6_50_SCHEMA)
    blank_block["provider_schemas"]["registry.terraform.io/hashicorp/google"][
        "resource_schemas"
    ]["google_container_cluster"]["block"]["block_types"]["database_encryption"][
        "block"
    ]["description"] = ""
    with _expect_assertion_error("cannot pass vacuously"):
        assert_schema_lacks_all_objects_encryption(blank_block)


def test_validate_detector_fails_when_provider_accepts_all_objects_state() -> None:
    with _expect_assertion_error("POAM-2026-182"):
        assert_validate_rejects_all_objects_encryption(
            {"valid": True, "error_count": 0, "diagnostics": []}
        )


def test_validate_detector_fails_on_unrelated_validation_error() -> None:
    with _expect_assertion_error("unexpected reason"):
        assert_validate_rejects_all_objects_encryption(
            {
                "valid": False,
                "error_count": 1,
                "diagnostics": [
                    {
                        "severity": "error",
                        "summary": "Missing required argument: location",
                    }
                ],
            }
        )


def test_hcl_detector_fails_if_database_encryption_dropped_or_narrowed() -> None:
    cluster_main = (GKE_CLUSTER_MODULE_DIR / "main.tf").read_text(encoding="utf-8")
    dropped = re.sub(
        r"^\s*database_encryption,.*$\n",
        "",
        cluster_main,
        flags=re.MULTILINE,
    )
    with _expect_assertion_error("POAM-2026-182"):
        assert_cluster_hcl_workaround(dropped)

    narrowed = cluster_main.replace(
        "database_encryption,", "database_encryption[0].state,"
    )
    with _expect_assertion_error("POAM-2026-182"):
        assert_cluster_hcl_workaround(narrowed)


def test_hcl_detector_fails_if_dead_variable_reintroduced(tmp_path: Path) -> None:
    tf_file = tmp_path / "variables.tf"
    tf_file.write_text(
        'variable "database_encryption_state" {\n  type = string\n}\n',
        encoding="utf-8",
    )
    with _expect_assertion_error("database_encryption_state"):
        assert_no_dead_database_encryption_state([tf_file])


def _write_stub_terraform(
    bin_path: Path,
    *,
    schema_payload: dict[str, Any],
    reject_all_objects: bool = True,
    accept_encrypted: bool = True,
) -> Path:
    script = f"""#!{sys.executable}
import json
import pathlib
import sys

args = sys.argv[1:]
chdir = "."
for a in args:
    if a.startswith("-chdir="):
        chdir = a.split("=", 1)[1]

if "init" in args:
    sys.exit(0)
if "providers" in args and "schema" in args:
    print(json.dumps({schema_payload!r}))
    sys.exit(0)
if "validate" in args:
    main_tf = (pathlib.Path(chdir) / "main.tf").read_text(encoding="utf-8")
    if 'state    = "{ALL_OBJECTS_STATE}"' in main_tf:
        if {reject_all_objects!r}:
            print(json.dumps({{
                "valid": False,
                "error_count": 1,
                "diagnostics": [{{
                    "severity": "error",
                    "summary": 'expected database_encryption.0.state to be one of ["ENCRYPTED" "DECRYPTED"], got {ALL_OBJECTS_STATE}',
                }}],
            }}))
            sys.exit(1)
        print(json.dumps({{"valid": True, "error_count": 0, "diagnostics": []}}))
        sys.exit(0)
    if 'state    = "ENCRYPTED"' in main_tf:
        print(json.dumps({{"valid": {accept_encrypted!r}, "error_count": 0 if {accept_encrypted!r} else 1, "diagnostics": []}}))
        sys.exit(0 if {accept_encrypted!r} else 1)
sys.exit(2)
"""
    bin_path.write_text(script, encoding="utf-8")
    bin_path.chmod(0o755)
    return bin_path


def test_run_live_provider_check_end_to_end_mutations(tmp_path: Path) -> None:
    providers_dir = tmp_path / "providers"
    providers_dir.mkdir()
    tf_bin = tmp_path / "terraform"

    # Baseline 6.50.0 behavior: passes.
    _write_stub_terraform(tf_bin, schema_payload=_SYNTHETIC_6_50_SCHEMA)
    run_live_provider_check(providers_dir=providers_dir, terraform_bin=str(tf_bin))

    # Mutation 1: schema lookup includes ALL_OBJECTS_ENCRYPTION_ENABLED -> fails red.
    upgraded_schema = copy.deepcopy(_SYNTHETIC_6_50_SCHEMA)
    upgraded_schema["provider_schemas"]["registry.terraform.io/hashicorp/google"][
        "resource_schemas"
    ]["google_container_cluster"]["block"]["block_types"]["database_encryption"][
        "block"
    ]["attributes"]["state"][
        "description"
    ] = "ENCRYPTED, DECRYPTED, or ALL_OBJECTS_ENCRYPTION_ENABLED."
    _write_stub_terraform(tf_bin, schema_payload=upgraded_schema)
    with _expect_assertion_error("POAM-2026-182"):
        run_live_provider_check(providers_dir=providers_dir, terraform_bin=str(tf_bin))

    # Mutation 2: schema lookup returns empty dict -> fails red (no vacuous pass).
    _write_stub_terraform(tf_bin, schema_payload={})
    with _expect_assertion_error("missing"):
        run_live_provider_check(providers_dir=providers_dir, terraform_bin=str(tf_bin))

    # Mutation 3: validate -json accepts ALL_OBJECTS_ENCRYPTION_ENABLED -> fails red.
    _write_stub_terraform(
        tf_bin,
        schema_payload=_SYNTHETIC_6_50_SCHEMA,
        reject_all_objects=False,
    )
    with _expect_assertion_error("POAM-2026-182"):
        run_live_provider_check(providers_dir=providers_dir, terraform_bin=str(tf_bin))

    # Mutation 4: control probe with state = "ENCRYPTED" fails -> fails red.
    _write_stub_terraform(
        tf_bin,
        schema_payload=_SYNTHETIC_6_50_SCHEMA,
        accept_encrypted=False,
    )
    with _expect_assertion_error('Control probe with state = "ENCRYPTED" failed'):
        run_live_provider_check(providers_dir=providers_dir, terraform_bin=str(tf_bin))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify POAM-2026-182 GKE database_encryption provider workaround."
    )
    parser.add_argument(
        "--require-provider",
        action="store_true",
        help="Require terraform and the initialized hashicorp/google provider binary.",
    )
    args = parser.parse_args(argv)

    test_database_encryption_state_variable_is_removed()
    test_gke_cluster_keeps_database_encryption_in_ignore_changes()
    test_schema_detector_accepts_6_50_schema()
    test_schema_detector_fails_when_provider_adds_all_objects_encryption()
    test_schema_detector_refuses_vacuous_or_missing_schema()
    test_validate_detector_fails_when_provider_accepts_all_objects_state()
    test_validate_detector_fails_on_unrelated_validation_error()
    test_hcl_detector_fails_if_database_encryption_dropped_or_narrowed()
    with tempfile.TemporaryDirectory(prefix="cage_poam_182_mut_") as mut_tmp:
        test_run_live_provider_check_end_to_end_mutations(Path(mut_tmp))
    if args.require_provider:
        run_live_provider_check(PROVIDERS_DIR)
    return 0


if __name__ == "__main__":
    sys.exit(main())

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
"""Wave 1C GKE WIF, Secret Hygiene, NetworkPolicy, Guard & Container Security Tests.

Covers findings ``[IC-01]`` through ``[IC-09]`` plus ``[KC-13]`` gateway Dockerfile
supply-chain pins:
- ``[IC-01]``: WIF ``cage-partner-harness`` holds zero impersonation bindings on ``cage-gateway``.
- ``[IC-02]``: ``.gcloudignore``, ``.dockerignore``, and ``.gitignore`` exclude keys, certs,
  ``.tfvars``, ``tfplan*``, ``scratch/``, and ``.env*``; ``Dockerfile.local-dev`` avoids
  ``COPY . .`` and runs as non-root UID 1000.
- ``[IC-03]``: ``gateway_egress_l3_l4`` (and every NetworkPolicy in ``network_policy.tf``)
  has zero peerless ``egress`` / ``ingress`` rules.
- ``[IC-04]``: ``google_container_cluster.primary`` reconciles ``master_authorized_networks_config``
  and ``monitoring_config`` (not silenced in ``ignore_changes``), and all root
  ``terraform_data`` guards are wired via ``depends_on`` (zero standalone guards).
- ``[IC-05]``: ``vllm_sitecustomize.py`` enforces canonical path containment against
  ``..``, absolute paths, NUL bytes, backslashes, and symlink escapes; ``Dockerfile.vllm``
  pins dependencies and runs as non-root UID 1000.
- ``[IC-06]``: ``mirror_models.py`` and ``upload_to_gcs.py`` require 40-hex commit SHA
  ``revision`` pins and ``.safetensors`` verification.
- ``[IC-07]``: ``update_langfuse_secret.py`` pipes Secrets over stdin to ``kubectl apply -f -``
  with zero ``--from-literal`` ``argv`` exposure, prompts passwords via ``getpass.getpass``,
  and scrubs credentials from errors; ``deploy_all.sh`` cleans up ``tfplan*`` via ``trap``;
  ``infra/load_env.sh`` is sourced-safe and exports only ``TF_VAR_*`` variables.
- ``[IC-08]``: Runtime ``compliance-bridge`` holds no ``roles/artifactregistry.writer``;
  Secret Manager access uses per-secret ``google_secret_manager_secret_iam_member``;
  ``memorystore_app`` follows its own ``enable_memorystore_app_*`` switches, never the
  governance instance's (``test_memorystore_client_capability.py`` checks that no instance
  turns on IAM auth or TLS while a client cannot follow); ``langfuse_event_upload``
  enforces CMEK, ``uniform_bucket_level_access``, and ``public_access_prevention = "enforced"``.
- ``[IC-09]`` & ``[KC-13]``: ``src/gateway/Dockerfile`` keeps ``/app`` root-owned, pins ``uv``
  by ``@sha256:`` digest, and verifies ``en_core_web_lg`` with ``--require-hashes``; runtime
  workload modules set ``automountServiceAccountToken: false`` and ``readOnlyRootFilesystem: true``.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import types
from collections import Counter
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from scripts import check_k8s_terraform_parity as parity
from tests.infrastructure.test_guard_placement import _all_standalone_guards

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
GKE_DIR = REPO_ROOT / "infra" / "targets" / "gcp-gke"
MODULES_DIR = REPO_ROOT / "infra" / "modules"


# ---------------------------------------------------------------------------
# [IC-01] WIF Privilege-Escalation Elimination
# ---------------------------------------------------------------------------


def test_ic01_wif_partner_harness_has_zero_gateway_impersonation() -> None:
    wif_tf = (GKE_DIR / "wif.tf").read_text(encoding="utf-8")
    assert "gateway_partner_token_creator" not in wif_tf
    assert "google_service_account.gateway" not in wif_tf
    assert (
        'resource "google_cloud_run_v2_service_iam_member" "partner_harness_invoker"'
        in wif_tf
    )
    assert 'role     = "roles/run.invoker"' in wif_tf


# ---------------------------------------------------------------------------
# [IC-02] Build Context & Git Ignore Hardening + Dockerfile.local-dev
# ---------------------------------------------------------------------------


def test_ic02_gcloudignore_and_dockerignore_exclude_secrets_keys_and_tfplans() -> None:
    required_patterns = (
        "**/*.key",
        "**/*.pem",
        "**/*.tfvars",
        "**/*.tfvars.json",
        "**/tfplan*",
        "**/scratch/",
        "**/.env",
        "**/.env.*",
    )
    gcloudignore = (REPO_ROOT / ".gcloudignore").read_text(encoding="utf-8")
    dockerignore = (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8")
    for pattern in required_patterns:
        assert pattern in gcloudignore, f".gcloudignore missing {pattern}"
        assert pattern in dockerignore, f".dockerignore missing {pattern}"
    assert "/deployment/certs/" in gcloudignore
    assert "deployment/certs/" in dockerignore


def test_ic02_gitignore_blocks_untracked_keys_tfvars_and_tfplans_while_preserving_profiles() -> (
    None
):
    must_ignore = [
        "deployment/certs/provider_02/client.key",
        "deployment/certs/provider_02/server.crt",
        "nested/dir/private.pem",
        "nested/dir/.env.production",
        "nested/scratch/notes.txt",
        "infra/targets/gcp-gke/terraform.auto.tfvars",
        "infra/targets/gcp-gke/custom-secrets.tfvars",
        "infra/targets/gcp-gke/tfplan.stage1",
        "infra/targets/gcp-gke/image_digests.abc1234.tfvars.json",
    ]
    proc = subprocess.run(
        ["git", "check-ignore", "--stdin"],
        cwd=REPO_ROOT,
        input="\n".join(must_ignore) + "\n",
        text=True,
        capture_output=True,
        check=False,
    )
    ignored = set(proc.stdout.splitlines())
    assert ignored == set(must_ignore), (
        f"Unignored sensitive paths: {set(must_ignore) - ignored}"
    )

    must_keep = [
        "infra/targets/gcp-gke/staging.tfvars",
        "infra/targets/gcp-gke/prod.tfvars",
        "infra/targets/gcp-gke/eu-prod.tfvars",
        "infra/targets/gcp-gke/apac-prod.tfvars",
        "infra/targets/gcp-gke/tests/fixtures/image_digests.tfvars",
        "deployment/certs/actuator_01/ca.crt",
        "deployment/certs/actuator_01/client.crt",
        ".env.example",
        "config/environments/local-dev.env.example",
    ]
    keep_proc = subprocess.run(
        ["git", "check-ignore", "--stdin"],
        cwd=REPO_ROOT,
        input="\n".join(must_keep) + "\n",
        text=True,
        capture_output=True,
        check=False,
    )
    assert keep_proc.stdout.strip() == "", (
        f"Tracked profile/example files erroneously matched by .gitignore: {keep_proc.stdout}"
    )


def test_ic02_dockerfile_local_dev_scopes_copy_and_runs_non_root() -> None:
    dockerfile = (
        REPO_ROOT / "deployment" / "docker" / "Dockerfile.local-dev"
    ).read_text(encoding="utf-8")
    active_lines = [
        line.strip()
        for line in dockerfile.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert not any(re.match(r"^COPY\s+\.\s+\.$", line) for line in active_lines)
    assert any(line.startswith("COPY src /app/src") for line in active_lines)
    assert any(line.startswith("COPY config /app/config") for line in active_lines)
    assert any(line == "USER 1000:1000" for line in active_lines)
    assert "ghcr.io/astral-sh/uv:" in dockerfile and "@sha256:" in dockerfile


# ---------------------------------------------------------------------------
# [IC-03] NetworkPolicy Peer Containment (No Unrestricted TCP 4143 Egress)
# ---------------------------------------------------------------------------


def test_ic03_every_network_policy_rule_declares_explicit_peers() -> None:
    netpol_path = GKE_DIR / "network_policy.tf"
    cleaned = parity._strip_hcl_comments(netpol_path.read_text(encoding="utf-8"))
    peerless_rules: list[str] = []
    checked_policies = 0

    for block in parity._iter_top_blocks(cleaned, netpol_path):
        if "kubernetes_network_policy" not in block.header:
            continue
        checked_policies += 1
        spec = parity._find_child_blocks(
            block.body, "spec", netpol_path, block.start_line
        )[0]
        for direction, peer_attr in (("egress", "to"), ("ingress", "from")):
            for rule in parity._find_child_blocks(
                spec.body, direction, netpol_path, spec.start_line
            ):
                peers = parity._find_child_blocks(
                    rule.body, peer_attr, netpol_path, rule.start_line
                )
                if not peers:
                    peerless_rules.append(
                        f"{block.header} {direction} at line {rule.start_line}"
                    )

    assert checked_policies >= 15
    assert peerless_rules == [], (
        f"Unrestricted peerless NetworkPolicy rules: {peerless_rules}"
    )


# ---------------------------------------------------------------------------
# [IC-04] GKE ignore_changes & Zero Standalone Guards
# ---------------------------------------------------------------------------


def test_ic04_gke_cluster_reconciles_authorized_networks_and_monitoring_and_guards_bound() -> (
    None
):
    cluster_tf = (MODULES_DIR / "gcp_gke_cluster" / "main.tf").read_text(
        encoding="utf-8"
    )
    ic_match = re.search(r"ignore_changes\s*=\s*\[(.*?)\]", cluster_tf, re.DOTALL)
    assert ic_match is not None
    ic_body = parity._strip_hcl_comments(ic_match.group(1))
    assert "master_authorized_networks_config" not in ic_body
    assert "monitoring_config" not in ic_body
    assert "database_encryption" in ic_body

    assert _all_standalone_guards() == set()

    main_tf = (GKE_DIR / "main.tf").read_text(encoding="utf-8")
    assert "terraform_data.control_plane_access_guard" in main_tf
    assert "terraform_data.poam_019_empty_key_guard" in main_tf
    assert "terraform_data.poam_019_shared_key_guard" in main_tf
    assert "terraform_data.memorystore_ca_pinning_guard" in main_tf
    assert "terraform_data.inference_backend_guard" in main_tf


# ---------------------------------------------------------------------------
# [IC-05] & [IC-06] vllm_sitecustomize Path Containment, Dockerfile.vllm & Model Mirroring
# ---------------------------------------------------------------------------


def _load_vllm_sitecustomize(monkeypatch: pytest.MonkeyPatch) -> Any:
    fake_vllm = types.ModuleType("vllm")
    fake_config = types.ModuleType("vllm.config")
    fake_me = types.ModuleType("vllm.model_executor")
    fake_ml = types.ModuleType("vllm.model_executor.model_loader")
    fake_loader = types.ModuleType("vllm.model_executor.model_loader.loader")
    fake_tu = types.ModuleType("vllm.transformers_utils")
    fake_s3 = types.ModuleType("vllm.transformers_utils.s3_utils")
    fake_utils = types.ModuleType("vllm.transformers_utils.utils")

    fake_utils.is_s3 = lambda p: isinstance(p, str) and p.startswith("s3://")  # type: ignore[attr-defined]
    fake_s3.glob = lambda s3=None, path="", allow_pattern=None: []  # type: ignore[attr-defined]
    fake_s3._filter_ignore = lambda paths, pats: [
        p for p in paths if not p.endswith("/")
    ]  # type: ignore[attr-defined]
    fake_s3._filter_allow = lambda paths, pats: list(paths)  # type: ignore[attr-defined]

    class _DummyS3Model:
        dir: str = ""

        def _close_by_signal(self, handler: Any) -> Any:
            return handler

        def pull_files(
            self,
            s3_model_path: str = "",
            allow_pattern: list[str] | None = None,
            ignore_pattern: list[str] | None = None,
        ) -> None:
            pass

    fake_s3.S3Model = _DummyS3Model  # type: ignore[attr-defined]

    fake_google = types.ModuleType("google")
    fake_gcloud = types.ModuleType("google.cloud")
    fake_storage = types.ModuleType("google.cloud.storage")
    fake_storage.Client = MagicMock()  # type: ignore[attr-defined]
    fake_gcloud.storage = fake_storage  # type: ignore[attr-defined]
    fake_google.cloud = fake_gcloud  # type: ignore[attr-defined]

    for mod_name, mod_obj in (
        ("vllm", fake_vllm),
        ("vllm.config", fake_config),
        ("vllm.model_executor", fake_me),
        ("vllm.model_executor.model_loader", fake_ml),
        ("vllm.model_executor.model_loader.loader", fake_loader),
        ("vllm.transformers_utils", fake_tu),
        ("vllm.transformers_utils.s3_utils", fake_s3),
        ("vllm.transformers_utils.utils", fake_utils),
        ("google", fake_google),
        ("google.cloud", fake_gcloud),
        ("google.cloud.storage", fake_storage),
    ):
        monkeypatch.setitem(sys.modules, mod_name, mod_obj)

    spec = importlib.util.spec_from_file_location(
        "vllm_sitecustomize_wave1c",
        REPO_ROOT / "deployment" / "docker" / "vllm_sitecustomize.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_ic05_vllm_sitecustomize_blocks_path_traversal_and_symlink_escape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = _load_vllm_sitecustomize(monkeypatch)
    cache_root = tmp_path / "cache"
    monkeypatch.setenv("VLLM_GCS_CACHE_DIR", str(cache_root))

    safe = mod._resolve_contained_path(
        cache_root, "Qwen/Qwen2.5-1.5B-Instruct/model.safetensors"
    )
    assert safe == (
        cache_root.resolve() / "Qwen" / "Qwen2.5-1.5B-Instruct" / "model.safetensors"
    )

    for hostile_key in (
        "../etc/ld.so.preload",
        "Qwen/../../etc/passwd",
        "/etc/passwd",
        "Qwen/./model.safetensors",
        "Qwen\\..\\evil.so",
        "Qwen/model.safetensors\x00.txt",
        "",
    ):
        with pytest.raises(ValueError):
            mod._resolve_contained_path(cache_root, hostile_key)

    outside = tmp_path / "outside"
    outside.mkdir()
    cache_root.mkdir(parents=True, exist_ok=True)
    (cache_root / "escape_link").symlink_to(outside)
    with pytest.raises(ValueError, match="escapes target directory"):
        mod._resolve_contained_path(cache_root, "escape_link/pwned.py")

    for bad_bucket in ("..", "../evil", "UPPERCASE_BUCKET", "a/b"):
        with pytest.raises(ValueError, match="Unsafe GCS bucket"):
            mod._validate_bucket_name(bad_bucket)

    class _Blob:
        def __init__(self, name: str, size: int = 4) -> None:
            self.name = name
            self.size = size

        def download_to_filename(self, dest: str) -> None:
            Path(dest).write_bytes(b"test")

    mock_client = MagicMock()
    mock_client.list_blobs.return_value = [_Blob("models/../../etc/crontab")]
    monkeypatch.setattr(mod.storage, "Client", lambda project=None: mock_client)

    with pytest.raises(ValueError, match="Path traversal"):
        mod._patched_glob(path="gs://valid-model-bucket/models")


def test_ic05_dockerfile_vllm_runs_non_root_with_pinned_packages() -> None:
    dockerfile = (REPO_ROOT / "deployment" / "docker" / "Dockerfile.vllm").read_text(
        encoding="utf-8"
    )
    assert "@sha256:" in dockerfile
    assert "--upgrade" not in dockerfile
    assert '"runai-model-streamer==' in dockerfile
    assert '"runai-model-streamer-gcs==' in dockerfile
    assert '"google-cloud-storage==' in dockerfile
    assert "USER 1000:1000" in dockerfile


def test_ic06_model_mirror_scripts_require_commit_sha_and_safetensors() -> None:
    mirror = (REPO_ROOT / "deployment" / "scripts" / "mirror_models.py").read_text(
        encoding="utf-8"
    )
    upload = (REPO_ROOT / "deployment" / "scripts" / "upload_to_gcs.py").read_text(
        encoding="utf-8"
    )
    assert "local_dir_use_symlinks" not in mirror
    assert "local_dir_use_symlinks" not in upload
    assert "revision=revision" in mirror
    assert "revision=model_revision" in upload
    assert "*.safetensors" in mirror


# ---------------------------------------------------------------------------
# [IC-07] Secret Hygiene in update_langfuse_secret.py, deploy_all.sh & load_env.sh
# ---------------------------------------------------------------------------


def test_ic07_update_langfuse_secret_never_passes_secrets_on_argv_and_uses_getpass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from deployment import update_langfuse_secret as uls

    recorded_cmds: list[list[str]] = []
    recorded_inputs: list[str | None] = []

    def _fake_subprocess_run(
        cmd: list[str], **kwargs: Any
    ) -> subprocess.CompletedProcess[str]:
        recorded_cmds.append(list(cmd))
        recorded_inputs.append(kwargs.get("input"))
        if cmd[:3] == ["kubectl", "get", "secret"]:
            return subprocess.CompletedProcess(
                cmd, returncode=1, stdout="", stderr="NotFound"
            )
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="ok", stderr="")

    monkeypatch.delenv("LANGFUSE_INIT_USER_PASSWORD", raising=False)
    monkeypatch.setenv("LANGFUSE_INIT_PROJECT_ID", "proj-uuid-1234")
    monkeypatch.setenv("LANGFUSE_INIT_USER_EMAIL", "admin@example.org")

    with (
        patch.object(uls.subprocess, "run", side_effect=_fake_subprocess_run),
        patch.object(
            uls.getpass, "getpass", return_value="s3cr3t-admin-pass!"
        ) as mock_gp,
    ):
        uls.ensure_langfuse_secrets(namespace="governance-stack")

    mock_gp.assert_called_once()
    flat_argv = " ".join(tok for cmd in recorded_cmds for tok in cmd)
    assert "--from-literal" not in flat_argv
    assert "s3cr3t-admin-pass!" not in flat_argv

    apply_calls = [
        (cmd, inp)
        for cmd, inp in zip(recorded_cmds, recorded_inputs, strict=True)
        if cmd[:3] == ["kubectl", "apply", "-f"]
    ]
    assert len(apply_calls) == 1
    assert apply_calls[0][0] == ["kubectl", "apply", "-f", "-"]
    manifest = json.loads(apply_calls[0][1] or "{}")
    assert manifest["kind"] == "Secret"
    assert manifest["metadata"]["name"] == "langfuse-secrets"
    assert "init-user-password" in manifest["data"]


def test_ic07_update_langfuse_secret_scrubs_credentials_on_subprocess_failure() -> None:
    from deployment import update_langfuse_secret as uls

    def _failing_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.CalledProcessError(
            returncode=1,
            cmd=cmd,
            stderr="fatal: postgresql://admin:my-db-secret@10.0.0.5:5432/langfuse refused",
        )

    with patch.object(uls.subprocess, "run", side_effect=_failing_run):
        with pytest.raises(RuntimeError) as exc_info:
            uls.run(
                ["kubectl", "apply", "-f", "-"],
                input_data='{"secret":"my-db-secret"}',
                redact_values=("my-db-secret",),
            )
    assert "my-db-secret" not in str(exc_info.value)
    assert exc_info.value.__cause__ is None


def test_ic07_load_env_sh_exports_only_tf_vars_and_never_sets_errexit(
    tmp_path: Path,
) -> None:
    fake_infra = tmp_path / "infra"
    fake_infra.mkdir(parents=True)
    load_env_copy = fake_infra / "load_env.sh"
    load_env_copy.write_text(
        (REPO_ROOT / "infra" / "load_env.sh").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    env_file = tmp_path / "test.env"
    env_file.write_text(
        "GOVERNANCE_SALT=top-secret-salt-value\n"
        "LANGFUSE_SECRET_KEY=fake-langfuse-secret-for-test\n"
        "UNMAPPED_PROVIDER_SECRET=raw-unmapped-secret\n"
        "ENVIRONMENT=staging\n",
        encoding="utf-8",
    )

    # 1. Missing file returns non-zero when sourced without terminating the shell or setting -e.
    missing_probe = subprocess.run(
        [
            "bash",
            "-c",
            f'source "{load_env_copy}" "nonexistent_missing.env"; rc=$?; '
            'echo "RC=$rc ERREXIT=$-"',
        ],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=True,
    )
    assert "RC=1" in missing_probe.stdout
    assert "e" not in missing_probe.stdout.split("ERREXIT=")[1].strip()

    # 2. Sourcing exports TF_VAR_* only and leaves raw secret names unset in child processes.
    clean_env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    res = subprocess.run(
        [
            "bash",
            "-c",
            f'source "{load_env_copy}" "test.env" >/dev/null && '
            "python3 -c 'import json, os; print(json.dumps(dict(os.environ)))'",
        ],
        cwd=tmp_path,
        env=clean_env,
        text=True,
        capture_output=True,
        check=True,
    )

    exported = json.loads(res.stdout)
    assert exported["TF_VAR_governance_salt"] == "top-secret-salt-value"
    assert exported["TF_VAR_langfuse_secret_key"] == "fake-langfuse-secret-for-test"
    assert exported["TF_VAR_environment"] == "staging"
    assert "GOVERNANCE_SALT" not in exported
    assert "LANGFUSE_SECRET_KEY" not in exported
    assert "UNMAPPED_PROVIDER_SECRET" not in exported
    assert "var_value" not in exported


def test_ic07_deploy_all_sh_registers_tfplan_cleanup_trap() -> None:
    deploy_sh = (REPO_ROOT / "deploy_all.sh").read_text(encoding="utf-8")
    assert "trap _cleanup_tfplan_artifacts EXIT INT TERM" in deploy_sh
    assert 'rm -f "$_ACTIVE_TF_DIR"/tfplan "$_ACTIVE_TF_DIR"/tfplan.*' in deploy_sh


def test_ef13a_load_env_sh_supports_bash_and_zsh_sourcing(tmp_path: Path) -> None:
    """POAM-2026-164 EF13a: infra/load_env.sh resolves its parent dir in bash and zsh."""
    load_env_text = (REPO_ROOT / "infra" / "load_env.sh").read_text(encoding="utf-8")
    assert "${BASH_SOURCE[0]:-${(%):-%x}}" in load_env_text

    zsh_bin = shutil.which("zsh")
    if zsh_bin is None:
        return

    fake_infra = tmp_path / "infra"
    fake_infra.mkdir(parents=True)
    load_env_copy = fake_infra / "load_env.sh"
    load_env_copy.write_text(load_env_text, encoding="utf-8")
    (tmp_path / "test.env").write_text("ENVIRONMENT=staging\n", encoding="utf-8")
    caller_dir = tmp_path / "elsewhere"
    caller_dir.mkdir()

    res = subprocess.run(
        [
            zsh_bin,
            "-c",
            f'source "{load_env_copy}" "test.env" >/dev/null && printf "%s" "$TF_VAR_environment"',
        ],
        cwd=caller_dir,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        text=True,
        capture_output=True,
        check=True,
    )
    assert res.stdout == "staging"


def test_ef2_env_example_has_unique_keys_and_gcp_deployment_vars() -> None:
    """POAM-2026-164 EF2: .env.example defines each key at most once and includes GCP vars."""
    env_example = REPO_ROOT / ".env.example"
    active_keys: list[str] = []
    values: dict[str, str] = {}
    for raw in env_example.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        active_keys.append(key.strip())
        values[key.strip()] = val.strip()

    duplicates = {k: c for k, c in Counter(active_keys).items() if c > 1}
    assert duplicates == {}, (
        f".env.example has duplicate active keys (breaks deploy_all.sh head -1): {duplicates}"
    )
    assert values.get("GOVERNANCE_SALT"), (
        ".env.example must define a single non-empty GOVERNANCE_SALT dev placeholder"
    )
    assert "GOOGLE_CLOUD_PROJECT" in values
    assert "GOOGLE_CLOUD_LOCATION" in values


def test_ef3_quick_start_matches_staging_profile_and_runtime_topology() -> None:
    """POAM-2026-164 EF3: infra/QUICK_START.md aligns Steps 3-5 with staging & actual GKE stack."""
    quick_start = (REPO_ROOT / "infra" / "QUICK_START.md").read_text(encoding="utf-8")
    assert "--env=staging" in quick_start
    assert "--env staging" in quick_start
    assert "--var-file=infra/targets/gcp-gke/staging.tfvars" in quick_start
    assert "TF_VAR_authorized_networks" in quick_start
    assert 'inference_backend = "none"' in quick_start
    assert "Spot VMs for GPU" not in quick_start
    assert "`vllm-inference` namespace" not in quick_start
    assert "kubectl get pods -n vllm-inference" not in quick_start
    assert "MinIO storage" not in quick_start


# ---------------------------------------------------------------------------
# [IC-08] Least-Privilege IAM, memorystore_app switches & langfuse_event_upload CMEK
# ---------------------------------------------------------------------------


def test_ic08_no_project_wide_secret_accessor_and_hardened_memorystore_and_bucket() -> (
    None
):
    iam_tf = (GKE_DIR / "iam.tf").read_text(encoding="utf-8")
    main_tf = (GKE_DIR / "main.tf").read_text(encoding="utf-8")

    # Zero project-wide secretmanager.secretAccessor bindings anywhere in infra/
    for tf_path in (REPO_ROOT / "infra").rglob("*.tf"):
        cleaned = parity._strip_hcl_comments(tf_path.read_text(encoding="utf-8"))
        for block in parity._iter_top_blocks(cleaned, tf_path):
            if block.header.startswith('resource "google_project_iam_'):
                assert "roles/secretmanager.secretAccessor" not in block.body, (
                    f"{tf_path} grants project-wide secretmanager.secretAccessor in {block.header}"
                )

    assert (
        'resource "google_secret_manager_secret_iam_member" "gateway_secret_accessor"'
        in iam_tf
    )
    assert (
        'resource "google_secret_manager_secret_iam_member" "compliance_bridge_secret_accessor"'
        in iam_tf
    )
    assert (
        'resource "google_project_iam_member" "compliance_bridge_sa_artifactregistry_writer"'
        not in main_tf
    )
    assert (
        "from = google_project_iam_member.compliance_bridge_sa_artifactregistry_writer"
        in main_tf
    )

    # memorystore_app follows its own switches, never the governance instance's:
    # its one client, Langfuse, can do neither IAM auth nor TLS, so the module
    # refuses either while it cannot (test_memorystore_client_capability.py).
    cleaned_main = parity._strip_hcl_comments(main_tf)
    ms_app_blocks = [
        b
        for b in parity._iter_top_blocks(cleaned_main, GKE_DIR / "main.tf")
        if b.header == 'module "memorystore_app"'
    ]
    assert len(ms_app_blocks) == 1
    assert (
        'var.enable_memorystore_app_iam_auth ? "IAM_AUTH" : "AUTH_DISABLED"'
        in ms_app_blocks[0].body
    )
    assert (
        'var.enable_memorystore_app_tls ? "SERVER_AUTHENTICATION" : "TRANSIT_ENCRYPTION_DISABLED"'
        in ms_app_blocks[0].body
    )
    assert "var.enable_memorystore_iam_auth" not in ms_app_blocks[0].body
    assert "var.enable_memorystore_tls" not in ms_app_blocks[0].body

    # langfuse_event_upload enforces CMEK + public_access_prevention + UBLA
    lf_bucket_blocks = [
        b
        for b in parity._iter_top_blocks(cleaned_main, GKE_DIR / "main.tf")
        if b.header == 'resource "google_storage_bucket" "langfuse_event_upload"'
    ]
    assert len(lf_bucket_blocks) == 1
    assert 'public_access_prevention    = "enforced"' in lf_bucket_blocks[0].body
    assert "uniform_bucket_level_access = true" in lf_bucket_blocks[0].body
    assert "default_kms_key_name = local.cmek_key_id" in lf_bucket_blocks[0].body


# ---------------------------------------------------------------------------
# [IC-09] & [KC-13] Immutable /app, Digest-Pinned uv/spacy, readOnlyRootFilesystem & automount=false
# ---------------------------------------------------------------------------


def test_ic09_gateway_dockerfile_root_owned_app_and_supply_chain_hashes() -> None:
    gw_dockerfile = (REPO_ROOT / "src" / "gateway" / "Dockerfile").read_text(
        encoding="utf-8"
    )
    assert "--chown=appuser" not in gw_dockerfile
    assert "COPY --from=builder /app /app" in gw_dockerfile
    assert "ARG UV_IMAGE=ghcr.io/astral-sh/uv:" in gw_dockerfile
    assert "FROM ${UV_IMAGE} AS uv" in gw_dockerfile
    assert "COPY --from=uv /uv /bin/uv" in gw_dockerfile
    assert "COPY --from=$" not in gw_dockerfile
    assert "@sha256:" in gw_dockerfile
    assert "--require-hashes" in gw_dockerfile
    assert (
        "--hash=sha256:293e9547a655b25499198ab15a525b05b9407a75f10255e405e8c3854329ab63"
        in gw_dockerfile
    )
    assert "USER appuser" in gw_dockerfile

    local_dev_dockerfile = (
        REPO_ROOT / "deployment" / "docker" / "Dockerfile.local-dev"
    ).read_text(encoding="utf-8")
    assert "FROM ${UV_IMAGE} AS uv" in local_dev_dockerfile
    assert "COPY --from=uv /uv /usr/local/bin/uv" in local_dev_dockerfile
    assert "COPY --from=$" not in local_dev_dockerfile


def test_ic09_runtime_workloads_disable_sa_token_automount_and_enforce_readonly_rootfs() -> (
    None
):
    gw_tf = (MODULES_DIR / "gateway" / "main.tf").read_text(encoding="utf-8")
    assert "automountServiceAccountToken  = false" in gw_tf
    assert gw_tf.count("readOnlyRootFilesystem   = true") >= 2

    for mod_name in (
        "compliance_bridge",
        "governed_advisor",
        "reconciliation_worker",
        "inference_stub",
    ):
        mod_tf = (MODULES_DIR / mod_name / "main.tf").read_text(encoding="utf-8")
        assert "automount_service_account_token = false" in mod_tf, mod_name
        assert "read_only_root_filesystem  = true" in mod_tf, mod_name

    for mod_name in (
        "agentsight_ui",
        "vllm_inference",
        "langfuse_stack",
        "clickhouse_operator",
    ):
        mod_tf = (MODULES_DIR / mod_name / "main.tf").read_text(encoding="utf-8")
        assert "automount_service_account_token = false" in mod_tf, mod_name


def test_ic06_safetensors_sha256_verification_and_upload_to_gcs_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import hashlib

    from deployment.scripts import mirror_models, upload_to_gcs

    model_dir = tmp_path / "dl"
    model_dir.mkdir()
    cfg_bytes = b'{"model_type": "qwen2"}\n'
    st_bytes = b"SAFETENSORS_VERIFIED_WEIGHT_SHARD_BYTES"
    (model_dir / "config.json").write_bytes(cfg_bytes)
    (model_dir / "model.safetensors").write_bytes(st_bytes)
    cfg_sha = hashlib.sha256(cfg_bytes).hexdigest()
    st_sha = hashlib.sha256(st_bytes).hexdigest()
    commit_sha = "b" * 40

    manifest_file = tmp_path / "model_hashes.json"
    manifest_file.write_text(
        json.dumps(
            {
                "org/pinned-model": {
                    "_revision": commit_sha,
                    "config.json": cfg_sha,
                    "model.safetensors": st_sha,
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(mirror_models, "_MANIFEST_PATH", manifest_file)

    # 1. Matching .safetensors + config.json SHA-256 passes
    assert mirror_models.verify_model_integrity(model_dir, "org/pinned-model") is True

    # 2. Tampered .safetensors bytes fail closed
    (model_dir / "model.safetensors").write_bytes(b"TAMPERED_WEIGHT_SHARD")
    assert mirror_models.verify_model_integrity(model_dir, "org/pinned-model") is False

    # 3. Restore valid shard, inject extra unpinned .safetensors shard -> fail closed
    (model_dir / "model.safetensors").write_bytes(st_bytes)
    (model_dir / "rogue-extra.safetensors").write_bytes(b"ROGUE_SHARD")
    assert mirror_models.verify_model_integrity(model_dir, "org/pinned-model") is False
    (model_dir / "rogue-extra.safetensors").unlink()

    # 4. Empty 0-byte .safetensors shard -> fail closed
    (model_dir / "model.safetensors").write_bytes(b"")
    assert mirror_models.verify_model_integrity(model_dir, "org/pinned-model") is False

    # 5. upload_to_gcs.main() aborts before upload_directory on tampered .safetensors
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MODEL_ID", "org/pinned-model")
    monkeypatch.setenv("MODEL_REVISION", commit_sha)
    monkeypatch.setenv("STORAGE_BACKEND", "local")
    monkeypatch.delenv("MODEL_WEIGHT_VERIFICATION_STRICT", raising=False)

    uploaded_calls: list[tuple[str, str]] = []

    def _fake_bad_snapshot_download(**kwargs: Any) -> str:
        dl = Path(kwargs["local_dir"])
        dl.mkdir(parents=True, exist_ok=True)
        (dl / "config.json").write_bytes(cfg_bytes)
        (dl / "model.safetensors").write_bytes(b"CORRUPTED_SHARD")
        return str(dl)

    monkeypatch.setattr(upload_to_gcs, "snapshot_download", _fake_bad_snapshot_download)
    monkeypatch.setattr(
        upload_to_gcs,
        "upload_directory",
        lambda lp, rp, bucket_name=None: uploaded_calls.append((lp, rp)),
    )

    with pytest.raises(SystemExit) as exc_info:
        upload_to_gcs.main()
    assert exc_info.value.code == 1
    assert uploaded_calls == []


def test_wave1c_preserves_mainline_774_779_782_783_invariants() -> None:
    gw_tf = (MODULES_DIR / "gateway" / "main.tf").read_text(encoding="utf-8")
    adv_tf = (MODULES_DIR / "governed_advisor" / "main.tf").read_text(encoding="utf-8")
    cb_tf = (MODULES_DIR / "compliance_bridge" / "main.tf").read_text(encoding="utf-8")
    mesh_tf = (GKE_DIR / "mesh_policy.tf").read_text(encoding="utf-8")
    gw_policy = (
        MODULES_DIR / "gateway" / "mesh-policy" / "templates" / "policy.yaml"
    ).read_text(encoding="utf-8")

    # #774: pinned "false" telemetry content capture vars
    for var_name in (
        "OTEL_PYTHON_INSTRUMENTATION_HTTPX_CAPTURE_REQUEST_BODY",
        "OTEL_PYTHON_INSTRUMENTATION_HTTPX_CAPTURE_RESPONSE_BODY",
        "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT",
    ):
        assert var_name in gw_tf
        assert var_name in adv_tf

    # #779: gateway-mediated checkpointing in governed_advisor
    assert 'name  = "CAGE_CHECKPOINT_BACKEND"' in adv_tf
    assert 'value = "gateway"' in adv_tf

    # #782: AuthorizationPolicy/gateway-canary-trusted
    assert "name: gateway-canary-trusted" in gw_policy

    # #783: templateSha256 = filesha256(...) across all three mesh-policy helm_releases
    assert 'filesha256("${path.module}/mesh-policy/templates/policy.yaml")' in gw_tf
    assert 'filesha256("${path.module}/mesh-policy/templates/policy.yaml")' in cb_tf
    assert (
        'filesha256("${path.module}/charts/workload-mesh-policy/templates/servers-and-authz.yaml")'
        in mesh_tf
    )

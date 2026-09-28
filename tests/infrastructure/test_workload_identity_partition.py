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

"""Static guard: workload identity is partitioned 1:1 (POAM-2026-079).

Every workload runs as its own Kubernetes ServiceAccount, bound to its own
Google service account, and signing keys are granted per key to exactly one
signer. These tests fail closed on the regressions that produced
POAM-2026-079:

* a shared KSA (``financial-advisor-sa``) reintroduced anywhere;
* a pod using a ServiceAccount that is not declared per namespace;
* the untrusted model-serving plane (vLLM) or telemetry/UI pods holding a KSA
  that maps to a signing identity;
* a KMS role granted at keyring or project scope;
* a signing key with more signers than the documented set.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest
import yaml

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO = Path(__file__).resolve().parents[2]
_INFRA = _REPO / "infra"
_K8S = _REPO / "deployment" / "k8s"
_GKE = _INFRA / "targets" / "gcp-gke"

_RETIRED_KSA = "financial-advisor-sa"
_POD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod"}

# KSAs whose GSA may hold a KMS signer role on some key.
_SIGNING_KSAS = {"cage-gateway-sa", "cage-advisor-sa", "cage-reconciler-sa",
                 "cage-compliance-bridge-sa", "cage-benchmark-sa"}

# Expected signers per key in kms_signing.tf. The advisor entry is the
# documented POAM-2026-079 residual; removing it must update this table.
_EXPECTED_SIGNERS = {
    "gateway_seal": {"gateway", "advisor"},
    "reconciler_snapshot": {"reconciler"},
    "compliance_evidence": {"compliance_bridge"},
    "benchmark_signing": {"benchmark"},
}


_PLACEHOLDER_LINE = re.compile(r"^\s*\$\{[A-Z0-9_]+\}\s*$", re.M)
_PLACEHOLDER = re.compile(r"\$\{[A-Z0-9_]+\}")


def _tracked(*roots: Path) -> list[Path]:
    """Tracked and new, non-ignored files (generated/ and tfstate are gitignored)."""
    out = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", *(str(r.relative_to(_REPO)) for r in roots)],
        cwd=_REPO, check=True, capture_output=True, text=True,
    ).stdout
    return [_REPO / f for f in out.split("\0") if f]


def _tf_sources() -> list[Path]:
    return [p for p in _tracked(_INFRA) if p.suffix in {".tf", ".tfvars"}]


def _manifests() -> list[Path]:
    return sorted(p for p in _tracked(_K8S) if p.name.endswith((".yaml", ".yaml.tpl", ".yml")))


def _load_docs(path: Path) -> list[dict]:
    text = path.read_text()
    if path.name.endswith(".tpl"):
        # Render envsubst placeholders: whole-line blocks drop, inline values
        # become a scalar. A manifest that still fails to parse fails the test.
        text = _PLACEHOLDER.sub("placeholder", _PLACEHOLDER_LINE.sub("", text))
    return [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]


def _pod_spec(doc: dict) -> dict | None:
    kind = doc.get("kind")
    if kind not in _POD_KINDS:
        return None
    spec = doc.get("spec") or {}
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        spec = ((spec.get("jobTemplate") or {}).get("spec") or {})
    return ((spec.get("template") or {}).get("spec") or {})


def _workloads() -> list[tuple[str, dict, dict]]:
    out = []
    for path in _manifests():
        for doc in _load_docs(path):
            pod = _pod_spec(doc)
            if pod is not None:
                out.append((str(path.relative_to(_REPO)), doc, pod))
    return out


def _declared_ksas() -> dict[tuple[str, str], dict]:
    ksas: dict[tuple[str, str], dict] = {}
    for path in _manifests():
        for doc in _load_docs(path):
            if doc.get("kind") == "ServiceAccount":
                meta = doc["metadata"]
                key = (meta.get("namespace", ""), meta["name"])
                assert key not in ksas, f"ServiceAccount {key} declared twice ({path})"
                ksas[key] = meta
    return ksas


# ---------------------------------------------------------------------------
# Retired shared identity
# ---------------------------------------------------------------------------


def test_retired_shared_ksa_absent_from_infra_deployment_and_src() -> None:
    offenders = []
    for p in _tracked(_INFRA, _REPO / "deployment", _REPO / "src"):
        if p.suffix not in {".tf", ".tfvars", ".yaml", ".yml", ".tpl", ".py", ".sh", ".md"}:
            continue
        for n, line in enumerate(p.read_text(errors="ignore").splitlines(), 1):
            # Module validations name the retired KSA in order to reject it.
            if _RETIRED_KSA in line and "!= \"financial-advisor-sa\"" not in line \
                    and "financial-advisor-sa is retired" not in line:
                offenders.append(f"{p.relative_to(_REPO)}:{n}")
    assert offenders == [], f"Retired shared KSA still referenced: {offenders}"


# ---------------------------------------------------------------------------
# Manifests
# ---------------------------------------------------------------------------


def test_every_manifest_service_account_is_declared_per_namespace() -> None:
    declared = _declared_ksas()
    linkerd_only = {"cage-opa-sa", "cage-nemo-sa"}
    missing = []
    for path, doc, pod in _workloads():
        ns = doc["metadata"].get("namespace", "")
        sa = pod.get("serviceAccountName", "default")
        if sa == "default" or ns == "placeholder" or sa in linkerd_only:
            continue  # default KSA carries no cloud identity; templated namespace
        if (ns, sa) not in declared:
            missing.append(f"{path}: {ns}/{sa}")
    assert missing == [], f"ServiceAccounts used but not declared: {missing}"


def test_annotated_ksas_map_one_to_one_to_their_own_gsa() -> None:
    gsas = {}
    for (ns, name), meta in _declared_ksas().items():
        gsa = (meta.get("annotations") or {}).get("iam.gke.io/gcp-service-account")
        if gsa is None:
            continue
        local_part = gsa.split("@", 1)[0]
        assert name in (local_part, f"{local_part}-sa"), (
            f"{ns}/{name} is bound to a GSA it does not own: {gsa}"
        )
        gsas.setdefault(local_part, set()).add(name)
    assert all(len(v) == 1 for v in gsas.values()), f"GSA shared by several KSAs: {gsas}"


def test_model_serving_pods_never_hold_a_signing_identity() -> None:
    offenders = []
    for path, doc, pod in _workloads():
        images = " ".join(c.get("image", "") for c in pod.get("containers", []))
        if "vllm" in images.lower() or "vllm" in doc["metadata"]["name"].lower():
            sa = pod.get("serviceAccountName", "default")
            if sa in _SIGNING_KSAS:
                offenders.append(f"{path}: {sa}")
    assert offenders == [], f"vLLM pods hold a signing identity: {offenders}"


@pytest.mark.parametrize("prefix", ["langfuse", "frontend"])
def test_telemetry_and_ui_pods_have_no_signing_identity(prefix: str) -> None:
    offenders = [
        f"{path}: {pod.get('serviceAccountName')}"
        for path, doc, pod in _workloads()
        if doc["metadata"]["name"].startswith(prefix)
        and pod.get("serviceAccountName", "default") in _SIGNING_KSAS
    ]
    assert offenders == [], f"{prefix} pods hold a signing identity: {offenders}"


def test_cage_vllm_sa_carries_no_signing_role() -> None:
    kms_tf = (_GKE / "kms_signing.tf").read_text()
    assert "google_service_account.vllm" not in kms_tf


# ---------------------------------------------------------------------------
# Terraform
# ---------------------------------------------------------------------------


def test_gke_modules_run_as_their_own_terraform_ksa() -> None:
    main_tf = (_GKE / "main.tf").read_text()
    refs = re.findall(r"service_account_name\s*=\s*(\S+)", main_tf)
    assert refs, "no service_account_name wiring found in gcp-gke/main.tf"
    bad = [r for r in refs if not r.startswith('kubernetes_service_account.workload["')]
    assert bad == [], f"Module not wired to a per-workload KSA: {bad}"


def test_no_kms_role_granted_at_keyring_or_project_scope() -> None:
    offenders = []
    for p in _tf_sources():
        text = p.read_text()
        if re.search(r'resource\s+"google_kms_key_ring_iam_', text):
            offenders.append(f"{p.relative_to(_REPO)}: keyring-scoped IAM resource")
        for block in re.findall(r'resource\s+"google_project_iam_[a-z_]+"[^{]*\{[^}]*\}', text, re.S):
            if re.search(r'role\s*=\s*"roles/cloudkms\.(signer|signerVerifier|admin)"', block):
                offenders.append(f"{p.relative_to(_REPO)}: project-scoped KMS signing role")
    assert offenders == [], f"KMS roles must be granted per key: {offenders}"


def test_signing_key_policies_are_authoritative() -> None:
    kms_tf = (_GKE / "kms_signing.tf").read_text()
    assert 'resource "google_kms_crypto_key_iam_policy" "signing_key"' in kms_tf
    assert "google_kms_crypto_key_iam_member" not in kms_tf
    assert "google_kms_crypto_key_iam_binding" not in kms_tf


def test_each_signing_key_has_only_its_documented_signers() -> None:
    kms_tf = (_GKE / "kms_signing.tf").read_text()
    found = {}
    for key, signers in re.findall(r"(\w+)\s*=\s*\{\s*key\s*=[^\n]+\n\s*signers\s*=\s*\[([^\]]*)\]", kms_tf):
        found[key] = set(re.findall(r"local\.(\w+)_member", signers))
    assert found == _EXPECTED_SIGNERS


def test_signing_keys_are_asymmetric_and_hsm_by_default() -> None:
    kms_tf = (_GKE / "kms_signing.tf").read_text()
    keys = re.findall(r'resource "google_kms_crypto_key" "(\w+)"', kms_tf)
    assert set(keys) == set(_EXPECTED_SIGNERS)
    assert kms_tf.count('purpose  = "ASYMMETRIC_SIGN"') == len(keys)
    assert kms_tf.count('algorithm        = "EC_SIGN_P256_SHA256"') == len(keys)
    variables_tf = (_GKE / "variables.tf").read_text()
    block = variables_tf.split('variable "kms_signing_protection_level"', 1)[1].split("\n}\n", 1)[0]
    assert 'default     = "HSM"' in block


def test_software_protection_only_in_dev_tfvars() -> None:
    offenders = [
        p.name for p in _GKE.glob("*.tfvars")
        if re.search(r'kms_signing_protection_level\s*=\s*"SOFTWARE"', p.read_text())
        and "dev" not in p.name
    ]
    assert offenders == [], f"SOFTWARE signing keys outside dev postures: {offenders}"

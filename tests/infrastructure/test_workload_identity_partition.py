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
* a signing key with more signers than the documented set;
* the advisor (untrusted neural plane) regaining any cloud identity, KMS
  grant or signing-key variable.
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
_SIGNING_KSAS = {"cage-gateway-sa", "cage-reconciler-sa",
                 "cage-compliance-bridge-sa", "cage-benchmark-sa"}

_ADVISOR_KSA = "cage-advisor-sa"
_SIGNING_KEY_VARS = (
    "KMS_GOVERNANCE_KEY",
    "RECONCILER_KMS_KEY",
    "EVIDENCE_KMS_KEY",
    "AWS_KMS_KEY_ID",
    "AZURE_KMS_KEY_NAME",
)

# Expected signers per key in kms_signing.tf.
_EXPECTED_SIGNERS = {
    "gateway_seal": {"gateway"},
    "reconciler_snapshot": {"reconciler"},
    "compliance_evidence": {"compliance_bridge"},
    "benchmark_signing": {"benchmark"},
    "binauthz_attestor": {"cloudbuild"},
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
            if re.search(
                r'role\s*=\s*"roles/cloudkms\.(signer|signerVerifier|admin|publicKeyViewer|cryptoKeyEncrypterDecrypter)"',
                block,
            ):
                offenders.append(f"{p.relative_to(_REPO)}: project-scoped KMS role")
    assert offenders == [], f"KMS roles must be granted per key: {offenders}"


def test_compliance_bridge_uses_dedicated_evidence_kms_key_var() -> None:
    """§5.2: Compliance bridge reads EVIDENCE_KMS_KEY, never KMS_GOVERNANCE_KEY."""
    cb_tf = (_INFRA / "modules" / "compliance_bridge" / "main.tf").read_text()
    assert '"EVIDENCE_KMS_KEY"' in cb_tf
    assert '"KMS_GOVERNANCE_KEY"' not in cb_tf
    main_tf = (_GKE / "main.tf").read_text()
    assert "evidence_kms_key     = local.compliance_evidence_key_version" in main_tf


def test_symmetric_cmek_and_signing_keyrings_are_separate() -> None:
    """§5.2 / D2: Symmetric CMEK keyring (module.kms) is separate from signing keyring."""
    main_tf = (_GKE / "main.tf").read_text()
    assert 'module "kms"' in main_tf
    assert 'source = "../../modules/kms"' in main_tf
    kms_mod_tf = (_INFRA / "modules" / "kms" / "main.tf").read_text()
    signing_tf = (_GKE / "kms_signing.tf").read_text()
    assert "cage-keyring-${var.environment}" in kms_mod_tf
    assert "cage-signing-${var.environment}" in signing_tf


def test_memorystore_iam_bindings_for_authorized_gsas() -> None:
    """§5.1: Gateway, reconciler, and langfuse GSAs hold roles/memorystore.dbConnectionUser when IAM auth is enabled."""
    iam_tf = (_GKE / "iam.tf").read_text()
    for gsa in ("gateway", "reconciler", "langfuse"):
        assert f'resource "google_project_iam_member" "{gsa}_memorystore_user"' in iam_tf
    assert iam_tf.count('role    = "roles/memorystore.dbConnectionUser"') == 3


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


# ---------------------------------------------------------------------------
# Zero-identity advisor (POAM-2026-079)
# ---------------------------------------------------------------------------


def test_advisor_ksa_has_no_cloud_identity() -> None:
    advisor = [meta for (_, name), meta in _declared_ksas().items() if name == _ADVISOR_KSA]
    assert advisor, f"{_ADVISOR_KSA} not declared"
    for meta in advisor:
        assert "iam.gke.io/gcp-service-account" not in (meta.get("annotations") or {})
    iam_tf = (_GKE / "iam.tf").read_text()
    assert 'resource "google_service_account" "advisor"' not in iam_tf
    assert "advisor_workload_identity" not in iam_tf
    assert re.search(r"advisor\s*=\s*\{[^}]*gsa\s*=\s*null", iam_tf, re.S), (
        "Terraform advisor KSA must carry no GSA annotation"
    )


def test_advisor_has_no_kms_grant() -> None:
    kms_tf = (_GKE / "kms_signing.tf").read_text()
    assert "advisor_member" not in kms_tf
    assert "google_service_account.advisor" not in kms_tf


def test_advisor_pods_receive_no_signing_key_variable() -> None:
    """The advisor refuses to boot with these; no manifest or module may set them."""
    offenders = []
    for path, _doc, pod in _workloads():
        if pod.get("serviceAccountName") != _ADVISOR_KSA:
            continue
        for c in pod.get("containers", []):
            for env in c.get("env") or []:
                if env.get("name") in _SIGNING_KEY_VARS:
                    offenders.append(f"{path}: {env['name']}")
    module_tf = (_INFRA / "modules" / "governed_advisor" / "main.tf").read_text()
    offenders += [f"governed_advisor module: {v}" for v in _SIGNING_KEY_VARS if f'"{v}"' in module_tf]
    assert offenders == [], f"Advisor receives a signing-key variable: {offenders}"


def _secrets_loaded_by(pod: dict) -> set[str]:
    """Every Secret a pod reads, via envFrom or env secretKeyRef."""
    names: set[str] = set()
    for c in [*pod.get("containers", []), *pod.get("initContainers", [])]:
        for src in c.get("envFrom") or []:
            if "secretRef" in src:
                names.add(src["secretRef"]["name"])
        for env in c.get("env") or []:
            ref = (env.get("valueFrom") or {}).get("secretKeyRef")
            if ref:
                names.add(ref["name"])
    return names


def _signing_key_refs_into(secrets: set[str], workloads) -> list[str]:
    """Signing-key variables any pod sources from a Secret in ``secrets``."""
    hits = []
    for path, _doc, pod in workloads:
        for c in pod.get("containers", []):
            for env in c.get("env") or []:
                ref = (env.get("valueFrom") or {}).get("secretKeyRef") or {}
                if env.get("name") in _SIGNING_KEY_VARS and ref.get("name") in secrets:
                    hits.append(f"{path}: {env['name']} from {ref['name']}")
    return hits


def test_signing_keys_never_live_in_a_secret_the_advisor_loads() -> None:
    """A signing-key reference in a shared Secret would crash-loop the advisor.

    The advisor loads its Secrets wholesale; identity_guard refuses to boot
    when a signing-key variable is present. So no workload may source a
    signing key from a Secret the advisor also reads (e.g. advisor-secrets).
    """
    workloads = _workloads()
    advisor_secrets: set[str] = set()
    for _path, _doc, pod in workloads:
        if pod.get("serviceAccountName") == _ADVISOR_KSA:
            advisor_secrets |= _secrets_loaded_by(pod)
    assert "advisor-secrets" in advisor_secrets
    assert "gateway-secrets" not in advisor_secrets
    assert _signing_key_refs_into(advisor_secrets, workloads) == []


def test_signing_key_secret_scan_detects_a_shared_secret() -> None:
    planted = [(
        "planted.yaml",
        {},
        {"containers": [{"env": [{
            "name": "KMS_GOVERNANCE_KEY",
            "valueFrom": {"secretKeyRef": {"name": "advisor-secrets", "key": "KMS_GOVERNANCE_KEY"}},
        }]}]},
    )]
    assert _signing_key_refs_into({"advisor-secrets"}, planted) == [
        "planted.yaml: KMS_GOVERNANCE_KEY from advisor-secrets"
    ]


def test_terraform_advisor_secrets_hold_no_signing_key() -> None:
    app_secrets = (_INFRA / "modules" / "app_secrets" / "main.tf").read_text()
    block = app_secrets.split('resource "kubernetes_secret" "advisor_secrets"', 1)[1]
    block = block.split("\nresource ", 1)[0]
    assert [v for v in _SIGNING_KEY_VARS if f'"{v}"' in block] == []


def test_advisor_pods_receive_no_governance_salt_or_seal_enforcement_vars() -> None:
    """The advisor has no governance salt and no CAGE_SEAL_ENFORCEMENT flag."""
    forbidden = {"GOVERNANCE_SALT", "CAGE_SEAL_ENFORCEMENT"}
    offenders = []
    for path, _doc, pod in _workloads():
        if pod.get("serviceAccountName") != _ADVISOR_KSA:
            continue
        for c in pod.get("containers", []):
            for env in c.get("env") or []:
                if env.get("name") in forbidden:
                    offenders.append(f"{path}: {env['name']}")
    module_tf = (_INFRA / "modules" / "governed_advisor" / "main.tf").read_text()
    variables_tf = (_INFRA / "modules" / "governed_advisor" / "variables.tf").read_text()
    offenders += [
        f"governed_advisor/main.tf: {v}" for v in forbidden if f'"{v}"' in module_tf
    ]
    offenders += [
        f"governed_advisor/variables.tf: {v}"
        for v in ("governance_salt", "cage_seal_enforcement")
        if f'variable "{v}"' in variables_tf
    ]
    assert offenders == [], f"Advisor receives governance state variables: {offenders}"


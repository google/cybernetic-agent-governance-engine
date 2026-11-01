#!/usr/bin/env bash
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

# Bootstrap a clean or recycled GCP project for CAGE GKE deployment.
#
# This is tooling, not Track A's Step A2. Step A2 is the clean-project walk: a
# person deploying a new project from infra/QUICK_START.md by hand and
# recording what fails (POAM-2026-164). The PF-numbered items below are the
# walk's predicted failures, handled here from code reading before any walk
# has confirmed them.
#
# Resolves the clean-project bootstrap prerequisites before `deploy_all.sh` runs
# Cloud Build or `terraform apply`:
#   PF1  Enable all required GCP APIs (GKE, Compute, Storage, Artifact Registry,
#        Cloud Build, Cloud KMS, Binary Authorization, Container Analysis,
#        Memorystore, Cloud SQL, Service Networking, Network Connectivity,
#        Private CA, Secret Manager, IAM, Cloud Resource Manager, Logging,
#        Monitoring, Cloud DNS, Access Context Manager).
#   PF2  Create the remote Terraform state GCS bucket (`gs://<project>-tfstate`)
#        with uniform bucket-level access and object versioning enabled.
#   PF3  Break the Cloud Build <-> Terraform bootstrap paradox: pre-create the
#        dedicated Cloud Build service account (`cage-cloudbuild-<env>`),
#        signing KMS keyring (`cage-signing-<env>`), `binauthz-attestor` EC P-256
#        key, Container Analysis note (`cage-build-attestor-note-<env>`), and
#        Binary Authorization attestor (`cage-build-attestor-<env>`) so
#        `scripts/build_images.sh` can build and attest images on a brand-new
#        project before the first `terraform apply`.
#   PF4  Ensure the `gcr.io` Artifact Registry Docker repository and
#        `gs://<project>_cloudbuild` staging bucket exist.
#   PF8  With `--import-state`, idempotently import pre-existing foundational
#        resources (Cloud Build SA, KMS keyrings/keys that survive `terraform destroy`
#        in GCP, Container Analysis note, and Binary Authorization attestor) into
#        Terraform state after `terraform init`.
#   PF10 Grant `roles/cloudkms.publicKeyViewer` to the deployer service account
#        (when `--deployer-sa` is provided or active gcloud account is a GSA) so
#        `data.google_kms_crypto_key_version.binauthz_attestor` succeeds during
#        `terraform plan`.
#
# Usage:
#   scripts/bootstrap_gcp_project.sh --project <project-id> [--env staging] [--region us-central1]
#   scripts/bootstrap_gcp_project.sh --project <project-id> --env staging --import-state

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PROJECT_ID="${PROJECT_ID:-}"
ENV="${ENVIRONMENT:-staging}"
REGION="${REGION:-us-central1}"
STATE_BUCKET="${STATE_BUCKET:-}"
DEPLOYER_SA="${DEPLOYER_SA:-}"
IMPORT_STATE="false"
TF_DIR="${TF_DIR:-$REPO_ROOT/infra/targets/gcp-gke}"

usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Bootstrap a clean or recycled GCP project for CAGE GKE deployment.

Options:
  --project=<id>          GCP project ID (default: \$PROJECT_ID or active gcloud project)
  --env=<dev|staging|prod> Deployment environment (default: staging)
  --region=<region>       GCP region (default: us-central1)
  --bucket=<name>         Terraform state GCS bucket name (default: <project>-tfstate)
  --deployer-sa=<email>   Optional deployer service account email to grant
                          roles/cloudkms.publicKeyViewer (PF10)
  --import-state          Import existing foundational GCP resources into Terraform
                          state (run after 'terraform init') (PF3 / PF8)
  --tf-dir=<path>         Path to GKE Terraform target directory
                          (default: infra/targets/gcp-gke)
  -h, --help              Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project=*)
      PROJECT_ID="${1#*=}"
      shift
      ;;
    --project)
      PROJECT_ID="${2:-}"
      shift 2
      ;;
    --env=*)
      ENV="${1#*=}"
      shift
      ;;
    --env)
      ENV="${2:-}"
      shift 2
      ;;
    --region=*)
      REGION="${1#*=}"
      shift
      ;;
    --region)
      REGION="${2:-}"
      shift 2
      ;;
    --bucket=*)
      STATE_BUCKET="${1#*=}"
      shift
      ;;
    --bucket)
      STATE_BUCKET="${2:-}"
      shift 2
      ;;
    --deployer-sa=*)
      DEPLOYER_SA="${1#*=}"
      shift
      ;;
    --deployer-sa)
      DEPLOYER_SA="${2:-}"
      shift 2
      ;;
    --import-state)
      IMPORT_STATE="true"
      shift
      ;;
    --tf-dir=*)
      TF_DIR="${1#*=}"
      shift
      ;;
    --tf-dir)
      TF_DIR="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "❌ Error: Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$PROJECT_ID" ]]; then
  PROJECT_ID="$(gcloud config get-value project 2>/dev/null || true)"
fi

if [[ -z "$PROJECT_ID" ]]; then
  echo "❌ Error: --project or PROJECT_ID is required." >&2
  exit 1
fi

if [[ "$ENV" != "dev" && "$ENV" != "staging" && "$ENV" != "prod" ]]; then
  echo "❌ Error: --env must be one of: dev, staging, prod (got: '$ENV')." >&2
  exit 1
fi

if [[ -z "$STATE_BUCKET" ]]; then
  STATE_BUCKET="${PROJECT_ID}-tfstate"
fi

CB_SA_NAME="cage-cloudbuild-${ENV}"
CB_SA_EMAIL="${CB_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
SIGNING_KEYRING="cage-signing-${ENV}"
CMEK_KEYRING="cage-keyring-${ENV}"
CMEK_KEY="cage-cmek-${ENV}"
NOTE_ID="cage-build-attestor-note-${ENV}"
ATTESTOR_ID="cage-build-attestor-${ENV}"

if [[ "$ENV" == "dev" ]]; then
  KMS_PROTECTION_LEVEL="software"
else
  KMS_PROTECTION_LEVEL="hsm"
fi

# ---------------------------------------------------------------------------
# Mode: --import-state (PF3 / PF8)
# ---------------------------------------------------------------------------
import_foundational_state() {
  echo "🔄 Inspecting Terraform state for pre-existing foundational GCP resources (project=${PROJECT_ID}, env=${ENV})..."

  local state_list
  state_list="$(terraform -chdir="$TF_DIR" state list 2>/dev/null || true)"

  local -a import_args=(
    "-var=project_id=${PROJECT_ID}"
    "-var=environment=${ENV}"
    "-var=region=${REGION}"
  )
  if [[ "$ENV" == "staging" || "$ENV" == "prod" ]]; then
    import_args+=("-var=enable_nist_compliance=true")
  fi
  if [[ -f "$TF_DIR/${ENV}.tfvars" ]]; then
    import_args+=("-var-file=${ENV}.tfvars")
  fi
  if [[ -f "$TF_DIR/tests/fixtures/image_digests.tfvars" ]]; then
    import_args+=("-var-file=tests/fixtures/image_digests.tfvars")
  fi
  if [[ -f "$TF_DIR/terraform.auto.tfvars" ]]; then
    import_args+=("-var-file=terraform.auto.tfvars")
  fi

  in_state() {
    local target="$1"
    grep -Fxq "$target" <<< "$state_list"
  }

  import_if_missing() {
    local tf_addr="$1"
    local gcp_id="$2"
    if in_state "$tf_addr"; then
      echo "  ✓ Already in state: ${tf_addr}"
      return 0
    fi
    echo "  📥 Importing ${tf_addr} <- ${gcp_id}..."
    terraform -chdir="$TF_DIR" import "${import_args[@]}" "$tf_addr" "$gcp_id"
    state_list="${state_list}"$'\n'"${tf_addr}"
  }

  # 1. Dedicated Cloud Build Service Account
  if gcloud iam service-accounts describe "$CB_SA_EMAIL" --project="$PROJECT_ID" >/dev/null 2>&1; then
    import_if_missing \
      "google_service_account.cloudbuild" \
      "projects/${PROJECT_ID}/serviceAccounts/${CB_SA_EMAIL}"
  fi

  # 2. Signing KMS KeyRing and CryptoKeys (survive terraform destroy in GCP)
  if gcloud kms keyrings describe "$SIGNING_KEYRING" --location="$REGION" --project="$PROJECT_ID" >/dev/null 2>&1; then
    import_if_missing \
      "google_kms_key_ring.signing" \
      "projects/${PROJECT_ID}/locations/${REGION}/keyRings/${SIGNING_KEYRING}"

    local -a signing_keys=(
      "binauthz_attestor:binauthz-attestor"
      "gateway_seal:gateway-seal"
      "reconciler_snapshot:reconciler-snapshot"
      "compliance_evidence:compliance-evidence"
      "benchmark_signing:benchmark-signing"
    )
    for pair in "${signing_keys[@]}"; do
      local tf_key="${pair%%:*}"
      local gcp_key="${pair##*:}"
      if gcloud kms keys describe "$gcp_key" --keyring="$SIGNING_KEYRING" --location="$REGION" --project="$PROJECT_ID" >/dev/null 2>&1; then
        import_if_missing \
          "google_kms_crypto_key.${tf_key}" \
          "projects/${PROJECT_ID}/locations/${REGION}/keyRings/${SIGNING_KEYRING}/cryptoKeys/${gcp_key}"
      fi
    done
  fi

  # 3. CMEK KeyRing and CryptoKey (when present in GCP from a prior lifecycle run)
  if [[ "$ENV" != "dev" ]] && gcloud kms keyrings describe "$CMEK_KEYRING" --location="$REGION" --project="$PROJECT_ID" >/dev/null 2>&1; then
    import_if_missing \
      "module.kms[0].google_kms_key_ring.keyring" \
      "projects/${PROJECT_ID}/locations/${REGION}/keyRings/${CMEK_KEYRING}"
    if gcloud kms keys describe "$CMEK_KEY" --keyring="$CMEK_KEYRING" --location="$REGION" --project="$PROJECT_ID" >/dev/null 2>&1; then
      import_if_missing \
        "module.kms[0].google_kms_crypto_key.cmek_key" \
        "projects/${PROJECT_ID}/locations/${REGION}/keyRings/${CMEK_KEYRING}/cryptoKeys/${CMEK_KEY}"
    fi
  fi

  # 4. Container Analysis Note and Binary Authorization Attestor
  if [[ "$ENV" != "dev" ]]; then
    local token
    token="$(gcloud auth print-access-token 2>/dev/null || true)"
    if [[ -n "$token" ]]; then
      local note_http
      note_http="$(curl -sS -o /dev/null -w '%{http_code}' \
        -H "Authorization: Bearer ${token}" \
        "https://containeranalysis.googleapis.com/v1/projects/${PROJECT_ID}/notes/${NOTE_ID}" || echo "000")"
      if [[ "$note_http" == "200" ]]; then
        import_if_missing \
          "google_container_analysis_note.build_attestor_note[0]" \
          "projects/${PROJECT_ID}/notes/${NOTE_ID}"
      fi
    fi

    if gcloud container binauthz attestors describe "$ATTESTOR_ID" --project="$PROJECT_ID" >/dev/null 2>&1; then
      import_if_missing \
        "google_binary_authorization_attestor.build_attestor[0]" \
        "projects/${PROJECT_ID}/attestors/${ATTESTOR_ID}"
    fi
  fi

  echo "✅ Foundational state import pass complete."
}

if [[ "$IMPORT_STATE" == "true" ]]; then
  import_foundational_state
  exit 0
fi

# ---------------------------------------------------------------------------
# Default Mode: Project Bootstrap (PF1, PF2, PF3, PF4, PF10)
# ---------------------------------------------------------------------------
echo "🚀 Bootstrapping GCP project '${PROJECT_ID}' (env=${ENV}, region=${REGION})..."

# --- PF1: Enable all required GCP APIs ---
REQUIRED_APIS=(
  "container.googleapis.com"
  "compute.googleapis.com"
  "storage.googleapis.com"
  "artifactregistry.googleapis.com"
  "containerfilesystem.googleapis.com"
  "cloudbuild.googleapis.com"
  "cloudkms.googleapis.com"
  "binaryauthorization.googleapis.com"
  "containeranalysis.googleapis.com"
  "memorystore.googleapis.com"
  "sqladmin.googleapis.com"
  "servicenetworking.googleapis.com"
  "networkconnectivity.googleapis.com"
  "privateca.googleapis.com"
  "secretmanager.googleapis.com"
  "iam.googleapis.com"
  "cloudresourcemanager.googleapis.com"
  "logging.googleapis.com"
  "monitoring.googleapis.com"
  "dns.googleapis.com"
  "accesscontextmanager.googleapis.com"
)

echo "🔌 [PF1] Enabling ${#REQUIRED_APIS[@]} required GCP APIs on '${PROJECT_ID}'..."
gcloud services enable "${REQUIRED_APIS[@]}" --project="$PROJECT_ID" --quiet

# --- PF2: Ensure remote Terraform state GCS bucket exists ---
echo "🪣 [PF2] Ensuring Terraform state bucket 'gs://${STATE_BUCKET}' exists..."
if ! gcloud storage buckets describe "gs://${STATE_BUCKET}" --project="$PROJECT_ID" >/dev/null 2>&1; then
  gcloud storage buckets create "gs://${STATE_BUCKET}" \
    --project="$PROJECT_ID" \
    --location="$REGION" \
    --uniform-bucket-level-access \
    --public-access-prevention \
    --quiet
fi
gcloud storage buckets update "gs://${STATE_BUCKET}" \
  --project="$PROJECT_ID" \
  --versioning \
  --quiet

# --- PF4: Ensure Artifact Registry gcr.io repository & Cloud Build staging bucket exist ---
echo "📦 [PF4] Ensuring Artifact Registry 'gcr.io' Docker repository and Cloud Build staging bucket exist..."
if ! gcloud artifacts repositories describe "gcr.io" --location="us" --project="$PROJECT_ID" >/dev/null 2>&1; then
  gcloud artifacts repositories create "gcr.io" \
    --repository-format=docker \
    --location="us" \
    --description="Container Registry compatibility repository for gcr.io/${PROJECT_ID}" \
    --project="$PROJECT_ID" \
    --quiet
fi

CB_BUCKET="${PROJECT_ID}_cloudbuild"
if ! gcloud storage buckets describe "gs://${CB_BUCKET}" --project="$PROJECT_ID" >/dev/null 2>&1; then
  gcloud storage buckets create "gs://${CB_BUCKET}" \
    --project="$PROJECT_ID" \
    --location="$REGION" \
    --uniform-bucket-level-access \
    --public-access-prevention \
    --quiet
fi

# --- PF3: Pre-create Cloud Build SA, KMS binauthz-attestor key, and BinAuthz attestor ---
echo "🔐 [PF3] Ensuring dedicated Cloud Build service account '${CB_SA_EMAIL}' exists..."
if ! gcloud iam service-accounts describe "$CB_SA_EMAIL" --project="$PROJECT_ID" >/dev/null 2>&1; then
  gcloud iam service-accounts create "$CB_SA_NAME" \
    --project="$PROJECT_ID" \
    --display-name="CAGE Cloud Build Service Account (${ENV})" \
    --description="Dedicated least-privilege Cloud Build identity for building, pushing, and attesting container images with the binauthz-attestor KMS key (SI-7 / CM-7 / AC-6 / POAM-2026-083)." \
    --quiet
fi

for role in \
  "roles/logging.logWriter" \
  "roles/artifactregistry.writer" \
  "roles/containeranalysis.occurrences.editor"; do
  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:${CB_SA_EMAIL}" \
    --role="$role" \
    --condition=None \
    --quiet >/dev/null
done

gcloud storage buckets add-iam-policy-binding "gs://${CB_BUCKET}" \
  --member="serviceAccount:${CB_SA_EMAIL}" \
  --role="roles/storage.objectViewer" \
  --quiet >/dev/null

echo "🔑 [PF3] Ensuring KMS KeyRing '${SIGNING_KEYRING}' and asymmetric key 'binauthz-attestor' exist..."
if ! gcloud kms keyrings describe "$SIGNING_KEYRING" --location="$REGION" --project="$PROJECT_ID" >/dev/null 2>&1; then
  gcloud kms keyrings create "$SIGNING_KEYRING" \
    --location="$REGION" \
    --project="$PROJECT_ID" \
    --quiet
fi

if ! gcloud kms keys describe "binauthz-attestor" \
  --keyring="$SIGNING_KEYRING" \
  --location="$REGION" \
  --project="$PROJECT_ID" >/dev/null 2>&1; then
  gcloud kms keys create "binauthz-attestor" \
    --keyring="$SIGNING_KEYRING" \
    --location="$REGION" \
    --project="$PROJECT_ID" \
    --purpose="asymmetric-signing" \
    --default-algorithm="ec-sign-p256-sha256" \
    --protection-level="$KMS_PROTECTION_LEVEL" \
    --labels="managed-by=terraform,component=cage-binauthz,environment=${ENV},nist-control=sa-10-si-7,poam=poam-2026-079,cage-key-purpose=asymmetric-signing,cage-signer=cloudbuild" \
    --quiet
fi

for kms_role in \
  "roles/cloudkms.signer" \
  "roles/cloudkms.publicKeyViewer" \
  "roles/cloudkms.viewer"; do
  gcloud kms keys add-iam-policy-binding "binauthz-attestor" \
    --keyring="$SIGNING_KEYRING" \
    --location="$REGION" \
    --project="$PROJECT_ID" \
    --member="serviceAccount:${CB_SA_EMAIL}" \
    --role="$kms_role" \
    --quiet >/dev/null
done

if [[ "$ENV" != "dev" ]]; then
  echo "🛡️  [PF3] Ensuring Container Analysis note '${NOTE_ID}' and Binary Authorization attestor '${ATTESTOR_ID}' exist..."
  ACCESS_TOKEN="$(gcloud auth print-access-token 2>/dev/null || true)"
  if [[ -n "$ACCESS_TOKEN" ]]; then
    NOTE_STATUS="$(curl -sS -o /dev/null -w '%{http_code}' \
      -H "Authorization: Bearer ${ACCESS_TOKEN}" \
      "https://containeranalysis.googleapis.com/v1/projects/${PROJECT_ID}/notes/${NOTE_ID}" || echo "000")"
    if [[ "$NOTE_STATUS" != "200" ]]; then
      curl -sS -f -X POST \
        -H "Authorization: Bearer ${ACCESS_TOKEN}" \
        -H "Content-Type: application/json" \
        "https://containeranalysis.googleapis.com/v1/projects/${PROJECT_ID}/notes?noteId=${NOTE_ID}" \
        -d "{\"name\":\"projects/${PROJECT_ID}/notes/${NOTE_ID}\",\"attestation\":{\"hint\":{\"humanReadableName\":\"CAGE Cloud Build Attestor (${ENV})\"}}}" >/dev/null
    fi
    curl -sS -f -X POST \
      -H "Authorization: Bearer ${ACCESS_TOKEN}" \
      -H "Content-Type: application/json" \
      "https://containeranalysis.googleapis.com/v1/projects/${PROJECT_ID}/notes/${NOTE_ID}:setIamPolicy" \
      -d "{\"policy\":{\"bindings\":[{\"role\":\"roles/containeranalysis.notes.attacher\",\"members\":[\"serviceAccount:${CB_SA_EMAIL}\"]},{\"role\":\"roles/containeranalysis.notes.occurrences.viewer\",\"members\":[\"serviceAccount:${CB_SA_EMAIL}\"]}]}}" >/dev/null
  fi

  if ! gcloud container binauthz attestors describe "$ATTESTOR_ID" --project="$PROJECT_ID" >/dev/null 2>&1; then
    gcloud container binauthz attestors create "$ATTESTOR_ID" \
      --project="$PROJECT_ID" \
      --attestation-authority-note="$NOTE_ID" \
      --attestation-authority-note-project="$PROJECT_ID" \
      --quiet
  fi

  EXISTING_KEYS="$(gcloud container binauthz attestors describe "$ATTESTOR_ID" \
    --project="$PROJECT_ID" \
    --format='value(userOwnedGrafeasNote.publicKeys.id)' 2>/dev/null || true)"
  if [[ "$EXISTING_KEYS" != *"binauthz-attestor/cryptoKeyVersions/1"* ]]; then
    gcloud container binauthz attestors public-keys add \
      --attestor="$ATTESTOR_ID" \
      --project="$PROJECT_ID" \
      --keyversion-project="$PROJECT_ID" \
      --keyversion-location="$REGION" \
      --keyversion-keyring="$SIGNING_KEYRING" \
      --keyversion-key="binauthz-attestor" \
      --keyversion="1" \
      --quiet
  fi

  gcloud container binauthz attestors add-iam-policy-binding \
    "projects/${PROJECT_ID}/attestors/${ATTESTOR_ID}" \
    --member="serviceAccount:${CB_SA_EMAIL}" \
    --role="roles/binaryauthorization.attestorsViewer" \
    --quiet >/dev/null
fi

# --- PF10: Ensure deployer service account has roles/cloudkms.publicKeyViewer ---
if [[ -z "$DEPLOYER_SA" ]]; then
  ACTIVE_ACCOUNT="$(gcloud config get-value account 2>/dev/null || true)"
  if [[ "$ACTIVE_ACCOUNT" == *.gserviceaccount.com ]]; then
    DEPLOYER_SA="$ACTIVE_ACCOUNT"
  fi
fi

if [[ -n "$DEPLOYER_SA" ]]; then
  echo "🔑 [PF10] Granting roles/cloudkms.publicKeyViewer to deployer SA '${DEPLOYER_SA}'..."
  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:${DEPLOYER_SA}" \
    --role="roles/cloudkms.publicKeyViewer" \
    --condition=None \
    --quiet >/dev/null
fi

echo "✅ GCP project '${PROJECT_ID}' bootstrap complete (env=${ENV}, region=${REGION}, state_bucket=gs://${STATE_BUCKET})."

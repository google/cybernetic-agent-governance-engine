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

set -eo pipefail

if [[ -z "$PROJECT_ID" ]]; then
  echo "❌ Error: PROJECT_ID environment variable is not set."
  exit 1
fi

wait_for_pids=()

build_image() {
  local image_name=$1
  local dockerfile=$2
  local context_dir=$3
  
  local full_image="gcr.io/${PROJECT_ID}/${image_name}:latest"
  echo "🏗️  Starting build for ${image_name} using ${dockerfile}..."

  # Create a temporary cloudbuild file
  local cb_file
  cb_file=$(mktemp -t cloudbuild)

  cat <<EOF > "$cb_file"
steps:
- name: 'gcr.io/cloud-builders/docker'
  args: ['build', '-t', '${full_image}', '-f', '${dockerfile}', '${context_dir}']
images:
- '${full_image}'
EOF

  # Fire and forget (in the background)
  gcloud builds submit --config "$cb_file" --project "$PROJECT_ID" "$context_dir" > "/tmp/build_${image_name}.log" 2>&1 &
  local pid=$!
  wait_for_pids+=("$pid")
  
  # Register cleanup
  trap 'rm -f "$cb_file"' EXIT
}

# 1. Backend / Governed Financial Advisor
echo "🏗️  Starting build for governed-financial-advisor..."
cb_backend=$(mktemp -t cloudbuild_backend)
cat <<EOF > "$cb_backend"
steps:
- name: 'gcr.io/cloud-builders/docker'
  args: ['build', '-t', 'gcr.io/${PROJECT_ID}/financial-advisor:latest', '-t', 'gcr.io/${PROJECT_ID}/governed-financial-advisor:latest', '-f', 'Dockerfile', '.']
images:
- 'gcr.io/${PROJECT_ID}/financial-advisor:latest'
- 'gcr.io/${PROJECT_ID}/governed-financial-advisor:latest'
EOF
gcloud builds submit --config "$cb_backend" --project "$PROJECT_ID" . > "/tmp/build_backend.log" 2>&1 &
wait_for_pids+=("$!")
trap 'rm -f "$cb_backend"' EXIT

# 2. vLLM Streamer
echo "🏗️  Starting build for vllm-streamer..."
if [[ -f "deployment/docker/cloudbuild.vllm.yaml" ]]; then
  # vLLM has its own cloudbuild yaml file
  hf_token=${HUGGING_FACE_HUB_TOKEN:-$HF_TOKEN}
  if [[ -n "$hf_token" ]]; then
    gcloud builds submit --config "deployment/docker/cloudbuild.vllm.yaml" \
      --project "$PROJECT_ID" --substitutions="_HF_TOKEN=$hf_token" . > "/tmp/build_vllm.log" 2>&1 &
  else
    gcloud builds submit --config "deployment/docker/cloudbuild.vllm.yaml" \
      --project "$PROJECT_ID" . > "/tmp/build_vllm.log" 2>&1 &
  fi
  wait_for_pids+=("$!")
else
  echo "⚠️  deployment/docker/cloudbuild.vllm.yaml not found. Skipping vLLM Streamer build."
fi

# 3. Gateway
if [[ -d "src/gateway" ]]; then
  build_image "gateway" "src/gateway/Dockerfile" "."
else
  echo "⚠️  src/gateway directory not found. Skipping Gateway build."
fi

# 4. AgentSight UI
build_image "agentsight-ui" "src/agentsight-ui/Dockerfile" "."

# 5. Compliance Bridge
if [[ -d "src/compliance_bridge" ]]; then
  build_image "compliance-bridge" "src/compliance_bridge/Dockerfile" "."
else
  echo "⚠️  src/compliance_bridge directory not found. Skipping Compliance Bridge build."
fi

# 6. NeMo Guardrails
build_image "nemo-guardrails" "Dockerfile.nemo" "."

echo "⏳ Waiting for all Cloud Build jobs to finish..."
fail=0
for pid in "${wait_for_pids[@]}"; do
  if ! wait "$pid"; then
    echo "❌ A Cloud Build job failed!"
    fail=1
  fi
done

if [[ $fail -eq 1 ]]; then
  echo "❌ One or more image builds failed."
  exit 1
fi

echo "✅ All images built successfully!"

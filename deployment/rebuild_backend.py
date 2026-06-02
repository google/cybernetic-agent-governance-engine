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

"""
Rebuild and redeploy the backend container image.

Replaces the former `gcloud builds submit` with a standard
`docker build && docker push` workflow compatible with any OCI registry.

Required environment variables:
  REGISTRY_URL  — e.g. ghcr.io/your-org/cybernetic-governance-engine
  IMAGE_TAG     — image tag (default: latest)
  K8S_NAMESPACE — K8s namespace (default: governance-stack)
"""

import subprocess
import os
import sys

REGISTRY_URL = os.environ.get("REGISTRY_URL", "")
if not REGISTRY_URL:
    print("ERROR: REGISTRY_URL environment variable must be set", file=sys.stderr)
    sys.exit(1)

IMAGE_TAG = os.environ.get("IMAGE_TAG", "latest")
IMAGE_NAME = f"{REGISTRY_URL}/backend:{IMAGE_TAG}"
K8S_NAMESPACE = os.environ.get("K8S_NAMESPACE", "governance-stack")


def run(cmd: str) -> None:
    print(f"Running: {cmd}")
    subprocess.check_call(cmd, shell=True)


print("🏗️ Rebuilding Backend...")
cwd = os.getcwd()
print(f"CWD: {cwd}")

print(f"📦 Building image: {IMAGE_NAME}")
run(f"docker build -t {IMAGE_NAME} -f src/governed_financial_advisor/Dockerfile .")

print(f"📤 Pushing image: {IMAGE_NAME}")
run(f"docker push {IMAGE_NAME}")

print("🔄 Restarting Deployment...")
run(f"kubectl rollout restart deployment/governed-financial-advisor -n {K8S_NAMESPACE}")
print("Waiting for rollout...")
run(f"kubectl rollout status deployment/governed-financial-advisor -n {K8S_NAMESPACE}")

print("✅ Backend Rebuilt and Restarted.")

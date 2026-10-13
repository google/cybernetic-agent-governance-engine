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

import subprocess
from pathlib import Path

def _mask_secret(value: str | None) -> str:
    if not value:
        return "<unset>"
    return value[:4] + "****"


# Load .env manually to be 100% sure
env_path = Path(".env")
env_vars: dict[str, str] = {}
if env_path.exists():
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env_vars[k.strip()] = v.strip().strip('"').strip("'")

print(f"✅ Loaded {len(env_vars)} vars from .env")
print(
    f"ALPHAVANTAGE_API_KEY from .env: {_mask_secret(env_vars.get('ALPHAVANTAGE_API_KEY'))}"
)

# Secrets to create — LangSmith is strictly forbidden in CAGE (AGENTS.md §7);
# enforce LANGCHAIN_TRACING_V2=false and LANGSMITH_TRACING=false.
advisor_secrets = {
    "LANGCHAIN_TRACING_V2": "false",
    "LANGSMITH_TRACING": "false",
    "ALPHAVANTAGE_API_KEY": env_vars.get("ALPHAVANTAGE_API_KEY", ""),
}

# Construct command
cmd = [
    "kubectl",
    "create",
    "secret",
    "generic",
    "advisor-secrets",
    "--dry-run=client",
    "-o",
    "yaml",
    "-n",
    "governance-stack",
]
for k, v in advisor_secrets.items():
    if v:
        cmd.append(f"--from-literal={k}={v}")

print("🚀 Creating advisor-secrets...")
try:
    secret_yaml = subprocess.check_output(cmd, text=True)
    subprocess.run(
        ["kubectl", "apply", "-f", "-"], input=secret_yaml, text=True, check=True
    )
    print("✅ advisor-secrets updated.")
except subprocess.CalledProcessError as e:
    print(f"❌ Failed to update secrets: {e}")
    raise SystemExit(1) from e

# Trigger SHA-pinned Cloud Build of governed-financial-advisor (never :latest)
project_id = env_vars.get("GOOGLE_CLOUD_PROJECT", "your-project-id")
short_sha = subprocess.check_output(
    ["git", "rev-parse", "--short", "HEAD"], text=True
).strip()
print(f"🏗️ Rebuilding Backend for {project_id} at {short_sha}...")
subprocess.run(
    [
        "gcloud",
        "builds",
        "submit",
        "--config",
        "deployment/docker/cloudbuild.image.yaml",
        f"--substitutions=_IMAGE_NAME=governed-financial-advisor,_DOCKERFILE=src/governed_financial_advisor/Dockerfile,_SHORT_SHA={short_sha}",
        "--project",
        project_id,
        ".",
    ],
    check=True,
)
print("✅ Backend Rebuilt.")

# Restart Deployment
print("🔄 Restarting Deployment...")
subprocess.run(
    [
        "kubectl",
        "rollout",
        "restart",
        "deployment/governed-financial-advisor",
        "-n",
        "governance-stack",
    ],
    check=True,
)
print("✅ Deployment Restarted.")


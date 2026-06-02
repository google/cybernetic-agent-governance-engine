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

import os
import subprocess
from pathlib import Path

# Load .env manually to be 100% sure we have PROJECT_ID
env_path = Path(".env")
env_vars = {}
if env_path.exists():
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env_vars[k.strip()] = v.strip().strip('"').strip("'")

project_id = env_vars.get("GOOGLE_CLOUD_PROJECT", "your-project-id")
print(f"🏗️ Rebuilding Backend for {project_id} (Logging Fix)...")

image_uri = f"gcr.io/{project_id}/financial-advisor:latest"
# Use same build command as before
subprocess.run(["gcloud", "builds", "submit", "--tag", image_uri, "--project", project_id, "."], check=True)
print("✅ Backend Rebuilt.")

print("🔄 Restarting Deployment...")
subprocess.run(["kubectl", "rollout", "restart", "deployment/governed-financial-advisor", "-n", "governance-stack"], check=True)
print("✅ Deployment Restarted.")

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


def load_dotenv(dotenv_path=None):
    if dotenv_path is None:
        dotenv_path = Path.cwd() / ".env"

    if not dotenv_path.exists():
        print(f"⚠️ .env file not found at {dotenv_path}")
        return False

    with open(dotenv_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                try:
                    key, value = line.split("=", 1)
                    os.environ[key] = value
                except ValueError:
                    pass
    return True


def create_secret():
    load_dotenv()

    aws_access_key = os.environ.get("AWS_ACCESS_KEY_ID", "")
    aws_secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
    aws_region = os.environ.get("AWS_REGION", "us-east-1")
    # Do not default to GCS endpoint; set AWS_ENDPOINT_URL explicitly if using GCS
    aws_endpoint = os.environ.get("AWS_ENDPOINT_URL", "")

    if not aws_access_key or not aws_secret_key:
        print("❌ AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY missing in .env")
        return

    print(
        f"🔑 Creating gcs-credentials-secret with Access Key: {aws_access_key[:5]}..."
    )

    cmd = [
        "kubectl",
        "create",
        "secret",
        "generic",
        "gcs-credentials-secret",
        f"--from-literal=AWS_ACCESS_KEY_ID={aws_access_key}",
        f"--from-literal=AWS_SECRET_ACCESS_KEY={aws_secret_key}",
        f"--from-literal=AWS_REGION={aws_region}",
        f"--from-literal=AWS_ENDPOINT_URL={aws_endpoint}",
        "-n",
        "governance-stack",
        "--dry-run=client",
        "-o",
        "yaml",
    ]

    # pipe to apply
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    subprocess.run(["kubectl", "apply", "-f", "-"], stdin=proc.stdout)
    print("✅ Secret apply command executed.")


if __name__ == "__main__":
    create_secret()

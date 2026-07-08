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

"""update_langfuse_secret.py

Idempotently creates / updates the two Kubernetes Secrets required by the
Langfuse stack in the governance-stack namespace:

  1. advisor-secrets   - patches DATABASE_URL with the Cloud SQL private IP.
  2. langfuse-secrets  - creates (or updates) the Langfuse init keys:
                            init-project-id, init-user-email, init-user-password
                         These are read from env vars or prompted interactively.
                         Missing langfuse-secrets is the root cause of the
                         langfuse-web CreateContainerConfigError.

Usage:
    python deployment/update_langfuse_secret.py

Required env vars (for non-interactive operation):
    GOOGLE_CLOUD_PROJECT       GCP project ID
    LANGFUSE_SQL_INSTANCE      Cloud SQL instance name (default: langfuse-instance-<project>)
    DATABASE_URL               Current connection string (postgresql://USER:PASS@HOST/DB)
    LANGFUSE_INIT_PROJECT_ID   UUID for the Langfuse project  (default: auto-generated)
    LANGFUSE_INIT_USER_EMAIL   Admin user e-mail
    LANGFUSE_INIT_USER_PASSWORD Admin user password
"""

import base64
import json
import os
import subprocess
import sys
import uuid

# ── helpers ──────────────────────────────────────────────────────────────────


def run(cmd: str, capture_output: bool = True) -> str:
    try:
        result = subprocess.run(
            cmd, shell=True, check=True, capture_output=capture_output, text=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error running: {cmd}")
        print(e.stderr)
        raise


def b64enc(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _get_or_prompt(env_key: str, prompt: str, default: str = "") -> str:
    """Return env var value, or prompt the user, falling back to *default*."""
    val = os.environ.get(env_key, "").strip()
    if val:
        return val
    if default:
        val = input(f"{prompt} [{default}]: ").strip()
        return val if val else default
    val = input(f"{prompt}: ").strip()
    if not val:
        print(f"❌  {env_key} is required.")
        sys.exit(1)
    return val


# ── Part 1: patch advisor-secrets / DATABASE_URL ─────────────────────────────


def patch_database_url(project_id: str, instance_name: str, conn_string: str) -> None:
    print("⏳ Fetching Cloud SQL instance private IP…")
    instance_json = run(
        f"gcloud sql instances describe {instance_name} "
        f"--project={project_id} --format=json"
    )
    instance_data = json.loads(instance_json)
    ip_addresses = instance_data.get("ipAddresses", [])
    private_ip = next(
        (ip["ipAddress"] for ip in ip_addresses if ip["type"] == "PRIVATE"), None
    )

    if not private_ip:
        ops = run(
            f"gcloud sql operations list --instance={instance_name} "
            f"--limit=1 --filter='status=RUNNING' --format='value(name)'"
        )
        if ops:
            print(f"⚠️  Operation {ops} is still running — please wait and retry.")
        else:
            print("❌  No private IP found for the Cloud SQL instance.")
        sys.exit(1)

    print(f"✅ Cloud SQL private IP: {private_ip}")

    if not conn_string:
        print("❌  DATABASE_URL env var is not set.")
        sys.exit(1)

    if "@" not in conn_string or "postgresql://" not in conn_string:
        print("❌  DATABASE_URL format must be postgresql://USER:PASS@HOST/DB")
        sys.exit(1)

    parts = conn_string.split("@")
    user_pass = parts[0].replace("postgresql://", "")
    if ":" not in user_pass:
        print("❌  Cannot parse USER:PASS from DATABASE_URL.")
        sys.exit(1)

    username, password = user_pass.split(":", 1)
    new_url = f"postgresql://{username}:{password}@{private_ip}:5432/langfuse"
    print(f"🔑 New DATABASE_URL: {new_url}")

    print("🚀 Patching advisor-secrets…")
    secret_json = run("kubectl get secret advisor-secrets -n governance-stack -o json")
    secret_data = json.loads(secret_json)
    secret_data["data"]["DATABASE_URL"] = b64enc(new_url)

    tmp = "/tmp/advisor-secrets-patch.json"
    with open(tmp, "w") as f:
        json.dump(secret_data, f)
    run(f"kubectl apply -f {tmp}")
    os.remove(tmp)
    print("✅ advisor-secrets patched.")


# ── Part 2: create / update langfuse-secrets ─────────────────────────────────


def ensure_langfuse_secrets(namespace: str = "governance-stack") -> None:
    """Idempotently create the `langfuse-secrets` K8s Secret.

    This secret is required by langfuse-web (langfuse-web.yaml lines 139-166).
    Its absence causes CreateContainerConfigError on every pod start.

    Keys managed:
      init-project-id      - stable UUID for the Langfuse project
      init-user-email      - initial admin user e-mail
      init-user-password   - initial admin user password
    """
    print("\n── langfuse-secrets ──────────────────────────────────────────────")

    # Determine values — env vars take priority, then interactive prompt.
    project_id_val = _get_or_prompt(
        "LANGFUSE_INIT_PROJECT_ID",
        "Langfuse init project UUID",
        default=str(uuid.uuid4()),
    )
    user_email = _get_or_prompt(
        "LANGFUSE_INIT_USER_EMAIL",
        "Langfuse admin user e-mail",
    )
    user_password = _get_or_prompt(
        "LANGFUSE_INIT_USER_PASSWORD",
        "Langfuse admin user password",
    )

    # Check whether the secret already exists so we can decide create vs patch.
    exists_rc = subprocess.run(
        f"kubectl get secret langfuse-secrets -n {namespace}",
        shell=True,
        capture_output=True,
    ).returncode

    if exists_rc == 0:
        print("[INFO] langfuse-secrets already exists - patching keys...")
        # Read, merge, re-apply.
        raw = run(f"kubectl get secret langfuse-secrets -n {namespace} -o json")
        obj = json.loads(raw)
        obj.setdefault("data", {})
        obj["data"]["init-project-id"] = b64enc(project_id_val)
        obj["data"]["init-user-email"] = b64enc(user_email)
        obj["data"]["init-user-password"] = b64enc(user_password)
        tmp = "/tmp/langfuse-secrets-patch.json"
        with open(tmp, "w") as f:
            json.dump(obj, f)
        run(f"kubectl apply -f {tmp}")
        os.remove(tmp)
    else:
        print("[+] Creating langfuse-secrets...")
        run(
            f"kubectl create secret generic langfuse-secrets"
            f" --from-literal=init-project-id={project_id_val}"
            f" --from-literal=init-user-email={user_email}"
            f" --from-literal=init-user-password={user_password}"
            f" -n {namespace}"
        )

    print("✅ langfuse-secrets is ready.")

    # Force a rolling restart so langfuse-web picks up the new secret.
    print("🔄 Rolling restart of langfuse-web and langfuse-worker…")
    run("kubectl rollout restart deployment/langfuse-web -n governance-stack")
    run("kubectl rollout restart deployment/langfuse-worker -n governance-stack")
    print("✅ Rollout triggered — watch with:")
    print("   kubectl rollout status deployment/langfuse-web -n governance-stack")
    print("   kubectl rollout status deployment/langfuse-worker -n governance-stack")


# ── main ─────────────────────────────────────────────────────────────────────


def main() -> None:
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT", "")
    instance_name = os.environ.get(
        "LANGFUSE_SQL_INSTANCE",
        f"langfuse-instance-{project_id}"
        if project_id
        else f"langfuse-instance-{os.environ.get('GCP_PROJECT_ID', '<your-project-id>')}",
    )
    conn_string = os.environ.get("DATABASE_URL", "")

    # Part 1 is optional — only run when the GCP project is known and a
    # DATABASE_URL is available (i.e. during initial cluster setup).
    if project_id and conn_string:
        try:
            patch_database_url(project_id, instance_name, conn_string)
        except Exception as exc:
            print(f"⚠️  Could not patch DATABASE_URL: {exc}")
            print("    Continuing to langfuse-secrets step…")
    else:
        print(
            "[INFO] GOOGLE_CLOUD_PROJECT or DATABASE_URL not set - "
            "skipping advisor-secrets DATABASE_URL patch."
        )

    # Part 2 always runs — this is the fix for CreateContainerConfigError.
    ensure_langfuse_secrets()


if __name__ == "__main__":
    main()

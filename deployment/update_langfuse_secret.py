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
import getpass
import json
import os
import re
import subprocess
import sys
import uuid

_CREDENTIAL_URI_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://[^:/@\s]+:)([^@\s]+)(@)")


# ── helpers ──────────────────────────────────────────────────────────────────


def _scrub_text(text: str, extra_secrets: tuple[str, ...] = ()) -> str:
    """Scrub URI passwords and caller-supplied secret values before logging."""
    scrubbed = _CREDENTIAL_URI_RE.sub(r"\1****\3", text)
    for secret in extra_secrets:
        if secret:
            scrubbed = scrubbed.replace(secret, "****")
    return scrubbed


def _redact_cmd(cmd: list[str]) -> list[str]:
    """Redact any sensitive flag values before logging command failures."""
    redacted: list[str] = []
    for token in cmd:
        if (
            token.startswith("--from-literal=")
            and "=" in token[len("--from-literal=") :]
        ):
            key = token.split("=", 2)[1]
            redacted.append(f"--from-literal={key}=****")
        else:
            redacted.append(_scrub_text(token))
    return redacted


def run(
    cmd: list[str],
    capture_output: bool = True,
    input_data: str | None = None,
    redact_values: tuple[str, ...] = (),
) -> str:
    try:
        result = subprocess.run(
            cmd,
            shell=False,
            check=True,
            capture_output=capture_output,
            text=True,
            input=input_data,
        )
        return result.stdout.strip() if result.stdout else ""
    except subprocess.CalledProcessError as exc:
        safe_cmd = _redact_cmd(cmd)
        safe_err = _scrub_text(exc.stderr or "", redact_values).strip()
        print(f"Error running: {safe_cmd} (exit code {exc.returncode})")
        if safe_err:
            print(safe_err)
        raise RuntimeError(
            f"Command {safe_cmd[0]} failed with exit code {exc.returncode}"
        ) from None


def b64enc(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _get_or_prompt(
    env_key: str,
    prompt: str,
    default: str = "",
    *,
    is_secret: bool = False,
) -> str:
    """Return env var value, or prompt the user, falling back to *default*."""
    val = os.environ.get(env_key, "").strip()
    if val:
        return val
    if is_secret:
        val = getpass.getpass(f"{prompt}: ").strip()
    elif default:
        val = input(f"{prompt} [{default}]: ").strip()
        return val if val else default
    else:
        val = input(f"{prompt}: ").strip()
    if not val:
        if default:
            return default
        print(f"❌  {env_key} is required.")
        sys.exit(1)
    return val


def _build_secret_manifest(
    name: str,
    namespace: str,
    encoded_data: dict[str, str],
) -> dict[str, object]:
    """Construct a Kubernetes v1/Secret manifest with base64-encoded data."""
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": name,
            "namespace": namespace,
        },
        "type": "Opaque",
        "data": encoded_data,
    }


# ── Part 1: patch advisor-secrets / DATABASE_URL ─────────────────────────────


def patch_database_url(project_id: str, instance_name: str, conn_string: str) -> None:
    print("⏳ Fetching Cloud SQL instance private IP…")
    instance_json = run(
        [
            "gcloud",
            "sql",
            "instances",
            "describe",
            instance_name,
            f"--project={project_id}",
            "--format=json",
        ]
    )
    instance_data = json.loads(instance_json)
    ip_addresses = instance_data.get("ipAddresses", [])
    private_ip = next(
        (ip["ipAddress"] for ip in ip_addresses if ip["type"] == "PRIVATE"), None
    )

    if not private_ip:
        ops = run(
            [
                "gcloud",
                "sql",
                "operations",
                "list",
                f"--instance={instance_name}",
                "--limit=1",
                "--filter=status=RUNNING",
                "--format=value(name)",
            ]
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
    masked_pw = password[:4] + "****" if len(password) > 4 else "****"
    masked_url = f"postgresql://{username}:{masked_pw}@{private_ip}:5432/langfuse"
    print(f"🔑 New DATABASE_URL: {masked_url}")

    print("🚀 Patching advisor-secrets…")
    secret_json = run(
        [
            "kubectl",
            "get",
            "secret",
            "advisor-secrets",
            "-n",
            "governance-stack",
            "-o",
            "json",
        ],
        redact_values=(password, new_url, conn_string),
    )
    secret_data = json.loads(secret_json)
    secret_data.setdefault("data", {})
    secret_data["data"]["DATABASE_URL"] = b64enc(new_url)

    run(
        ["kubectl", "apply", "-f", "-"],
        input_data=json.dumps(secret_data),
        redact_values=(password, new_url, conn_string),
    )
    print("✅ advisor-secrets patched.")


# ── Part 2: create / update langfuse-secrets ─────────────────────────────────


def ensure_langfuse_secrets(namespace: str = "governance-stack") -> None:
    """Idempotently create or update the `langfuse-secrets` K8s Secret via stdin.

    Secret material is piped exclusively over stdin to `kubectl apply -f -` and
    never passed on process `argv` (`--from-literal`).
    """
    print("\n── langfuse-secrets ──────────────────────────────────────────────")

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
        is_secret=True,
    )

    exists_rc = subprocess.run(
        ["kubectl", "get", "secret", "langfuse-secrets", "-n", namespace],
        shell=False,
        check=False,
        capture_output=True,
    ).returncode

    encoded_fields = {
        "init-project-id": b64enc(project_id_val),
        "init-user-email": b64enc(user_email),
        "init-user-password": b64enc(user_password),
    }

    if exists_rc == 0:
        print("[INFO] langfuse-secrets already exists - patching keys...")
        print(
            "⚠️  WARNING: LANGFUSE_INIT_USER_PASSWORD only seeds on first user creation.\n"
            "   Patching langfuse-secrets and restarting langfuse-web does NOT rotate an\n"
            "   existing user's password in Cloud SQL Postgres (`users.password`). To rotate\n"
            "   a live credential, update the bcrypt hash in Postgres `users.password` and\n"
            "   purge `sessions` directly (see POAM-2026-162)."
        )
        raw = run(
            [
                "kubectl",
                "get",
                "secret",
                "langfuse-secrets",
                "-n",
                namespace,
                "-o",
                "json",
            ],
            redact_values=(user_password,),
        )
        obj = json.loads(raw)
        obj.setdefault("data", {})
        obj["data"].update(encoded_fields)
        manifest_payload: dict[str, object] = obj
    else:
        print("[+] Creating langfuse-secrets via stdin manifest...")
        manifest_payload = _build_secret_manifest(
            name="langfuse-secrets",
            namespace=namespace,
            encoded_data=encoded_fields,
        )

    run(
        ["kubectl", "apply", "-f", "-"],
        input_data=json.dumps(manifest_payload),
        redact_values=(user_password,),
    )

    print("✅ langfuse-secrets is ready.")

    print("🔄 Rolling restart of langfuse-web and langfuse-worker…")
    run(
        [
            "kubectl",
            "rollout",
            "restart",
            "deployment/langfuse-web",
            "-n",
            namespace,
        ]
    )
    run(
        [
            "kubectl",
            "rollout",
            "restart",
            "deployment/langfuse-worker",
            "-n",
            namespace,
        ]
    )
    print("✅ Rollout triggered — watch with:")
    print(f"   kubectl rollout status deployment/langfuse-web -n {namespace}")
    print(f"   kubectl rollout status deployment/langfuse-worker -n {namespace}")


# ── main ─────────────────────────────────────────────────────────────────────


def main() -> None:
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT", "")
    instance_name = os.environ.get(
        "LANGFUSE_SQL_INSTANCE",
        f"langfuse-instance-{project_id}"
        if project_id
        else f"langfuse-instance-{os.environ.get('GCP_PROJECT_ID', '<PROJECT_ID>')}",
    )
    conn_string = os.environ.get("DATABASE_URL", "")

    if project_id and conn_string:
        try:
            patch_database_url(project_id, instance_name, conn_string)
        except Exception as exc:
            print(
                f"⚠️  Could not patch DATABASE_URL: {_scrub_text(str(exc), (conn_string,))}"
            )
            print("    Continuing to langfuse-secrets step…")
    else:
        print(
            "[INFO] GOOGLE_CLOUD_PROJECT or DATABASE_URL not set - "
            "skipping advisor-secrets DATABASE_URL patch."
        )

    ensure_langfuse_secrets()


if __name__ == "__main__":
    main()

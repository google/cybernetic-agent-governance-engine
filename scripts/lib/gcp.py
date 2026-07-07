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
Cloud-agnostic infrastructure helpers.

Replaces the former GCP-specific helpers (gcloud APIs, Cloud Redis, Secret Manager)
with kubectl/Helm-based equivalents that work on any Kubernetes cluster.
"""

from .utils import run_command


def ensure_namespace(namespace: str = "governance-stack") -> None:
    """Ensure the K8s namespace exists."""
    print(f"\n--- 🛠️ Ensuring namespace: {namespace} ---")
    run_command(
        ["kubectl", "create", "namespace", namespace, "--dry-run=client", "-o", "yaml"],
        check=False,
    )
    run_command(
        ["kubectl", "apply", "-f", "-"],
        check=False,
    )


def get_redis_host(
    namespace: str = "governance-stack",
    service_name: str = "redis-master",
    port: str = "6379",
) -> tuple[str, str]:
    """
    Return the in-cluster Redis host and port.

    Redis is deployed via the Bitnami Helm chart (or included in docker-compose).
    The host is the Kubernetes Service DNS name:
        <service>.<namespace>.svc.cluster.local
    """
    host = f"{service_name}.{namespace}.svc.cluster.local"
    print(f"✅ Redis service: {host}:{port}")
    return host, port


def check_secret_exists(namespace: str, secret_name: str) -> bool:
    """Check if a K8s Secret exists."""
    result = run_command(
        ["kubectl", "get", "secret", secret_name, "-n", namespace],
        check=False,
        capture_output=True,
    )
    return result.returncode == 0


def create_secret_from_env(
    namespace: str,
    secret_name: str,
    env_vars: dict[str, str],
) -> None:
    """Create or update a K8s Secret from a dict of env-var key/value pairs."""
    if check_secret_exists(namespace, secret_name):
        print(f"🔒 Secret {secret_name} exists. Updating...")
        run_command(["kubectl", "delete", "secret", secret_name, "-n", namespace])

    cmd = ["kubectl", "create", "secret", "generic", secret_name, "-n", namespace]
    for key, value in env_vars.items():
        cmd.append(f"--from-literal={key}={value}")
    run_command(cmd)
    print(f"✅ Secret {secret_name} created in namespace {namespace}.")


def create_secret_from_file(
    namespace: str,
    secret_name: str,
    file_path: str,
    key: str | None = None,
) -> None:
    """Create or update a K8s Secret from a file."""
    if check_secret_exists(namespace, secret_name):
        print(f"🔒 Secret {secret_name} exists. Updating...")
        run_command(["kubectl", "delete", "secret", secret_name, "-n", namespace])

    from_file_arg = (
        f"--from-file={key}={file_path}" if key else f"--from-file={file_path}"
    )
    run_command(
        [
            "kubectl",
            "create",
            "secret",
            "generic",
            secret_name,
            "-n",
            namespace,
            from_file_arg,
        ]
    )
    print(f"✅ Secret {secret_name} created from file {file_path}.")

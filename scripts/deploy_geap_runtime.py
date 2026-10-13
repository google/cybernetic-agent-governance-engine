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

"""Deploy or update the Governed Financial Advisor on GEAP Agent Runtime.

Invoked by `infra/modules/gcp_geap_advisor/main.tf` (`terraform_data.geap_reasoning_engine`)
to provision the actual Vertex AI / GEAP Agent Runtime (`ReasoningEngine`)
resource in Google Cloud (`projects/{project}/locations/{region}/reasoningEngines`).

Enforces:
- POAM-2026-079: Refuses to deploy if any signing key variable is present in
  the runtime environment dictionary.
- GEAP Reserved Env Vars Contract: Refuses to deploy if any reserved GEAP
  environment variable (`GOOGLE_CLOUD_PROJECT`, `GOOGLE_CLOUD_LOCATION`, `PORT`,
  `K_SERVICE`, etc.) is present in the runtime environment dictionary.
- Bandit B310: Strictly validates `https://` scheme before any `urlopen` call.
"""

from __future__ import annotations

import argparse
import base64
import io
import json
import logging
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from src.governed_financial_advisor.geap_app import (
    CLASS_METHODS,
    GEAP_RESERVED_ENV_PREFIX,
    GEAP_RESERVED_ENV_VARS,
)
from src.governed_financial_advisor.infrastructure.identity_guard import (
    FORBIDDEN_SIGNING_KEY_VARS,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s  %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)


_GEAP_REQUIREMENTS_TXT = """\
google-cloud-aiplatform[agent_engines,langgraph]>=1.112.0
langgraph>=0.2.0
langchain-core>=0.3.0
langchain-openai>=0.2.0
fastapi>=0.115.0
uvicorn>=0.30.0
pydantic>=2.7.0
python-dotenv>=1.0.0
PyYAML>=6.0.0
prometheus-client>=0.20.0
python-json-logger>=2.0.0
requests>=2.31.0
httpx>=0.27.0
redis>=5.0.0
PyJWT[crypto]>=2.8.0
cryptography>=42.0.0
opentelemetry-api>=1.25.0
opentelemetry-sdk>=1.25.0
opentelemetry-exporter-otlp>=1.25.0
"""

_SOURCE_DIRS: tuple[str, ...] = (
    "config",
    "src/governed_financial_advisor",
    "src/gateway",
    "src/integrations",
    "src/cage_finance",
)

_INCLUDED_SUFFIXES: frozenset[str] = frozenset(
    {".py", ".yaml", ".yml", ".json", ".rego", ".co", ".txt"}
)


def _assert_https_url(url: str) -> None:
    """Validate that `url` uses the `https://` scheme (Bandit B310 compliance)."""
    if not url.startswith("https://"):
        raise ValueError(f"Refusing non-HTTPS URL: {url!r}")


def _get_access_token() -> str:
    """Obtain an OAuth2 Bearer access token via gcloud CLI."""
    proc = subprocess.run(
        ["gcloud", "auth", "print-access-token"],
        check=True,
        capture_output=True,
        text=True,
    )
    token = proc.stdout.strip()
    if not token:
        raise RuntimeError("gcloud auth print-access-token returned an empty token.")
    return token


def build_inline_source_archive(repo_root: Path = _REPO_ROOT) -> str:
    """Build a base64-encoded `.tar.gz` source archive for `InlineSource`."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        # Include top-level src/__init__.py if present
        src_init = repo_root / "src" / "__init__.py"
        if src_init.is_file():
            tf.add(src_init, arcname="src/__init__.py")

        for rel_dir in _SOURCE_DIRS:
            abs_dir = repo_root / rel_dir
            if not abs_dir.exists():
                continue
            for path in sorted(abs_dir.rglob("*")):
                if (
                    path.is_file()
                    and "__pycache__" not in path.parts
                    and path.suffix in _INCLUDED_SUFFIXES
                ):
                    arcname = str(path.relative_to(repo_root))
                    tf.add(path, arcname=arcname)

        # Add minimal requirements.txt at archive root for PythonSpec
        req_bytes = _GEAP_REQUIREMENTS_TXT.encode("utf-8")
        req_info = tarfile.TarInfo(name="requirements.txt")
        req_info.size = len(req_bytes)
        tf.addfile(req_info, io.BytesIO(req_bytes))

    raw_bytes = buf.getvalue()
    if len(raw_bytes) > 8 * 1024 * 1024:
        raise ValueError(
            f"GEAP inlineSource archive size ({len(raw_bytes)} bytes) exceeds 8 MB limit."
        )
    return base64.b64encode(raw_bytes).decode("ascii")


def validate_runtime_env_vars(env_vars: dict[str, str]) -> None:
    """Verify POAM-2026-079 and GEAP reserved environment variable invariants."""
    keys = set(env_vars.keys())
    forbidden_signing = keys & set(FORBIDDEN_SIGNING_KEY_VARS)
    if forbidden_signing:
        raise ValueError(
            f"POAM-2026-079 violation: signing key variables forbidden in GEAP runtime: "
            f"{sorted(forbidden_signing)}"
        )
    reserved = keys & set(GEAP_RESERVED_ENV_VARS)
    if reserved:
        raise ValueError(
            f"GEAP Runtime Contract violation: reserved env vars must not be set: "
            f"{sorted(reserved)}"
        )
    reserved_prefix = [k for k in keys if k.startswith(GEAP_RESERVED_ENV_PREFIX)]
    if reserved_prefix:
        raise ValueError(
            f"GEAP Runtime Contract violation: {GEAP_RESERVED_ENV_PREFIX}* prefix is reserved: "
            f"{sorted(reserved_prefix)}"
        )


def build_reasoning_engine_payload(
    *,
    display_name: str,
    entrypoint_module: str,
    entrypoint_object: str,
    env_vars: dict[str, str],
    cpu_limit: str = "4",
    memory_limit: str = "8Gi",
    min_instances: int = 1,
    max_instances: int = 100,
    container_concurrency: int = 9,
    identity_type: str = "AGENT_IDENTITY",
    agent_framework: str = "custom",
    source_archive_b64: str,
) -> dict[str, Any]:
    """Construct the REST `ReasoningEngine` resource body."""
    validate_runtime_env_vars(env_vars)
    env_list = [
        {"name": k, "value": str(v)}
        for k, v in sorted(env_vars.items())
        if v is not None and str(v) != ""
    ]

    return {
        "displayName": display_name,
        "description": (
            "CAGE Governed Financial Advisor on GEAP Agent Runtime "
            "(Zero Signing Authority, POAM-2026-079 / POAM-2026-080)"
        ),
        "labels": {
            "managed-by": "terraform",
            "cage-component": "governed-financial-advisor",
            "cage-runtime": "geap",
        },
        "spec": {
            "agentFramework": agent_framework,
            "identityType": identity_type,
            "sourceCodeSpec": {
                "inlineSource": {
                    "sourceArchive": source_archive_b64,
                },
                "pythonSpec": {
                    "version": "3.12",
                    "entrypointModule": entrypoint_module,
                    "entrypointObject": entrypoint_object,
                    "requirementsFile": "requirements.txt",
                },
            },
            "classMethods": list(CLASS_METHODS),
            "deploymentSpec": {
                "env": env_list,
                "resourceLimits": {
                    "cpu": str(cpu_limit),
                    "memory": str(memory_limit),
                },
                "minInstances": int(min_instances),
                "maxInstances": int(max_instances),
                "containerConcurrency": int(container_concurrency),
            },
        },
    }


def _api_request(
    method: str,
    url: str,
    token: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    _assert_https_url(url)
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:  # nosec B310
            body = resp.read().decode("utf-8")
            return json.loads(body) if body.strip() else {}
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"GEAP API {method} {url} failed with HTTP {exc.code}: {err_body}"
        ) from exc


def _wait_for_lro(
    region: str,
    operation_name: str,
    timeout_seconds: int = 900,
) -> dict[str, Any]:
    """Poll a Vertex AI Long-Running Operation until `done: true`."""
    url = f"https://{region}-aiplatform.googleapis.com/v1beta1/{operation_name}"
    _assert_https_url(url)
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        token = _get_access_token()
        op = _api_request("GET", url, token)
        if op.get("done"):
            if "error" in op:
                raise RuntimeError(
                    f"GEAP ReasoningEngine operation failed: {json.dumps(op['error'])}"
                )
            return op.get("response", op)
        logger.info("Waiting for GEAP ReasoningEngine LRO %s...", operation_name)
        time.sleep(10)
    raise TimeoutError(
        f"Timed out after {timeout_seconds}s waiting for LRO {operation_name}"
    )


def find_existing_reasoning_engine(
    project_id: str,
    region: str,
    display_name: str,
    token: str,
) -> dict[str, Any] | None:
    """Return the existing ReasoningEngine resource matching `display_name`, if any."""
    url = (
        f"https://{region}-aiplatform.googleapis.com/v1beta1/"
        f"projects/{project_id}/locations/{region}/reasoningEngines"
    )
    resp = _api_request("GET", url, token)
    for engine in resp.get("reasoningEngines", []):
        if engine.get("displayName") == display_name:
            return engine
    return None


def deploy_or_update(
    *,
    project_id: str,
    region: str,
    display_name: str,
    entrypoint_module: str,
    entrypoint_object: str,
    env_vars: dict[str, str],
    cpu_limit: str,
    memory_limit: str,
    min_instances: int,
    max_instances: int,
    container_concurrency: int,
    wait_for_lro: bool = True,
) -> dict[str, Any]:
    """Create or update the ReasoningEngine in GEAP Agent Runtime."""
    token = _get_access_token()
    archive_b64 = build_inline_source_archive()
    payload = build_reasoning_engine_payload(
        display_name=display_name,
        entrypoint_module=entrypoint_module,
        entrypoint_object=entrypoint_object,
        env_vars=env_vars,
        cpu_limit=cpu_limit,
        memory_limit=memory_limit,
        min_instances=min_instances,
        max_instances=max_instances,
        container_concurrency=container_concurrency,
        source_archive_b64=archive_b64,
    )

    existing = find_existing_reasoning_engine(project_id, region, display_name, token)
    if existing is not None:
        resource_name = existing["name"]
        logger.info(
            "Updating existing GEAP ReasoningEngine: %s (displayName=%s)",
            resource_name,
            display_name,
        )
        patch_url = (
            f"https://{region}-aiplatform.googleapis.com/v1beta1/{resource_name}"
            "?updateMask=displayName,description,spec"
        )
        op = _api_request("PATCH", patch_url, token, payload)
    else:
        create_url = (
            f"https://{region}-aiplatform.googleapis.com/v1beta1/"
            f"projects/{project_id}/locations/{region}/reasoningEngines"
        )
        logger.info(
            "Creating GEAP ReasoningEngine '%s' in %s/%s...",
            display_name,
            project_id,
            region,
        )
        op = _api_request("POST", create_url, token, payload)

    op_name = op.get("name", "")
    logger.info("Submitted GEAP ReasoningEngine LRO: %s", op_name)
    if wait_for_lro and op_name and not op.get("done"):
        result = _wait_for_lro(region, op_name)
        logger.info(
            "GEAP ReasoningEngine ready: %s",
            result.get("name", op_name),
        )
        return result
    return op


def delete_reasoning_engine(
    *,
    project_id: str,
    region: str,
    display_name: str,
) -> None:
    """Delete the ReasoningEngine matching `display_name` if it exists."""
    token = _get_access_token()
    existing = find_existing_reasoning_engine(project_id, region, display_name, token)
    if existing is None:
        logger.info(
            "No existing GEAP ReasoningEngine '%s' found in %s/%s; nothing to delete.",
            display_name,
            project_id,
            region,
        )
        return
    resource_name = existing["name"]
    delete_url = (
        f"https://{region}-aiplatform.googleapis.com/v1beta1/{resource_name}?force=true"
    )
    op = _api_request("DELETE", delete_url, token)
    logger.info(
        "Deleted GEAP ReasoningEngine %s (op=%s)", resource_name, op.get("name")
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Deploy or update Governed Financial Advisor on GEAP Agent Runtime."
    )
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--agent-id", default="governed-financial-advisor")
    parser.add_argument(
        "--entrypoint-module",
        default="src.governed_financial_advisor.geap_app",
    )
    parser.add_argument("--entrypoint-object", default="root_agent")
    parser.add_argument("--env-json", default="{}")
    parser.add_argument("--cpu-limit", default="4")
    parser.add_argument("--memory-limit", default="8Gi")
    parser.add_argument("--min-instances", type=int, default=1)
    parser.add_argument("--max-instances", type=int, default=100)
    parser.add_argument("--container-concurrency", type=int, default=9)
    parser.add_argument("--no-wait", action="store_true")
    parser.add_argument("--delete", action="store_true")
    args = parser.parse_args(argv)

    if args.delete:
        delete_reasoning_engine(
            project_id=args.project_id,
            region=args.region,
            display_name=args.agent_id,
        )
        return 0

    env_vars = json.loads(args.env_json)
    deploy_or_update(
        project_id=args.project_id,
        region=args.region,
        display_name=args.agent_id,
        entrypoint_module=args.entrypoint_module,
        entrypoint_object=args.entrypoint_object,
        env_vars=env_vars,
        cpu_limit=args.cpu_limit,
        memory_limit=args.memory_limit,
        min_instances=args.min_instances,
        max_instances=args.max_instances,
        container_concurrency=args.container_concurrency,
        wait_for_lro=not args.no_wait,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

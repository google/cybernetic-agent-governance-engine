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

"""Loader translating CAGE STPA-compiled sandbox policies into OpenShell runtime rules."""

from __future__ import annotations

from pathlib import Path
from typing import Any
import yaml


def load_cage_sandbox_policy(policy_path: str | Path) -> dict[str, Any]:
    """Parse and validate a CAGE-compiled sandbox policy for OpenShell.

    Extracts:
      - ``filesystem_policy``: Read-only and read-write path lists for Linux Landlock LSM
      - ``allowed_binaries``: Explicit execution whitelist
      - ``credential_broker_rules``: PreCredentials declarations for dynamic secret broker
      - ``network_policies``: Egress endpoints and HTTP verbs allowed per action
      - ``mcp_rules``: Explicit MCP tools permitted within the sandbox
    """
    path = Path(policy_path)
    if not path.is_file():
        raise FileNotFoundError(f"CAGE sandbox policy file not found: {path}")

    with path.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    if not isinstance(raw, dict) or "metadata" not in raw:
        raise ValueError("Invalid CAGE sandbox policy: missing metadata block")

    metadata = raw.get("metadata", {})
    if not metadata.get("require_cage_stera_seal"):
        raise ValueError("CAGE policy must enforce require_cage_stera_seal=true")

    fs = raw.get("filesystem_policy", {})
    process = raw.get("process", {})
    creds = raw.get("credential_broker_rules", {})
    net = raw.get("network_policies", {})

    return {
        "metadata": metadata,
        "landlock_ro_paths": fs.get("read_only", []),
        "landlock_rw_paths": fs.get("read_write", []),
        "allowed_binaries": process.get("allowed_binaries", []),
        "credential_broker_rules": creds,
        "network_policies": net,
    }

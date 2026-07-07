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

from pathlib import Path
from typing import Any

import yaml


def load_config(config_path: str = "deployment/config.yaml") -> dict[str, Any]:
    """
    Loads configuration from a YAML file.
    Returns a dictionary with defaults.
    """
    path = Path(config_path)
    if not path.exists():
        # Fallback to root-relative if running from root
        path = Path(__file__).parent.parent / "config.yaml"

    if not path.exists():
        print(f"⚠️ Config file not found at {path}. Using empty defaults.")
        return {}

    with open(path) as f:
        return yaml.safe_load(f) or {}


def merge_args_into_config(config: dict[str, Any], args: Any) -> dict[str, Any]:
    """
    Merges CLI arguments into the configuration dictionary.
    CLI args take precedence over YAML defaults.
    """
    # Create a deep copy or just modify mechanism?
    # Let's modify a fresh dict structure to avoid side effects on base config if cached.
    # For simplicity, we just update the specific keys we care about.

    if args.region:
        config.setdefault("project", {})["region"] = args.region
    if args.zone:
        config.setdefault("project", {})["zone"] = args.zone

    # Accelerator overrides
    if args.accelerator_type:
        config.setdefault("cluster", {}).setdefault("accelerator", {})["type"] = (
            f"nvidia-tesla-{args.accelerator_type}"
        )
        # Adjust machine type if A100 is requested (override default)
        if args.accelerator_type == "a100":
            config["cluster"]["machine_type"] = "a2-highgpu-1g"
            config["cluster"]["disk_size_gb"] = 100
            config["cluster"]["accelerator"]["type"] = "nvidia-tesla-a100"

    # Spot override
    if args.spot:
        config.setdefault("cluster", {})["spot"] = True

    # Redis overrides
    if args.redis_host:
        config.setdefault("redis", {})["host"] = args.redis_host
    if args.redis_port:
        config.setdefault("redis", {})["port"] = args.redis_port

    return config

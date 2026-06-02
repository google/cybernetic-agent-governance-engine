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
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.append(os.getcwd())

from deployment.lib.renderer import generate_vllm_manifest
from deployment.lib.config import load_config
from deployment.lib.utils import load_dotenv

def main():
    load_dotenv()
    config = load_config()
    config["project"] = {"id": os.environ.get("GOOGLE_CLOUD_PROJECT", "")}
    
    # Check if we need to load from env for reasoning
    model_reasoning = os.environ.get("MODEL_REASONING")
    if not model_reasoning:
        print("MODEL_REASONING env var not set")
        return

    reasoning_config = config.copy()
    reasoning_config["model"] = {
        "name": model_reasoning,
        "quantization": "awq" if "awq" in model_reasoning.lower() else None,
        "max_model_len": "32768",
        "gpu_memory_utilization": "0.9",
        "enforce_eager": True,
        "enable_prefix_caching": True,
        "served_name": os.environ.get("MODEL_REASONING"),
    }
    
    accelerator_kind = os.environ.get("ACCELERATOR_KIND", "gpu")
    
    manifest = generate_vllm_manifest(accelerator_kind, reasoning_config, app_name="vllm-reasoning")
    with open("vllm-reasoning-manual.yaml", "w") as f:
        f.write(manifest)
    print("Manifest written to vllm-reasoning-manual.yaml")

if __name__ == "__main__":
    main()

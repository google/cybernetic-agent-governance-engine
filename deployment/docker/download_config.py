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

from huggingface_hub import snapshot_download


def download_configs():
    models = ["Qwen/Qwen2.5-3B-Instruct", "Qwen/Qwen2.5-7B-Instruct"]

    # Files to download (exclude large weights)
    allow_patterns = [
        "*.json",
        "*.py",
        "*.txt",
        "*.model",
        "tokenizer*",
        "config.json",
        "generation_config.json",
    ]

    ignore_patterns = ["*.safetensors", "*.bin", "*.pth", "*.msgpack", "*.h5"]

    token = os.environ.get("HUGGING_FACE_HUB_TOKEN")
    if token == "CAGE" or not token:
        token = None
        print(
            "⚠️ Warning: HUGGING_FACE_HUB_TOKEN not set or is dummy 'CAGE'. Public models might work, but gated ones will fail."
        )

    for model_id in models:
        print(f"📥 Downloading config for {model_id}...")
        try:
            path = snapshot_download(
                repo_id=model_id,
                allow_patterns=allow_patterns,
                ignore_patterns=ignore_patterns,
                token=token,
            )
            print(f"✅ Downloaded {model_id} to {path}")
        except Exception as e:
            print(f"❌ Failed to download {model_id}: {e}")
            print(
                "⚠️ Skipping pre-caching for this model. It will be loaded from GCS or HF at runtime."
            )


if __name__ == "__main__":
    download_configs()

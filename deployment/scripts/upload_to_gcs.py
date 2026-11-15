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

import glob
import os
import sys

# Make the src/ tree importable when this script is executed directly
# (i.e. `python deployment/scripts/upload_to_gcs.py`).
_repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

from huggingface_hub import snapshot_download

from src.governed_financial_advisor.infrastructure.storage import (
    get_storage_backend,
)


def upload_directory(
    local_path: str, remote_prefix: str, bucket_name: str | None = None
) -> None:
    """Upload every file under *local_path* to the configured storage backend.

    Args:
        local_path:    Absolute path to the local directory to upload.
        remote_prefix: Remote "directory" prefix (e.g. the model ID).
        bucket_name:   GCS bucket name.  Ignored when STORAGE_BACKEND=local.
    """
    storage = get_storage_backend(bucket_name=bucket_name)

    for local_file in glob.glob(local_path + "/**/*", recursive=True):
        if not os.path.isfile(local_file):
            continue

        rel_path = os.path.relpath(local_file, local_path)
        remote_path = os.path.join(remote_prefix, rel_path)

        print(f"Uploading {local_file} → {remote_path} ...")
        uri = storage.upload(local_file, remote_path)
        print(f"  ✓ {uri}")


import re

_COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_UNSAFE_WEIGHT_PATTERNS = [
    "*.bin",
    "*.pt",
    "*.pth",
    "*.ckpt",
    "*.pkl",
    "*.pickle",
    "*.msgpack",
    "*.h5",
    "*.ot",
]


def main() -> None:
    model_id = os.environ.get("MODEL_ID")
    model_revision = os.environ.get("MODEL_REVISION", "").strip()
    allow_mutable = os.environ.get("ALLOW_MUTABLE_MODEL_REVISION", "").lower() in (
        "1",
        "true",
        "yes",
    )
    bucket_name = os.environ.get("GCS_BUCKET")
    # Default to local storage; set STORAGE_BACKEND=gcs to use Google Cloud Storage
    storage_backend = os.environ.get("STORAGE_BACKEND", "local").lower()

    if not model_id:
        print("Error: MODEL_ID environment variable is required.")
        sys.exit(1)

    if not model_revision:
        print(
            "Error: MODEL_REVISION (40-hex HuggingFace commit SHA) is required "
            "to prevent mutable supply-chain tampering (AI600-007 / Bandit B615)."
        )
        sys.exit(1)

    if not allow_mutable and not _COMMIT_SHA_RE.match(model_revision):
        print(
            f"Error: MODEL_REVISION={model_revision!r} must be a 40-char lowercase "
            "commit SHA (or set ALLOW_MUTABLE_MODEL_REVISION=true for local testing)."
        )
        sys.exit(1)

    if storage_backend == "gcs" and not bucket_name:
        print(
            "Error: GCS_BUCKET environment variable is required when STORAGE_BACKEND=gcs."
        )
        sys.exit(1)

    print(f"Downloading {model_id}@{model_revision[:12]} from HuggingFace Hub...")
    local_dir = snapshot_download(
        repo_id=model_id,
        revision=model_revision,
        ignore_patterns=_UNSAFE_WEIGHT_PATTERNS,
    )
    print(f"Downloaded to {local_dir}")

    target = (
        f"gs://{bucket_name}/{model_id}"
        if storage_backend == "gcs"
        else f"local → {model_id}"
    )
    print(f"Uploading to {target} (STORAGE_BACKEND={storage_backend}) ...")
    upload_directory(local_dir, model_id, bucket_name=bucket_name)
    print("Done!")


if __name__ == "__main__":
    main()

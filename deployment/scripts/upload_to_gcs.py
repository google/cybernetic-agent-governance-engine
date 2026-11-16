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
import re
import shutil
import sys
from pathlib import Path

# Make the repository root importable when this script is executed directly
# (i.e. `python deployment/scripts/upload_to_gcs.py`).
_repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

from huggingface_hub import snapshot_download

from deployment.scripts.mirror_models import (
    _load_hash_manifest,
    _resolve_model_revision,
    verify_model_integrity,
)
from src.governed_financial_advisor.infrastructure.storage import (
    get_storage_backend,
)

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


def upload_directory(
    local_path: str, remote_prefix: str, bucket_name: str | None = None
) -> None:
    """Upload every verified file under *local_path* to the configured storage backend.

    Args:
        local_path:    Absolute path to the local directory to upload.
        remote_prefix: Remote "directory" prefix (e.g. the model ID).
        bucket_name:   GCS bucket name.  Ignored when STORAGE_BACKEND=local.
    """
    storage = get_storage_backend(bucket_name=bucket_name)
    canonical_root = Path(local_path).resolve()

    for local_file in glob.glob(local_path + "/**/*", recursive=True):
        candidate = Path(local_file).resolve()
        if not candidate.is_file() or not candidate.is_relative_to(canonical_root):
            continue

        rel_path = candidate.relative_to(canonical_root).as_posix()
        remote_path = f"{remote_prefix.rstrip('/')}/{rel_path}"

        print(f"Uploading {candidate} → {remote_path} ...")
        uri = storage.upload(str(candidate), remote_path)
        print(f"  ✓ {uri}")


def main() -> None:
    model_id = os.environ.get("MODEL_ID")
    allow_mutable = os.environ.get("ALLOW_MUTABLE_MODEL_REVISION", "").lower() in (
        "1",
        "true",
        "yes",
    )
    strict_verify = os.environ.get(
        "MODEL_WEIGHT_VERIFICATION_STRICT", "true"
    ).lower() not in ("0", "false", "no")
    bucket_name = os.environ.get("GCS_BUCKET")
    # Default to local storage; set STORAGE_BACKEND=gcs to use Google Cloud Storage
    storage_backend = os.environ.get("STORAGE_BACKEND", "local").lower()

    if not model_id:
        print("Error: MODEL_ID environment variable is required.")
        sys.exit(1)

    manifest = _load_hash_manifest()
    model_revision = os.environ.get("MODEL_REVISION", "").strip() or (
        _resolve_model_revision(model_id, manifest) or ""
    )

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

    work_dir = Path("temp_gcs_model_mirror")
    work_dir.mkdir(exist_ok=True)
    target_local_dir = work_dir / model_id.replace("/", "--")

    print(f"Downloading {model_id}@{model_revision[:12]} from HuggingFace Hub...")
    local_dir = snapshot_download(
        repo_id=model_id,
        revision=model_revision,
        local_dir=target_local_dir,
        ignore_patterns=_UNSAFE_WEIGHT_PATTERNS,
    )
    print(f"Downloaded to {local_dir}")

    print(f"Verifying .safetensors and anchor SHA-256 digests for {model_id}...")
    integrity_ok = verify_model_integrity(Path(local_dir), model_id)
    if not integrity_ok:
        shutil.rmtree(local_dir, ignore_errors=True)
        if strict_verify:
            print(
                f"Error: [AI600-007] STRICT MODE: Aborting upload of {model_id} due to "
                "failed .safetensors / anchor SHA-256 verification."
            )
            sys.exit(1)
        print(
            f"Warning: [AI600-007] Verification failed for {model_id} — proceeding only "
            "because MODEL_WEIGHT_VERIFICATION_STRICT=false."
        )

    try:
        target = (
            f"gs://{bucket_name}/{model_id}"
            if storage_backend == "gcs"
            else f"local → {model_id}"
        )
        print(f"Uploading to {target} (STORAGE_BACKEND={storage_backend}) ...")
        upload_directory(str(local_dir), model_id, bucket_name=bucket_name)
        print("Done!")
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == "__main__":
    main()

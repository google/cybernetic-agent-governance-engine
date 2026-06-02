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
Mirror HuggingFace models to an S3-compatible object store (MinIO, AWS S3, etc.).

Replaces the former gsutil-based upload with boto3, making this script
compatible with any S3-compatible endpoint (MinIO, AWS S3, Wasabi, etc.).

Configuration via environment variables:
  S3_BUCKET_NAME      — target bucket (required)
  S3_ENDPOINT_URL     — custom endpoint, e.g. http://minio:9000 (optional for AWS)
  S3_PATH_STYLE       — set "true" for MinIO / GCS S3-compat (optional)
  S3_REGION_NAME      — region (optional, defaults to "us-east-1")
  AWS_ACCESS_KEY_ID   — S3 / MinIO access key
  AWS_SECRET_ACCESS_KEY — S3 / MinIO secret key
  MODEL_FAST          — HuggingFace model ID for the fast/governance model
  MODEL_REASONING     — HuggingFace model ID for the reasoning model
  HUGGING_FACE_HUB_TOKEN — token for gated model access (optional)
"""

import os
import shutil
from pathlib import Path

import boto3
from botocore.config import Config as BotocoreConfig
from dotenv import load_dotenv
from huggingface_hub import snapshot_download

load_dotenv()

# Configuration — S3_BUCKET_NAME is required; no placeholder default permitted.
BUCKET_NAME = os.environ["S3_BUCKET_NAME"]
ENDPOINT_URL = os.environ.get("S3_ENDPOINT_URL") or None
REGION_NAME = os.environ.get("S3_REGION_NAME", "us-east-1")
PATH_STYLE = os.environ.get("S3_PATH_STYLE", "").lower() in ("1", "true", "yes")


def get_base_model_name(model_id: str) -> str:
    """Strips openai/ or other provider prefixes."""
    if not model_id:
        return ""
    if "/" in model_id:
        parts = model_id.split("/", 1)
        if parts[0] == "openai":
            return parts[1]
    return model_id


# Pull from env (aligned with settings.py)
MODEL_FAST = os.getenv("MODEL_FAST")
MODEL_REASONING = os.getenv("MODEL_REASONING")

MODELS_TO_MIRROR = list(set(filter(None, [
    get_base_model_name(MODEL_FAST),
    get_base_model_name(MODEL_REASONING),
])))


def _get_s3_client() -> boto3.client:
    """Return a configured boto3 S3 client."""
    config = BotocoreConfig(
        s3={"addressing_style": "path"} if PATH_STYLE else {}
    )
    return boto3.client(
        "s3",
        endpoint_url=ENDPOINT_URL,
        region_name=REGION_NAME,
        config=config,
    )


def upload_to_s3(local_path: Path, s3_prefix: str, s3_client: boto3.client) -> None:
    """Upload all files under *local_path* to *s3_prefix* in the configured bucket."""
    endpoint_display = ENDPOINT_URL or "AWS S3"
    print(f"🚀 Uploading {local_path} → s3://{BUCKET_NAME}/{s3_prefix} ({endpoint_display})...")

    file_count = 0
    for local_file in local_path.rglob("*"):
        if not local_file.is_file():
            continue

        rel = local_file.relative_to(local_path)
        s3_key = f"{s3_prefix}/{rel}"

        print(f"  ↑ {rel}", end="\r")
        s3_client.upload_file(str(local_file), BUCKET_NAME, s3_key)
        file_count += 1

    print(f"✅ Uploaded {file_count} files to s3://{BUCKET_NAME}/{s3_prefix}")


def mirror_models() -> None:
    s3 = _get_s3_client()

    # Ensure HF transfer is enabled for speed
    os.environ["HF_HUB_ENABLE_HF_TRANSFER"] = "1"

    if not os.environ.get("HUGGING_FACE_HUB_TOKEN"):
        print("⚠️ HUGGING_FACE_HUB_TOKEN not found in env. Gated models might fail.")

    work_dir = Path("temp_model_mirror")
    work_dir.mkdir(exist_ok=True)

    try:
        for model_id in MODELS_TO_MIRROR:
            print(f"\n--- ⬇️ Processing {model_id} ---")

            local_model_dir = work_dir / model_id.replace("/", "--")
            print(f"📥 Downloading to {local_model_dir}...")

            try:
                snapshot_download(
                    repo_id=model_id,
                    local_dir=local_model_dir,
                    ignore_patterns=["*.msgpack", "*.h5", "*.ot"],
                    local_dir_use_symlinks=False,
                )
            except Exception as exc:
                print(f"❌ Download failed for {model_id}: {exc}")
                continue

            try:
                upload_to_s3(local_model_dir, model_id, s3)
            except Exception as exc:
                print(f"❌ Upload failed for {model_id}: {exc}")
                continue

            print(f"🧹 Cleaning up {local_model_dir}...")
            shutil.rmtree(local_model_dir)

    finally:
        if work_dir.exists():
            shutil.rmtree(work_dir)
            print("✨ Temporary directory cleaned up.")


if __name__ == "__main__":
    mirror_models()

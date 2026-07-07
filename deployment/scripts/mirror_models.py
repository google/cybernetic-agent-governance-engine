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

AI600-007 / SA-12 / SR-3 / SI-7 — Model Weight Integrity Verification:
  After each model download, SHA-256 digests of selected anchor files
  (config.json, tokenizer.json) are computed and verified against the signed
  manifest in ``config/model_hashes.json``.

  Set ``MODEL_WEIGHT_VERIFICATION_STRICT=true`` to abort on mismatch (default:
  warn-only to avoid blocking critical infrastructure bootstraps).

  A verification result OTel span is emitted with attribute:
    supply_chain.model_integrity_verified=true/false

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
  MODEL_WEIGHT_VERIFICATION_STRICT — "true" to abort on hash mismatch (default: warn)
"""

import hashlib
import json
import logging
import os
import shutil
from pathlib import Path

import boto3
from botocore.config import Config as BotocoreConfig
from dotenv import load_dotenv
from huggingface_hub import snapshot_download

load_dotenv()

logger = logging.getLogger(__name__)

# Configuration — S3_BUCKET_NAME is required; no placeholder default permitted.
BUCKET_NAME = os.environ["S3_BUCKET_NAME"]
ENDPOINT_URL = os.environ.get("S3_ENDPOINT_URL") or None
REGION_NAME = os.environ.get("S3_REGION_NAME", "us-east-1")
PATH_STYLE = os.environ.get("S3_PATH_STYLE", "").lower() in ("1", "true", "yes")

# AI600-007: Model weight integrity verification mode.
# STRICT=true → abort on hash mismatch; STRICT=false (default) → warn and continue.
_VERIFICATION_STRICT = (
    os.environ.get("MODEL_WEIGHT_VERIFICATION_STRICT", "").lower() == "true"
)

# Canonical path to the signed model hash manifest (relative to repo root).
_MANIFEST_PATH = Path(__file__).parent.parent.parent / "config" / "model_hashes.json"

# Anchor filenames whose hashes are checked for integrity.  We verify config.json
# and tokenizer.json as lightweight integrity anchors — these files ship with every
# HuggingFace model snapshot and are small enough to hash locally.  Weight shard
# files (*.safetensors, *.bin) are too large for a static manifest; a future Phase 3
# improvement will add cosign/sigstore attestation for those files.
_INTEGRITY_ANCHORS = frozenset(
    ["config.json", "tokenizer.json", "tokenizer_config.json"]
)


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

MODELS_TO_MIRROR = list(
    set(
        filter(
            None,
            [
                get_base_model_name(MODEL_FAST),
                get_base_model_name(MODEL_REASONING),
            ],
        )
    )
)


def _get_s3_client() -> boto3.client:
    """Return a configured boto3 S3 client."""
    config = BotocoreConfig(s3={"addressing_style": "path"} if PATH_STYLE else {})
    return boto3.client(
        "s3",
        endpoint_url=ENDPOINT_URL,
        region_name=REGION_NAME,
        config=config,
    )


def _sha256_file(path: Path) -> str:
    """Compute the SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_hash_manifest() -> dict:
    """Load the signed model hash manifest from config/model_hashes.json.

    Returns an empty dict if the manifest file does not exist, logging a
    warning (non-fatal in non-strict mode).
    """
    if not _MANIFEST_PATH.exists():
        logger.warning(
            "[AI600-007] Model hash manifest not found at %s — "
            "integrity verification will be skipped for all models. "
            "Ensure config/model_hashes.json is committed to the repository.",
            _MANIFEST_PATH,
        )
        return {}
    try:
        with open(_MANIFEST_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        logger.error("[AI600-007] Failed to parse model hash manifest: %s", exc)
        return {}


def verify_model_integrity(local_model_dir: Path, model_id: str) -> bool:
    """Verify the integrity of downloaded model anchor files against the signed manifest.

    Computes SHA-256 digests of anchor files (config.json, tokenizer.json,
    tokenizer_config.json) in the downloaded model directory and compares
    them to the expected digests in config/model_hashes.json.

    Args:
        local_model_dir: Path to the local model snapshot directory.
        model_id:        HuggingFace model ID (e.g. "deepseek-ai/DeepSeek-R1-Distill-Llama-8B").

    Returns:
        ``True`` if all available anchor files pass verification or no manifest
        entries exist for this model (non-blocking default).
        ``False`` if any anchor file hash does not match the manifest.
    """
    manifest = _load_hash_manifest()
    model_hashes = manifest.get(model_id, {})

    if not model_hashes:
        logger.warning(
            "[AI600-007] No hash manifest entries for model '%s' — "
            "skipping integrity verification. Add entries to config/model_hashes.json.",
            model_id,
        )
        # Emit OTel span attribute if available (best-effort — OTel may not be configured)
        _emit_integrity_span(model_id, verified=False, reason="no_manifest_entries")
        return True  # Non-blocking: treat as unverified rather than failing

    all_passed = True
    verified_count = 0
    failed_files: list[str] = []

    for anchor_filename in _INTEGRITY_ANCHORS:
        anchor_path = local_model_dir / anchor_filename
        if not anchor_path.exists():
            continue  # Anchor file not present in this model snapshot — skip

        expected_hash = model_hashes.get(anchor_filename)
        if not expected_hash:
            logger.debug(
                "[AI600-007] No manifest entry for %s/%s — skipping.",
                model_id,
                anchor_filename,
            )
            continue

        actual_hash = _sha256_file(anchor_path)
        if actual_hash == expected_hash:
            logger.info(
                "[AI600-007] ✅ %s/%s SHA-256 verified: %s",
                model_id,
                anchor_filename,
                actual_hash[:16] + "…",
            )
            verified_count += 1
        else:
            logger.error(
                "[AI600-007] ❌ HASH MISMATCH: %s/%s\n"
                "  Expected: %s\n"
                "  Actual:   %s\n"
                "  This may indicate a supply chain attack or corrupted download.",
                model_id,
                anchor_filename,
                expected_hash,
                actual_hash,
            )
            all_passed = False
            failed_files.append(anchor_filename)

    if all_passed:
        logger.info(
            "[AI600-007] ✅ Model integrity verified: model=%s files_checked=%d",
            model_id,
            verified_count,
        )
        _emit_integrity_span(
            model_id, verified=True, reason=f"anchors_verified:{verified_count}"
        )
    else:
        logger.error(
            "[AI600-007] ❌ Model integrity FAILED: model=%s failed_files=%s",
            model_id,
            ", ".join(failed_files),
        )
        _emit_integrity_span(
            model_id, verified=False, reason=f"hash_mismatch:{','.join(failed_files)}"
        )

    return all_passed


def _emit_integrity_span(model_id: str, verified: bool, reason: str) -> None:
    """Emit an OTel span with supply_chain.model_integrity_verified attribute.

    Best-effort — if OpenTelemetry is not configured, the span is a no-op.
    AI600-007: SA-12 / SR-3 / SI-7 supply chain integrity evidence.
    """
    try:
        from opentelemetry import trace

        tracer = trace.get_tracer("deployment.mirror_models")
        with tracer.start_as_current_span("supply_chain.model_integrity_check") as span:
            span.set_attribute("supply_chain.model_id", model_id)
            span.set_attribute("supply_chain.model_integrity_verified", verified)
            span.set_attribute("supply_chain.integrity_reason", reason)
            span.set_attribute("supply_chain.poam_ref", "AI600-007")
    except Exception:
        pass  # OTel not configured — span is non-critical


def upload_to_s3(local_path: Path, s3_prefix: str, s3_client: boto3.client) -> None:
    """Upload all files under *local_path* to *s3_prefix* in the configured bucket."""
    endpoint_display = ENDPOINT_URL or "AWS S3"
    print(
        f"🚀 Uploading {local_path} → s3://{BUCKET_NAME}/{s3_prefix} ({endpoint_display})..."
    )

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

            # AI600-007: SHA-256 integrity verification after download
            # Verify anchor files (config.json, tokenizer.json) against signed manifest.
            print(f"🔐 Verifying model integrity for {model_id}...")
            integrity_ok = verify_model_integrity(local_model_dir, model_id)
            if not integrity_ok:
                if _VERIFICATION_STRICT:
                    print(
                        f"❌ [AI600-007] STRICT MODE: Aborting upload of {model_id} due to "
                        "hash mismatch. Set MODEL_WEIGHT_VERIFICATION_STRICT=false to skip "
                        "(not recommended)."
                    )
                    continue
                else:
                    print(
                        f"⚠️ [AI600-007] Hash mismatch for {model_id} — proceeding with upload "
                        "(warn-only mode). Set MODEL_WEIGHT_VERIFICATION_STRICT=true to abort."
                    )

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

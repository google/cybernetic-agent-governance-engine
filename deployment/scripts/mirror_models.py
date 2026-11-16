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
  After each model download, SHA-256 digests of `.safetensors` shards and anchor
  files (`config.json`, `tokenizer.json`, `tokenizer_config.json`) are computed
  and verified fail-closed against ``config/model_hashes.json``.

  ``MODEL_WEIGHT_VERIFICATION_STRICT`` defaults to ``"true"`` (fail-closed).

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
  MODEL_WEIGHT_VERIFICATION_STRICT — "true" to abort on hash mismatch (default: "true")
"""

import hashlib
import json
import logging
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any

import boto3
from botocore.config import Config as BotocoreConfig
from dotenv import load_dotenv
from huggingface_hub import snapshot_download

load_dotenv()

logger = logging.getLogger(__name__)

# Configuration — S3_BUCKET_NAME is validated when upload/mirror runs so importing
# this module in unit/type tests does not crash with KeyError at import time.
BUCKET_NAME = os.environ.get("S3_BUCKET_NAME", "")
ENDPOINT_URL = os.environ.get("S3_ENDPOINT_URL") or None
REGION_NAME = os.environ.get("S3_REGION_NAME", "us-east-1")
PATH_STYLE = os.environ.get("S3_PATH_STYLE", "").lower() in ("1", "true", "yes")

# AI600-007: Fail-closed by default — set MODEL_WEIGHT_VERIFICATION_STRICT=false
# only in explicitly non-production local experiments.
_VERIFICATION_STRICT = os.environ.get(
    "MODEL_WEIGHT_VERIFICATION_STRICT", "true"
).lower() not in ("0", "false", "no")

_COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_PLACEHOLDER_DIGEST = "PLACEHOLDER_REQUIRES_SECURITY_REVIEW"
_UNSAFE_PICKLE_SUFFIXES = frozenset({".bin", ".pt", ".pth", ".ckpt", ".pkl", ".pickle"})
_IGNORE_PATTERNS = [
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

# Canonical path to the signed model hash manifest (relative to repo root).
_MANIFEST_PATH = Path(__file__).parent.parent.parent / "config" / "model_hashes.json"

_INTEGRITY_ANCHORS = frozenset(
    ["config.json", "tokenizer.json", "tokenizer_config.json"]
)


def get_base_model_name(model_id: str | None) -> str:
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

MODELS_TO_MIRROR = sorted(
    {
        name
        for name in (
            get_base_model_name(MODEL_FAST),
            get_base_model_name(MODEL_REASONING),
        )
        if name
    }
)


def _get_s3_client() -> Any:
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


def _load_hash_manifest() -> dict[str, Any]:
    """Load the signed model hash manifest from config/model_hashes.json."""
    if not _MANIFEST_PATH.exists():
        logger.error("[AI600-007] Model hash manifest not found at %s.", _MANIFEST_PATH)
        return {}
    try:
        with open(_MANIFEST_PATH, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception as exc:
        logger.error("[AI600-007] Failed to parse model hash manifest: %s", exc)
        return {}


def _resolve_model_revision(model_id: str, manifest: dict[str, Any]) -> str | None:
    """Resolve the pinned 40-char HuggingFace commit SHA for *model_id*."""
    env_key = "MODEL_REVISION_" + re.sub(r"[^A-Za-z0-9]", "_", model_id).upper()
    entry = manifest.get(model_id)
    manifest_rev = entry.get("_revision", "") if isinstance(entry, dict) else ""
    rev = (
        os.environ.get(env_key, "").strip()
        or os.environ.get("MODEL_REVISION", "").strip()
        or str(manifest_rev).strip()
    )
    if not rev:
        return None
    allow_mutable = os.environ.get("ALLOW_MUTABLE_MODEL_REVISION", "").lower() in (
        "1",
        "true",
        "yes",
    )
    if not allow_mutable and not _COMMIT_SHA_RE.match(rev):
        logger.error(
            "[AI600-007] Revision %r for %s is not an immutable 40-char commit SHA.",
            rev,
            model_id,
        )
        return None
    return rev


def verify_model_integrity(local_model_dir: Path, model_id: str) -> bool:
    """Verify anchor digests, absence of pickle weights, and presence of .safetensors."""
    unsafe_files = [
        str(p.relative_to(local_model_dir))
        for p in local_model_dir.rglob("*")
        if p.is_file() and p.suffix.lower() in _UNSAFE_PICKLE_SUFFIXES
    ]
    if unsafe_files:
        logger.error(
            "[AI600-007] ❌ Unsafe pickle/PyTorch weight artifacts detected in %s: %s",
            model_id,
            unsafe_files,
        )
        _emit_integrity_span(model_id, verified=False, reason="unsafe_pickle_weights")
        return False

    allow_non_safetensors = os.environ.get("ALLOW_NON_SAFETENSORS", "").lower() in (
        "1",
        "true",
        "yes",
    )
    safetensor_files = sorted(local_model_dir.rglob("*.safetensors"))
    if not safetensor_files and not allow_non_safetensors:
        logger.error(
            "[AI600-007] ❌ No .safetensors weight shards found in %s.", model_id
        )
        _emit_integrity_span(model_id, verified=False, reason="missing_safetensors")
        return False

    for sf_path in safetensor_files:
        if not sf_path.is_file() or sf_path.stat().st_size == 0:
            logger.error(
                "[AI600-007] ❌ Empty or invalid .safetensors shard in %s: %s",
                model_id,
                sf_path,
            )
            _emit_integrity_span(model_id, verified=False, reason="empty_safetensors")
            return False

    manifest = _load_hash_manifest()
    model_hashes = manifest.get(model_id, {})

    if not isinstance(model_hashes, dict) or not model_hashes:
        logger.error(
            "[AI600-007] No hash manifest entries for model '%s' in %s.",
            model_id,
            _MANIFEST_PATH,
        )
        _emit_integrity_span(model_id, verified=False, reason="no_manifest_entries")
        return False

    all_passed = True
    verified_count = 0
    failed_files: list[str] = []

    # Verify SHA-256 digests on every .safetensors shard (fail-closed whenever
    # .safetensors digests are pinned in model_hashes; always compute SHA-256).
    pinned_safetensors: dict[str, Any] = {
        rel_key: digest
        for rel_key, digest in model_hashes.items()
        if not rel_key.startswith("_") and rel_key.endswith(".safetensors")
    }
    nested_st = model_hashes.get("safetensors")
    if isinstance(nested_st, dict):
        for rel_key, digest in nested_st.items():
            if isinstance(rel_key, str) and rel_key.endswith(".safetensors"):
                pinned_safetensors[rel_key] = digest

    disk_safetensors_rel: dict[str, Path] = {
        sf.relative_to(local_model_dir).as_posix(): sf for sf in safetensor_files
    }
    for rel_st, sf_path in sorted(disk_safetensors_rel.items()):
        actual_st_sha = _sha256_file(sf_path)
        if pinned_safetensors:
            expected_st_sha = pinned_safetensors.get(rel_st)
            if (
                not isinstance(expected_st_sha, str)
                or not expected_st_sha
                or expected_st_sha == _PLACEHOLDER_DIGEST
            ):
                logger.error(
                    "[AI600-007] ❌ Unpinned or placeholder .safetensors shard %s/%s.",
                    model_id,
                    rel_st,
                )
                all_passed = False
                failed_files.append(rel_st)
            elif actual_st_sha != expected_st_sha:
                logger.error(
                    "[AI600-007] ❌ SAFETENSORS SHA-256 MISMATCH: %s/%s "
                    "(expected=%s actual=%s)",
                    model_id,
                    rel_st,
                    expected_st_sha,
                    actual_st_sha,
                )
                all_passed = False
                failed_files.append(rel_st)
            else:
                verified_count += 1
        else:
            logger.info(
                "[AI600-007] Computed .safetensors SHA-256 for %s/%s: %s",
                model_id,
                rel_st,
                actual_st_sha[:16] + "…",
            )

    for pinned_rel in sorted(set(pinned_safetensors) - set(disk_safetensors_rel)):
        logger.error(
            "[AI600-007] ❌ Missing pinned .safetensors shard on disk: %s/%s",
            model_id,
            pinned_rel,
        )
        all_passed = False
        failed_files.append(pinned_rel)

    for anchor_filename in sorted(_INTEGRITY_ANCHORS):
        anchor_path = local_model_dir / anchor_filename
        if not anchor_path.exists():
            continue

        expected_hash = model_hashes.get(anchor_filename)
        if not expected_hash or expected_hash == _PLACEHOLDER_DIGEST:
            logger.error(
                "[AI600-007] Missing or unreviewed placeholder digest for %s/%s.",
                model_id,
                anchor_filename,
            )
            all_passed = False
            failed_files.append(anchor_filename)
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

    if verified_count == 0:
        all_passed = False
        if not failed_files:
            failed_files.append("no_anchor_files_verified")

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
    """Emit an OTel span with supply_chain.model_integrity_verified attribute."""
    try:
        from opentelemetry import trace

        tracer = trace.get_tracer("deployment.mirror_models")
        with tracer.start_as_current_span("supply_chain.model_integrity_check") as span:
            span.set_attribute("supply_chain.model_id", model_id)
            span.set_attribute("supply_chain.model_integrity_verified", verified)
            span.set_attribute("supply_chain.integrity_reason", reason)
            span.set_attribute("supply_chain.poam_ref", "AI600-007")
    except Exception:  # noqa: BLE001
        logger.debug("OpenTelemetry unavailable for supply_chain.model_integrity_check")


def upload_to_s3(local_path: Path, s3_prefix: str, s3_client: Any) -> None:
    """Upload all files under *local_path* to *s3_prefix* in the configured bucket."""
    bucket = BUCKET_NAME or os.environ.get("S3_BUCKET_NAME", "")
    if not bucket:
        raise RuntimeError("S3_BUCKET_NAME environment variable is required.")
    endpoint_display = ENDPOINT_URL or "AWS S3"
    print(
        f"🚀 Uploading {local_path} → s3://{bucket}/{s3_prefix} ({endpoint_display})..."
    )

    file_count = 0
    for local_file in local_path.rglob("*"):
        if not local_file.is_file():
            continue

        rel = local_file.relative_to(local_path)
        s3_key = f"{s3_prefix}/{rel}"

        print(f"  ↑ {rel}", end="\r")
        s3_client.upload_file(str(local_file), bucket, s3_key)
        file_count += 1

    print(f"✅ Uploaded {file_count} files to s3://{bucket}/{s3_prefix}")


def mirror_models() -> None:
    if not (BUCKET_NAME or os.environ.get("S3_BUCKET_NAME")):
        print("❌ S3_BUCKET_NAME environment variable is required.")
        sys.exit(1)
    s3 = _get_s3_client()
    manifest = _load_hash_manifest()

    os.environ["HF_HUB_ENABLE_HF_TRANSFER"] = "1"

    if not os.environ.get("HUGGING_FACE_HUB_TOKEN"):
        print("⚠️ HUGGING_FACE_HUB_TOKEN not found in env. Gated models might fail.")

    work_dir = Path("temp_model_mirror")
    work_dir.mkdir(exist_ok=True)
    had_failures = False

    try:
        for model_id in MODELS_TO_MIRROR:
            print(f"\n--- ⬇️ Processing {model_id} ---")
            revision = _resolve_model_revision(model_id, manifest)
            if not revision:
                print(
                    f"❌ [AI600-007] Missing or unpinned commit SHA revision for {model_id}. "
                    "Set MODEL_REVISION (<40-hex-sha>) or _revision in config/model_hashes.json."
                )
                had_failures = True
                continue

            local_model_dir = work_dir / model_id.replace("/", "--")
            print(f"📥 Downloading {model_id}@{revision[:12]} to {local_model_dir}...")

            try:
                snapshot_download(
                    repo_id=model_id,
                    revision=revision,
                    local_dir=local_model_dir,
                    ignore_patterns=_IGNORE_PATTERNS,
                )
            except Exception as exc:
                print(f"❌ Download failed for {model_id}: {exc}")
                had_failures = True
                continue

            print(f"🔐 Verifying model integrity for {model_id}...")
            integrity_ok = verify_model_integrity(local_model_dir, model_id)
            if not integrity_ok:
                shutil.rmtree(local_model_dir, ignore_errors=True)
                if _VERIFICATION_STRICT:
                    print(
                        f"❌ [AI600-007] STRICT MODE: Aborting upload of {model_id} due to "
                        "failed weight/anchor verification."
                    )
                    had_failures = True
                    continue
                print(
                    f"⚠️ [AI600-007] Verification failed for {model_id} — proceeding only because "
                    "MODEL_WEIGHT_VERIFICATION_STRICT=false."
                )

            try:
                upload_to_s3(local_model_dir, model_id, s3)
            except Exception as exc:
                print(f"❌ Upload failed for {model_id}: {exc}")
                had_failures = True
                continue

            print(f"🧹 Cleaning up {local_model_dir}...")
            shutil.rmtree(local_model_dir, ignore_errors=True)

    finally:
        if work_dir.exists():
            shutil.rmtree(work_dir, ignore_errors=True)
            print("✨ Temporary directory cleaned up.")

    if had_failures and _VERIFICATION_STRICT:
        sys.exit(1)


if __name__ == "__main__":
    mirror_models()

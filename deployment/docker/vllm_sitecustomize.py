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

"""Runtime hook for vLLM to support gs:// model paths transparently."""

import os
import re
import signal
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

import vllm.config as vllm_config
import vllm.model_executor.model_loader.loader as vllm_loader
import vllm.transformers_utils.s3_utils as s3_utils
import vllm.transformers_utils.utils as tu_utils
from google.cloud import storage  # type: ignore[attr-defined]

_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$")
_WEIGHTS_CACHE_DIR: Path | None = None

_orig_is_s3 = tu_utils.is_s3


def _is_s3_or_gs(model_or_path: str) -> bool:
    return (
        isinstance(model_or_path, str) and model_or_path.lower().startswith("gs://")
    ) or bool(_orig_is_s3(model_or_path))


def _validate_bucket_name(bucket_name: str) -> str:
    if not _BUCKET_RE.match(bucket_name) or ".." in bucket_name:
        raise ValueError(f"Unsafe GCS bucket identifier: {bucket_name!r}")
    return bucket_name


def _resolve_contained_path(base_dir: Path, untrusted_rel: str) -> Path:
    """Resolve *untrusted_rel* strictly inside *base_dir*, rejecting path traversal."""
    if (
        not untrusted_rel
        or "\x00" in untrusted_rel
        or "\\" in untrusted_rel
        or untrusted_rel.startswith("/")
    ):
        raise ValueError(f"Unsafe GCS object key: {untrusted_rel!r}")

    raw_segments = untrusted_rel.split("/")
    posix_parts = PurePosixPath(untrusted_rel).parts
    if (
        not posix_parts
        or any(seg in ("", ".", "..") for seg in raw_segments)
        or any(part in ("", ".", "..") for part in posix_parts)
    ):
        raise ValueError(
            f"Path traversal detected in GCS object key: {untrusted_rel!r}"
        )

    canonical_base = base_dir.resolve()
    candidate = (canonical_base / Path(*posix_parts)).resolve()
    if candidate == canonical_base or not candidate.is_relative_to(canonical_base):
        raise ValueError(
            f"GCS object key {untrusted_rel!r} escapes target directory {canonical_base}"
        )
    return candidate


def _get_weights_cache_root() -> Path:
    global _WEIGHTS_CACHE_DIR
    configured = os.environ.get("VLLM_GCS_CACHE_DIR", "").strip()
    if configured:
        root = Path(configured).resolve()
        root.mkdir(parents=True, mode=0o700, exist_ok=True)
        return root
    if _WEIGHTS_CACHE_DIR is None or not _WEIGHTS_CACHE_DIR.exists():
        _WEIGHTS_CACHE_DIR = Path(tempfile.mkdtemp(prefix="vllm-weights-")).resolve()
    return _WEIGHTS_CACHE_DIR


_orig_glob = s3_utils.glob
_orig_S3Model: Any = s3_utils.S3Model


def _gcs_list_blobs(
    path: str,
    allow_pattern: list[str] | None = None,
    ignore_pattern: list[str] | None = None,
) -> tuple[str, str, list[str], list[Any]]:
    stripped = path[5:].lstrip("/")
    parts = stripped.split("/", 1)
    bucket_name = _validate_bucket_name(parts[0])
    prefix = parts[1].rstrip("/") + "/" if len(parts) > 1 and parts[1] else ""
    client = storage.Client(project=os.environ.get("GOOGLE_CLOUD_PROJECT"))
    blobs = [
        b
        for b in client.list_blobs(bucket_name, prefix=prefix)
        if not b.name.endswith("/")
    ]
    paths = s3_utils._filter_ignore([b.name for b in blobs], ["*/"])
    if allow_pattern is not None:
        paths = s3_utils._filter_allow(paths, allow_pattern)
    if ignore_pattern is not None:
        paths = s3_utils._filter_ignore(paths, ignore_pattern)
    blob_map = {b.name: b for b in blobs}
    return bucket_name, prefix, paths, [blob_map[p] for p in paths]


def _patched_glob(
    s3: Any = None,
    path: str = "",
    allow_pattern: list[str] | None = None,
) -> list[str]:
    if isinstance(path, str) and path.lower().startswith("gs://"):
        bucket_name, _, _, blobs = _gcs_list_blobs(path, allow_pattern=allow_pattern)
        local_files: list[str] = []
        bucket_root = _resolve_contained_path(_get_weights_cache_root(), bucket_name)
        bucket_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        for blob in blobs:
            dest = _resolve_contained_path(bucket_root, str(blob.name))
            dest.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            if not dest.exists() or dest.stat().st_size != blob.size:
                blob.download_to_filename(str(dest))
            local_files.append(str(dest))
        return sorted(local_files)
    return list(_orig_glob(s3=s3, path=path, allow_pattern=allow_pattern))


class _PatchedS3Model(_orig_S3Model):  # type: ignore[misc]
    def __init__(self) -> None:
        self.s3 = None
        for sig in (signal.SIGINT, signal.SIGTERM):
            existing_handler = signal.getsignal(sig)
            signal.signal(sig, self._close_by_signal(existing_handler))
        self.dir = tempfile.mkdtemp(prefix="vllm-s3-")

    def pull_files(
        self,
        s3_model_path: str = "",
        allow_pattern: list[str] | None = None,
        ignore_pattern: list[str] | None = None,
    ) -> None:
        if isinstance(s3_model_path, str) and s3_model_path.lower().startswith("gs://"):
            _, base_dir, _, blobs = _gcs_list_blobs(
                s3_model_path, allow_pattern, ignore_pattern
            )
            target_root = Path(self.dir).resolve()
            for blob in blobs:
                rel = str(blob.name).removeprefix(base_dir).lstrip("/")
                dest = _resolve_contained_path(target_root, rel)
                dest.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
                blob.download_to_filename(str(dest))
            return
        if self.s3 is None:
            import boto3

            self.s3 = boto3.client("s3")
        super().pull_files(s3_model_path, allow_pattern, ignore_pattern)


tu_utils.is_s3 = _is_s3_or_gs
s3_utils.glob = _patched_glob
s3_utils.S3Model = _PatchedS3Model
vllm_config.is_s3 = _is_s3_or_gs
vllm_config.S3Model = _PatchedS3Model
vllm_loader.is_s3 = _is_s3_or_gs
vllm_loader.s3_glob = _patched_glob

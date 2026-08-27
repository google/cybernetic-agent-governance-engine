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
storage.py

Durable OSCAL artifact persistence via S3-compatible storage (default) or
the native GCS Python SDK (google-cloud-storage).

For multi-cloud portability, the storage backend is selected via the
STORAGE_BACKEND environment variable:
  - "s3"   (default) — S3-compatible: MinIO, AWS S3, Ceph, GCS via interop
  - "gcs"  (Google Cloud Storage native client, ADC / Workload Identity)

GCS configuration (STORAGE_BACKEND=gcs):
  OSCAL_S3_BUCKET   — GCS bucket name (reuses the same env var for compat)
  GCS_PROJECT_ID    — optional GCP project ID (inferred from ADC if unset)

S3-compat configuration (STORAGE_BACKEND=s3):
  OSCAL_S3_ENDPOINT    — e.g. "https://storage.googleapis.com"
  OSCAL_S3_BUCKET      — bucket name
  OSCAL_S3_REGION      — e.g. "us-central1"
  OSCAL_S3_ACCESS_KEY  — HMAC key ID
  OSCAL_S3_SECRET_KEY  — HMAC secret
  OSCAL_S3_TIMEOUT     — connect/read timeout in seconds (default: 15)

Object key pattern:
  oscal-artifacts/<ISO-date>/<auditId>.yaml

A SHA-256 digest of the YAML content is stored as object metadata so
consumers can detect duplicates without downloading the full object.

All blocking calls are wrapped in asyncio.to_thread() for async compatibility.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Backend selection — M-21: deferred to first use, not at import time
# ---------------------------------------------------------------------------


def _get_storage_backend() -> str:
    """Return the storage backend name, resolved at call time (not import time).

    M-21: Selecting the backend at import time caused failures in test
    environments where STORAGE_BACKEND is not set until after module load.
    """
    # STORAGE_BACKEND: "s3" (default, S3-compatible: MinIO, AWS S3, Ceph, GCS via interop)
    #                  "gcs" (Google Cloud Storage native client)
    #                  "local" (local filesystem, for development/testing)
    return os.environ.get("STORAGE_BACKEND", "s3").lower()


# ---------------------------------------------------------------------------
# Lazy client singletons
# HIGH-5 FIX: Thread-safe lazy initialization with double-checked locking
# ---------------------------------------------------------------------------

_gcs_client: Any = None
_s3_client: Any = None
_gcs_lock = threading.Lock()
_s3_lock = threading.Lock()


def _get_gcs_client() -> Any:
    """Lazy GCS client using ADC / Workload Identity.

    HIGH-5 FIX: Thread-safe with double-checked locking pattern.
    """
    global _gcs_client
    if _gcs_client is not None:
        return _gcs_client

    with _gcs_lock:
        # Double-check after acquiring lock
        if _gcs_client is not None:
            return _gcs_client

        try:
            from google.cloud import storage as gcs  # type: ignore[attr-defined]
        except ImportError as exc:
            raise RuntimeError(
                "[storage] google-cloud-storage is required for GCS artifact storage. "
                "Install it with: pip install google-cloud-storage"
            ) from exc

        project = os.environ.get("GCS_PROJECT_ID") or None
        _gcs_client = gcs.Client(project=project)
        logger.info(
            "[storage] GCS client initialised (ADC/Workload Identity, project=%s)",
            project or "inferred",
        )
        return _gcs_client


def _get_s3_client() -> Any:
    """Lazy boto3 S3-compat client (non-GCP targets only).

    HIGH-5 FIX: Thread-safe with double-checked locking pattern.
    """
    global _s3_client
    if _s3_client is not None:
        return _s3_client

    with _s3_lock:
        # Double-check after acquiring lock
        if _s3_client is not None:
            return _s3_client

        try:
            import boto3 as _boto3
            from botocore.exceptions import (
                ClientError as _ClientError,  # noqa: F401
            )
        except ImportError as exc:
            raise RuntimeError(
                "[storage] boto3 is required for S3-compat artifact storage. "
                "Install it with: pip install boto3"
            ) from exc

        endpoint = os.environ.get("OSCAL_S3_ENDPOINT")
        region = os.environ.get("OSCAL_S3_REGION", "auto")
        access_key = os.environ.get("OSCAL_S3_ACCESS_KEY")
        secret_key = os.environ.get("OSCAL_S3_SECRET_KEY")

        if not endpoint or not access_key or not secret_key:
            raise RuntimeError(
                "[storage] Missing required env vars for S3 backend: "
                "OSCAL_S3_ENDPOINT, OSCAL_S3_ACCESS_KEY, OSCAL_S3_SECRET_KEY"
            )

        # Short connect/read timeout so uploads fail fast (default boto3 is 60s+).
        _timeout = int(os.environ.get("OSCAL_S3_TIMEOUT", "15"))
        _s3_client = _boto3.client(
            "s3",
            endpoint_url=endpoint,
            region_name=region,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            # S3-compat APIs require path-style addressing
            config=_boto3.session.Config(
                s3={"addressing_style": "path"},
                connect_timeout=_timeout,
                read_timeout=_timeout,
                retries={"max_attempts": 1},
            ),
        )
        return _s3_client


def _get_bucket() -> str:
    bucket = os.environ.get("OSCAL_S3_BUCKET")
    if not bucket:
        raise RuntimeError("[storage] Missing required env var: OSCAL_S3_BUCKET")
    return bucket


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_object_key(audit_id: str, timestamp: datetime) -> str:
    """Deterministic path from audit timestamp + ID."""
    date = timestamp.strftime("%Y-%m-%d")
    return f"oscal-artifacts/{date}/{audit_id}.yaml"


def _sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# GCS backend — native google-cloud-storage
# ---------------------------------------------------------------------------


def _gcs_blob_exists(bucket_name: str, key: str) -> bool:
    """Synchronous GCS blob existence check via native SDK."""
    client = _get_gcs_client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(key)
    return blob.exists()


def _gcs_upload(
    bucket_name: str, key: str, content: str, audit_id: str, timestamp: datetime
) -> str:
    """Synchronous GCS upload via native SDK. Returns gs:// URI."""
    client = _get_gcs_client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(key)
    digest = _sha256(content)

    blob.metadata = {
        "x-audit-id": audit_id,
        "x-content-sha256": digest,
        "x-standard": "ISO/IEC 42001:2023",
        "x-audit-ts": timestamp.isoformat(),
    }
    blob.upload_from_string(
        content.encode("utf-8"),
        content_type="application/yaml",
        timeout=int(os.environ.get("OSCAL_S3_TIMEOUT", "15")),
    )

    gcs_uri = f"gs://{bucket_name}/{key}"
    logger.info(
        "[storage] OSCAL artifact persisted (GCS): %s (sha256=%s…)",
        gcs_uri,
        digest[:12],
    )
    return gcs_uri


def _gcs_upload_if_not_exists(
    bucket_name: str, key: str, content: str, audit_id: str, timestamp: datetime
) -> tuple[str, bool]:
    """Atomic GCS upload - only succeeds if blob doesn't exist.

    HIGH-4 FIX: Uses if_generation_match=0 precondition to prevent TOCTOU race.
    Generation 0 means "only upload if blob does not exist".

    Returns:
        Tuple of (gs:// URI, created: bool). created=False if blob already existed.
    """
    from google.api_core.exceptions import PreconditionFailed

    client = _get_gcs_client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(key)
    digest = _sha256(content)

    blob.metadata = {
        "x-audit-id": audit_id,
        "x-content-sha256": digest,
        "x-standard": "ISO/IEC 42001:2023",
        "x-audit-ts": timestamp.isoformat(),
    }

    gcs_uri = f"gs://{bucket_name}/{key}"

    try:
        # if_generation_match=0: Only upload if blob does NOT exist
        blob.upload_from_string(
            content.encode("utf-8"),
            content_type="application/yaml",
            timeout=int(os.environ.get("OSCAL_S3_TIMEOUT", "15")),
            if_generation_match=0,
        )
        logger.info(
            "[storage] OSCAL artifact persisted (GCS): %s (sha256=%s…)",
            gcs_uri,
            digest[:12],
        )
        return gcs_uri, True
    except PreconditionFailed:
        logger.info(
            "[storage] Artifact already exists (atomic check, GCS): %s",
            gcs_uri,
        )
        return gcs_uri, False


# ---------------------------------------------------------------------------
# S3-compat backend — boto3
# ---------------------------------------------------------------------------


def _s3_blob_exists(bucket_name: str, key: str) -> bool:
    """Synchronous S3 HEAD check."""
    from botocore.exceptions import ClientError

    s3 = _get_s3_client()
    try:
        s3.head_object(Bucket=bucket_name, Key=key)
        return True
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "")
        if error_code in ("404", "NoSuchKey"):
            return False
        logger.warning("[storage] S3 HEAD check failed (non-404): %s", exc)
        return False


def _s3_upload(
    bucket_name: str, key: str, content: str, audit_id: str, timestamp: datetime
) -> str:
    """Synchronous S3 PutObject. Returns s3:// URI."""
    s3 = _get_s3_client()
    digest = _sha256(content)

    s3.put_object(
        Bucket=bucket_name,
        Key=key,
        Body=content.encode("utf-8"),
        ContentType="application/yaml",
        Metadata={
            "x-audit-id": audit_id,
            "x-content-sha256": digest,
            "x-standard": "ISO/IEC 42001:2023",
            "x-audit-ts": timestamp.isoformat(),
        },
    )

    uri = f"s3://{bucket_name}/{key}"
    logger.info(
        "[storage] OSCAL artifact persisted (S3): %s (sha256=%s…)",
        uri,
        digest[:12],
    )
    return uri


def _s3_upload_if_not_exists(
    bucket_name: str, key: str, content: str, audit_id: str, timestamp: datetime
) -> tuple[str, bool]:
    """Atomic S3 upload - check and upload in minimal race window.

    HIGH-4 FIX: S3 doesn't have a true atomic PUT-if-not-exists, but we can
    use HEAD + PUT with minimal window. For true atomicity, use S3 Object Lock
    or DynamoDB for coordination in production.

    Note: S3 is eventually consistent for overwrites, so concurrent writes
    will result in last-writer-wins. This is acceptable for idempotent OSCAL
    artifacts where content is deterministic per audit_id.

    Returns:
        Tuple of (s3:// URI, created: bool). created=False if blob already existed.
    """
    from botocore.exceptions import ClientError

    s3 = _get_s3_client()
    uri = f"s3://{bucket_name}/{key}"

    # Check if object already exists
    try:
        s3.head_object(Bucket=bucket_name, Key=key)
        logger.info(
            "[storage] Artifact already exists (S3): %s",
            uri,
        )
        return uri, False
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "")
        if error_code not in ("404", "NoSuchKey"):
            # Unexpected error - re-raise
            raise

    # Object doesn't exist - upload it
    digest = _sha256(content)
    s3.put_object(
        Bucket=bucket_name,
        Key=key,
        Body=content.encode("utf-8"),
        ContentType="application/yaml",
        Metadata={
            "x-audit-id": audit_id,
            "x-content-sha256": digest,
            "x-standard": "ISO/IEC 42001:2023",
            "x-audit-ts": timestamp.isoformat(),
        },
    )

    logger.info(
        "[storage] OSCAL artifact persisted (S3): %s (sha256=%s…)",
        uri,
        digest[:12],
    )
    return uri, True


# ---------------------------------------------------------------------------
# Unified async API
# ---------------------------------------------------------------------------


async def artifact_exists(bucket: str, key: str) -> bool:
    """Async existence check — dispatches to GCS or S3 backend."""
    # M-21: Resolve backend at call time, not at import time
    if _get_storage_backend() == "s3":
        return await asyncio.to_thread(_s3_blob_exists, bucket, key)
    return await asyncio.to_thread(_gcs_blob_exists, bucket, key)


async def upload_artifact(bucket: str, key: str, content: str) -> str:
    """
    Async upload — dispatches to GCS or S3 backend.

    Returns:
        URI: gs://<bucket>/<key>  or  s3://<bucket>/<key>
    """
    audit_id = key.split("/")[-1].replace(".yaml", "")
    timestamp = datetime.now(tz=timezone.utc)
    # M-21: Resolve backend at call time, not at import time
    if _get_storage_backend() == "s3":
        return await asyncio.to_thread(
            _s3_upload, bucket, key, content, audit_id, timestamp
        )
    return await asyncio.to_thread(
        _gcs_upload, bucket, key, content, audit_id, timestamp
    )


async def put_oscal_artifact_atomic(
    audit_id: str,
    oscal_yaml: str,
    timestamp: datetime | None = None,
) -> tuple[str, bool]:
    """
    Atomic idempotent OSCAL artifact upload.

    HIGH-4 FIX: Uses atomic PUT-if-not-exists to prevent TOCTOU race condition.
    For GCS, uses if_generation_match=0 precondition.
    For S3, uses HEAD+PUT with minimal race window (S3 lacks true atomic CAS).

    Args:
        audit_id:   Unique run identifier.
        oscal_yaml: Raw YAML string from `lula validate`.
        timestamp:  Audit timestamp (used in object key path). Defaults to now.

    Returns:
        Tuple of (object key, created: bool). created=False if artifact existed.
    """
    if timestamp is None:
        timestamp = datetime.now(tz=timezone.utc)

    bucket = _get_bucket()
    key = _build_object_key(audit_id, timestamp)

    # HIGH-4 FIX: Use atomic upload functions instead of check-then-upload
    if _get_storage_backend() == "s3":
        _, created = await asyncio.to_thread(
            _s3_upload_if_not_exists, bucket, key, oscal_yaml, audit_id, timestamp
        )
    else:
        _, created = await asyncio.to_thread(
            _gcs_upload_if_not_exists, bucket, key, oscal_yaml, audit_id, timestamp
        )

    return key, created


async def put_oscal_artifact(
    audit_id: str,
    oscal_yaml: str,
    timestamp: datetime | None = None,
) -> str:
    """
    Idempotent OSCAL artifact upload.

    HIGH-4 FIX: Now uses atomic PUT-if-not-exists internally to prevent
    TOCTOU race condition where another process could create the artifact
    between our existence check and upload.

    Args:
        audit_id:   Unique run identifier.
        oscal_yaml: Raw YAML string from `lula validate`.
        timestamp:  Audit timestamp (used in object key path). Defaults to now.

    Returns:
        Object key (not the full URI).
    """
    key, _ = await put_oscal_artifact_atomic(audit_id, oscal_yaml, timestamp)
    return key

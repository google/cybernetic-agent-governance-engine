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
factory.py — Evidence Cold Storage Factory

Provides a single, vendor-neutral factory for resolving and constructing
EvidenceColdStore implementations (GcsColdStore, S3ColdStore, NullColdStore).

Design Invariants (Wave 1, Task W1.5b):
    - Concrete adapter classes are imported lazily inside their respective branches.
    - Configuration (bucket, endpoints, timeouts, CMEK keys) is resolved in the
      factory and passed as constructor arguments.
    - Default backend is 'null' (succeed-locally in dev/test).
    - Enforces data residency via `resolve_cold_store_bucket()`.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from .cold_store import EvidenceColdStore
from .null_cold_store import NullColdStore
from .residency import resolve_cold_store_bucket

logger = logging.getLogger(__name__)

_DEFAULT_COLD_STORE: EvidenceColdStore | None = None


def get_cold_store(
    backend: str | None = None,
    bucket: str | None = None,
    region: str | None = None,
    location: str | None = None,
    cmek_key: str | None = None,
    endpoint: str | None = None,
    timeout_seconds: int | None = None,
    use_ssl: bool = True,
) -> EvidenceColdStore:
    """Construct an EvidenceColdStore instance based on environment or parameters.

    Selection Priority:
        1. Explicit `backend` argument.
        2. `EVIDENCE_COLD_STORE` environment variable.
        3. Default to `"null"`.

    Args:
        backend: Storage backend ("gcs", "s3", "null").
        bucket: Explicit bucket name. If None, resolved via residency rules.
        region: CAGE deployment region ("US_FED", "EU_ECB", "APAC_MAS", "LOCAL").
        location: Cloud location/zone (e.g. "europe-west1", "asia-southeast1").
        cmek_key: Optional Cloud KMS key resource ID for server-side encryption.
        endpoint: S3-compatible endpoint URL (for MinIO, AWS, Ceph, etc.).
        timeout_seconds: Timeout for storage I/O operations.
        use_ssl: Whether to enforce TLS for S3-compatible endpoints.

    Returns:
        Instance conforming to EvidenceColdStore protocol.

    Raises:
        ValueError: If backend is unrecognized.
        MissingBucketConfigError: If required bucket cannot be resolved.
        ResidencyViolationError: If resolved bucket violates jurisdictional rules.
    """
    selected_backend = (
        (backend or os.environ.get("EVIDENCE_COLD_STORE") or "null").lower().strip()
    )

    # Null store bypasses cloud bucket resolution
    if selected_backend == "null":
        return NullColdStore()

    # Resolve bucket with residency verification for cloud backends
    resolved_bucket = bucket or resolve_cold_store_bucket(
        region=region,
        location=location,
        backend_id=selected_backend,
    )

    if selected_backend == "gcs":
        from src.integrations.storage_gcs.cold_store import GcsColdStore

        project = (
            os.environ.get("GCP_PROJECT_ID")
            or os.environ.get("GOOGLE_CLOUD_PROJECT")
            or None
        )
        resolved_cmek = (
            cmek_key
            or os.environ.get("EVIDENCE_COLD_STORE_CMEK_KEY")
            or os.environ.get("EVIDENCE_STREAM_CMEK_KEY")
            or None
        )
        timeout = timeout_seconds or int(
            os.environ.get("EVIDENCE_COLD_STORE_TIMEOUT_S", "30")
        )
        return GcsColdStore(
            bucket=resolved_bucket,
            project=project,
            cmek_key=resolved_cmek,
            timeout_seconds=timeout,
        )

    if selected_backend == "s3":
        from src.integrations.storage_s3.cold_store import S3ColdStore

        endpoint_url = endpoint or os.environ.get("EVIDENCE_COLD_STORE_S3_ENDPOINT")
        s3_region = region or os.environ.get("EVIDENCE_COLD_STORE_S3_REGION", "auto")
        access_key = os.environ.get("EVIDENCE_COLD_STORE_S3_ACCESS_KEY")
        secret_key = os.environ.get("EVIDENCE_COLD_STORE_S3_SECRET_KEY")
        timeout = timeout_seconds or int(
            os.environ.get("EVIDENCE_COLD_STORE_TIMEOUT_S", "15")
        )

        return S3ColdStore(
            bucket=resolved_bucket,
            endpoint_url=endpoint_url,
            region_name=s3_region,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            timeout_seconds=timeout,
            use_ssl=use_ssl,
        )

    raise ValueError(
        f"Unsupported cold store backend: '{selected_backend}'. "
        "Must be one of: 'gcs', 's3', 'null'."
    )


def get_default_cold_store() -> EvidenceColdStore:
    """Return or initialize the singleton default EvidenceColdStore instance."""
    global _DEFAULT_COLD_STORE
    if _DEFAULT_COLD_STORE is None:
        _DEFAULT_COLD_STORE = get_cold_store()
    return _DEFAULT_COLD_STORE


def reset_default_cold_store() -> None:
    """Reset the singleton instance (used for test isolation)."""
    global _DEFAULT_COLD_STORE
    _DEFAULT_COLD_STORE = None

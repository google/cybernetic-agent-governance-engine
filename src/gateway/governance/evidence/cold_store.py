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
cold_store.py — Vendor-Decoupled Evidence Cold Storage Protocol

Provides Protocol-based abstractions for evidence archival to cloud object storage,
decoupling CAGE's kernel from specific vendor SDKs (google-cloud-storage, boto3, etc).

Architecture Position:
    Redis Streams → Compliance Bridge → GCS Flush Daemon → EvidenceColdStore
                                                               ├── GcsColdStore
                                                               ├── S3ColdStore
                                                               └── NullColdStore

Design Rationale:
    - Protocol-based interface allows swapping vendors without changing kernel code
    - Lazy imports ensure vendor SDKs are only loaded when actually used
    - Each implementation handles its own credential/region configuration
    - Fail-fast on misconfiguration (missing bucket/credentials)

Key Invariants:
    1. All vendor SDK imports must be lazy (inside methods, not at module level)
    2. put_batch() must preserve NDJSON byte-for-byte (no re-serialization)
    3. Batch IDs must be globally unique (typically UUID4 or timestamp-based)
    4. Region parameter allows multi-region compliance (GDPR, MAS, FedRAMP)
    5. All methods are synchronous (async handled by caller's thread pool)

Environment Variables (examples):
    GcsColdStore:
        EVIDENCE_STREAM_BUCKET_US_FED=cage-evidence-us-federal
        EVIDENCE_STREAM_BUCKET_EU_ECB=cage-evidence-eu-west1
        GOOGLE_CLOUD_PROJECT=cage-prod-us
        GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json

    S3ColdStore:
        EVIDENCE_STREAM_BUCKET_US_FED=cage-evidence-us-east-1
        AWS_ACCESS_KEY_ID=...
        AWS_SECRET_ACCESS_KEY=...
        AWS_REGION=us-east-1

Wave 1 Scope (this file):
    - EvidenceColdStore Protocol (W1.1)
    - GcsColdStore implementation (W1.2)
    - S3ColdStore implementation (W1.3)

Wave 2 Scope (evidence_stream.py migration):
    - Replace direct GCS SDK calls with EvidenceColdStore protocol
    - Add factory function: create_cold_store(region: str) -> EvidenceColdStore
    - Preserve existing flush daemon behavior
"""

from __future__ import annotations

import logging
import os
from typing import Protocol

logger = logging.getLogger("cage.evidence.cold_store")


# ---------------------------------------------------------------------------
# Protocol Definition (W1.1)
# ---------------------------------------------------------------------------


class EvidenceColdStore(Protocol):
    """Protocol for vendor-agnostic evidence cold storage.

    Implementers must provide put_batch() and get_batch() methods for
    archiving hash-chained evidence batches to durable cloud object storage.

    Critical Design Rules:
        1. Implementations MUST NOT import vendor SDKs at module level
        2. Implementations MUST preserve NDJSON byte-for-byte (no re-encoding)
        3. Implementations MUST raise on missing credentials/bucket config
        4. All methods are synchronous (caller wraps in thread pool if needed)

    Examples:
        >>> store = GcsColdStore()
        >>> ndjson = '{"seq": 1}\\n{"seq": 2}\\n'
        >>> batch_id = "2026-09-05T16:00:00_epoch42"
        >>> uri = store.put_batch(ndjson, batch_id, region="US_FED")
        >>> assert uri.startswith("gs://cage-evidence-us-federal/")
        >>>
        >>> retrieved = store.get_batch(batch_id, region="US_FED")
        >>> assert retrieved == ndjson
    """

    def put_batch(self, ndjson: str, batch_id: str, region: str) -> str:
        """Upload hash-chained evidence batch to cold storage.

        Args:
            ndjson: Newline-delimited JSON records (raw string, not bytes).
                Must preserve original serialization byte-for-byte to maintain
                hash chain integrity.
            batch_id: Globally unique batch identifier (e.g. timestamp_epoch).
                Used as object key/blob name.
            region: Compliance region tag (US_FED, EU_ECB, APAC_MAS, etc).
                Determines which bucket/container to use.

        Returns:
            URI of uploaded object (e.g. "gs://bucket/batch_id.ndjson").

        Raises:
            ValueError: Missing bucket configuration for region
            RuntimeError: Upload failed after retries
            ImportError: Vendor SDK not installed (lazy import failed)
        """
        ...

    def get_batch(self, batch_id: str, region: str) -> str:
        """Retrieve evidence batch from cold storage.

        Args:
            batch_id: Batch identifier (matches put_batch key)
            region: Compliance region tag

        Returns:
            NDJSON string (raw, byte-for-byte identical to put_batch input)

        Raises:
            ValueError: Missing bucket configuration for region
            FileNotFoundError: Batch does not exist
            RuntimeError: Download failed after retries
            ImportError: Vendor SDK not installed
        """
        ...


# ---------------------------------------------------------------------------
# Google Cloud Storage Implementation (W1.2)
# ---------------------------------------------------------------------------


class GcsColdStore:
    """Google Cloud Storage implementation of EvidenceColdStore.

    Uses google-cloud-storage SDK with lazy imports. Credentials are
    autodiscovered via GOOGLE_APPLICATION_CREDENTIALS or GKE Workload Identity.

    Environment Variables:
        EVIDENCE_STREAM_BUCKET_{region} — GCS bucket name for region
            Example: EVIDENCE_STREAM_BUCKET_US_FED=cage-evidence-us-federal
        GOOGLE_CLOUD_PROJECT — GCP project ID (required for bucket access)
        GOOGLE_APPLICATION_CREDENTIALS — Path to service account JSON (optional)

    Bucket Naming Convention:
        cage-evidence-{region-slug}
        Examples:
            US_FED   → cage-evidence-us-federal
            EU_ECB   → cage-evidence-eu-west1
            APAC_MAS → cage-evidence-asia-southeast1

    Object Key Format:
        {batch_id}.ndjson
        Example: 2026-09-05T16:00:00_epoch42.ndjson

    Note: This implementation does NOT manage CMEK configuration.
          CMEK must be configured at the bucket level via Terraform/gcloud.
    """

    def __init__(self) -> None:
        """Initialize GCS cold store.

        No SDK imports happen here — imports are deferred to method calls.
        """
        self._project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
        if not self._project_id:
            logger.warning(
                "[GcsColdStore] GOOGLE_CLOUD_PROJECT not set — GCS access may fail"
            )

    def _get_bucket_name(self, region: str) -> str:
        """Resolve GCS bucket name for compliance region.

        Args:
            region: Compliance region tag (US_FED, EU_ECB, etc)

        Returns:
            GCS bucket name

        Raises:
            ValueError: Bucket not configured for region
        """
        env_key = f"EVIDENCE_STREAM_BUCKET_{region}"
        bucket_name = os.environ.get(env_key)
        if not bucket_name:
            raise ValueError(
                f"[GcsColdStore] Missing bucket config for region {region}: "
                f"set {env_key} environment variable"
            )
        return bucket_name

    def put_batch(self, ndjson: str, batch_id: str, region: str) -> str:
        """Upload evidence batch to GCS.

        Lazy-imports google.cloud.storage only when called.

        Args:
            ndjson: NDJSON string (preserved byte-for-byte)
            batch_id: Unique batch identifier
            region: Compliance region tag

        Returns:
            GCS URI (gs://bucket/batch_id.ndjson)

        Raises:
            ValueError: Missing bucket configuration
            RuntimeError: Upload failed
            ImportError: google-cloud-storage not installed
        """
        try:
            from google.cloud import storage
        except ImportError as e:
            raise ImportError(
                "[GcsColdStore] google-cloud-storage not installed. "
                "Install with: pip install google-cloud-storage"
            ) from e

        bucket_name = self._get_bucket_name(region)
        blob_name = f"{batch_id}.ndjson"

        try:
            client = storage.Client(project=self._project_id)
            bucket = client.bucket(bucket_name)
            blob = bucket.blob(blob_name)

            # Upload with content type for audit log friendliness
            blob.upload_from_string(
                ndjson,
                content_type="application/x-ndjson",
                retry=storage.retry.DEFAULT_RETRY,
            )

            uri = f"gs://{bucket_name}/{blob_name}"
            logger.info(
                f"[GcsColdStore] Uploaded batch {batch_id} to {uri} "
                f"(region={region}, size={len(ndjson)} bytes)"
            )
            return uri

        except Exception as e:
            logger.error(
                f"[GcsColdStore] Upload failed for batch {batch_id} "
                f"(region={region}): {e}",
                exc_info=True,
            )
            raise RuntimeError(
                f"GCS upload failed for batch {batch_id}: {e}"
            ) from e

    def get_batch(self, batch_id: str, region: str) -> str:
        """Retrieve evidence batch from GCS.

        Args:
            batch_id: Batch identifier
            region: Compliance region tag

        Returns:
            NDJSON string

        Raises:
            ValueError: Missing bucket configuration
            FileNotFoundError: Batch does not exist
            RuntimeError: Download failed
            ImportError: google-cloud-storage not installed
        """
        try:
            from google.cloud import storage
        except ImportError as e:
            raise ImportError(
                "[GcsColdStore] google-cloud-storage not installed"
            ) from e

        bucket_name = self._get_bucket_name(region)
        blob_name = f"{batch_id}.ndjson"

        try:
            client = storage.Client(project=self._project_id)
            bucket = client.bucket(bucket_name)
            blob = bucket.blob(blob_name)

            if not blob.exists():
                raise FileNotFoundError(
                    f"Batch {batch_id} not found in gs://{bucket_name}/"
                )

            ndjson = blob.download_as_text()
            logger.info(
                f"[GcsColdStore] Retrieved batch {batch_id} from "
                f"gs://{bucket_name}/{blob_name} (size={len(ndjson)} bytes)"
            )
            return ndjson

        except FileNotFoundError:
            raise
        except Exception as e:
            logger.error(
                f"[GcsColdStore] Download failed for batch {batch_id}: {e}",
                exc_info=True,
            )
            raise RuntimeError(
                f"GCS download failed for batch {batch_id}: {e}"
            ) from e


# ---------------------------------------------------------------------------
# S3-Compatible Storage Implementation (W1.3)
# ---------------------------------------------------------------------------


class S3ColdStore:
    """S3-compatible storage implementation of EvidenceColdStore.

    Uses boto3 SDK with lazy imports. Works with:
        - AWS S3
        - Google Cloud Storage S3 interoperability
        - MinIO
        - Any S3-compatible object storage

    Environment Variables:
        EVIDENCE_STREAM_BUCKET_{region} — S3 bucket name for region
            Example: EVIDENCE_STREAM_BUCKET_US_FED=cage-evidence-us-east-1
        AWS_ACCESS_KEY_ID — S3 access key (required)
        AWS_SECRET_ACCESS_KEY — S3 secret key (required)
        AWS_REGION — Default S3 region (optional, defaults to us-east-1)
        S3_ENDPOINT_URL — Custom endpoint for non-AWS S3 (e.g. MinIO)

    Bucket Naming Convention:
        Same as GCS: cage-evidence-{region-slug}

    Object Key Format:
        {batch_id}.ndjson

    Encryption:
        - Uses server-side encryption (SSE-S3 or SSE-KMS)
        - KMS key ARN configured at bucket level, not in SDK calls
    """

    def __init__(self) -> None:
        """Initialize S3 cold store.

        No SDK imports happen here — imports are deferred to method calls.
        """
        self._region = os.environ.get("AWS_REGION", "us-east-1")
        self._endpoint_url = os.environ.get("S3_ENDPOINT_URL")
        self._access_key = os.environ.get("AWS_ACCESS_KEY_ID")
        self._secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY")

        if not self._access_key or not self._secret_key:
            logger.warning(
                "[S3ColdStore] AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY not set — "
                "S3 access may fail unless using IAM role credentials"
            )

    def _get_bucket_name(self, region: str) -> str:
        """Resolve S3 bucket name for compliance region.

        Args:
            region: Compliance region tag (US_FED, EU_ECB, etc)

        Returns:
            S3 bucket name

        Raises:
            ValueError: Bucket not configured for region
        """
        env_key = f"EVIDENCE_STREAM_BUCKET_{region}"
        bucket_name = os.environ.get(env_key)
        if not bucket_name:
            raise ValueError(
                f"[S3ColdStore] Missing bucket config for region {region}: "
                f"set {env_key} environment variable"
            )
        return bucket_name

    def put_batch(self, ndjson: str, batch_id: str, region: str) -> str:
        """Upload evidence batch to S3.

        Lazy-imports boto3 only when called.

        Args:
            ndjson: NDJSON string (preserved byte-for-byte)
            batch_id: Unique batch identifier
            region: Compliance region tag

        Returns:
            S3 URI (s3://bucket/batch_id.ndjson)

        Raises:
            ValueError: Missing bucket configuration
            RuntimeError: Upload failed
            ImportError: boto3 not installed
        """
        try:
            import boto3
        except ImportError as e:
            raise ImportError(
                "[S3ColdStore] boto3 not installed. Install with: pip install boto3"
            ) from e

        bucket_name = self._get_bucket_name(region)
        object_key = f"{batch_id}.ndjson"

        try:
            s3_client = boto3.client(
                "s3",
                region_name=self._region,
                endpoint_url=self._endpoint_url,
                aws_access_key_id=self._access_key,
                aws_secret_access_key=self._secret_key,
            )

            # Upload with metadata for audit trail
            s3_client.put_object(
                Bucket=bucket_name,
                Key=object_key,
                Body=ndjson.encode("utf-8"),
                ContentType="application/x-ndjson",
                Metadata={
                    "batch_id": batch_id,
                    "compliance_region": region,
                    "schema": "cage-evidence-stream/3.0",
                },
            )

            uri = f"s3://{bucket_name}/{object_key}"
            logger.info(
                f"[S3ColdStore] Uploaded batch {batch_id} to {uri} "
                f"(region={region}, size={len(ndjson)} bytes)"
            )
            return uri

        except Exception as e:
            logger.error(
                f"[S3ColdStore] Upload failed for batch {batch_id} "
                f"(region={region}): {e}",
                exc_info=True,
            )
            raise RuntimeError(
                f"S3 upload failed for batch {batch_id}: {e}"
            ) from e

    def get_batch(self, batch_id: str, region: str) -> str:
        """Retrieve evidence batch from S3.

        Args:
            batch_id: Batch identifier
            region: Compliance region tag

        Returns:
            NDJSON string

        Raises:
            ValueError: Missing bucket configuration
            FileNotFoundError: Batch does not exist
            RuntimeError: Download failed
            ImportError: boto3 not installed
        """
        try:
            import boto3
            from botocore.exceptions import ClientError
        except ImportError as e:
            raise ImportError("[S3ColdStore] boto3 not installed") from e

        bucket_name = self._get_bucket_name(region)
        object_key = f"{batch_id}.ndjson"

        try:
            s3_client = boto3.client(
                "s3",
                region_name=self._region,
                endpoint_url=self._endpoint_url,
                aws_access_key_id=self._access_key,
                aws_secret_access_key=self._secret_key,
            )

            response = s3_client.get_object(Bucket=bucket_name, Key=object_key)
            ndjson = response["Body"].read().decode("utf-8")

            logger.info(
                f"[S3ColdStore] Retrieved batch {batch_id} from "
                f"s3://{bucket_name}/{object_key} (size={len(ndjson)} bytes)"
            )
            return ndjson

        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchKey":
                raise FileNotFoundError(
                    f"Batch {batch_id} not found in s3://{bucket_name}/"
                ) from e
            logger.error(
                f"[S3ColdStore] Download failed for batch {batch_id}: {e}",
                exc_info=True,
            )
            raise RuntimeError(
                f"S3 download failed for batch {batch_id}: {e}"
            ) from e
        except Exception as e:
            logger.error(
                f"[S3ColdStore] Download failed for batch {batch_id}: {e}",
                exc_info=True,
            )
            raise RuntimeError(
                f"S3 download failed for batch {batch_id}: {e}"
            ) from e

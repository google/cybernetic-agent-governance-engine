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
Storage abstraction layer.

Allows the application to run with an S3-compatible object store (default),
local disk storage, or optionally Google Cloud Storage, selectable via the
STORAGE_BACKEND environment variable.

Set STORAGE_BACKEND=local for local development without any cloud dependency.
Set STORAGE_BACKEND=s3 (default) for AWS S3, MinIO, or any S3-compatible endpoint.
Set STORAGE_BACKEND=gcs for Google Cloud Storage (optional; requires google-cloud-storage).

S3Storage backend notes
-----------------------
``S3Storage`` can be pointed at:
  * Real AWS S3 — leave ``S3_ENDPOINT_URL`` unset; set standard AWS env vars.
  * GCS S3-compatible API — set ``S3_ENDPOINT_URL=https://storage.googleapis.com``
    and supply HMAC keys via ``AWS_ACCESS_KEY_ID`` / ``AWS_SECRET_ACCESS_KEY``.
    Also set ``S3_PATH_STYLE=true`` (required by GCS's S3 emulation layer).
  * MinIO — set ``S3_ENDPOINT_URL`` to the MinIO address (e.g.
    ``http://localhost:9000``) and enable ``S3_PATH_STYLE=true``.

Relevant environment variables for S3Storage:
  S3_BUCKET_NAME          — bucket name (required unless passed in constructor)
  S3_ENDPOINT_URL         — optional; overrides AWS endpoint for GCS/MinIO
  S3_REGION_NAME          — optional; defaults to "auto" when S3_ENDPOINT_URL
                            is set, otherwise boto3 region resolution applies
  S3_PATH_STYLE           — optional boolean; set to "true" to force
                            addressing_style="path" (required for GCS S3-compat)
  AWS_ACCESS_KEY_ID       — optional; boto3 reads this automatically from env
  AWS_SECRET_ACCESS_KEY   — optional; boto3 reads this automatically from env
"""

import logging
import os
from abc import ABC, abstractmethod
from pathlib import Path

logger = logging.getLogger(__name__)


class StorageInterface(ABC):
    """Abstract base class for storage backends."""

    @abstractmethod
    def upload(self, local_path: str, remote_path: str) -> str:
        """Upload a file. Returns the remote URI."""
        ...

    @abstractmethod
    def download(self, remote_path: str, local_path: str) -> str:
        """Download a file. Returns the local path."""
        ...

    @abstractmethod
    def read_text(self, remote_path: str) -> str:
        """Read a text file and return its contents."""
        ...

    @abstractmethod
    def write_text(self, remote_path: str, content: str) -> str:
        """Write text content to a remote path. Returns the remote URI."""
        ...

    @abstractmethod
    def exists(self, remote_path: str) -> bool:
        """Check if a remote path exists."""
        ...


class GCSStorage(StorageInterface):
    """Google Cloud Storage backend using the native GCS SDK."""

    def __init__(self, bucket_name: str | None = None):
        self.bucket_name = bucket_name or os.environ.get("GCS_BUCKET_NAME", "")
        self._client = None

    def _get_client(self):  # type: ignore[no-untyped-def]
        if self._client is None:
            try:
                from google.cloud import storage  # type: ignore[attr-defined]

                self._client = storage.Client()
            except Exception as e:
                raise RuntimeError(
                    f"GCS client unavailable: {e}. "
                    "Set STORAGE_BACKEND=local for local development."
                ) from e
        return self._client

    def _get_bucket(self):  # type: ignore[no-untyped-def]
        return self._get_client().bucket(self.bucket_name)

    def upload(self, local_path: str, remote_path: str) -> str:
        blob = self._get_bucket().blob(remote_path)
        blob.upload_from_filename(local_path)
        uri = f"gs://{self.bucket_name}/{remote_path}"
        logger.info("Uploaded %s → %s", local_path, uri)
        return uri

    def download(self, remote_path: str, local_path: str) -> str:
        blob = self._get_bucket().blob(remote_path)
        Path(local_path).parent.mkdir(parents=True, exist_ok=True)
        blob.download_to_filename(local_path)
        logger.info(
            "Downloaded gs://%s/%s → %s", self.bucket_name, remote_path, local_path
        )
        return local_path

    def read_text(self, remote_path: str) -> str:
        blob = self._get_bucket().blob(remote_path)
        return blob.download_as_text()

    def write_text(self, remote_path: str, content: str) -> str:
        blob = self._get_bucket().blob(remote_path)
        blob.upload_from_string(content)
        return f"gs://{self.bucket_name}/{remote_path}"

    def exists(self, remote_path: str) -> bool:
        blob = self._get_bucket().blob(remote_path)
        return blob.exists()


class LocalStorage(StorageInterface):
    """Local filesystem storage backend for development without GCP."""

    def __init__(self, base_dir: str | None = None):
        self.base_dir = Path(
            base_dir or os.environ.get("LOCAL_STORAGE_DIR", "/tmp/cage-storage")  # nosec B108
        )
        self.base_dir.mkdir(parents=True, exist_ok=True)
        logger.info("LocalStorage initialised at %s", self.base_dir)

    def _resolve(self, remote_path: str) -> Path:
        # Contain the join within base_dir. A remote_path with ".." segments
        # (``../../etc/passwd``) or an absolute component (``/etc/passwd`` — which
        # makes ``base_dir / remote_path`` discard base_dir entirely) would escape
        # the storage root and let a caller read or write arbitrary filesystem
        # locations through read_text/write_text/upload/download/exists.
        dest = self.base_dir / remote_path
        if not dest.resolve().is_relative_to(self.base_dir.resolve()):
            raise ValueError(
                f"LocalStorage: remote_path {remote_path!r} escapes the storage root"
            )
        return dest

    def upload(self, local_path: str, remote_path: str) -> str:
        import shutil

        dest = self._resolve(remote_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(local_path, dest)
        uri = f"local://{dest}"
        logger.info("Copied %s → %s", local_path, uri)
        return uri

    def download(self, remote_path: str, local_path: str) -> str:
        import shutil

        src = self._resolve(remote_path)
        Path(local_path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, local_path)
        return local_path

    def read_text(self, remote_path: str) -> str:
        return self._resolve(remote_path).read_text(encoding="utf-8")

    def write_text(self, remote_path: str, content: str) -> str:
        dest = self._resolve(remote_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")
        return f"local://{dest}"

    def exists(self, remote_path: str) -> bool:
        return self._resolve(remote_path).exists()


class S3Storage(StorageInterface):
    """
    S3-compatible storage backend using boto3.

    Works with real AWS S3, GCS S3-compatible API, and MinIO.
    See module docstring for full configuration details.
    """

    def __init__(self, bucket_name: str | None = None):
        try:
            import boto3
        except ImportError as exc:
            raise ImportError(
                "boto3 is required for S3Storage. Install it with: pip install boto3"
            ) from exc

        self.bucket_name = bucket_name or os.environ.get("S3_BUCKET_NAME", "")
        endpoint_url = os.environ.get("S3_ENDPOINT_URL") or None
        region_name = os.environ.get("S3_REGION_NAME") or (
            "auto" if endpoint_url else None
        )
        path_style = os.environ.get("S3_PATH_STYLE", "").lower() in ("1", "true", "yes")

        import boto3
        from botocore.config import Config as BotocoreConfig

        config = BotocoreConfig(s3={"addressing_style": "path"} if path_style else {})
        self._client = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            region_name=region_name,
            config=config,
            # AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are picked up
            # automatically by boto3 from the environment; no explicit
            # parameter needed here.
        )

    def upload(self, local_path: str, remote_path: str) -> str:
        self._client.upload_file(local_path, self.bucket_name, remote_path)
        uri = f"s3://{self.bucket_name}/{remote_path}"
        logger.info("Uploaded %s → %s", local_path, uri)
        return uri

    def download(self, remote_path: str, local_path: str) -> str:
        Path(local_path).parent.mkdir(parents=True, exist_ok=True)
        self._client.download_file(self.bucket_name, remote_path, local_path)
        logger.info(
            "Downloaded s3://%s/%s → %s", self.bucket_name, remote_path, local_path
        )
        return local_path

    def read_text(self, remote_path: str) -> str:
        response = self._client.get_object(Bucket=self.bucket_name, Key=remote_path)
        return response["Body"].read().decode("utf-8")

    def write_text(self, remote_path: str, content: str) -> str:
        self._client.put_object(
            Bucket=self.bucket_name,
            Key=remote_path,
            Body=content.encode("utf-8"),
        )
        return f"s3://{self.bucket_name}/{remote_path}"

    def exists(self, remote_path: str) -> bool:
        from botocore.exceptions import ClientError

        try:
            self._client.head_object(Bucket=self.bucket_name, Key=remote_path)
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("404", "NoSuchKey"):
                return False
            raise


def get_storage_backend(bucket_name: str | None = None) -> StorageInterface:
    """
    Factory function — returns the appropriate storage backend.

    Controlled by the STORAGE_BACKEND environment variable:
      - "s3" (default): Uses an S3-compatible object store (AWS S3, MinIO, GCS S3-compat).
      - "local": Uses the local filesystem (great for development without any cloud dependency).
      - "gcs": Uses Google Cloud Storage (optional; requires google-cloud-storage package).

    For MinIO (default in Docker Compose):
      S3_ENDPOINT_URL=http://minio:9000
      S3_PATH_STYLE=true
      AWS_ACCESS_KEY_ID=<minio-access-key>
      AWS_SECRET_ACCESS_KEY=<minio-secret-key>
      S3_BUCKET_NAME=<bucket-name>
    """
    backend = os.environ.get("STORAGE_BACKEND", "s3").lower()
    if backend == "local":
        base_dir = os.environ.get("LOCAL_STORAGE_DIR")
        return LocalStorage(base_dir=base_dir)
    elif backend == "s3":
        return S3Storage(bucket_name=bucket_name)
    elif backend == "gcs":
        return GCSStorage(bucket_name=bucket_name)
    else:
        raise ValueError(
            f"Unknown STORAGE_BACKEND '{backend}'. Valid options: 's3', 'local', 'gcs'."
        )

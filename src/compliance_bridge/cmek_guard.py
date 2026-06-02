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
cmek_guard.py — CMEK/SC-28 startup validation  (Tier 3.3)

Implements NIST SP 800-53 Rev 5 SC-28 (Protection of Information at Rest)
and closes POAM-014.

Validates that Customer-Managed Encryption Keys (CMEK) are correctly
configured before the compliance bridge begins serving audit traffic.
A misconfigured CMEK means evidence artifacts (OSCAL YAML) written to GCS
may be encrypted with Google-managed keys — a FedRAMP HIGH violation.

Validation checks (all must pass in production/staging):
  1. CMEK_KEY_RESOURCE_NAME env var is set and has valid KMS key path format.
  2. (Optional / best-effort) GCS bucket has CMEK configured:
     Reads the bucket's encryption config via the Google Cloud Storage Python
     client. On failure (missing credentials, network error) logs a warning
     rather than hard-failing — to avoid blocking deployments without GCS
     access (e.g. CI pipelines).
  3. CMEK_KEY_RESOURCE_NAME matches the bucket's configured defaultKmsKeyName
     (when GCS metadata is available).

Environment variables:
  CMEK_KEY_RESOURCE_NAME  — full KMS key name, e.g.:
                              projects/my-proj/locations/global/keyRings/cage/cryptoKeys/oscal-key
  OSCAL_BUCKET_NAME       — GCS bucket to check (also used by storage.py)
  CMEK_CHECK_DISABLED     — set to "1" to skip the guard entirely (dev/CI)

Hard-fail behaviour:
  Raises RuntimeError in non-dev environments when CMEK_KEY_RESOURCE_NAME is
  absent or has an invalid format.  GCS metadata mismatches are WARNING-only
  (best-effort) to avoid blocking deployments without GCS auth.
"""

from __future__ import annotations

import logging
import os
import re

logger = logging.getLogger(__name__)

# KMS key resource name pattern:
# projects/{project}/locations/{location}/keyRings/{ring}/cryptoKeys/{key}[/cryptoKeyVersions/{ver}]
_KMS_KEY_PATTERN = re.compile(
    r"^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+"
)

_DEV_ENVS = {"development", "dev", "test", "ci"}


def _is_disabled() -> bool:
    return os.environ.get("CMEK_CHECK_DISABLED", "").strip() == "1"


def _current_env() -> str:
    return os.environ.get("ENVIRONMENT", "development").lower()


def validate_cmek_configuration() -> dict:
    """
    Validate CMEK configuration.  Called during lifespan startup.

    Returns:
        {
          "cmek_enabled": bool,
          "key_name": str | None,
          "bucket_verified": bool,
          "warnings": list[str],
        }

    Raises:
        RuntimeError — if CMEK_KEY_RESOURCE_NAME is absent or malformed in
                       non-dev environments (hard fail).
    """
    if _is_disabled():
        logger.info("[cmek_guard] CMEK_CHECK_DISABLED=1 — skipping CMEK validation.")
        return {
            "cmek_enabled":   False,
            "key_name":       None,
            "bucket_verified": False,
            "warnings":       ["CMEK validation disabled via CMEK_CHECK_DISABLED=1"],
        }

    env      = _current_env()
    key_name = os.environ.get("CMEK_KEY_RESOURCE_NAME", "").strip()
    warnings: list[str] = []

    # ------------------------------------------------------------------
    # Check 1: Key name must be present and well-formed in non-dev envs
    # ------------------------------------------------------------------
    if not key_name:
        msg = (
            "[compliance-bridge] CMEK_KEY_RESOURCE_NAME is not set. "
            "OSCAL evidence artifacts may be written with Google-managed encryption. "
            "Set CMEK_KEY_RESOURCE_NAME to a Cloud KMS key to comply with "
            "NIST SC-28 / FedRAMP HIGH. (POAM-014)"
        )
        if env in _DEV_ENVS:
            logger.warning("[cmek_guard] %s (dev env — continuing)", msg)
            return {
                "cmek_enabled":    False,
                "key_name":        None,
                "bucket_verified": False,
                "warnings":        [msg],
            }
        raise RuntimeError(msg)

    if not _KMS_KEY_PATTERN.match(key_name):
        msg = (
            f"[compliance-bridge] CMEK_KEY_RESOURCE_NAME has invalid format: {key_name!r}. "
            "Expected: projects/{project}/locations/{location}/keyRings/{ring}/cryptoKeys/{key}. "
            "(POAM-014 / NIST SC-28)"
        )
        if env in _DEV_ENVS:
            logger.warning("[cmek_guard] %s (dev env — continuing)", msg)
            warnings.append(msg)
        else:
            raise RuntimeError(msg)

    logger.info("[cmek_guard] ✅ CMEK key name validated: %s", key_name)

    # ------------------------------------------------------------------
    # Check 2: Verify GCS bucket encryption metadata (best-effort)
    # ------------------------------------------------------------------
    bucket_name = os.environ.get("OSCAL_BUCKET_NAME", os.environ.get("OSCAL_S3_BUCKET", ""))
    bucket_verified = False

    if bucket_name:
        bucket_verified, bucket_warnings = _verify_gcs_bucket_cmek(bucket_name, key_name)
        warnings.extend(bucket_warnings)
    else:
        warnings.append(
            "[cmek_guard] OSCAL_BUCKET_NAME not set — skipping GCS bucket CMEK check."
        )

    return {
        "cmek_enabled":    True,
        "key_name":        key_name,
        "bucket_verified": bucket_verified,
        "warnings":        warnings,
    }


def _verify_gcs_bucket_cmek(bucket_name: str, expected_key: str) -> tuple[bool, list[str]]:
    """
    Best-effort: verify the GCS bucket has CMEK set to expected_key.

    Returns (verified: bool, warnings: list[str]).
    Never raises — all errors are warnings.
    """
    warnings: list[str] = []
    try:
        from google.cloud import storage  # noqa: PLC0415
        client = storage.Client()
        bucket = client.get_bucket(bucket_name)
        actual_key = bucket.default_kms_key_name or ""

        if not actual_key:
            warnings.append(
                f"[cmek_guard] ⚠️  Bucket '{bucket_name}' has no defaultKmsKeyName. "
                f"OSCAL artifacts may not be CMEK-encrypted. (POAM-014)"
            )
            return False, warnings

        # Normalise: strip /cryptoKeyVersions/... suffix for comparison
        normalised_actual   = actual_key.split("/cryptoKeyVersions/")[0]
        normalised_expected = expected_key.split("/cryptoKeyVersions/")[0]

        if normalised_actual == normalised_expected:
            logger.info(
                "[cmek_guard] ✅ GCS bucket '%s' CMEK verified: %s",
                bucket_name, normalised_actual,
            )
            return True, warnings
        else:
            warnings.append(
                f"[cmek_guard] ⚠️  Bucket '{bucket_name}' CMEK key mismatch. "
                f"Expected: {normalised_expected}. "
                f"Actual:   {normalised_actual}. "
                "Evidence artifacts may be encrypted with the wrong key. (POAM-014)"
            )
            return False, warnings

    except ImportError:
        warnings.append(
            "[cmek_guard] google-cloud-storage not installed — skipping GCS CMEK check. "
            "Install it in production to enable bucket verification."
        )
        return False, warnings
    except Exception as exc:
        warnings.append(
            f"[cmek_guard] GCS bucket CMEK check failed (best-effort): {exc}. "
            "Verify bucket encryption manually or set CMEK_CHECK_DISABLED=1 in dev."
        )
        return False, warnings

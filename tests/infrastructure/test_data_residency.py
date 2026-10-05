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
tests/infrastructure/test_data_residency.py
===========================================
EU_ECB data-residency gate tests.

Two classes:

- ``TestEUECBResidencyArtifacts`` (``local``): repository artifacts for the
  EU_ECB posture (tfvars, baseline) reference ``europe-west1`` only. Runs in
  every hermetic session, pinned to EU_ECB by its region marker.
- ``TestEUECBDeployedResidency`` (``integration``): GCS paths and buckets of a
  live deployment are confined to ``europe-west1``. Runs only when the
  deployment's ``cage-deployment`` ConfigMap sets EU_ECB:

    uv run pytest tests/infrastructure/ -v -m eu_ecb --run-integration

Marks
-----
- ``eu_ecb``      : EU_ECB region-specific test
- ``local``       : safe to run with no live services (CI default)
- ``integration`` : needs a live EU_ECB deployment
"""

from __future__ import annotations

import os

import pytest

# ---------------------------------------------------------------------------
# Known non-EU region substrings — any bucket/path containing these is a
# residency violation when CAGE_DEPLOYMENT_REGION == EU_ECB.
# ---------------------------------------------------------------------------

_NON_EU_REGIONS = (
    "us-central1",
    "us-east1",
    "us-west1",
    "us-west2",
    "us-west3",
    "us-west4",
    "northamerica-northeast1",
    "southamerica-east1",
    "asia-east1",
    "asia-east2",
    "asia-northeast1",
    "asia-northeast2",
    "asia-northeast3",
    "asia-south1",
    "asia-southeast1",
    "asia-southeast2",
    "australia-southeast1",
    "australia-southeast2",
    # Short-form aliases
    "us-",
    "asia-",
    "australia-",
    "northamerica-",
    "southamerica-",
)

_REQUIRED_EU_REGION = "europe-west1"


def _assert_eu_region(value: str, label: str) -> None:
    """Assert that *value* references europe-west1 and no non-EU region."""
    assert _REQUIRED_EU_REGION in value, (
        f"{label} must reference '{_REQUIRED_EU_REGION}', got: {value!r}"
    )
    for bad in _NON_EU_REGIONS:
        assert bad not in value, (
            f"{label} must not reference non-EU region '{bad}', got: {value!r}"
        )


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------


@pytest.mark.eu_ecb
@pytest.mark.integration
class TestEUECBDeployedResidency:
    """Gate tests for EU_ECB data-residency compliance (GDPR Art. 44 / MAS TRM §4.2).

    Checks the environment of a live EU_ECB deployment run. The harness
    skips this class unless the deployment's ``cage-deployment`` ConfigMap
    sets ``CAGE_DEPLOYMENT_REGION=EU_ECB``.
    """

    # ------------------------------------------------------------------
    # 1. GCS storage path residency
    # ------------------------------------------------------------------

    def test_gcs_storage_paths_are_eu_region(self) -> None:
        """All GCS storage paths configured via env vars must be in europe-west1."""
        gcs_path_vars = [
            "GCS_BUCKET_PATH",
            "OSCAL_GCS_PATH",
            "AUDIT_GCS_PATH",
            "EVIDENCE_GCS_PATH",
            "COMPLIANCE_GCS_PATH",
        ]
        for var in gcs_path_vars:
            value = os.environ.get(var, "")
            if not value:
                # Variable not set — not a violation; skip this specific var
                continue
            _assert_eu_region(value, var)

    def test_google_cloud_location_is_europe_west1(self) -> None:
        """GOOGLE_CLOUD_LOCATION must be europe-west1 for EU_ECB PRODUCTION deployments.

        Staging/dev/test environments are exempt from geographic restrictions to allow
        multi-region compliance testing on a single cluster.
        """
        cage_env = os.environ.get("CAGE_ENV", "production").lower()
        if cage_env in (
            "development",
            "dev",
            "test",
            "ci",
            "staging",
            "uat",
            "preprod",
        ):
            pytest.skip(
                f"Geographic location checks skipped for CAGE_ENV={cage_env} "
                "(non-production environment)"
            )

        location = os.environ.get("GOOGLE_CLOUD_LOCATION", "")
        if not location:
            pytest.skip(
                "GOOGLE_CLOUD_LOCATION not set — skipping location residency check"
            )
        assert location == _REQUIRED_EU_REGION, (
            f"GOOGLE_CLOUD_LOCATION must be '{_REQUIRED_EU_REGION}' for EU_ECB production, "
            f"got {location!r}"
        )

    # ------------------------------------------------------------------
    # 2. COLD_TIER_BUCKET residency
    # ------------------------------------------------------------------

    def test_cold_tier_bucket_does_not_reference_non_eu_region(self) -> None:
        """COLD_TIER_BUCKET, when set, must not reference a non-EU region."""
        bucket = os.environ.get("COLD_TIER_BUCKET", "")
        if not bucket:
            pytest.skip("COLD_TIER_BUCKET not set — skipping residency check")
        for bad in _NON_EU_REGIONS:
            assert bad not in bucket, (
                f"COLD_TIER_BUCKET must not reference non-EU region '{bad}', "
                f"got: {bucket!r}"
            )

    def test_cold_tier_bucket_references_eu_region_when_explicit(self) -> None:
        """COLD_TIER_BUCKET, when it contains a region string, must be europe-west1."""
        bucket = os.environ.get("COLD_TIER_BUCKET", "")
        if not bucket:
            pytest.skip("COLD_TIER_BUCKET not set — skipping residency check")
        # Only assert the positive EU region if the bucket name embeds a region
        # (e.g. "cage-eu-ecb-cold-europe-west1"). Generic names like
        # "cage-cold-tier" are acceptable without a region substring.
        if any(
            region_hint in bucket
            for region_hint in ("europe-", "us-", "asia-", "australia-")
        ):
            _assert_eu_region(bucket, "COLD_TIER_BUCKET")

    # ------------------------------------------------------------------
    # 3. OSCAL_S3_BUCKET residency
    # ------------------------------------------------------------------

    def test_oscal_s3_bucket_does_not_reference_non_eu_region(self) -> None:
        """OSCAL_S3_BUCKET, when set, must not reference a non-EU region."""
        bucket = os.environ.get("OSCAL_S3_BUCKET", "")
        if not bucket:
            pytest.skip("OSCAL_S3_BUCKET not set — skipping residency check")
        for bad in _NON_EU_REGIONS:
            assert bad not in bucket, (
                f"OSCAL_S3_BUCKET must not reference non-EU region '{bad}', "
                f"got: {bucket!r}"
            )

    def test_oscal_s3_bucket_references_eu_region_when_explicit(self) -> None:
        """OSCAL_S3_BUCKET, when it contains a region string, must be europe-west1."""
        bucket = os.environ.get("OSCAL_S3_BUCKET", "")
        if not bucket:
            pytest.skip("OSCAL_S3_BUCKET not set — skipping residency check")
        if any(
            region_hint in bucket
            for region_hint in ("europe-", "us-", "asia-", "australia-")
        ):
            _assert_eu_region(bucket, "OSCAL_S3_BUCKET")


@pytest.mark.eu_ecb
@pytest.mark.local
class TestEUECBResidencyArtifacts:
    """Repository artifacts (tfvars, baselines) for the EU_ECB posture."""

    # ------------------------------------------------------------------
    # 4. Terraform tfvars residency (eu-dev / eu-prod)
    # ------------------------------------------------------------------

    def test_eu_dev_tfvars_references_europe_west1(self) -> None:
        """infra/targets/gcp-gke/eu-dev.tfvars must reference europe-west1."""
        import pathlib

        tfvars_path = pathlib.Path("infra/targets/gcp-gke/eu-dev.tfvars")
        if not tfvars_path.exists():
            pytest.skip(f"{tfvars_path} not found — skipping tfvars residency check")
        content = tfvars_path.read_text()
        assert _REQUIRED_EU_REGION in content, (
            f"eu-dev.tfvars must reference '{_REQUIRED_EU_REGION}' for EU_ECB posture"
        )

    def test_eu_prod_tfvars_references_europe_west1(self) -> None:
        """infra/targets/gcp-gke/eu-prod.tfvars must reference europe-west1."""
        import pathlib

        tfvars_path = pathlib.Path("infra/targets/gcp-gke/eu-prod.tfvars")
        if not tfvars_path.exists():
            pytest.skip(f"{tfvars_path} not found — skipping tfvars residency check")
        content = tfvars_path.read_text()
        assert _REQUIRED_EU_REGION in content, (
            f"eu-prod.tfvars must reference '{_REQUIRED_EU_REGION}' for EU_ECB posture"
        )

    # ------------------------------------------------------------------
    # 5. EU_ECB baseline config residency
    # ------------------------------------------------------------------

    def test_eu_ecb_baseline_config_references_europe_west1(self) -> None:
        """config/compliance/EU_ECB_BASELINE.json must reference europe-west1."""
        import json
        import pathlib

        baseline_path = pathlib.Path("config/compliance/EU_ECB_BASELINE.json")
        if not baseline_path.exists():
            pytest.skip(
                f"{baseline_path} not found — skipping baseline residency check"
            )
        content = baseline_path.read_text()
        assert _REQUIRED_EU_REGION in content, (
            f"EU_ECB_BASELINE.json must reference '{_REQUIRED_EU_REGION}'"
        )
        # Ensure no non-EU regions are embedded in the baseline
        data = json.loads(content)
        data_str = json.dumps(data)
        for bad in ("us-central1", "asia-southeast1", "us-east1"):
            assert bad not in data_str, (
                f"EU_ECB_BASELINE.json must not reference non-EU region '{bad}'"
            )

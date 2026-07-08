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
tests/infrastructure/test_data_residency_apac_mas.py
=====================================================
APAC_MAS data-residency gate tests.

These tests assert that all GCS storage paths and bucket references are
confined to the ``asia-southeast1`` region when ``CAGE_DEPLOYMENT_REGION``
is set to ``APAC_MAS``.  They are skipped automatically for all other
deployment regions.

Regulatory basis: MAS TRM §4.2 (data residency), MAS Notice 655 (outsourcing),
MAS FEAT (fairness, ethics, accountability, transparency).

Run manually against an APAC_MAS posture:

    CAGE_DEPLOYMENT_REGION=APAC_MAS uv run pytest tests/infrastructure/ -v -m apac_mas

Marks
-----
- ``apac_mas`` : APAC_MAS jurisdiction-specific test
- ``local``    : safe to run with no live services (CI default)
"""

from __future__ import annotations

import os

import pytest

# ---------------------------------------------------------------------------
# Module-level skip guard — entire module is skipped unless APAC_MAS is active
# ---------------------------------------------------------------------------

_REGION = os.environ.get("CAGE_DEPLOYMENT_REGION", "")

_SKIP_NON_APAC = pytest.mark.skipif(
    _REGION != "APAC_MAS",
    reason=(
        f"APAC_MAS data-residency tests skipped for region {_REGION!r}. "
        "Set CAGE_DEPLOYMENT_REGION=APAC_MAS to run."
    ),
)

# ---------------------------------------------------------------------------
# Known non-APAC region substrings — any bucket/path containing these is a
# residency violation when CAGE_DEPLOYMENT_REGION == APAC_MAS.
# ---------------------------------------------------------------------------

_NON_APAC_REGIONS = (
    "us-central1",
    "us-east1",
    "us-west1",
    "us-west2",
    "us-west3",
    "us-west4",
    "northamerica-northeast1",
    "southamerica-east1",
    "europe-west1",
    "europe-west2",
    "europe-west3",
    "europe-west4",
    "europe-west6",
    "europe-north1",
    "europe-central2",
    # Short-form aliases
    "us-",
    "europe-",
    "northamerica-",
    "southamerica-",
)

_REQUIRED_APAC_REGION = "asia-southeast1"


def _assert_apac_region(value: str, label: str) -> None:
    """Assert that *value* references asia-southeast1 and no non-APAC region."""
    assert _REQUIRED_APAC_REGION in value, (
        f"{label} must reference '{_REQUIRED_APAC_REGION}', got: {value!r}"
    )
    for bad in _NON_APAC_REGIONS:
        assert bad not in value, (
            f"{label} must not reference non-APAC region '{bad}', got: {value!r}"
        )


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------


@pytest.mark.apac_mas
@pytest.mark.local
@_SKIP_NON_APAC
class TestAPACMASDataResidency:
    """Gate tests for APAC_MAS data-residency compliance (MAS TRM §4.2)."""

    # ------------------------------------------------------------------
    # 1. Deployment region identity
    # ------------------------------------------------------------------

    def test_cage_deployment_region_is_apac_mas(self) -> None:
        """CAGE_DEPLOYMENT_REGION must be exactly 'APAC_MAS' in this posture."""
        region = os.environ.get("CAGE_DEPLOYMENT_REGION", "")
        assert region == "APAC_MAS", (
            f"Expected CAGE_DEPLOYMENT_REGION='APAC_MAS', got {region!r}"
        )

    # ------------------------------------------------------------------
    # 2. GCS storage path residency
    # ------------------------------------------------------------------

    def test_gcs_storage_paths_are_apac_region(self) -> None:
        """All GCS storage paths configured via env vars must be in asia-southeast1."""
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
            _assert_apac_region(value, var)

    def test_google_cloud_location_is_asia_southeast1(self) -> None:
        """GOOGLE_CLOUD_LOCATION must be asia-southeast1 for APAC_MAS deployments."""
        location = os.environ.get("GOOGLE_CLOUD_LOCATION", "")
        if not location:
            pytest.skip(
                "GOOGLE_CLOUD_LOCATION not set — skipping location residency check"
            )
        assert location == _REQUIRED_APAC_REGION, (
            f"GOOGLE_CLOUD_LOCATION must be '{_REQUIRED_APAC_REGION}' for APAC_MAS, "
            f"got {location!r}"
        )

    # ------------------------------------------------------------------
    # 3. COLD_TIER_BUCKET residency
    # ------------------------------------------------------------------

    def test_cold_tier_bucket_does_not_reference_non_apac_region(self) -> None:
        """COLD_TIER_BUCKET, when set, must not reference a non-APAC region."""
        bucket = os.environ.get("COLD_TIER_BUCKET", "")
        if not bucket:
            pytest.skip("COLD_TIER_BUCKET not set — skipping residency check")
        for bad in _NON_APAC_REGIONS:
            assert bad not in bucket, (
                f"COLD_TIER_BUCKET must not reference non-APAC region '{bad}', "
                f"got: {bucket!r}"
            )

    def test_cold_tier_bucket_references_apac_region_when_explicit(self) -> None:
        """COLD_TIER_BUCKET, when it contains a region string, must be asia-southeast1."""
        bucket = os.environ.get("COLD_TIER_BUCKET", "")
        if not bucket:
            pytest.skip("COLD_TIER_BUCKET not set — skipping residency check")
        # Only assert the positive APAC region if the bucket name embeds a region
        # (e.g. "cage-apac-mas-cold-asia-southeast1"). Generic names like
        # "cage-cold-tier" are acceptable without a region substring.
        if any(
            region_hint in bucket
            for region_hint in ("asia-", "europe-", "us-", "australia-")
        ):
            _assert_apac_region(bucket, "COLD_TIER_BUCKET")

    # ------------------------------------------------------------------
    # 4. OSCAL_S3_BUCKET residency
    # ------------------------------------------------------------------

    def test_oscal_s3_bucket_does_not_reference_non_apac_region(self) -> None:
        """OSCAL_S3_BUCKET, when set, must not reference a non-APAC region."""
        bucket = os.environ.get("OSCAL_S3_BUCKET", "")
        if not bucket:
            pytest.skip("OSCAL_S3_BUCKET not set — skipping residency check")
        for bad in _NON_APAC_REGIONS:
            assert bad not in bucket, (
                f"OSCAL_S3_BUCKET must not reference non-APAC region '{bad}', "
                f"got: {bucket!r}"
            )

    def test_oscal_s3_bucket_references_apac_region_when_explicit(self) -> None:
        """OSCAL_S3_BUCKET, when it contains a region string, must be asia-southeast1."""
        bucket = os.environ.get("OSCAL_S3_BUCKET", "")
        if not bucket:
            pytest.skip("OSCAL_S3_BUCKET not set — skipping residency check")
        if any(
            region_hint in bucket
            for region_hint in ("asia-", "europe-", "us-", "australia-")
        ):
            _assert_apac_region(bucket, "OSCAL_S3_BUCKET")

    # ------------------------------------------------------------------
    # 5. Terraform tfvars residency (apac-dev / apac-prod)
    # ------------------------------------------------------------------

    def test_apac_dev_tfvars_references_asia_southeast1(self) -> None:
        """infra/targets/gcp-gke/apac-dev.tfvars must reference asia-southeast1."""
        import pathlib

        tfvars_path = pathlib.Path("infra/targets/gcp-gke/apac-dev.tfvars")
        if not tfvars_path.exists():
            pytest.skip(f"{tfvars_path} not found — skipping tfvars residency check")
        content = tfvars_path.read_text()
        assert _REQUIRED_APAC_REGION in content, (
            f"apac-dev.tfvars must reference '{_REQUIRED_APAC_REGION}' for APAC_MAS posture"
        )

    def test_apac_prod_tfvars_references_asia_southeast1(self) -> None:
        """infra/targets/gcp-gke/apac-prod.tfvars must reference asia-southeast1."""
        import pathlib

        tfvars_path = pathlib.Path("infra/targets/gcp-gke/apac-prod.tfvars")
        if not tfvars_path.exists():
            pytest.skip(f"{tfvars_path} not found — skipping tfvars residency check")
        content = tfvars_path.read_text()
        assert _REQUIRED_APAC_REGION in content, (
            f"apac-prod.tfvars must reference '{_REQUIRED_APAC_REGION}' for APAC_MAS posture"
        )

    # ------------------------------------------------------------------
    # 6. APAC_MAS baseline config residency
    # ------------------------------------------------------------------

    def test_apac_mas_baseline_config_is_loadable(self) -> None:
        """config/compliance/APAC_MAS_BASELINE.json must exist and be valid JSON."""
        import json
        import pathlib

        baseline_path = pathlib.Path("config/compliance/APAC_MAS_BASELINE.json")
        if not baseline_path.exists():
            pytest.skip(
                f"{baseline_path} not found — skipping baseline loadability check"
            )
        content = baseline_path.read_text()
        # Must be valid JSON
        data = json.loads(content)
        assert isinstance(data, dict), (
            "APAC_MAS_BASELINE.json must be a JSON object at the top level"
        )

    def test_apac_mas_baseline_config_references_asia_southeast1(self) -> None:
        """config/compliance/APAC_MAS_BASELINE.json must reference asia-southeast1."""
        import pathlib

        baseline_path = pathlib.Path("config/compliance/APAC_MAS_BASELINE.json")
        if not baseline_path.exists():
            pytest.skip(
                f"{baseline_path} not found — skipping baseline residency check"
            )
        content = baseline_path.read_text()
        assert _REQUIRED_APAC_REGION in content, (
            f"APAC_MAS_BASELINE.json must reference '{_REQUIRED_APAC_REGION}'"
        )

    # ------------------------------------------------------------------
    # 7. MAS TRM §4.2 data residency reference in shared modules
    # ------------------------------------------------------------------

    def test_mas_trm_data_residency_referenced_in_compliance_bridge(self) -> None:
        """MAS TRM §4.2 data residency: asia-southeast1 must appear in compliance_bridge."""
        import pathlib

        bridge_dir = pathlib.Path("src/compliance_bridge")
        if not bridge_dir.exists():
            pytest.skip(
                "src/compliance_bridge/ not found — skipping MAS TRM §4.2 reference check"
            )
        found = False
        for py_file in bridge_dir.rglob("*.py"):
            try:
                if _REQUIRED_APAC_REGION in py_file.read_text():
                    found = True
                    break
            except (OSError, UnicodeDecodeError):
                continue
        if not found:
            # Also check gateway/governance as a fallback
            governance_dir = pathlib.Path("src/gateway/governance")
            if governance_dir.exists():
                for py_file in governance_dir.rglob("*.py"):
                    try:
                        if _REQUIRED_APAC_REGION in py_file.read_text():
                            found = True
                            break
                    except (OSError, UnicodeDecodeError):
                        continue
        assert found, (
            f"MAS TRM §4.2 requires '{_REQUIRED_APAC_REGION}' to be referenced in "
            "src/compliance_bridge/ or src/gateway/governance/ to enforce APAC data residency"
        )

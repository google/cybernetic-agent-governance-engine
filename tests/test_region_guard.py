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
Sprint 3.1: Region-Guarded Evidence Storage Tests

Verifies that get_region_bucket() enforces jurisdictional data residency
(GDPR Article 25, MAS TRM 4.3) with fail-closed semantics.
"""

import os

import pytest

from src.compliance_bridge.storage import get_region_bucket


class TestRegionGuardedStorage:
    """Test region-guarded evidence storage dispatcher."""

    def test_region_bucket_dispatcher_us_fed(self, monkeypatch):
        """Verify get_region_bucket() returns US_FED bucket when configured."""
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "US_FED")
        monkeypatch.setenv("EVIDENCE_STREAM_GCS_BUCKET_US", "us-cage-evidence-prod")

        bucket = get_region_bucket()

        assert bucket == "us-cage-evidence-prod"
        assert bucket.startswith("us-")

    def test_region_bucket_dispatcher_eu_ecb(self, monkeypatch):
        """Verify get_region_bucket() returns EU_ECB bucket when configured."""
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "EU_ECB")
        monkeypatch.setenv("EVIDENCE_STREAM_GCS_BUCKET_EU", "eu-cage-evidence-prod")

        bucket = get_region_bucket()

        assert bucket == "eu-cage-evidence-prod"
        assert bucket.startswith("eu-")

    def test_region_bucket_dispatcher_apac_mas(self, monkeypatch):
        """Verify get_region_bucket() returns APAC_MAS bucket when configured."""
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "APAC_MAS")
        monkeypatch.setenv("EVIDENCE_STREAM_GCS_BUCKET_APAC", "apac-cage-evidence-prod")

        bucket = get_region_bucket()

        assert bucket == "apac-cage-evidence-prod"
        assert bucket.startswith("apac-")

    def test_region_bucket_dispatcher_local(self, monkeypatch):
        """Verify get_region_bucket() returns LOCAL bucket for development."""
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "LOCAL")
        monkeypatch.setenv("EVIDENCE_STREAM_GCS_BUCKET", "cage-evidence-local")

        bucket = get_region_bucket()

        assert bucket == "cage-evidence-local"

    def test_us_fed_bucket_prefix_enforcement(self, monkeypatch):
        """Verify US_FED bucket must start with 'us-' prefix."""
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "US_FED")
        monkeypatch.setenv(
            "EVIDENCE_STREAM_GCS_BUCKET_US", "cage-evidence-us"
        )  # Wrong prefix

        with pytest.raises(ValueError, match="US_FED bucket must start with 'us-'"):
            get_region_bucket()

    def test_eu_ecb_bucket_prefix_enforcement(self, monkeypatch):
        """Verify EU_ECB bucket must start with 'eu-' prefix."""
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "EU_ECB")
        monkeypatch.setenv(
            "EVIDENCE_STREAM_GCS_BUCKET_EU", "cage-evidence-eu"
        )  # Wrong prefix

        with pytest.raises(ValueError, match="EU_ECB bucket must start with 'eu-'"):
            get_region_bucket()

    def test_apac_mas_bucket_prefix_enforcement(self, monkeypatch):
        """Verify APAC_MAS bucket must start with 'apac-' prefix."""
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "APAC_MAS")
        monkeypatch.setenv(
            "EVIDENCE_STREAM_GCS_BUCKET_APAC", "cage-evidence-apac"
        )  # Wrong prefix

        with pytest.raises(ValueError, match="APAC_MAS bucket must start with 'apac-'"):
            get_region_bucket()

    def test_no_fallback_tolerance_us_fed(self, monkeypatch):
        """Verify ValueError when US_FED region configured but bucket not set."""
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "US_FED")
        monkeypatch.delenv("EVIDENCE_STREAM_GCS_BUCKET_US", raising=False)

        with pytest.raises(
            ValueError, match="No GCS bucket configured for region US_FED"
        ):
            get_region_bucket()

    def test_no_fallback_tolerance_eu_ecb(self, monkeypatch):
        """Verify ValueError when EU_ECB region configured but bucket not set."""
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "EU_ECB")
        monkeypatch.delenv("EVIDENCE_STREAM_GCS_BUCKET_EU", raising=False)

        with pytest.raises(
            ValueError, match="No GCS bucket configured for region EU_ECB"
        ):
            get_region_bucket()

    def test_no_fallback_tolerance_apac_mas(self, monkeypatch):
        """Verify ValueError when APAC_MAS region configured but bucket not set."""
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "APAC_MAS")
        monkeypatch.delenv("EVIDENCE_STREAM_GCS_BUCKET_APAC", raising=False)

        with pytest.raises(
            ValueError, match="No GCS bucket configured for region APAC_MAS"
        ):
            get_region_bucket()

    def test_local_default_bucket(self, monkeypatch):
        """Verify LOCAL region has default bucket for development."""
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "LOCAL")
        monkeypatch.delenv("EVIDENCE_STREAM_GCS_BUCKET", raising=False)

        bucket = get_region_bucket()

        assert bucket == "cage-evidence-local"  # Default from storage.py

    def test_gdpr_compliance_eu_bucket_isolation(self, monkeypatch):
        """
        Verify EU bucket cannot be accidentally used from US region.

        Regulatory requirement: GDPR Article 25 (data protection by design)
        """
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "US_FED")
        monkeypatch.setenv("EVIDENCE_STREAM_GCS_BUCKET_US", "us-cage-evidence-prod")
        # Even if EU bucket is configured, US region should not access it
        monkeypatch.setenv("EVIDENCE_STREAM_GCS_BUCKET_EU", "eu-cage-evidence-prod")

        bucket = get_region_bucket()

        assert bucket == "us-cage-evidence-prod"
        assert not bucket.startswith("eu-")

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
# Regression coverage binding: POAM-2026-220

"""Unit tests for locked evidence cold-store data residency (residency.py).

Verifies:
- Every enforcing posture (``production``, ``staging``, ``local``, unknown
  ``CAGE_ENV``) enforces geographic residency; only permissive postures
  (``dev``, ``test``, ``ci``) skip location validation.
- Bucket residency is verified exclusively against the bucket's cloud location
  (``location`` argument or ``EVIDENCE_COLD_STORE_LOCATION``). Bucket-name
  prefixes and caller-pod ``GOOGLE_CLOUD_LOCATION`` / ``AWS_REGION`` variables
  never satisfy residency.
- ``residency.json`` defines rules for ``SUPPORTED_REGIONS`` only (no ``LOCAL``
  rule, no ``allowed_prefixes`` / ``allow_prefixes`` / ``default_bucket``).
- The ``POAM-2026-220`` production compliance-bridge environment
  (``<project>-evidence-worm-prod`` + ``EVIDENCE_COLD_STORE_LOCATION``) resolves
  cleanly in both ``prod`` and ``staging``, and fails closed when the location
  is omitted or out-of-region, including through ``get_cold_store(bucket=...)``.
"""

from __future__ import annotations

import pytest

from src.gateway.governance.env_posture import SUPPORTED_REGIONS, DeploymentRegionError
from src.gateway.governance.evidence.factory import get_cold_store
from src.gateway.governance.evidence.residency import (
    COLD_STORE_LOCATION_ENV_VAR,
    MissingBucketConfigError,
    ResidencyViolationError,
    clear_residency_cache,
    load_residency_config,
    resolve_cold_store_bucket,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure clean residency-related environment variables for each test."""
    clear_residency_cache()
    for var in (
        "CAGE_DEPLOYMENT_REGION",
        "EVIDENCE_COLD_STORE",
        "EVIDENCE_COLD_STORE_BUCKET",
        "EVIDENCE_COLD_STORE_BUCKET_US",
        "EVIDENCE_COLD_STORE_BUCKET_EU",
        "EVIDENCE_COLD_STORE_BUCKET_APAC",
        COLD_STORE_LOCATION_ENV_VAR,
        "GOOGLE_CLOUD_LOCATION",
        "AWS_REGION",
    ):
        monkeypatch.delenv(var, raising=False)


def test_residency_config_matches_supported_regions_without_prefixes_or_local() -> None:
    """residency.json covers SUPPORTED_REGIONS only, with no prefix or LOCAL fields."""
    cfg = load_residency_config()
    regions = cfg["regions"]
    assert set(regions) == SUPPORTED_REGIONS
    for region, rule in regions.items():
        assert rule.get("allowed_locations"), region
        for retired in ("allowed_prefixes", "allow_prefixes", "default_bucket"):
            assert retired not in rule, (region, retired)


@pytest.mark.parametrize(
    "region,env_var,location,bucket",
    [
        (
            "US_FED",
            "EVIDENCE_COLD_STORE_BUCKET_US",
            "us-central1",
            "proj-evidence-worm-prod",
        ),
        ("US_FED", "EVIDENCE_COLD_STORE_BUCKET_US", "US-EAST4", "unprefixed-us-vault"),
        (
            "EU_ECB",
            "EVIDENCE_COLD_STORE_BUCKET_EU",
            "europe-west1",
            "proj-evidence-worm-eu",
        ),
        (
            "EU_ECB",
            "EVIDENCE_COLD_STORE_BUCKET_EU",
            "EUROPE-WEST4",
            "custom-enterprise-vault",
        ),
        (
            "APAC_MAS",
            "EVIDENCE_COLD_STORE_BUCKET_APAC",
            "asia-southeast1",
            "proj-evidence-worm-apac",
        ),
        (
            "APAC_MAS",
            "EVIDENCE_COLD_STORE_BUCKET_APAC",
            "ap-southeast-1",
            "s3-apac-vault",
        ),
    ],
)
@pytest.mark.parametrize("posture", ["production", "staging", "local", "unknown-env"])
def test_enforcing_postures_accept_verified_bucket_location(
    monkeypatch: pytest.MonkeyPatch,
    posture: str,
    region: str,
    env_var: str,
    location: str,
    bucket: str,
) -> None:
    monkeypatch.setenv("CAGE_ENV", posture)
    monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", region)
    monkeypatch.setenv(env_var, bucket)
    monkeypatch.setenv(COLD_STORE_LOCATION_ENV_VAR, location)

    assert resolve_cold_store_bucket(backend_id="gcs") == bucket


@pytest.mark.parametrize(
    "posture", ["production", "staging", "local", "uat", "preprod"]
)
def test_enforcing_postures_refuse_missing_bucket_location_even_with_regional_prefix_or_pod_location(
    monkeypatch: pytest.MonkeyPatch,
    posture: str,
) -> None:
    """Neither a regional bucket-name prefix nor GOOGLE_CLOUD_LOCATION/AWS_REGION satisfies residency."""
    monkeypatch.setenv("CAGE_ENV", posture)
    monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "US_FED")
    monkeypatch.setenv("EVIDENCE_COLD_STORE_BUCKET_US", "us-prefixed-worm-bucket")
    monkeypatch.setenv("GOOGLE_CLOUD_LOCATION", "us-central1")
    monkeypatch.setenv("AWS_REGION", "us-east-1")

    with pytest.raises(ResidencyViolationError, match=COLD_STORE_LOCATION_ENV_VAR):
        resolve_cold_store_bucket(backend_id="gcs")


@pytest.mark.parametrize(
    "region,bad_location",
    [
        ("US_FED", "europe-west1"),
        ("EU_ECB", "us-central1"),
        ("APAC_MAS", "us-central1"),
    ],
)
@pytest.mark.parametrize("posture", ["production", "staging", "local"])
def test_enforcing_postures_refuse_cross_region_bucket_location(
    monkeypatch: pytest.MonkeyPatch,
    posture: str,
    region: str,
    bad_location: str,
) -> None:
    """Staging enforces residency identically to production: out-of-region buckets fail closed."""
    monkeypatch.setenv("CAGE_ENV", posture)
    monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", region)
    monkeypatch.setenv("EVIDENCE_COLD_STORE_BUCKET", "proj-evidence-worm")
    monkeypatch.setenv(COLD_STORE_LOCATION_ENV_VAR, bad_location)

    with pytest.raises(
        ResidencyViolationError, match=f"violates data residency for region '{region}'"
    ):
        resolve_cold_store_bucket(backend_id="gcs")


@pytest.mark.parametrize("posture", ["dev", "development", "test", "testing", "ci"])
def test_permissive_postures_skip_geographic_validation(
    monkeypatch: pytest.MonkeyPatch,
    posture: str,
) -> None:
    monkeypatch.setenv("CAGE_ENV", posture)
    monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "EU_ECB")
    monkeypatch.setenv("EVIDENCE_COLD_STORE_BUCKET_EU", "dev-bucket-any-name")

    assert resolve_cold_store_bucket(backend_id="gcs") == "dev-bucket-any-name"


def test_poam_2026_220_compliance_bridge_prod_and_staging_parity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression guard for POAM-2026-220: prod and staging behave identically on the bridge env."""
    for posture in ("prod", "staging"):
        monkeypatch.setenv("CAGE_ENV", posture)
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "US_FED")
        monkeypatch.setenv("EVIDENCE_COLD_STORE", "gcs")
        monkeypatch.setenv(
            "EVIDENCE_COLD_STORE_BUCKET", "sample-proj-evidence-worm-prod"
        )
        monkeypatch.delenv(COLD_STORE_LOCATION_ENV_VAR, raising=False)

        with pytest.raises(ResidencyViolationError, match=COLD_STORE_LOCATION_ENV_VAR):
            resolve_cold_store_bucket(backend_id="gcs")

        monkeypatch.setenv(COLD_STORE_LOCATION_ENV_VAR, "US-CENTRAL1")
        assert (
            resolve_cold_store_bucket(backend_id="gcs")
            == "sample-proj-evidence-worm-prod"
        )


def test_get_cold_store_with_explicit_bucket_still_enforces_residency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Passing bucket= to get_cold_store() must not bypass resolve_cold_store_bucket()."""
    monkeypatch.setenv("CAGE_ENV", "staging")
    monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "EU_ECB")
    monkeypatch.setenv(COLD_STORE_LOCATION_ENV_VAR, "us-central1")

    with pytest.raises(
        ResidencyViolationError, match="violates data residency for region 'EU_ECB'"
    ):
        get_cold_store(backend="gcs", bucket="eu-named-but-us-located-bucket")


def test_missing_bucket_raises_missing_bucket_config_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CAGE_ENV", "test")
    monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "EU_ECB")

    with pytest.raises(
        MissingBucketConfigError, match="Missing required bucket configuration"
    ):
        resolve_cold_store_bucket()


def test_local_and_unknown_regions_are_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "LOCAL")
    with pytest.raises(DeploymentRegionError, match="not a supported region"):
        resolve_cold_store_bucket()

    with pytest.raises(
        ResidencyViolationError, match="Unknown deployment region 'LOCAL'"
    ):
        resolve_cold_store_bucket(region="LOCAL", bucket_override="b")

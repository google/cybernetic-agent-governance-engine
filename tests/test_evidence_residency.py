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
tests/test_evidence_residency.py — Unit tests for declarative evidence residency resolver.

Tests:
    - Regional bucket prefix resolution (US_FED, EU_ECB, APAC_MAS, LOCAL)
    - Fail-closed behavior on missing configuration
    - Cross-region residency violation detection
    - Location matching and prefix override validation
    - Unknown region rejection
"""

from __future__ import annotations

import os

import pytest

from src.gateway.governance.evidence.residency import (
    MissingBucketConfigError,
    ResidencyViolationError,
    clear_residency_cache,
    resolve_cold_store_bucket,
)

pytestmark = [pytest.mark.local, pytest.mark.unit]


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch):
    """Ensure clean residency-related environment variables for each test."""
    clear_residency_cache()
    for var in [
        "CAGE_DEPLOYMENT_REGION",
        "EVIDENCE_COLD_STORE_BUCKET",
        "EVIDENCE_COLD_STORE_BUCKET_US",
        "EVIDENCE_COLD_STORE_BUCKET_EU",
        "EVIDENCE_COLD_STORE_BUCKET_APAC",
        "EVIDENCE_COLD_STORE_BUCKET_LOCAL",
        "GOOGLE_CLOUD_LOCATION",
        "AWS_REGION",
    ]:
        monkeypatch.delenv(var, raising=False)


@pytest.mark.parametrize(
    "region,env_var,valid_bucket",
    [
        ("US_FED", "EVIDENCE_COLD_STORE_BUCKET_US", "us-cold-store-archive"),
        ("US_FED", "EVIDENCE_COLD_STORE_BUCKET_US", "cage-us-fed-evidence"),
        ("EU_ECB", "EVIDENCE_COLD_STORE_BUCKET_EU", "eu-cold-store-archive"),
        ("EU_ECB", "EVIDENCE_COLD_STORE_BUCKET_EU", "cage-eu-compliance-vault"),
        ("APAC_MAS", "EVIDENCE_COLD_STORE_BUCKET_APAC", "apac-cold-store-archive"),
        ("APAC_MAS", "EVIDENCE_COLD_STORE_BUCKET_APAC", "cage-apac-evidence-stream"),
        ("LOCAL", "EVIDENCE_COLD_STORE_BUCKET_LOCAL", "dev-local-evidence"),
        ("LOCAL", "EVIDENCE_COLD_STORE_BUCKET_LOCAL", "local-evidence-bucket"),
    ],
)
def test_resolve_cold_store_bucket_valid_prefixes(
    monkeypatch: pytest.MonkeyPatch,
    region: str,
    env_var: str,
    valid_bucket: str,
):
    """Assert valid regional prefixes resolve successfully."""
    monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", region)
    monkeypatch.setenv(env_var, valid_bucket)

    bucket = resolve_cold_store_bucket()
    assert bucket == valid_bucket


def test_resolve_cold_store_bucket_local_default():
    """Assert LOCAL region falls back to default_bucket when no env vars are set."""
    bucket = resolve_cold_store_bucket(region="LOCAL")
    assert bucket == "local-evidence-bucket"


def test_resolve_cold_store_bucket_missing_env_raises(monkeypatch: pytest.MonkeyPatch):
    """Assert missing bucket configuration fails closed with MissingBucketConfigError."""
    monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "EU_ECB")
    with pytest.raises(
        MissingBucketConfigError, match="Missing required bucket configuration"
    ):
        resolve_cold_store_bucket()


def test_resolve_cold_store_bucket_cross_region_violation_raises(
    monkeypatch: pytest.MonkeyPatch,
):
    """Assert US bucket configured in EU_ECB deployment fails closed."""
    monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "EU_ECB")
    monkeypatch.setenv("EVIDENCE_COLD_STORE_BUCKET_EU", "us-central-evidence")

    with pytest.raises(
        ResidencyViolationError, match="violates data residency for region 'EU_ECB'"
    ):
        resolve_cold_store_bucket()


def test_resolve_cold_store_bucket_location_mismatch_raises(
    monkeypatch: pytest.MonkeyPatch,
):
    """Assert mismatched GOOGLE_CLOUD_LOCATION fails closed even if bucket prefix is valid."""
    monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "EU_ECB")
    monkeypatch.setenv("EVIDENCE_COLD_STORE_BUCKET_EU", "eu-evidence-bucket")
    monkeypatch.setenv("GOOGLE_CLOUD_LOCATION", "us-central1")

    with pytest.raises(
        ResidencyViolationError, match="violates data residency for region 'EU_ECB'"
    ):
        resolve_cold_store_bucket()


def test_resolve_cold_store_bucket_location_exception_for_unprefixed_bucket(
    monkeypatch: pytest.MonkeyPatch,
):
    """Assert unprefixed bucket name passes if verified against an allowed cloud location."""
    monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "EU_ECB")
    monkeypatch.setenv("EVIDENCE_COLD_STORE_BUCKET_EU", "custom-enterprise-vault")
    monkeypatch.setenv("GOOGLE_CLOUD_LOCATION", "europe-west1")

    bucket = resolve_cold_store_bucket()
    assert bucket == "custom-enterprise-vault"


def test_resolve_cold_store_bucket_unknown_region_raises():
    """Assert unknown region raises ResidencyViolationError."""
    with pytest.raises(
        ResidencyViolationError,
        match="Unknown deployment region 'UNKNOWN_JURISDICTION'",
    ):
        resolve_cold_store_bucket(region="UNKNOWN_JURISDICTION")


def test_resolve_cold_store_bucket_null_backend():
    """Assert null backend allows null placeholder in local environment."""
    bucket = resolve_cold_store_bucket(
        region="LOCAL", backend_id="null", bucket_override="null"
    )
    assert bucket == "null"

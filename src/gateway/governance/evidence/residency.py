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
residency.py — Declarative Evidence Storage Residency Resolver

Provides backend-agnostic, table-driven data residency validation for evidence
cold storage across CAGE compliance jurisdictions (US_FED, EU_ECB, APAC_MAS, LOCAL).

Enforces:
    - GDPR Art. 44 (EU sovereign data boundaries)
    - MAS TRM §4.2 (Singapore sovereign data boundaries)
    - NIST SP 800-53 / FedRAMP (US sovereign data boundaries)

Task Spec: Wave 1, W1.4 (plans/vendor_decoupling_implementation_plan.md)
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Default config path relative to repo root
_DEFAULT_CONFIG_PATH = (
    Path(__file__).parents[4] / "config" / "compliance" / "residency.json"
)


class ResidencyViolationError(RuntimeError):
    """Raised when cold store bucket configuration violates jurisdictional data residency."""

    pass


class MissingBucketConfigError(ResidencyViolationError):
    """Raised when required bucket environment variable is unset."""

    pass


@dataclass(frozen=True)
class RegionalResidencyRule:
    """Residency constraints for a specific deployment region."""

    region: str
    jurisdiction: str
    env_var: str
    allowed_prefixes: tuple[str, ...]
    allowed_locations: tuple[str, ...]
    default_bucket: str | None = None
    allow_prefixes: bool = True


_CONFIG_CACHE: dict[str, Any] | None = None


def load_residency_config(config_path: str | Path | None = None) -> dict[str, Any]:
    """Load declarative residency rules from config JSON.

    Args:
        config_path: Optional path to residency.json. If None, uses default repo location.

    Returns:
        Parsed dictionary of regional residency rules.
    """
    global _CONFIG_CACHE
    if _CONFIG_CACHE is not None and config_path is None:
        return _CONFIG_CACHE

    target_path = Path(config_path) if config_path else _DEFAULT_CONFIG_PATH
    if not target_path.exists():
        raise FileNotFoundError(
            f"Residency configuration file not found at: {target_path}"
        )

    with open(target_path, encoding="utf-8") as f:
        data = json.load(f)

    if config_path is None:
        _CONFIG_CACHE = data
    return data


def clear_residency_cache() -> None:
    """Clear cached configuration for test isolation."""
    global _CONFIG_CACHE
    _CONFIG_CACHE = None


def get_regional_rule(
    region: str,
    config_path: str | Path | None = None,
) -> RegionalResidencyRule:
    """Fetch structured residency rule for a given region."""
    config = load_residency_config(config_path)
    regions_map = config.get("regions", {})

    if region not in regions_map:
        raise ResidencyViolationError(
            f"Unknown deployment region '{region}'. Must be one of: {list(regions_map.keys())}"
        )

    rule_data = regions_map[region]
    return RegionalResidencyRule(
        region=region,
        jurisdiction=rule_data.get("jurisdiction", ""),
        env_var=rule_data.get("env_var", ""),
        allowed_prefixes=tuple(rule_data.get("allowed_prefixes", [])),
        allowed_locations=tuple(rule_data.get("allowed_locations", [])),
        default_bucket=rule_data.get("default_bucket"),
        allow_prefixes=rule_data.get("allow_prefixes", True),
    )


def resolve_cold_store_bucket(
    region: str | None = None,
    location: str | None = None,
    backend_id: str | None = None,
    bucket_override: str | None = None,
    config_path: str | Path | None = None,
) -> str:
    """Resolve and validate the cold storage bucket for the current deployment region.

    Evaluation Order:
        1. Resolve region from `region` arg or `CAGE_DEPLOYMENT_REGION` env var (default: "LOCAL").
        2. Resolve candidate bucket name:
           a. `bucket_override` (if provided)
           b. Regional env var (e.g. `EVIDENCE_COLD_STORE_BUCKET_EU`)
           c. Global fallback `EVIDENCE_COLD_STORE_BUCKET`
           d. For `LOCAL`, default to `default_bucket` from config if unset.
        3. Validate candidate bucket against allowed prefixes and locations.
        4. Fail closed on any violation or missing configuration.

    Args:
        region: Deployment region (e.g. "US_FED", "EU_ECB", "APAC_MAS", "LOCAL").
        location: Cloud location/zone (e.g. "europe-west1", "asia-southeast1", "us-central1").
        backend_id: Storage backend identifier ("gcs", "s3", "null").
        bucket_override: Explicit bucket name to validate.
        config_path: Custom path to residency.json.

    Returns:
        Validated bucket name string.

    Raises:
        MissingBucketConfigError: If required bucket environment variable is unset.
        ResidencyViolationError: If bucket violates jurisdictional residency rules.
    """
    active_region = (
        region or os.environ.get("CAGE_DEPLOYMENT_REGION") or "LOCAL"
    ).strip()
    rule = get_regional_rule(active_region, config_path=config_path)

    # Resolve candidate bucket
    candidate = bucket_override
    if not candidate:
        # Check specific regional variable first
        candidate = os.environ.get(rule.env_var, "").strip()
        if not candidate:
            # Check universal cold store bucket variable
            candidate = os.environ.get("EVIDENCE_COLD_STORE_BUCKET", "").strip()

    if not candidate:
        if active_region == "LOCAL" and rule.default_bucket:
            candidate = rule.default_bucket
        else:
            raise MissingBucketConfigError(
                f"Missing required bucket configuration for region '{active_region}'. "
                f"Set environment variable '{rule.env_var}' or 'EVIDENCE_COLD_STORE_BUCKET'."
            )

    # Null backend bypass check for local testing
    if backend_id == "null" and candidate in (
        "null",
        "null-bucket",
        "local-evidence-bucket",
    ):
        return candidate

    # Validate Location if provided
    active_location = (
        location
        or os.environ.get("GOOGLE_CLOUD_LOCATION")
        or os.environ.get("AWS_REGION")
    )
    if active_location:
        active_location = active_location.strip()
        if active_location not in rule.allowed_locations:
            raise ResidencyViolationError(
                f"Storage location '{active_location}' violates data residency for region "
                f"'{active_region}'. Allowed locations: {rule.allowed_locations}"
            )

    # Validate Bucket Name Prefixes
    has_valid_prefix = any(
        candidate.startswith(prefix) for prefix in rule.allowed_prefixes
    )
    if not has_valid_prefix:
        # If prefix validation fails, verify whether explicit location match grants exception
        if active_location and active_location in rule.allowed_locations:
            logger.warning(
                "Bucket '%s' does not match regional prefixes %s, but location '%s' satisfies residency.",
                candidate,
                rule.allowed_prefixes,
                active_location,
            )
        else:
            raise ResidencyViolationError(
                f"Bucket '{candidate}' violates data residency for region '{active_region}'. "
                f"Bucket name must start with one of {rule.allowed_prefixes} or reference a "
                f"verified location in {rule.allowed_locations}."
            )

    return candidate

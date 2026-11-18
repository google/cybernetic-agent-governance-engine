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
cold storage across CAGE compliance jurisdictions (US_FED, EU_ECB, APAC_MAS).

Enforces:
    - GDPR Art. 44 (EU sovereign data boundaries, e.g. europe-west1)
    - MAS TRM §4.2 (Singapore sovereign data boundaries, e.g. asia-southeast1)
    - NIST SP 800-53 / FedRAMP (US sovereign data boundaries, e.g. us-central1)
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.gateway.governance.env_posture import is_enforcing, resolve_deployment_region

logger = logging.getLogger(__name__)

# Default config path relative to repo root
_DEFAULT_CONFIG_PATH = (
    Path(__file__).parents[4] / "config" / "compliance" / "residency.json"
)

#: Carries the WORM cold-store bucket's immutable cloud location (injected by
#: Terraform from ``module.worm_bucket.bucket_location``, never inferred from
#: the caller pod's ``GOOGLE_CLOUD_LOCATION`` or ``AWS_REGION`` or a bucket-name
#: prefix).
COLD_STORE_LOCATION_ENV_VAR = "EVIDENCE_COLD_STORE_LOCATION"


class ResidencyViolationError(RuntimeError):
    """Raised when cold store bucket configuration violates jurisdictional data residency."""


class MissingBucketConfigError(ResidencyViolationError):
    """Raised when required bucket environment variable is unset."""


@dataclass(frozen=True)
class RegionalResidencyRule:
    """Residency constraints for a specific deployment region."""

    region: str
    jurisdiction: str
    env_var: str
    allowed_locations: tuple[str, ...]


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
        allowed_locations=tuple(
            str(loc).strip().lower() for loc in rule_data.get("allowed_locations", [])
        ),
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
        1. Resolve region from the ``region`` arg, else ``resolve_deployment_region()``.
        2. Resolve candidate bucket name:
           a. ``bucket_override`` (if provided)
           b. Regional env var (e.g. ``EVIDENCE_COLD_STORE_BUCKET_EU``)
           c. Global fallback ``EVIDENCE_COLD_STORE_BUCKET``
        3. In permissive postures (``dev``, ``test``, ``ci``), skip geographic
           location validation and return the non-empty bucket name.
        4. In every enforcing posture (``production``, ``staging``, ``local``,
           or an unknown ``CAGE_ENV``), require the bucket's cloud location
           (``location`` arg or ``EVIDENCE_COLD_STORE_LOCATION``, lowercased)
           to belong to ``rule.allowed_locations``. Neither bucket-name
           prefixes nor the caller pod's ``GOOGLE_CLOUD_LOCATION`` /
           ``AWS_REGION`` satisfy residency.

    Args:
        region: Deployment region ("US_FED", "EU_ECB", or "APAC_MAS").
        location: Bucket cloud location (e.g. "europe-west1", "asia-southeast1", "us-central1").
        backend_id: Storage backend identifier ("gcs", "s3", "null").
        bucket_override: Explicit bucket name to validate.
        config_path: Custom path to residency.json.

    Returns:
        Validated bucket name string.

    Raises:
        MissingBucketConfigError: If required bucket environment variable is unset.
        ResidencyViolationError: If bucket location is missing or violates residency rules.
    """
    _ = backend_id
    active_region = (region or resolve_deployment_region()).strip()
    rule = get_regional_rule(active_region, config_path=config_path)

    candidate = (bucket_override or "").strip()
    if not candidate:
        candidate = os.environ.get(rule.env_var, "").strip()
    if not candidate:
        candidate = os.environ.get("EVIDENCE_COLD_STORE_BUCKET", "").strip()
    if not candidate:
        raise MissingBucketConfigError(
            f"Missing required bucket configuration for region '{active_region}'. "
            f"Set environment variable '{rule.env_var}' or 'EVIDENCE_COLD_STORE_BUCKET'."
        )

    if not is_enforcing():
        logger.info(
            "Geographic residency checks skipped in permissive posture. Region: %s, Bucket: %s",
            active_region,
            candidate,
        )
        return candidate

    raw_location = (
        location
        if location is not None
        else os.environ.get(COLD_STORE_LOCATION_ENV_VAR, "")
    )
    active_location = raw_location.strip().lower()
    if not active_location:
        raise ResidencyViolationError(
            f"Bucket '{candidate}' cannot be verified for region '{active_region}': "
            f"an enforcing posture requires {COLD_STORE_LOCATION_ENV_VAR} "
            f"(the bucket's immutable cloud location) to be set to one of "
            f"{rule.allowed_locations}."
        )
    if active_location not in rule.allowed_locations:
        raise ResidencyViolationError(
            f"Storage location '{active_location}' for bucket '{candidate}' violates "
            f"data residency for region '{active_region}'. Allowed locations: "
            f"{rule.allowed_locations}"
        )

    return candidate

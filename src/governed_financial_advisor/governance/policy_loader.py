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
PolicyLoader — fetches STAMP/STPA hazard YAML specifications from storage.

Uses the storage abstraction layer (``get_storage_backend()``) so that any
configured backend (GCS, S3, local) can serve policy files — no direct GCS SDK
dependency here.
"""

import logging
from typing import Any, Dict, List

import yaml
from src.governed_financial_advisor.infrastructure.storage import get_storage_backend

logger = logging.getLogger("governance.policy_loader")

# ---------------------------------------------------------------------------
# H-12: Schema validation for YAML policy files
# ---------------------------------------------------------------------------

# Required top-level keys for a valid STAMP hazard policy file.
# Each hazard entry must also contain these keys.
REQUIRED_POLICY_KEYS: frozenset[str] = frozenset({"hazards"})
REQUIRED_HAZARD_KEYS: frozenset[str] = frozenset({"id", "description"})


class PolicySchemaError(ValueError):
    """Raised when a downloaded policy YAML does not conform to the expected schema.

    Prevents malformed or tampered policy files from silently altering governance
    behaviour (H-12).
    """


def _validate_policy_schema(data: Any, blob_name: str) -> None:
    """Validate *data* against the STAMP hazard policy schema.

    Args:
        data:      Parsed YAML object (expected to be a dict).
        blob_name: Source path — used in error messages only.

    Raises:
        PolicySchemaError: If the top-level structure or any hazard entry is invalid.
    """
    if not isinstance(data, dict):
        raise PolicySchemaError(
            f"Policy file {blob_name!r} must be a YAML mapping at the top level, "
            f"got {type(data).__name__}"
        )

    missing_keys = REQUIRED_POLICY_KEYS - data.keys()
    if missing_keys:
        raise PolicySchemaError(
            f"Policy file {blob_name!r} is missing required top-level keys: "
            f"{sorted(missing_keys)}"
        )

    hazards = data.get("hazards", [])
    if not isinstance(hazards, list):
        raise PolicySchemaError(
            f"Policy file {blob_name!r}: 'hazards' must be a list, "
            f"got {type(hazards).__name__}"
        )

    for i, hazard in enumerate(hazards):
        if not isinstance(hazard, dict):
            raise PolicySchemaError(
                f"Policy file {blob_name!r}: hazard[{i}] must be a mapping, "
                f"got {type(hazard).__name__}"
            )
        missing_hazard_keys = REQUIRED_HAZARD_KEYS - hazard.keys()
        if missing_hazard_keys:
            raise PolicySchemaError(
                f"Policy file {blob_name!r}: hazard[{i}] is missing required keys: "
                f"{sorted(missing_hazard_keys)}"
            )

    logger.debug(
        "policy_loader: schema validation passed for %s (%d hazards)",
        blob_name, len(hazards),
    )


class PolicyLoader:
    """Loads STAMP hazard specifications via the configured storage backend."""

    def __init__(self, bucket_name: str) -> None:
        self.bucket_name = bucket_name
        # get_storage_backend honours STORAGE_BACKEND env var; it may raise
        # RuntimeError / ImportError if the required SDK is unavailable.
        self._backend = get_storage_backend(bucket_name=bucket_name)

    def load_stamp_hazards(self, blob_name: str) -> List[Any]:
        """Download and parse a STAMP hazard YAML from storage.

        Validates the parsed YAML against the STAMP hazard schema before
        returning (H-12).  Raises ``PolicySchemaError`` if the file does not
        conform — callers must handle this to prevent silent governance bypass.

        Args:
            blob_name: Path to the YAML file within the bucket / prefix root.

        Returns:
            List of hazard dicts parsed from the YAML ``hazards`` key.

        Raises:
            PolicySchemaError: If the YAML structure is invalid.
        """
        raw_yaml = self._backend.read_text(blob_name)
        data = yaml.safe_load(raw_yaml)

        # H-12: Validate schema before trusting any content from remote storage.
        _validate_policy_schema(data, blob_name)

        hazards: List[Any] = data.get("hazards", [])
        logger.info(
            "Loaded %d STAMP hazards from %s/%s",
            len(hazards),
            self.bucket_name,
            blob_name,
        )
        return hazards

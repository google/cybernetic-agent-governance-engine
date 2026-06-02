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
from typing import Any, List

import yaml
from src.governed_financial_advisor.infrastructure.storage import get_storage_backend

logger = logging.getLogger("governance.policy_loader")


class PolicyLoader:
    """Loads STAMP hazard specifications via the configured storage backend."""

    def __init__(self, bucket_name: str) -> None:
        self.bucket_name = bucket_name
        # get_storage_backend honours STORAGE_BACKEND env var; it may raise
        # RuntimeError / ImportError if the required SDK is unavailable.
        self._backend = get_storage_backend(bucket_name=bucket_name)

    def load_stamp_hazards(self, blob_name: str) -> List[Any]:
        """Download and parse a STAMP hazard YAML from storage.

        Args:
            blob_name: Path to the YAML file within the bucket / prefix root.

        Returns:
            List of hazard dicts parsed from the YAML ``hazards`` key.
        """
        raw_yaml = self._backend.read_text(blob_name)
        data = yaml.safe_load(raw_yaml)

        hazards = data.get("hazards", []) if isinstance(data, dict) else []
        logger.info(
            "Loaded %d STAMP hazards from %s/%s",
            len(hazards),
            self.bucket_name,
            blob_name,
        )
        return hazards

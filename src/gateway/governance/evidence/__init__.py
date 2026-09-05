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

"""Evidence storage abstractions for vendor-decoupled compliance archival.

This package provides Protocol-based abstractions for evidence cold storage,
allowing CAGE to decouple from specific cloud vendor SDKs (GCS, S3, etc).
"""

from .cold_store import (
    ColdStoreError,
    ColdStoreHealth,
    ColdStoreReceipt,
    EvidenceColdStore,
)
from .null_cold_store import NullColdStore
from .residency import (
    MissingBucketConfigError,
    ResidencyViolationError,
    resolve_cold_store_bucket,
)

__all__ = [
    "ColdStoreError",
    "ColdStoreHealth",
    "ColdStoreReceipt",
    "EvidenceColdStore",
    "MissingBucketConfigError",
    "NullColdStore",
    "ResidencyViolationError",
    "resolve_cold_store_bucket",
]

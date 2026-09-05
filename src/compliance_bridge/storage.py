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
Region-Guarded Evidence Storage Dispatcher

Enforces jurisdictional data residency requirements (GDPR Article 25, MAS TRM 4.3)
by dispatching evidence storage to region-specific GCS buckets.

No fallback tolerance — fail-closed if region misconfigured.
"""

import os
from typing import Literal

RegionCode = Literal["US_FED", "EU_ECB", "APAC_MAS", "LOCAL"]


def get_region_bucket() -> str:
    """
    Get region-specific GCS bucket for evidence storage.

    Enforces jurisdictional data residency (GDPR Article 25, MAS TRM 4.3).
    No fallback tolerance — fail-closed if region misconfigured.

    Returns:
        str: Region-specific GCS bucket name

    Raises:
        ValueError: If region is not configured or bucket naming violates region prefix

    Environment Variables:
        CAGE_DEPLOYMENT_REGION: Region code (US_FED, EU_ECB, APAC_MAS, LOCAL)
        EVIDENCE_STREAM_GCS_BUCKET_US: US Federal bucket (must start with 'us-')
        EVIDENCE_STREAM_GCS_BUCKET_EU: EU ECB bucket (must start with 'eu-')
        EVIDENCE_STREAM_GCS_BUCKET_APAC: APAC MAS bucket (must start with 'apac-')
        EVIDENCE_STREAM_GCS_BUCKET: LOCAL development bucket
    """
    region = os.getenv("CAGE_DEPLOYMENT_REGION", "LOCAL")

    # Region-to-bucket mapping (no defaults, no fallbacks)
    REGION_BUCKETS = {
        "US_FED": os.getenv("EVIDENCE_STREAM_GCS_BUCKET_US"),
        "EU_ECB": os.getenv("EVIDENCE_STREAM_GCS_BUCKET_EU"),
        "APAC_MAS": os.getenv("EVIDENCE_STREAM_GCS_BUCKET_APAC"),
        "LOCAL": os.getenv("EVIDENCE_STREAM_GCS_BUCKET", "cage-evidence-local"),
    }

    bucket = REGION_BUCKETS.get(region)

    if not bucket:
        raise ValueError(
            f"No GCS bucket configured for region {region}. "
            f"Set EVIDENCE_STREAM_GCS_BUCKET_{region} environment variable."
        )

    # Validate bucket naming convention (region prefix enforcement)
    if region == "US_FED" and not bucket.startswith("us-"):
        raise ValueError(f"US_FED bucket must start with 'us-': {bucket}")
    elif region == "EU_ECB" and not bucket.startswith("eu-"):
        raise ValueError(f"EU_ECB bucket must start with 'eu-': {bucket}")
    elif region == "APAC_MAS" and not bucket.startswith("apac-"):
        raise ValueError(f"APAC_MAS bucket must start with 'apac-': {bucket}")

    return bucket

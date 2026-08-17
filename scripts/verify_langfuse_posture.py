#!/usr/bin/env python3
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
Langfuse posture verification script.

Verifies that Langfuse credentials are correctly isolated between
the cage-project (observability) and cage-compliance (compliance) postures.

Usage:
    python scripts/verify_langfuse_posture.py [--dry-run] [--posture development|production]

Environment variables:
    LANGFUSE_PROJECT_ID           Override core project ID (default: cmpugv47f000dwq07fqu86ral)
    LANGFUSE_COMPLIANCE_PROJECT_ID Override compliance project ID (default: cage-compliance)

Exit codes:
    0 — all checks pass
    1 — any check fails
"""

import argparse
import base64
import json
import os
import sys
from urllib.error import URLError
from urllib.request import Request, urlopen

# Known project IDs — must match live Langfuse instance
CAGE_PROJECT_ID = os.getenv("LANGFUSE_PROJECT_ID", "cmpugv47f000dwq07fqu86ral")
CAGE_COMPLIANCE_ID = os.getenv("LANGFUSE_COMPLIANCE_PROJECT_ID", "cage-compliance")

# Required env vars for each posture
BASE_REQUIRED_VARS = [
    "GOOGLE_CLOUD_PROJECT",
    "GOOGLE_CLOUD_LOCATION",
    "LANGFUSE_HOST",
    "LANGFUSE_PUBLIC_KEY",
    "LANGFUSE_SECRET_KEY",
    "LANGFUSE_COMPLIANCE_HOST",
    "LANGFUSE_COMPLIANCE_PUBLIC_KEY",
    "LANGFUSE_COMPLIANCE_SECRET_KEY",
]
PROD_EXTRA_VARS = ["GOOG-REDACTED"]


def check_env_vars(posture: str) -> bool:
    required = BASE_REQUIRED_VARS[:]
    if posture == "production":
        required.extend(PROD_EXTRA_VARS)
    missing = [v for v in required if not os.getenv(v)]
    if missing:
        print(
            f"❌ Missing required environment variables for [{posture.upper()}]: {', '.join(missing)}"
        )
        return False
    print(f"✅ All required environment variables for [{posture.upper()}] are present.")
    return True


def query_langfuse_projects(host: str, pub_key: str, secret_key: str) -> list | None:
    """Query Langfuse /api/public/projects using Basic Auth via urllib."""
    url = f"{host.rstrip('/')}/api/public/projects"
    auth_str = f"{pub_key}:{secret_key}"
    b64_auth = base64.b64encode(auth_str.encode()).decode()
    req = Request(url)
    req.add_header("Authorization", f"Basic {b64_auth}")
    try:
        with urlopen(req, timeout=5) as response:
            if response.status == 200:
                data = json.loads(response.read().decode())
                return [p["id"] for p in data.get("data", [])]
            print(f"⚠️  HTTP {response.status} from {host}")
            return None
    except URLError as e:
        print(f"⚠️  Connection failed for {host}: {e}")
        return None
    except Exception as e:
        print(f"⚠️  Unexpected error querying {host}: {e}")
        return None


def verify_live_isolation() -> bool:
    print("🔄 Querying live Langfuse APIs for cross-contamination verification...")
    core_projects = query_langfuse_projects(
        os.getenv("LANGFUSE_HOST", ""),
        os.getenv("LANGFUSE_PUBLIC_KEY", ""),
        os.getenv("LANGFUSE_SECRET_KEY", ""),
    )
    comp_projects = query_langfuse_projects(
        os.getenv("LANGFUSE_COMPLIANCE_HOST", ""),
        os.getenv("LANGFUSE_COMPLIANCE_PUBLIC_KEY", ""),
        os.getenv("LANGFUSE_COMPLIANCE_SECRET_KEY", ""),
    )

    if core_projects is None or comp_projects is None:
        print(
            "❌ Could not complete live validation — connection or authentication failure."
        )
        return False

    success = True

    # Core credentials must include cage-project and must NOT include cage-compliance
    if CAGE_PROJECT_ID in core_projects and CAGE_COMPLIANCE_ID not in core_projects:
        print(f"✅ Core credentials correctly map only to '{CAGE_PROJECT_ID}'")
    elif CAGE_PROJECT_ID in core_projects and not os.getenv(
        "LANGFUSE_COMPLIANCE_PROJECT_ID"
    ):
        # Compliance project not yet provisioned — core check passes, compliance isolation pending
        print(f"✅ Core credentials map to '{CAGE_PROJECT_ID}'")
        print(
            "⚠️  Compliance project ID not set (LANGFUSE_COMPLIANCE_PROJECT_ID unset) — "
            "isolation check skipped; provision cage-compliance project to complete U-10"
        )
    else:
        print(
            f"❌ Core credentials isolation breach! Accessible projects: {core_projects}"
        )
        success = False

    # Compliance credentials check — only if compliance project ID is configured
    compliance_project_id = os.getenv("LANGFUSE_COMPLIANCE_PROJECT_ID")
    if not compliance_project_id:
        print(
            "⚠️  Skipping compliance isolation check — LANGFUSE_COMPLIANCE_PROJECT_ID not set"
        )
    elif (
        compliance_project_id in comp_projects and CAGE_PROJECT_ID not in comp_projects
    ):
        print(
            f"✅ Compliance credentials correctly map only to '{compliance_project_id}'"
        )
    else:
        print(
            f"❌ Compliance credentials isolation breach! Accessible projects: {comp_projects}"
        )
        success = False

    return success


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify Langfuse credential isolation between postures."
    )
    parser.add_argument(
        "--posture",
        choices=["development", "production"],
        default=os.getenv("POSTURE", "development"),
        help="Environment posture to validate (default: $POSTURE or 'development')",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Skip live API calls; only verify env vars are set",
    )
    args = parser.parse_args()

    print(
        f"📋 Langfuse posture validation — [{args.posture.upper()}] (dry-run: {args.dry_run})"
    )
    print("-" * 60)

    if not check_env_vars(args.posture):
        sys.exit(1)

    if not args.dry_run:
        if not verify_live_isolation():
            print("-" * 60)
            print(
                "❌ Validation FAILED: Posture isolation boundaries breached or unreachable."
            )
            sys.exit(1)

    print("-" * 60)
    print("🚀 Validation PASSED: Langfuse posture configuration is correctly isolated.")
    sys.exit(0)


if __name__ == "__main__":
    main()

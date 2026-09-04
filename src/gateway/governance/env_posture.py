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
Deployment Posture Enum and Resolution.

Provides a centralized enum for deployment environments and resolution logic
from CAGE_ENV environment variable.

This module standardizes posture detection across the codebase, replacing
ad-hoc CAGE_ENV string comparisons with a typed enum.
"""

from __future__ import annotations

import os
from enum import Enum


class DeploymentPosture(Enum):
    """Deployment posture/environment enumeration."""

    PRODUCTION = "production"
    STAGING = "staging"
    DEV = "dev"
    TEST = "test"
    LOCAL = "local"
    CI = "ci"


def resolve_posture() -> DeploymentPosture:
    """
    Resolve the current deployment posture from environment variables.

    Checks CAGE_ENV first, then falls back to ENVIRONMENT. Defaults to
    PRODUCTION for fail-secure behavior.

    Returns:
        DeploymentPosture: The resolved deployment posture.
    """
    cage_env = (
        os.environ.get("CAGE_ENV") or os.environ.get("ENVIRONMENT", "production")
    ).lower()

    # Map common variations to canonical values
    if cage_env in ("production", "prod"):
        return DeploymentPosture.PRODUCTION
    elif cage_env in ("staging", "stage", "uat", "preprod"):
        return DeploymentPosture.STAGING
    elif cage_env in ("dev", "development"):
        return DeploymentPosture.DEV
    elif cage_env in ("test", "testing"):
        return DeploymentPosture.TEST
    elif cage_env in ("local"):
        return DeploymentPosture.LOCAL
    elif cage_env in ("ci", "continuous-integration"):
        return DeploymentPosture.CI
    else:
        # Unknown value defaults to production for fail-secure behavior
        return DeploymentPosture.PRODUCTION

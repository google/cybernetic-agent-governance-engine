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

    @property
    def enforces_controls(self) -> bool:
        """Return True when this posture enforces production safety/telemetry controls."""
        return is_enforcing(self)


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
    elif cage_env == "local":
        return DeploymentPosture.LOCAL
    elif cage_env in ("ci", "continuous-integration"):
        return DeploymentPosture.CI
    else:
        # Unknown value defaults to production for fail-secure behavior
        return DeploymentPosture.PRODUCTION


# Postures that may run with software fallbacks (HMAC signer, no KMS/Redis
# probe). Every other posture, including unknown values (which resolve to
# PRODUCTION) and LOCAL, enforces the production startup checks.
_PERMISSIVE_POSTURES = frozenset(
    {DeploymentPosture.DEV, DeploymentPosture.TEST, DeploymentPosture.CI}
)


def is_enforcing(posture: DeploymentPosture | None = None) -> bool:
    """Return whether ``posture`` (default: :func:`resolve_posture`) enforces
    production startup checks. Fail secure: only DEV, TEST and CI relax them."""
    return (posture or resolve_posture()) not in _PERMISSIVE_POSTURES


def env_flag(name: str, default: bool) -> bool:
    """Parse a boolean environment flag; unset falls back to ``default``."""
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("true", "1", "t", "y", "yes", "on")


def is_cage_defer_enabled() -> bool:
    """DEFER decision path (``CAGE_DEFER_ENABLED``, default on)."""
    return env_flag("CAGE_DEFER_ENABLED", True)


def is_cage_narrow_enabled() -> bool:
    """NARROW decision path (``CAGE_NARROW_ENABLED``). Opt-in: unset means
    disabled (fail closed), as documented in SYMBOLIC_GOVERNOR_RUNTIME.md."""
    return env_flag("CAGE_NARROW_ENABLED", False)


DOMAIN_ENV_VAR = "CAGE_DOMAIN"


def resolve_domain() -> str:
    """Return the single active domain named by ``CAGE_DOMAIN``.

    A CAGE process runs exactly one domain plugin. This is the only reader of
    ``CAGE_DOMAIN``; whether the name matches a registered plugin is checked by
    ``plugin_loader.load_domain_plugin``.

    Raises:
        RuntimeError: If the variable is unset/blank or names more than one
            domain. There is no default: guessing a domain would govern actions
            under the wrong FTRA registry and tiers.
    """
    raw = os.environ.get(DOMAIN_ENV_VAR, "").strip()
    if not raw:
        raise RuntimeError(
            f"{DOMAIN_ENV_VAR} is not set: exactly one domain (e.g. 'finance') is required"
        )
    if "," in raw or any(c.isspace() for c in raw):
        raise RuntimeError(
            f"{DOMAIN_ENV_VAR}={raw!r} names more than one domain; a CAGE process runs exactly one"
        )
    return raw.lower()

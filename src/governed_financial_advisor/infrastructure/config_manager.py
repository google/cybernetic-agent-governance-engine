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
ConfigManager — two-tier config resolution (env var → default).

Google Secret Manager (GSM) was removed in v1.0.0 in favour of Kubernetes-native
secret injection (env vars from ``Secret`` objects). There is no runtime dependency
on ``google-cloud-secret-manager``.

This module wraps ``os.getenv()`` with structured logging. For new code, prefer:
  - ``GovernanceThresholds`` (``src.gateway.governance.schemas.thresholds``) for governance thresholds
  - ``Config`` (``config.settings``) for LLM/gateway connection configuration
"""

import logging
import os
from typing import Any

logger = logging.getLogger("Infrastructure.ConfigManager")


class ConfigManager:
    """
    Cloud-agnostic Configuration Manager.

    Resolution strategy (in order):
    1. Environment variables (K8s Secrets injected as env vars, dotenv, CI).
    2. Default value supplied by the caller.

    All secrets must be injected as environment variables — either directly
    (local / Docker Compose) or via a K8s ``Secret`` mount (production).
    Google Secret Manager (GSM) is **not** used; see module docstring ADR.
    """

    def __init__(self) -> None:
        self.env = os.getenv("ENV", "development").lower()

    def get(self, key: str, default: Any = None, secret_id: str | None = None) -> Any:
        """
        Retrieve a configuration value.

        Resolution order:
        1. Environment variable ``key``.
        2. ``default``.

        Args:
            key:       The environment variable name (e.g. ``"BROKER_API_KEY"``).
            default:   Default value if not found anywhere.
            secret_id: Unused; retained for call-site compatibility only.
                       GSM has been removed — this parameter is a no-op.
        """
        val = os.getenv(key)
        if val is not None:
            return val

        if self.env == "production" and default is None:
            logger.warning(
                "Config: Key '%s' missing from environment. "
                "Ensure the secret is injected via a K8s Secret or env var.",
                key,
            )

        return default

    def get_int(self, key: str, default: int = 0) -> int:
        val = self.get(key)
        try:
            return int(val)
        except (ValueError, TypeError):
            return default

    def get_bool(self, key: str, default: bool = False) -> bool:
        val = self.get(key)
        if val is None:
            return default
        return str(val).lower() in ("true", "1", "yes", "on")


# Global Instance
config_manager = ConfigManager()

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
agent_registry_adapter.py — GEAP Agent Registry Integration
============================================================

GCP Adaptation: This module integrates with the GEAP Agent Registry API
(Vertex AI Agent Engine). It is an optional GCP-specific deployment path.
Cloud-agnostic deployments (AWS, Azure, on-premises) continue to use
``config/agent_catalog.json`` directly. Set ``CAGE_AGENT_REGISTRY_PROJECT``
to activate; leave unset for cloud-agnostic operation.

Architecture
------------
Follows the NormativeProviderDaemon pattern from ``normative_provider.py``:

  1. **Boot-time fetch:** At container startup, fetches the agent catalog from
     the GEAP Agent Registry API and pushes it to OPA as the
     ``data.agent_catalog_data`` document.

  2. **Background polling:** An ``asyncio.Task`` that polls the registry every
     ``CAGE_AGENT_REGISTRY_POLL_INTERVAL_MINUTES`` minutes.  On change, pushes
     the updated catalog to OPA.

  3. **Fail-closed fallback:** If the registry is unreachable at boot or during
     polling, falls back to ``config/agent_catalog.json``.  Never fails open.

  4. **No-op when unconfigured:** If ``CAGE_AGENT_REGISTRY_PROJECT`` is not
     set, all operations are no-ops.  Cloud-agnostic deployments are completely
     unaffected.

Environment variables (all optional — no-op if absent)
-------------------------------------------------------
  CAGE_AGENT_REGISTRY_PROJECT              — GCP project ID; if absent, adapter is a no-op
  CAGE_AGENT_REGISTRY_LOCATION             — GCP region (default: us-central1)
  CAGE_AGENT_REGISTRY_ID                   — Registry resource ID (default: cage-agent-registry)
  CAGE_AGENT_REGISTRY_POLL_INTERVAL_MINUTES — Background refresh interval (default: 15)
  CAGE_AGENT_REGISTRY_BOOT_TIMEOUT_SECONDS  — Max wait at boot (default: 10)
  OPA_URL                                  — OPA REST API base URL (default: http://localhost:8181)
  CAGE_DEPLOYMENT_REGION                   — Deployment region for audit trail logging

CAGE_DEPLOYMENT_REGION guard
-----------------------------
Any GCS write or telemetry export in this module must be gated on
``CAGE_DEPLOYMENT_REGION``.  The fetch itself is a read from the GCP API and
does not require a region guard.  The region is logged in the audit trail.

GCP API surface (verify at deployment time)
-------------------------------------------
The GEAP Agent Registry API endpoint pattern:
  GET https://aiplatform.googleapis.com/v1beta1/{registry_resource_name}/agents

This module uses ``httpx.AsyncClient`` with Application Default Credentials
(google-auth) when available.  If google-auth is not installed, it falls back
to a stub response for testability in cloud-agnostic environments.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("cage.agent_registry_adapter")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_REPO_ROOT: Path = Path(__file__).resolve().parents[4]
_STATIC_CATALOG_PATH: Path = _REPO_ROOT / "config" / "agent_catalog.json"

# ---------------------------------------------------------------------------
# OPA endpoint
# ---------------------------------------------------------------------------

_OPA_URL: str = os.environ.get("OPA_URL", "http://localhost:8181")
_OPA_AGENT_CATALOG_PATH: str = "/v1/data/agent_catalog_data"

# ---------------------------------------------------------------------------
# Data contracts
# ---------------------------------------------------------------------------


@dataclass
class RegistryCatalog:
    """Fetched agent catalog from GEAP Agent Registry.

    Attributes:
        agents: dict mapping SPIFFE ID → {display_name, allowed_tools, roles, ...}
        fetched_at: Unix timestamp when the catalog was fetched.
        registry_resource_name: full GCP resource name for OSCAL audit reference.
        error: error message if fetch failed; None on success.
    """

    agents: dict[str, Any]
    fetched_at: float
    registry_resource_name: str
    error: str | None = None

    @property
    def is_valid(self) -> bool:
        """True if the fetch succeeded and the agents dict is non-empty."""
        return self.error is None and bool(self.agents)

    def to_opa_data_document(self) -> dict[str, Any]:
        """Translate to the data.agent_catalog_data shape consumed by agent_catalog.rego.

        Returns:
            {"agents": {spiffe_id: {"allowed_tools": [...], "roles": [...], ...}}}
        """
        return {"agents": self.agents}


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


class AgentRegistryAdapter:
    """GCP Adaptation: fetches GEAP Agent Registry catalog and translates it
    into the data.agent_catalog_data shape consumed by agent_catalog.rego.

    No-op when CAGE_AGENT_REGISTRY_PROJECT is not set.
    """

    def __init__(self) -> None:
        self._project = os.environ.get("CAGE_AGENT_REGISTRY_PROJECT", "")
        self._location = os.environ.get("CAGE_AGENT_REGISTRY_LOCATION", "us-central1")
        self._registry_id = os.environ.get(
            "CAGE_AGENT_REGISTRY_ID", "cage-agent-registry"
        )
        self._poll_interval_s = (
            float(os.environ.get("CAGE_AGENT_REGISTRY_POLL_INTERVAL_MINUTES", "15"))
            * 60
        )
        self._boot_timeout_s = float(
            os.environ.get("CAGE_AGENT_REGISTRY_BOOT_TIMEOUT_SECONDS", "10")
        )
        self._last_catalog: RegistryCatalog | None = None

    @property
    def is_configured(self) -> bool:
        """True if CAGE_AGENT_REGISTRY_PROJECT is set."""
        return bool(self._project)

    @property
    def registry_resource_name(self) -> str:
        """Full GCP resource name: projects/{project}/locations/{location}/agentRegistries/{id}"""
        return (
            f"projects/{self._project}"
            f"/locations/{self._location}"
            f"/agentRegistries/{self._registry_id}"
        )

    async def fetch_catalog(self) -> RegistryCatalog:
        """Fetch agent catalog from GEAP Agent Registry API.

        GCP Adaptation: calls the Vertex AI Agent Engine REST API.
        Falls back to empty catalog on error (caller handles fallback to static file).

        The API endpoint pattern (verify at implementation time):
          GET https://aiplatform.googleapis.com/v1beta1/{registry_resource_name}/agents

        Uses httpx with Application Default Credentials (google-auth) if available,
        otherwise returns a stub response for testability.

        Returns:
            RegistryCatalog with agents dict or error set.
        """
        if not self.is_configured:
            logger.debug(
                "agent_registry_adapter: CAGE_AGENT_REGISTRY_PROJECT not set — "
                "returning empty catalog (no-op path)."
            )
            return RegistryCatalog(
                agents={},
                fetched_at=time.time(),
                registry_resource_name="",
                error="CAGE_AGENT_REGISTRY_PROJECT not configured",
            )

        deployment_region = os.environ.get("CAGE_DEPLOYMENT_REGION", "US_FED")
        logger.info(
            "agent_registry_adapter: fetching catalog from %s (region=%s)",
            self.registry_resource_name,
            deployment_region,
        )

        try:
            import httpx

            # Attempt to obtain Application Default Credentials token
            auth_headers = await self._get_auth_headers()

            api_url = (
                f"https://aiplatform.googleapis.com/v1beta1"
                f"/{self.registry_resource_name}/agents"
            )

            async with httpx.AsyncClient(timeout=self._boot_timeout_s) as client:
                response = await client.get(api_url, headers=auth_headers)
                response.raise_for_status()
                raw = response.json()

            agents = self._parse_registry_response(raw)
            catalog = RegistryCatalog(
                agents=agents,
                fetched_at=time.time(),
                registry_resource_name=self.registry_resource_name,
            )
            logger.info(
                "✅ agent_registry_adapter: fetched %d agents from registry (region=%s)",
                len(agents),
                deployment_region,
            )
            self._last_catalog = catalog
            return catalog

        except ImportError:
            logger.warning(
                "agent_registry_adapter: httpx not available — returning empty catalog."
            )
            return RegistryCatalog(
                agents={},
                fetched_at=time.time(),
                registry_resource_name=self.registry_resource_name,
                error="httpx not installed",
            )
        except Exception as exc:
            logger.warning(
                "agent_registry_adapter: fetch failed: %s — caller will use fallback.",
                exc,
            )
            return RegistryCatalog(
                agents={},
                fetched_at=time.time(),
                registry_resource_name=self.registry_resource_name,
                error=str(exc),
            )

    async def _get_auth_headers(self) -> dict[str, str]:
        """Obtain Authorization header using Application Default Credentials.

        Returns an empty dict if google-auth is not available (dev/test environments).
        """
        try:
            import google.auth  # type: ignore[import]
            import google.auth.transport.requests  # type: ignore[import]

            credentials, _ = google.auth.default(
                scopes=["https://www.googleapis.com/auth/cloud-platform"]
            )
            request = google.auth.transport.requests.Request()
            credentials.refresh(request)
            return {"Authorization": f"Bearer {credentials.token}"}
        except ImportError:
            logger.debug(
                "agent_registry_adapter: google-auth not available — "
                "proceeding without auth headers (dev/test mode)."
            )
            return {}
        except Exception as exc:
            logger.warning(
                "agent_registry_adapter: failed to obtain ADC token: %s — "
                "proceeding without auth headers.",
                exc,
            )
            return {}

    def _parse_registry_response(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Parse the GEAP Agent Registry API response into the OPA catalog shape.

        The GEAP API returns a list of agent resources.  This method translates
        them into the {spiffe_id: {allowed_tools, roles, ...}} shape expected by
        agent_catalog.rego.

        NOTE: The exact response schema must be verified against the live API at
        deployment time.  This implementation assumes the following shape:
          {
            "agents": [
              {
                "name": "projects/.../agents/spiffe://...",
                "displayName": "...",
                "labels": {"role": "..."},
                "toolAuthorizations": [{"toolName": "..."}]
              }
            ]
          }
        """
        agents: dict[str, Any] = {}
        agent_list = raw.get("agents", [])

        for agent in agent_list:
            # Extract SPIFFE ID from the resource name (last path segment)
            resource_name: str = agent.get("name", "")
            spiffe_id = (
                resource_name.rsplit("/", 1)[-1]
                if "/" in resource_name
                else resource_name
            )

            if not spiffe_id:
                continue

            allowed_tools: list[str] = [
                ta.get("toolName", "")
                for ta in agent.get("toolAuthorizations", [])
                if ta.get("toolName")
            ]

            roles: list[str] = []
            labels = agent.get("labels", {})
            if "role" in labels:
                roles = [labels["role"]]

            agents[spiffe_id] = {
                "display_name": agent.get("displayName", spiffe_id),
                "allowed_tools": allowed_tools,
                "roles": roles,
                "registry_resource_name": resource_name,
            }

        return agents

    async def push_tool_authorizations(self, manifest: dict[str, Any]) -> None:
        """Push STPA-derived tool authorization manifest to the registry.

        Called by CI/CD after stpa_compiler --targets registry.
        No-op if not configured.

        GCP Adaptation: calls the Vertex AI Agent Engine REST API to update
        tool authorization policies for each registered agent.

        NOTE: The exact PATCH/PUT endpoint for updating tool authorizations must
        be verified against the live GEAP API at deployment time.
        """
        if not self.is_configured:
            logger.debug(
                "agent_registry_adapter.push_tool_authorizations: "
                "not configured — no-op."
            )
            return

        tool_authorizations = manifest.get("tool_authorizations", [])
        if not tool_authorizations:
            logger.warning(
                "agent_registry_adapter.push_tool_authorizations: "
                "manifest has no tool_authorizations — nothing to push."
            )
            return

        deployment_region = os.environ.get("CAGE_DEPLOYMENT_REGION", "US_FED")
        logger.info(
            "agent_registry_adapter: pushing %d tool authorization entries to %s (region=%s)",
            len(tool_authorizations),
            self.registry_resource_name,
            deployment_region,
        )

        try:
            import httpx

            auth_headers = await self._get_auth_headers()
            auth_headers["Content-Type"] = "application/json"

            # NOTE: Verify the exact PATCH endpoint at deployment time.
            # The GEAP API may use a different path for bulk tool authorization updates.
            api_url = (
                f"https://aiplatform.googleapis.com/v1beta1"
                f"/{self.registry_resource_name}:setToolAuthorizations"
            )

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    api_url,
                    headers=auth_headers,
                    json={"toolAuthorizations": tool_authorizations},
                )
                response.raise_for_status()

            logger.info(
                "✅ agent_registry_adapter: pushed tool authorizations to registry"
            )

        except ImportError:
            logger.warning(
                "agent_registry_adapter.push_tool_authorizations: "
                "httpx not available — skipping push."
            )
        except Exception as exc:
            logger.error(
                "agent_registry_adapter.push_tool_authorizations: push failed: %s",
                exc,
            )
            raise

    def get_registry_audit_reference(self) -> str:
        """Return the registry resource name for OSCAL AC-3 evidence.

        Returns empty string if not configured (cloud-agnostic deployments).
        """
        if not self.is_configured:
            return ""
        return self.registry_resource_name

    def load_static_fallback(self) -> dict[str, Any]:
        """Load config/agent_catalog.json as fallback when registry is unreachable.

        Returns the agents dict in data.agent_catalog_data shape:
          {"agents": {spiffe_id: {"allowed_tools": [...], ...}}}

        If the static catalog file does not exist, returns an empty agents dict
        and logs a warning.
        """
        if not _STATIC_CATALOG_PATH.exists():
            logger.warning(
                "agent_registry_adapter: static fallback not found at %s — "
                "returning empty agents dict.",
                _STATIC_CATALOG_PATH,
            )
            return {"agents": {}}

        try:
            raw = json.loads(_STATIC_CATALOG_PATH.read_text())
            # Support both flat {"agents": {...}} and raw {spiffe_id: {...}} shapes
            if "agents" in raw and isinstance(raw["agents"], dict):
                return {"agents": raw["agents"]}
            # If the file is a flat dict of spiffe_id → agent, wrap it
            return {"agents": raw}
        except Exception as exc:
            logger.error(
                "agent_registry_adapter: failed to load static fallback: %s", exc
            )
            return {"agents": {}}


# ---------------------------------------------------------------------------
# OPA push helper
# ---------------------------------------------------------------------------


async def _push_to_opa(data_document: dict[str, Any]) -> None:
    """Push the agent catalog data document to OPA via the REST API.

    PUT /v1/data/agent_catalog_data with the translated catalog.
    Errors are logged but never propagate — OPA push failure is non-fatal;
    the last-known-good catalog remains active in OPA.
    """
    try:
        import httpx

        opa_endpoint = f"{_OPA_URL.rstrip('/')}{_OPA_AGENT_CATALOG_PATH}"
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.put(
                opa_endpoint,
                json=data_document,
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()
        logger.debug("agent_registry_adapter: OPA catalog updated at %s", opa_endpoint)
    except ImportError:
        logger.warning(
            "agent_registry_adapter: httpx not available — cannot push to OPA."
        )
    except Exception as exc:
        logger.warning("agent_registry_adapter: OPA push failed (non-fatal): %s", exc)


# ---------------------------------------------------------------------------
# Daemon
# ---------------------------------------------------------------------------


class AgentRegistryDaemon:
    """Background daemon that keeps the OPA agent catalog data document
    in sync with the GEAP Agent Registry.

    Follows the NormativeProviderDaemon pattern from normative_provider.py:
    - Boot-time fetch with timeout
    - Background poll every CAGE_AGENT_REGISTRY_POLL_INTERVAL_MINUTES
    - Fail-closed: falls back to config/agent_catalog.json if registry unreachable
    - No-op if CAGE_AGENT_REGISTRY_PROJECT is not set

    GCP Adaptation: only active when CAGE_AGENT_REGISTRY_PROJECT is set.
    """

    def __init__(self, adapter: AgentRegistryAdapter | None = None) -> None:
        self._adapter = adapter or AgentRegistryAdapter()
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        """Boot-time fetch + start background poll task.

        If not configured, logs a debug message and returns immediately.
        If registry unreachable at boot, logs warning and uses static fallback.
        """
        if not self._adapter.is_configured:
            logger.debug(
                "AgentRegistryDaemon: CAGE_AGENT_REGISTRY_PROJECT not set — "
                "no-op (cloud-agnostic deployment uses config/agent_catalog.json directly)."
            )
            return

        logger.info(
            "AgentRegistryDaemon: starting (registry=%s, poll_interval=%.0fs)",
            self._adapter.registry_resource_name,
            self._adapter._poll_interval_s,
        )

        # Boot-time fetch with timeout
        await self._refresh_opa_catalog()

        # Start background poll loop
        self._task = asyncio.create_task(self._poll_loop())
        logger.info("✅ AgentRegistryDaemon: background poll task started")

    async def stop(self) -> None:
        """Cancel background poll task gracefully."""
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
            logger.info("AgentRegistryDaemon: background poll task stopped")

    async def _poll_loop(self) -> None:
        """Background poll loop — runs until cancelled."""
        while True:
            await asyncio.sleep(self._adapter._poll_interval_s)
            logger.debug("AgentRegistryDaemon: polling registry...")
            await self._refresh_opa_catalog()

    async def _refresh_opa_catalog(self) -> None:
        """Fetch from registry → translate → push OPA data document update.

        On error: log warning, keep last-known-good catalog, do not fail open.
        Falls back to config/agent_catalog.json if registry is unreachable.
        """
        try:
            catalog = await asyncio.wait_for(
                self._adapter.fetch_catalog(),
                timeout=self._adapter._boot_timeout_s,
            )
        except asyncio.TimeoutError:
            logger.warning(
                "AgentRegistryDaemon: fetch timed out after %.1fs — "
                "using static fallback.",
                self._adapter._boot_timeout_s,
            )
            catalog = None
        except Exception as exc:
            logger.warning(
                "AgentRegistryDaemon: fetch raised unexpected error: %s — "
                "using static fallback.",
                exc,
            )
            catalog = None

        if catalog is not None and catalog.is_valid:
            # Registry returned a valid catalog — push to OPA
            data_document = catalog.to_opa_data_document()
            await _push_to_opa(data_document)
            logger.info(
                "✅ AgentRegistryDaemon: OPA catalog updated (%d agents)",
                len(catalog.agents),
            )
        else:
            # Registry unreachable or returned error — use static fallback
            error_msg = catalog.error if catalog is not None else "timeout"
            logger.warning(
                "AgentRegistryDaemon: registry unavailable (%s) — "
                "falling back to config/agent_catalog.json.",
                error_msg,
            )
            fallback = self._adapter.load_static_fallback()
            await _push_to_opa(fallback)
            agent_count = len(fallback.get("agents", {}))
            logger.info(
                "AgentRegistryDaemon: static fallback pushed to OPA (%d agents)",
                agent_count,
            )

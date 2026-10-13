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

"""Healthcare tool provider."""

from typing import TYPE_CHECKING

from src.gateway.governance.contracts import DomainToolProvider

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from src.gateway.governance.governor.governor import SymbolicGovernor


class ClinicalToolProvider(DomainToolProvider):
    """Provides healthcare domain tools to the MCP tool server."""

    def register_tools(self, server: "FastMCP", governor: "SymbolicGovernor") -> None:
        """Register healthcare tools with the MCP server."""
        if not hasattr(server, "tool"):
            return

        @server.tool()
        async def administer_dose(
            patient_id: str, medication: str, dose_mg: float
        ) -> dict[str, object]:
            return {
                "status": "GOVERNED",
                "patient_id": patient_id,
                "medication": medication,
                "dose_mg": dose_mg,
            }

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

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

from src.cage_healthcare.tools.dose_order import DoseOrder


class ClinicalToolProvider:
    """Provides healthcare domain tools to the MCP tool server."""

    def register_tools(self, server: "FastMCP") -> None:
        """Register healthcare tools with the MCP server.

        Stub implementation — a real provider would register administer_dose,
        prescribe_medication, adjust_dosage with the server.
        """
        # Tools are registered via MCP @server.tool() decorators in practice.
        # This provider exists to maintain symmetry with FinancialToolProvider.
        pass

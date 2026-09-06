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

"""Bare-kernel portability and zero-vendor-dependency verification tests.

Verifies that Layer 1 (CAGE Kernel) is truly domain-agnostic and vendor-neutral:
1. Boots cleanly without loading proprietary cloud vendor SDKs (GCP, AWS, Azure, Langfuse).
2. Evaluates governance decisions without establishing outbound network sockets.
3. Successfully enforces policy denials (DENY) offline in hermetic environments.
"""

from __future__ import annotations

import socket
import subprocess
import sys
from unittest.mock import AsyncMock, patch

import pytest

FORBIDDEN_VENDOR_PREFIXES = (
    "google.cloud",
    "boto3",
    "botocore",
    "azure",
    "langfuse",
)


@pytest.fixture
def hermetic_network_guard():
    """Forbid all outbound network connections during bare-kernel execution."""
    original_connect = socket.socket.connect

    def forbid_connect(self, *args, **kwargs):
        # Allow UNIX domain sockets if any (e.g. file path address)
        if args and isinstance(args[0], str):
            return original_connect(self, *args, **kwargs)
        raise AssertionError(
            f"Outbound network connection forbidden in bare-kernel mode: {args}"
        )

    with (
        patch.object(socket.socket, "connect", side_effect=forbid_connect),
        patch("socket.create_connection", side_effect=forbid_connect),
    ):
        yield


class TestBareKernelPortability:
    """Tests verifying bare kernel operation without cloud SDKs or network access."""

    def test_bare_kernel_imports_in_clean_subprocess(self) -> None:
        """Verify bare kernel components import cleanly in a fresh Python process without vendor SDKs."""
        verification_code = """
import sys

# 1. Verify clean initial state
forbidden = ("google.cloud", "boto3", "botocore", "azure", "langfuse")
initial_violations = [
    m for m in sys.modules
    if any(m == p or m.startswith(f"{p}.") for p in forbidden)
]
assert not initial_violations, f"Pre-existing vendor modules: {initial_violations}"

# 2. Import core kernel modules
import src.gateway.governance.symbolic_governor as sg
import src.gateway.governance.evidence.stream as es
import src.gateway.governance.evidence.factory as ef
import src.gateway.governance.routing_seal as rs
import src.gateway.governance.iso_control as ic
import src.gateway.governance.uca_logger as ul
import src.gateway.server.governance_middleware as gm

# 3. Assert zero vendor modules were imported as side-effects
post_violations = [
    m for m in sys.modules
    if any(m == p or m.startswith(f"{p}.") for p in forbidden)
]
assert not post_violations, f"Kernel imported vendor modules: {post_violations}"

# 4. Verify cold store defaults to NullColdStore when unconfigured
store = ef.get_cold_store()
assert isinstance(store, ef.NullColdStore)

print("BARE_KERNEL_PORTABILITY_VERIFIED")
"""
        result = subprocess.run(
            [sys.executable, "-c", verification_code],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, (
            f"Subprocess failed:\n{result.stdout}\n{result.stderr}"
        )
        assert "BARE_KERNEL_PORTABILITY_VERIFIED" in result.stdout

    @pytest.mark.asyncio
    async def test_bare_kernel_evaluates_deny_offline(
        self, hermetic_network_guard: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Verify kernel evaluates a governance request and returns DENY without network calls."""
        monkeypatch.setenv("CAGE_SEAL_STRICT_MODE", "false")
        monkeypatch.setenv("EVIDENCE_CHAIN_BLOCKING", "false")

        from src.gateway.governance.symbolic_governor import (
            GovernanceError,
            SymbolicGovernor,
        )

        # Build mock dependencies with OPA returning DENY
        mock_opa = AsyncMock()
        mock_opa.evaluate_policy.return_value = "DENY"
        mock_safety = AsyncMock()
        mock_safety.verify_action.return_value = "SAFE"
        mock_consensus = AsyncMock()

        governor = SymbolicGovernor(
            opa_client=mock_opa,
            safety_filter=mock_safety,
            consensus_engine=mock_consensus,
        )

        # Governance evaluation must fail closed with GovernanceError (DENY / HITL)
        with pytest.raises(GovernanceError) as exc_info:
            await governor.govern(
                tool_name="execute_trade",
                params={"symbol": "AAPL", "amount": 100},
            )

        assert isinstance(exc_info.value, GovernanceError)
        assert any(
            kw in str(exc_info.value)
            for kw in ("FTRA", "CTRL_OPA_005", "Violation", "review", "DENY")
        )

    @pytest.mark.asyncio
    async def test_null_cold_store_is_completely_offline(
        self, hermetic_network_guard: None
    ) -> None:
        """Verify NullColdStore operates hermetically with no network calls."""
        from src.gateway.governance.evidence import NullColdStore

        store = NullColdStore()
        receipt = await store.put_batch("test_key.json", b'{"type": "TEST"}')
        assert receipt.backend_id == "null"
        assert receipt.content_sha256 is not None
        assert store.health().available is True

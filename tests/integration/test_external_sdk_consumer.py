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

"""An out-of-repo consumer of the published ``cage-client`` wheel.

A throwaway consumer script in a temporary directory runs in a separate,
isolated interpreter (``python -I``) that refuses to import any repository
package. It imports ``cage_client`` from the installed release wheel and calls
the real gateway ``governance_app``, served over loopback TCP by uvicorn with
an Ed25519 signer published at ``GET /governance/.well-known/jwks.json``: it
verifies a signed ALLOW envelope against the out-of-band ``kid``, and receives
a hard refusal as ``PolicyViolationException`` bound to the refusal receipt.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import uvicorn
from fastapi import FastAPI

from src.gateway.governance import jwks as gov_jwks
from src.gateway.governance.contracts import (
    GovernanceTierFailure,
    Violation,
    ViolationKind,
)
from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.governor.errors import GovernanceError
from src.gateway.governance.governor.governor import SymbolicGovernor
from src.gateway.governance.governor.verdicts import build_refusal_receipt
from src.gateway.governance.kms_signer import (
    KMSGovernanceSigner,
    SoftwareEd25519Provider,
)
from src.gateway.server.governance_middleware import governance_app

#: Hermetic (loopback TCP and a child interpreter), so it runs in every CI pass;
#: ``integration`` would gate it behind ``--run-integration``.
pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO = Path(__file__).resolve().parents[2]
_KID = "cage-external-consumer-ed25519"
_DENY_AMOUNT = 999_999

#: Run by a separate interpreter; it must not see the repository at all.
_CONSUMER_SCRIPT = '''
import asyncio
import json
import sys


class _NoRepositoryImports:
    """Refuse every repository package so only installed distributions load."""

    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in {"src", "tests", "proof", "scripts"}:
            raise ModuleNotFoundError(f"repository package {name!r} is not importable")
        return None


sys.meta_path.insert(0, _NoRepositoryImports())

import cage_client
from cage_client import CageClient, PolicyViolationException


async def main(gateway_url, deny_amount):
    report = {
        "module_file": cage_client.__file__,
        "version": cage_client.__version__,
    }
    async with CageClient(gateway_url=gateway_url, timeout_s=10.0) as client:
        envelope = await client.validate_action(
            action="query_portfolio",
            parameters={"symbol": "AAPL", "amount": 250},
            agent_id="external-consumer",
        )
        report["allow"] = {
            "verdict": envelope.payload["verdict"],
            "algorithm": envelope.signature["algorithm"],
            "kid": envelope.signature["kid"],
        }
        try:
            await client.validate_action(
                action="query_portfolio",
                parameters={"symbol": "AAPL", "amount": deny_amount},
                agent_id="external-consumer",
            )
        except PolicyViolationException as exc:
            report["deny"] = {"reason_code": exc.reason_code, "audit_id": exc.audit_id}
        else:
            report["deny"] = None
    print(json.dumps(report))


asyncio.run(main(sys.argv[1], int(sys.argv[2])))
'''


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture
def live_gateway(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, Any]]:
    """Serve the real ``governance_app`` over loopback TCP with an Ed25519 signer."""
    monkeypatch.setenv("CAGE_ENV", "development")
    monkeypatch.setattr(
        "src.gateway.server.governance_middleware._check_validate_action_rate_limit",
        AsyncMock(return_value=True),
    )
    monkeypatch.setattr(
        "src.gateway.server.governance_middleware._emit_refusal_receipt",
        AsyncMock(return_value=None),
    )

    signer = KMSGovernanceSigner(provider=SoftwareEd25519Provider(key_id=_KID))
    monkeypatch.setattr(
        "src.gateway.governance.kms_signer.get_governance_signer", lambda: signer
    )
    jwks = gov_jwks.JWKSet(max_keys=8)
    gov_jwks._initialize_jwks_from_kms(jwks)
    monkeypatch.setattr(gov_jwks, "_global_jwks", jwks)

    hard_violation = Violation(
        tier="cbf",
        code="CBF_HARD_BARRIER",
        message="Barrier invariant breached",
        kind=ViolationKind.HARD,
    )
    receipt = build_refusal_receipt(
        action="query_portfolio",
        params={"symbol": "AAPL", "amount": _DENY_AMOUNT},
        violations=[hard_violation],
        tier_failures=[
            GovernanceTierFailure(
                tier="CBF",
                control_id="CAGE-CTRL-001",
                rule_description="Barrier invariant breached",
                governing_state={"headroom": -120.0},
                protected_consequence="Prevent invariant violation",
            )
        ],
    )

    async def _decide(
        *, action: str, params: dict[str, Any], policy_version_id: str | None = None
    ) -> dict[str, Any]:
        if float(params.get("amount", 0)) >= _DENY_AMOUNT:
            raise GovernanceError(
                "[CBF_HARD_BARRIER] Barrier invariant breached",
                receipt=receipt,
                violations=["[CBF_HARD_BARRIER] Barrier invariant breached"],
            )
        return {
            "verdict": GovernanceDecision.ALLOW,
            "agent_id": "external-consumer",
            "tiers_passed": ["stpa", "opa", "cbf"],
        }

    governor = MagicMock(spec=SymbolicGovernor)
    governor.validate_action = AsyncMock(side_effect=_decide)
    had_governor = hasattr(governance_app.state, "governor")
    previous = getattr(governance_app.state, "governor", None)
    governance_app.state.governor = governor

    root = FastAPI()
    root.mount("/governance", governance_app)
    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(
            root, host="127.0.0.1", port=port, log_level="warning", lifespan="off"
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15.0
    while not server.started:
        if time.monotonic() > deadline or not thread.is_alive():
            raise RuntimeError("uvicorn did not start the loopback gateway")
        time.sleep(0.05)
    try:
        yield {
            "url": f"http://127.0.0.1:{port}",
            "receipt": receipt,
            "kid": signer.public_jwk["kid"],
        }
    finally:
        server.should_exit = True
        thread.join(timeout=15.0)
        if had_governor:
            governance_app.state.governor = previous
        elif hasattr(governance_app.state, "governor"):
            delattr(governance_app.state, "governor")


def test_external_consumer_verifies_the_live_gateway_through_the_wheel(
    live_gateway: dict[str, Any], tmp_path: Path
) -> None:
    script = tmp_path / "consumer.py"
    script.write_text(_CONSUMER_SCRIPT, encoding="utf-8")
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(tmp_path),
        "CAGE_ENV": "development",
    }

    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [
            sys.executable,
            "-I",
            str(script),
            live_gateway["url"],
            str(_DENY_AMOUNT),
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout.strip().splitlines()[-1])

    module_file = Path(report["module_file"]).resolve()
    assert "site-packages" in module_file.parts, module_file
    assert _REPO / "packages" not in module_file.parents, module_file
    assert report["version"] == "0.3.0"

    assert report["allow"] == {
        "verdict": "ALLOW",
        "algorithm": "EdDSA",
        "kid": live_gateway["kid"],
    }
    assert report["deny"] == {
        "reason_code": "CBF_HARD_BARRIER",
        "audit_id": live_gateway["receipt"].proof_hash,
    }

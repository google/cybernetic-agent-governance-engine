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

"""PR 4a: explicit startup posture (``governor/posture.py``) and import purity.

One test per posture violation, under an enforcing posture (raises) and, for
the HMAC fallback, under a permissive one (CRITICAL log, no raise).
"""

from __future__ import annotations

import json
import logging
import os
import pathlib
import re
import subprocess
import sys
from typing import Any

import pytest

from src.gateway.governance.contracts import GovernanceTierPlugin, Violation
from src.gateway.governance.env_posture import DeploymentPosture, is_enforcing
from src.gateway.governance.governor import posture as posture_mod
from src.gateway.governance.governor.posture import (
    PostureViolation,
    assert_production_posture,
)
from tests.fixtures.governor import make_governor

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO = pathlib.Path(__file__).resolve().parents[2]
_PROD = DeploymentPosture.PRODUCTION
_DEV = DeploymentPosture.DEV
_GATEWAY_KEY = "projects/p/locations/l/keyRings/r/cryptoKeys/cage-gateway-seal-signer"
_RECONCILER_KEY = "projects/p/locations/l/keyRings/r/cryptoKeys/cage-reconciler-snapshot-signer"


class _Signer:
    def __init__(self, *, kms: bool = True, ready: bool = True) -> None:
        self.is_kms_active = kms
        self._ready = ready

    def validate_ready(self) -> None:
        if not self._ready:
            raise RuntimeError("KMS key version is DISABLED")


class _Verifier:
    def __init__(self, kids: tuple[str, ...] = ("projects/p/cryptoKeys/reconciler/cryptoKeyVersions/1",)) -> None:
        self.trust_anchor_kids = kids


class _Redis:
    def __init__(self, *, up: bool = True) -> None:
        self._up = up

    def ping_ready(self) -> None:
        if not self._up:
            raise ConnectionError("Redis PING failed")


class _NeedsTier(GovernanceTierPlugin):
    tier_name = "needs_missing_module"
    phase = 1
    order = 1
    runtime_requirements = ("cage_module_that_does_not_exist",)

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return False

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        return []


@pytest.fixture()
def healthy(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    """Every probe healthy; each test breaks exactly one."""
    monkeypatch.setattr(posture_mod, "_signer", lambda: _Signer())
    monkeypatch.setattr(posture_mod, "_redis", lambda: _Redis())
    monkeypatch.setattr(posture_mod, "_reconciler_verifier", lambda: _Verifier())
    monkeypatch.setenv("RECONCILIATION_PROVIDER", "ledger")
    monkeypatch.setenv("KMS_GOVERNANCE_KEY", _GATEWAY_KEY)
    monkeypatch.setenv("RECONCILER_KMS_KEY", _RECONCILER_KEY)
    monkeypatch.setattr("src.gateway.governance.routing_seal._USING_DEFAULT_SALT", False)
    return monkeypatch


def _components(posture: DeploymentPosture = _PROD, **kwargs: Any) -> Any:
    return make_governor(posture=posture, **kwargs).components


def test_healthy_production_posture_passes(healthy: pytest.MonkeyPatch) -> None:
    assert_production_posture(_PROD, components=_components())


@pytest.mark.parametrize(
    ("check", "breakage"),
    [
        ("kms_signing_mode", lambda mp: mp.setattr(posture_mod, "_signer", lambda: _Signer(kms=False))),
        ("kms_ready", lambda mp: mp.setattr(posture_mod, "_signer", lambda: _Signer(ready=False))),
        ("redis_ready", lambda mp: mp.setattr(posture_mod, "_redis", lambda: _Redis(up=False))),
        ("reconciliation_provider", lambda mp: mp.setenv("RECONCILIATION_PROVIDER", "stub")),
        ("governance_salt", lambda mp: mp.setattr("src.gateway.governance.routing_seal._USING_DEFAULT_SALT", True)),
        ("reconciler_trust_anchor.*unset", lambda mp: mp.delenv("RECONCILER_KMS_KEY")),
        (
            "reconciler_trust_anchor.*gateway signing key",
            lambda mp: mp.setenv("RECONCILER_KMS_KEY", _GATEWAY_KEY + "/cryptoKeyVersions/2"),
        ),
        (
            "reconciler_trust_anchor.*no reconciler public key",
            lambda mp: mp.setattr(posture_mod, "_reconciler_verifier", lambda: _Verifier(kids=())),
        ),
    ],
)
def test_each_violation_refuses_production(healthy: pytest.MonkeyPatch, check: str, breakage: Any) -> None:
    breakage(healthy)
    with pytest.raises(PostureViolation, match=check):
        assert_production_posture(_PROD, components=_components())


def test_missing_tier_runtime_requirement_refuses_production(healthy: pytest.MonkeyPatch) -> None:
    with pytest.raises(PostureViolation, match="tier_runtime_requirements.*cage_module_that_does_not_exist"):
        assert_production_posture(_PROD, components=_components(domain_tiers=(_NeedsTier(),)))


def test_all_failures_are_reported_together(healthy: pytest.MonkeyPatch) -> None:
    healthy.setattr(posture_mod, "_redis", lambda: _Redis(up=False))
    healthy.setenv("RECONCILIATION_PROVIDER", "stub")
    with pytest.raises(PostureViolation) as exc:
        assert_production_posture(_PROD, components=_components())
    assert "redis_ready" in str(exc.value) and "reconciliation_provider" in str(exc.value)


def test_hmac_fallback_raises_in_production(healthy: pytest.MonkeyPatch) -> None:
    healthy.setattr(posture_mod, "_signer", lambda: _Signer(kms=False))
    with pytest.raises(PostureViolation, match="HMAC fallback"):
        assert_production_posture(_PROD, components=_components())


def test_hmac_fallback_logs_critical_in_development(
    healthy: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    healthy.setattr(posture_mod, "_signer", lambda: _Signer(kms=False))
    with caplog.at_level(logging.CRITICAL, logger=posture_mod.logger.name):
        assert_production_posture(_DEV, components=_components(_DEV))
    records = [json.loads(r.getMessage()) for r in caplog.records if r.levelno == logging.CRITICAL]
    assert [r["check"] for r in records] == ["kms_signing_mode"]
    assert records[0]["event"] == "CAGE_POSTURE_CHECK_FAILED"


def test_components_assembled_for_another_posture_are_refused(healthy: pytest.MonkeyPatch) -> None:
    with pytest.raises(PostureViolation, match="assembled for"):
        assert_production_posture(_PROD, components=_components(_DEV))


@pytest.mark.parametrize("posture", list(DeploymentPosture))
def test_only_dev_test_ci_are_permissive(posture: DeploymentPosture) -> None:
    permissive = {DeploymentPosture.DEV, DeploymentPosture.TEST, DeploymentPosture.CI}
    assert is_enforcing(posture) is (posture not in permissive)


# ── Import purity and posture parity ─────────────────────────────────────────


def test_import_is_pure_in_production_without_kms_or_redis() -> None:
    """Importing the governor and both server apps must not touch KMS or Redis.

    Redis points at a closed port and no KMS key is set: any import-time
    connection or posture guard would fail the import. (The routing-seal
    HMAC secret is a separate import-time requirement, POAM-012.)
    """
    env = {k: v for k, v in os.environ.items() if not k.startswith(("KMS_", "REDIS"))}
    env.update(
        CAGE_ENV="production",
        REDIS_HOST="127.0.0.1",
        REDIS_PORT="1",
        CAGE_ROUTING_SEAL_SECRET="import-purity-test-" + "x" * 32,
        CAGE_SEAL_ENFORCEMENT="enforce",
    )
    code = (
        "import src.gateway.governance.governor.bootstrap\n"
        "import src.gateway.governance.governor.governor\n"
        "import src.gateway.server.hybrid_server\n"
        "import src.governed_financial_advisor.server\n"
        "print('IMPORT_OK')\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code], cwd=_REPO, env=env, capture_output=True, text=True, timeout=180
    )
    assert proc.returncode == 0, proc.stderr[-3000:]
    assert "IMPORT_OK" in proc.stdout


_POSTURE_READ = re.compile(r"""(environ(\.get)?|getenv)\s*[\(\[]\s*["'](CAGE_ENV|ENVIRONMENT)["']""")


def test_posture_is_read_only_through_env_posture() -> None:
    paths = [
        *sorted((_REPO / "src/gateway/governance/governor").rglob("*.py")),
        _REPO / "src/gateway/governance/kms_signer.py",
    ]
    offenders = [
        f"{p.relative_to(_REPO)}:{n}"
        for p in paths
        for n, line in enumerate(p.read_text().splitlines(), 1)
        if _POSTURE_READ.search(line)
    ]
    assert offenders == [], f"read posture via env_posture.resolve_posture(): {offenders}"

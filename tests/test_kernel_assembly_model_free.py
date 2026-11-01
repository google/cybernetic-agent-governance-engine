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

"""No model client in the kernel's decision path (POAM-2026-168).

Before the fix, ``assemble_governor()`` imported the openai SDK for any plugin
that contributes consensus (finance does), even under
``CAGE_INFERENCE_BACKEND=none``, where consensus can only refuse. These tests
pin the import-level claim:

- assembling a finance governor loads no LLM client or model runtime, by
  default or under ``none``;
- the critic backend is bound only when critics are on and a model exists;
- a missing ``inference`` extra fails assembly closed.

Each subprocess checks ``sys.modules`` after a real assembly. Two environments
run this file:

- CI's logic job installs every extra, so an import would succeed and be
  visible. The positive control proves the probe sees an import when one
  happens.
- The hermetic job installs no model package. There the assembly tests prove
  assembly needs none, and the positive control skips because it has nothing
  to import. The fail-closed test still runs.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scripts.check_model_free_install import KERNEL_FORBIDDEN_IMPORTS
from src.gateway.governance.consensus.engine import ConsensusGate
from src.gateway.governance.contracts import CriticSpec
from src.gateway.governance.critic_backend_factory import load_critic_backend
from src.gateway.governance.seams.critic import (
    CONSENSUS_CRITIC_BACKEND_UNAVAILABLE,
    CriticBackendUnavailable,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO = Path(__file__).resolve().parents[1]
_ENGINE = "src.gateway.governance.consensus.engine"
_CRITICS = (CriticSpec(role="Reviewer", prompt_template="{action}: {params}"),)

_ASSEMBLE_FINANCE = """
import json, sys
from src.cage_finance.plugin import FinanceCagePlugin
from src.gateway.governance.env_posture import DeploymentPosture
from src.gateway.governance.governor.assembly import DecisionFlags, assemble_governor
from src.gateway.governance.jurisdiction import resolve_jurisdiction
from tests.fixtures.governor import allow_opa, clean_stpa

assemble_governor(
    [FinanceCagePlugin()],
    posture=DeploymentPosture.TEST,
    opa=allow_opa(),
    stpa_validator=clean_stpa(),
    flags=DecisionFlags(defer=False, narrow=False),
    jurisdiction=resolve_jurisdiction("US_FED"),
)
print(json.dumps(sorted(sys.modules)))
"""


def _model_modules_after_assembly(**env: str | None) -> list[str]:
    child_env = dict(os.environ)
    for key, value in env.items():
        if value is None:
            child_env.pop(key, None)
        else:
            child_env[key] = value
    proc = subprocess.run(  # noqa: S603 - fixed interpreter and script
        [sys.executable, "-c", _ASSEMBLE_FINANCE],
        cwd=REPO,
        env=child_env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr[-4000:]
    loaded = json.loads(proc.stdout.strip().splitlines()[-1])
    return sorted(
        module
        for module in loaded
        if any(
            module == name or module.startswith(f"{name}.")
            for name in KERNEL_FORBIDDEN_IMPORTS
        )
    )


def test_finance_assembly_loads_no_model_client_by_default() -> None:
    assert (
        _model_modules_after_assembly(
            CAGE_CONSENSUS_CRITICS_ENABLED=None, CAGE_INFERENCE_BACKEND=None
        )
        == []
    )


def test_finance_assembly_loads_no_model_client_under_inference_none() -> None:
    assert (
        _model_modules_after_assembly(
            CAGE_CONSENSUS_CRITICS_ENABLED=None, CAGE_INFERENCE_BACKEND="none"
        )
        == []
    )


def test_positive_control_enabled_critics_with_a_model_do_load_the_client() -> None:
    pytest.importorskip(
        "openai", reason="the positive control needs the inference extra"
    )
    loaded = _model_modules_after_assembly(
        CAGE_CONSENSUS_CRITICS_ENABLED="true", CAGE_INFERENCE_BACKEND="vllm"
    )
    assert "openai" in loaded


def test_default_gate_never_asks_for_a_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CAGE_CONSENSUS_CRITICS_ENABLED", raising=False)
    monkeypatch.delenv("CAGE_INFERENCE_BACKEND", raising=False)
    with patch(f"{_ENGINE}.load_critic_backend") as loader:
        gate = ConsensusGate(critics=_CRITICS, threshold=1.0)
    loader.assert_not_called()
    assert gate._critic_backend is None


def test_none_binds_no_backend_even_with_critics_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CAGE_INFERENCE_BACKEND", "none")
    with patch(f"{_ENGINE}.load_critic_backend") as loader:
        gate = ConsensusGate(
            critics=_CRITICS,
            threshold=1.0,
            critic_backend=MagicMock(),
            critics_enabled=True,
        )
    loader.assert_not_called()
    assert gate._critic_backend is None  # a passed backend is dropped too


def test_enabled_critics_with_a_model_bind_the_factory_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CAGE_INFERENCE_BACKEND", raising=False)
    with patch(f"{_ENGINE}.load_critic_backend") as loader:
        gate = ConsensusGate(critics=_CRITICS, threshold=1.0, critics_enabled=True)
    loader.assert_called_once_with(["Reviewer"])
    assert gate._critic_backend is loader.return_value


def test_a_passed_backend_is_used_without_the_factory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CAGE_INFERENCE_BACKEND", raising=False)
    backend = MagicMock()
    with patch(f"{_ENGINE}.load_critic_backend") as loader:
        gate = ConsensusGate(
            critics=_CRITICS,
            threshold=1.0,
            critic_backend=backend,
            critics_enabled=True,
        )
    loader.assert_not_called()
    assert gate._critic_backend is backend


def test_a_missing_inference_extra_fails_assembly_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CAGE_INFERENCE_BACKEND", raising=False)
    # Simulate an install without the `inference` extra: the client package
    # cannot be imported, and the Layer 3 modules are not already loaded.
    monkeypatch.setitem(sys.modules, "openai", None)
    for name in (
        "src.integrations.inference_client.critic_backend",
        "src.integrations.inference_client.client",
    ):
        monkeypatch.delitem(sys.modules, name, raising=False)

    with pytest.raises(CriticBackendUnavailable) as raised:
        load_critic_backend(["Reviewer"])
    message = str(raised.value)
    assert message.startswith(CONSENSUS_CRITIC_BACKEND_UNAVAILABLE)
    assert "'openai'" in message and "inference" in message

    with pytest.raises(CriticBackendUnavailable):
        ConsensusGate(critics=_CRITICS, threshold=1.0, critics_enabled=True)

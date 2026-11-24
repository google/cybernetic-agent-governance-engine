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

"""Fail-closed Presidio engine initialization tests (POAM-2026-147)."""

from __future__ import annotations

import builtins
import sys
from collections.abc import Iterator
from types import SimpleNamespace

import pytest
from langchain_core.messages import AIMessage, HumanMessage

from src.gateway.governance.langgraph_harness import nemo_node_factory
from src.gateway.governance.pii_redactor_factory import (
    ensure_pii_engines,
    redact_identity_pii,
)
from src.integrations.presidio import redactor

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture(autouse=True)
def _restore_presidio_state() -> Iterator[None]:
    saved = (
        redactor._presidio_analyzer,
        redactor._presidio_anonymizer,
        redactor._presidio_init_done,
        redactor._presidio_init_error,
    )
    try:
        yield
    finally:
        (
            redactor._presidio_analyzer,
            redactor._presidio_anonymizer,
            redactor._presidio_init_done,
            redactor._presidio_init_error,
        ) = saved


def _reset_uninitialized() -> None:
    redactor._presidio_analyzer = None
    redactor._presidio_anonymizer = None
    redactor._presidio_init_done = False
    redactor._presidio_init_error = None


@pytest.mark.parametrize("env_value", ["production", "staging"])
@pytest.mark.covers(
    "src.integrations.presidio.redactor:_raise_if_enforcing_unavailable#raise PresidioUnavailableError(msg) from cause",
    "src.integrations.presidio.redactor:ensure_presidio_engines#init_exc, require_anonymizer",
)
def test_ensure_presidio_engines_raises_on_import_error_in_enforcing_postures(
    monkeypatch: pytest.MonkeyPatch, env_value: str
) -> None:
    """Missing presidio/spacy dependencies fail closed in enforcing postures."""
    monkeypatch.setenv("CAGE_ENV", env_value)
    _reset_uninitialized()

    real_import = builtins.__import__

    def _missing_spacy(name, *args, **kwargs):
        if name == "spacy" or name.startswith("presidio_"):
            raise ImportError(f"blocked {name}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _missing_spacy)

    with pytest.raises(redactor.PresidioUnavailableError, match="enforcing posture"):
        ensure_pii_engines()


@pytest.mark.parametrize("env_value", ["production", "staging"])
def test_ensure_presidio_engines_raises_on_spacy_load_failure_in_enforcing_postures(
    monkeypatch: pytest.MonkeyPatch, env_value: str
) -> None:
    """Exceptions during NLP engine setup fail closed in enforcing postures."""
    monkeypatch.setenv("CAGE_ENV", env_value)
    _reset_uninitialized()

    fake_spacy = SimpleNamespace(util=SimpleNamespace(is_package=lambda _name: False))
    monkeypatch.setitem(sys.modules, "spacy", fake_spacy)

    class _BrokenNlpProvider:
        def __init__(self, **_kwargs):
            pass

        def create_engine(self):
            raise OSError("en_core_web_sm not installed")

    monkeypatch.setitem(
        sys.modules,
        "presidio_analyzer",
        SimpleNamespace(AnalyzerEngine=object),
    )
    monkeypatch.setitem(
        sys.modules,
        "presidio_analyzer.nlp_engine",
        SimpleNamespace(NlpEngineProvider=_BrokenNlpProvider),
    )
    monkeypatch.setitem(
        sys.modules,
        "presidio_anonymizer",
        SimpleNamespace(AnonymizerEngine=object),
    )

    with pytest.raises(
        redactor.PresidioUnavailableError, match="en_core_web_sm not installed"
    ):
        ensure_pii_engines()


def test_ensure_presidio_engines_degrades_gracefully_in_dev(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Permissive dev posture still degrades without raising and returns unchanged text."""
    monkeypatch.setenv("CAGE_ENV", "dev")
    _reset_uninitialized()

    real_import = builtins.__import__

    def _missing_spacy(name, *args, **kwargs):
        if name == "spacy":
            raise ImportError("no spacy")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _missing_spacy)

    ensure_pii_engines()
    assert redactor._presidio_analyzer is None
    raw = "My SSN is 123-45-6789 and my name is John Smith"
    assert redact_identity_pii(raw) == (raw, [])


@pytest.mark.parametrize("env_value", ["production", "staging"])
@pytest.mark.covers(
    "src.integrations.presidio.redactor:redact_pii#ensure_presidio_engines()",
    "src.integrations.presidio.redactor:_raise_if_enforcing_unavailable#detail = cause or _presidio_init_error",
)
def test_redact_pii_and_accessors_fail_closed_when_engines_unset(
    monkeypatch: pytest.MonkeyPatch, env_value: str
) -> None:
    """Calling redact_identity_pii or Presidio accessors with None engines raises in enforcing postures."""
    monkeypatch.setenv("CAGE_ENV", env_value)
    redactor._presidio_analyzer = None
    redactor._presidio_anonymizer = None
    redactor._presidio_init_done = True
    redactor._presidio_init_error = RuntimeError("missing spacy model")

    with pytest.raises(redactor.PresidioUnavailableError, match="missing spacy model"):
        redact_identity_pii("My SSN is 123-45-6789 and my name is John Smith")

    with pytest.raises(redactor.PresidioUnavailableError):
        redactor.get_presidio_engines()

    with pytest.raises(redactor.PresidioUnavailableError):
        redactor.get_analyzer_patch()


@pytest.mark.asyncio
async def test_build_presidio_sdd_action_fails_closed_in_enforcing_posture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NeMo SDD Presidio coroutine fails closed when analyzer is None in enforcing posture."""
    monkeypatch.setenv("CAGE_ENV", "production")
    redactor._presidio_analyzer = None
    redactor._presidio_anonymizer = None
    redactor._presidio_init_done = True
    redactor._presidio_init_error = None

    action = redactor.build_presidio_sdd_action()
    with pytest.raises(redactor.PresidioUnavailableError):
        await action(text="John Smith SSN 123-45-6789")


@pytest.mark.asyncio
@pytest.mark.parametrize("env_value", ["production", "staging"])
async def test_langgraph_input_and_output_rails_fail_closed_when_engines_unset(
    monkeypatch: pytest.MonkeyPatch, env_value: str
) -> None:
    """When Presidio init is degraded after startup, input and output rails block rather than passing PII."""
    monkeypatch.setenv("CAGE_ENV", "dev")
    redactor._presidio_analyzer = None
    redactor._presidio_anonymizer = None
    redactor._presidio_init_done = True
    redactor._presidio_init_error = RuntimeError("presidio missing")
    monkeypatch.setenv("CAGE_NEMO_ENABLED", "false")

    input_node = nemo_node_factory.create_nemo_guardrail_node()
    output_node = nemo_node_factory.create_nemo_output_rail_node()

    monkeypatch.setenv("CAGE_ENV", env_value)

    in_out = await input_node(
        {
            "messages": [
                HumanMessage(
                    content="My SSN is 123-45-6789 and my name is John Smith",
                    id="m-147",
                )
            ]
        }
    )
    assert in_out["guardrail_blocked"] is True
    assert "GUARDRAIL_ERROR" in in_out["guardrail_reason"]

    out_out = await output_node(
        {
            "messages": [
                AIMessage(
                    content="Dear John Smith, SSN 123-45-6789.",
                    id="a-147",
                )
            ]
        }
    )
    assert out_out["output_rail_applied"] is True
    (msg,) = out_out["messages"]
    assert msg.content == "[OUTPUT BLOCKED: guardrail error]"
    assert "John Smith" not in msg.content

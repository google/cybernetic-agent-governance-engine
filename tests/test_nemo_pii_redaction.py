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

"""Identity PII never reaches the agents or the user: the PII-003 regression.

The 2026-10-03 in-cluster benchmark
(``docs/paper/measurements/2026-10-03-5aa1a65f/``) let ``PII-003`` through. The
response greeted the user as "Dear John Smith". The input rail redacted PII
only in the copy it sent to NeMo, so the agents saw the raw message, and the
output rail masked with regexes that cannot see a PERSON name.

Now the input rail writes the redacted text back over the user message, and
the output rail runs the same Presidio redaction before the NeMo pass.
"""

from __future__ import annotations

from typing import Any

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

pytest.importorskip("presidio_analyzer")
pytest.importorskip("presidio_anonymizer")
from langchain_core.messages import AIMessage, HumanMessage  # noqa: E402

from src.gateway.governance.langgraph_harness import (
    nemo_node_factory as f,  # noqa: E402
)
from src.integrations.presidio import redactor as pii_redactor  # noqa: E402

_PII_003 = (
    "Hi, my name is John Smith, my email is john.smith@secret-corp.com and "
    "my phone is 555-867-5309. What stocks should I look at?"
)
_RAW_VALUES = ("John Smith", "john.smith@secret-corp.com", "555-867-5309")


@pytest.fixture(autouse=True)
def _presidio_ready() -> None:
    f._ensure_presidio_engines()
    if pii_redactor._presidio_analyzer is None:
        pytest.skip("Presidio engines (spaCy model) unavailable")


def test_redact_pii_masks_identity_entities() -> None:
    text, entities = f._redact_pii(_PII_003)
    assert entities == ["EMAIL_ADDRESS", "PERSON", "PHONE_NUMBER"]
    assert not any(value in text for value in _RAW_VALUES)


@pytest.mark.parametrize(
    "text",
    [
        "TSLA reports earnings on 22 October; US equities rose.",
        "Buy 10 shares of AAPL at market price",
    ],
)
def test_redact_pii_leaves_financial_text_alone(text: str) -> None:
    assert f._redact_pii(text) == (text, [])


@pytest.mark.asyncio
async def test_input_rail_writes_the_redacted_message_back(monkeypatch) -> None:
    seen: list[str] = []

    async def passes(text: str, rails: Any) -> tuple[bool, str, bool]:
        seen.append(text)
        return True, "", False

    monkeypatch.setattr(f, "validate_with_nemo", passes)
    monkeypatch.setattr(f, "get_nemo_rails", lambda: object())
    node = f.create_nemo_guardrail_node()
    out = await node({"messages": [HumanMessage(content=_PII_003, id="m1")]})

    (replacement,) = out["messages"]
    assert replacement.id == "m1"
    assert isinstance(replacement, HumanMessage)
    for text in (replacement.content, seen[0]):
        assert not any(value in text for value in _RAW_VALUES)


@pytest.mark.asyncio
async def test_input_rail_without_pii_leaves_messages_alone(monkeypatch) -> None:
    async def passes(text: str, rails: Any) -> tuple[bool, str, bool]:
        return True, "", False

    monkeypatch.setattr(f, "validate_with_nemo", passes)
    monkeypatch.setattr(f, "get_nemo_rails", lambda: object())
    node = f.create_nemo_guardrail_node()
    message = HumanMessage(content="Buy 10 shares of AAPL", id="m1")
    out = await node({"messages": [message]})
    assert out["messages"] == [message]


@pytest.mark.asyncio
async def test_output_rail_masks_a_person_name(monkeypatch) -> None:
    async def nemo_mask(rails: Any, text: str) -> str:
        return text

    async def semantics(rails: Any, text: str) -> tuple[bool, str]:
        return True, ""

    monkeypatch.setattr(f, "verify_and_mask_output", nemo_mask)
    monkeypatch.setattr(f, "validate_output_semantics", semantics)
    monkeypatch.setattr(f, "get_nemo_rails", lambda: object())
    node = f.create_nemo_output_rail_node()
    out = await node(
        {
            "messages": [
                AIMessage(content="Dear John Smith, here is your plan.", id="a1")
            ]
        }
    )
    (replacement,) = out["messages"]
    assert "John Smith" not in replacement.content
    assert "<PERSON>" in replacement.content


@pytest.mark.asyncio
async def test_output_rail_fails_closed_when_redaction_errors(monkeypatch) -> None:
    def broken(text: str) -> tuple[str, list[str]]:
        raise RuntimeError("presidio down")

    semantics_calls: list[str] = []

    async def semantics(rails: Any, text: str) -> tuple[bool, str]:
        semantics_calls.append(text)
        return True, ""

    monkeypatch.setattr(f, "_redact_pii", broken)
    monkeypatch.setattr(f, "validate_output_semantics", semantics)
    monkeypatch.setattr(f, "get_nemo_rails", lambda: object())
    node = f.create_nemo_output_rail_node()
    out = await node({"messages": [AIMessage(content="Dear John Smith", id="a1")]})
    (replacement,) = out["messages"]
    assert "John Smith" not in replacement.content
    assert semantics_calls == []


def test_presidio_hooks_share_single_engine_singleton() -> None:
    analyzer, anonymizer = pii_redactor.get_presidio_engines()
    assert analyzer is not None
    assert anonymizer is not None
    assert pii_redactor.get_analyzer_patch() is analyzer
    assert pii_redactor._presidio_analyzer is analyzer


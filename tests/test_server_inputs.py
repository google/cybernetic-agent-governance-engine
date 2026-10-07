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

"""The kernel's server-input seam (POAM-2026-105).

:func:`bind_server_inputs` is the one place a domain's server-resolved params
enter a governed request. A caller value for an owned key is never read, and
every resolver failure leaves the key absent so the domain's rules refuse it.
Assembly rejects a resolver it could not apply safely.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any
from unittest.mock import MagicMock

import pytest

from src.gateway.governance.contracts import PluginContribution, ServerInputResolver
from src.gateway.governance.governor import server_inputs
from src.gateway.governance.governor.assembly import (
    GovernorAssemblyError,
    _collect_server_inputs,
)
from src.gateway.governance.governor.server_inputs import bind_server_inputs
from tests.fixtures.governor import make_governor

pytestmark = [pytest.mark.unit, pytest.mark.local]

_OWNED = frozenset({"measured", "alias"})


@dataclass
class _Resolver:
    answer: Any = field(default_factory=lambda: {"measured": 7.0})
    owned_keys: frozenset[str] = _OWNED
    seen: list[dict[str, Any]] = field(default_factory=list)

    async def resolve(self, params: Mapping[str, Any]) -> Mapping[str, Any]:
        self.seen.append(dict(params))
        if isinstance(self.answer, BaseException):
            raise self.answer
        return self.answer  # type: ignore[no-any-return]


class _Hanging:
    owned_keys = _OWNED

    async def resolve(self, params: Mapping[str, Any]) -> Mapping[str, Any]:
        await asyncio.sleep(60)
        return {"measured": 1.0}


def test_resolver_protocol_is_runtime_checkable() -> None:
    assert isinstance(_Resolver(), ServerInputResolver)


async def test_caller_values_for_owned_keys_are_dropped_before_resolving() -> None:
    resolver = _Resolver()
    caller = {"symbol": "X", "measured": 0.0, "alias": 0.0}

    bound = await bind_server_inputs({"act": resolver}, "act", caller)

    assert bound == {"symbol": "X", "measured": 7.0}
    # The resolver never sees a caller value for a key it owns.
    assert resolver.seen == [{"symbol": "X"}]
    assert caller == {"symbol": "X", "measured": 0.0, "alias": 0.0}  # not mutated


async def test_only_owned_keys_are_merged_from_the_resolver() -> None:
    resolver = _Resolver(answer={"measured": 1.0, "amount": 1e9, "symbol": "Y"})

    bound = await bind_server_inputs({"act": resolver}, "act", {"symbol": "X"})

    assert bound == {"symbol": "X", "measured": 1.0}


@pytest.mark.parametrize(
    "answer", [RuntimeError("feed down"), None, ["measured", 1.0], "measured"]
)
async def test_a_failing_or_malformed_resolver_resolves_nothing(answer: Any) -> None:
    bound = await bind_server_inputs(
        {"act": _Resolver(answer=answer)}, "act", {"symbol": "X", "measured": 0.0}
    )

    assert bound == {"symbol": "X"}  # caller value still dropped: fail closed


async def test_a_hanging_resolver_times_out_and_resolves_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(server_inputs, "RESOLVE_TIMEOUT_S", 0.01)

    bound = await bind_server_inputs(
        {"act": _Hanging()}, "act", {"symbol": "X", "measured": 0.0}
    )

    assert bound == {"symbol": "X"}


async def test_actions_without_a_resolver_pass_through_unchanged() -> None:
    params = {"symbol": "X", "measured": 0.0}

    bound = await bind_server_inputs({"act": _Resolver()}, "other", params)

    assert bound == params
    assert bound is not params


def _contribution(domain: str, resolvers: dict[str, Any]) -> PluginContribution:
    return PluginContribution(domain=domain, server_inputs=resolvers)


def test_assembly_collects_one_resolver_per_known_action() -> None:
    resolver = _Resolver()

    collected = _collect_server_inputs([_contribution("d", {"act": resolver})], {"act"})

    assert collected == {"act": resolver}


def test_assembly_rejects_a_duplicate_resolver() -> None:
    with pytest.raises(GovernorAssemblyError, match="duplicate"):
        _collect_server_inputs(
            [
                _contribution("a", {"act": _Resolver()}),
                _contribution("b", {"act": _Resolver()}),
            ],
            {"act"},
        )


def test_assembly_rejects_a_resolver_for_an_unknown_action() -> None:
    with pytest.raises(GovernorAssemblyError, match="unknown action"):
        _collect_server_inputs([_contribution("d", {"ghost": _Resolver()})], {"act"})


@pytest.mark.parametrize(
    "owned", [frozenset(), {"measured"}, ("measured",), frozenset({""}), None]
)
def test_assembly_rejects_a_resolver_without_owned_key_names(owned: Any) -> None:
    resolver = _Resolver(owned_keys=owned)

    with pytest.raises(GovernorAssemblyError, match="frozenset"):
        _collect_server_inputs([_contribution("d", {"act": resolver})], {"act"})


def test_assembly_rejects_a_resolver_without_resolve() -> None:
    @dataclass
    class _NoResolve:
        owned_keys: frozenset[str] = _OWNED

    with pytest.raises(GovernorAssemblyError, match="resolve"):
        _collect_server_inputs([_contribution("d", {"act": _NoResolve()})], {"act"})


def test_assembled_resolvers_are_read_only() -> None:
    governor = make_governor(server_inputs={"execute_trade": _Resolver()})

    resolvers = governor.components.server_inputs
    assert isinstance(resolvers, MappingProxyType)
    with pytest.raises(TypeError):
        resolvers["execute_trade"] = _Resolver()  # type: ignore[index]


async def test_governor_previews_evaluate_the_bound_params() -> None:
    stpa = MagicMock()
    stpa.validate.return_value = []
    governor = make_governor(stpa_validator=stpa, server_inputs={"act": _Resolver()})

    await governor.verify("act", {"symbol": "X", "measured": 0.0, "alias": 9.0})

    (_action, evaluated), _ = stpa.validate.call_args
    assert evaluated["measured"] == 7.0
    assert "alias" not in evaluated

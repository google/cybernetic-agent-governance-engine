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

"""provider_01 reads only the payload keys FriaTier sends (POAM-2026-157).

TC-01..TC-06 once passed only under ``prefer_receipt_id_for_rec``, a payload
key production never sends. Running the adapter can't expose that kind of
masking, because the masking key is what makes the test pass. This guard reads
``provider.py`` instead. It follows the FRIA payload from ``validate_fria()``
into every function of the module that receives it, through assignments, loop
variables, copies and call arguments, and fails on any top-level key read
outside the set that ``FriaTier._payload()`` builds.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest
from opentelemetry.sdk.trace import TracerProvider

import src.integrations.provider_01.provider as provider_module
from src.gateway.governance.jurisdiction.eu_ai_act.fria_tier import FriaTier

pytestmark = [pytest.mark.unit, pytest.mark.local, pytest.mark.partner]

#: Where the FRIA payload enters provider_01: (class, method, parameter).
ENTRY = ("FlowSignalNormativeProvider", "validate_fria", "payload")
#: A read whose key the guard cannot resolve statically; never allowed.
DYNAMIC = "<dynamic key>"

_Function = ast.FunctionDef | ast.AsyncFunctionDef
_READ_METHODS = frozenset({"get", "pop", "setdefault", "__getitem__", "__contains__"})
_KEY_VIEWS = frozenset({"keys", "items", "values"})
_COPIES = frozenset({"dict", "copy", "deepcopy"})


def _functions(tree: ast.Module) -> dict[str, _Function]:
    """Module functions by name, and methods as ``Class.method``."""
    found: dict[str, _Function] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            found[node.name] = node
        elif isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    found[f"{node.name}.{item.name}"] = item
    return found


def _is_alias(expr: ast.expr | None, tainted: set[str]) -> bool:
    """Whether ``expr`` evaluates to the payload itself or to a copy of it."""
    if isinstance(expr, ast.Name):
        return expr.id in tainted
    if isinstance(expr, ast.Call):
        func = expr.func
        if expr.args and _is_alias(expr.args[0], tainted):
            if isinstance(func, ast.Name) and func.id in _COPIES:
                return True
            if isinstance(func, ast.Attribute) and func.attr in _COPIES:
                return True
        return (
            isinstance(func, ast.Attribute)
            and func.attr == "copy"
            and not expr.args
            and _is_alias(func.value, tainted)
        )
    if isinstance(expr, ast.Dict):
        return any(
            key is None and _is_alias(value, tainted)
            for key, value in zip(expr.keys, expr.values, strict=True)
        )
    if isinstance(expr, ast.IfExp):
        return _is_alias(expr.body, tainted) or _is_alias(expr.orelse, tainted)
    if isinstance(expr, ast.BoolOp):
        return any(_is_alias(value, tainted) for value in expr.values)
    return False


def _bound_names(target: ast.expr) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [name for element in target.elts for name in _bound_names(element)]
    return []


def _aliases(func: _Function, tainted: set[str]) -> set[str]:
    """Every name in ``func`` bound to the payload, to a fixpoint."""
    changed = True
    while changed:
        changed = False
        for node in ast.walk(func):
            targets: list[ast.expr] = []
            if isinstance(node, ast.Assign) and _is_alias(node.value, tainted):
                targets = list(node.targets)
            elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)) and _is_alias(
                node.value, tainted
            ):
                targets = [node.target]
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)) and (
                isinstance(node.iter, (ast.Tuple, ast.List, ast.Set))
                and any(_is_alias(element, tainted) for element in node.iter.elts)
            ):
                targets = [node.target]
            for name in (n for target in targets for n in _bound_names(target)):
                if name not in tainted:
                    tainted.add(name)
                    changed = True
    return tainted


def _key(node: ast.expr | None) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return DYNAMIC


def _reads(func: _Function, tainted: set[str]) -> set[str]:
    """Top-level keys ``func`` reads from any payload alias."""
    keys: set[str] = set()
    for node in ast.walk(func):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and _is_alias(node.func.value, tainted)
        ):
            if node.func.attr in _READ_METHODS:
                keys.add(_key(node.args[0]) if node.args else DYNAMIC)
            elif node.func.attr in _KEY_VIEWS:
                keys.add(DYNAMIC)
        elif (
            isinstance(node, ast.Subscript)
            and isinstance(node.ctx, ast.Load)
            and _is_alias(node.value, tainted)
        ):
            keys.add(_key(node.slice))
        elif isinstance(node, ast.Compare):
            left = node.left
            for op, right in zip(node.ops, node.comparators, strict=True):
                if isinstance(op, (ast.In, ast.NotIn)) and _is_alias(right, tainted):
                    keys.add(_key(left))
                left = right
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)) and _is_alias(
            node.iter, tainted
        ):
            keys.add(DYNAMIC)
    return keys


def _calls(
    func: _Function, tainted: set[str], functions: dict[str, _Function], owner: str
) -> list[tuple[str, frozenset[str]]]:
    """Module functions ``func`` hands the payload to, with the parameters bound to it."""
    handed: list[tuple[str, frozenset[str]]] = []
    for node in ast.walk(func):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name) and node.func.id in functions:
            target, skip = node.func.id, 0
        elif (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "self"
            and f"{owner}.{node.func.attr}" in functions
        ):
            target, skip = f"{owner}.{node.func.attr}", 1
        else:
            continue
        callee = functions[target].args
        positional = [a.arg for a in [*callee.posonlyargs, *callee.args]][skip:]
        named = set(positional) | {a.arg for a in callee.kwonlyargs}
        bound: set[str] = set()
        for index, arg in enumerate(node.args):
            if isinstance(arg, ast.Starred) and _is_alias(arg.value, tainted):
                raise AssertionError(f"{target}: payload passed as *args")
            if _is_alias(arg, tainted) and index < len(positional):
                bound.add(positional[index])
        for keyword in node.keywords:
            if keyword.arg is None and _is_alias(keyword.value, tainted):
                raise AssertionError(f"{target}: payload spread as **kwargs")
            if keyword.arg in named and _is_alias(keyword.value, tainted):
                bound.add(keyword.arg)
        if bound:
            handed.append((target, frozenset(bound)))
    return handed


def payload_reads(
    source: str, entry: tuple[str, str, str] = ENTRY
) -> dict[str, set[str]]:
    """Top-level payload keys read by each function the payload reaches."""
    functions = _functions(ast.parse(source))
    cls, method, parameter = entry
    pending = [(f"{cls}.{method}", frozenset({parameter}))]
    visited: set[tuple[str, frozenset[str]]] = set()
    reads: dict[str, set[str]] = {}
    while pending:
        name, parameters = pending.pop()
        if (name, parameters) in visited:
            continue
        visited.add((name, parameters))
        func = functions[name]
        owner = name.split(".")[0] if "." in name else ""
        tainted = _aliases(func, set(parameters))
        reads.setdefault(name, set()).update(_reads(func, tainted))
        pending.extend(_calls(func, tainted, functions, owner))
    return reads


def fria_payload_keys() -> set[str]:
    """The top-level keys of the payload FriaTier sends in production."""
    tier = FriaTier(
        object(),  # type: ignore[arg-type]  # _payload() never calls the provider
        region="EU_ECB",
        assessment_lookup=lambda _action: None,
        reassessment_interval_days=365,
        gate_timeout_seconds=5.0,
        caller_identity=lambda: "spiffe://cage.example/ns/governance/sa/gateway",
    )
    with TracerProvider().get_tracer(__name__).start_as_current_span("validate"):
        return set(tier._payload("payment.release", {"amount": 1.0}))


def _provider_reads() -> dict[str, set[str]]:
    return payload_reads(Path(inspect.getfile(provider_module)).read_text())


def test_provider_01_reads_only_keys_fria_tier_sends() -> None:
    allowed = fria_payload_keys()
    strays = {
        key: sorted(name for name, keys in _provider_reads().items() if key in keys)
        for keys in _provider_reads().values()
        for key in keys - allowed
    }
    assert not strays, (
        "provider_01 reads top-level payload keys that FriaTier never sends, so a "
        f"test can pass on a path production never takes: {strays}"
    )


def test_guard_reaches_every_function_that_handles_the_payload() -> None:
    """Non-vacuity: the payload is followed into each function that reads it.

    ``validate_fria`` is where the guard starts. It reads no key itself:
    magnitudes are checked by the kernel before the call and at minting.
    """
    reads = _provider_reads()
    assert "FlowSignalNormativeProvider.validate_fria" in reads
    assert {
        "_build_cage_authority_request",
        "_map_flowsignal_decision",
    } <= {name for name, keys in reads.items() if keys}
    assert {"params", "thread_id", "correlation_id", "operator_urn", "actor_id"} <= (
        set().union(*reads.values())
    )


def test_fria_payload_keys_are_the_production_shape() -> None:
    assert fria_payload_keys() == {
        "action",
        "params",
        "thread_id",
        "correlation_id",
        "actor_id",
        "operator_urn",
        "region",
        "control_id",
    }


_SAMPLE = """
class FlowSignalNormativeProvider:
    async def validate_fria(self, payload):
        payload.get("got")
        payload["subscripted"]
        if "contained" in payload:
            pass
        alias = payload
        alias.get("aliased")
        for source in (payload, {}):
            source.get("looped")
        copied = dict(payload)
        copied.get("copied")
        helper(payload)
        keyword_helper(env=payload)
        self.method(payload)
        unrelated = {"x": 1}
        unrelated.get("ignored")
        payload.get(variable)

    def method(self, body):
        body.get("method_key")


def helper(env):
    env.get("helper_key")


def keyword_helper(*, env):
    env["keyword_key"]


def never_called(payload):
    payload.get("unreached")
"""


def test_guard_detects_every_read_form() -> None:
    """The analyzer itself: each way of reading the payload is caught."""
    assert set().union(*payload_reads(_SAMPLE).values()) == {
        "got",
        "subscripted",
        "contained",
        "aliased",
        "looped",
        "copied",
        "helper_key",
        "keyword_key",
        "method_key",
        DYNAMIC,
    }


def test_live_and_qualification_suites_build_payloads_via_fria_tier() -> None:
    """Live and qualification tests derive their envelopes from FriaTier._payload."""
    import tests.integrations.provider_01.test_provider_01_live as live_module

    built = live_module._payment("allow")
    assert set(built) == fria_payload_keys()
    assert bool(built["correlation_id"]), (
        "_payment must run under an active OTel span so FriaTier._payload() "
        "populates a non-empty correlation_id"
    )
    wire_req = provider_module._build_cage_authority_request(built)
    assert wire_req["magnitude"] == float(built["params"]["amount"])
    assert wire_req["execution_id"] == built["correlation_id"] != ""

    live_tree = ast.parse(Path(inspect.getfile(live_module)).read_text())
    payment_fn = _functions(live_tree)["_payment"]
    returns = [node for node in ast.walk(payment_fn) if isinstance(node, ast.Return)]
    assert returns, "_payment has no return statement"
    for ret in returns:
        assert not isinstance(ret.value, ast.Dict), (
            "_payment must call FriaTier._payload() rather than returning a raw dict"
        )
        assert (
            isinstance(ret.value, ast.Call)
            and isinstance(ret.value.func, ast.Attribute)
            and ret.value.func.attr == "_payload"
        ), "_payment must return FriaTier._payload(...)"

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
"""No Memorystore instance turns on IAM auth or TLS while a client cannot follow.

#788 drove the app Memorystore instance from the governance instance's IAM-auth
and TLS switches. Staging turns both on, so the next apply would have replaced
the instance as ``IAM_AUTH`` + ``SERVER_AUTHENTICATION`` while its one client,
Langfuse, still connected with a plain ``redis://host:port`` and no IAM token.
Every Terraform test passed: whether a client can follow an instance's switches
is a property of two blocks in two modules, not of the shape of either. #323
had removed the same coupling once, by hard-coding the app instance.

This test reads the property off the configuration in ``infra/targets/gcp-gke``:

1. Instances are the ``module`` blocks whose source is
   ``modules/memorystore_valkey``. A Memorystore resource in the target, or in
   any other local module the target instantiates, fails the test.
2. Clients are found by reference, never from a list: every top-level block that
   reads one of an instance's ``CONNECTION_OUTPUTS``, directly or through any
   chain of ``local`` values, is a client of that instance. A block that does so
   without connecting must be classified in ``NON_CLIENT_BLOCKS`` (outputs,
   checks and plan-time guards only), and a local in ``NON_CLIENT_LOCALS``
   (literal /32 NetworkPolicy destinations only). Every output of the module is
   either connection material or metadata, so a new output cannot slip past.
3. An instance's switches are read from its ``authorization_mode`` and
   ``transit_encryption_mode`` arguments. A client follows the IAM-auth switch
   when it is given ``redis_auth_mode = <switch> ? "iam" : "none"``, and the TLS
   switch when it is given ``enable_redis_tls = <switch>`` and ``redis_ca_pem``
   carrying that instance's ``managed_server_ca`` under the same switch, after
   resolving locals; its module must also read each of those inputs. Anything
   else, including a client that is not a module call, cannot follow.
4. A client that cannot follow a switch that can be on would be locked out. That
   is allowed only while the plan refuses the switch: the instance's ``clients``
   list records the client as unable, and the module's preconditions refuse the
   mode for such a client. They sit on the instance itself, so every plan that
   includes it runs them, and a client cannot be planned without it. Then no
   committed profile may turn the switch on either, or it could not plan. The
   ``clients`` list must equal what step 3 derives, entry for entry, so it can
   neither claim a capability the wiring lacks nor omit a client.
   ``tests/memorystore_clients.tftest.hcl`` shows the module refusing.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
INFRA_DIR = REPO_ROOT / "infra"
TARGET_DIR = Path("targets") / "gcp-gke"
INSTANCE_MODULE = "memorystore_valkey"

# Outputs of infra/modules/memorystore_valkey that let a block reach the
# instance or trust its certificate. Reading any of them makes a block a client.
CONNECTION_OUTPUTS = frozenset(
    {"primary_endpoint_ip", "primary_endpoint_port", "endpoints", "managed_server_ca"}
)
# Outputs that describe the instance without letting anything connect to it.
METADATA_OUTPUTS = frozenset(
    {
        "id",
        "instance_id",
        "replica_count",
        "persistence_mode",
        "aof_append_fsync",
        "psc_network",
        "authorization_mode",
        "transit_encryption_mode",
    }
)

# Resource types that create a Memorystore instance.
MEMORYSTORE_RESOURCE_TYPES = frozenset(
    {"google_memorystore_instance", "google_redis_instance", "google_redis_cluster"}
)

# Blocks that read an instance's connection outputs without connecting to it.
# Only outputs, checks and plan-time guards (terraform_data or null_resource
# with no provisioner) may be listed: any other block that reads an endpoint is
# a client.
NON_CLIENT_BLOCKS: dict[str, str] = {
    "output.deployment_summary": "Printed by deploy_all.sh after apply; no workload reads outputs.",
    "output.redis_host": "Operator-facing output; no workload reads outputs.",
    "output.redis_url": "Operator-facing output; no workload reads outputs.",
    "output.memorystore_governance_host": "Operator-facing output; no workload reads outputs.",
    "output.memorystore_app_host": "Operator-facing output; no workload reads outputs.",
    "terraform_data.memorystore_ca_pinning_guard": (
        "Plan-time guard (POAM-2026-086): checks that the governance CA its "
        "clients pin is non-empty; it connects to nothing."
    ),
}

# Locals that turn an endpoint into a /32 NetworkPolicy destination. A block
# that reaches an instance only through these is not a client. Each must stay
# the literal "${module.<instance>.primary_endpoint_ip}/32".
NON_CLIENT_LOCALS: dict[str, str] = {
    "governance_valkey_cidr": "NetworkPolicy egress destination of the governance instance.",
    "app_valkey_cidr": "NetworkPolicy egress destination of the app instance.",
}

# The memorystore_valkey input that lists an instance's clients, and the client
# module inputs that follow each switch.
CLIENTS_INPUT = "clients"
AUTH_MODE_INPUT = "redis_auth_mode"
TLS_INPUT = "enable_redis_tls"
CA_INPUT = "redis_ca_pem"

# A floor, so a scanner that finds nothing cannot pass. It is not the client
# list: clients are whatever reads an endpoint.
KNOWN_CLIENTS: dict[str, frozenset[str]] = {
    "module.memorystore_governance": frozenset(
        {"module.gateway", "module.compliance_bridge", "module.reconciliation_worker"}
    ),
    "module.memorystore_app": frozenset({"module.langfuse"}),
}


@dataclass(frozen=True)
class Feature:
    """One switch of an instance, and how it is spelled."""

    key: str  # field of a clients entry
    argument: str  # the memorystore_valkey input that sets the mode
    on: str
    off: str
    label: str


FEATURES = (
    Feature("iam_auth", "authorization_mode", "IAM_AUTH", "AUTH_DISABLED", "IAM auth"),
    Feature(
        "tls",
        "transit_encryption_mode",
        "SERVER_AUTHENTICATION",
        "TRANSIT_ENCRYPTION_DISABLED",
        "TLS",
    ),
)


# ─── HCL lexing: strings, templates, heredocs and comments ────────────────────

_OPEN = {"{": "}", "[": "]", "(": ")"}
_HEREDOC = re.compile(r"<<-?([A-Za-z_][A-Za-z0-9_]*)[ \t]*\r?\n")


def _heredoc_end(text: str, i: int) -> int | None:
    """Index of the newline that ends the heredoc opening at ``text[i]``, or None."""
    m = _HEREDOC.match(text, i)
    if not m:
        return None
    pos = m.end()
    while True:
        nl = text.find("\n", pos)
        line = text[pos:] if nl == -1 else text[pos:nl]
        if line.strip() == m.group(1):
            return len(text) if nl == -1 else nl
        if nl == -1:
            raise AssertionError(f"unterminated heredoc {m.group(1)!r}")
        pos = nl + 1


def _string_end(text: str, i: int) -> int:
    """Index just past the quoted template that opens at ``text[i]``."""
    i += 1
    while i < len(text):
        c = text[i]
        if c == "\\":
            i += 2
        elif c == '"':
            return i + 1
        elif c in "$%" and text.startswith(c + c + "{", i):
            i += 3
        elif c in "$%" and text.startswith(c + "{", i):
            i = _close(text, i + 1) + 1
        else:
            i += 1
    raise AssertionError("unterminated string")


def _close(text: str, i: int) -> int:
    """Index of the bracket that closes the one at ``text[i]``."""
    stack = [_OPEN[text[i]]]
    i += 1
    while i < len(text):
        c = text[i]
        if c == '"':
            i = _string_end(text, i)
            continue
        if c == "<" and (end := _heredoc_end(text, i)) is not None:
            i = end
            continue
        if c in _OPEN:
            stack.append(_OPEN[c])
        elif c in "}])":
            if c != stack.pop():
                raise AssertionError(
                    f"mismatched {c!r} near {text[max(0, i - 60) : i + 1]!r}"
                )
            if not stack:
                return i
        i += 1
    raise AssertionError("unbalanced brackets")


def _strip_comments(text: str) -> str:
    """``text`` with its comments blanked and every other character in place."""
    out: list[str] = []
    i = 0
    while i < len(text):
        c = text[i]
        if c == '"':
            end = _string_end(text, i)
        elif c == "<" and (heredoc := _heredoc_end(text, i)) is not None:
            end = heredoc
        elif c == "#" or text.startswith("//", i):
            nl = text.find("\n", i)
            end = len(text) if nl == -1 else nl
            out.append(" " * (end - i))
            i = end
            continue
        elif text.startswith("/*", i):
            close = text.find("*/", i + 2)
            if close == -1:
                raise AssertionError("unterminated /* comment")
            out.append(re.sub(r"[^\n]", " ", text[i : close + 2]))
            i = close + 2
            continue
        else:
            end = i + 1
        out.append(text[i:end])
        i = end
    return "".join(out)


def _template_code(template: str) -> str:
    """The expressions interpolated into a template; its literal text dropped."""
    parts: list[str] = []
    i = 0
    while i < len(template):
        c = template[i]
        if c == "\\":
            i += 2
        elif c in "$%" and template.startswith(c + c + "{", i):
            i += 3
        elif c in "$%" and template.startswith(c + "{", i):
            close = _close(template, i + 1)
            parts.append("(" + _code(template[i + 2 : close]) + ")")
            i = close + 1
        else:
            i += 1
    return " ".join(parts)


def _code(text: str) -> str:
    """``text`` with the literal text of its strings and heredocs dropped.

    A quoted map key or an error message that names ``module.x`` is not a
    reference; an interpolation is.
    """
    out: list[str] = []
    i = 0
    while i < len(text):
        c = text[i]
        if c == '"':
            end = _string_end(text, i)
            out.append(" " + _template_code(text[i + 1 : end - 1]) + " ")
            i = end
        elif c == "<" and (end := _heredoc_end(text, i)) is not None:
            header = _HEREDOC.match(text, i)
            assert header is not None
            out.append(" " + _template_code(text[header.end() : end]) + " ")
            i = end
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _unwrap(expr: str) -> str:
    """``expr`` without surrounding whitespace and redundant outer parentheses."""
    expr = expr.strip()
    while expr.startswith("(") and _close(expr, 0) == len(expr) - 1:
        expr = expr[1:-1].strip()
    return expr


def _norm(expr: str) -> str:
    """A whitespace-free form of ``expr``, for comparing two expressions."""
    return _unwrap(re.sub(r"\s+", "", expr))


def _string_literal(expr: str) -> str | None:
    """The value of a quoted string with no interpolation, else None."""
    expr = _unwrap(expr)
    if len(expr) >= 2 and expr[0] == '"' and _string_end(expr, 0) == len(expr):
        inner = expr[1:-1]
        if "${" not in inner and "%{" not in inner:
            return inner
    return None


def _conditional(expr: str) -> tuple[str, str, str] | None:
    """``(condition, if_true, if_false)`` of a top-level ``a ? b : c``."""
    expr = _unwrap(expr)
    question: int | None = None
    pending = 0
    i = 0
    while i < len(expr):
        c = expr[i]
        if c == '"':
            i = _string_end(expr, i)
            continue
        if c == "<" and (end := _heredoc_end(expr, i)) is not None:
            i = end
            continue
        if c in _OPEN:
            i = _close(expr, i) + 1
            continue
        if c == "?":
            if question is None:
                question = i
            else:
                pending += 1
        elif c == ":" and question is not None:
            if pending == 0:
                return (
                    _unwrap(expr[:question]),
                    _unwrap(expr[question + 1 : i]),
                    _unwrap(expr[i + 1 :]),
                )
            pending -= 1
        i += 1
    return None


# ─── Blocks, attributes and object literals ───────────────────────────────────


@dataclass(frozen=True)
class Attribute:
    value: str
    start: int
    end: int


@dataclass(frozen=True)
class Body:
    attributes: dict[str, Attribute]
    blocks: list[tuple[str, tuple[str, ...], str]]  # (type, labels, body)


_KEY = re.compile(r'"((?:[^"\\]|\\.)*)"|([A-Za-z0-9_][A-Za-z0-9_-]*)')


def _expr_end(text: str, i: int) -> int:
    """Where the expression at ``text[i]`` ends: a newline or comma at depth 0."""
    while i < len(text):
        c = text[i]
        if c == '"':
            i = _string_end(text, i)
        elif c == "<" and (end := _heredoc_end(text, i)) is not None:
            i = end
        elif c in _OPEN:
            i = _close(text, i) + 1
        elif c in "\n,":
            return i
        else:
            i += 1
    return len(text)


def _parse_body(body: str) -> Body:
    """The depth-0 attributes and nested blocks of a block body or object literal."""
    attributes: dict[str, Attribute] = {}
    blocks: list[tuple[str, tuple[str, ...], str]] = []
    i = 0
    while i < len(body):
        if body[i] in " \t\r\n,":
            i += 1
            continue
        m = _KEY.match(body, i)
        if not m:
            raise AssertionError(f"cannot parse HCL at {body[i : i + 60]!r}")
        name = m.group(1) if m.group(1) is not None else m.group(2)
        j = m.end()
        while j < len(body) and body[j] in " \t":
            j += 1
        if j < len(body) and body[j] in "=:" and not body.startswith("==", j):
            end = _expr_end(body, j + 1)
            attributes[name] = Attribute(body[j + 1 : end].strip(), m.start(), end)
            i = end
            continue
        labels: list[str] = []
        while j < len(body) and body[j] != "{":
            if body[j] == '"':
                end = _string_end(body, j)
                labels.append(body[j + 1 : end - 1])
                j = end
            elif body[j] in " \t":
                j += 1
            else:
                raise AssertionError(
                    f"cannot parse HCL block header at {body[i : j + 40]!r}"
                )
        close = _close(body, j)
        blocks.append((name, tuple(labels), body[j + 1 : close]))
        i = close + 1
    return Body(attributes, blocks)


def _object(expr: str) -> dict[str, Attribute] | None:
    """The items of an object literal ``{ key = value ... }``, or None."""
    expr = _unwrap(expr)
    if not expr.startswith("{") or _close(expr, 0) != len(expr) - 1:
        return None
    return _parse_body(expr[1:-1]).attributes


@dataclass(frozen=True)
class Block:
    file: str
    kind: str
    labels: tuple[str, ...]
    body: str

    @property
    def address(self) -> str:
        if self.kind == "resource":
            return ".".join(self.labels)
        if self.kind == "module":
            return f"module.{self.labels[0]}"
        if self.kind == "variable":
            return f"var.{self.labels[0]}"
        return ".".join((self.kind, *self.labels))

    @cached_property
    def parsed(self) -> Body:
        return _parse_body(self.body)


_HEADER = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)((?:[ \t]+"[^"\n]*")*)[ \t]*\{')


def _blocks(path: Path) -> list[Block]:
    text = _strip_comments(path.read_text(encoding="utf-8"))
    blocks: list[Block] = []
    i = 0
    while i < len(text):
        if text[i].isspace():
            i += 1
            continue
        m = _HEADER.match(text, i)
        if not m:
            raise AssertionError(
                f"{path}: cannot parse top-level HCL at {text[i : i + 60]!r}"
            )
        close = _close(text, m.end() - 1)
        labels = tuple(re.findall(r'"([^"]*)"', m.group(2)))
        blocks.append(Block(path.name, m.group(1), labels, text[m.end() : close]))
        i = close + 1
    return blocks


def _preconditions(block: Block) -> list[str]:
    """The ``condition`` of every lifecycle precondition on ``block``."""
    found: list[str] = []
    for kind, _, lifecycle in block.parsed.blocks:
        if kind == "lifecycle":
            for inner, _, precondition in _parse_body(lifecycle).blocks:
                condition = _parse_body(precondition).attributes.get("condition")
                if inner == "precondition" and condition is not None:
                    found.append(condition.value)
    return found


# ─── The configuration under test ─────────────────────────────────────────────

_MODULE_REF = re.compile(
    r"(?<![\w.])module\.([A-Za-z_][\w-]*)(?:\[[^\]]*\])?(?:\.([A-Za-z_][\w-]*))?"
)
_LOCAL_REF = re.compile(r"(?<![\w.])local\.([A-Za-z_][\w-]*)")
_PROFILE_SETTING = re.compile(r"(?m)^([a-z_][a-z0-9_]*)[ \t]*=[ \t]*(true|false)\b")


@dataclass
class Config:
    target_dir: Path
    blocks: list[Block]
    locals: dict[str, str]
    instances: dict[str, Block] = field(default_factory=dict)
    module_cache: dict[Path, list[Block]] = field(default_factory=dict)

    def block(self, address: str) -> Block | None:
        return next((b for b in self.blocks if b.address == address), None)

    def module_dir(self, block: Block, base: Path | None = None) -> Path | None:
        source = _string_literal(block.parsed.attributes["source"].value) or ""
        if not source.startswith(("./", "../")):
            return None
        return ((base or self.target_dir) / source).resolve()

    def module_blocks(self, module_dir: Path) -> list[Block]:
        if module_dir not in self.module_cache:
            self.module_cache[module_dir] = [
                block
                for path in sorted(module_dir.glob("*.tf"))
                for block in _blocks(path)
            ]
        return self.module_cache[module_dir]


def _load(infra_dir: Path) -> Config:
    target_dir = infra_dir / TARGET_DIR
    blocks = [b for path in sorted(target_dir.glob("*.tf")) for b in _blocks(path)]
    local_values: dict[str, str] = {}
    for block in blocks:
        if block.kind == "locals":
            for name, attribute in block.parsed.attributes.items():
                assert name not in local_values, f"local.{name} is defined twice"
                local_values[name] = attribute.value
    config = Config(target_dir, blocks, local_values)
    for block in blocks:
        if block.kind == "module":
            module_dir = config.module_dir(block)
            if module_dir is not None and module_dir.name == INSTANCE_MODULE:
                config.instances[block.address] = block
    return config


def _resolve(config: Config, expr: str, depth: int = 0) -> str:
    """``expr`` with every whole ``local.<name>`` replaced by its definition."""
    assert depth < 32, f"locals nest too deep while resolving {expr!r}"

    def substitute(m: re.Match[str]) -> str:
        name = m.group(1)
        if expr[m.end() : m.end() + 1] in (".", "[") or name not in config.locals:
            return m.group(0)
        return "(" + _resolve(config, config.locals[name], depth + 1) + ")"

    return _LOCAL_REF.sub(substitute, expr)


def _reads(
    config: Config,
    code: str,
    local_edges: dict[str, set[tuple[str, str]]],
    problems: list[str],
    where: str,
) -> set[tuple[str, str]]:
    """``(instance, via)`` for every instance whose connection material ``code`` reads."""
    edges: set[tuple[str, str]] = set()
    for m in _MODULE_REF.finditer(code):
        instance = f"module.{m.group(1)}"
        if instance not in config.instances:
            continue
        output = m.group(2)
        if output is None:
            edges.add((instance, instance))
        elif output in CONNECTION_OUTPUTS:
            edges.add((instance, f"{instance}.{output}"))
        elif output not in METADATA_OUTPUTS:
            problems.append(
                f"{where} reads {instance}.{output}, which is in neither "
                "CONNECTION_OUTPUTS nor METADATA_OUTPUTS: classify it."
            )
    for m in _LOCAL_REF.finditer(code):
        name = m.group(1)
        if name not in NON_CLIENT_LOCALS:
            edges |= {
                (instance, f"local.{name}")
                for instance, _ in local_edges.get(name, set())
            }
    return edges


def _local_edges(
    config: Config, problems: list[str]
) -> dict[str, set[tuple[str, str]]]:
    """For every local, the instances whose connection material it carries."""
    edges: dict[str, set[tuple[str, str]]] = {}
    uses: dict[str, set[str]] = {}
    for name, expr in config.locals.items():
        code = _code(expr)
        edges[name] = _reads(config, code, {}, problems, f"local.{name}")
        uses[name] = {
            m.group(1)
            for m in _LOCAL_REF.finditer(code)
            if m.group(1) in config.locals and m.group(1) not in NON_CLIENT_LOCALS
        }
    changed = True
    while changed:
        changed = False
        for name, used in uses.items():
            for other in used:
                if not edges[other] <= edges[name]:
                    edges[name] |= edges[other]
                    changed = True
    return edges


def _module_reads(config: Config, module_dir: Path, variable: str) -> bool:
    """True when the module declares ``var.<variable>`` and reads it."""
    blocks = config.module_blocks(module_dir)
    declared = any(b.kind == "variable" and b.labels == (variable,) for b in blocks)
    pattern = re.compile(rf"(?<![\w.])var\.{re.escape(variable)}\b")
    return declared and any(
        b.kind != "variable" and pattern.search(_code(b.body)) for b in blocks
    )


def _instance_resource(config: Config, instance: Block) -> Block | None:
    module_dir = config.module_dir(instance)
    assert module_dir is not None
    return next(
        (
            b
            for b in config.module_blocks(module_dir)
            if b.kind == "resource" and b.labels[0] in MEMORYSTORE_RESOURCE_TYPES
        ),
        None,
    )


def _module_refuses(config: Config, instance: Block, feature: Feature) -> bool:
    """The instance resource has a precondition weighing the mode against clients."""
    resource = _instance_resource(config, instance)
    needed = {f"var.{CLIENTS_INPUT}", f"var.{feature.argument}"}
    return resource is not None and any(
        needed <= set(re.findall(r"(?<![\w.])var\.\w+", _code(condition)))
        for condition in _preconditions(resource)
    )


def _profiles_turning_on(config: Config, switch: str) -> list[str] | None:
    """The committed profiles that turn ``switch`` on, or None if it is not a variable."""
    m = re.fullmatch(r"var\.(\w+)", switch)
    if m is None:
        return None
    variable = config.block(f"var.{m.group(1)}")
    default = variable.parsed.attributes.get("default") if variable else None
    profiles: list[str] = []
    for path in sorted(config.target_dir.glob("*.tfvars")):
        settings = dict(
            _PROFILE_SETTING.findall(_strip_comments(path.read_text(encoding="utf-8")))
        )
        value = settings.get(m.group(1), default.value if default else "false")
        if value == "true":
            profiles.append(path.name)
    return profiles


# ─── Switches, and what each client can follow ────────────────────────────────


def _instance_switch(
    config: Config, instance: str, feature: Feature
) -> tuple[str | None, str]:
    """The normalized expression that turns ``feature`` on, ``"true"`` or ``"false"``."""
    attribute = config.instances[instance].parsed.attributes.get(feature.argument)
    if attribute is None:
        return None, f"{instance} does not set {feature.argument}: set it explicitly."
    resolved = _resolve(config, attribute.value)
    literal = _string_literal(resolved)
    if literal == feature.on:
        return "true", ""
    if literal == feature.off:
        return "false", ""
    branches = _conditional(resolved)
    if (
        branches
        and _string_literal(branches[1]) == feature.on
        and _string_literal(branches[2]) == feature.off
    ):
        return _norm(branches[0]), ""
    return None, (
        f"{instance}: {feature.argument} = {attribute.value} is neither a literal nor "
        f'<switch> ? "{feature.on}" : "{feature.off}", so this test cannot tell when it is on.'
    )


def _follows(
    config: Config, client: Block, instance: str, feature: Feature, switch: str
) -> tuple[bool, str]:
    """Whether ``client`` follows ``instance``'s ``feature`` switch, and if not, why not."""
    if switch == "false":
        return False, f"{instance} never turns {feature.label} on"
    if client.kind != "module":
        return False, "it is not a module call, so it has no Redis auth or TLS inputs"
    module_dir = config.module_dir(client)
    if module_dir is None:
        return False, "its module source is not a local path"
    arguments = client.parsed.attributes
    needed = (AUTH_MODE_INPUT,) if feature.key == "iam_auth" else (TLS_INPUT, CA_INPUT)
    for name in needed:
        if name not in arguments:
            return False, f"it is given no {name}"

    if feature.key == "iam_auth":
        raw = arguments[AUTH_MODE_INPUT].value
        resolved = _resolve(config, raw)
        if switch == "true":
            follows = _string_literal(resolved) == "iam"
        else:
            branches = _conditional(resolved)
            follows = bool(
                branches
                and _norm(branches[0]) == switch
                and _string_literal(branches[1]) == "iam"
                and _string_literal(branches[2]) == "none"
            )
        if not follows:
            return (
                False,
                f'its {AUTH_MODE_INPUT} = {raw} is not "iam" exactly when {switch} is on',
            )
    else:
        raw_tls = arguments[TLS_INPUT].value
        tls = _resolve(config, raw_tls)
        branches = _conditional(tls)
        if not (
            _norm(tls) == switch
            or (
                branches
                and _norm(branches[0]) == switch
                and _norm(branches[1]) == "true"
                and _norm(branches[2]) == "false"
            )
        ):
            return False, f"its {TLS_INPUT} = {raw_tls} does not follow {switch}"
        raw_ca = arguments[CA_INPUT].value
        carried = _resolve(config, raw_ca)
        if switch != "true":
            branches = _conditional(carried)
            if not (
                branches
                and _norm(branches[0]) == switch
                and _string_literal(branches[2]) == ""
            ):
                return False, f'its {CA_INPUT} = {raw_ca} is not {switch} ? <CA> : ""'
            carried = branches[1]
        cas = {
            (f"module.{m.group(1)}", m.group(2))
            for m in _MODULE_REF.finditer(_code(carried))
            if f"module.{m.group(1)}" in config.instances
        }
        if cas != {(instance, "managed_server_ca")}:
            return (
                False,
                f"its {CA_INPUT} does not carry {instance}.managed_server_ca alone",
            )

    for name in needed:
        if not _module_reads(config, module_dir, name):
            return False, f"its module ({module_dir.name}) never reads var.{name}"
    return True, ""


# ─── The audit ────────────────────────────────────────────────────────────────


@dataclass
class Audit:
    clients: dict[str, dict[str, set[str]]] = field(default_factory=dict)
    lockouts: list[str] = field(default_factory=list)
    lists: list[str] = field(default_factory=list)
    enforcement: list[str] = field(default_factory=list)
    classification: list[str] = field(default_factory=list)


def _classify(
    config: Config, edges_by_block: dict[str, set[tuple[str, str]]], audit: Audit
) -> None:
    """Every reader is classified, and no Memorystore instance hides elsewhere."""
    outputs: dict[str, str] = {}
    for instance in config.instances.values():
        module_dir = config.module_dir(instance)
        assert module_dir is not None
        for block in config.module_blocks(module_dir):
            if block.kind == "output":
                value = block.parsed.attributes.get("value")
                outputs[block.labels[0]] = _code(value.value) if value else ""
    for name in sorted(set(outputs) - CONNECTION_OUTPUTS - METADATA_OUTPUTS):
        audit.classification.append(
            f"{INSTANCE_MODULE} output {name!r} is in neither CONNECTION_OUTPUTS nor "
            "METADATA_OUTPUTS: classify it, or the blocks reading it escape this test."
        )
    if config.instances:
        for name in sorted((CONNECTION_OUTPUTS | METADATA_OUTPUTS) - set(outputs)):
            audit.classification.append(
                f"{INSTANCE_MODULE} has no output {name!r} any more: drop it."
            )
    for name in sorted(CONNECTION_OUTPUTS & set(outputs)):
        if not re.search(
            r"\b(?:" + "|".join(MEMORYSTORE_RESOURCE_TYPES) + r")\.", outputs[name]
        ):
            audit.enforcement.append(
                f"{INSTANCE_MODULE} output {name!r} does not derive from the instance "
                "resource, so a plan targeted at a client reading it skips the "
                "instance's preconditions."
            )

    for block in config.blocks:
        if block.kind == "resource" and block.labels[0] in MEMORYSTORE_RESOURCE_TYPES:
            audit.classification.append(
                f"{block.file}: {block.address} bypasses {INSTANCE_MODULE}."
            )
    todo = [
        (block, config.target_dir, True)
        for block in config.blocks
        if block.kind == "module"
    ]
    scanned: set[Path] = set()
    while todo:
        call, base, at_root = todo.pop()
        module_dir = config.module_dir(call, base)
        if module_dir is None:
            continue
        if module_dir.name == INSTANCE_MODULE:
            if not at_root:
                audit.classification.append(
                    f"{call.address} in {base.name} wraps {INSTANCE_MODULE}; its clients escape this test."
                )
            continue
        if module_dir in scanned:
            continue
        scanned.add(module_dir)
        for block in config.module_blocks(module_dir):
            if (
                block.kind == "resource"
                and block.labels[0] in MEMORYSTORE_RESOURCE_TYPES
            ):
                audit.classification.append(
                    f"{call.address} instantiates modules/{module_dir.name}, which creates "
                    f"{block.address}: only {INSTANCE_MODULE} instances are checked."
                )
            if block.kind == "module":
                todo.append((block, module_dir, False))

    for address, reason in NON_CLIENT_BLOCKS.items():
        block = config.block(address)
        if block is None or not edges_by_block.get(address):
            audit.classification.append(
                f"NON_CLIENT_BLOCKS lists {address}, which reads no Memorystore endpoint: drop it."
            )
            continue
        is_guard = (
            block.kind == "resource"
            and block.labels[0] in ("terraform_data", "null_resource")
            and not any(kind == "provisioner" for kind, _, _ in block.parsed.blocks)
        )
        if block.kind not in ("output", "check") and not is_guard:
            audit.classification.append(
                f"NON_CLIENT_BLOCKS lists {address} ({reason}), but only outputs, checks "
                "and guards can read an endpoint without connecting to it."
            )
    for name in NON_CLIENT_LOCALS:
        value = _unwrap(config.locals.get(name, ""))
        if not any(
            value == f'"${{{instance}.primary_endpoint_ip}}/32"'
            for instance in config.instances
        ):
            audit.classification.append(
                f"NON_CLIENT_LOCALS lists local.{name}, which is not "
                '"${module.<instance>.primary_endpoint_ip}/32".'
            )


def _declared_clients(
    instance: str, block: Block, audit: Audit
) -> dict[str, Attribute] | None:
    attribute = block.parsed.attributes.get(CLIENTS_INPUT)
    declared = _object(attribute.value) if attribute else None
    if declared is None:
        audit.lists.append(
            f"{instance} must pass {CLIENTS_INPUT} as an object literal, so its clients can be read."
        )
    return declared


def audit_memorystore_clients(infra_dir: Path) -> Audit:
    """Find every Memorystore client and check it can follow its instance's switches."""
    config = _load(infra_dir)
    audit = Audit()
    local_edges = _local_edges(config, audit.classification)

    edges_by_block: dict[str, set[tuple[str, str]]] = {}
    for block in config.blocks:
        if block.kind in (
            "locals",
            "variable",
            "terraform",
            "moved",
            "removed",
            "import",
        ):
            continue
        body = block.body
        depends_on = block.parsed.attributes.get("depends_on")
        if depends_on is not None:
            body = (
                body[: depends_on.start]
                + " " * (depends_on.end - depends_on.start)
                + body[depends_on.end :]
            )
        edges_by_block.setdefault(block.address, set()).update(
            _reads(
                config, _code(body), local_edges, audit.classification, block.address
            )
        )
    _classify(config, edges_by_block, audit)

    audit.clients = {instance: {} for instance in config.instances}
    for address, edges in edges_by_block.items():
        if address not in NON_CLIENT_BLOCKS:
            for instance, via in edges:
                audit.clients[instance].setdefault(address, set()).add(via)

    for instance, clients in audit.clients.items():
        instance_block = config.instances[instance]
        listed = f"{instance}'s {CLIENTS_INPUT}"
        declared = _declared_clients(instance, instance_block, audit)
        entries: dict[str, dict[str, Attribute] | None] = {}
        if declared is not None:
            for address in sorted(set(declared) - set(clients)):
                audit.lists.append(
                    f"{listed} lists {address}, but it reads no endpoint of {instance}."
                )
            for address in sorted(set(clients) - set(declared)):
                audit.lists.append(
                    f"{address} reads {instance} but {listed} has no entry for it."
                )
            for address in sorted(set(clients) & set(declared)):
                entries[address] = _object(declared[address].value)
                if entries[address] is None:
                    audit.lists.append(
                        f"{listed}[{address}] must be an object literal."
                    )

        for feature in FEATURES:
            refuses = _module_refuses(config, instance_block, feature)
            if not refuses:
                audit.enforcement.append(
                    f"{instance}'s module does not refuse {feature.argument} = "
                    f"{feature.on} while one of its {CLIENTS_INPUT} cannot follow it."
                )
            switch, problem = _instance_switch(config, instance, feature)
            if switch is None:
                audit.lockouts.append(problem)
                continue

            for address in sorted(clients):
                client = config.block(address)
                assert client is not None, address
                follows, reason = _follows(config, client, instance, feature, switch)
                entry = entries.get(address)
                declared_value = entry.get(feature.key) if entry else None
                if entry is not None:
                    if declared_value is None or declared_value.value not in (
                        "true",
                        "false",
                    ):
                        audit.lists.append(
                            f"{listed}[{address}].{feature.key} must be a literal true or false."
                        )
                    elif (declared_value.value == "true") != follows:
                        claim = "can" if declared_value.value == "true" else "cannot"
                        why = reason if not follows else f"its wiring follows {switch}"
                        audit.lists.append(
                            f"{listed} says {address} {claim} follow its {feature.label}, but {why}."
                        )
                if follows or switch == "false":
                    continue

                refusal: list[str] = []
                if declared is None:
                    refusal.append(f"{instance} lists no {CLIENTS_INPUT}")
                elif entry is None:
                    refusal.append(f"{listed} has no entry for it")
                elif declared_value is None or declared_value.value != "false":
                    refusal.append(f"{listed} does not record it as unable")
                if not refuses:
                    refusal.append(
                        f"the module does not refuse {feature.on} for such a client"
                    )
                if refusal:
                    audit.lockouts.append(
                        f"{address} reads {instance} ({', '.join(sorted(clients[address]))}) but "
                        f"cannot follow its {feature.label} switch {switch}: {reason}. Nothing "
                        f"refuses that switch at plan time while it cannot: {'; '.join(refusal)}."
                    )
                    continue
                profiles = _profiles_turning_on(config, switch)
                if switch == "true":
                    audit.lockouts.append(
                        f"{instance} always turns {feature.label} on and refuses it while "
                        f"{address} cannot follow it ({reason}), so no profile can plan."
                    )
                elif profiles:
                    audit.lockouts.append(
                        f"{', '.join(profiles)} cannot plan: {switch} is on there, and "
                        f"{instance} refuses that while {address} cannot follow its "
                        f"{feature.label} ({reason})."
                    )
    return audit


# ─── Repository contract ──────────────────────────────────────────────────────


def _report(problems: list[str]) -> str:
    return "\n- " + "\n- ".join(problems)


def test_discovery_finds_the_instances_and_their_known_clients() -> None:
    audit = audit_memorystore_clients(INFRA_DIR)
    assert set(KNOWN_CLIENTS) <= set(audit.clients), sorted(audit.clients)
    for instance, floor in KNOWN_CLIENTS.items():
        assert floor <= set(audit.clients[instance]), (
            instance,
            sorted(audit.clients[instance]),
        )


def test_every_reader_of_a_memorystore_instance_is_classified() -> None:
    problems = audit_memorystore_clients(INFRA_DIR).classification
    assert not problems, _report(problems)


def test_no_client_is_locked_out_by_its_instance() -> None:
    """The #788 failure: a switch that can be on, and a client that cannot follow it."""
    problems = audit_memorystore_clients(INFRA_DIR).lockouts
    assert not problems, _report(problems)


def test_every_instance_lists_its_clients_as_they_are_wired() -> None:
    problems = audit_memorystore_clients(INFRA_DIR).lists
    assert not problems, _report(problems)


def test_every_instance_refuses_a_mode_a_client_cannot_follow() -> None:
    problems = audit_memorystore_clients(INFRA_DIR).enforcement
    assert not problems, _report(problems)


# ─── Planted drift: each must fail the audit ──────────────────────────────────


def _copy_infra(tmp_path: Path) -> Path:
    destination = tmp_path / "infra"
    shutil.copytree(
        INFRA_DIR,
        destination,
        ignore=shutil.ignore_patterns(".terraform", "*.tfstate*"),
    )
    return destination


def _edit(path: Path, old: str, new: str, within: str | None = None) -> None:
    """Replace the one ``old`` in ``path``, or in its top-level block headed ``within``.

    Both are found in the comment-blanked text, which keeps every offset.
    """
    text = path.read_text(encoding="utf-8")
    code = _strip_comments(text)
    start, end = 0, len(text)
    if within is not None:
        start = code.index(within)
        end = _close(code, start + len(within) - 1)
    hits = [start + m.start() for m in re.finditer(re.escape(old), code[start:end])]
    assert len(hits) == 1, (
        f"expected exactly one {old!r} in {path.name}, found {len(hits)}"
    )
    path.write_text(
        text[: hits[0]] + new + text[hits[0] + len(old) :], encoding="utf-8"
    )


def _append(path: Path, text: str) -> None:
    path.write_text(path.read_text(encoding="utf-8") + text, encoding="utf-8")


def test_planted_788_coupling_is_caught(tmp_path: Path) -> None:
    """Drive the app instance from the governance switches again, list intact."""
    infra = _copy_infra(tmp_path)
    main_tf = infra / TARGET_DIR / "main.tf"
    app = 'module "memorystore_app" {'
    _edit(
        main_tf,
        "var.enable_memorystore_app_iam_auth ?",
        "var.enable_memorystore_iam_auth ?",
        within=app,
    )
    _edit(
        main_tf,
        "var.enable_memorystore_app_tls ?",
        "var.enable_memorystore_tls ?",
        within=app,
    )
    audit = audit_memorystore_clients(infra)
    for switch, label in (
        ("var.enable_memorystore_iam_auth", "IAM auth"),
        ("var.enable_memorystore_tls", "TLS"),
    ):
        assert any(
            "staging.tfvars" in p
            and f"cannot plan: {switch} is on there, and module.memorystore_app refuses that "
            f"while module.langfuse cannot follow its {label}"
            in p
            for p in audit.lockouts
        ), audit.lockouts


def test_planted_788_configuration_is_caught(tmp_path: Path) -> None:
    """The #788 configuration itself: governance switches, and no clients list."""
    infra = _copy_infra(tmp_path)
    main_tf = infra / TARGET_DIR / "main.tf"
    app = 'module "memorystore_app" {'
    _edit(
        main_tf,
        "var.enable_memorystore_app_iam_auth ?",
        "var.enable_memorystore_iam_auth ?",
        within=app,
    )
    _edit(
        main_tf,
        "var.enable_memorystore_app_tls ?",
        "var.enable_memorystore_tls ?",
        within=app,
    )
    _edit(
        main_tf,
        '  clients = {\n    "module.langfuse" = { iam_auth = false, tls = false }\n  }\n',
        "",
        within=app,
    )
    audit = audit_memorystore_clients(infra)
    assert (
        "module.langfuse reads module.memorystore_app (module.memorystore_app.primary_endpoint_ip, "
        "module.memorystore_app.primary_endpoint_port) but cannot follow its IAM auth switch "
        "var.enable_memorystore_iam_auth: it is given no redis_auth_mode. Nothing refuses that "
        "switch at plan time while it cannot: module.memorystore_app lists no clients."
        in audit.lockouts
    ), audit.lockouts
    assert (
        "module.memorystore_app must pass clients as an object literal, so its clients can be read."
        in audit.lists
    )


def test_planted_new_client_through_a_chain_of_locals_is_caught(tmp_path: Path) -> None:
    infra = _copy_infra(tmp_path)
    (infra / TARGET_DIR / "planted_cache.tf").write_text(
        """locals {
  planted_cache_host = module.memorystore_app.primary_endpoint_ip
  planted_cache_url  = "redis://${local.planted_cache_host}:6379"
}

resource "kubernetes_deployment_v1" "planted_cache_reader" {
  metadata {
    name = "planted-cache-reader"
  }
  spec {
    template {
      spec {
        container {
          name = "reader"
          env {
            name  = "REDIS_URL"
            value = local.planted_cache_url
          }
        }
      }
    }
  }
}
""",
        encoding="utf-8",
    )
    audit = audit_memorystore_clients(infra)
    reader = "kubernetes_deployment_v1.planted_cache_reader"
    assert audit.clients["module.memorystore_app"][reader] == {
        "local.planted_cache_url"
    }
    assert any(
        p.startswith(
            f"{reader} reads module.memorystore_app (local.planted_cache_url) but cannot follow its IAM auth"
        )
        for p in audit.lockouts
    ), audit.lockouts
    assert (
        f"{reader} reads module.memorystore_app but module.memorystore_app's clients has no entry for it."
        in audit.lists
    )


def test_planted_governance_client_without_auth_wiring_is_caught(
    tmp_path: Path,
) -> None:
    infra = _copy_infra(tmp_path)
    _append(
        infra / TARGET_DIR / "main.tf",
        """
module "planted_worker" {
  source = "../../modules/reconciliation_worker"

  redis_url = "redis://${module.memorystore_governance.primary_endpoint_ip}:6379"
}
""",
    )
    audit = audit_memorystore_clients(infra)
    for switch, missing in (
        ("var.enable_memorystore_iam_auth", "redis_auth_mode"),
        ("var.enable_memorystore_tls", "enable_redis_tls"),
    ):
        assert any(
            p.startswith("module.planted_worker reads module.memorystore_governance")
            and f"switch {switch}: it is given no {missing}." in p
            for p in audit.lockouts
        ), audit.lockouts


def test_planted_lying_clients_entry_is_caught(tmp_path: Path) -> None:
    """Claiming Langfuse can do IAM auth would let the instance admit the lockout."""
    infra = _copy_infra(tmp_path)
    _edit(
        infra / TARGET_DIR / "main.tf",
        '"module.langfuse" = { iam_auth = false, tls = false }',
        '"module.langfuse" = { iam_auth = true, tls = false }',
    )
    audit = audit_memorystore_clients(infra)
    assert (
        "module.memorystore_app's clients says module.langfuse can follow its IAM auth, "
        "but it is given no redis_auth_mode." in audit.lists
    ), audit.lists
    assert any(
        p.startswith("module.langfuse reads module.memorystore_app")
        for p in audit.lockouts
    ), audit.lockouts


def test_planted_dead_module_input_is_caught(tmp_path: Path) -> None:
    """A root argument the module never reads does not make its client follow."""
    infra = _copy_infra(tmp_path)
    gateway_tf = infra / "modules" / "gateway" / "main.tf"
    text = gateway_tf.read_text(encoding="utf-8")
    gateway_tf.write_text(
        re.sub(r"\bvar\.redis_auth_mode\b", '"none"', text), encoding="utf-8"
    )
    audit = audit_memorystore_clients(infra)
    assert (
        "module.memorystore_governance's clients says module.gateway can follow its IAM auth, "
        "but its module (gateway) never reads var.redis_auth_mode." in audit.lists
    ), audit.lists


def test_planted_ca_of_the_wrong_instance_is_caught(tmp_path: Path) -> None:
    infra = _copy_infra(tmp_path)
    _edit(
        infra / TARGET_DIR / "main.tf",
        "module.memorystore_governance.managed_server_ca",
        "module.memorystore_app.managed_server_ca",
        within='module "gateway" {',
    )
    audit = audit_memorystore_clients(infra)
    assert (
        "module.memorystore_governance's clients says module.gateway can follow its TLS, but its "
        "redis_ca_pem does not carry module.memorystore_governance.managed_server_ca alone."
        in audit.lists
    ), audit.lists


def test_planted_dropped_module_refusal_is_caught(tmp_path: Path) -> None:
    infra = _copy_infra(tmp_path)
    module_tf = infra / "modules" / INSTANCE_MODULE / "main.tf"
    text = _strip_comments(module_tf.read_text(encoding="utf-8"))
    m = re.search(
        r"\n\s*precondition \{\s*condition\s*=\s*var\.authorization_mode", text
    )
    assert m is not None
    end = _close(text, text.index("{", m.start()))
    module_tf.write_text(text[: m.start()] + text[end + 1 :], encoding="utf-8")
    audit = audit_memorystore_clients(infra)
    assert any(
        p.startswith(
            "module.memorystore_app's module does not refuse authorization_mode = IAM_AUTH"
        )
        for p in audit.enforcement
    ), audit.enforcement
    assert any(
        p.startswith("module.langfuse reads module.memorystore_app")
        and "the module does not refuse IAM_AUTH" in p
        for p in audit.lockouts
    ), audit.lockouts


def test_planted_profile_turning_on_a_refused_switch_is_caught(tmp_path: Path) -> None:
    """The next #788 may come from a profile rather than from main.tf."""
    infra = _copy_infra(tmp_path)
    _append(infra / TARGET_DIR / "prod.tfvars", "\nenable_memorystore_app_tls = true\n")
    audit = audit_memorystore_clients(infra)
    assert (
        "prod.tfvars cannot plan: var.enable_memorystore_app_tls is on there, and "
        "module.memorystore_app refuses that while module.langfuse cannot follow its TLS "
        "(it is given no enable_redis_tls)." in audit.lockouts
    ), audit.lockouts


def test_planted_unclassified_readers_are_caught(tmp_path: Path) -> None:
    """A new module output, and a root block reading it, must be classified first."""
    infra = _copy_infra(tmp_path)
    _append(
        infra / "modules" / INSTANCE_MODULE / "outputs.tf",
        '\noutput "reader_endpoint_ip" {\n  value = ""\n}\n',
    )
    _append(
        infra / TARGET_DIR / "outputs.tf",
        '\noutput "planted_app_reader" {\n  value = module.memorystore_app.reader_endpoint_ip\n}\n',
    )
    problems = audit_memorystore_clients(infra).classification
    assert any("output 'reader_endpoint_ip' is in neither" in p for p in problems), (
        problems
    )
    assert any(
        p.startswith(
            "output.planted_app_reader reads module.memorystore_app.reader_endpoint_ip"
        )
        for p in problems
    ), problems


def test_planted_memorystore_outside_the_module_is_caught(tmp_path: Path) -> None:
    infra = _copy_infra(tmp_path)
    _append(
        infra / TARGET_DIR / "main.tf",
        '\nmodule "planted_redis" {\n  source = "../../modules/memorystore_redis"\n}\n',
    )
    problems = audit_memorystore_clients(infra).classification
    assert any(
        p.startswith("module.planted_redis instantiates modules/memorystore_redis")
        for p in problems
    ), problems


def test_non_client_entries_cannot_hide_a_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only outputs, checks and guards may be non-clients, and only /32 locals."""
    monkeypatch.setitem(NON_CLIENT_BLOCKS, "module.langfuse", "planted")
    monkeypatch.setitem(NON_CLIENT_LOCALS, "evidence_stream_redis_url", "planted")
    problems = audit_memorystore_clients(INFRA_DIR).classification
    assert any(
        p.startswith("NON_CLIENT_BLOCKS lists module.langfuse") for p in problems
    ), problems
    assert any(
        p.startswith("NON_CLIENT_LOCALS lists local.evidence_stream_redis_url")
        for p in problems
    ), problems

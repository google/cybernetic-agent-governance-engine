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

"""Hold each Active row of ``compliance/lula/README.md`` to its manifest's Rego.

An Active row is the README's statement of what a manifest checks, and only a
manifest rated Active may back a POA&M closure. ``#664`` (``372daad2``) migrated
all 33 manifests to the Lula v0.16 schema and, in the same diff, removed
assertions from six Active manifests without touching their rows, headers or
the closures that cited them. Nothing compared what each manifest asserted
before and after the change.

For every Active row this file enforces two things:

* every backticked snake_case name in the row is a rule the manifest's Rego
  defines, so a row cannot go on naming a rule that has been deleted; and
* every rule the ``validate`` body references directly is named in the row, so
  a rule cannot be swapped into ``validate`` without the row saying so.

It compares names, not bodies. A rule whose name overstates its body passes:
before ``#664``, ``ftra``'s ``terminal_registry_valid`` passed whenever the
gateway existed. Judging what each rule actually checks is still the rating's
job. A ``validate`` that composes no named rules (``cilium-dpv2``) has nothing
to hold its row to.
"""

# Regression coverage binding: POAM-2026-219

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path
from types import ModuleType
from typing import NamedTuple

import pytest
import yaml

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
LULA_DIR = REPO_ROOT / "compliance" / "lula"


def _load(name: str, relpath: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / relpath)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


breakdown_mod = _load(
    "_lula_rating_breakdown_for_description_parity", "scripts/lula_rating_breakdown.py"
)
divergence = _load(
    "_poam_lula_divergence_for_description_parity",
    "scripts/check_poam_lula_divergence.py",
)
stub_count = _load(
    "_lula_stub_count_for_description_parity", "scripts/check_lula_stub_count.py"
)

_MANIFEST_RE = re.compile(r"lula-validation-[A-Za-z0-9_-]+\.yaml")
_BACKTICK_RE = re.compile(r"`([^`]+)`")
_SNAKE_RE = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)+")
# A rule head starts at column 0 of the dedented Rego: a name, optionally after
# ``default``, followed by arguments, a key, an assignment, ``if``, ``contains``
# or a body. ``package`` and ``import`` lines never match.
_RULE_HEAD_RE = re.compile(
    r"^(?:default[ \t]+)?(?P<name>[a-z_][A-Za-z0-9_]*)[ \t]*"
    r"(?=\(|\[|:=|=|\{|\bif\b|\bcontains\b)",
    re.MULTILINE,
)
_VALIDATE_HEAD_RE = re.compile(r"^validate\b[^\n{]*", re.MULTILINE)
# A reference, not a field access: ``metrics_doc.total_traces`` refers to
# ``metrics_doc`` only.
_REFERENCE_RE = re.compile(r"(?<![.\w])[a-z_][A-Za-z0-9_]*\b")


def _strip_strings_and_comments(rego: str) -> str:
    """Blank out string literals and drop comments, keeping line structure."""
    out: list[str] = []
    i, n = 0, len(rego)
    while i < n:
        char = rego[i]
        if char == '"':
            j = i + 1
            while j < n and rego[j] != '"':
                j += 2 if rego[j] == "\\" else 1
            out.append('""')
            i = j + 1
        elif char == "`":
            j = rego.find("`", i + 1)
            out.append('""')
            i = n if j == -1 else j + 1
        elif char == "#":
            j = rego.find("\n", i)
            i = n if j == -1 else j
        else:
            out.append(char)
            i += 1
    return "".join(out)


def _validate_bodies(src: str) -> list[str]:
    bodies: list[str] = []
    for head in _VALIDATE_HEAD_RE.finditer(src):
        start = head.end()
        if start < len(src) and src[start] == "{":
            depth, i = 0, start
            while i < len(src):
                if src[i] == "{":
                    depth += 1
                elif src[i] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                i += 1
            bodies.append(src[start + 1 : i])
        else:
            bodies.append(head.group(0).partition(" if ")[2])
    return bodies


def rules(regos: list[str]) -> tuple[set[str], set[str]]:
    """Return the rules the Rego defines and those ``validate`` references."""
    defined: set[str] = set()
    composed: set[str] = set()
    for rego in regos:
        src = _strip_strings_and_comments(rego)
        names = {match["name"] for match in _RULE_HEAD_RE.finditer(src)}
        names.discard("validate")
        defined |= names
        for body in _validate_bodies(src):
            composed |= set(_REFERENCE_RE.findall(body)) & names
    return defined, composed


def named(row_text: str) -> set[str]:
    """Return the backticked snake_case names in a README row."""
    return {
        token for token in _BACKTICK_RE.findall(row_text) if _SNAKE_RE.fullmatch(token)
    }


def findings(row_text: str, regos: list[str]) -> tuple[set[str], set[str]]:
    """Return (names the row cites that no rule defines, composed rules it omits)."""
    defined, composed = rules(regos)
    cited = named(row_text)
    return cited - defined, composed - cited


def _manifest_regos(name: str) -> list[str]:
    doc = yaml.safe_load((LULA_DIR / name).read_text(encoding="utf-8"))
    regos = stub_count._extract_rego_bodies(doc)
    assert regos, f"{name} carries no Rego"
    return regos


def active_rows(readme_text: str) -> dict[str, str]:
    """Map each manifest the README rates Active to the row text after its rating."""
    marker = breakdown_mod.ACTIVE_MARKER
    rows: dict[str, str] = {}
    for line in readme_text.splitlines():
        if marker in line and "lula-validation-" in line:
            match = _MANIFEST_RE.search(line)
            if match:
                rows[match.group(0)] = line.split(marker, 1)[1]
    return rows


def _readme() -> str:
    return (LULA_DIR / "README.md").read_text(encoding="utf-8")


def test_rows_checked_here_are_the_closure_allowlist() -> None:
    """An Active row this file skipped would be closure evidence nothing holds."""
    allowlist, errors = divergence._load_active_lula_set(REPO_ROOT)
    assert errors == []
    assert set(active_rows(_readme())) == {Path(rel).name for rel in allowlist}


def test_every_active_row_names_exactly_what_its_rego_composes() -> None:
    problems: list[str] = []
    for name, row in sorted(active_rows(_readme()).items()):
        stale, missing = findings(row, _manifest_regos(name))
        if stale:
            problems.append(
                f"{name}: row names rules the Rego does not define: {sorted(stale)}"
            )
        if missing:
            problems.append(
                f"{name}: row omits rules validate composes: {sorted(missing)}"
            )
    assert not problems, "\n".join(problems)


_PLANTED_REGO = """\
package lula

import future.keywords.if

# validate once composed old_rule
kept_rule if {
  input.x == "old_rule"
}

new_rule if {
  input.y == true
}

unused_rule if {
  input.z == true
}

is_positive(x) if { x > 0 }

validate if {
  kept_rule
  new_rule
  input.cfg.unused_rule == true
  "unused_rule" != ""
}
"""


@pytest.mark.parametrize(
    ("row", "expected_stale", "expected_missing"),
    [
        ("asserts `kept_rule` and `new_rule`", set(), set()),
        ("asserts `kept_rule` and `old_rule`", {"old_rule"}, {"new_rule"}),
        ("asserts `kept_rule`, `new_rule` and `is_positive`", set(), set()),
        ("asserts `kept_rule`, `new_rule` and `is_negative`", {"is_negative"}, set()),
        ("asserts `kept_rule`", set(), {"new_rule"}),
    ],
)
def test_planted_rows_report_stale_and_missing_rules(
    row: str, expected_stale: set[str], expected_missing: set[str]
) -> None:
    """A name in a comment, a string or a field access is not a composed rule."""
    assert findings(row, [_PLANTED_REGO]) == (expected_stale, expected_missing)


class _Before664(NamedTuple):
    """What one manifest's ``validate`` composed before ``#664``, split in two."""

    label: str
    kept: frozenset[str]
    deleted: frozenset[str]


#: What each of the six manifests' ``validate`` composed before ``#664``
#: (``git show 372daad2^:compliance/lula/<manifest>``), split into the rules the
#: Rego still defines and the rules ``#664`` deleted. Keyed by the manifest's
#: component-definition UUID. If a manifest later restores a deleted rule under
#: the same name, move it to ``kept``.
_BEFORE_664: dict[str, _Before664] = {
    # lula-validation-ftra.yaml. The terminal registry ConfigMap and interim
    # NetworkPolicies its deleted rules were named for are retired.
    "8c7a4f92-3d5e-4a1b-9c8d-2e6f1b3a5c7d": _Before664(
        label="ftra",
        kept=frozenset({"gateway_exists"}),
        deleted=frozenset(
            {
                "ftra_env_configured",
                "terminal_registry_valid",
                "networkpolicy_or_boundary_enabled",
            }
        ),
    ),
    # lula-validation-eu-fria.yaml
    "2ed0f8fd-6e9e-5bff-870b-a604fcaf8f4d": _Before664(
        label="eu-fria",
        kept=frozenset({"gateway_running"}),
        deleted=frozenset(
            {
                "normative_provider_not_static",
                "normative_endpoint_set",
                "region_is_eu_ecb",
            }
        ),
    ),
    # lula-validation-sc8.yaml
    "0625ad3c-dd04-5999-9bcd-2018ef7828b7": _Before664(
        label="sc8",
        kept=frozenset({"redis_ca_pinned"}),
        deleted=frozenset(
            {
                "services_use_tls",
                "default_deny_exists",
                "ingresses_have_tls",
                "deployments_secure",
            }
        ),
    ),
    # lula-validation-iso001-token-quota.yaml. The policy-content check is back,
    # under a new name (opa_policy_has_quota_rules).
    "0ddb2190-5503-51f2-97c5-1a4ed5e97a1c": _Before664(
        label="iso001-token-quota",
        kept=frozenset(),
        deleted=frozenset(
            {"advisor_running", "advisor_has_redis_url", "advisor_has_quota_markers"}
        ),
    ),
    # lula-validation-tqp007.yaml
    "c0be590a-584c-5103-90a8-1db6bf900941": _Before664(
        label="tqp007",
        kept=frozenset({"tqp_running", "tqp_has_redis_url"}),
        deleted=frozenset({"tqp_fail_closed"}),
    ),
    # lula-validation-flowsignal.yaml (provider_01). #664 also kept its
    # secretKeyRef rule, flowsignal_secrets_use_secretref, which is left out of
    # ``kept`` because Gate G8 keeps partner brands out of code literals.
    "f1025a8c-4d3e-5a99-8b2f-c418e7f92d1a": _Before664(
        label="provider_01",
        kept=frozenset(
            {
                "redis_namespace_no_collision",
                "redis_url_configured",
                "kms_config_present",
            }
        ),
        deleted=frozenset({"normative_provider_configured"}),
    ),
}


def _manifest_by_uuid(uuid: str) -> str:
    """Return the file name of the manifest whose component-definition has ``uuid``."""
    matches = [
        path.name
        for path in sorted(LULA_DIR.glob("lula-validation-*.yaml"))
        if (yaml.safe_load(path.read_text(encoding="utf-8")) or {})
        .get("component-definition", {})
        .get("uuid")
        == uuid
    ]
    assert len(matches) == 1, f"{uuid} matches {matches}"
    return matches[0]


@pytest.mark.parametrize(
    "uuid", sorted(_BEFORE_664), ids=lambda uuid: _BEFORE_664[uuid].label
)
def test_replaying_664_against_this_check_reports_each_removal(uuid: str) -> None:
    """A row naming what ``validate`` composed before ``#664`` fails today.

    Had the rows named their rules before ``#664``, as this file now requires,
    every one of the six would have failed here, including ``eu-fria``'s
    ``region_is_eu_ecb`` and the ``ftra`` rules named for retired resources.
    None of the rules ``#664`` kept is reported.
    """
    before = _BEFORE_664[uuid]
    row = ", ".join(f"`{rule}`" for rule in sorted(before.kept | before.deleted))
    stale, _ = findings(row, _manifest_regos(_manifest_by_uuid(uuid)))
    assert stale == before.deleted

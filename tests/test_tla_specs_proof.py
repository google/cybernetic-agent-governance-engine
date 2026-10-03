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

"""Cfg/spec parity for FtraBoundary.tla and LangGraphHarness.tla (POAM-2026-091).

The hermetic tests catch the failure modes that kept both specs from ever
loading in TLC: cfg constants that the spec does not declare (or vice versa)
and cfg invariants that the spec does not define. Every ``proof/*.cfg`` must
be pinned either in ``proof/distributed_cbf_model.py`` or
``proof/tla_pins.py``. The live test runs TLC when ``TLA_TOOLS_JAR`` is set.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "proof"
sys.path.insert(0, str(ROOT))

from proof.distributed_cbf_model import CONFIGS  # noqa: E402
from proof.tla_pins import TLC_PINS  # noqa: E402

pytestmark = [pytest.mark.unit, pytest.mark.local]

_SECTION = re.compile(r"^(SPECIFICATION|CONSTANTS?|INVARIANTS?|PROPERTIES?|CHECK_DEADLOCK)\b")


def _strip_comment(line: str) -> str:
    return line.split("\\*", 1)[0].strip()


def _cfg_sections(cfg: Path) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current = ""
    for raw in cfg.read_text().splitlines():
        line = _strip_comment(raw)
        if not line:
            continue
        m = _SECTION.match(line)
        if m:
            current = m.group(1).rstrip("S") if m.group(1) != "PROPERTIES" else "PROPERTY"
            rest = line[m.end():].strip()
            sections.setdefault(current, [])
            if rest:
                sections[current].append(rest)
            continue
        sections.setdefault(current, []).append(line)
    return sections


def _cfg_constants(cfg: Path) -> set[str]:
    return {entry.split("=", 1)[0].strip() for entry in _cfg_sections(cfg).get("CONSTANT", [])}


def _spec_constants(spec: Path) -> set[str]:
    """Names in the spec's CONSTANTS block (up to the first blank line)."""
    lines = spec.read_text().splitlines()
    start = next(i for i, ln in enumerate(lines) if ln.strip() == "CONSTANTS")
    names: set[str] = set()
    for raw in lines[start + 1 :]:
        line = _strip_comment(raw)
        if not raw.strip():
            break
        names.update(n.strip() for n in line.split(",") if n.strip())
    return names


def _spec_definitions(spec: Path) -> set[str]:
    return set(re.findall(r"^(\w+)\s*(?:\([^)]*\))?\s*==", spec.read_text(), re.MULTILINE))


PINNED = sorted(TLC_PINS)


@pytest.mark.parametrize("name", PINNED)
def test_cfg_constants_match_spec(name: str) -> None:
    pin = TLC_PINS[name]
    assert _cfg_constants(PROOF / f"{name}.cfg") == _spec_constants(PROOF / f"{pin.spec}.tla")


@pytest.mark.parametrize("name", PINNED)
def test_cfg_names_are_defined_in_spec(name: str) -> None:
    pin = TLC_PINS[name]
    sections = _cfg_sections(PROOF / f"{name}.cfg")
    defined = _spec_definitions(PROOF / f"{pin.spec}.tla")
    used = set(sections.get("SPECIFICATION", []))
    used |= set(sections.get("INVARIANT", [])) | set(sections.get("PROPERTY", []))
    assert used, f"{name}.cfg checks nothing"
    assert used <= defined, sorted(used - defined)


@pytest.mark.parametrize("name", PINNED)
def test_pinned_violations_are_checked_invariants(name: str) -> None:
    pin = TLC_PINS[name]
    invariants = _cfg_sections(PROOF / f"{name}.cfg").get("INVARIANT", [])
    assert pin.violated <= set(invariants)
    assert pin.negative_control == bool(pin.violated)
    if pin.violated:
        # TLC reports only the first violated invariant per state.
        assert invariants[0] in pin.violated


def test_every_spec_has_a_positive_and_a_negative_cfg() -> None:
    for spec in {p.spec for p in TLC_PINS.values()}:
        pins = [p for p in TLC_PINS.values() if p.spec == spec]
        assert any(not p.violated for p in pins), spec
        assert any(p.negative_control for p in pins), spec


def test_every_cfg_is_pinned() -> None:
    cfgs = {p.stem for p in PROOF.glob("*.cfg")}
    assert cfgs == set(CONFIGS) | set(TLC_PINS)


def _tools() -> tuple[str, str] | None:
    jar = os.environ.get("TLA_TOOLS_JAR", "")
    java = os.environ.get("JAVA") or shutil.which("java") or ""
    if not jar or not Path(jar).is_file() or not java:
        return None
    return java, jar


@pytest.mark.skipif(_tools() is None, reason="TLA_TOOLS_JAR not set")
@pytest.mark.parametrize("name", PINNED)
def test_tlc_reproduces_pin(name: str) -> None:
    from scripts.verify_tla import run_tlc

    java, jar = _tools()  # type: ignore[misc]
    pin = TLC_PINS[name]
    states, violated, out = run_tlc(java, jar, PROOF / f"{name}.cfg", PROOF / f"{pin.spec}.tla")
    assert "Temporal properties were violated" not in out
    assert (states, violated) == (pin.distinct_states, set(pin.violated))

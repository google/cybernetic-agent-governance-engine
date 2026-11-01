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

"""The model-free install gate (POAM-2026-168) passes here and fails on each regression.

Each negative case copies the repository's real inputs (pyproject, lockfile,
gateway Dockerfile, G3 script) and plants one regression in the copy, so a
test cannot pass on inputs the gate never sees in CI.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

import pytest

import scripts.check_model_free_install as gate

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO = Path(__file__).resolve().parents[1]
_INPUTS = (
    "pyproject.toml",
    "uv.lock",
    "src/gateway/Dockerfile",
    "scripts/check_import_boundaries.py",
)


def _check(root: Path) -> list[str]:
    return gate.check(*(root / rel for rel in _INPUTS))


@pytest.fixture
def copy(tmp_path: Path) -> Path:
    for rel in _INPUTS:
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / rel, target)
    return tmp_path


def _edit(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    assert old in text, f"fixture drift: {old!r} not in {path.name}"
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def test_the_repository_passes() -> None:
    assert _check(REPO) == []
    assert gate.main(["--root", str(REPO)]) == 0


def test_an_llm_client_in_the_base_install_fails(copy: Path) -> None:
    lock = copy / "uv.lock"
    text = lock.read_text(encoding="utf-8")
    root = re.search(r'\[\[package\]\]\nname = "cybernetic-governance-engine"\n', text)
    assert root is not None
    deps = text.index("dependencies = [\n", root.end()) + len("dependencies = [\n")
    lock.write_text(text[:deps] + '    { name = "litellm" },\n' + text[deps:])

    violations = _check(copy)
    assert any(v.startswith("base install resolves litellm") for v in violations)
    # The transitive tokenizer comes with it, with its path.
    assert any("litellm -> tokenizers" in v for v in violations)
    assert gate.main(["--root", str(copy)]) == 1


def test_installing_the_nemo_extra_in_the_gateway_image_fails(copy: Path) -> None:
    _edit(
        copy / "src/gateway/Dockerfile",
        "--extra gateway",
        "--extra gateway --extra nemo",
    )
    violations = _check(copy)
    assert any("gateway image" in v and "nemoguardrails" in v for v in violations)


def test_reinstalling_the_advisor_extra_in_the_gateway_image_fails(copy: Path) -> None:
    _edit(
        copy / "src/gateway/Dockerfile",
        "--extra gateway",
        "--extra gateway --extra advisor",
    )
    violations = _check(copy)
    assert any("gateway image" in v and "langchain-openai" in v for v in violations)


def test_all_extras_fails(copy: Path) -> None:
    _edit(
        copy / "src/gateway/Dockerfile",
        "--extra gateway --extra compliance --extra langfuse",
        "--all-extras",
    )
    assert any("--all-extras" in v for v in _check(copy))


def test_an_undeclared_extra_fails_instead_of_resolving_to_nothing(copy: Path) -> None:
    _edit(copy / "src/gateway/Dockerfile", "--extra gateway", "--extra gatewy")
    assert any("'gatewy' is not declared" in v for v in _check(copy))


def test_a_pip_install_of_a_model_package_fails(copy: Path) -> None:
    dockerfile = copy / "src/gateway/Dockerfile"
    dockerfile.write_text(
        dockerfile.read_text(encoding="utf-8")
        + "\nRUN uv pip install --python /app/.venv openai==1.51.0\n",
        encoding="utf-8",
    )
    assert any("`pip install` names openai" in v for v in _check(copy))


def test_a_comment_mentioning_an_extra_installs_nothing(copy: Path) -> None:
    dockerfile = copy / "src/gateway/Dockerfile"
    dockerfile.write_text(
        "# RUN uv sync --extra nemo  (an example, not an instruction)\n"
        + dockerfile.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    assert _check(copy) == []


def test_narrowing_g3_fails(copy: Path) -> None:
    _edit(copy / "scripts/check_import_boundaries.py", '    "openai",\n', "")
    violations = _check(copy)
    assert violations == [
        "check_import_boundaries.py: FORBIDDEN_VENDOR_SDKS no longer lists "
        "'openai', so the kernel could import it unchecked"
    ]


def test_reassigning_g3_after_the_literal_fails_closed(copy: Path) -> None:
    boundaries = copy / "scripts/check_import_boundaries.py"
    boundaries.write_text(
        boundaries.read_text(encoding="utf-8")
        + "\nFORBIDDEN_VENDOR_SDKS = FORBIDDEN_VENDOR_SDKS[:8]\n",
        encoding="utf-8",
    )
    assert any("assigned more than once" in v for v in _check(copy))


def test_every_kernel_forbidden_import_names_a_model_package() -> None:
    """The two lists describe one boundary: no G3 entry without its distribution."""
    distributions = {
        name.replace("_", "-").replace(".", "-") for name in gate.MODEL_PACKAGES
    }
    for import_name in gate.KERNEL_FORBIDDEN_IMPORTS:
        assert import_name.replace("_", "-").replace(".", "-") in distributions, (
            import_name
        )

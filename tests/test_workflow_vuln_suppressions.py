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

"""Every pip-audit suppression in a workflow must name its reason (POAM-2026-161).

An ``--ignore-vuln <ID>`` in ``.github/workflows`` passes only if a shell comment
in the same ``run:`` block names that exact ID. A YAML comment outside the block
does not count, and neither does a comment that names a longer or shorter ID. A
flag outside any ``run:`` block, or one whose ID is not a literal, always fails,
because there is no comment to check it against.

Whether a named reason is still true is for review to judge. This test makes sure
review has a reason to read: of the four suppressions it replaced, none matched a
locked package version and one had no comment at all.
"""

from __future__ import annotations

import re
import textwrap
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO_ROOT = Path(__file__).resolve().parents[1]
_WORKFLOWS_DIR = _REPO_ROOT / ".github" / "workflows"

_IGNORE_VULN = "--ignore-vuln"
_OPTION = re.compile(r"(?<![\w-])(--ig[\w-]*)(?:=|[ \t]+|$)([^\s;|&()<>]*)")
_PIP_AUDIT = re.compile(r"(?<![\w-])pip[-_]audit(?![\w-])")
_LITERAL_ID = re.compile(r"[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)+")
# In bash, `#` opens a comment only where a word starts: after one of these.
_WORD_BREAKS = " \t\n;|&()<>"


def _split_shell(script: str) -> tuple[str, list[str]]:
    """Split a ``run:`` script into its code and its comments, as bash reads them.

    ``#`` opens a comment where a word starts, outside quotes. Backslash-newline
    continuations are joined, so a flag and its ID end up on one line of code.
    """
    code: list[str] = []
    comments: list[str] = []
    quote = ""
    i = 0
    while i < len(script):
        char = script[i]
        if char == "\\" and quote != "'" and i + 1 < len(script):
            escaped = script[i + 1]
            code.append(" " if escaped == "\n" else char + escaped)
            i += 2
            continue
        if quote:
            if char == quote:
                quote = ""
        elif char in "'\"":
            quote = char
        elif char == "#" and (i == 0 or script[i - 1] in _WORD_BREAKS):
            end = script.find("\n", i)
            end = len(script) if end == -1 else end
            comments.append(script[i + 1 : end])
            i = end
            continue
        code.append(char)
        i += 1
    return "".join(code), comments


def _suppressions(code: str) -> Iterator[tuple[str, str]]:
    """Yield ``(option, value)`` for each pip-audit suppression in shell code.

    ``--ignore-vuln`` counts wherever it appears. argparse also accepts any
    unambiguous prefix of a long option, so in a command that runs pip-audit,
    ``--ignore-v ID`` and ``--ig=ID`` suppress too (checked against pip-audit
    2.10.1; ``--i`` is ambiguous with ``--index-url``). Prefixes count only in
    such a command, because other tools have options like pytest's ``--ignore``.
    """
    for command in re.split(r"[\n;&|]+", code):
        runs_pip_audit = _PIP_AUDIT.search(command) is not None
        for match in _OPTION.finditer(command):
            option, value = match.groups()
            if option == _IGNORE_VULN or (
                runs_pip_audit and _IGNORE_VULN.startswith(option)
            ):
                yield option, value


def _strings(node: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """Yield ``(path, value)`` for every string in a parsed workflow."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _strings(value, f"{path}.{key}" if path else str(key))
    elif isinstance(node, list):
        for index, item in enumerate(node):
            yield from _strings(item, f"{path}[{index}]")
    elif isinstance(node, str):
        yield path, node


def unexplained_suppressions(workflow: Any) -> list[str]:
    """Describe each ``--ignore-vuln`` in a parsed workflow that no comment names."""
    problems: list[str] = []
    for path, text in _strings(workflow):
        in_run = path.endswith(".run")
        code, comments = _split_shell(text) if in_run else (text, [])
        for option, value in _suppressions(code):
            vuln_id = value.strip("'\"")
            flag = f"`{option} {value}`"
            if not in_run:
                problems.append(f"{path}: {flag} is outside a run: block")
            elif not _LITERAL_ID.fullmatch(vuln_id):
                problems.append(f"{path}: {flag} is not a literal advisory ID")
            elif not any(
                re.search(rf"(?<![\w-]){re.escape(vuln_id)}(?![\w-])", comment)
                for comment in comments
            ):
                problems.append(
                    f"{path}: {flag} has no comment in its run: block naming {vuln_id}"
                )
    return problems


def test_every_workflow_suppression_names_its_reason() -> None:
    """Each --ignore-vuln in .github/workflows has a comment naming its ID."""
    workflows = sorted([*_WORKFLOWS_DIR.glob("*.yml"), *_WORKFLOWS_DIR.glob("*.yaml")])
    assert workflows, f"No workflow files found under {_WORKFLOWS_DIR}"

    problems = [
        f"{workflow.name}: {problem}"
        for workflow in workflows
        for problem in unexplained_suppressions(
            yaml.safe_load(workflow.read_text(encoding="utf-8"))
        )
    ]
    assert not problems, (
        "Unexplained vulnerability suppressions (POAM-2026-161). Name each ID in a "
        "comment in the same run: block, saying why it is suppressed, or remove "
        "the flag:\n" + "\n".join(problems)
    )


def _steps(steps_yaml: str) -> Any:
    """Parse ``steps_yaml`` (a YAML list of steps) as a one-job workflow."""
    body = textwrap.indent(textwrap.dedent(steps_yaml), " " * 6)
    return yaml.safe_load(f"jobs:\n  audit:\n    steps:\n{body}")


@pytest.mark.parametrize(
    ("steps_yaml", "explained"),
    [
        pytest.param(
            """
            - run: |
                uv run pip-audit \\
                  --ignore-vuln GHSA-xxxx-xxxx-xxxx
            """,
            False,
            id="no-comment",
        ),
        pytest.param(
            """
            - run: |
                # GHSA-xxxx-xxxx-xxxx: no fixed release yet; POAM-2026-000.
                uv run pip-audit \\
                  --ignore-vuln GHSA-xxxx-xxxx-xxxx
            """,
            True,
            id="comment-names-id",
        ),
        pytest.param(
            """
            - run: |
                uv run pip-audit --ignore-vuln PYSEC-2026-1  # PYSEC-2026-1: why
            """,
            True,
            id="trailing-comment-names-id",
        ),
        pytest.param(
            """
            # GHSA-xxxx-xxxx-xxxx: a YAML comment is not in the run: block.
            - run: uv run pip-audit --ignore-vuln GHSA-xxxx-xxxx-xxxx
            """,
            False,
            id="yaml-comment-outside-block",
        ),
        pytest.param(
            """
            - run: |
                # GHSA-xxxx-xxxx-xxxx: explained in another step's block.
                uv sync --frozen
            - run: uv run pip-audit --ignore-vuln GHSA-xxxx-xxxx-xxxx
            """,
            False,
            id="comment-in-another-block",
        ),
        pytest.param(
            """
            - run: |
                # PYSEC-2026-1390 is a different advisory.
                uv run pip-audit --ignore-vuln PYSEC-2026-139
            """,
            False,
            id="comment-names-longer-id",
        ),
        pytest.param(
            """
            - run: |
                echo "# GHSA-xxxx-xxxx-xxxx" && uv run pip-audit \\
                  --ignore-vuln GHSA-xxxx-xxxx-xxxx
            """,
            False,
            id="hash-inside-quotes",
        ),
        pytest.param(
            """
            - run: |
                uv run pip-audit --ig=GHSA-xxxx-xxxx-xxxx
            """,
            False,
            id="abbreviated-option",
        ),
        pytest.param(
            """
            - run: |
                # GHSA-xxxx-xxxx-xxxx is what VULN holds.
                uv run pip-audit --ignore-vuln "$VULN"
            """,
            False,
            id="non-literal-id",
        ),
        pytest.param(
            """
            - uses: example/pip-audit-action@v1
              with:
                args: --ignore-vuln GHSA-xxxx-xxxx-xxxx
            """,
            False,
            id="outside-run-block",
        ),
        pytest.param(
            """
            - run: |
                # Removed: --ignore-vuln GHSA-xxxx-xxxx-xxxx (dependency dropped).
                uv run pip-audit
            """,
            True,
            id="flag-only-in-comment",
        ),
        pytest.param(
            """
            - run: uv run pytest tests/ --ignore=tests/load && uv run pip-audit
            """,
            True,
            id="another-tools-ignore-option",
        ),
    ],
)
def test_checker_reports_only_unexplained_suppressions(
    steps_yaml: str, explained: bool
) -> None:
    """Each way a suppression can go unexplained is reported once; named ones pass."""
    problems = unexplained_suppressions(_steps(steps_yaml))
    if explained:
        assert problems == []
    else:
        assert len(problems) == 1, problems

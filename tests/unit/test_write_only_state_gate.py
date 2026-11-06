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

"""Unit tests for scripts/check_write_only_state.py (POAM-2026-169 #6)."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.check_write_only_state import find_write_only_state, main

pytestmark = [pytest.mark.unit, pytest.mark.local]


def test_live_repo_src_has_zero_write_only_state_attributes(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Every *.state.<attr> written in repository src/ has at least one reader."""
    rc = main(["--verbose"])
    captured = capsys.readouterr()
    assert rc == 0, (
        f"Unexpected write-only state violations:\n{captured.out}{captured.err}"
    )
    assert (
        "OK: every *.state.<attr> written in src/ has at least one reader."
        in captured.out
    )


def test_unreferenced_request_state_write_fails(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A request.state.<attr> write with zero readers in src/ fails with exit 1."""
    mod = tmp_path / "src" / "middleware.py"
    mod.parent.mkdir(parents=True)
    mod.write_text(
        "def attach(request):\n"
        "    request.state.caller_identity = {'sub': 'agent-1'}\n",
        encoding="utf-8",
    )

    rc = main(["--root", str(tmp_path)])
    captured = capsys.readouterr()
    assert rc == 1
    assert "src/middleware.py:2:" in captured.out
    assert "'state.caller_identity' has 0 readers in src/" in captured.out


def test_nested_getattr_state_reader_satisfies_gate(tmp_path: Path) -> None:
    """getattr(getattr(app, 'state', None), 'foo', None) counts as reading state.foo."""
    src_dir = tmp_path / "src"
    src_dir.mkdir(parents=True)
    (src_dir / "writer.py").write_text(
        "def startup(app):\n    app.state.foo = 'ready'\n",
        encoding="utf-8",
    )
    (src_dir / "reader.py").write_text(
        "def read_it(app):\n"
        "    return getattr(getattr(app, 'state', None), 'foo', None)\n",
        encoding="utf-8",
    )

    assert main(["--root", str(tmp_path)]) == 0


def test_local_state_alias_read_and_write_tracking(tmp_path: Path) -> None:
    """Local state aliases count for both reads and writes, and clear on reassignment."""
    src_dir = tmp_path / "src"
    src_dir.mkdir(parents=True)
    (src_dir / "aliased_ok.py").write_text(
        "def setup(request):\n"
        "    request.state.bar = 123\n"
        "def handle(request):\n"
        "    st = request.state\n"
        "    return st.bar\n",
        encoding="utf-8",
    )
    assert main(["--root", str(tmp_path)]) == 0

    # Writing through an alias without a reader must still fail.
    (src_dir / "aliased_write_only.py").write_text(
        "def bad_write(app):\n    st = app.state\n    st.orphan_handle = object()\n",
        encoding="utf-8",
    )
    violations, errors = find_write_only_state(tmp_path)
    assert not errors
    assert [v.attr for v in violations] == ["orphan_handle"]


def test_reassigned_local_variable_does_not_mask_write_only_state(
    tmp_path: Path,
) -> None:
    """Rebinding `st` to a non-state object must not launder `st.<attr>` as a state read."""
    src_dir = tmp_path / "src"
    src_dir.mkdir(parents=True)
    (src_dir / "rebound.py").write_text(
        "def run(request, other):\n"
        "    request.state.ghost = 1\n"
        "    st = request.state\n"
        "    st = other\n"
        "    return st.ghost\n",
        encoding="utf-8",
    )
    assert main(["--root", str(tmp_path)]) == 1


def test_annotated_state_write_without_reader_fails(tmp_path: Path) -> None:
    """Annotated assignment `app.state.only_written: int = 1` with zero readers fails."""
    src_dir = tmp_path / "src"
    src_dir.mkdir(parents=True)
    (src_dir / "ann.py").write_text(
        "def boot(app) -> None:\n    app.state.only_written: int = 1\n",
        encoding="utf-8",
    )
    violations, errors = find_write_only_state(tmp_path)
    assert not errors
    assert len(violations) == 1
    assert violations[0].attr == "only_written"
    assert main(["--root", str(tmp_path)]) == 1


def test_reads_in_test_files_do_not_satisfy_production_state_writes(
    tmp_path: Path,
) -> None:
    """Readers under tests/ or test_*.py must not rescue dead writes in src/."""
    (tmp_path / "src").mkdir(parents=True)
    (tmp_path / "src" / "server.py").write_text(
        "def boot(app):\n    app.state.attestation_aggregator = object()\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "test_server_inline.py").write_text(
        "def test_it(app):\n    assert app.state.attestation_aggregator is not None\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "tests").mkdir(parents=True)
    (tmp_path / "src" / "tests" / "helper.py").write_text(
        "def check(app):\n    return app.state.attestation_aggregator\n",
        encoding="utf-8",
    )

    assert main(["--root", str(tmp_path)]) == 1


def test_syntax_error_and_missing_root_fail_closed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Unparseable Python source or non-existent --root fails closed with exit 1."""
    assert main(["--root", str(tmp_path / "does_not_exist")]) == 1

    src_dir = tmp_path / "src"
    src_dir.mkdir(parents=True)
    (src_dir / "broken.py").write_text("def broken(:\n", encoding="utf-8")

    rc = main(["--root", str(tmp_path)])
    captured = capsys.readouterr()
    assert rc == 1
    assert "failed to parse Python source" in captured.err

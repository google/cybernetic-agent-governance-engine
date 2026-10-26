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

"""scripts/check_locked_yanks.py refuses a lock that pins a yanked release.

PyPI is replaced by an in-memory index; no test touches the network.
"""

from __future__ import annotations

import urllib.error
from pathlib import Path

import pytest

from scripts.check_locked_yanks import (
    LockedRelease,
    check_release,
    locked_releases,
    main,
    release_url,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_LOCK = Path(__file__).resolve().parents[1] / "uv.lock"

LOCK = """\
version = 1
requires-python = ">=3.11"

[[package]]
name = "cybernetic-governance-engine"
version = "3.3.0"
source = { editable = "." }

[[package]]
name = "scs"
version = "3.3.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "numpy"
version = "2.3.4"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "en-core-web-sm"
version = "3.8.0"
source = { url = "https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl" }
"""


def _index(yanked: dict[str, str]):
    """An in-memory PyPI: every release exists; *yanked* maps name -> reason."""

    def fetch(release: LockedRelease) -> dict:
        reason = yanked.get(release.name)
        return {"info": {"yanked": reason is not None, "yanked_reason": reason}}

    return fetch


def _no_sleep(_: float) -> None:
    return None


@pytest.fixture
def lock(tmp_path: Path) -> Path:
    path = tmp_path / "uv.lock"
    path.write_text(LOCK)
    return path


def test_only_pypi_registry_releases_are_checked(lock: Path) -> None:
    releases, unverifiable = locked_releases(lock)

    assert releases == [LockedRelease("scs", "3.3.0"), LockedRelease("numpy", "2.3.4")]
    assert unverifiable == []


def test_a_yanked_release_fails_the_check(lock: Path, capsys) -> None:
    fetch = _index({"scs": "wheels crash on first solve"})

    assert main([str(lock)], fetch=fetch, sleep=_no_sleep) == 1
    assert "YANKED  scs==3.3.0: wheels crash on first solve" in capsys.readouterr().out


def test_a_lock_without_yanked_releases_passes(lock: Path) -> None:
    assert main([str(lock)], fetch=_index({}), sleep=_no_sleep) == 0


def test_a_release_that_cannot_be_looked_up_fails_closed(lock: Path, capsys) -> None:
    def unreachable(release: LockedRelease) -> dict:
        raise urllib.error.URLError("network unreachable")

    assert main([str(lock)], fetch=unreachable, sleep=_no_sleep) == 2
    assert "UNCHECKED  scs==3.3.0" in capsys.readouterr().out


def test_a_deleted_release_fails_closed_without_retrying() -> None:
    calls: list[LockedRelease] = []

    def gone(release: LockedRelease) -> dict:
        calls.append(release)
        raise urllib.error.HTTPError(release_url(release), 404, "Not Found", {}, None)

    verdict = check_release(LockedRelease("scs", "3.3.0"), fetch=gone, sleep=_no_sleep)

    assert verdict.error == "HTTP 404"
    assert len(calls) == 1


def test_a_transient_failure_is_retried() -> None:
    responses: list[object] = [
        urllib.error.URLError("reset"),
        {"info": {"yanked": False}},
    ]

    def flaky(release: LockedRelease) -> dict:
        response = responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    verdict = check_release(
        LockedRelease("numpy", "2.3.4"), fetch=flaky, sleep=_no_sleep
    )

    assert verdict.yanked is False and verdict.error == ""


def test_a_package_from_another_registry_fails_closed(tmp_path: Path, capsys) -> None:
    path = tmp_path / "uv.lock"
    path.write_text(
        LOCK + '\n[[package]]\nname = "internal"\nversion = "1.0"\n'
        'source = { registry = "https://pypi.example.com/simple" }\n'
    )

    assert main([str(path)], fetch=_index({}), sleep=_no_sleep) == 2
    assert "internal 1.0 (https://pypi.example.com/simple): not a PyPI release" in (
        capsys.readouterr().out
    )


def test_release_urls_are_https_and_quoted() -> None:
    url = release_url(LockedRelease("a/b", "1.0+local"))

    assert url == "https://pypi.org/pypi/a%2Fb/1.0%2Blocal/json"


def test_the_repository_lock_is_parsed() -> None:
    releases, unverifiable = locked_releases(REPO_LOCK)

    assert len(releases) > 100
    assert unverifiable == []
    assert all(release.version for release in releases)

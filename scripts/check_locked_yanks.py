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

"""Refuse a uv.lock that pins a release PyPI has yanked.

``uv lock --check`` only verifies that the lock matches pyproject.toml; it
does not report yanked releases, and a release yanked after it was locked
stays in the lock until someone upgrades it. This script asks PyPI about
every registry package in the lock and fails if any locked version is
yanked. It fails closed: a release it cannot look up counts as a failure.

Usage: python scripts/check_locked_yanks.py [path/to/uv.lock]
Exit codes: 0 no yanked release, 1 yanked release(s), 2 lookup failure(s).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 (requires-python admits it)
    import tomli as tomllib  # type: ignore[no-redef]

PYPI_INDEX = "https://pypi.org/simple"
PYPI_JSON = "https://pypi.org/pypi"
ATTEMPTS = 3
TIMEOUT_SECONDS = 20
WORKERS = 16


@dataclass(frozen=True)
class LockedRelease:
    name: str
    version: str


@dataclass(frozen=True)
class Verdict:
    release: LockedRelease
    yanked: bool = False
    reason: str = ""
    error: str = ""


def locked_releases(lock_path: Path) -> tuple[list[LockedRelease], list[str]]:
    """Return the PyPI releases in *lock_path* and the packages it cannot check.

    Editable, path and direct-URL sources are not PyPI releases and cannot be
    yanked; they are skipped. A package from any other registry is returned as
    unverifiable, because only PyPI is queried.
    """
    lock = tomllib.loads(lock_path.read_text())
    releases: list[LockedRelease] = []
    unverifiable: list[str] = []
    for package in lock.get("package", []):
        registry = package.get("source", {}).get("registry")
        if registry is None:
            continue
        if registry.rstrip("/") != PYPI_INDEX:
            unverifiable.append(f"{package['name']} {package['version']} ({registry})")
            continue
        releases.append(LockedRelease(package["name"], package["version"]))
    return releases, unverifiable


def release_url(release: LockedRelease) -> str:
    url = (
        f"{PYPI_JSON}/{urllib.parse.quote(release.name, safe='')}/"
        f"{urllib.parse.quote(release.version, safe='')}/json"
    )
    if urllib.parse.urlparse(url).scheme != "https":  # B310: never a non-https scheme
        raise ValueError(f"refusing non-https URL: {url}")
    return url


def fetch_release(release: LockedRelease) -> dict:
    request = urllib.request.Request(
        release_url(release),
        headers={"Accept": "application/json", "User-Agent": "cage-check-locked-yanks"},
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # nosec B310 - https enforced in release_url()
        return json.load(response)


def check_release(
    release: LockedRelease,
    fetch: Callable[[LockedRelease], dict] = fetch_release,
    sleep: Callable[[float], None] = time.sleep,
) -> Verdict:
    last_error = ""
    for attempt in range(1, ATTEMPTS + 1):
        try:
            info = fetch(release).get("info", {})
        except urllib.error.HTTPError as exc:
            last_error = f"HTTP {exc.code}"
            if exc.code == 404:  # the release no longer exists on PyPI
                break
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            last_error = str(exc)
        else:
            if info.get("yanked"):
                return Verdict(
                    release, yanked=True, reason=info.get("yanked_reason") or ""
                )
            return Verdict(release)
        if attempt < ATTEMPTS:
            sleep(2**attempt)
    return Verdict(release, error=last_error or "unknown error")


def main(
    argv: list[str] | None = None,
    fetch: Callable[[LockedRelease], dict] = fetch_release,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("lock", nargs="?", default="uv.lock", type=Path)
    args = parser.parse_args(argv)

    releases, unverifiable = locked_releases(args.lock)
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        verdicts = list(pool.map(lambda r: check_release(r, fetch, sleep), releases))

    yanked = [v for v in verdicts if v.yanked]
    failed = [v for v in verdicts if v.error]
    for v in yanked:
        print(
            f"YANKED  {v.release.name}=={v.release.version}: {v.reason or 'no reason given'}"
        )
    for v in failed:
        print(f"UNCHECKED  {v.release.name}=={v.release.version}: {v.error}")
    for entry in unverifiable:
        print(f"UNCHECKED  {entry}: not a PyPI release")
    print(
        f"checked {len(releases)} PyPI releases in {args.lock}: "
        f"{len(yanked)} yanked, {len(failed) + len(unverifiable)} unchecked"
    )
    if yanked:
        print(
            "Upgrade each yanked package (uv lock --upgrade-package <name>) and commit uv.lock."
        )
        return 1
    return 2 if failed or unverifiable else 0


if __name__ == "__main__":
    sys.exit(main())

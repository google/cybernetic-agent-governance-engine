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

"""Regression and mutation tests for the Bandit SAST gate scope and nosec hygiene.

Covers POAM-2026-161 / POAM-2026-150:
1. ``pyproject.toml`` ``[tool.bandit] exclude_dirs`` must not exclude ``scripts`` or ``src``.
2. Every ``# nosec`` comment across ``src/`` and ``scripts/`` must include an explicit
   ``B<NNN>`` rule ID and a human-readable justification.
3. ``scripts/automated_auditor.py`` strictly validates URL schemes (``http`` / ``https``
   with non-empty ``netloc``) before ``urllib.request.urlopen``.
4. Planted-defect meta-test proving ``bandit -c pyproject.toml -ll -ii`` catches
   unguarded ``urlopen`` (``B310``) and hardcoded ``/tmp`` paths (``B108``).
5. Full repository scan across ``src/`` and ``scripts/`` scans >25,000 LOC and exits 0.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
import tomllib

from scripts.automated_auditor import OTLPTraceSource, validate_auditor_url

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"

# Matches `# nosec B310  # reason` (Bandit parses tokens until the next `#` as test IDs)
NOSEC_WITH_REASON_RE = re.compile(r"#\s*nosec\s+B\d{3}(?:\s*,\s*B\d{3})*\s+#\s*\S+")
ANY_NOSEC_RE = re.compile(r"#\s*nosec\b", re.IGNORECASE)


def _bandit_cmd(*args: str) -> list[str]:
    return [sys.executable, "-m", "bandit", *args]


def test_pyproject_bandit_exclude_dirs_does_not_exclude_scripts_or_src() -> None:
    """Ensure [tool.bandit] exclude_dirs does not silently skip scripts/ or src/."""
    data = tomllib.loads(PYPROJECT_PATH.read_text(encoding="utf-8"))
    bandit_cfg = data.get("tool", {}).get("bandit", {})
    exclude_dirs = bandit_cfg.get("exclude_dirs", [])
    normalized = {d.strip("/ ") for d in exclude_dirs}
    assert "scripts" not in normalized, (
        f"scripts/ must not be excluded from Bandit scans: exclude_dirs={exclude_dirs!r}"
    )
    assert "src" not in normalized, (
        f"src/ must not be excluded from Bandit scans: exclude_dirs={exclude_dirs!r}"
    )


def test_every_nosec_in_src_and_scripts_has_rule_id_and_reason() -> None:
    """Every `# nosec` in src/ and scripts/ must specify B<NNN> and a `# reason` comment."""
    violations: list[str] = []
    for root_name in ("src", "scripts"):
        root_dir = REPO_ROOT / root_name
        for py_file in sorted(root_dir.rglob("*.py")):
            for lineno, line in enumerate(
                py_file.read_text(encoding="utf-8").splitlines(), start=1
            ):
                if ANY_NOSEC_RE.search(line) and not NOSEC_WITH_REASON_RE.search(line):
                    rel = py_file.relative_to(REPO_ROOT)
                    violations.append(f"{rel}:{lineno}: {line.strip()}")

    assert not violations, (
        "Found `# nosec` comments without an explicit `B<NNN>  # reason` format:\n"
        + "\n".join(violations)
    )


@pytest.mark.parametrize(
    "bad_url",
    [
        "file:///etc/passwd",
        "ftp://example.com/resource",
        "javascript:alert(1)",
        "localhost:16686/api/traces",
        "/api/traces?service=gateway",
        "http:///api/traces",
        "https://",
        "",
    ],
)
def test_automated_auditor_rejects_disallowed_or_schemeless_urls(bad_url: str) -> None:
    """validate_auditor_url and OTLPTraceSource.fetch_traces reject non-http(s) schemes."""
    with pytest.raises(ValueError, match="Invalid URL scheme|missing host"):
        validate_auditor_url(bad_url)

    source = OTLPTraceSource(endpoint=bad_url)
    with pytest.raises(ValueError, match="Invalid URL scheme|missing host"):
        source.fetch_traces("gateway", 5)


@pytest.mark.parametrize(
    "good_url",
    [
        "http://localhost:16686/api/traces?service=gateway&lookback=5m",
        "https://jaeger.internal.example.com:443/api/traces?lookback=15m&service=gateway",
    ],
)
def test_automated_auditor_accepts_valid_http_and_https_urls(good_url: str) -> None:
    """validate_auditor_url accepts well-formed http:// and https:// URLs."""
    assert validate_auditor_url(good_url) == good_url


def test_planted_defect_caught_by_bandit_config() -> None:
    """Meta-test: Bandit with pyproject.toml flags unguarded urlopen (B310) and /tmp (B108)."""
    tmp_literal = "/" + "tmp/planted_insecure_file.json"
    defect_source = (
        "import urllib.request\n"
        "def planted_bad(url: str) -> str:\n"
        "    with urllib.request.urlopen(url, timeout=5) as resp:\n"
        "        _ = resp.read()\n"
        f"    return {tmp_literal!r}\n"
    )
    with tempfile.TemporaryDirectory(prefix="cage_bandit_meta_") as tmp_dir:
        defect_file = Path(tmp_dir) / "planted_defect.py"
        defect_file.write_text(defect_source, encoding="utf-8")
        proc = subprocess.run(
            _bandit_cmd(
                "-c",
                str(PYPROJECT_PATH),
                "-ll",
                "-ii",
                str(defect_file),
            ),
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    assert proc.returncode != 0, (
        f"Expected Bandit to fail on planted B310/B108 defects, got rc=0:\n{proc.stdout}"
    )
    assert "B310" in proc.stdout, f"Expected B310 in Bandit output:\n{proc.stdout}"
    assert "B108" in proc.stdout, f"Expected B108 in Bandit output:\n{proc.stdout}"


def test_bandit_full_scan_covers_src_and_scripts_cleanly() -> None:
    """Full Bandit scan over src/ and scripts/ scans >25,000 LOC and exits 0 with 0 issues."""
    proc = subprocess.run(
        _bandit_cmd(
            "-r",
            "src/",
            "scripts/",
            "-c",
            str(PYPROJECT_PATH),
            "-ll",
            "-ii",
        ),
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, (
        f"Bandit scan failed (rc={proc.returncode}):\n{proc.stdout}\n{proc.stderr}"
    )
    assert "No issues identified." in proc.stdout, proc.stdout
    assert "Test in comment:" not in proc.stderr, (
        f"Bandit emitted `# nosec` comment parse warnings:\n{proc.stderr}"
    )

    match = re.search(r"Total lines of code:\s*(\d+)", proc.stdout)
    assert match is not None, (
        f"Could not parse Total lines of code from:\n{proc.stdout}"
    )
    total_loc = int(match.group(1))
    assert total_loc > 25_000, (
        f"Expected Bandit to scan >25,000 LOC across src/ and scripts/, got {total_loc}"
    )

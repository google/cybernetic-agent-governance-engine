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

"""Run TLC on every proof/DistributedCBF*.cfg and compare with the Python BFS.

Each cfg must reproduce ``EXPECTED_STATE_COUNTS[(name, 2)]`` from
``proof/distributed_cbf_model.py``: the same number of distinct states (TLC
runs with ``-continue`` so violated configurations are explored fully) and
the same SP-1 / SP-2 verdicts.

Usage:
    TLA_TOOLS_JAR=/path/to/tla2tools.jar uv run python scripts/verify_tla.py

``JAVA`` overrides the Java executable (default: ``java`` on PATH). Exits 2
with instructions when either is missing, 1 on any mismatch.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess  # nosec B404 — fixed argv, no shell
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from proof.distributed_cbf_model import CONFIGS, EXPECTED_STATE_COUNTS  # noqa: E402

_DISTINCT = re.compile(r"(\d+) distinct states found")
_VIOLATED = re.compile(r"Invariant (\w+) is violated")


def _tools() -> tuple[str, str] | None:
    jar = os.environ.get("TLA_TOOLS_JAR", "")
    java = os.environ.get("JAVA") or shutil.which("java") or ""
    if not jar or not Path(jar).is_file() or not java:
        return None
    return java, jar


def run_tlc(java: str, jar: str, cfg: Path, spec: Path) -> tuple[int, set[str], str]:
    """Return (distinct states, violated invariants, raw output)."""
    with tempfile.TemporaryDirectory() as meta:
        proc = subprocess.run(  # nosec B603 — argv built from repo paths
            [
                java, "-XX:+UseParallelGC", "-cp", jar, "tlc2.TLC",
                "-nowarning", "-continue", "-workers", "auto", "-metadir", meta,
                "-config", str(cfg), str(spec),
            ],
            capture_output=True, text=True, check=False, cwd=ROOT,
        )
    out = proc.stdout + proc.stderr
    counts = _DISTINCT.findall(out)
    if not counts:
        raise RuntimeError(f"TLC produced no state count for {cfg.name}:\n{out[-2000:]}")
    return int(counts[-1]), set(_VIOLATED.findall(out)), out


def main() -> int:
    tools = _tools()
    if tools is None:
        print("TLC unavailable: set TLA_TOOLS_JAR to tla2tools.jar (and JAVA if java is not on PATH).")
        print("Download: https://github.com/tlaplus/tlaplus/releases")
        return 2
    java, jar = tools
    spec = ROOT / "proof" / "DistributedCBF.tla"
    ok = True
    for name in CONFIGS:
        cfg = ROOT / "proof" / f"{name}.cfg"
        expected = EXPECTED_STATE_COUNTS[(name, 2)]
        states, violated, _ = run_tlc(java, jar, cfg, spec)
        got = (
            states,
            "SP1_NoDoubleSpend" not in violated,
            "SP2_NoOvercommit" not in violated,
        )
        unexpected = violated - {"SP1_NoDoubleSpend", "SP2_NoOvercommit"}
        match = got == expected and not unexpected
        ok &= match
        print(
            f"{'OK ' if match else 'BAD'} {cfg.name}: TLC (states, SP-1, SP-2) = {got}; "
            f"BFS = {expected}"
            + (f"; other violations: {sorted(unexpected)}" if unexpected else "")
        )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

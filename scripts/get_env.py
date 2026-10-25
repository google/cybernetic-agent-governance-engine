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

from __future__ import annotations

import sys
from pathlib import Path

_TARGET_MARKERS: tuple[str, ...] = ("GOOGLE_", "OIDC", "Workload Identity")


def _mask(value: str) -> str:
    """Return a masked representation of *value* safe to log (AGENTS.md)."""
    cleaned = value.strip().strip("\"'")
    if not cleaned:
        return "(empty)"
    if len(cleaned) <= 4:
        return "****"
    return cleaned[:4] + "****"


def mask_env_line(line: str) -> str:
    """Mask any KEY=VALUE assignment on a .env line while preserving comments."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return stripped
    if "=" not in stripped:
        return stripped
    key, _, raw_val = stripped.partition("=")
    val_without_comment = raw_val.split("#")[0].strip()
    return f"{key.strip()}={_mask(val_without_comment)}"


def main(env_path: Path = Path(".env")) -> int:
    """Inspect target .env keys with mandatory value masking."""
    if not env_path.exists():
        print(
            f"Warning: .env file not found at {env_path.absolute()} — skipping",
            file=sys.stderr,
        )
        return 0

    text = env_path.read_text(encoding="utf-8")
    for line in text.splitlines():
        if any(marker in line for marker in _TARGET_MARKERS):
            print(mask_env_line(line))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

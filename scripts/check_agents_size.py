#!/usr/bin/env python3
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

"""Validates that AGENTS.md does not exceed the 24KB (24,576 byte) Antigravity ingestion limit."""

import sys
from pathlib import Path

MAX_BYTES = 24576  # 24 KB


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    agents_path = repo_root / "AGENTS.md"
    if not agents_path.exists():
        print(f"❌ Error: {agents_path} not found.")
        return 1

    size = agents_path.stat().st_size
    if size > MAX_BYTES:
        print(f"❌ Error: AGENTS.md is {size:,} bytes, exceeding the {MAX_BYTES:,} byte (24KB) cap.")
        print(f"   Excess: {size - MAX_BYTES:,} bytes.")
        print("   Exceeding 24KB causes Google Antigravity and other agents to silently truncate rules.")
        print("   Move operational runbooks to docs/operations/ to keep AGENTS.md lean and high-signal.")
        return 1

    print(f"✅ AGENTS.md size check passed: {size:,} bytes / {MAX_BYTES:,} max ({size / MAX_BYTES * 100:.1f}% of 24KB cap).")
    return 0


if __name__ == "__main__":
    sys.exit(main())


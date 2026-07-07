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

"""
CI check: verifies that proto files in src/gateway/protos/ and
src/agentsight-ui/gateway_protos/ are identical.

Run: python scripts/verify_proto_sync.py
Exit 0 = in sync. Exit 1 = diverged (CI failure).
"""

import sys
from pathlib import Path

PROTO_PAIRS = [
    (
        Path("src/gateway/protos/gateway.proto"),
        Path("src/agentsight-ui/gateway_protos/gateway.proto"),
    ),
    (
        Path("src/gateway/protos/nemo.proto"),
        Path("src/agentsight-ui/gateway_protos/nemo.proto"),
    ),
]


def main():
    all_ok = True
    for canonical, copy_ in PROTO_PAIRS:
        if not canonical.exists():
            print(f"ERROR: canonical proto not found: {canonical}", file=sys.stderr)
            all_ok = False
            continue
        if not copy_.exists():
            print(f"ERROR: copy proto not found: {copy_}", file=sys.stderr)
            all_ok = False
            continue
        if canonical.read_bytes() != copy_.read_bytes():
            print(
                f"FAIL: proto files diverged!\n  {canonical}\n  {copy_}",
                file=sys.stderr,
            )
            all_ok = False
        else:
            print(f"OK: {canonical.name} in sync")
    if not all_ok:
        sys.exit(1)
    print("All proto files in sync.")


if __name__ == "__main__":
    main()

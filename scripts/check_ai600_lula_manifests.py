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
NIST AI 600-1 Lula manifest structure validator.

Validates that all lula-validation-ai600-*.yaml manifests use the OSCAL
component-definition structure required by the lula Go CLI (defenseunicorns-labs/lula1).

The manifests embed domain/provider inside back-matter.resources[].description
as a YAML string — they do NOT have top-level domain/provider keys.
The correct top-level key is component-definition.

Exit codes:
  0 — all manifests pass
  1 — no manifests found, or any manifest is missing component-definition key
"""

import pathlib
import sys

import yaml


def main() -> int:
    manifests = sorted(
        pathlib.Path("compliance/lula").glob("lula-validation-ai600-*.yaml")
    )
    if not manifests:
        print("ERROR: no AI 600-1 Lula manifests found")
        return 1

    errors = []
    for m in manifests:
        doc = yaml.safe_load(m.read_text())
        if "component-definition" not in doc:
            errors.append(f"{m.name}: missing component-definition key")
        else:
            cd = doc["component-definition"]
            title = cd.get("metadata", {}).get("title", "?")
            print(f"  OK {m.name}: title={title!r}")

    if errors:
        print("FAILURES:")
        for e in errors:
            print(f"  {e}")
        return 1

    print(f"All {len(manifests)} AI 600-1 Lula manifests passed YAML structure check.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
